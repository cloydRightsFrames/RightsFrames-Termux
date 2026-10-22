#!/usr/bin/env python3
"""Off-box anchor pinning.

`pin` verifies the current ledger against ALL previously recorded pins, then records the
newest anchor in a pins file meant to live OFF the operator's machine (committed and pushed
to a remote, tagged). `check` re-verifies the live ledger against the pins file; it exits 0
only when verification reaches trust level anchor_pinned. A pins file that disagrees with
the live anchor chain means history was rewritten, rolled back, or regenerated.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


class PinError(Exception):
    pass


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_verifier = _load('rf_verify_pintool', 'verifier/rf_verify.py')
_exporter = _load('rf_export_pintool', 'tools/rf_export_evidence.py')


def read_pins(path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    pins: list[dict[str, Any]] = []
    seen: set[int] = set()
    for number, line in enumerate(p.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            raise PinError(f'pins line {number} is not JSON') from None
        seq = item.get('seq') if isinstance(item, dict) else None
        digest = item.get('anchor_hash') if isinstance(item, dict) else None
        if (not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
                or not isinstance(digest, str) or not _HEX64.match(digest)):
            raise PinError(f'pins line {number} is malformed')
        if seq in seen:
            raise PinError(f'pins line {number} duplicates seq {seq}')
        seen.add(seq)
        pins.append(item)
    return pins


def _inspect(data_dir, pins):
    tmp = tempfile.mkdtemp(prefix='rf-pin-')
    try:
        bundle = Path(tmp) / 'bundle.zip'
        _exporter.export_bundle(data_dir, bundle)
        try:
            report = _verifier.verify_bundle(
                str(bundle),
                pin_anchors=[(p['seq'], p['anchor_hash']) for p in pins],
                min_anchors=max([p['seq'] for p in pins], default=0),
            )
        except _verifier.VerificationError as exc:
            raise PinError(f'verification against pins failed: {exc}') from exc
        members = _verifier._read_members(str(bundle))
        anchors = _verifier._parse_lines(members['anchors.jsonl'], 'anchors')
        return report, anchors
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _create_anchor(data_dir) -> None:
    sys.path.insert(0, str(ROOT / 'core'))
    import rf_core  # noqa: E402
    if Path(data_dir).resolve() != Path(rf_core.DATA_DIR).resolve():
        raise PinError('data dir does not match rf_core.DATA_DIR')
    rf_core.init_db()
    conn = rf_core._connect()
    try:
        count = conn.execute('SELECT COUNT(*) FROM ledger_entries').fetchone()[0]
    finally:
        conn.close()
    if count == 0:
        rf_core.append_entry('system.bootstrap', {'note': 'ledger initialised by rf_pin_anchor'})
    rf_core.append_entry('audit.cli', {'actor': getpass.getuser(), 'action': 'anchor.create'})
    rf_core.create_anchor()


def check(data_dir, pins_path) -> dict[str, Any]:
    pins = read_pins(pins_path)
    report, _ = _inspect(data_dir, pins)
    return {**report, 'pins': len(pins)}


def pin(data_dir, pins_path, create_anchor: bool = False) -> dict[str, Any]:
    pins = read_pins(pins_path)
    if create_anchor:
        _create_anchor(data_dir)
    report, anchors = _inspect(data_dir, pins)
    if not anchors:
        raise PinError('no anchors to pin; run with --create-anchor')
    latest = anchors[-1]
    if any(p['seq'] == latest['seq'] for p in pins):
        return {'status': 'already_pinned', 'seq': latest['seq'],
                'anchor_hash': latest['anchor_hash'], 'trust_level': report['trust_level']}
    record = {
        'seq': latest['seq'], 'anchor_hash': latest['anchor_hash'], 'key_id': report['key_id'],
        'ledger_count': latest['ledger_count'], 'ledger_head': latest['ledger_head'],
        'anchor_created_at': latest['created_at'],
        'pinned_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
    }
    path = Path(pins_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('ab') as handle:
        handle.write((json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8'))
        handle.flush()
        os.fsync(handle.fileno())
    return {'status': 'pinned', **record, 'trust_level': report['trust_level']}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Pin and check RightsFrames anchors off-box.')
    sub = parser.add_subparsers(dest='cmd', required=True)
    p_pin = sub.add_parser('pin')
    p_pin.add_argument('--pins', required=True)
    p_pin.add_argument('--create-anchor', action='store_true')
    p_check = sub.add_parser('check')
    p_check.add_argument('--pins', required=True)
    args = parser.parse_args(argv)
    if not os.environ.get('RF_DATA_DIR'):
        print('RF_DATA_DIR must be set', file=sys.stderr)
        return 2
    data_dir = Path(os.environ['RF_DATA_DIR']).resolve()
    try:
        if args.cmd == 'pin':
            result = pin(data_dir, args.pins, args.create_anchor)
            code = 0
        else:
            result = check(data_dir, args.pins)
            code = 0 if result['trust_level'] == 'anchor_pinned' else 10
    except PinError as exc:
        print(f'FAILED: {exc}', file=sys.stderr)
        return 1
    for key, value in result.items():
        if key == 'warnings':
            for warning in value:
                print(f'WARNING: {warning}')
        else:
            print(f'{key}: {value}')
    return code


if __name__ == '__main__':
    sys.exit(main())