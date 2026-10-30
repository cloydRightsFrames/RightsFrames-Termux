#!/usr/bin/env python3
"""RightsFrames one-command evaluation demo.

Builds a fresh ledger in a temporary directory, exports a signed evidence
bundle, verifies it with the independent verifier (verifier/rf_verify.py, run
as a separate isolated process), then mounts tampering attacks in which the
attacker recomputes everything that does not need the operator's private key
(entry hashes, hash links, manifest digests and summaries). Every attack must
be rejected; an unpinned forgery must be reported as internal_only, never as
anchor_pinned.

When the installed cryptography supports ML-DSA-65, anchors are hybrid
(Ed25519 + ML-DSA-65) and two post-quantum attacks are added: a "quantum
forger" who holds the operator's Ed25519 private key (as if recovered by a
quantum computer) but not the ML-DSA-65 key, and a downgrade that strips the
post-quantum signatures. Both must be rejected without any anchor pin.

Usage:
    python tools/rf_demo.py [--entries N] [--keep DIR] [--json]

Exit status: 0 when every expectation holds, 1 otherwise.
Requires: Python 3.10+ and the `cryptography` package (core/requirements.txt).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / 'verifier' / 'rf_verify.py'
EXPORTER = ROOT / 'tools' / 'rf_export_evidence.py'
ZERO_HASH = '0' * 64
ANCHOR_V3 = 'rf.anchor.v3'
ANCHOR_CORE_V2 = ('schema', 'seq', 'created_at', 'ledger_count', 'ledger_head',
                  'prev_anchor_hash', 'key_id')
ANCHOR_CORE_V3 = ANCHOR_CORE_V2 + ('pq_key_id',)

_LEDGER_SCRIPT = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from core import rf_core
count = int(sys.argv[2])
tag = sys.argv[3]
for index in range(count):
    rf_core.append_entry('demo.event', {'actor': tag, 'n': index})
anchor = rf_core.create_anchor()
ok_chain, _ = rf_core.verify_chain()
ok_anchors, _ = rf_core.verify_anchors()
print(json.dumps({'anchor': anchor, 'chain_ok': ok_chain, 'anchors_ok': ok_anchors}))
'''


class DemoError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_ledger(data_dir: Path, entries: int, tag: str) -> dict[str, Any]:
    """Create a ledger in its own process so RF_DATA_DIR is honoured at import."""
    data_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env['RF_DATA_DIR'] = str(data_dir)
    proc = subprocess.run(
        [sys.executable, '-c', _LEDGER_SCRIPT, str(ROOT), str(entries), tag],
        cwd=str(ROOT), env=env, text=True, capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        raise DemoError(f'ledger build failed ({tag}): {proc.stderr.strip()[-800:]}')
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    if not (result['chain_ok'] and result['anchors_ok']):
        raise DemoError(f'freshly built ledger failed self-verification ({tag})')
    return result['anchor']


def export_bundle(data_dir: Path, out: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location('rf_export_evidence_demo', EXPORTER)
    if spec is None or spec.loader is None:
        raise DemoError(f'cannot load exporter: {EXPORTER}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_bundle(data_dir, out)


def verify(bundle: Path, pins: Sequence[str] = ()) -> tuple[int, dict[str, Any]]:
    cmd = [sys.executable, '-I', str(VERIFIER), str(bundle), '--json', *pins]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
    lines = proc.stdout.strip().splitlines()
    if not lines:
        raise DemoError(f'verifier produced no output: {proc.stderr.strip()[-800:]}')
    return proc.returncode, json.loads(lines[-1])


def read_bundle(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_bundle(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, blob in members.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), blob)


def split_jsonl(blob: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in blob.decode('utf-8').splitlines() if line.strip()]


def join_jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b''.join((canonical_json(row) + '\n').encode('utf-8') for row in rows)


def rechain(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute every hash link exactly as an attacker without the key could."""
    previous = ZERO_HASH
    out = []
    for index, row in enumerate(rows, 1):
        row = dict(row, id=index, prev_hash=previous)
        material = f"{index}|{previous}|{row['ts']}|{row['entry_type']}|{row['payload']}"
        row['entry_hash'] = sha256_hex(material.encode('utf-8'))
        previous = row['entry_hash']
        out.append(row)
    return out


def reseal_manifest(members: dict[str, bytes]) -> dict[str, bytes]:
    """Make the unsigned manifest consistent with forged members."""
    manifest = json.loads(members['manifest.json'])
    ledger = split_jsonl(members['ledger.jsonl'])
    anchors = split_jsonl(members['anchors.jsonl'])
    for name in list(manifest['files']):
        manifest['files'][name] = {'sha256': sha256_hex(members[name]), 'bytes': len(members[name])}
    manifest['ledger_count'] = len(ledger)
    manifest['ledger_head'] = ledger[-1]['entry_hash'] if ledger else ZERO_HASH
    manifest['anchor_count'] = len(anchors)
    members = dict(members)
    members['manifest.json'] = canonical_json(manifest).encode('utf-8')
    return members


def attack_edit_keep_hashes(members: dict[str, bytes]) -> dict[str, bytes]:
    """Content edit with every stored hash and link left intact (pointer-only checks miss this)."""
    rows = split_jsonl(members['ledger.jsonl'])
    payload = json.loads(rows[1]['payload'])
    payload['n'] = 999_999
    rows[1]['payload'] = canonical_json(payload)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows)})
    return reseal_manifest(members)


def attack_edit_and_rechain(members: dict[str, bytes]) -> dict[str, bytes]:
    rows = split_jsonl(members['ledger.jsonl'])
    target = rows[1]
    payload = json.loads(target['payload'])
    payload['n'] = 999_999
    target['payload'] = canonical_json(payload)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rechain(rows))})
    return reseal_manifest(members)


def attack_truncate(members: dict[str, bytes]) -> dict[str, bytes]:
    rows = split_jsonl(members['ledger.jsonl'])[:-1]
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows)})
    return reseal_manifest(members)


def attack_strip_anchors(members: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(members, **{'anchors.jsonl': b''})
    return reseal_manifest(members)


def resign_with_ed25519(members: dict[str, bytes], ed25519_key: Path,
                        downgrade: bool) -> dict[str, bytes]:
    """Rewrite entry 2, re-chain, and re-sign every anchor with the stolen Ed25519 key.

    The ML-DSA-65 key is NOT available to this attacker: either the old
    post-quantum signatures are kept (they no longer match), or, with
    downgrade=True, they are stripped and anchors are relabelled rf.anchor.v2.
    """
    from cryptography.hazmat.primitives import serialization
    private = serialization.load_pem_private_key(ed25519_key.read_bytes(), password=None)
    rows = split_jsonl(members['ledger.jsonl'])
    payload = json.loads(rows[1]['payload'])
    payload['n'] = 999_999
    rows[1]['payload'] = canonical_json(payload)
    rows = rechain(rows)
    heads = [ZERO_HASH] + [row['entry_hash'] for row in rows]
    previous = ZERO_HASH
    anchors = []
    for anchor in split_jsonl(members['anchors.jsonl']):
        anchor = dict(anchor, ledger_head=heads[anchor['ledger_count']], prev_anchor_hash=previous)
        if downgrade and anchor.get('schema') == ANCHOR_V3:
            anchor['schema'] = 'rf.anchor.v2'
            anchor.pop('pq_key_id', None)
            anchor.pop('pq_signature', None)
        fields = ANCHOR_CORE_V3 if anchor.get('schema') == ANCHOR_V3 else ANCHOR_CORE_V2
        anchor['anchor_hash'] = sha256_hex(canonical_json({k: anchor[k] for k in fields}).encode('utf-8'))
        signature = private.sign(anchor['anchor_hash'].encode('ascii'))
        anchor['signature'] = base64.b64encode(signature).decode('ascii')
        previous = anchor['anchor_hash']
        anchors.append(anchor)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows), 'anchors.jsonl': join_jsonl(anchors)})
    return reseal_manifest(members)


def run_demo(workdir: Path, entries: int) -> dict[str, Any]:
    if entries < 3:
        raise DemoError('--entries must be at least 3')
    operator_anchor = build_ledger(workdir / 'operator', entries, 'operator')
    bundle = workdir / 'evidence.zip'
    manifest = export_bundle(workdir / 'operator', bundle)

    key_id = manifest['key_id']
    pq_key_id = manifest.get('pq_key_id')
    key_pins = ['--pin-key-id', key_id]
    if pq_key_id:
        key_pins += ['--pin-pq-key-id', pq_key_id, '--require-pq']
    pin_args = key_pins + ['--pin-anchor',
                           f"{operator_anchor['seq']}:{operator_anchor['anchor_hash']}"]
    original = read_bundle(bundle)
    results: list[dict[str, Any]] = []

    def check(name: str, path: Path, pins: Sequence[str], expect_code: int,
              expect_trust: str | None = None) -> None:
        code, report = verify(path, pins)
        held = code == expect_code and (expect_trust is None or report.get('trust_level') == expect_trust)
        outcome = (f"VERIFIED ({report.get('trust_level')})" if report.get('status') == 'VERIFIED'
                   else f"REJECTED: {report.get('error')}")
        results.append({'check': name, 'expected_exit': expect_code, 'exit': code,
                        'outcome': outcome, 'held': held})

    check('honest bundle, operator pins held externally', bundle, pin_args, 0, 'anchor_pinned')
    check('honest bundle, no pins (self-consistency only)', bundle, [], 10, 'internal_only')

    attacks: list[tuple[str, Callable[[dict[str, bytes]], dict[str, bytes]]]] = [
        ('edit past entry, keep stored hashes + reseal manifest', attack_edit_keep_hashes),
        ('edit past entry + recompute every hash + reseal manifest', attack_edit_and_rechain),
        ('delete an anchored entry + reseal manifest', attack_truncate),
        ('strip all signed anchors + reseal manifest', attack_strip_anchors),
    ]
    for index, (name, mutate) in enumerate(attacks, 1):
        forged = workdir / f'attack-{index}.zip'
        write_bundle(forged, mutate(original))
        check(name, forged, pin_args, 1)

    forged_dir = workdir / 'attacker'
    build_ledger(forged_dir, entries, 'attacker')
    forged_bundle = workdir / 'attack-forged-history.zip'
    export_bundle(forged_dir, forged_bundle)
    check('rewrite entire history with attacker key, no pins', forged_bundle, [], 10, 'internal_only')
    check('rewrite entire history with attacker key, operator pins', forged_bundle, pin_args, 1)

    if pq_key_id:
        stolen_ed25519 = workdir / 'operator' / 'signing_key.pem'
        quantum = workdir / 'attack-quantum-forger.zip'
        write_bundle(quantum, resign_with_ed25519(original, stolen_ed25519, downgrade=False))
        check('quantum forger: stolen Ed25519 key, re-sign anchors, key pins only',
              quantum, key_pins, 1)
        stripped = workdir / 'attack-pq-downgrade.zip'
        write_bundle(stripped, resign_with_ed25519(original, stolen_ed25519, downgrade=True))
        check('downgrade: strip ML-DSA-65 signatures, re-sign Ed25519, key pins only',
              stripped, key_pins, 1)
    return {'results': results, 'post_quantum': 'hybrid ML-DSA-65' if pq_key_id else 'unavailable',
            'pq_key_id': pq_key_id}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='RightsFrames tamper-evidence demo.')
    parser.add_argument('--entries', type=int, default=5)
    parser.add_argument('--keep', metavar='DIR', help='keep bundles in DIR (must not exist)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    try:
        if args.keep:
            workdir = Path(args.keep)
            workdir.mkdir(parents=True, exist_ok=False)
            outcome = run_demo(workdir, args.entries)
        else:
            with tempfile.TemporaryDirectory(prefix='rf-demo-', ignore_cleanup_errors=True) as tmp:
                outcome = run_demo(Path(tmp), args.entries)
    except (DemoError, OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f'rf-demo: error: {exc}', file=sys.stderr)
        return 1

    results = outcome['results']
    passed = all(item['held'] for item in results)
    if args.json:
        print(json.dumps({'passed': passed, 'post_quantum': outcome['post_quantum'],
                          'results': results}, sort_keys=True))
    else:
        print(f"post-quantum anchor signatures: {outcome['post_quantum']}"
              + ('' if outcome['pq_key_id'] else
                 ' (ML-DSA-65 missing from this cryptography build, or RF_PQ_SIGNING=off;'
                 ' post-quantum attacks skipped)') + '\n')
        width = max(len(item['check']) for item in results)
        for item in results:
            mark = 'PASS' if item['held'] else 'FAIL'
            print(f"[{mark}] {item['check']:<{width}}  exit={item['exit']}  {item['outcome']}")
        print(f"\n{sum(i['held'] for i in results)}/{len(results)} expectations held"
              + ('' if passed else ' -- DEMO FAILED'))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
