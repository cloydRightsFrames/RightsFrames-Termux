#!/usr/bin/env python3
"""Fuzz target: rf.evidence.v1 / v2 evidence bundles (ZIP) through the independent verifier.

    python fuzz/fuzz_bundle.py -max_total_time=60

An input is either a JSON description of a bundle, which this target packs into a ZIP
(so member contents can be mutated and, optionally, the manifest's hashes brought back
in line with them), or raw bytes handed to the verifier as the ZIP file itself.

Fails if `verify_bundle` raises anything but VerificationError, or accepts a bundle whose
anchors or anchored entries differ from the genuine ledger (see fuzz/_harness.py).
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import warnings
import zipfile
from typing import Any

import atheris

import _harness

WORLD = _harness.World()
sys.path.insert(0, str(_harness.ROOT / 'verifier'))
with atheris.instrument_imports(include=['rf_verify']):
    import rf_verify

warnings.simplefilter('ignore')  # zipfile warns about the duplicate member names we create on purpose
COMPRESSION = (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA)
HYBRID_PINS = {'pin_key_id': WORLD.key_id, 'pin_pq_key_id': WORLD.pq_key_id}
PIN_MODES: tuple[dict[str, Any], ...] = (
    {},
    HYBRID_PINS,
    {**HYBRID_PINS, 'pin_anchors': WORLD.pins, 'require_pq': True},
    {**HYBRID_PINS, 'pin_anchors': WORLD.pins[-1:], 'require_full_pin': True},
    {'pin_key_id': WORLD.legacy_key_id,
     'pin_anchors': [(anchor['seq'], anchor['anchor_hash']) for anchor in WORLD.legacy_anchors]},
    {'min_anchors': 1},
)


def describe(bundle: bytes) -> bytes:
    """A genuine bundle as the JSON description this target mutates (bytes kept exact via latin-1)."""
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        members = [[name, archive.read(name).decode('latin-1')] for name in archive.namelist()]
    return _harness.dumps({'members': members, 'fix': 0, 'compression': 0})


def _fix_manifest(members: list[tuple[str, bytes]], level: int) -> list[tuple[str, bytes]]:
    """Bring the manifest's hashes (1) and ledger summary (2) back in line with mutated members."""
    try:
        manifest = json.loads(dict(members)['manifest.json'])
        if not isinstance(manifest, dict):
            return members
        others = {name: blob for name, blob in members if name != 'manifest.json'}
        manifest['files'] = {name: {'sha256': hashlib.sha256(blob).hexdigest(), 'bytes': len(blob)}
                             for name, blob in others.items()}
        if level >= 2:
            lines = [line for line in others.get('ledger.jsonl', b'').split(b'\n') if line]
            manifest['ledger_count'] = len(lines)
            manifest['ledger_head'] = json.loads(lines[-1])['entry_hash'] if lines else '0' * 64
            manifest['anchor_count'] = len([line for line in others.get('anchors.jsonl', b'').split(b'\n') if line])
        text = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
    except (ValueError, KeyError, TypeError, RecursionError):
        return members
    return [(name, text.encode('utf-8') if name == 'manifest.json' else blob) for name, blob in members]


def build(data: bytes) -> bytes:
    """The ZIP a description stands for; anything that is not a description is the ZIP itself."""
    try:
        description = json.loads(data)
        members = [(str(name), content.encode('latin-1', 'replace'))
                   for name, content in description['members'] if isinstance(content, str)]
        level, method = description.get('fix'), description.get('compression')
        if isinstance(level, int) and not isinstance(level, bool) and level > 0:
            members = _fix_manifest(members, level)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name, blob in members:
                info = zipfile.ZipInfo(name)
                info.compress_type = COMPRESSION[method % len(COMPRESSION)] if isinstance(method, int) else 0
                archive.writestr(info, blob)
        return buffer.getvalue()
    except Exception:  # not a usable description: fuzz the ZIP reader with the raw bytes instead
        return data


def _lines(blob: bytes) -> list[Any]:
    return [json.loads(line) for line in blob.decode('utf-8').split('\n') if line]


def test_one_input(data: bytes) -> None:
    bundle = build(data)
    pins = PIN_MODES[len(data) % len(PIN_MODES)]
    try:
        report = rf_verify.verify_bundle(WORLD.write(bundle), **pins)
    except rf_verify.VerificationError:
        return
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        anchors = _lines(archive.read('anchors.jsonl'))
        entries = _lines(archive.read('ledger.jsonl'))
    if report.get('status') != 'VERIFIED' or report.get('anchors') != len(anchors):
        raise AssertionError(f'verifier report does not describe the bundle: {report}')
    if not anchors:
        return  # an unsigned ledger is accepted as internal_only by design; nothing is claimed for it
    if report.get('key_id') == WORLD.key_id:
        genuine_anchors, genuine_entries = WORLD.anchors, WORLD.entries
    elif report.get('key_id') == WORLD.legacy_key_id:
        genuine_anchors, genuine_entries = WORLD.legacy_anchors, WORLD.legacy_entries
    else:
        raise AssertionError(f'FORGERY ACCEPTED: anchors verified under unknown key {report.get("key_id")}')
    for position, anchor in enumerate(anchors, 1):
        if _harness.anchor_at(genuine_anchors, anchor, 'bundle anchor')['seq'] != position:
            raise AssertionError(f'verifier accepted anchor {anchor.get("seq")} at position {position}')
    covered = anchors[-1]['ledger_count']
    _harness.require_genuine(entries[:covered], genuine_entries[:covered], 'anchored ledger prefix')
    if 'pin_anchors' in pins and report.get('trust_level') != 'anchor_pinned':
        raise AssertionError(f'pinned bundle not reported as anchor_pinned: {report}')


if __name__ == '__main__':
    _harness.run(test_one_input,
                 [describe(WORLD.bundle), describe(WORLD.legacy_bundle), WORLD.bundle, WORLD.legacy_bundle],
                 _harness.JsonMutator())
