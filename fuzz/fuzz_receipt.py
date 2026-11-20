#!/usr/bin/env python3
"""Fuzz target: rf.receipt.v1 single-entry inclusion receipts through the independent verifier.

    python fuzz/fuzz_receipt.py -max_total_time=60

Fails if `verify_receipt` raises anything but VerificationError, or accepts a receipt whose
entry or anchor differs from the genuine ledger (see fuzz/_harness.py).
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from typing import Any

import atheris

import _harness

WORLD = _harness.World()
sys.path.insert(0, str(_harness.ROOT / 'verifier'))
with atheris.instrument_imports(include=['rf_verify']):
    import rf_verify

PIN_MODES: tuple[dict[str, Any], ...] = (
    {},
    {'pin_key_id': WORLD.key_id, 'pin_pq_key_id': WORLD.pq_key_id},
    {'pin_key_id': WORLD.key_id, 'pin_pq_key_id': WORLD.pq_key_id, 'pin_anchors': WORLD.pins},
)


def _rehash_entry(doc: Any, _rng: random.Random) -> None:
    """Recompute entry_hash so a mutated entry gets past the hash check to the Merkle path."""
    entry = doc.get('entry') if isinstance(doc, dict) else None
    if isinstance(entry, dict):
        material = '|'.join(str(entry.get(name)) for name in ('id', 'prev_hash', 'ts', 'entry_type', 'payload'))
        entry['entry_hash'] = hashlib.sha256(material.encode('utf-8', 'replace')).hexdigest()


def _rehash_anchor(doc: Any, _rng: random.Random) -> None:
    """Recompute anchor_hash so a mutated anchor gets past the hash check to the signatures."""
    anchor = doc.get('anchor') if isinstance(doc, dict) else None
    if isinstance(anchor, dict):
        core = {name: anchor.get(name) for name in rf_verify.ANCHOR_CORE_V4}
        text = json.dumps(core, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        anchor['anchor_hash'] = hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()


def _realign(doc: Any, _rng: random.Random) -> None:
    """Make tree_size and leaf_index agree with the (possibly mutated) anchor and entry."""
    if isinstance(doc, dict) and isinstance(doc.get('anchor'), dict) and isinstance(doc.get('entry'), dict):
        doc['tree_size'] = doc['anchor'].get('ledger_count')
        entry_id = doc['entry'].get('id')
        doc['leaf_index'] = entry_id - 1 if isinstance(entry_id, int) else entry_id


def test_one_input(data: bytes) -> None:
    pins = PIN_MODES[len(data) % len(PIN_MODES)]
    try:
        report = rf_verify.verify_receipt(WORLD.write(data), **pins)
    except rf_verify.VerificationError:
        return
    doc = json.loads(data)
    anchor = _harness.anchor_at(WORLD.anchors, doc.get('anchor'), 'receipt anchor')
    entry = doc.get('entry')
    entry_id = entry.get('id') if isinstance(entry, dict) else None
    if not isinstance(entry_id, int) or isinstance(entry_id, bool) or not 1 <= entry_id <= anchor['ledger_count']:
        raise AssertionError(f'FORGERY ACCEPTED: receipt for entry {entry_id!r} outside anchor {anchor["seq"]}')
    genuine = WORLD.entries[entry_id - 1]
    _harness.require_genuine(entry, genuine, 'receipt entry')
    if (report.get('status'), report.get('entry_hash'), report.get('anchor_hash')) != (
            'VERIFIED', genuine['entry_hash'], anchor['anchor_hash']):
        raise AssertionError(f'verifier report does not describe the genuine entry and anchor: {report}')


if __name__ == '__main__':
    _harness.run(test_one_input, [_harness.dumps(receipt) for receipt in WORLD.receipts],
                 _harness.JsonMutator(fixups=(_rehash_entry, _rehash_anchor, _realign)))
