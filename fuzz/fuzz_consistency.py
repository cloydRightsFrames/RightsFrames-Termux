#!/usr/bin/env python3
"""Fuzz target: rf.consistency.v1 append-only proofs through the independent verifier.

    python fuzz/fuzz_consistency.py -max_total_time=60

Fails if `verify_consistency` raises anything but VerificationError, or accepts a proof whose
anchors differ from the genuine ones or are not in order (see fuzz/_harness.py).
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


def _rehash_anchors(doc: Any, rng: random.Random) -> None:
    """Recompute an anchor_hash so a mutated anchor gets past the hash check to the signatures."""
    if not isinstance(doc, dict):
        return
    anchor = doc.get(rng.choice(('first_anchor', 'second_anchor')))
    if isinstance(anchor, dict):
        core = {name: anchor.get(name) for name in rf_verify.ANCHOR_CORE_V4}
        text = json.dumps(core, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        anchor['anchor_hash'] = hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()


def _swap_anchors(doc: Any, _rng: random.Random) -> None:
    if isinstance(doc, dict) and 'first_anchor' in doc and 'second_anchor' in doc:
        doc['first_anchor'], doc['second_anchor'] = doc['second_anchor'], doc['first_anchor']


def test_one_input(data: bytes) -> None:
    pins = PIN_MODES[len(data) % len(PIN_MODES)]
    try:
        report = rf_verify.verify_consistency(WORLD.write(data), **pins)
    except rf_verify.VerificationError:
        return
    doc = json.loads(data)
    first = _harness.anchor_at(WORLD.anchors, doc.get('first_anchor'), 'first anchor')
    second = _harness.anchor_at(WORLD.anchors, doc.get('second_anchor'), 'second anchor')
    if first['seq'] >= second['seq']:
        raise AssertionError(f'verifier accepted a proof from anchor {first["seq"]} to {second["seq"]}')
    expected = ('VERIFIED', first['anchor_hash'], second['anchor_hash'],
                second['ledger_count'] - first['ledger_count'], f'{second["seq"]}:{second["anchor_hash"]}')
    if (report.get('status'), report.get('first_anchor_hash'), report.get('second_anchor_hash'),
            report.get('appended_entries'), report.get('next_pin')) != expected:
        raise AssertionError(f'verifier report does not describe the genuine anchors: {report}')


if __name__ == '__main__':
    _harness.run(test_one_input, [_harness.dumps(proof) for proof in WORLD.proofs],
                 _harness.JsonMutator(fixups=(_rehash_anchors, _swap_anchors)))
