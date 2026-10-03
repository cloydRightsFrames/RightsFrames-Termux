from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from core.evidence.envelope import canonical_bytes, verify_envelope
from core.evidence.ledger import LedgerRecord, verify_chain
from core.evidence.merkle import MerkleProof, verify_proof
from core.evidence.signing import verify as verify_signature


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def verify_envelope_file(path: Path) -> tuple[bool, str]:
    return verify_envelope(load_json(path))


def verify_ledger_file(path: Path) -> tuple[bool, str]:
    data = load_json(path)

    records = [
        LedgerRecord(
            ledger_sequence=item['ledger_sequence'],
            event_id=item['event_id'],
            payload_digest=item['payload_digest'],
            previous_record_digest=item.get('previous_record_digest'),
            record_digest=item['record_digest'],
        )
        for item in data
    ]

    return verify_chain(records)


def verify_proof_file(path: Path) -> tuple[bool, str]:
    data = load_json(path)

    proof = MerkleProof(
        leaf_index=data['leaf_index'],
        tree_size=data['tree_size'],
        leaf_hash=data['leaf_hash'],
        siblings=tuple(data['siblings']),
    )

    return (
        verify_proof(proof, data['root_hash']),
        'valid' if verify_proof(proof, data['root_hash']) else 'invalid_proof',
    )


def verify_signature_file(path: Path) -> tuple[bool, str]:
    data = load_json(path)

    public_key = bytes.fromhex(data['public_key'])
    payload = bytes.fromhex(data['payload'])

    return verify_signature(
        public_key,
        payload,
        data['signature'],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--envelope')
    parser.add_argument('--ledger')
    parser.add_argument('--proof')
    parser.add_argument('--signature')
    args = parser.parse_args()

    checks: dict[str, tuple[bool, str]] = {}

    if args.envelope:
        checks['ENVELOPE_INTEGRITY'] = verify_envelope_file(Path(args.envelope))

    if args.ledger:
        checks['LEDGER_CONTINUITY'] = verify_ledger_file(Path(args.ledger))

    if args.proof:
        checks['MERKLE_INCLUSION'] = verify_proof_file(Path(args.proof))

    if args.signature:
        checks['SIGNATURE_VALIDITY'] = verify_signature_file(Path(args.signature))

    if not checks:
        parser.error('at least one verification target required')

    failed = False

    for name, (ok, reason) in checks.items():
        print(f'{name}={'PASS' if ok else 'FAIL'}:{reason}')
        failed |= not ok

    print(
        'RIGHTSFRAMES_INDEPENDENT_VERIFIER='
        + ('FAIL' if failed else 'PASS')
    )

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
