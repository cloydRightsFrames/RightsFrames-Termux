from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .envelope import canonical_bytes, sha256


LEDGER_SCHEMA = 'rf.ledger.record.v1'


@dataclass(frozen=True)
class LedgerRecord:
    ledger_sequence: int
    event_id: str
    payload_digest: str
    previous_record_digest: str | None
    record_digest: str


def record_material(
    ledger_sequence: int,
    event_id: str,
    payload_digest: str,
    previous_record_digest: str | None,
) -> dict[str, Any]:
    return {
        'schema': LEDGER_SCHEMA,
        'ledger_sequence': ledger_sequence,
        'event_id': event_id,
        'payload_digest': payload_digest,
        'previous_record_digest': previous_record_digest,
    }


def build_record(
    ledger_sequence: int,
    event_id: str,
    payload_digest: str,
    previous_record_digest: str | None = None,
) -> LedgerRecord:
    if ledger_sequence < 0:
        raise ValueError('ledger sequence must be non-negative')

    if not event_id:
        raise ValueError('event_id required')

    if len(payload_digest) != 64:
        raise ValueError('payload digest must be sha256')

    if previous_record_digest is not None and len(previous_record_digest) != 64:
        raise ValueError('previous record digest must be sha256')

    material = record_material(
        ledger_sequence,
        event_id,
        payload_digest,
        previous_record_digest,
    )

    digest = sha256(canonical_bytes(material))

    return LedgerRecord(
        ledger_sequence=ledger_sequence,
        event_id=event_id,
        payload_digest=payload_digest,
        previous_record_digest=previous_record_digest,
        record_digest=digest,
    )


def verify_chain(records: list[LedgerRecord]) -> tuple[bool, str]:
    if not records:
        return True, 'empty'

    previous: LedgerRecord | None = None

    for expected_sequence, record in enumerate(records):
        if record.ledger_sequence != expected_sequence:
            return False, 'sequence_gap'

        expected_previous = previous.record_digest if previous else None

        if record.previous_record_digest != expected_previous:
            return False, 'previous_digest_mismatch'

        rebuilt = build_record(
            ledger_sequence=record.ledger_sequence,
            event_id=record.event_id,
            payload_digest=record.payload_digest,
            previous_record_digest=record.previous_record_digest,
        )

        if rebuilt.record_digest != record.record_digest:
            return False, 'record_digest_mismatch'

        previous = record

    return True, 'valid'
