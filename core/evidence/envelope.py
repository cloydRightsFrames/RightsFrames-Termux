from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


SCHEMA = 'rf.evidence.v1'
HASH_ALGORITHM = 'sha256'


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value
    raise TypeError(type(value).__name__)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True,
    ).encode('utf-8')


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_envelope(
    tenant_id: str,
    event_id: str,
    event_type: str,
    source: dict[str, Any],
    observation: dict[str, Any],
    subject: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    authority: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    sequence: dict[str, Any] | None = None,
    classification: dict[str, Any] | None = None,
    retention: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    received_at = utc_now()

    envelope = {
        'schema': SCHEMA,
        'tenant_id': tenant_id,
        'event_id': event_id,
        'event_type': event_type,
        'observed_at': observed_at or received_at,
        'received_at': received_at,
        'source': source,
        'subject': subject or {},
        'actor': actor or {},
        'authority': authority or {},
        'observation': observation,
        'provenance': provenance or {},
        'integrity': {
            'hash_algorithm': HASH_ALGORITHM,
        },
        'sequence': sequence or {},
        'classification': classification or {},
        'retention': retention or {},
    }

    payload = canonical_bytes(envelope)
    envelope['integrity']['payload_digest'] = sha256(payload)

    return envelope


def verify_envelope(envelope: dict[str, Any]) -> tuple[bool, str]:
    if envelope.get('schema') != SCHEMA:
        return False, 'schema'

    integrity = envelope.get('integrity')
    if not isinstance(integrity, dict):
        return False, 'integrity'

    expected = integrity.get('payload_digest')
    if not isinstance(expected, str):
        return False, 'payload_digest'

    unsigned = dict(envelope)
    unsigned_integrity = dict(integrity)
    unsigned_integrity.pop('payload_digest', None)
    unsigned['integrity'] = unsigned_integrity

    actual = sha256(canonical_bytes(unsigned))

    if actual != expected:
        return False, 'payload_digest_mismatch'

    return True, 'valid'
