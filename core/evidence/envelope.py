"""Evidence envelope (rf.evidence.v1) and the RightsFrames canonical JSON profile.

Canonical JSON profile (rf-cjson-1), used for every hashed or signed structure here:

* objects: keys MUST be strings; output sorted by Unicode code point; no duplicate keys
* arrays: order preserved (tuples are encoded as arrays)
* integers: only within the I-JSON safe range |n| <= 2**53 - 1
* floats, NaN and Infinity: rejected (binary floats have no single canonical text form)
* booleans and null: as JSON literals
* strings: UTF-8, not ASCII-escaped, no lone surrogates, no Unicode normalisation applied
* separators ',' and ':' with no whitespace; maximum nesting depth 64

Anything outside the profile raises CanonicalizationError (a TypeError subclass) instead of
being silently coerced: coercion is how two different documents end up with one digest.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

SCHEMA = 'rf.evidence.v1'
HASH_ALGORITHM = 'sha256'
CANONICAL_PROFILE = 'rf-cjson-1'
MAX_SAFE_INTEGER = 2 ** 53 - 1
MAX_DEPTH = 64


class CanonicalizationError(TypeError):
    """Value cannot be represented in the canonical JSON profile."""


def _normalize(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise CanonicalizationError('nesting depth exceeds limit')
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f'object key must be str, not {type(key).__name__}')
        return {key: _normalize(value[key], depth + 1) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            return value
        raise CanonicalizationError('integer outside the I-JSON safe range')
    if isinstance(value, str):
        try:
            value.encode('utf-8')
        except UnicodeEncodeError:
            raise CanonicalizationError('string contains a lone surrogate') from None
        return value
    if isinstance(value, float):
        raise CanonicalizationError('float values are not canonical; encode as string or integer')
    raise CanonicalizationError(type(value).__name__)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True,
        allow_nan=False,
    ).encode('utf-8')


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key {key!r}')
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f'non-finite JSON constant {name}')


def _reject_float(text: str) -> Any:
    raise ValueError(f'float literal {text} is not canonical')


def loads_strict(text: str | bytes) -> Any:
    """Parse JSON for verification: rejects duplicate keys, NaN/Infinity and floats.

    The standard parser keeps the LAST duplicate key; another consumer may keep the first.
    Verifying one interpretation while acting on the other is a parser-differential attack.
    """
    if isinstance(text, bytes):
        text = text.decode('utf-8')
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
        parse_float=_reject_float,
    )


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
    for name, value in (('tenant_id', tenant_id), ('event_id', event_id),
                        ('event_type', event_type)):
        if not isinstance(value, str) or not value:
            raise ValueError(f'{name} must be a non-empty string')

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
    if not isinstance(envelope, dict):
        return False, 'envelope'

    if envelope.get('schema') != SCHEMA:
        return False, 'schema'

    integrity = envelope.get('integrity')
    if not isinstance(integrity, dict):
        return False, 'integrity'

    if integrity.get('hash_algorithm') != HASH_ALGORITHM:
        return False, 'hash_algorithm'

    expected = integrity.get('payload_digest')
    if not isinstance(expected, str):
        return False, 'payload_digest'

    unsigned = dict(envelope)
    unsigned_integrity = dict(integrity)
    unsigned_integrity.pop('payload_digest', None)
    unsigned['integrity'] = unsigned_integrity

    try:
        actual = sha256(canonical_bytes(unsigned))
    except CanonicalizationError:
        return False, 'non_canonical_value'

    if actual != expected:
        return False, 'payload_digest_mismatch'

    return True, 'valid'
