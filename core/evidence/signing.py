from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITHM = 'Ed25519'
SIGNATURE_SCHEMA = 'rf.signature.v1'


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes_raw(),
        public_key.public_bytes_raw(),
    )


def sign(private_key_bytes: bytes, payload: bytes, key_id: str) -> dict[str, Any]:
    if len(private_key_bytes) != 32:
        raise ValueError('invalid Ed25519 private key')

    signature = Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    ).sign(payload)

    return {
        'schema': SIGNATURE_SCHEMA,
        'algorithm': ALGORITHM,
        'key_id': key_id,
        'signature': _b64(signature),
    }


def verify(
    public_key_bytes: bytes,
    payload: bytes,
    signature: dict[str, Any],
) -> tuple[bool, str]:
    if signature.get('schema') != SIGNATURE_SCHEMA:
        return False, 'schema'

    if signature.get('algorithm') != ALGORITHM:
        return False, 'algorithm'

    if not isinstance(signature.get('key_id'), str):
        return False, 'key_id'

    encoded = signature.get('signature')
    if not isinstance(encoded, str):
        return False, 'signature'

    try:
        raw_signature = _unb64(encoded)
        if len(public_key_bytes) != 32 or len(raw_signature) != 64:
            return False, 'encoding'

        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            raw_signature,
            payload,
        )
    except (ValueError, InvalidSignature):
        return False, 'invalid_signature'

    return True, 'valid'
