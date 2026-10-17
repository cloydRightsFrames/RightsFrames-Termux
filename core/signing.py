from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sign_data(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_signature(
    public_key: Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
