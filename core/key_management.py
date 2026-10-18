from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(private_key, filepath):
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    path.write_bytes(data)
    os.chmod(path, 0o600)


def load_private_key(filepath):
    key = serialization.load_pem_private_key(
        Path(filepath).read_bytes(),
        password=None,
    )

    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected Ed25519 private key")

    return key


def save_public_key(public_key, filepath):
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    path.write_bytes(data)
    os.chmod(path, 0o600)


def load_public_key(filepath):
    key = serialization.load_pem_public_key(
        Path(filepath).read_bytes()
    )

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected Ed25519 public key")

    return key
