"""Signed Merkle checkpoints (rf.merkle.checkpoint.v2).

A checkpoint commits to the first ``tree_size`` ledger record digests (RFC 9162 tree head)
and to the previous checkpoint root. Its Ed25519 signature covers ``checkpoint_bytes``, which
also binds the tree algorithm. A relying party that pins the signing key id (and ideally the
newest root, held outside the operator's infrastructure) can detect truncation, rollback,
substitution and forked histories with consistency proofs between successive checkpoints.
"""
from __future__ import annotations

from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .merkle import TREE_ALGORITHM, MerkleCheckpoint, build_checkpoint, checkpoint_bytes
from .signing import key_id_for, sign


def checkpoint_document(checkpoint: MerkleCheckpoint) -> dict[str, Any]:
    return {
        'schema': checkpoint.schema,
        'tree_algorithm': TREE_ALGORITHM,
        'tree_size': checkpoint.tree_size,
        'root_hash': checkpoint.root_hash,
        'previous_root': checkpoint.previous_root,
    }


def sign_checkpoint(private_key_bytes: bytes, record_digests: Sequence[str],
                    previous_root: str | None = None) -> dict[str, Any]:
    if len(private_key_bytes) != 32:
        raise ValueError('invalid Ed25519 private key')
    public = Ed25519PrivateKey.from_private_bytes(private_key_bytes).public_key().public_bytes_raw()
    key_id = key_id_for(public)
    checkpoint = build_checkpoint(record_digests, previous_root)
    return {
        'checkpoint': checkpoint_document(checkpoint),
        'public_key': public.hex(),
        'signature': sign(private_key_bytes, checkpoint_bytes(checkpoint), key_id),
    }
