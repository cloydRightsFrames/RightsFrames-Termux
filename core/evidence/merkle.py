"""Merkle tree over ledger record digests, following RFC 9162 section 2.1.

Tree hash (MTH), inclusion proofs and consistency proofs use the RFC 9162 construction:

    MTH({})        = SHA-256()
    MTH({d0})      = SHA-256(0x00 || d0)
    MTH(D[n])      = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                     where k is the largest power of two smaller than n

Leaves are the raw 32-byte record digests (``record_digest`` decoded from hex). Unlike the
"duplicate the last node" construction used by rf.merkle.checkpoint.v1, an odd node is never
duplicated, so two different leaf lists can never produce the same root (CVE-2012-2459 class).

All public values are lowercase hex strings.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Sequence

from .envelope import canonical_bytes

MERKLE_SCHEMA = 'rf.merkle.checkpoint.v2'
TREE_ALGORITHM = 'rfc9162-sha256'
LEAF_PREFIX = b'\x00'
NODE_PREFIX = b'\x01'
MAX_TREE_SIZE = 2 ** 62
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


class MerkleError(ValueError):
    """Raised for malformed Merkle input."""


def _digest_bytes(value: str, what: str) -> bytes:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise MerkleError(f'{what} must be 64 lowercase hex characters')
    return bytes.fromhex(value)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_leaf(record_digest: str) -> str:
    return _sha256(LEAF_PREFIX + _digest_bytes(record_digest, 'record digest')).hex()


def hash_node(left: str, right: str) -> str:
    return _sha256(
        NODE_PREFIX + _digest_bytes(left, 'left node') + _digest_bytes(right, 'right node')
    ).hex()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _mth(leaf_hashes: Sequence[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return _sha256(b'')
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return _sha256(NODE_PREFIX + _mth(leaf_hashes[:k]) + _mth(leaf_hashes[k:]))


def _leaf_hashes(record_digests: Sequence[str]) -> list[bytes]:
    if len(record_digests) > MAX_TREE_SIZE:
        raise MerkleError('tree too large')
    return [_sha256(LEAF_PREFIX + _digest_bytes(d, 'record digest')) for d in record_digests]


def merkle_root(record_digests: Sequence[str]) -> str:
    return _mth(_leaf_hashes(record_digests)).hex()


@dataclass(frozen=True)
class MerkleProof:
    leaf_index: int
    tree_size: int
    leaf_hash: str
    siblings: tuple[str, ...]


@dataclass(frozen=True)
class MerkleCheckpoint:
    schema: str
    tree_size: int
    root_hash: str
    previous_root: str | None


def _inclusion_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return _inclusion_path(index, leaves[:k]) + [_mth(leaves[k:])]
    return _inclusion_path(index - k, leaves[k:]) + [_mth(leaves[:k])]


def build_proof(record_digests: Sequence[str], leaf_index: int) -> MerkleProof:
    if not record_digests:
        raise MerkleError('empty tree')
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise MerkleError('leaf index must be an integer')
    if leaf_index < 0 or leaf_index >= len(record_digests):
        raise IndexError('leaf index')
    leaves = _leaf_hashes(record_digests)
    return MerkleProof(
        leaf_index=leaf_index,
        tree_size=len(leaves),
        leaf_hash=leaves[leaf_index].hex(),
        siblings=tuple(node.hex() for node in _inclusion_path(leaf_index, leaves)),
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def verify_proof(proof: MerkleProof, root_hash: str) -> bool:
    """RFC 9162 section 2.1.3.2 inclusion verification. Fails closed on any malformed input."""
    try:
        if not _is_int(proof.tree_size) or not _is_int(proof.leaf_index):
            return False
        if proof.tree_size <= 0 or proof.tree_size > MAX_TREE_SIZE:
            return False
        if proof.leaf_index < 0 or proof.leaf_index >= proof.tree_size:
            return False
        root = _digest_bytes(root_hash, 'root hash')
        current = _digest_bytes(proof.leaf_hash, 'leaf hash')
        path = [_digest_bytes(node, 'sibling') for node in proof.siblings]
    except (MerkleError, AttributeError, TypeError):
        return False

    fn, sn = proof.leaf_index, proof.tree_size - 1
    for sibling in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            current = _sha256(NODE_PREFIX + sibling + current)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            current = _sha256(NODE_PREFIX + current + sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and current == root


def verify_inclusion(record_digest: str, proof: MerkleProof, root_hash: str) -> bool:
    """Inclusion of a specific record digest: the leaf hash is recomputed, never trusted."""
    try:
        expected_leaf = hash_leaf(record_digest)
    except MerkleError:
        return False
    if proof.leaf_hash != expected_leaf:
        return False
    return verify_proof(proof, root_hash)


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [_mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def build_consistency_proof(record_digests: Sequence[str], old_size: int) -> tuple[str, ...]:
    """RFC 9162 section 2.1.4 consistency proof between tree sizes old_size and len(digests)."""
    leaves = _leaf_hashes(record_digests)
    if not _is_int(old_size) or old_size < 0 or old_size > len(leaves):
        raise MerkleError('old size out of range')
    if old_size == 0 or old_size == len(leaves):
        return ()
    return tuple(node.hex() for node in _subproof(old_size, leaves, True))


def verify_consistency(old_size: int, new_size: int, old_root: str, new_root: str,
                       proof: Sequence[str]) -> bool:
    """RFC 9162 section 2.1.4.2. True only if the old tree is a prefix of the new tree."""
    try:
        if not _is_int(old_size) or not _is_int(new_size):
            return False
        if old_size < 0 or new_size < old_size or new_size > MAX_TREE_SIZE:
            return False
        old = _digest_bytes(old_root, 'old root')
        new = _digest_bytes(new_root, 'new root')
        path = [_digest_bytes(node, 'proof node') for node in proof]
    except (MerkleError, TypeError):
        return False

    if old_size == 0:
        # The empty tree is a prefix of every tree; its root is SHA-256 of the empty string.
        return not path and old == _sha256(b'') and (new_size > 0 or new == old)
    if old_size == new_size:
        return not path and old == new
    if not path:
        return False
    if old_size & (old_size - 1) == 0:
        path = [old] + path
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _sha256(NODE_PREFIX + node + fr)
            sr = _sha256(NODE_PREFIX + node + sr)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _sha256(NODE_PREFIX + sr + node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old and sr == new


def build_checkpoint(record_digests: Sequence[str],
                     previous_root: str | None = None) -> MerkleCheckpoint:
    if previous_root is not None:
        _digest_bytes(previous_root, 'previous root')
    return MerkleCheckpoint(
        schema=MERKLE_SCHEMA,
        tree_size=len(record_digests),
        root_hash=merkle_root(record_digests),
        previous_root=previous_root,
    )


def checkpoint_bytes(checkpoint: MerkleCheckpoint) -> bytes:
    """Bytes that a checkpoint signature covers. Binds schema, algorithm, size and roots."""
    return canonical_bytes({
        'schema': checkpoint.schema,
        'tree_algorithm': TREE_ALGORITHM,
        'tree_size': checkpoint.tree_size,
        'root_hash': checkpoint.root_hash,
        'previous_root': checkpoint.previous_root,
    })
