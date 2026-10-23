"""Domain-separated SHA-256 Merkle roots for signed release manifests.

v2 (current): RFC 9162 tree shape (split at the largest power of two below n). An odd node is
never duplicated, so distinct leaf lists cannot share a root.

v1 (legacy, verification only): duplicated the last node of odd levels, so [a, b, c] and
[a, b, c, c] produced the same root (CVE-2012-2459 class). Kept solely so manifests signed
before the fix still verify; their file lists are covered by the signature, which is what
actually binds them.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_DOMAIN = b"RightsFrames-Merkle-Leaf-v2\x00"
NODE_DOMAIN = b"RightsFrames-Merkle-Node-v2\x00"
EMPTY_DOMAIN = b"RightsFrames-Merkle-Empty-v2\x00"

LEGACY_LEAF_DOMAIN = b"RightsFrames-Merkle-Leaf-v1\x00"
LEGACY_NODE_DOMAIN = b"RightsFrames-Merkle-Node-v1\x00"
LEGACY_EMPTY_DOMAIN = b"RightsFrames-Merkle-Empty-v1\x00"


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _root(nodes: Sequence[bytes]) -> bytes:
    n = len(nodes)
    if n == 1:
        return nodes[0]
    k = 1
    while k << 1 < n:
        k <<= 1
    return hash_node(_root(nodes[:k]), _root(nodes[k:]))


def compute_merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(EMPTY_DOMAIN).digest()
    return _root([hash_leaf(item) for item in leaves])


def compute_legacy_merkle_root(leaves: list[bytes]) -> bytes:
    """v1 construction. Verification of pre-fix manifests only; never use for new data."""
    if not leaves:
        return hashlib.sha256(LEGACY_EMPTY_DOMAIN).digest()
    level = [hashlib.sha256(LEGACY_LEAF_DOMAIN + item).digest() for item in leaves]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [
            hashlib.sha256(LEGACY_NODE_DOMAIN + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0]
