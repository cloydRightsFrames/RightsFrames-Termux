from __future__ import annotations

import hashlib


LEAF_DOMAIN = b"RightsFrames-Merkle-Leaf-v1\x00"
NODE_DOMAIN = b"RightsFrames-Merkle-Node-v1\x00"
EMPTY_DOMAIN = b"RightsFrames-Merkle-Empty-v1\x00"


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(
        LEAF_DOMAIN + data
    ).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(
        NODE_DOMAIN + left + right
    ).digest()


def compute_merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(EMPTY_DOMAIN).digest()

    level = [hash_leaf(item) for item in leaves]

    # An odd trailing node is carried up unchanged, never paired with a copy of
    # itself: duplicating it would give [a, b, c] and [a, b, c, c] the same root
    # (CVE-2012-2459). Carrying it up yields the RFC 9162 tree shape.
    while len(level) > 1:
        paired = [
            hash_node(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) & 1:
            paired.append(level[-1])
        level = paired

    return level[0]
