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

    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])

        level = [
            hash_node(level[i], level[i + 1])
            for i in range(0, len(level), 2)
        ]

    return level[0]
