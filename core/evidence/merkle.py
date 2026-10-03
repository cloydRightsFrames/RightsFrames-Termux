from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .envelope import canonical_bytes, sha256


MERKLE_SCHEMA = 'rf.merkle.checkpoint.v1'


def hash_leaf(record_digest: str) -> str:
    return sha256(b'\x00' + record_digest.encode('ascii'))


def hash_node(left: str, right: str) -> str:
    return sha256(
        b'\x01' +
        left.encode('ascii') +
        right.encode('ascii')
    )


def _levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return [[]]

    levels = [leaves]

    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt: list[str] = []

        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            nxt.append(hash_node(left, right))

        levels.append(nxt)

    return levels


def merkle_root(record_digests: list[str]) -> str:
    if not record_digests:
        return sha256(b'')

    leaves = [hash_leaf(digest) for digest in record_digests]
    return _levels(leaves)[-1][0]


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


def build_proof(record_digests: list[str], leaf_index: int) -> MerkleProof:
    if not record_digests:
        raise ValueError('empty tree')

    if leaf_index < 0 or leaf_index >= len(record_digests):
        raise IndexError('leaf index')

    levels = _levels([hash_leaf(digest) for digest in record_digests])

    siblings: list[str] = []
    index = leaf_index

    for level in levels[:-1]:
        sibling_index = index ^ 1

        if sibling_index < len(level):
            siblings.append(level[sibling_index])
        else:
            siblings.append(level[index])

        index //= 2

    return MerkleProof(
        leaf_index=leaf_index,
        tree_size=len(record_digests),
        leaf_hash=levels[0][leaf_index],
        siblings=tuple(siblings),
    )


def verify_proof(proof: MerkleProof, root_hash: str) -> bool:
    if proof.tree_size <= 0:
        return False

    if proof.leaf_index < 0 or proof.leaf_index >= proof.tree_size:
        return False

    current = proof.leaf_hash
    index = proof.leaf_index

    for sibling in proof.siblings:
        if index & 1:
            current = hash_node(sibling, current)
        else:
            current = hash_node(current, sibling)

        index //= 2

    return current == root_hash


def build_checkpoint(
    record_digests: list[str],
    previous_root: str | None = None,
) -> MerkleCheckpoint:
    root = merkle_root(record_digests)

    return MerkleCheckpoint(
        schema=MERKLE_SCHEMA,
        tree_size=len(record_digests),
        root_hash=root,
        previous_root=previous_root,
    )


def checkpoint_bytes(checkpoint: MerkleCheckpoint) -> bytes:
    return canonical_bytes({
        'schema': checkpoint.schema,
        'tree_size': checkpoint.tree_size,
        'root_hash': checkpoint.root_hash,
        'previous_root': checkpoint.previous_root,
    })
