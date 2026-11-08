from __future__ import annotations

from dataclasses import dataclass

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

        # An odd trailing node is carried up unchanged rather than hashed with a
        # copy of itself, so no two leaf lists share a root (CVE-2012-2459) and
        # the tree has the RFC 9162 shape.
        for index in range(0, len(current) - 1, 2):
            nxt.append(hash_node(current[index], current[index + 1]))
        if len(current) & 1:
            nxt.append(current[-1])

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
    width = proof.tree_size
    siblings = iter(proof.siblings)

    while width > 1:
        if index & 1:
            sibling = next(siblings, None)
            if sibling is None:
                return False
            current = hash_node(sibling, current)
        elif index + 1 < width:
            sibling = next(siblings, None)
            if sibling is None:
                return False
            current = hash_node(current, sibling)
        # else: the last node of an odd level is carried up without a sibling.

        index //= 2
        width = (width + 1) // 2

    if next(siblings, None) is not None:
        return False

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
