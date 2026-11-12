"""RFC 9162 (Certificate Transparency v2) Merkle tree over RightsFrames entry hashes.

The tree commits to the ordered list of ledger entry hashes 1..N. Each leaf is the
raw 32-byte SHA-256 entry hash (decoded from its hex form), hashed with the RFC 9162
domain separation that prevents second-preimage attacks between leaves and nodes:

    leaf  = SHA-256(0x00 || entry_hash_bytes)
    node  = SHA-256(0x01 || left || right)
    empty = SHA-256("")

The tree shape is the RFC 9162 one (split at the largest power of two below N); an odd
node is never duplicated, so two different leaf lists cannot share a root
(CVE-2012-2459 class ambiguity). An inclusion path for leaf m in a tree of size N
lets anyone holding only that entry, the path and a signed root prove membership in
O(log N) hashes without seeing any other entry.

This module imports nothing from RightsFrames. verifier/rf_verify.py carries its own
independent re-implementation of the verification half.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, Sequence

_HEX64 = re.compile(r'^[0-9a-f]{64}\Z')
EMPTY_ROOT = hashlib.sha256(b'').hexdigest()
MAX_PATH_LENGTH = 64


def _entry_bytes(entry_hash: str) -> bytes:
    if not isinstance(entry_hash, str) or not _HEX64.match(entry_hash):
        raise ValueError('entry hash must be 64 lowercase hex characters')
    return bytes.fromhex(entry_hash)


def leaf_hash(entry_hash: str) -> bytes:
    return hashlib.sha256(b'\x00' + _entry_bytes(entry_hash)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b'\x01' + left + right).digest()


class CompactRange:
    """Incremental tree builder: append leaves in order, read the root at any size.

    Holds one hash per set bit of the size (the perfect-subtree peaks), so a root can
    be taken after every append in O(log N) without rebuilding the tree.
    """

    __slots__ = ('_peaks', 'size')

    def __init__(self) -> None:
        self._peaks: list[tuple[int, bytes]] = []
        self.size = 0

    def append_leaf(self, leaf: bytes) -> None:
        height, digest = 0, leaf
        while self._peaks and self._peaks[-1][0] == height:
            _, left = self._peaks.pop()
            digest = node_hash(left, digest)
            height += 1
        self._peaks.append((height, digest))
        self.size += 1

    def append(self, entry_hash: str) -> None:
        self.append_leaf(leaf_hash(entry_hash))

    def root_bytes(self) -> bytes:
        if not self._peaks:
            return hashlib.sha256(b'').digest()
        digest = self._peaks[-1][1]
        for _, left in reversed(self._peaks[:-1]):
            digest = node_hash(left, digest)
        return digest

    def root(self) -> str:
        return self.root_bytes().hex()


def merkle_root(entry_hashes: Iterable[str]) -> str:
    tree = CompactRange()
    for entry_hash in entry_hashes:
        tree.append(entry_hash)
    return tree.root()


def roots_at(entry_hashes: Sequence[str], sizes: Iterable[int]) -> dict[int, str]:
    """Return {size: root} for each requested prefix size in one pass over the leaves."""
    wanted = sorted(set(sizes))
    if wanted and (wanted[0] < 0 or wanted[-1] > len(entry_hashes)):
        raise ValueError('requested tree size outside the ledger')
    result: dict[int, str] = {}
    tree = CompactRange()
    position = 0
    for size in wanted:
        while tree.size < size:
            tree.append(entry_hashes[position])
            position += 1
        result[size] = tree.root()
    return result


def _largest_power_of_two_below(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def _subtree_root(leaves: Sequence[bytes], lo: int, hi: int) -> bytes:
    tree = CompactRange()
    for index in range(lo, hi):
        tree.append_leaf(leaves[index])
    return tree.root_bytes()


def inclusion_path(entry_hashes: Sequence[str], index: int) -> list[str]:
    """RFC 9162 section 2.1.3.1 PATH(m, D[n]) for leaf `index` (0-based), as hex strings."""
    size = len(entry_hashes)
    if not 0 <= index < size:
        raise IndexError('leaf index outside the tree')
    leaves = [leaf_hash(item) for item in entry_hashes]
    path: list[bytes] = []
    lo, hi, target = 0, size, index
    while hi - lo > 1:
        split = lo + _largest_power_of_two_below(hi - lo)
        if target < split:
            path.append(_subtree_root(leaves, split, hi))
            hi = split
        else:
            path.append(_subtree_root(leaves, lo, split))
            lo = split
    return [item.hex() for item in reversed(path)]


def root_from_inclusion_path(entry_hash: str, index: int, size: int,
                             path: Sequence[str]) -> str:
    """RFC 9162 section 2.1.3.2: recompute the root implied by an inclusion path.

    Raises ValueError for any structurally invalid proof (wrong length, bad index,
    malformed hashes), so a caller can never confuse "invalid" with "different root".
    """
    if not isinstance(index, int) or isinstance(index, bool) or not isinstance(size, int) \
            or isinstance(size, bool):
        raise ValueError('leaf index and tree size must be integers')
    if not 0 <= index < size:
        raise ValueError('leaf index outside the tree')
    if not isinstance(path, (list, tuple)) or len(path) > MAX_PATH_LENGTH:
        raise ValueError('inclusion path is malformed')
    fn, sn = index, size - 1
    digest = leaf_hash(entry_hash)
    for item in path:
        if not isinstance(item, str) or not _HEX64.match(item):
            raise ValueError('inclusion path element is malformed')
        sibling = bytes.fromhex(item)
        if sn == 0:
            raise ValueError('inclusion path is longer than the tree requires')
        if fn & 1 or fn == sn:
            digest = node_hash(sibling, digest)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            digest = node_hash(digest, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError('inclusion path is shorter than the tree requires')
    return digest.hex()


def verify_inclusion(entry_hash: str, index: int, size: int, path: Sequence[str],
                     root: str) -> bool:
    try:
        computed = root_from_inclusion_path(entry_hash, index, size, path)
    except ValueError:
        return False
    return isinstance(root, str) and computed == root
