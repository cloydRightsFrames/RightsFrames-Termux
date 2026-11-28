#!/usr/bin/env python3
"""Fuzz target: the two RFC 9162 Merkle implementations against each other.

    python fuzz/fuzz_merkle.py -max_total_time=60

`core/rf_merkle.py` builds and checks inclusion and consistency paths; the verifier carries
its own implementation of the checking half. For any tree, any position and any (mutated)
path they must agree: both compute the same root(s) or both reject. Honest paths built by
the core must reproduce the real roots in both. Any other exception type is a failure.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable

import atheris

ROOT = Path(__file__).resolve().parents[1]
for sub in ('core', 'verifier'):
    sys.path.insert(0, str(ROOT / sub))
with atheris.instrument_imports(include=['rf_merkle', 'rf_verify']):
    import rf_merkle
    import rf_verify

MAX_LEAVES = 300
LEAVES = [hashlib.sha256(b'rightsframes fuzz leaf %d' % number).hexdigest() for number in range(MAX_LEAVES)]
JUNK: tuple[Any, ...] = (None, 0, True, '', 'zz', '0' * 63, '0' * 65, 'F' * 64, ['0' * 64], {'a': 1}, 1.5)


def _outcome(function: Callable[..., Any], rejection: type[Exception], *args: Any) -> tuple[str, Any]:
    try:
        return 'ok', function(*args)
    except rejection:
        return 'rejected', None


def _mutate_path(fdp: atheris.FuzzedDataProvider, path: list[Any]) -> list[Any]:
    path = list(path)
    for _ in range(fdp.ConsumeIntInRange(0, 3)):
        choice = fdp.ConsumeIntInRange(0, 6)
        position = fdp.ConsumeIntInRange(0, max(len(path) - 1, 0))
        if choice == 0 and path:
            del path[position]
        elif choice == 1:
            path.insert(position, LEAVES[fdp.ConsumeIntInRange(0, MAX_LEAVES - 1)])
        elif choice == 2 and path:
            path[position] = JUNK[fdp.ConsumeIntInRange(0, len(JUNK) - 1)]
        elif choice == 3 and path and isinstance(path[position], str) and path[position]:
            text = path[position]
            at = fdp.ConsumeIntInRange(0, len(text) - 1)
            path[position] = text[:at] + '0123456789abcdefG'[fdp.ConsumeIntInRange(0, 16)] + text[at + 1:]
        elif choice == 4:
            path.reverse()
        elif choice == 5:
            path = path + [LEAVES[0]] * fdp.ConsumeIntInRange(0, 70)
        elif choice == 6 and len(path) > 1:
            path[0], path[-1] = path[-1], path[0]
    return path


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    size = fdp.ConsumeIntInRange(1, MAX_LEAVES)
    leaves = LEAVES[:size]
    root = rf_merkle.merkle_root(leaves)

    if fdp.ConsumeBool():  # inclusion
        index = fdp.ConsumeIntInRange(0, size - 1)
        honest = rf_merkle.inclusion_path(leaves, index)
        if rf_verify._root_from_path(leaves[index], index, size, list(honest)) != root or \
                rf_merkle.root_from_inclusion_path(leaves[index], index, size, honest) != root:
            raise AssertionError(f'honest inclusion path rejected: index {index}, size {size}')
        claimed_index = index + fdp.ConsumeIntInRange(-2, 2)
        claimed_size = size + fdp.ConsumeIntInRange(-2, 2)
        leaf = LEAVES[fdp.ConsumeIntInRange(0, MAX_LEAVES - 1)] if fdp.ConsumeBool() else leaves[index]
        path = _mutate_path(fdp, honest)
        core = _outcome(rf_merkle.root_from_inclusion_path, ValueError, leaf, claimed_index, claimed_size, path)
        verifier = _outcome(rf_verify._root_from_path, rf_verify.VerificationError,
                            leaf, claimed_index, claimed_size, list(path))
        if core != verifier:
            raise AssertionError(f'inclusion: core {core} but verifier {verifier} for index {claimed_index}, '
                                 f'size {claimed_size}, path {path}')
        return

    if size < 2:
        return
    first = fdp.ConsumeIntInRange(1, size - 1)
    first_root = rf_merkle.merkle_root(leaves[:first])
    honest = rf_merkle.consistency_path(leaves, first)
    expected = (first_root, root)
    if rf_verify._roots_from_consistency_path(first, size, list(honest), first_root) != expected or \
            rf_merkle.roots_from_consistency_path(first, size, honest, first_root) != expected or \
            not rf_merkle.verify_consistency(first, size, honest, first_root, root):
        raise AssertionError(f'honest consistency path rejected: {first} -> {size}')
    claimed_first = max(1, first + fdp.ConsumeIntInRange(-2, 2))
    claimed_size = max(claimed_first + 1, size + fdp.ConsumeIntInRange(-2, 2))
    claimed_root = LEAVES[fdp.ConsumeIntInRange(0, MAX_LEAVES - 1)] if fdp.ConsumeBool() else first_root
    path = _mutate_path(fdp, honest)
    core = _outcome(rf_merkle.roots_from_consistency_path, ValueError, claimed_first, claimed_size, path, claimed_root)
    verifier = _outcome(rf_verify._roots_from_consistency_path, rf_verify.VerificationError,
                        claimed_first, claimed_size, list(path), claimed_root)
    if core != verifier:
        raise AssertionError(f'consistency: core {core} but verifier {verifier} for {claimed_first} -> '
                             f'{claimed_size}, path {path}')
    # A path that is not the honest one must never reproduce both real roots for the real sizes.
    if path != honest and (claimed_first, claimed_size, claimed_root) == (first, size, first_root) \
            and core == ('ok', expected):
        raise AssertionError(f'a second consistency path verifies for {first} -> {size}: {path}')


if __name__ == '__main__':
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
