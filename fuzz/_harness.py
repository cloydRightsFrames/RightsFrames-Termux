"""Shared pieces of the RightsFrames fuzz targets (Atheris / libFuzzer).

Each target feeds attacker-controlled documents to the independent verifier
(`verifier/rf_verify.py`) and fails on either of two things:

  1. the verifier raises anything other than `VerificationError` (its documented way of
     rejecting input), or
  2. the verifier ACCEPTS a document whose signed content differs from the genuine ledger
     built below. The fuzzer never holds a signing key, so that would be a forgery.

The genuine ledger is deterministic (fixed test keys, fixed clock), so a crashing input
reproduces on any machine:

    python fuzz/fuzz_receipt.py path/to/crash-file

Documents are JSON, so plain byte flipping mostly produces invalid JSON that is rejected
at the first parse. `JsonMutator` therefore mutates the parsed tree (replace, delete,
copy between fields, retype, re-hash) and falls back to libFuzzer's byte mutations part
of the time, which keeps the parser itself under test.
"""
from __future__ import annotations

import atexit
import copy
import hashlib
import itertools
import json
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable

import atheris

ROOT = Path(__file__).resolve().parents[1]

# Replaced in the serialised text, because json.dumps cannot emit these itself.
_INF = '@@RF_FUZZ_INF@@'
_NEG_INF = '@@RF_FUZZ_NEG_INF@@'
_NAN = '@@RF_FUZZ_NAN@@'
_HUGE = '@@RF_FUZZ_HUGE_INT@@'
_TEXT_SUBSTITUTIONS = (
    (f'"{_INF}"', '1e999'), (f'"{_NEG_INF}"', '-1e999'), (f'"{_NAN}"', 'NaN'),
    (f'"{_HUGE}"', '1' + '0' * 5000),
)

INTERESTING: tuple[Any, ...] = (
    None, True, False, 0, 1, -1, 2, 2 ** 31, 2 ** 63, 2 ** 64, 10 ** 30, 0.5, -0.0, 1.0,
    '', ' ', 'a', '0' * 64, 'f' * 64, 'F' * 64, '0' * 63, '0' * 65, 'A' * 300,
    '\ud800', '\udfff', '\x00', 'é', '\n',
    'rf.anchor.v2', 'rf.anchor.v3', 'rf.anchor.v4', 'rf.receipt.v1', 'rf.consistency.v1',
    'rf.evidence.v1', 'rf.evidence.v2', 'ed25519:' + '0' * 64, 'mldsa65:' + '0' * 64,
    '2026-01-01T00:00:00.000000Z', '0000-00-00T00:00:00.000000Z',
    [], {}, [[]], [None], {'a': 1}, _INF, _NEG_INF, _NAN, _HUGE,
)
_HEX = '0123456789abcdef'
_MAX_SLOTS = 20000


def _interesting(rng: random.Random) -> Any:
    """A fresh copy: the lists and dicts above must never end up shared between documents."""
    return copy.deepcopy(rng.choice(INTERESTING))


def _cleanup_later(path: Path) -> Path:
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path


class World:
    """A genuine, deterministic ledger with hybrid-signed anchors, and documents exported from it."""

    def __init__(self) -> None:
        self.dir = _cleanup_later(Path(tempfile.mkdtemp(prefix='rf-fuzz-world-')))
        data = self.dir / 'data'
        # rf_core reads its data directory once, at import time.
        os.environ['RF_DATA_DIR'] = str(data)
        os.environ['RF_PQ_SIGNING'] = 'on'
        for name in ('RF_KEY_PASSPHRASE', 'RF_KEY_PASSPHRASE_FILE', 'RF_REQUIRE_SEALED_KEYS'):
            os.environ.pop(name, None)
        for sub in ('core', 'tools'):
            sys.path.insert(0, str(ROOT / sub))
        import rf_consistency
        import rf_core
        import rf_export_evidence
        import rf_receipt
        from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

        self._core = rf_core
        clock = itertools.count()
        rf_core._utc_now = lambda: f'2026-01-01T00:00:00.{next(clock):06d}Z'

        # Fixed, public test keys: derived from labels, never used outside this harness.
        self._install_keys(
            ed25519.Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(b'rightsframes fuzz ed25519 test key').digest()),
            mldsa.MLDSA65PrivateKey.from_seed_bytes(
                hashlib.sha256(b'rightsframes fuzz ml-dsa-65 test key').digest()))

        self.anchors: list[dict[str, Any]] = []
        for upto in (5, 9, 9, 13):
            for number in range(self._count(), upto):
                rf_core.append_entry('fuzz.event', {'n': number, 'note': 'naïve ✓', 'nested': {'k': [1, 2.5]}})
            self.anchors.append(rf_core.create_anchor())
        for number in range(13, 15):
            rf_core.append_entry('fuzz.tail', {'n': number})

        self.entries = self._entries()
        self.key_id = self.anchors[0]['key_id']
        self.pq_key_id = self.anchors[0]['pq_key_id']
        self.pins = [(anchor['seq'], anchor['anchor_hash']) for anchor in self.anchors]

        self.receipts = [
            rf_receipt.build_receipt(data, entry_id, anchor_seq)
            for entry_id, anchor_seq in ((1, None), (5, 1), (9, None), (13, None), (3, 2), (7, 3))]
        self.proofs = [
            rf_consistency.build_consistency_proof(data, first, second)
            for first, second in ((1, 2), (2, 3), (1, 4), (3, 4), (2, 4))]
        bundle = self.dir / 'genuine.zip'
        rf_export_evidence.export_bundle(data, bundle)
        self.bundle = bundle.read_bytes()

        # An Ed25519-only ledger, for the pre-hybrid (rf.evidence.v1 / rf.anchor.v2) paths.
        os.environ['RF_PQ_SIGNING'] = 'off'
        legacy = self.dir / 'legacy'
        self._point(legacy)
        self._install_keys(
            ed25519.Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(b'rightsframes fuzz ed25519 legacy test key').digest()), None)
        self.legacy_anchors = []
        for upto in (3, 6):
            for number in range(self._count(), upto):
                rf_core.append_entry('fuzz.legacy', {'n': number})
            self.legacy_anchors.append(rf_core.create_anchor())
        self.legacy_entries = self._entries()
        self.legacy_key_id = self.legacy_anchors[0]['key_id']
        legacy_bundle = self.dir / 'legacy.zip'
        rf_export_evidence.export_bundle(legacy, legacy_bundle)
        self.legacy_bundle = legacy_bundle.read_bytes()

        self.scratch = self.dir / 'input'

    def _point(self, base: Path) -> None:
        core = self._core
        base.mkdir(parents=True, exist_ok=True)
        for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                            ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                            ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                            ('KEY_ID_PATH', base / 'signing_key.id'),
                            ('ANCHOR_PATH', base / 'anchors.jsonl'),
                            ('LOCK_PATH', base / 'anchors.lock')):
            setattr(core, name, value)

    def _install_keys(self, ed: Any, pq: Any) -> None:
        core = self._core
        core._secure_directory()
        core._store_private_key(core.PRIVATE_KEY_PATH, ed, 'ed25519')
        if pq is not None:
            core._store_private_key(core.pq_private_key_path(), pq, 'mldsa65')

    def _count(self) -> int:
        return len(self._core._ledger_snapshot())

    def _entries(self) -> list[dict[str, Any]]:
        return [{'id': row[0], 'ts': row[1], 'entry_type': row[2], 'payload': row[3],
                 'prev_hash': row[4], 'entry_hash': row[5]} for row in self._core._ledger_snapshot()]

    def write(self, data: bytes) -> str:
        self.scratch.write_bytes(data)
        return str(self.scratch)


def exact(value: Any) -> str:
    """Type-exact comparison form: 1, 1.0 and true are different documents."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def require_genuine(value: Any, genuine: Any, what: str) -> None:
    if exact(value) != exact(genuine):
        raise AssertionError(f'FORGERY ACCEPTED: verifier accepted a {what} that differs from the '
                             f'genuine one: {exact(value)[:400]}')


def anchor_at(anchors: list[dict[str, Any]], anchor: Any, what: str) -> dict[str, Any]:
    """The genuine anchor an accepted anchor must be identical to."""
    seq = anchor.get('seq') if isinstance(anchor, dict) else None
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= len(anchors):
        raise AssertionError(f'FORGERY ACCEPTED: verifier accepted {what} with seq {seq!r}, '
                             f'which the genuine ledger does not have')
    require_genuine(anchor, anchors[seq - 1], what)
    return anchors[seq - 1]


def dumps(doc: Any) -> bytes:
    """Serialise a mutated tree; ensure_ascii keeps lone surrogates expressible as escapes."""
    text = json.dumps(doc, ensure_ascii=True, separators=(',', ':'))
    for needle, replacement in _TEXT_SUBSTITUTIONS:
        text = text.replace(needle, replacement)
    return text.encode('ascii')


class JsonMutator:
    """Structure-aware libFuzzer custom mutator for JSON documents."""

    def __init__(self, fixups: Iterable[Callable[[Any, random.Random], None]] = (),
                 byte_level: float = 0.25) -> None:
        self.fixups = tuple(fixups)
        self.byte_level = byte_level

    def __call__(self, data: bytes, max_size: int, seed: int) -> bytes:
        rng = random.Random(seed)
        if rng.random() < self.byte_level:
            return atheris.Mutate(data, max_size)
        try:
            doc = json.loads(data)
        except (ValueError, RecursionError):
            return atheris.Mutate(data, max_size)
        try:
            for _ in range(rng.choice((1, 1, 1, 2, 3))):
                doc = self.mutate(doc, rng)
            if self.fixups and rng.random() < 0.5:
                rng.choice(self.fixups)(doc, rng)
            out = dumps(doc)
        except Exception:  # a tree this mutator cannot handle; the oracle lives in the target
            return atheris.Mutate(data, max_size)
        return out if len(out) <= max_size else atheris.Mutate(data, max_size)

    # --- tree mutation -------------------------------------------------------------------

    @staticmethod
    def _slots(doc: Any) -> list[tuple[Any, Any]]:
        """Every (container, key) position in the tree."""
        slots: list[tuple[Any, Any]] = []
        stack = [doc]
        while stack and len(slots) < _MAX_SLOTS:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    slots.append((node, key))
                    stack.append(value)
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    slots.append((node, index))
                    stack.append(value)
        return slots

    def mutate(self, doc: Any, rng: random.Random) -> Any:
        slots = self._slots(doc)
        if not slots or rng.random() < 0.02:
            return _interesting(rng)
        container, key = rng.choice(slots)
        value = container[key]
        op = rng.randrange(10)
        if op == 0:
            container[key] = _interesting(rng)
        elif op == 1:  # copy another part of the document here (field confusion)
            source, source_key = rng.choice(slots)
            container[key] = json.loads(json.dumps(source[source_key]))
        elif op == 2:  # swap two positions
            other, other_key = rng.choice(slots)
            container[key], other[other_key] = other[other_key], container[key]
        elif op == 3:  # delete
            del container[key]
        elif op == 4 and isinstance(container, dict):  # add or rename a field
            names = [name for holder, name in slots if isinstance(holder, dict)]
            if rng.random() < 0.5:
                container[rng.choice(names + ['extra'])] = _interesting(rng)
            else:
                container[rng.choice(names + ['extra'])] = container.pop(key)
        elif op == 5 and isinstance(container, list):  # duplicate, reverse or truncate a list
            choice = rng.randrange(3)
            if choice == 0:
                container.insert(rng.randrange(len(container) + 1), json.loads(json.dumps(value)))
            elif choice == 1:
                container.reverse()
            else:
                del container[rng.randrange(len(container)):]
        else:
            container[key] = self._tweak(value, rng)
        return doc

    def _tweak(self, value: Any, rng: random.Random) -> Any:
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            return rng.choice((value + 1, value - 1, -value, value * 2, value + 2 ** 32, float(value), str(value)))
        if isinstance(value, float):
            return rng.choice((int(value), value * 2, -value, _INF))
        if isinstance(value, str):
            return self._tweak_text(value, rng)
        if isinstance(value, list):
            return rng.choice((value + value, value[:len(value) // 2], [value], {'0': value}))
        if isinstance(value, dict):
            return rng.choice(([value], list(value.values()), list(value), json.dumps(value)))
        return _interesting(rng)

    def _tweak_text(self, text: str, rng: random.Random) -> str:
        if text[:1] in '{[' and rng.random() < 0.7:  # JSON inside a string (entry payloads, members)
            try:
                inner = json.loads(text)
            except (ValueError, RecursionError):
                inner = None
            if isinstance(inner, (dict, list)):
                inner = self.mutate(inner, rng)
                if rng.random() < 0.8:
                    return json.dumps(inner, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                return json.dumps(inner)
        if '\n' in text and rng.random() < 0.7:  # JSON lines (ledger.jsonl, anchors.jsonl)
            lines = text.split('\n')
            choice = rng.randrange(5)
            index = rng.randrange(len(lines))
            if choice == 0:
                lines[index] = self._tweak_text(lines[index], rng)
            elif choice == 1:
                del lines[index]
            elif choice == 2:
                lines.insert(index, lines[rng.randrange(len(lines))])
            elif choice == 3:
                other = rng.randrange(len(lines))
                lines[index], lines[other] = lines[other], lines[index]
            else:
                del lines[index:]
            return '\n'.join(lines)
        if not text:
            return rng.choice(('0', ' ', '\x00'))
        index = rng.randrange(len(text))
        choice = rng.randrange(8)
        if choice == 0:  # change one character, staying hex where the text is hex
            pool = _HEX if text[index] in _HEX else 'aZ0 +/=\x00é'
            return text[:index] + rng.choice(pool) + text[index + 1:]
        if choice == 1:
            return text[:index]
        if choice == 2:
            return text + text[index:]
        if choice == 3:
            return text.upper() if text != text.upper() else text.lower()
        if choice == 4:
            return text[:index] + '\ud800' + text[index:]
        if choice == 5:
            return text[:index] + text[index + 1:]
        if choice == 6:
            return ' ' + text if rng.random() < 0.5 else text + '\n'
        return text[index:] + text[:index]


def run(test_one_input: Callable[[bytes], None], seeds: Iterable[bytes],
        mutator: Callable[[bytes, int, int], bytes] | None = None) -> None:
    """Start libFuzzer. Positional arguments are corpus directories, or files to replay."""
    argv = list(sys.argv)
    replaying = any(os.path.isfile(arg) for arg in argv[1:] if not arg.startswith('-'))
    if not replaying:
        seed_dir = _cleanup_later(Path(tempfile.mkdtemp(prefix='rf-fuzz-seeds-')))
        for number, seed in enumerate(seeds):
            (seed_dir / f'seed-{number:03d}').write_bytes(seed)
        argv.append(str(seed_dir))
    if mutator is None:
        atheris.Setup(argv, test_one_input)
    else:
        atheris.Setup(argv, test_one_input, custom_mutator=mutator)
    atheris.Fuzz()
