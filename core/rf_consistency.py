"""Build rf.consistency.v1 append-only proofs between two anchors of a RightsFrames ledger.

A consistency proof shows that the ledger signed by a later rf.anchor.v4 anchor is the
ledger signed by an earlier one with entries appended: no entry the earlier anchor
covered was edited, removed or reordered. It is an RFC 9162 Merkle consistency path of
at most about 2*log2(N) hashes between the two signed Merkle roots and discloses no
entry at all, so an auditor, customer or regulator who pinned an anchor at the last
review can check everything written since without being given the records. Verify with:

    python verifier/rf_verify.py proof.json --consistency --pin-anchor SEQ:HASH

Read-only: opens the ledger database read-only and reads PUBLIC keys only; never a
private key. Refuses to emit a proof that would not verify (self-check of both Merkle
roots, the path and the key identities against the two anchors).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:  # imported as core.rf_consistency (package) or as rf_consistency (core/ on sys.path)
    from . import rf_merkle as _merkle
except ImportError:
    import rf_merkle as _merkle  # type: ignore[no-redef]

CONSISTENCY_SCHEMA = 'rf.consistency.v1'
ANCHOR_SCHEMA_V4 = 'rf.anchor.v4'
PUBLIC_KEY_NAME = 'signing_key.pub.pem'
PQ_PUBLIC_KEY_NAME = 'signing_key_mldsa65.pub.pem'
MAX_ANCHOR_LINE_BYTES = 65536


class ConsistencyUnavailable(ValueError):
    """The two anchors cannot carry a consistency proof (for example, one has no Merkle root)."""


def _read_anchors(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    raw = path.read_bytes()
    complete = raw[:raw.rfind(b'\n') + 1]
    anchors: list[dict[str, Any]] = []
    for number, line in enumerate(complete.split(b'\n'), 1):
        if not line.strip():
            continue
        if len(line) > MAX_ANCHOR_LINE_BYTES:
            raise ValueError(f'anchor line {number} exceeds size limit')
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f'anchor line {number} is not an object')
        anchors.append(item)
    return anchors


def _key_id(prefix: str, key: Any) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return prefix + hashlib.sha256(raw).hexdigest()


def _seq(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f'{what} anchor seq must be a positive integer')
    return value


def _merkle_anchor(anchors: list[dict[str, Any]], seq: int) -> dict[str, Any]:
    if seq > len(anchors):
        raise LookupError(f'anchor {seq} does not exist ({len(anchors)} anchors)')
    anchor = anchors[seq - 1]
    if anchor.get('schema') != ANCHOR_SCHEMA_V4:
        raise ConsistencyUnavailable(f'anchor {seq} is {anchor.get("schema")}, not '
                                     f'{ANCHOR_SCHEMA_V4}; it carries no Merkle commitment')
    count, root = anchor.get('ledger_count'), anchor.get('merkle_root')
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 \
            or not isinstance(root, str) or anchor.get('seq') != seq:
        raise ValueError(f'anchor {seq} is malformed')
    return anchor


def build_consistency_proof(data_dir: str | Path, first_seq: int,
                            second_seq: int | None = None) -> dict[str, Any]:
    """Return the rf.consistency.v1 document from anchor `first_seq` to `second_seq` (default: newest)."""
    first_seq = _seq(first_seq, 'first')
    data = Path(data_dir).resolve()
    db_path = data / 'ledger.db'
    pub_path, pq_path = data / PUBLIC_KEY_NAME, data / PQ_PUBLIC_KEY_NAME
    if not db_path.is_file():
        raise FileNotFoundError(f'ledger database not found: {db_path}')

    anchors = _read_anchors(data / 'anchors.jsonl')
    second_seq = len(anchors) if second_seq is None else _seq(second_seq, 'second')
    if first_seq > len(anchors):
        raise LookupError(f'anchor {first_seq} does not exist ({len(anchors)} anchors)')
    if second_seq <= first_seq:
        raise ConsistencyUnavailable(
            f'anchor {second_seq} is not later than anchor {first_seq}; a consistency proof '
            'runs from an earlier anchor to a later one')
    first = _merkle_anchor(anchors, first_seq)
    second = _merkle_anchor(anchors, second_seq)
    first_size, second_size = first['ledger_count'], second['ledger_count']
    if first_size > second_size:
        raise ValueError(f'anchor {second_seq} covers fewer entries than anchor {first_seq}; '
                         'run integrity verification')
    if not pub_path.is_file() or not pq_path.is_file():
        raise ConsistencyUnavailable(
            'consistency proofs need both the Ed25519 and the ML-DSA-65 public keys')

    conn = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        hashes = [str(row[0]) for row in conn.execute(
            'SELECT entry_hash FROM ledger_entries WHERE id <= ? ORDER BY id ASC',
            (second_size,)).fetchall()]
    finally:
        conn.close()
    if len(hashes) != second_size:
        raise ValueError(f'ledger has {len(hashes)} entries below anchor {second_seq}, '
                         f'which commits to {second_size}')

    roots = _merkle.roots_at(hashes, (first_size, second_size))
    for anchor, size in ((first, first_size), (second, second_size)):
        if roots[size] != anchor['merkle_root']:
            raise ValueError(f'ledger does not match the Merkle root of anchor {anchor["seq"]}; '
                             'run integrity verification before issuing consistency proofs')

    pub_pem = pub_path.read_bytes()
    pq_pem = pq_path.read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError('public key is not Ed25519')
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
    pq_key = serialization.load_pem_public_key(pq_pem)
    if not isinstance(pq_key, MLDSA65PublicKey):
        raise TypeError('post-quantum public key is not ML-DSA-65')
    key_id, pq_key_id = _key_id('ed25519:', public_key), _key_id('mldsa65:', pq_key)
    for anchor in (first, second):
        if key_id != anchor.get('key_id') or pq_key_id != anchor.get('pq_key_id'):
            raise ValueError(
                f'public keys in the data directory did not sign anchor {anchor["seq"]}')

    path = _merkle.consistency_path(hashes, first_size)
    if not _merkle.verify_consistency(first_size, second_size, path,
                                      first['merkle_root'], second['merkle_root']):
        raise ValueError('consistency path self-check failed; run integrity verification')
    return {
        'schema': CONSISTENCY_SCHEMA,
        'first_anchor': first,
        'second_anchor': second,
        'consistency_path': path,
        'signing_key_pem': pub_pem.decode('ascii'),
        'pq_signing_key_pem': pq_pem.decode('ascii'),
    }


def canonical_proof(proof: dict[str, Any]) -> bytes:
    return (json.dumps(proof, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')
