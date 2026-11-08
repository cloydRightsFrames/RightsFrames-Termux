"""Build rf.receipt.v1 single-entry inclusion receipts from a RightsFrames data directory.

A receipt proves that one ledger entry, exactly as shown, is entry `id` of the ledger
committed to by a hybrid-signed (Ed25519 + ML-DSA-65) rf.anchor.v4 anchor, using an
RFC 9162 Merkle inclusion path of ceil(log2 N) hashes. It discloses no other entry, so
a single record can be handed to a regulator, court or counterparty without exposing
the rest of the ledger. Verify with:

    python verifier/rf_verify.py receipt.json --receipt --pin-anchor SEQ:HASH

Read-only: opens the ledger database read-only and reads PUBLIC keys only; never a
private key. Refuses to emit a receipt that would not verify (self-check of the
Merkle root and key identities against the chosen anchor).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:  # imported as core.rf_receipt (package) or as rf_receipt (core/ on sys.path)
    from . import rf_merkle as _merkle
except ImportError:
    import rf_merkle as _merkle  # type: ignore[no-redef]

RECEIPT_SCHEMA = 'rf.receipt.v1'
ANCHOR_SCHEMA_V4 = 'rf.anchor.v4'
PUBLIC_KEY_NAME = 'signing_key.pub.pem'
PQ_PUBLIC_KEY_NAME = 'signing_key_mldsa65.pub.pem'
MAX_ANCHOR_LINE_BYTES = 65536


class ReceiptUnavailable(ValueError):
    """No anchor can prove this entry yet (for example, it is after the newest v4 anchor)."""


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


def _select_anchor(anchors: list[dict[str, Any]], entry_id: int,
                   anchor_seq: int | None) -> dict[str, Any]:
    if anchor_seq is not None:
        if not 1 <= anchor_seq <= len(anchors):
            raise LookupError(f'anchor {anchor_seq} does not exist ({len(anchors)} anchors)')
        anchor = anchors[anchor_seq - 1]
        if anchor.get('schema') != ANCHOR_SCHEMA_V4:
            raise ReceiptUnavailable(f'anchor {anchor_seq} is {anchor.get("schema")}, not '
                                     f'{ANCHOR_SCHEMA_V4}; it carries no Merkle commitment')
        if int(anchor['ledger_count']) < entry_id:
            raise ReceiptUnavailable(f'anchor {anchor_seq} covers entries 1..'
                                     f'{anchor["ledger_count"]}, not entry {entry_id}')
        return anchor
    for anchor in reversed(anchors):
        if anchor.get('schema') == ANCHOR_SCHEMA_V4 and int(anchor['ledger_count']) >= entry_id:
            return anchor
    raise ReceiptUnavailable(f'no {ANCHOR_SCHEMA_V4} anchor covers entry {entry_id} yet; '
                             'create an anchor first')


def build_receipt(data_dir: str | Path, entry_id: int,
                  anchor_seq: int | None = None) -> dict[str, Any]:
    """Return the rf.receipt.v1 document for `entry_id` against the newest (or given) v4 anchor."""
    if not isinstance(entry_id, int) or isinstance(entry_id, bool) or entry_id < 1:
        raise ValueError('entry id must be a positive integer')
    data = Path(data_dir).resolve()
    db_path = data / 'ledger.db'
    pub_path, pq_path = data / PUBLIC_KEY_NAME, data / PQ_PUBLIC_KEY_NAME
    if not db_path.is_file():
        raise FileNotFoundError(f'ledger database not found: {db_path}')

    anchor = _select_anchor(_read_anchors(data / 'anchors.jsonl'), entry_id, anchor_seq)
    if not pub_path.is_file() or not pq_path.is_file():
        raise ReceiptUnavailable('receipts need both the Ed25519 and the ML-DSA-65 public keys')
    tree_size = int(anchor['ledger_count'])

    conn = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        conn.execute('BEGIN')
        entry_row = conn.execute(
            'SELECT id, ts, entry_type, payload, prev_hash, entry_hash FROM ledger_entries '
            'WHERE id = ?', (entry_id,)).fetchone()
        hashes = [str(row[0]) for row in conn.execute(
            'SELECT entry_hash FROM ledger_entries WHERE id <= ? ORDER BY id ASC',
            (tree_size,)).fetchall()]
    finally:
        conn.close()
    if entry_row is None:
        raise LookupError(f'entry {entry_id} does not exist')
    if len(hashes) != tree_size:
        raise ValueError(f'ledger has {len(hashes)} entries below anchor {anchor["seq"]}, '
                         f'which commits to {tree_size}')

    if _merkle.merkle_root(hashes) != anchor['merkle_root']:
        raise ValueError(f'ledger does not match the Merkle root of anchor {anchor["seq"]}; '
                         'run integrity verification before issuing receipts')

    pub_pem = pub_path.read_bytes()
    pq_pem = pq_path.read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError('public key is not Ed25519')
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
    pq_key = serialization.load_pem_public_key(pq_pem)
    if not isinstance(pq_key, MLDSA65PublicKey):
        raise TypeError('post-quantum public key is not ML-DSA-65')
    if _key_id('ed25519:', public_key) != anchor['key_id'] or \
            _key_id('mldsa65:', pq_key) != anchor['pq_key_id']:
        raise ValueError(f'public keys in the data directory did not sign anchor {anchor["seq"]}')

    entry = {'id': int(entry_row[0]), 'ts': entry_row[1], 'entry_type': entry_row[2],
             'payload': entry_row[3], 'prev_hash': entry_row[4], 'entry_hash': entry_row[5]}
    return {
        'schema': RECEIPT_SCHEMA,
        'entry': entry,
        'leaf_index': entry_id - 1,
        'tree_size': tree_size,
        'inclusion_path': _merkle.inclusion_path(hashes, entry_id - 1),
        'anchor': anchor,
        'signing_key_pem': pub_pem.decode('ascii'),
        'pq_signing_key_pem': pq_pem.decode('ascii'),
    }


def canonical_receipt(receipt: dict[str, Any]) -> bytes:
    return (json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')
