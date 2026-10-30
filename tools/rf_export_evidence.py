#!/usr/bin/env python3
"""Read-only exporter: ledger.db + anchors.jsonl + PUBLIC key(s) -> evidence bundle.

Writes rf.evidence.v1, or rf.evidence.v2 when the data directory holds an ML-DSA-65
post-quantum public key (signing_key_mldsa65.pub.pem); v2 adds that key as a fifth
member and its pq_key_id to the manifest. Never reads a private key. Refuses to overwrite an existing output file. Entries are
exported exactly as stored (forensic export); judging them is the verifier's job.
Anchors are read BEFORE the ledger snapshot, so every exported anchor refers to a ledger
prefix present in the snapshot (the ledger only grows).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import zipfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BUNDLE_SCHEMA = 'rf.evidence.v1'
BUNDLE_SCHEMA_V2 = 'rf.evidence.v2'
PQ_PUBLIC_KEY_NAME = 'signing_key_mldsa65.pub.pem'
ZERO_HASH = '0' * 64


def _pq_key_id(pem: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
    except ImportError as exc:
        raise RuntimeError('post-quantum key present but this cryptography build '
                           'lacks ML-DSA; upgrade cryptography to export it') from exc
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, MLDSA65PublicKey):
        raise TypeError('post-quantum public key is not ML-DSA-65')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return 'mldsa65:' + _sha(raw)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_bundle(data_dir: str | os.PathLike, out_path: str | os.PathLike) -> dict[str, Any]:
    data = Path(data_dir).resolve()
    out = Path(out_path)
    db_path, anchors_path, pub_path = data / 'ledger.db', data / 'anchors.jsonl', data / 'signing_key.pub.pem'
    if not db_path.is_file():
        raise FileNotFoundError(f'ledger database not found: {db_path}')
    if not pub_path.is_file():
        raise FileNotFoundError(f'public key not found: {pub_path}')

    pub_pem = pub_path.read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError('public key is not Ed25519')
    key_id = 'ed25519:' + _sha(public_key.public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw))
    pq_path = data / PQ_PUBLIC_KEY_NAME
    pq_pem = pq_path.read_bytes() if pq_path.is_file() else None
    pq_key_id = _pq_key_id(pq_pem) if pq_pem is not None else None

    anchor_bytes = b''
    anchor_count = 0
    if anchors_path.is_file():
        raw = anchors_path.read_bytes()
        cut = raw.rfind(b'\n')
        complete = raw[:cut + 1] if cut >= 0 else b''
        lines = [line.strip() for line in complete.split(b'\n') if line.strip()]
        anchor_bytes = b''.join(line + b'\n' for line in lines)
        anchor_count = len(lines)

    conn = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        conn.execute('BEGIN')
        rows = conn.execute('SELECT id, ts, entry_type, payload, prev_hash, entry_hash '
                            'FROM ledger_entries ORDER BY id ASC').fetchall()
    finally:
        conn.close()
    ledger_bytes = b''.join(
        (_canonical({'id': r[0], 'ts': r[1], 'entry_type': r[2], 'payload': r[3],
                     'prev_hash': r[4], 'entry_hash': r[5]}) + '\n').encode('utf-8')
        for r in rows)

    members = {'ledger.jsonl': ledger_bytes, 'anchors.jsonl': anchor_bytes,
               'signing_key.pub.pem': pub_pem}
    if pq_pem is not None:
        members[PQ_PUBLIC_KEY_NAME] = pq_pem
    manifest = {
        'schema': BUNDLE_SCHEMA_V2 if pq_pem is not None else BUNDLE_SCHEMA,
        'created_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'files': {name: {'sha256': _sha(blob), 'bytes': len(blob)} for name, blob in members.items()},
        'ledger_count': len(rows),
        'ledger_head': str(rows[-1][5]) if rows else ZERO_HASH,
        'anchor_count': anchor_count,
        'key_id': key_id,
    }
    if pq_key_id is not None:
        manifest['pq_key_id'] = pq_key_id
    members = {'manifest.json': _canonical(manifest).encode('utf-8'), **members}

    try:
        with open(out, 'xb') as handle, zipfile.ZipFile(handle, 'w') as archive:
            for name, blob in members.items():
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, blob)
    except FileExistsError:
        raise
    except Exception:
        try:
            out.unlink()
        except OSError as cleanup_err:
            print(f'warning: failed to remove incomplete output {out}: {cleanup_err}', file=sys.stderr)
        raise
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description='Export a RightsFrames evidence bundle.')
    parser.add_argument('--data-dir', default=os.environ.get('RF_DATA_DIR'))
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if not args.data_dir:
        parser.error('--data-dir or RF_DATA_DIR is required')
    manifest = export_bundle(args.data_dir, args.out)
    print(f"exported {manifest['ledger_count']} entries, {manifest['anchor_count']} anchors, "
          f"key {manifest['key_id']}")
    if 'pq_key_id' in manifest:
        print(f"post-quantum key: {manifest['pq_key_id']} ({manifest['schema']})")
    print(f"ledger_head: {manifest['ledger_head']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())