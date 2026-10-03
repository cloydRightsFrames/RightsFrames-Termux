"""RightsFrames production ledger core with transactional integrity controls."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA_DIR = Path(os.environ.get('RF_DATA_DIR', '/data')).resolve()
DB_PATH = DATA_DIR / 'ledger.db'
PRIVATE_KEY_PATH = DATA_DIR / 'signing_key.pem'
PUBLIC_KEY_PATH = DATA_DIR / 'signing_key.pub.pem'
KEY_ID_PATH = DATA_DIR / 'signing_key.id'
ANCHOR_PATH = DATA_DIR / 'anchors.jsonl'
LOCK_PATH = DATA_DIR / 'anchors.lock'

MAX_ENTRY_TYPE = 128
MAX_PAYLOAD_BYTES = 262144
MAX_ANCHOR_BYTES = 10485760
MAX_ANCHOR_CORE_BYTES = 65536
MAX_ANCHOR_CHAIN_LENGTH = 1000000


def _secure_directory() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec='microseconds')
        .replace('+00:00', 'Z')
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    )


def _payload_bytes(payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict):
        raise ValueError('payload must be an object')
    encoded = _canonical_json(payload).encode('utf-8')
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError('payload exceeds maximum size')
    return encoded


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _key_id(public_key: bytes) -> str:
    return 'ed25519:' + _sha256(public_key)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    _secure_directory()
    fd, tmp_name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=DATA_DIR)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        dir_fd = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def _write_text_atomic(path: Path, value: str, mode: int) -> None:
    _atomic_write(path, value.encode('utf-8'), mode)


def load_or_create_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    _secure_directory()

    if PRIVATE_KEY_PATH.exists():
        private = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(),
            password=None,
        )
        if not isinstance(private, Ed25519PrivateKey):
            raise TypeError('signing key is not Ed25519')
    else:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _atomic_write(PRIVATE_KEY_PATH, pem, 0o600)

    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    if PUBLIC_KEY_PATH.exists():
        stored_public = serialization.load_pem_public_key(
            PUBLIC_KEY_PATH.read_bytes()
        )
        if not hasattr(stored_public, 'public_bytes'):
            raise TypeError('stored public key is invalid')
        stored_raw = stored_public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if not secrets.compare_digest(stored_raw, public):
            raise ValueError('public key does not match private key')
    else:
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _atomic_write(PUBLIC_KEY_PATH, public_pem, 0o644)

    key_id = _key_id(public)

    if KEY_ID_PATH.exists():
        stored_id = KEY_ID_PATH.read_text(encoding='utf-8').strip()
        if stored_id != key_id:
            raise ValueError('signing key identity mismatch')
    else:
        _write_text_atomic(KEY_ID_PATH, key_id + '\n', 0o600)

    return private, public, key_id


def init_db() -> None:
    _secure_directory()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=5000')
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS ledger_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            )
            '''
        )
        conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_ledger_entries_entry_hash '
            'ON ledger_entries(entry_hash)'
        )
        conn.commit()


def _connect() -> sqlite3.Connection:
    init_db()
    conn = sqlite3.connect(
        DB_PATH,
        timeout=5,
        isolation_level=None,
    )
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn


def _entry_material(
    entry_id: int,
    prev_hash: str,
    timestamp: str,
    entry_type: str,
    payload: str,
) -> bytes:
    return (
        f'{entry_id}|{prev_hash}|{timestamp}|{entry_type}|{payload}'
    ).encode('utf-8')


def append_entry(entry_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(entry_type, str) or not entry_type:
        raise ValueError('entry_type must be a non-empty string')
    if len(entry_type) > MAX_ENTRY_TYPE:
        raise ValueError('entry_type exceeds maximum length')

    payload_text = _payload_bytes(payload).decode('utf-8')

    conn = _connect()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT id, entry_hash FROM ledger_entries '
            'ORDER BY id DESC LIMIT 1'
        ).fetchone()

        previous_id = int(row[0]) if row else 0
        previous_hash = str(row[1]) if row else '0' * 64
        entry_id = previous_id + 1
        timestamp = _utc_now()

        entry_hash = _sha256(
            _entry_material(
                entry_id,
                previous_hash,
                timestamp,
                entry_type,
                payload_text,
            )
        )

        conn.execute(
            '''
            INSERT INTO ledger_entries
                (id, ts, entry_type, payload, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                entry_id,
                timestamp,
                entry_type,
                payload_text,
                previous_hash,
                entry_hash,
            ),
        )
        conn.commit()

        return {
            'id': entry_id,
            'ts': timestamp,
            'entry_type': entry_type,
            'payload': payload,
            'prev_hash': previous_hash,
            'entry_hash': entry_hash,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _validate_stored_payload(payload: str) -> None:
    raw = payload.encode('utf-8')
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError('stored payload exceeds maximum size')
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError('stored payload is not an object')


def verify_chain() -> tuple[bool, str]:
    conn = _connect()
    try:
        rows = conn.execute(
            '''
            SELECT id, ts, entry_type, payload, prev_hash, entry_hash
            FROM ledger_entries
            ORDER BY id ASC
            '''
        ).fetchall()
    finally:
        conn.close()

    expected_id = 1
    expected_previous = '0' * 64

    for row in rows:
        entry_id, timestamp, entry_type, payload, prev_hash, entry_hash = row

        if entry_id != expected_id:
            return False, f'id discontinuity at {entry_id}'

        if prev_hash != expected_previous:
            return False, f'previous hash mismatch at {entry_id}'

        try:
            _validate_stored_payload(payload)
        except Exception as exc:
            return False, f'payload invalid at {entry_id}: {exc}'

        expected_hash = _sha256(
            _entry_material(
                entry_id,
                prev_hash,
                timestamp,
                entry_type,
                payload,
            )
        )

        if not secrets.compare_digest(expected_hash, entry_hash):
            return False, f'hash mismatch at {entry_id}'

        expected_previous = entry_hash
        expected_id += 1

    return True, f'verified {len(rows)} entries'


@contextlib.contextmanager
def _anchor_lock() -> Iterator[None]:
    _secure_directory()
    import fcntl

    with LOCK_PATH.open('a+b') as handle:
        os.chmod(LOCK_PATH, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_anchors() -> list[dict[str, Any]]:
    if not ANCHOR_PATH.exists():
        return []

    if ANCHOR_PATH.stat().st_size > MAX_ANCHOR_BYTES:
        raise ValueError('anchor log exceeds maximum size')

    anchors: list[dict[str, Any]] = []

    with ANCHOR_PATH.open('r', encoding='utf-8') as handle:
        for line_number, line in enumerate(handle, 1):
            if len(line.encode('utf-8')) > MAX_ANCHOR_CORE_BYTES:
                raise ValueError(f'anchor line too large at {line_number}')
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f'anchor is not an object at {line_number}')
            anchors.append(item)
            if len(anchors) > MAX_ANCHOR_CHAIN_LENGTH:
                raise ValueError('anchor chain exceeds maximum length')

    return anchors


def _legacy_anchor_hash(core: dict[str, Any]) -> str:
    return _sha256(
        json.dumps(
            core,
            sort_keys=True,
        ).encode('utf-8')
    )


def _canonical_anchor_hash(core: dict[str, Any]) -> str:
    encoded = _canonical_json(core).encode('utf-8')
    if len(encoded) > MAX_ANCHOR_CORE_BYTES:
        raise ValueError('anchor core exceeds maximum size')
    return _sha256(encoded)


def _append_anchor_line(anchor: dict[str, Any]) -> None:
    _secure_directory()
    line = (_canonical_json(anchor) + '\n').encode('utf-8')

    if len(line) > MAX_ANCHOR_CORE_BYTES:
        raise ValueError('anchor exceeds maximum size')

    with ANCHOR_PATH.open('ab') as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())

    dir_fd = os.open(DATA_DIR, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def create_anchor() -> dict[str, Any]:
    private, public, key_id = load_or_create_keypair()
    init_db()

    with _anchor_lock():
        ok, reason = verify_chain()
        if not ok:
            raise ValueError(f'ledger verification failed: {reason}')

        conn = _connect()
        try:
            row = conn.execute(
                'SELECT id, entry_hash FROM ledger_entries '
                'ORDER BY id DESC LIMIT 1'
            ).fetchone()
        finally:
            conn.close()

        anchors = _read_anchors()
        previous_anchor_hash = (
            anchors[-1]['anchor_hash'] if anchors else '0' * 64
        )

        last_id = int(row[0]) if row else 0
        head_hash = str(row[1]) if row else '0' * 64

        sequence = len(anchors) + 1

        core = {
            'schema': 'rf.anchor.v2',
            'seq': sequence,
            'created_at': _utc_now(),
            'ledger_count': last_id,
            'ledger_head': head_hash,
            'prev_anchor_hash': previous_anchor_hash,
            'key_id': key_id,
        }

        anchor_hash = _canonical_anchor_hash(core)
        signature = private.sign(anchor_hash.encode('ascii'))

        anchor = {
            **core,
            'anchor_hash': anchor_hash,
            'signature': base64.b64encode(signature).decode('ascii'),
        }

        _append_anchor_line(anchor)

        return anchor


def verify_anchors() -> tuple[bool, str]:
    try:
        _, public, current_key_id = load_or_create_keypair()
        anchors = _read_anchors()
    except Exception as exc:
        return False, str(exc)

    if not anchors:
        return True, 'no anchors'

    previous_anchor_hash = '0' * 64
    previous_ledger_count = 0

    for index, anchor in enumerate(anchors, 1):
        try:
            sequence = int(anchor['seq'])
            ledger_count = int(anchor['ledger_count'])
            ledger_head = str(anchor['ledger_head'])
            previous_hash = str(anchor['prev_anchor_hash'])
            anchor_hash = str(anchor['anchor_hash'])
            signature = base64.b64decode(
                anchor['signature'],
                validate=True,
            )
        except Exception as exc:
            return False, f'anchor {index} malformed: {exc}'

        if sequence != index:
            return False, f'anchor sequence mismatch at {index}'

        if previous_hash != previous_anchor_hash:
            return False, f'anchor chain broken at {index}'

        if ledger_count < previous_ledger_count:
            return False, f'ledger count regressed at anchor {index}'

        legacy = 'key_id' not in anchor

        if legacy:
            core = {
                key: anchor[key]
                for key in (
                    'schema',
                    'seq',
                    'created_at',
                    'ledger_count',
                    'ledger_head',
                    'prev_anchor_hash',
                )
            }
            expected_hash = _legacy_anchor_hash(core)
        else:
            if anchor.get('key_id') != current_key_id:
                return False, f'key identity mismatch at anchor {index}'

            core = {
                key: anchor[key]
                for key in (
                    'schema',
                    'seq',
                    'created_at',
                    'ledger_count',
                    'ledger_head',
                    'prev_anchor_hash',
                    'key_id',
                )
            }
            expected_hash = _canonical_anchor_hash(core)

        if not secrets.compare_digest(expected_hash, anchor_hash):
            return False, f'anchor hash mismatch at {index}'

        try:
            public_key = serialization.load_pem_public_key(
                PUBLIC_KEY_PATH.read_bytes()
            )
            public_key.verify(signature, anchor_hash.encode('ascii'))
        except Exception:
            return False, f'anchor signature invalid at {index}'

        previous_anchor_hash = anchor_hash
        previous_ledger_count = ledger_count

    conn = _connect()
    try:
        row = conn.execute(
            'SELECT id, entry_hash FROM ledger_entries '
            'ORDER BY id DESC LIMIT 1'
        ).fetchone()
    finally:
        conn.close()

    current_count = int(row[0]) if row else 0
    current_head = str(row[1]) if row else '0' * 64

    latest = anchors[-1]

    if int(latest['ledger_count']) > current_count:
        return False, 'ledger is shorter than latest anchor'

    if int(latest['ledger_count']) == current_count:
        if latest['ledger_head'] != current_head:
            return False, 'ledger head differs from latest anchor'

    return True, f'verified {len(anchors)} anchors'


def health() -> dict[str, Any]:
    chain_ok, chain_reason = verify_chain()
    anchor_ok, anchor_reason = verify_anchors()

    return {
        'service': 'rightsframes-core',
        'status': 'ok' if chain_ok and anchor_ok else 'degraded',
        'ledger': {
            'ok': chain_ok,
            'reason': chain_reason,
        },
        'anchors': {
            'ok': anchor_ok,
            'reason': anchor_reason,
        },
    }
