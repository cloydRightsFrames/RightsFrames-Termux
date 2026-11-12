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

try:  # imported as core.rf_core (package) or as rf_core (core/ on sys.path)
    from . import rf_keyseal as _keyseal
    from . import rf_merkle as _merkle
except ImportError:
    import rf_keyseal as _keyseal  # type: ignore[no-redef]
    import rf_merkle as _merkle  # type: ignore[no-redef]

DATA_DIR = Path(os.environ.get('RF_DATA_DIR', '/data')).resolve()
DB_PATH = DATA_DIR / 'ledger.db'
PRIVATE_KEY_PATH = DATA_DIR / 'signing_key.pem'
PUBLIC_KEY_PATH = DATA_DIR / 'signing_key.pub.pem'
KEY_ID_PATH = DATA_DIR / 'signing_key.id'
ANCHOR_PATH = DATA_DIR / 'anchors.jsonl'
LOCK_PATH = DATA_DIR / 'anchors.lock'

MAX_ENTRY_TYPE = 128
MAX_PAYLOAD_BYTES = 262144
# Hybrid (Ed25519 + ML-DSA-65) anchors are ~4.9 KB per line, so the log cap
# matches the verifier's 256 MiB member limit (~54,000 hybrid anchors).
MAX_ANCHOR_BYTES = 268435456
MAX_ANCHOR_CORE_BYTES = 65536
MAX_ANCHOR_CHAIN_LENGTH = 1000000

ANCHOR_SCHEMA_V2 = 'rf.anchor.v2'
ANCHOR_SCHEMA_V3 = 'rf.anchor.v3'
ANCHOR_SCHEMA_V4 = 'rf.anchor.v4'
HYBRID_SCHEMAS = (ANCHOR_SCHEMA_V3, ANCHOR_SCHEMA_V4)
ANCHOR_CORE_LEGACY = ('schema', 'seq', 'created_at', 'ledger_count', 'ledger_head',
                      'prev_anchor_hash')
ANCHOR_CORE_V2 = ANCHOR_CORE_LEGACY + ('key_id',)
ANCHOR_CORE_V3 = ANCHOR_CORE_V2 + ('pq_key_id',)
# v4 = v3 + an RFC 9162 Merkle root over entry hashes 1..ledger_count, so a single
# entry can be proven with an O(log n) inclusion receipt (rf.receipt.v1).
ANCHOR_CORE_V4 = ANCHOR_CORE_V3 + ('merkle_root',)

# Post-quantum co-signature: ML-DSA-65 (NIST FIPS 204), domain-separated by
# context string. v3 anchors are valid only if BOTH signatures verify, so an
# anchor stays unforgeable while either Ed25519 or ML-DSA-65 remains unbroken.
PQ_ALGORITHM = 'ML-DSA-65'
PQ_KEY_PREFIX = 'mldsa65:'
PQ_SIGNATURE_CONTEXT = b'rf.anchor.v3'
# Each hybrid schema signs under its own ML-DSA context string (its schema name).
PQ_CONTEXTS = {ANCHOR_SCHEMA_V3: b'rf.anchor.v3', ANCHOR_SCHEMA_V4: b'rf.anchor.v4'}
PQ_MODES = ('auto', 'on', 'off')
PQ_PRIVATE_KEY_NAME = 'signing_key_mldsa65.pem'
PQ_PUBLIC_KEY_NAME = 'signing_key_mldsa65.pub.pem'


def _secure_directory() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # Reviewed false positive: 0700 grants owner-only directory access and traversal; 0644 would be unsafe.
        os.chmod(DATA_DIR, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    except OSError:
        # Best effort: filesystems without POSIX modes (FAT/exFAT on Android shared
        # storage, some Windows volumes) reject chmod; the directory still works.
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
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            # Best effort: the mode was already applied with fchmod before the data
            # was written; this repeat only matters where fchmod is unavailable.
            pass
        if os.name == 'posix':
            dir_fd = os.open(str(DATA_DIR), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def _write_text_atomic(path: Path, value: str, mode: int) -> None:
    _atomic_write(path, value.encode('utf-8'), mode)


# Opened sealed keys, keyed by file identity and content digest, so a long-running
# service pays the memory-hard KDF once per key rather than once per anchor or per
# /health probe (which would also be a cheap denial-of-service lever).
_SEALED_KEY_CACHE: dict[tuple[Any, ...], Any] = {}
_SEALED_KEY_CACHE_LIMIT = 8


def _load_private_key_file(path: Path, role: str) -> Any:
    data = path.read_bytes()
    if not _keyseal.is_sealed(data):
        return _keyseal.load_private_key(data, role, None)
    passphrase = _keyseal.passphrase_from_env()
    if passphrase is None:
        return _keyseal.load_private_key(data, role, None)
    info = path.stat()
    # Keyed by file identity and the sealed (ciphertext) content only; the passphrase
    # is never hashed. A hit must present the same passphrase the key was opened
    # with, compared in constant time, so a changed or wrong passphrase always goes
    # through full unsealing (and fails there if it is wrong).
    cache_key = (str(path), info.st_ino, info.st_mtime_ns, role, hashlib.sha256(data).digest())
    cached = _SEALED_KEY_CACHE.get(cache_key)
    if cached is not None and secrets.compare_digest(cached[0], passphrase):
        return cached[1]
    private = _keyseal.load_private_key(data, role, passphrase)
    if len(_SEALED_KEY_CACHE) >= _SEALED_KEY_CACHE_LIMIT:
        _SEALED_KEY_CACHE.clear()
    _SEALED_KEY_CACHE[cache_key] = (passphrase, private)
    return private


def _store_private_key(path: Path, private: Any, role: str) -> None:
    blob = _keyseal.serialize_private_key(private, role, _keyseal.passphrase_from_env())
    _atomic_write(path, blob, 0o600)


def key_custody() -> dict[str, Any]:
    """Non-secret at-rest status of both private signing keys (sealed, plaintext or absent)."""
    report: dict[str, Any] = {'sealing_required': _keyseal.sealing_required()}
    for role, path in (('ed25519', PRIVATE_KEY_PATH), ('mldsa65', pq_private_key_path())):
        report[role] = _keyseal.describe(path.read_bytes()) if path.exists() else {'absent': True}
    return report


def load_or_create_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    _secure_directory()

    if PRIVATE_KEY_PATH.exists():
        private = _load_private_key_file(PRIVATE_KEY_PATH, 'ed25519')
        if not isinstance(private, Ed25519PrivateKey):
            raise TypeError('signing key is not Ed25519')
    else:
        private = Ed25519PrivateKey.generate()
        _store_private_key(PRIVATE_KEY_PATH, private, 'ed25519')

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
        _atomic_write(PUBLIC_KEY_PATH, public_pem, 0o600)

    key_id = _key_id(public)

    if KEY_ID_PATH.exists():
        stored_id = KEY_ID_PATH.read_text(encoding='utf-8').strip()
        if stored_id != key_id:
            raise ValueError('signing key identity mismatch')
    else:
        _write_text_atomic(KEY_ID_PATH, key_id + '\n', 0o600)

    return private, public, key_id


_PQ_PROBE: dict[str, Any] = {}


def _pq_module() -> Any:
    """Return the ML-DSA module when this cryptography build supports it, else None."""
    if 'module' not in _PQ_PROBE:
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            mldsa.MLDSA65PrivateKey.generate()
            _PQ_PROBE['module'] = mldsa
        except Exception:
            _PQ_PROBE['module'] = None
    return _PQ_PROBE['module']


def pq_available() -> bool:
    return _pq_module() is not None


def pq_mode() -> str:
    mode = os.environ.get('RF_PQ_SIGNING', 'auto').strip().lower() or 'auto'
    if mode not in PQ_MODES:
        raise ValueError(f'RF_PQ_SIGNING must be one of {", ".join(PQ_MODES)}')
    return mode


def pq_private_key_path() -> Path:
    return DATA_DIR / PQ_PRIVATE_KEY_NAME


def pq_public_key_path() -> Path:
    return DATA_DIR / PQ_PUBLIC_KEY_NAME


def _pq_key_id(public_raw: bytes) -> str:
    return PQ_KEY_PREFIX + _sha256(public_raw)


def _pq_raw(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_pq_public_key() -> tuple[Any, str] | None:
    """Return (ML-DSA-65 public key, pq_key_id), or None when no PQ key exists."""
    path = pq_public_key_path()
    if not path.exists():
        return None
    mldsa = _pq_module()
    if mldsa is None:
        raise RuntimeError('post-quantum key present but this cryptography build lacks ML-DSA')
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, mldsa.MLDSA65PublicKey):
        raise TypeError('post-quantum public key is not ML-DSA-65')
    return key, _pq_key_id(_pq_raw(key))


def load_or_create_pq_keypair() -> tuple[Any, str]:
    """Load or create the ML-DSA-65 co-signing key; returns (private key, pq_key_id)."""
    mldsa = _pq_module()
    if mldsa is None:
        raise RuntimeError('ML-DSA-65 is unavailable in this cryptography build')
    _secure_directory()
    private_path, public_path = pq_private_key_path(), pq_public_key_path()

    if private_path.exists():
        private = _load_private_key_file(private_path, 'mldsa65')
        if not isinstance(private, mldsa.MLDSA65PrivateKey):
            raise TypeError('post-quantum signing key is not ML-DSA-65')
    else:
        if public_path.exists():
            raise ValueError('post-quantum public key exists without its private key; '
                             'refusing to rotate silently')
        private = mldsa.MLDSA65PrivateKey.generate()
        _store_private_key(private_path, private, 'mldsa65')

    public_raw = _pq_raw(private.public_key())
    if public_path.exists():
        stored = serialization.load_pem_public_key(public_path.read_bytes())
        if (not isinstance(stored, mldsa.MLDSA65PublicKey)
                or not secrets.compare_digest(_pq_raw(stored), public_raw)):
            raise ValueError('post-quantum public key does not match private key')
    else:
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _atomic_write(public_path, public_pem, 0o600)

    return private, _pq_key_id(public_raw)


def init_db() -> None:
    _secure_directory()
    conn = sqlite3.connect(DB_PATH)
    try:
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
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _connect() -> sqlite3.Connection:
    init_db()
    conn = sqlite3.connect(
        DB_PATH,
        timeout=5,
        isolation_level=None,
    )
    try:
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=5000')
        # synchronous is a per-connection setting: the value init_db() sets on
        # its own connection does not carry over, and some SQLite builds
        # default WAL databases to NORMAL, where a power loss can drop the
        # most recent commits. Every connection that can write asks for FULL.
        conn.execute('PRAGMA synchronous=FULL')
    except Exception:
        conn.close()
        raise
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


def _validated_entry(entry_type: str, payload: dict[str, Any]) -> str:
    if not isinstance(entry_type, str) or not entry_type:
        raise ValueError('entry_type must be a non-empty string')
    if len(entry_type) > MAX_ENTRY_TYPE:
        raise ValueError('entry_type exceeds maximum length')
    return _payload_bytes(payload).decode('utf-8')


def _insert_entry(conn: sqlite3.Connection, entry_type: str, payload: dict[str, Any],
                  payload_text: str) -> dict[str, Any]:
    """Chain and insert one entry on a connection that already holds the write lock."""
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

    return {
        'id': entry_id,
        'ts': timestamp,
        'entry_type': entry_type,
        'payload': payload,
        'prev_hash': previous_hash,
        'entry_hash': entry_hash,
    }


def append_entry(entry_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    payload_text = _validated_entry(entry_type, payload)

    conn = _connect()
    try:
        conn.execute('BEGIN IMMEDIATE')
        entry = _insert_entry(conn, entry_type, payload, payload_text)
        conn.commit()
        return entry
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def write_transaction() -> Iterator[sqlite3.Connection]:
    """One IMMEDIATE transaction on ledger.db: everything inside commits together or not at all.

    Use append_entry_in() for ledger entries inside it; append_entry() opens its own
    connection and would wait on this transaction's write lock.
    """
    conn = _connect()
    try:
        conn.execute('BEGIN IMMEDIATE')
        yield conn
        conn.execute('COMMIT')
    except BaseException:
        if conn.in_transaction:
            conn.execute('ROLLBACK')
        raise
    finally:
        conn.close()


def append_entry_in(conn: sqlite3.Connection, entry_type: str,
                    payload: dict[str, Any]) -> dict[str, Any]:
    """Append an entry inside a write_transaction(), atomically with the caller's other writes."""
    if not conn.in_transaction:
        raise RuntimeError('append_entry_in requires an open write_transaction()')
    return _insert_entry(conn, entry_type, payload, _validated_entry(entry_type, payload))


def _validate_stored_payload(payload: str) -> None:
    raw = payload.encode('utf-8')
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError('stored payload exceeds maximum size')
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError('stored payload is not an object')


def _ledger_snapshot() -> list[tuple[Any, ...]]:
    """Every ledger row from ONE read (a single SQLite snapshot, even under concurrent appends)."""
    conn = _connect()
    try:
        return conn.execute(
            '''
            SELECT id, ts, entry_type, payload, prev_hash, entry_hash
            FROM ledger_entries
            ORDER BY id ASC
            '''
        ).fetchall()
    finally:
        conn.close()


def verify_chain() -> tuple[bool, str]:
    return _check_chain_rows(_ledger_snapshot())


def _check_chain_rows(rows: list[tuple[Any, ...]]) -> tuple[bool, str]:
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
        except Exception:
            return False, f'payload invalid at {entry_id}'

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
    if os.name == 'nt':
        import msvcrt
        with LOCK_PATH.open('a+b') as handle:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b'\x00')
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl
    with LOCK_PATH.open('a+b') as handle:
        os.chmod(LOCK_PATH, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

class AnchorLogTornError(ValueError):
    """The anchor log ends in an incomplete line: an append was interrupted (crash, power loss)."""


ANCHOR_TORN_MESSAGE = ('anchor log ends with an incomplete line from an interrupted write; '
                       'run tools/rf_repair_anchor_log.py')


def _anchor_log_is_torn() -> bool:
    with ANCHOR_PATH.open('rb') as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            return False
        handle.seek(-1, os.SEEK_END)
        return handle.read(1) != b'\n'


def _read_anchors() -> list[dict[str, Any]]:
    if not ANCHOR_PATH.exists():
        return []

    if ANCHOR_PATH.stat().st_size > MAX_ANCHOR_BYTES:
        raise ValueError('anchor log exceeds maximum size')

    # Every anchor is written as one line ending in a newline. A missing final newline
    # means an append was cut short; refuse to parse (or append after) a torn tail.
    if _anchor_log_is_torn():
        raise AnchorLogTornError(ANCHOR_TORN_MESSAGE)

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

    if os.name == 'posix':
        dir_fd = os.open(str(DATA_DIR), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _select_pq_signer(anchors: list[dict[str, Any]]) -> tuple[Any, str] | None:
    """Decide whether the next anchor is hybrid; refuse any post-quantum downgrade."""
    mode = pq_mode()
    already_pq = any(item.get('schema') in HYBRID_SCHEMAS for item in anchors)
    if mode == 'off':
        if already_pq:
            raise ValueError('ledger already has post-quantum anchors; '
                             'RF_PQ_SIGNING=off would downgrade it')
        return None
    if mode == 'auto' and not already_pq and not pq_available():
        return None
    try:
        return load_or_create_pq_keypair()
    except (RuntimeError, TypeError) as exc:
        raise ValueError(f'post-quantum anchor signing unavailable: {exc}') from exc


def _check_extends_newest_anchor(rows: list[tuple[Any, ...]], anchors: list[dict[str, Any]],
                                 created_at: str) -> None:
    """Refuse to anchor state that contradicts what the newest anchor already signed.

    The newest anchor commits to the entry hash at its ledger_count and, through the
    hash chain, to every entry before it. A ledger that is shorter than that, or holds
    another hash at that position, was truncated or rewritten after it was signed (or
    restored from an older copy). A new anchor over it would put a valid signature on
    the divergent history, and no verifier accepts such an anchor after its
    predecessor, so the anchor log could never verify again. The same is true of an
    anchor dated before its predecessor, which the independent verifier rejects.

    `rows` must already have passed _check_chain_rows (ids 1..n, hashes chained). This
    is a consistency guard for the signer, not a defence against an attacker who can
    rewrite the data directory, anchor log included: only anchor pins held elsewhere
    detect that.
    """
    if not anchors:
        return
    seq = len(anchors)
    newest = anchors[-1]
    count = newest.get('ledger_count')
    head = newest.get('ledger_head')
    previous_created = newest.get('created_at')
    if (not isinstance(count, int) or isinstance(count, bool) or count < 0
            or not isinstance(head, str) or not isinstance(previous_created, str)
            or not isinstance(newest.get('anchor_hash'), str)):
        raise ValueError(f'anchor {seq} is malformed; refusing to anchor after it')
    if count > len(rows):
        raise ValueError(f'ledger has {len(rows)} entries but anchor {seq} signed {count}; '
                         'refusing to anchor a truncated ledger')
    stored = str(rows[count - 1][5]) if count else '0' * 64
    if stored != head:
        raise ValueError(f'ledger entry {count} differs from the head signed by anchor {seq}; '
                         'refusing to anchor rewritten history')
    if created_at < previous_created:
        raise ValueError(f'system clock ({created_at}) is behind anchor {seq} '
                         f'({previous_created}); correct the clock before anchoring')


def create_anchor() -> dict[str, Any]:
    private, public, key_id = load_or_create_keypair()
    init_db()

    with _anchor_lock():
        # Verify, take the head and build the Merkle leaves from ONE snapshot, so an
        # entry written (or forged) after verification can never be signed unverified.
        rows = _ledger_snapshot()
        ok, reason = _check_chain_rows(rows)
        if not ok:
            raise ValueError(f'ledger verification failed: {reason}')
        row = (rows[-1][0], rows[-1][5]) if rows else None

        anchors = _read_anchors()
        created_at = _utc_now()
        _check_extends_newest_anchor(rows, anchors, created_at)
        pq_signer = _select_pq_signer(anchors)
        previous_anchor_hash = (
            anchors[-1]['anchor_hash'] if anchors else '0' * 64
        )

        last_id = int(row[0]) if row else 0
        head_hash = str(row[1]) if row else '0' * 64

        sequence = len(anchors) + 1

        core = {
            'schema': ANCHOR_SCHEMA_V2,
            'seq': sequence,
            'created_at': created_at,
            'ledger_count': last_id,
            'ledger_head': head_hash,
            'prev_anchor_hash': previous_anchor_hash,
            'key_id': key_id,
        }
        if pq_signer is not None:
            core['schema'] = ANCHOR_SCHEMA_V4
            core['pq_key_id'] = pq_signer[1]
            core['merkle_root'] = _merkle.merkle_root(str(item[5]) for item in rows)

        anchor_hash = _canonical_anchor_hash(core)
        signed = anchor_hash.encode('ascii')
        signature = private.sign(signed)

        anchor = {
            **core,
            'anchor_hash': anchor_hash,
            'signature': base64.b64encode(signature).decode('ascii'),
        }
        if pq_signer is not None:
            pq_signature = pq_signer[0].sign(signed, PQ_CONTEXTS[core['schema']])
            anchor['pq_signature'] = base64.b64encode(pq_signature).decode('ascii')

        _append_anchor_line(anchor)

        return anchor


def verify_anchors() -> tuple[bool, str]:
    try:
        _, public, current_key_id = load_or_create_keypair()
        anchors = _read_anchors()
    except AnchorLogTornError:
        return False, ANCHOR_TORN_MESSAGE
    except Exception:
        return False, 'anchor verification initialization failed'

    if not anchors:
        return True, 'no anchors'

    previous_anchor_hash = '0' * 64
    previous_ledger_count = 0
    previous_created = ''
    seen_pq = False
    seen_merkle = False
    pq_public: tuple[Any, str] | None = None
    ledger_heads: list[str] = []
    merkle_claims: dict[int, list[tuple[int, str]]] = {}

    for index, anchor in enumerate(anchors, 1):
        try:
            sequence = int(anchor['seq'])
            ledger_count = int(anchor['ledger_count'])
            # Compared with the ledger entry it names once the signature
            # chain is verified (below).
            ledger_heads.append(str(anchor['ledger_head']))
            previous_hash = str(anchor['prev_anchor_hash'])
            anchor_hash = str(anchor['anchor_hash'])
            signature = base64.b64decode(
                anchor['signature'],
                validate=True,
            )
        except Exception:
            return False, f'anchor {index} malformed'

        if sequence != index:
            return False, f'anchor sequence mismatch at {index}'

        if previous_hash != previous_anchor_hash:
            return False, f'anchor chain broken at {index}'

        if ledger_count < previous_ledger_count:
            return False, f'ledger count regressed at anchor {index}'

        # Same rule and same wording as the independent verifier, so a ledger the
        # verifier would reject is not reported healthy here.
        created = anchor.get('created_at')
        if not isinstance(created, str):
            return False, f'anchor {index} malformed'
        if created < previous_created:
            return False, f'anchor time regressed at {index}'

        legacy = 'key_id' not in anchor
        schema = anchor.get('schema')
        hybrid = schema in HYBRID_SCHEMAS
        merkle = schema == ANCHOR_SCHEMA_V4

        if legacy and hybrid:
            return False, f'anchor {index} claims {schema} without a key identity'
        if seen_pq and not hybrid:
            return False, f'post-quantum downgrade at anchor {index}'
        if seen_merkle and not merkle:
            return False, f'merkle commitment downgrade at anchor {index}'

        try:
            if legacy:
                core = {key: anchor[key] for key in ANCHOR_CORE_LEGACY}
                expected_hash = _legacy_anchor_hash(core)
            else:
                if anchor.get('key_id') != current_key_id:
                    return False, f'key identity mismatch at anchor {index}'
                fields = (ANCHOR_CORE_V4 if merkle else
                          ANCHOR_CORE_V3 if hybrid else ANCHOR_CORE_V2)
                core = {key: anchor[key] for key in fields}
                expected_hash = _canonical_anchor_hash(core)
                if merkle:
                    root = anchor['merkle_root']
                    if not isinstance(root, str) or len(root) != 64 or \
                            root.strip('0123456789abcdef'):
                        return False, f'anchor {index} malformed'
                    merkle_claims.setdefault(ledger_count, []).append((index, root))
        except (KeyError, ValueError):
            return False, f'anchor {index} malformed'

        if not secrets.compare_digest(expected_hash, anchor_hash):
            return False, f'anchor hash mismatch at {index}'

        try:
            public_key = serialization.load_pem_public_key(
                PUBLIC_KEY_PATH.read_bytes()
            )
            public_key.verify(signature, anchor_hash.encode('ascii'))
        except Exception:
            return False, f'anchor signature invalid at {index}'

        if hybrid:
            if pq_public is None:
                try:
                    pq_public = load_pq_public_key()
                except Exception:
                    return False, 'post-quantum verification unavailable'
                if pq_public is None:
                    return False, f'post-quantum public key missing for anchor {index}'
            if anchor.get('pq_key_id') != pq_public[1]:
                return False, f'post-quantum key identity mismatch at anchor {index}'
            try:
                pq_signature = base64.b64decode(anchor['pq_signature'], validate=True)
                pq_public[0].verify(pq_signature, anchor_hash.encode('ascii'),
                                    PQ_CONTEXTS[schema])
            except Exception:
                return False, f'post-quantum signature invalid at anchor {index}'
            seen_pq = True
            seen_merkle = seen_merkle or merkle

        previous_anchor_hash = anchor_hash
        previous_ledger_count = ledger_count
        previous_created = created

    conn = _connect()
    try:
        row = conn.execute(
            'SELECT id, entry_hash FROM ledger_entries '
            'ORDER BY id DESC LIMIT 1'
        ).fetchone()
    finally:
        conn.close()

    try:
        anchor_conn = _connect()
        try:
            for index, item in enumerate(anchors, 1):
                anchored_count = int(item['ledger_count'])
                if anchored_count == 0:
                    stored_head = '0' * 64
                else:
                    found = anchor_conn.execute(
                        'SELECT entry_hash FROM ledger_entries WHERE id = ?',
                        (anchored_count,),
                    ).fetchone()
                    if found is None:
                        return (
                            False,
                            f'anchor {index} references missing ledger entry '
                            f'{anchored_count}',
                        )
                    stored_head = str(found[0])
                if not secrets.compare_digest(
                    stored_head, ledger_heads[index - 1]
                ):
                    return (
                        False,
                        f'anchor {index} ledger head differs from ledger '
                        f'entry {anchored_count}',
                    )
            if merkle_claims:
                hashes = [str(item[0]) for item in anchor_conn.execute(
                    'SELECT entry_hash FROM ledger_entries WHERE id <= ? ORDER BY id ASC',
                    (max(merkle_claims),),
                ).fetchall()]
                try:
                    roots = _merkle.roots_at(hashes, merkle_claims)
                except ValueError:
                    return False, 'merkle commitment references missing ledger entries'
                for count, claims in merkle_claims.items():
                    for index, claimed in claims:
                        if not secrets.compare_digest(roots[count], claimed):
                            return False, f'merkle root mismatch at anchor {index}'
        finally:
            anchor_conn.close()
    except sqlite3.Error:
        return False, 'ledger unreadable'

    current_count = int(row[0]) if row else 0
    current_head = str(row[1]) if row else '0' * 64

    latest = anchors[-1]

    if int(latest['ledger_count']) > current_count:
        return False, 'ledger is shorter than latest anchor'

    if int(latest['ledger_count']) == current_count:
        if latest['ledger_head'] != current_head:
            return False, 'ledger head differs from latest anchor'

    return True, f'verified {len(anchors)} anchors'


def repair_anchor_log() -> dict[str, Any]:
    """Recover from an interrupted anchor append without destroying evidence.

    Under the anchor lock: if the log does not end in a newline, the trailing fragment
    is copied to anchors.torn.<UTC timestamp>.bin (mode 0600) and the log is rewritten
    atomically, either terminated (the fragment is a complete JSON object that only lost
    its newline; verify_anchors still checks its hash and signatures) or truncated to its
    last complete line. The repair is then recorded in the ledger itself as a
    `maintenance.anchor_log.repaired` entry with the fragment's SHA-256, so the repair is
    tamper-evident. A log that is not torn is left untouched.
    """
    with _anchor_lock():
        if not ANCHOR_PATH.exists() or not _anchor_log_is_torn():
            return {'status': 'clean'}
        raw = ANCHOR_PATH.read_bytes()
        cut = raw.rfind(b'\n') + 1
        fragment = raw[cut:]
        try:
            complete = isinstance(json.loads(fragment.decode('utf-8')), dict)
        except ValueError:
            complete = False
        stamp = _utc_now().replace(':', '').replace('-', '').replace('.', '')
        quarantine = DATA_DIR / f'anchors.torn.{stamp}.bin'
        _atomic_write(quarantine, fragment, 0o600)
        action = 'terminated' if complete else 'truncated'
        _atomic_write(ANCHOR_PATH, raw + b'\n' if complete else raw[:cut], 0o600)
        entry = append_entry('maintenance.anchor_log.repaired', {
            'action': action,
            'fragment_bytes': len(fragment),
            'fragment_sha256': _sha256(fragment),
            'quarantine': quarantine.name,
        })
    return {'status': 'repaired', 'action': action, 'fragment_bytes': len(fragment),
            'quarantine': str(quarantine), 'ledger_entry': entry['id']}


def health() -> dict[str, Any]:
    import logging
    log = logging.getLogger('rightsframes.core')
    chain_ok, chain_reason = verify_chain()
    anchor_ok, anchor_reason = verify_anchors()
    if not chain_ok:
        log.warning('ledger verification failed: %s', chain_reason)
    if not anchor_ok:
        log.warning('anchor verification failed: %s', anchor_reason)

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
