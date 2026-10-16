"""Per-principal credentials, scopes and idempotency for RightsFrames API v1.

Tokens look like rfp1.<principal-id>.<secret>. Only SHA-256(secret) is stored; the secret
is 256 bits of CSPRNG output, so a fast hash is appropriate. Principal ids are never reused.
Creation and revocation are written to the evidence ledger in the same transaction scope:
if the audit entry cannot be written, the change is rolled back.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from typing import Any, Callable

import rf_core

SCOPES = frozenset({
    'entries:write', 'ledger:read', 'anchor:create', 'evidence:export', 'admin:principals',
})
TOKEN_PREFIX = 'rfp1'
_ID = re.compile(r'^[a-z0-9][a-z0-9-]{2,39}$')
_PBKDF2_NAME = 'sha256'
_PBKDF2_ITERATIONS = 310_000
_DUMMY_SALT_HEX = secrets.token_hex(16)
_DUMMY_HASH = hashlib.pbkdf2_hmac(
    _PBKDF2_NAME, b'rf-dummy-credential', bytes.fromhex(_DUMMY_SALT_HEX), _PBKDF2_ITERATIONS
).hex()


def _token_hash(secret: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        _PBKDF2_NAME, secret.encode('utf-8'), bytes.fromhex(salt_hex), _PBKDF2_ITERATIONS
    ).hex()


def _new_token_hash(secret: str) -> tuple[str, str]:
    salt_hex = secrets.token_hex(16)
    return salt_hex, _token_hash(secret, salt_hex)


class Conflict(ValueError):
    """State conflict (exists, already revoked, last admin)."""


class IdempotencyConflict(Exception):
    """Idempotency key reused with a different request."""


def _db() -> sqlite3.Connection:
    rf_core._secure_directory()
    conn = sqlite3.connect(str(rf_core.DATA_DIR / 'principals.db'), timeout=5, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.execute(
        'CREATE TABLE IF NOT EXISTS principals ('
        'id TEXT PRIMARY KEY, scopes TEXT NOT NULL, label TEXT NOT NULL, '
        'token_hash TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)'
    )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS idempotency ('
        'principal_id TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL, '
        'response TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (principal_id, key))'
    )
    return conn


def _rollback(conn: sqlite3.Connection) -> None:
    try:
        conn.execute('ROLLBACK')
    except sqlite3.Error:
        # Best-effort cleanup: avoid masking the original exception path
        # if rollback itself fails (for example, no active transaction).
        pass


def validate_scopes(scopes: Any) -> list[str]:
    if not isinstance(scopes, (list, tuple, set, frozenset)) or not scopes:
        raise ValueError('at least one scope is required')
    unique = sorted(set(scopes))
    unknown = [item for item in unique if item not in SCOPES]
    if unknown:
        raise ValueError(f'unknown scopes: {unknown}')
    return unique


def valid_principal_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.match(value))


def create_principal(principal_id: str, scopes: Any, label: str = '', actor: str = 'unknown') -> str:
    if not valid_principal_id(principal_id):
        raise ValueError('invalid principal id')
    if not isinstance(label, str) or len(label) > 128:
        raise ValueError('invalid label')
    scope_list = validate_scopes(scopes)
    secret = secrets.token_urlsafe(32)
    salt_hex, token_hash = _new_token_hash(secret)
    stored_hash = f'pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt_hex}${token_hash}'
    conn = _db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        try:
            conn.execute(
                'INSERT INTO principals (id, scopes, label, token_hash, created_at, revoked_at) '
                'VALUES (?, ?, ?, ?, ?, NULL)',
                (principal_id, json.dumps(scope_list), label, stored_hash, rf_core._utc_now()),
            )
        except sqlite3.IntegrityError:
            raise Conflict('principal already exists') from None
        rf_core.append_entry('auth.principal.created', {
            'principal': principal_id, 'scopes': scope_list, 'label': label, 'actor': actor,
        })
        conn.execute('COMMIT')
    except Exception:
        _rollback(conn)
        raise
    finally:
        conn.close()
    return f'{TOKEN_PREFIX}.{principal_id}.{secret}'


def authenticate(token: Any) -> dict[str, Any] | None:
    if not isinstance(token, str) or len(token) > 256:
        return None
    parts = token.split('.')
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not valid_principal_id(parts[1]) or not parts[2]:
        return None
    conn = _db()
    try:
        row = conn.execute(
            'SELECT scopes, token_hash, revoked_at FROM principals WHERE id = ?', (parts[1],)
        ).fetchone()
    finally:
        conn.close()
    stored = row[1] if row else f'pbkdf2_sha256${_PBKDF2_ITERATIONS}${_DUMMY_SALT_HEX}${_DUMMY_HASH}'
    try:
        scheme, iterations_s, salt_hex, expected = stored.split('$', 3)
        if scheme != 'pbkdf2_sha256':
            raise ValueError('unsupported hash scheme')
        iterations = int(iterations_s)
        supplied = hashlib.pbkdf2_hmac(
            _PBKDF2_NAME, parts[2].encode('utf-8'), bytes.fromhex(salt_hex), iterations
        ).hex()
    except (ValueError, TypeError):
        supplied = _DUMMY_HASH
        expected = _DUMMY_HASH
    matched = hmac.compare_digest(supplied, expected if row else _DUMMY_HASH)
    if row is None or not matched or row[2] is not None:
        return None
    return {'id': parts[1], 'scopes': frozenset(json.loads(row[0]))}


def get_principal(principal_id: str) -> dict[str, Any] | None:
    conn = _db()
    try:
        row = conn.execute(
            'SELECT id, scopes, label, created_at, revoked_at FROM principals WHERE id = ?',
            (principal_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {'id': row[0], 'scopes': json.loads(row[1]), 'label': row[2],
            'created_at': row[3], 'revoked_at': row[4]}


def list_principals() -> list[dict[str, Any]]:
    conn = _db()
    try:
        rows = conn.execute(
            'SELECT id, scopes, label, created_at, revoked_at FROM principals ORDER BY created_at, id'
        ).fetchall()
    finally:
        conn.close()
    return [{'id': r[0], 'scopes': json.loads(r[1]), 'label': r[2],
             'created_at': r[3], 'revoked_at': r[4]} for r in rows]


def revoke_principal(principal_id: str, actor: str) -> None:
    conn = _db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT scopes, revoked_at FROM principals WHERE id = ?', (principal_id,)
        ).fetchone()
        if row is None:
            raise LookupError('principal not found')
        if row[1] is not None:
            raise Conflict('principal already revoked')
        if 'admin:principals' in json.loads(row[0]):
            active_admins = sum(
                1 for (scopes,) in conn.execute('SELECT scopes FROM principals WHERE revoked_at IS NULL')
                if 'admin:principals' in json.loads(scopes)
            )
            if active_admins <= 1:
                raise Conflict('cannot revoke the last active admin')
        conn.execute('UPDATE principals SET revoked_at = ? WHERE id = ?',
                     (rf_core._utc_now(), principal_id))
        rf_core.append_entry('auth.principal.revoked', {'principal': principal_id, 'actor': actor})
        conn.execute('COMMIT')
    except Exception:
        _rollback(conn)
        raise
    finally:
        conn.close()


def idempotent_append(principal_id: str, key: str, request_hash: str,
                      action: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], bool]:
    """Run action() at most once per (principal, key). Returns (result, replayed).

    Residual risk: if the process dies after action() commits to the ledger but before the
    idempotency row commits, a retry appends a second entry. The ledger itself is never
    corrupted; the duplicate is visible and attributable via the audit entries.
    """
    conn = _db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT request_hash, response FROM idempotency WHERE principal_id = ? AND key = ?',
            (principal_id, key),
        ).fetchone()
        if row is not None:
            conn.execute('COMMIT')
            if not hmac.compare_digest(row[0], request_hash):
                raise IdempotencyConflict()
            return json.loads(row[1]), True
        result = action()
        conn.execute(
            'INSERT INTO idempotency (principal_id, key, request_hash, response, created_at) '
            'VALUES (?, ?, ?, ?, ?)',
            (principal_id, key, request_hash, json.dumps(result, sort_keys=True), rf_core._utc_now()),
        )
        conn.execute('COMMIT')
        return result, False
    except IdempotencyConflict:
        raise
    except Exception:
        _rollback(conn)
        raise
    finally:
        conn.close()