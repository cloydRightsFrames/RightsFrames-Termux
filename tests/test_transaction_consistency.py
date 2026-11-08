"""Transaction and crash consistency of the ledger, the anchor log and the auth store.

Each test pins down a failure that was possible before v0.4.0:
  * an entry written between chain verification and head selection could be signed
    into an anchor without ever being verified (time-of-check/time-of-use);
  * a torn anchor append (crash, power loss) wedged anchoring and verification with an
    opaque JSON error, and the next append would have been glued onto the fragment;
  * credential changes and idempotent writes committed to principals.db and ledger.db
    separately, so a crash between the two left an audit entry without its change, or
    a duplicated entry after an idempotent retry.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_auth  # noqa: E402
import rf_core  # noqa: E402


def _point(mp, base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)
    return base


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    return _point(monkeypatch, tmp_path / 'data')


def _entry_types() -> list[str]:
    conn = sqlite3.connect(rf_core.DB_PATH)
    try:
        return [row[0] for row in conn.execute('SELECT entry_type FROM ledger_entries ORDER BY id')]
    finally:
        conn.close()


def _forge_row(entry_id: int) -> None:
    conn = sqlite3.connect(rf_core.DB_PATH)
    try:
        conn.execute('INSERT INTO ledger_entries (id, ts, entry_type, payload, prev_hash, entry_hash) '
                     "VALUES (?, '2026-01-01T00:00:00.000000Z', 'forged', '{}', ?, ?)",
                     (entry_id, 'f' * 64, hashlib.sha256(b'forged').hexdigest()))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- anchor snapshot (TOCTOU)


def test_entry_written_after_verification_is_never_signed(data, monkeypatch):
    for n in range(3):
        rf_core.append_entry('evt', {'n': n})
    real_check = rf_core._check_chain_rows

    def check_then_race(rows):
        result = real_check(rows)
        _forge_row(len(rows) + 1)  # lands after the verified snapshot was taken
        return result

    monkeypatch.setattr(rf_core, '_check_chain_rows', check_then_race)
    anchor = rf_core.create_anchor()
    monkeypatch.setattr(rf_core, '_check_chain_rows', real_check)
    assert anchor['ledger_count'] == 3  # only what was verified is signed
    assert rf_core.verify_chain() == (False, 'previous hash mismatch at 4')
    with pytest.raises(ValueError, match='ledger verification failed'):
        rf_core.create_anchor()


@pytest.mark.skipif(not rf_core.pq_available(), reason='cryptography build lacks ML-DSA-65')
def test_merkle_root_comes_from_the_verified_snapshot(data, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    for n in range(5):
        rf_core.append_entry('evt', {'n': n})
    anchor = rf_core.create_anchor()
    hashes = [row[5] for row in rf_core._ledger_snapshot()]
    import rf_merkle
    assert anchor['merkle_root'] == rf_merkle.merkle_root(hashes)
    assert anchor['ledger_head'] == hashes[-1]


# ---------------------------------------------------------------- torn anchor log


def _tear(fraction: float = 0.5, drop_newline_only: bool = False) -> bytes:
    raw = rf_core.ANCHOR_PATH.read_bytes()
    line = raw.splitlines(keepends=True)[-1]
    fragment = line[:-1] if drop_newline_only else line[:int(len(line) * fraction)]
    rf_core.ANCHOR_PATH.write_bytes(raw + fragment)
    return fragment


def test_torn_anchor_log_is_reported_clearly_and_blocks_appends(data):
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    before = rf_core.ANCHOR_PATH.read_bytes()
    _tear()
    assert rf_core.verify_anchors() == (False, rf_core.ANCHOR_TORN_MESSAGE)
    with pytest.raises(rf_core.AnchorLogTornError, match='rf_repair_anchor_log'):
        rf_core.create_anchor()
    assert rf_core.ANCHOR_PATH.read_bytes().startswith(before)  # nothing glued on
    assert rf_core.health()['status'] == 'degraded'


def test_repair_truncates_fragment_keeps_evidence_and_audits(data):
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    good = rf_core.ANCHOR_PATH.read_bytes()
    fragment = _tear(0.4)
    result = rf_core.repair_anchor_log()
    assert result['status'] == 'repaired' and result['action'] == 'truncated'
    assert rf_core.ANCHOR_PATH.read_bytes() == good
    assert Path(result['quarantine']).read_bytes() == fragment
    if os.name == 'posix':
        assert Path(result['quarantine']).stat().st_mode & 0o777 == 0o600
    assert _entry_types()[-1] == 'maintenance.anchor_log.repaired'
    conn = sqlite3.connect(rf_core.DB_PATH)
    payload = json.loads(conn.execute('SELECT payload FROM ledger_entries ORDER BY id DESC LIMIT 1')
                         .fetchone()[0])
    conn.close()
    assert payload['fragment_sha256'] == hashlib.sha256(fragment).hexdigest()
    assert rf_core.verify_chain()[0] and rf_core.verify_anchors() == (True, 'verified 1 anchors')
    assert rf_core.create_anchor()['seq'] == 2  # anchoring resumes and covers the repair entry
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    assert rf_core.repair_anchor_log() == {'status': 'clean'}


def test_repair_terminates_a_complete_anchor_that_lost_its_newline(data):
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    rf_core.append_entry('evt', {'n': 2})
    second = rf_core.create_anchor()
    raw = rf_core.ANCHOR_PATH.read_bytes()
    rf_core.ANCHOR_PATH.write_bytes(raw[:-1])  # only the final newline was lost
    result = rf_core.repair_anchor_log()
    assert result['action'] == 'terminated'
    assert rf_core._read_anchors()[-1]['anchor_hash'] == second['anchor_hash']
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')


def test_repair_leaves_a_clean_or_missing_log_untouched(data):
    assert rf_core.repair_anchor_log() == {'status': 'clean'}
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    before = rf_core.ANCHOR_PATH.read_bytes()
    count = len(_entry_types())
    assert rf_core.repair_anchor_log() == {'status': 'clean'}
    assert rf_core.ANCHOR_PATH.read_bytes() == before and len(_entry_types()) == count


def test_repair_tool_end_to_end(tmp_path):
    data_dir = tmp_path / 'node'
    env = {**os.environ, 'RF_DATA_DIR': str(data_dir), 'RF_PQ_SIGNING': 'off'}
    setup = ('import sys; sys.path.insert(0, sys.argv[1]); from core import rf_core; '
             "rf_core.append_entry('evt', {'n': 1}); rf_core.create_anchor()")
    subprocess.run([sys.executable, '-c', setup, str(ROOT)], env=env, check=True, timeout=120)
    log = data_dir / 'anchors.jsonl'
    log.write_bytes(log.read_bytes() + b'{"schema":"rf.anc')
    tool = [sys.executable, str(ROOT / 'tools' / 'rf_repair_anchor_log.py'), '--data-dir', str(data_dir)]
    check = subprocess.run(tool + ['--check'], capture_output=True, text=True, timeout=120)
    assert check.returncode == 2 and json.loads(check.stdout) == {'torn': True}
    repair = subprocess.run(tool, capture_output=True, text=True, timeout=120)
    assert repair.returncode == 0, repair.stderr
    report = json.loads(repair.stdout)
    assert report['action'] == 'truncated' and report['anchors'] == 'verified 1 anchors'
    assert subprocess.run(tool + ['--check'], capture_output=True, timeout=120).returncode == 0
    missing = subprocess.run(tool[:-1] + [str(tmp_path / 'none')], capture_output=True, timeout=120)
    assert missing.returncode == 1


# ---------------------------------------------------------------- auth store atomicity


def test_principal_change_and_audit_entry_commit_together(data, monkeypatch):
    rf_auth.create_principal('admin-1', ['admin:principals'], 'a', 'test')
    rf_auth.create_principal('reader-1', ['ledger:read'], 'r', 'admin-1')
    count = len(_entry_types())

    def failing_audit(conn, entry_type, payload):
        raise sqlite3.OperationalError('disk I/O error')

    with monkeypatch.context() as patch:
        patch.setattr(rf_core, 'append_entry_in', failing_audit)
        with pytest.raises(sqlite3.OperationalError):
            rf_auth.create_principal('user-1', ['ledger:read'], 'u', 'admin-1')
        with pytest.raises(sqlite3.OperationalError):
            rf_auth.revoke_principal('reader-1', 'admin-1')
    assert rf_auth.get_principal('user-1') is None            # no principal without its audit entry
    assert rf_auth.get_principal('reader-1')['revoked_at'] is None
    assert len(_entry_types()) == count                        # and no audit entry without its change
    rf_auth.revoke_principal('reader-1', 'admin-1')
    assert rf_auth.get_principal('reader-1')['revoked_at'] is not None
    assert _entry_types()[-1] == 'auth.principal.revoked'


def test_audit_entry_is_rolled_back_with_a_failed_principal_insert(data):
    rf_auth.create_principal('admin-1', ['admin:principals'], 'a', 'test')
    count = len(_entry_types())
    with pytest.raises(rf_auth.Conflict):
        rf_auth.create_principal('admin-1', ['ledger:read'], 'dup', 'test')
    assert len(_entry_types()) == count
    assert rf_core.verify_chain()[0]


def test_idempotent_write_is_exactly_once_even_if_it_fails_midway(data):
    calls = []

    def action(conn):
        rf_core.append_entry_in(conn, 'audit.api', {'action': 'entries.append'})
        calls.append(1)
        if len(calls) == 1:
            raise OSError('process killed after the first entry')
        return rf_core.append_entry_in(conn, 'evt', {'n': 1})

    with pytest.raises(OSError):
        rf_auth.idempotent_append('p-1', 'key-00001', 'h', action)
    assert _entry_types() == []                      # nothing half-written
    first, replayed = rf_auth.idempotent_append('p-1', 'key-00001', 'h', action)
    assert not replayed and _entry_types() == ['audit.api', 'evt']
    again, replayed = rf_auth.idempotent_append('p-1', 'key-00001', 'h', action)
    assert replayed and again == json.loads(json.dumps(first, sort_keys=True))
    assert _entry_types() == ['audit.api', 'evt']    # retry appended nothing
    with pytest.raises(rf_auth.IdempotencyConflict):
        rf_auth.idempotent_append('p-1', 'key-00001', 'other', action)


def test_append_entry_in_requires_a_transaction(data):
    conn = rf_core._connect()
    try:
        with pytest.raises(RuntimeError, match='write_transaction'):
            rf_core.append_entry_in(conn, 'evt', {})
    finally:
        conn.close()


def test_legacy_principals_db_is_migrated_once_atomically(data):
    rf_core.append_entry('evt', {'n': 0})
    legacy = rf_core.DATA_DIR / 'principals.db'
    secret = 'legacy-secret-value'
    salt = '00' * 16
    digest = rf_auth._token_hash(secret, salt)
    conn = sqlite3.connect(legacy)
    conn.execute('CREATE TABLE principals (id TEXT PRIMARY KEY, scopes TEXT NOT NULL, label TEXT '
                 'NOT NULL, token_hash TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)')
    conn.execute('CREATE TABLE idempotency (principal_id TEXT NOT NULL, key TEXT NOT NULL, '
                 'request_hash TEXT NOT NULL, response TEXT NOT NULL, created_at TEXT NOT NULL, '
                 'PRIMARY KEY (principal_id, key))')
    conn.execute('INSERT INTO principals VALUES (?, ?, ?, ?, ?, NULL)',
                 ('old-admin', json.dumps(['admin:principals']), 'legacy',
                  f'pbkdf2_sha256${rf_auth._PBKDF2_ITERATIONS}${salt}${digest}',
                  '2026-01-01T00:00:00.000000Z'))
    conn.execute('INSERT INTO idempotency VALUES (?, ?, ?, ?, ?)',
                 ('old-admin', 'key-legacy1', 'h', '{"id":1}', '2026-01-01T00:00:00.000000Z'))
    conn.commit()
    conn.close()

    principal = rf_auth.authenticate(f'rfp1.old-admin.{secret}')
    assert principal == {'id': 'old-admin', 'scopes': frozenset({'admin:principals'})}
    assert not legacy.exists() and (rf_core.DATA_DIR / 'principals.db.migrated').exists()
    assert _entry_types() == ['evt', 'auth.store.migrated']
    replay, replayed = rf_auth.idempotent_append('old-admin', 'key-legacy1', 'h', lambda c: {})
    assert replayed and replay == {'id': 1}
    rf_auth.list_principals()
    assert _entry_types() == ['evt', 'auth.store.migrated']  # migrated exactly once
    assert rf_core.verify_chain() == (True, 'verified 2 entries')


def test_migration_conflict_rolls_back_completely(data):
    rf_auth.create_principal('dup-admin', ['admin:principals'], 'new', 'test')
    count = len(_entry_types())
    legacy = rf_core.DATA_DIR / 'principals.db'
    conn = sqlite3.connect(legacy)
    conn.execute('CREATE TABLE principals (id TEXT PRIMARY KEY, scopes TEXT NOT NULL, label TEXT '
                 'NOT NULL, token_hash TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)')
    conn.execute("INSERT INTO principals VALUES ('dup-admin', '[]', 'old', 'x', 't', NULL)")
    conn.commit()
    conn.close()
    with pytest.raises(sqlite3.IntegrityError):
        rf_auth.list_principals()
    assert legacy.exists()                       # left in place for the operator
    assert len(_entry_types()) == count          # no migration entry
