from __future__ import annotations

import importlib
import json
import os
import stat
from pathlib import Path

import pytest


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_DATA_DIR', str(tmp_path))
    import core.rf_core as rf_core

    rf_core = importlib.reload(rf_core)
    rf_core.init_db()
    return rf_core


def test_entry_type_limit(isolated):
    with pytest.raises(ValueError, match='entry_type exceeds maximum length'):
        isolated.append_entry('x' * 129, {})


def test_payload_limit(isolated):
    with pytest.raises(ValueError, match='payload exceeds maximum size'):
        isolated.append_entry(
            'test',
            {'data': 'x' * isolated.MAX_PAYLOAD_BYTES},
        )


def test_transactional_chain(isolated):
    first = isolated.append_entry('test', {'n': 1})
    second = isolated.append_entry('test', {'n': 2})

    assert second['id'] == first['id'] + 1
    assert second['prev_hash'] == first['entry_hash']

    ok, reason = isolated.verify_chain()
    assert ok, reason


def test_chain_detects_tampering(isolated):
    isolated.append_entry('test', {'n': 1})

    with isolated.DB_PATH.open('rb') as handle:
        original = handle.read()

    import sqlite3

    with sqlite3.connect(isolated.DB_PATH) as conn:
        conn.execute(
            'UPDATE ledger_entries SET payload=? WHERE id=1',
            (json.dumps({'n': 999}),),
        )
        conn.commit()

    ok, reason = isolated.verify_chain()
    assert not ok
    assert 'hash mismatch' in reason

    isolated.DB_PATH.write_bytes(original)


def test_database_filesystem_is_created_restrictively(isolated):
    mode = stat.S_IMODE(isolated.DATA_DIR.stat().st_mode)
    assert mode == 0o700


def test_key_identity_matches_public_key(isolated):
    private, public, key_id = isolated.load_or_create_keypair()

    assert private is not None
    assert len(public) == 32
    assert key_id.startswith('ed25519:')

    stored_id = isolated.KEY_ID_PATH.read_text().strip()
    assert stored_id == key_id


def test_anchor_round_trip(isolated):
    isolated.append_entry('test', {'n': 1})
    anchor = isolated.create_anchor()

    assert anchor['schema'] == 'rf.anchor.v2'
    assert anchor['key_id'].startswith('ed25519:')

    ok, reason = isolated.verify_anchors()
    assert ok, reason


def test_anchor_consecutive_round_trip(isolated):
    isolated.append_entry('test', {'n': 1})
    first = isolated.create_anchor()

    isolated.append_entry('test', {'n': 2})
    second = isolated.create_anchor()

    assert second['seq'] == first['seq'] + 1
    assert second['prev_anchor_hash'] == first['anchor_hash']

    ok, reason = isolated.verify_anchors()
    assert ok, reason


def test_legacy_anchor_remains_verifiable(isolated):
    isolated.append_entry('test', {'n': 1})

    private, _, _ = isolated.load_or_create_keypair()

    core = {
        'schema': 'rf.anchor.v1',
        'seq': 1,
        'created_at': '2026-10-03T00:00:00Z',
        'ledger_count': 1,
        'ledger_head': isolated.append_entry.__name__ and '',
        'prev_anchor_hash': '0' * 64,
    }

    import sqlite3

    with sqlite3.connect(isolated.DB_PATH) as conn:
        row = conn.execute(
            'SELECT entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1'
        ).fetchone()

    core['ledger_head'] = row[0]

    anchor_hash = isolated._legacy_anchor_hash(core)
    signature = private.sign(anchor_hash.encode('ascii'))

    anchor = {
        **core,
        'anchor_hash': anchor_hash,
        'signature': __import__('base64').b64encode(signature).decode('ascii'),
    }

    isolated.ANCHOR_PATH.write_text(
        json.dumps(anchor, sort_keys=True) + '\n',
        encoding='utf-8',
    )

    ok, reason = isolated.verify_anchors()
    assert ok, reason


def test_atomic_key_material_exists(isolated):
    isolated.load_or_create_keypair()

    assert isolated.PRIVATE_KEY_PATH.exists()
    assert isolated.PUBLIC_KEY_PATH.exists()
    assert isolated.KEY_ID_PATH.exists()

    private_mode = stat.S_IMODE(
        isolated.PRIVATE_KEY_PATH.stat().st_mode
    )
    identity_mode = stat.S_IMODE(
        isolated.KEY_ID_PATH.stat().st_mode
    )

    assert private_mode == 0o600
    assert identity_mode == 0o600


def test_anchor_log_is_jsonl(isolated):
    isolated.append_entry('test', {'n': 1})
    isolated.create_anchor()

    lines = isolated.ANCHOR_PATH.read_text(
        encoding='utf-8'
    ).splitlines()

    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed['seq'] == 1
