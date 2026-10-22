from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import core.rf_core as rf
from core.evidence.envelope import build_envelope, sha256, verify_envelope
from core.evidence.ledger import build_record, verify_chain as verify_evidence_chain
from core.evidence.merkle import (
    build_checkpoint,
    build_proof,
    merkle_root,
    verify_proof,
)
from core.evidence.signing import generate_keypair, sign, verify


def isolate_rf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rf, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(rf, 'DB_PATH', tmp_path / 'ledger.db')
    monkeypatch.setattr(rf, 'PRIVATE_KEY_PATH', tmp_path / 'signing_key.pem')
    monkeypatch.setattr(rf, 'PUBLIC_KEY_PATH', tmp_path / 'signing_key.pub.pem')
    monkeypatch.setattr(rf, 'KEY_ID_PATH', tmp_path / 'signing_key.id')
    monkeypatch.setattr(rf, 'ANCHOR_PATH', tmp_path / 'anchors.jsonl')
    monkeypatch.setattr(rf, 'LOCK_PATH', tmp_path / 'anchors.lock')


def test_rf_secure_directory_oserror(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rf.os,
        'chmod',
        lambda path, mode: (_ for _ in ()).throw(OSError('chmod denied')),
    )
    rf._secure_directory()


def test_rf_atomic_write_chmod_failure(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    target = tmp_path / 'atomic.bin'
    original = rf.os.chmod

    def fail_chmod(path, mode):
        if path == target:
            raise OSError('chmod denied')
        return original(path, mode)

    monkeypatch.setattr(rf.os, 'chmod', fail_chmod)
    rf._atomic_write(target, b'rightsframes', 0o600)
    assert target.read_bytes() == b'rightsframes'


def test_rf_atomic_write_cleanup(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    target = tmp_path / 'atomic.bin'
    original_replace = rf.os.replace

    def fail_replace(src, dst):
        raise OSError('replace denied')

    monkeypatch.setattr(rf.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='replace denied'):
        rf._atomic_write(target, b'rightsframes', 0o600)

    monkeypatch.setattr(rf.os, 'replace', original_replace)
    assert list(tmp_path.glob('.atomic.bin.*')) == []


def test_rf_payload_canonicalization_and_limits(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match='payload must be an object'):
        rf._payload_bytes([])

    with pytest.raises(ValueError, match='payload exceeds maximum size'):
        rf._payload_bytes({'x': 'a' * rf.MAX_PAYLOAD_BYTES})

    encoded = rf._payload_bytes({'z': 1, 'a': 2})
    assert encoded == b'{"a":2,"z":1}'


def test_rf_keypair_create_reuse_and_permissions(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    private, public, key_id = rf.load_or_create_keypair()

    assert rf.PRIVATE_KEY_PATH.exists()
    assert rf.PUBLIC_KEY_PATH.exists()
    assert rf.KEY_ID_PATH.exists()
    assert len(public) == 32
    assert key_id == rf._key_id(public)

    private2, public2, key_id2 = rf.load_or_create_keypair()

    assert private2.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ) == private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert public2 == public
    assert key_id2 == key_id


def test_rf_invalid_stored_private_key_type(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rf.PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    rf.PRIVATE_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    with pytest.raises(TypeError, match='signing key is not Ed25519'):
        rf.load_or_create_keypair()


def test_rf_public_key_mismatch(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.load_or_create_keypair()

    other = rf.Ed25519PrivateKey.generate()
    other_public = other.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rf.PUBLIC_KEY_PATH.write_bytes(other_public)

    with pytest.raises(ValueError, match='public key does not match private key'):
        rf.load_or_create_keypair()


def test_rf_public_key_invalid_object(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.load_or_create_keypair()

    monkeypatch.setattr(
        rf.serialization,
        'load_pem_public_key',
        lambda data: object(),
    )

    with pytest.raises(TypeError, match='stored public key is invalid'):
        rf.load_or_create_keypair()


def test_rf_key_id_mismatch(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.load_or_create_keypair()
    rf.KEY_ID_PATH.write_text('ed25519:' + '0' * 64, encoding='utf-8')

    with pytest.raises(ValueError, match='signing key identity mismatch'):
        rf.load_or_create_keypair()


def test_rf_append_validation_and_sequence(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match='entry_type must be a non-empty string'):
        rf.append_entry('', {})

    with pytest.raises(ValueError, match='entry_type must be a non-empty string'):
        rf.append_entry(1, {})

    with pytest.raises(ValueError, match='entry_type exceeds maximum length'):
        rf.append_entry('x' * (rf.MAX_ENTRY_TYPE + 1), {})

    with pytest.raises(ValueError, match='payload exceeds maximum size'):
        rf.append_entry('oversize', {'x': 'a' * rf.MAX_PAYLOAD_BYTES})

    first = rf.append_entry('event', {'z': 2, 'a': 1})
    second = rf.append_entry('event', {'value': True})

    assert first['id'] == 1
    assert first['prev_hash'] == '0' * 64
    assert second['id'] == 2
    assert second['prev_hash'] == first['entry_hash']
    assert rf.verify_chain() == (True, 'verified 2 entries')


def test_rf_append_rollback_path(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.init_db()

    class BrokenConnection:
        def __init__(self):
            self.calls = []

        def execute(self, sql, *args):
            self.calls.append(sql)
            if sql == 'BEGIN IMMEDIATE':
                return None
            if sql.startswith('SELECT id, entry_hash'):
                class Cursor:
                    def fetchone(self):
                        return None
                return Cursor()
            raise sqlite3.IntegrityError('forced insert failure')

        def rollback(self):
            self.calls.append('ROLLBACK')

        def commit(self):
            self.calls.append('COMMIT')

        def close(self):
            self.calls.append('CLOSE')

    broken = BrokenConnection()
    monkeypatch.setattr(rf, '_connect', lambda: broken)

    with pytest.raises(sqlite3.IntegrityError, match='forced insert failure'):
        rf.append_entry('event', {'ok': True})

    assert 'ROLLBACK' in broken.calls
    assert 'CLOSE' in broken.calls


def test_rf_verify_chain_id_discontinuity(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('event', {'ok': True})

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute(
        'UPDATE ledger_entries SET id = 2 WHERE id = 1'
    )
    conn.commit()
    conn.close()

    ok, reason = rf.verify_chain()
    assert ok is False
    assert reason == 'id discontinuity at 2'


def test_rf_verify_chain_previous_hash_mismatch(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('one', {'ok': 1})
    rf.append_entry('two', {'ok': 2})

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute(
        'UPDATE ledger_entries SET prev_hash = ? WHERE id = 2',
        ('f' * 64,),
    )
    conn.commit()
    conn.close()

    ok, reason = rf.verify_chain()
    assert ok is False
    assert reason.startswith('previous hash mismatch at 2')


def test_rf_verify_chain_invalid_payload(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('one', {'ok': 1})

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute(
        "UPDATE ledger_entries SET payload = '[]' WHERE id = 1"
    )
    conn.commit()
    conn.close()

    ok, reason = rf.verify_chain()
    assert ok is False
    assert reason.startswith('payload invalid at 1')


def test_rf_verify_chain_hash_mismatch(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('one', {'ok': 1})

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute(
        'UPDATE ledger_entries SET entry_hash = ? WHERE id = 1',
        ('f' * 64,),
    )
    conn.commit()
    conn.close()

    ok, reason = rf.verify_chain()
    assert ok is False
    assert reason.startswith('hash mismatch at 1')


def test_rf_validate_stored_payload_paths(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    rf._validate_stored_payload('{}')

    with pytest.raises(ValueError, match='stored payload is not an object'):
        rf._validate_stored_payload('[]')

    with pytest.raises(json.JSONDecodeError):
        rf._validate_stored_payload('{bad')

    with pytest.raises(ValueError, match='stored payload exceeds maximum size'):
        rf._validate_stored_payload(
            json.dumps({'x': 'a' * rf.MAX_PAYLOAD_BYTES})
        )


def test_rf_anchor_read_paths(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    assert rf._read_anchors() == []

    rf.ANCHOR_PATH.write_text('\n{}\n', encoding='utf-8')
    assert rf._read_anchors() == [{}]

    rf.ANCHOR_PATH.write_text('[]\n', encoding='utf-8')
    with pytest.raises(
        ValueError,
        match='anchor is not an object at 1',
    ):
        rf._read_anchors()

    rf.ANCHOR_PATH.write_text(
        'x' * (rf.MAX_ANCHOR_CORE_BYTES + 1) + '\n',
        encoding='utf-8',
    )
    with pytest.raises(
        ValueError,
        match='anchor line too large at 1',
    ):
        rf._read_anchors()

    rf.ANCHOR_PATH.write_text('{}\n', encoding='utf-8')
    monkeypatch.setattr(rf, 'MAX_ANCHOR_CHAIN_LENGTH', 0)
    with pytest.raises(
        ValueError,
        match='anchor chain exceeds maximum length',
    ):
        rf._read_anchors()


def test_rf_anchor_hash_and_append_limits(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    monkeypatch.setattr(rf, 'MAX_ANCHOR_CORE_BYTES', 3)

    with pytest.raises(
        ValueError,
        match='anchor core exceeds maximum size',
    ):
        rf._canonical_anchor_hash({'value': 'x'})

    with pytest.raises(
        ValueError,
        match='anchor exceeds maximum size',
    ):
        rf._append_anchor_line({'value': 'x'})


def test_rf_anchor_log_size_limit(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    oversized = tmp_path / 'oversized.jsonl'
    oversized.write_bytes(b'x' * (rf.MAX_ANCHOR_BYTES + 1))
    monkeypatch.setattr(rf, 'ANCHOR_PATH', oversized)

    with pytest.raises(
        ValueError,
        match='anchor log exceeds maximum size',
    ):
        rf._read_anchors()


def test_rf_create_and_verify_anchors(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    anchor1 = rf.create_anchor()
    assert anchor1['schema'] == 'rf.anchor.v2'
    assert anchor1['seq'] == 1
    assert rf.verify_anchors() == (True, 'verified 1 anchors')

    rf.append_entry('event', {'x': 1})
    anchor2 = rf.create_anchor()
    assert anchor2['seq'] == 2
    assert anchor2['ledger_count'] == 1
    assert rf.verify_anchors() == (True, 'verified 2 anchors')


def test_rf_verify_anchors_no_anchors(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    assert rf.verify_anchors() == (True, 'no anchors')


@pytest.mark.parametrize(
    ('field', 'value', 'expected'),
    [
        ('seq', 2, 'anchor sequence mismatch'),
        ('prev_anchor_hash', 'f' * 64, 'anchor chain broken'),
        ('ledger_count', -1, 'ledger count regressed'),
        ('key_id', 'ed25519:' + '0' * 64, 'key identity mismatch'),
        ('anchor_hash', 'f' * 64, 'anchor hash mismatch'),
        (
            'signature',
            base64.b64encode(b'bad').decode('ascii'),
            'anchor signature invalid',
        ),
    ],
)
def test_rf_verify_anchor_tamper_matrix(
    tmp_path,
    monkeypatch,
    field,
    value,
    expected,
):
    isolate_rf(tmp_path, monkeypatch)
    rf.create_anchor()

    original = rf.ANCHOR_PATH.read_bytes()
    anchor = json.loads(original.decode('utf-8').strip())
    anchor[field] = value
    rf.ANCHOR_PATH.write_text(
        json.dumps(anchor) + '\n',
        encoding='utf-8',
    )

    ok, reason = rf.verify_anchors()

    assert ok is False
    assert expected in reason

    rf.ANCHOR_PATH.write_bytes(original)


def test_rf_legacy_anchor_verification(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.create_anchor()

    anchor = json.loads(
        rf.ANCHOR_PATH.read_text(encoding='utf-8').strip()
    )

    legacy_core = {
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

    anchor.pop('key_id')
    anchor['anchor_hash'] = rf._legacy_anchor_hash(legacy_core)

    private, _, _ = rf.load_or_create_keypair()
    anchor['signature'] = base64.b64encode(
        private.sign(anchor['anchor_hash'].encode('ascii'))
    ).decode('ascii')

    rf.ANCHOR_PATH.write_text(
        json.dumps(anchor) + '\n',
        encoding='utf-8',
    )

    assert rf.verify_anchors() == (True, 'verified 1 anchors')


def test_rf_ledger_shorter_than_anchor(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('event', {'x': 1})
    rf.create_anchor()

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute('DELETE FROM ledger_entries')
    conn.commit()
    conn.close()

    assert rf.verify_anchors() == (
        False,
        'anchor 1 references missing ledger entry 1',
    )


def test_rf_ledger_head_differs_from_anchor(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    rf.append_entry('event', {'ok': True})
    rf.create_anchor()

    conn = sqlite3.connect(rf.DB_PATH)
    conn.execute(
        'UPDATE ledger_entries SET entry_hash = ? WHERE id = 1',
        ('1' * 64,),
    )
    conn.commit()
    conn.close()

    assert rf.verify_anchors() == (
        False,
        'anchor 1 ledger head differs from ledger entry 1',
    )

def test_rf_create_anchor_rejects_invalid_ledger(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rf,
        'verify_chain',
        lambda: (False, 'bad ledger'),
    )

    with pytest.raises(
        ValueError,
        match='ledger verification failed: bad ledger',
    ):
        rf.create_anchor()


def test_rf_health_ok_and_degraded(tmp_path, monkeypatch):
    isolate_rf(tmp_path, monkeypatch)

    healthy = rf.health()
    assert healthy['status'] == 'ok'
    assert healthy['ledger']['ok'] is True
    assert healthy['anchors']['ok'] is True

    monkeypatch.setattr(
        rf,
        'verify_chain',
        lambda: (False, 'broken'),
    )

    degraded = rf.health()
    assert degraded['status'] == 'degraded'
    assert degraded['ledger']['reason'] == 'broken'


def test_evidence_envelope_remaining_paths():
    envelope = build_envelope(
        'tenant',
        'event',
        'type',
        {'name': 'source'},
        {'value': 1},
    )

    tampered = dict(envelope)
    tampered['event_type'] = 'changed'

    assert verify_envelope(tampered) == (
        False,
        'payload_digest_mismatch',
    )


def test_evidence_ledger_remaining_paths():
    assert verify_evidence_chain([]) == (True, 'empty')

    first = build_record(0, 'e1', sha256(b'a'))
    second = build_record(
        1,
        'e2',
        sha256(b'b'),
        first.record_digest,
    )

    assert verify_evidence_chain([first, second]) == (
        True,
        'valid',
    )

    bad_sequence = build_record(
        2,
        'e2',
        sha256(b'b'),
        first.record_digest,
    )

    assert verify_evidence_chain([first, bad_sequence]) == (
        False,
        'sequence_gap',
    )

    bad_previous = build_record(
        1,
        'e2',
        sha256(b'b'),
        'f' * 64,
    )

    assert verify_evidence_chain([first, bad_previous]) == (
        False,
        'previous_digest_mismatch',
    )


def test_evidence_merkle_remaining_paths():
    digests = [
        sha256(b'0'),
        sha256(b'1'),
        sha256(b'2'),
    ]

    assert merkle_root(digests) == merkle_root(digests)

    proof = build_proof(digests, 2)
    root = merkle_root(digests)

    assert verify_proof(proof, root) is True
    assert verify_proof(proof, '0' * 64) is False

    with pytest.raises(ValueError, match='empty tree'):
        build_proof([], 0)

    with pytest.raises(IndexError, match='leaf index'):
        build_proof(digests, 3)

    checkpoint = build_checkpoint(
        digests,
        previous_root='f' * 64,
    )

    assert checkpoint.tree_size == 3
    assert checkpoint.previous_root == 'f' * 64


def test_evidence_signing_remaining_paths():
    private, public = generate_keypair()
    signed = sign(private, b'payload', 'key-1')

    assert verify(
        public,
        b'payload',
        signed,
    ) == (True, 'valid')

    malformed = dict(signed)
    malformed['signature'] = '!'
    assert verify(public, b'payload', malformed)[0] is False


def test_app_security_middleware_invalid_content_length():
    from core.app import security_middleware

    class Request:
        headers = {'content-length': 'invalid'}

    async def call_next(request):
        raise AssertionError('invalid content-length must be rejected')

    import asyncio

    response = asyncio.run(
        security_middleware(Request(), call_next)
    )

    assert response.status_code == 400


def test_app_security_middleware_size_limit():
    from core.app import security_middleware

    class Request:
        headers = {'content-length': '393217'}

    async def call_next(request):
        raise AssertionError('oversized request must be rejected')

    import asyncio

    response = asyncio.run(
        security_middleware(Request(), call_next)
    )

    assert response.status_code == 413
