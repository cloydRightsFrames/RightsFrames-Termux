"""Signing keys sealed at rest (rf.sealed-key.v1): format, fail-closed loading, migration tool."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rf_core, rf_keyseal  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_seal_test', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence_seal_test', 'tools/rf_export_evidence.py')
seal_tool = _load('rf_seal_keys_test', 'tools/rf_seal_keys.py')

PASS = b'correct horse battery staple 42'
needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
needs_argon2 = pytest.mark.skipif(not rf_keyseal.argon2_available(),
                                  reason='cryptography/OpenSSL build lacks Argon2id')


def _point(mp, base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)
    mp.setattr(rf_core, '_SEALED_KEY_CACHE', {})
    return base


def _passfile(tmp_path: Path, value: bytes = PASS, name: str = 'pass', mode: int = 0o600) -> Path:
    path = tmp_path / name
    path.write_bytes(value + b'\n')
    os.chmod(path, mode)
    return path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (rf_keyseal.ENV_PASSPHRASE_FILE, rf_keyseal.ENV_PASSPHRASE,
                 rf_keyseal.ENV_REQUIRE_SEALED):
        monkeypatch.delenv(name, raising=False)


def _der(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _document(sealed: bytes) -> dict:
    body = b''.join(sealed.strip()[len(rf_keyseal.PEM_BEGIN):-len(rf_keyseal.PEM_END)].split())
    return json.loads(base64.b64decode(body))


def _armour(document: dict) -> bytes:
    body = base64.encodebytes(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())
    return rf_keyseal.PEM_BEGIN + b'\n' + body + rf_keyseal.PEM_END + b'\n'


# ---------------------------------------------------------------- format


@pytest.mark.parametrize('kdf', ['scrypt', pytest.param('argon2id', marks=needs_argon2)])
def test_seal_round_trip_and_header(kdf):
    der = _der(Ed25519PrivateKey.generate())
    sealed = rf_keyseal.seal_der(der, PASS, 'ed25519', kdf)
    assert rf_keyseal.is_sealed(sealed) and b'PRIVATE KEY-----' in sealed.splitlines()[0]
    assert der not in sealed and base64.b64encode(der) not in sealed
    assert rf_keyseal.unseal_der(sealed, PASS, 'ed25519') == der
    header = _document(sealed)['header']
    assert header['schema'] == 'rf.sealed-key.v1' and header['kdf']['name'] == kdf
    assert rf_keyseal.describe(sealed) == {'sealed': True, 'role': 'ed25519', 'kdf': kdf}
    assert rf_keyseal.seal_der(der, PASS, 'ed25519', kdf) != sealed  # fresh salt and nonce


def test_default_kdf_prefers_argon2id():
    sealed = rf_keyseal.seal_der(_der(Ed25519PrivateKey.generate()), PASS, 'ed25519')
    expected = 'argon2id' if rf_keyseal.argon2_available() else 'scrypt'
    assert _document(sealed)['header']['kdf']['name'] == expected


def test_wrong_passphrase_role_swap_and_bit_flips_fail_closed():
    sealed = rf_keyseal.seal_der(_der(Ed25519PrivateKey.generate()), PASS, 'ed25519', 'scrypt')
    with pytest.raises(rf_keyseal.SealedKeyError, match='wrong key passphrase'):
        rf_keyseal.unseal_der(sealed, b'x' * 20, 'ed25519')
    with pytest.raises(rf_keyseal.SealedKeyError, match="expected 'mldsa65'"):
        rf_keyseal.unseal_der(sealed, PASS, 'mldsa65')
    doc = _document(sealed)
    ciphertext = bytearray(base64.b64decode(doc['ciphertext']))
    ciphertext[5] ^= 1
    doc['ciphertext'] = base64.b64encode(bytes(ciphertext)).decode()
    with pytest.raises(rf_keyseal.SealedKeyError, match='tampered'):
        rf_keyseal.unseal_der(_armour(doc), PASS, 'ed25519')
    doc = _document(sealed)
    doc['header']['nonce'] = base64.b64encode(b'\x00' * 12).decode()  # AAD-bound header edit
    with pytest.raises(rf_keyseal.SealedKeyError, match='tampered'):
        rf_keyseal.unseal_der(_armour(doc), PASS, 'ed25519')


@pytest.mark.parametrize('mutate,match', [
    (lambda d: d['header']['kdf'].__setitem__('n', 1 << 10), 'out of range'),
    (lambda d: d['header']['kdf'].__setitem__('n', 1 << 30), 'out of range'),
    (lambda d: d['header']['kdf'].__setitem__('n', (1 << 17) + 1), 'power of two'),
    (lambda d: d['header']['kdf'].__setitem__('r', True), 'out of range'),
    (lambda d: d['header']['kdf'].__setitem__('name', 'pbkdf2'), 'unsupported KDF'),
    (lambda d: d['header']['kdf'].__setitem__('extra', 1), 'unexpected fields'),
    (lambda d: d['header']['kdf'].__setitem__('salt', base64.b64encode(b'x').decode()), 'too short'),
    (lambda d: d['header']['kdf'].__setitem__('salt', '***'), 'not base64'),
    (lambda d: d['header'].__setitem__('aead', 'AES-128-CBC'), 'unsupported schema or cipher'),
    (lambda d: d['header'].__setitem__('schema', 'rf.sealed-key.v0'), 'unsupported schema'),
    (lambda d: d['header'].__setitem__('nonce', base64.b64encode(b'n').decode()), 'nonce'),
    (lambda d: d['header'].pop('role'), 'header has unexpected fields'),
    (lambda d: d.__setitem__('extra', 1), 'document has unexpected fields'),
    (lambda d: d.__setitem__('ciphertext', 5), 'ciphertext is malformed'),
])
def test_hostile_headers_are_refused_before_key_derivation(mutate, match, monkeypatch):
    sealed = rf_keyseal.seal_der(_der(Ed25519PrivateKey.generate()), PASS, 'ed25519', 'scrypt')
    doc = _document(sealed)
    mutate(doc)
    calls = []
    original = rf_keyseal._derive
    monkeypatch.setattr(rf_keyseal, '_derive', lambda *a: calls.append(a) or original(*a))
    with pytest.raises(rf_keyseal.SealedKeyError, match=match):
        rf_keyseal.unseal_der(_armour(doc), PASS, 'ed25519')
    assert not calls or match in ('ciphertext is malformed',)


@pytest.mark.parametrize('blob,match', [
    (b'-----BEGIN RF SEALED PRIVATE KEY-----\nAAAA', 'armour is malformed'),
    (rf_keyseal.PEM_BEGIN + b'\n!!!!\n' + rf_keyseal.PEM_END, 'body is malformed'),
    (rf_keyseal.PEM_BEGIN + b'\n' + base64.b64encode(b'[1]') + b'\n' + rf_keyseal.PEM_END,
     'unexpected fields'),
    (rf_keyseal.PEM_BEGIN + b'\n' + b'A' * 70000 + b'\n' + rf_keyseal.PEM_END, 'too large'),
])
def test_malformed_armour(blob, match):
    with pytest.raises(rf_keyseal.SealedKeyError, match=match):
        rf_keyseal.unseal_der(blob, PASS, 'ed25519')
    assert rf_keyseal.describe(blob)['sealed'] is True


def test_seal_input_validation():
    der = _der(Ed25519PrivateKey.generate())
    with pytest.raises(rf_keyseal.SealedKeyError, match='unknown key role'):
        rf_keyseal.seal_der(der, PASS, 'rsa')
    with pytest.raises(rf_keyseal.SealedKeyError, match='at least 16'):
        rf_keyseal.seal_der(der, b'short', 'ed25519')
    with pytest.raises(rf_keyseal.SealedKeyError, match='unsupported KDF'):
        rf_keyseal.seal_der(der, PASS, 'ed25519', 'md5')
    with pytest.raises(rf_keyseal.SealedKeyError, match='too long'):
        rf_keyseal.seal_der(der, b'a' * 5000, 'ed25519')
    with pytest.raises(rf_keyseal.SealedKeyError, match='not valid UTF-8'):
        rf_keyseal.seal_der(der, b'\xff' * 20, 'ed25519')


def test_argon2id_sealed_key_fails_cleanly_without_argon2(monkeypatch):
    sealed = rf_keyseal.seal_der(_der(Ed25519PrivateKey.generate()), PASS, 'ed25519', 'scrypt')
    doc = _document(sealed)
    doc['header']['kdf'] = {'name': 'argon2id', 'memory_cost': 65536, 'iterations': 3,
                            'lanes': 4, 'salt': doc['header']['kdf']['salt']}
    monkeypatch.setitem(rf_keyseal._ARGON2_PROBE, 'ok', False)
    with pytest.raises(rf_keyseal.SealedKeyError, match='lacks Argon2id'):
        rf_keyseal.unseal_der(_armour(doc), PASS, 'ed25519')


# ---------------------------------------------------------------- passphrase sources


def test_passphrase_sources_and_rules(tmp_path, monkeypatch):
    assert rf_keyseal.passphrase_from_env() is None
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, PASS.decode())
    assert rf_keyseal.passphrase_from_env() == PASS
    path = _passfile(tmp_path)
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(path))
    assert rf_keyseal.passphrase_from_env() == PASS  # file wins; trailing newline stripped
    path.write_bytes(PASS + b'\r\n')
    assert rf_keyseal.passphrase_from_env() == PASS
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(tmp_path / 'missing'))
    with pytest.raises(rf_keyseal.SealedKeyError, match='not readable'):
        rf_keyseal.passphrase_from_env()
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(tmp_path))
    with pytest.raises(rf_keyseal.SealedKeyError, match='not a regular file'):
        rf_keyseal.passphrase_from_env()
    monkeypatch.delenv(rf_keyseal.ENV_PASSPHRASE_FILE)
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, 'too short')
    with pytest.raises(rf_keyseal.SealedKeyError, match='at least 16'):
        rf_keyseal.passphrase_from_env()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permission bits')
def test_group_readable_passphrase_file_is_refused(tmp_path):
    with pytest.raises(rf_keyseal.SealedKeyError, match='chmod 600'):
        rf_keyseal.read_passphrase_file(_passfile(tmp_path, mode=0o640))


def test_sealing_required_flag(monkeypatch):
    for value, expected in (('1', True), ('true', True), ('ON', True), ('0', False), ('', False)):
        monkeypatch.setenv(rf_keyseal.ENV_REQUIRE_SEALED, value)
        assert rf_keyseal.sealing_required() is expected


# ---------------------------------------------------------------- core integration


@needs_pq
def test_core_creates_sealed_keys_and_anchors_with_them(tmp_path, monkeypatch):
    base = _point(monkeypatch, tmp_path / 'data')
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(_passfile(tmp_path)))
    monkeypatch.setenv(rf_keyseal.ENV_REQUIRE_SEALED, '1')
    rf_core.append_entry('evt', {'n': 1})
    anchor = rf_core.create_anchor()
    assert anchor['schema'] == 'rf.anchor.v4'
    for name in ('signing_key.pem', rf_core.PQ_PRIVATE_KEY_NAME):
        blob = (base / name).read_bytes()
        assert rf_keyseal.is_sealed(blob) and b'BEGIN PRIVATE KEY' not in blob
        if os.name == 'posix':
            assert (base / name).stat().st_mode & 0o777 == 0o600
    custody = rf_core.key_custody()
    assert custody['sealing_required'] is True
    assert custody['ed25519']['sealed'] and custody['mldsa65']['sealed']
    assert rf_core.verify_anchors() == (True, 'verified 1 anchors')
    bundle = tmp_path / 'b.zip'
    exporter.export_bundle(base, bundle)
    report = verifier.verify_bundle(str(bundle), pin_anchors=[(1, anchor['anchor_hash'])])
    assert report['trust_level'] == 'anchor_pinned'


@needs_pq
def test_sealed_key_is_derived_once_per_process(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, PASS.decode())
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    calls = []
    original = rf_keyseal.unseal_der
    monkeypatch.setattr(rf_keyseal, 'unseal_der', lambda *a: calls.append(a[2]) or original(*a))
    monkeypatch.setattr(rf_core, '_SEALED_KEY_CACHE', {})
    for _ in range(5):
        assert rf_core.health()['status'] == 'ok'
        rf_core.create_anchor()
    assert sorted(calls) == ['ed25519', 'mldsa65']


def test_core_without_passphrase_fails_closed(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, PASS.decode())
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    rf_core.load_or_create_keypair()
    monkeypatch.delenv(rf_keyseal.ENV_PASSPHRASE)
    monkeypatch.setattr(rf_core, '_SEALED_KEY_CACHE', {})
    with pytest.raises(rf_keyseal.SealedKeyError, match='no passphrase is configured'):
        rf_core.load_or_create_keypair()
    assert rf_core.health()['status'] == 'degraded'
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, 'a different passphrase!!')
    with pytest.raises(rf_keyseal.SealedKeyError, match='wrong key passphrase'):
        rf_core.load_or_create_keypair()


def test_require_sealed_refuses_plaintext_keys(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    rf_core.load_or_create_keypair()  # plaintext, as created before sealing existed
    monkeypatch.setenv(rf_keyseal.ENV_REQUIRE_SEALED, '1')
    with pytest.raises(rf_keyseal.SealedKeyError, match='stored in plaintext'):
        rf_core.load_or_create_keypair()
    fresh = _point(monkeypatch, tmp_path / 'fresh')
    with pytest.raises(rf_keyseal.SealedKeyError, match='no key passphrase is configured'):
        rf_core.load_or_create_keypair()
    assert not (fresh / 'signing_key.pem').exists()


def test_plaintext_keys_still_load_when_passphrase_is_configured(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    _, public, key_id = rf_core.load_or_create_keypair()
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, PASS.decode())
    assert rf_core.load_or_create_keypair()[1:] == (public, key_id)
    assert rf_core.key_custody()['ed25519'] == {'sealed': False}
    assert rf_core.key_custody()['mldsa65'] == {'absent': True}


# ---------------------------------------------------------------- migration tool


@needs_pq
def test_seal_tool_migrates_live_ledger_without_changing_identity(tmp_path, monkeypatch, capsys):
    base = _point(monkeypatch, tmp_path / 'data')
    rf_core.append_entry('evt', {'n': 1})
    first = rf_core.create_anchor()
    key_id_before = (base / 'signing_key.id').read_text()
    assert seal_tool.main(['--data-dir', str(base), '--status']) == 0
    assert json.loads(capsys.readouterr().out)['ed25519'] == {'sealed': False}

    assert seal_tool.main(['--data-dir', str(base)]) == 1
    assert 'set RF_KEY_PASSPHRASE_FILE' in capsys.readouterr().err

    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(_passfile(tmp_path)))
    assert seal_tool.main(['--data-dir', str(base), '--kdf', 'scrypt']) == 0
    assert 'sealed ed25519, mldsa65' in capsys.readouterr().out
    assert (base / 'signing_key.id').read_text() == key_id_before
    monkeypatch.setattr(rf_core, '_SEALED_KEY_CACHE', {})
    monkeypatch.setenv(rf_keyseal.ENV_REQUIRE_SEALED, '1')
    rf_core.append_entry('evt', {'n': 2})
    second = rf_core.create_anchor()
    assert second['key_id'] == first['key_id'] and second['pq_key_id'] == first['pq_key_id']
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')

    # Already sealed: needs the old passphrase to re-key.
    assert seal_tool.main(['--data-dir', str(base)]) == 1
    assert 'already sealed' in capsys.readouterr().err
    old = tmp_path / 'pass'
    new = _passfile(tmp_path, b'an entirely new passphrase 2026', name='new')
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(new))
    assert seal_tool.main(['--data-dir', str(base), '--old-passphrase-file', str(old)]) == 0
    monkeypatch.setattr(rf_core, '_SEALED_KEY_CACHE', {})
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    rf_core.create_anchor()
    capsys.readouterr()
    wrong = _passfile(tmp_path, b'not the passphrase at all!!', name='wrong')
    assert seal_tool.main(['--data-dir', str(base), '--old-passphrase-file', str(wrong)]) == 1
    assert 'wrong key passphrase' in capsys.readouterr().err


@needs_pq
def test_seal_tool_is_all_or_nothing(tmp_path, monkeypatch, capsys):
    base = _point(monkeypatch, tmp_path / 'data')
    rf_core.create_anchor()
    before = {name: (base / name).read_bytes()
              for name in ('signing_key.pem', rf_core.PQ_PRIVATE_KEY_NAME)}
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (base / 'signing_key_mldsa65.pub.pem').write_bytes(other)
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE_FILE, str(_passfile(tmp_path)))
    assert seal_tool.main(['--data-dir', str(base), '--kdf', 'scrypt']) == 1
    assert 'does not match' in capsys.readouterr().err
    for name, blob in before.items():
        assert (base / name).read_bytes() == blob  # Ed25519 key was NOT sealed alone
    (base / 'signing_key_mldsa65.pub.pem').unlink()
    assert seal_tool.main(['--data-dir', str(base)]) == 1
    assert 'is missing' in capsys.readouterr().err


def test_seal_tool_argument_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv('RF_DATA_DIR', raising=False)
    with pytest.raises(SystemExit):
        seal_tool.main([])
    assert seal_tool.main(['--data-dir', str(tmp_path / 'missing')]) == 1
    empty = tmp_path / 'empty'
    empty.mkdir()
    monkeypatch.setenv(rf_keyseal.ENV_PASSPHRASE, PASS.decode())
    assert seal_tool.main(['--data-dir', str(empty)]) == 1
    assert 'no private signing keys' in capsys.readouterr().err
    monkeypatch.setitem(rf_keyseal._ARGON2_PROBE, 'ok', False)
    assert seal_tool.main(['--data-dir', str(empty), '--kdf', 'argon2id']) == 1
    assert 'Argon2id is not available' in capsys.readouterr().err
