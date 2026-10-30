"""Hybrid Ed25519 + ML-DSA-65 anchors, downgrade resistance, and pin-coverage reporting.

Attackers here hold everything except what each case says they lack. The
"quantum forger" holds the operator's Ed25519 private key (as if recovered with
Shor's algorithm) but not the ML-DSA-65 key.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rf_core  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_pq_test', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence_pq_test', 'tools/rf_export_evidence.py')

needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
ZERO = '0' * 64


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


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {n: archive.read(n) for n in archive.namelist()}


def _jsonl(blob: bytes) -> list[dict]:
    return [json.loads(line) for line in blob.decode().splitlines() if line.strip()]


def _dump(rows) -> bytes:
    return b''.join((_canon(r) + '\n').encode() for r in rows)


def _reseal(m: dict[str, bytes]) -> dict[str, bytes]:
    man = json.loads(m['manifest.json'])
    for name in list(man['files']):
        man['files'][name] = {'sha256': _sha(m[name]), 'bytes': len(m[name])}
    ledger, anchors = _jsonl(m['ledger.jsonl']), _jsonl(m['anchors.jsonl'])
    man['ledger_count'] = len(ledger)
    man['ledger_head'] = ledger[-1]['entry_hash'] if ledger else ZERO
    man['anchor_count'] = len(anchors)
    return {**m, 'manifest.json': _canon(man).encode()}


def _write(path: Path, m: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, 'w') as archive:
        for name, blob in m.items():
            archive.writestr(name, blob)
    return path


def _rechain(rows):
    prev = ZERO
    out = []
    for i, r in enumerate(rows, 1):
        r = dict(r, id=i, prev_hash=prev)
        r['entry_hash'] = _sha(f"{i}|{prev}|{r['ts']}|{r['entry_type']}|{r['payload']}".encode())
        prev = r['entry_hash']
        out.append(r)
    return out


def _ed_private(base: Path):
    return serialization.load_pem_private_key((base / 'signing_key.pem').read_bytes(), None)


def _resign_ed25519(anchors, ledger, ed_private, keep_pq=True, downgrade_from=None):
    """Recompute anchor heads/hashes and Ed25519 signatures as a key-holding attacker."""
    heads = [ZERO] + [r['entry_hash'] for r in ledger]
    prev = ZERO
    out = []
    for i, a in enumerate(anchors, 1):
        a = dict(a, ledger_head=heads[a['ledger_count']], prev_anchor_hash=prev)
        if downgrade_from is not None and i >= downgrade_from and a['schema'] == 'rf.anchor.v3':
            a['schema'] = 'rf.anchor.v2'
            a.pop('pq_key_id')
            a.pop('pq_signature')
        fields = verifier.ANCHOR_CORE_V3 if a['schema'] == 'rf.anchor.v3' else verifier.ANCHOR_CORE_V2
        a['anchor_hash'] = _sha(_canon({k: a[k] for k in fields}).encode())
        a['signature'] = base64.b64encode(ed_private.sign(a['anchor_hash'].encode())).decode()
        if not keep_pq and 'pq_signature' in a:
            a['pq_signature'] = base64.b64encode(b'\x00' * 3309).decode()
        prev = a['anchor_hash']
        out.append(a)
    return out


@pytest.fixture
def hybrid(tmp_path, monkeypatch):
    """Ledger: 3 entries, anchor 1, 2 entries, anchor 2 (both hybrid)."""
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    base = _point(monkeypatch, tmp_path / 'op')
    for i in range(3):
        rf_core.append_entry('evt', {'n': i})
    a1 = rf_core.create_anchor()
    for i in range(3, 5):
        rf_core.append_entry('evt', {'n': i})
    a2 = rf_core.create_anchor()
    bundle = tmp_path / 'bundle.zip'
    manifest = exporter.export_bundle(base, bundle)
    return {'base': base, 'tmp': tmp_path, 'a1': a1, 'a2': a2, 'bundle': bundle,
            'manifest': manifest}


# ---------------------------------------------------------------- core


@needs_pq
def test_core_creates_and_verifies_hybrid_anchors(hybrid):
    a1 = hybrid['a1']
    assert a1['schema'] == 'rf.anchor.v3'
    assert a1['pq_key_id'].startswith('mldsa65:')
    assert len(base64.b64decode(a1['pq_signature'])) == 3309
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')


def test_core_auto_falls_back_to_v2_without_ml_dsa(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    monkeypatch.setattr(rf_core, '_pq_module', lambda: None)
    _point(monkeypatch, tmp_path)
    assert rf_core.create_anchor()['schema'] == 'rf.anchor.v2'
    assert rf_core.verify_anchors()[0]


def test_core_on_mode_requires_ml_dsa(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'on')
    monkeypatch.setattr(rf_core, '_pq_module', lambda: None)
    _point(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match='post-quantum anchor signing unavailable'):
        rf_core.create_anchor()


def test_core_rejects_unknown_mode(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'maybe')
    _point(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match='RF_PQ_SIGNING'):
        rf_core.create_anchor()


@needs_pq
def test_core_refuses_downgrade_by_mode_off(hybrid, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    with pytest.raises(ValueError, match='would downgrade'):
        rf_core.create_anchor()


@needs_pq
def test_core_refuses_anchor_when_ml_dsa_disappears(hybrid, monkeypatch):
    monkeypatch.setattr(rf_core, '_pq_module', lambda: None)
    with pytest.raises(ValueError, match='unavailable'):
        rf_core.create_anchor()
    assert rf_core.verify_anchors() == (False, 'post-quantum verification unavailable')


@needs_pq
def test_core_upgrades_v2_ledger_to_hybrid(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path)
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    rf_core.append_entry('evt', {'n': 1})
    assert rf_core.create_anchor()['schema'] == 'rf.anchor.v2'
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    rf_core.append_entry('evt', {'n': 2})
    assert rf_core.create_anchor()['schema'] == 'rf.anchor.v3'
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    report = verifier.verify_bundle(str(exporter.export_bundle(tmp_path, tmp_path / 'b.zip') and
                                        tmp_path / 'b.zip'), require_pq=True)
    assert report['post_quantum'] == 'hybrid' and report['pq_anchors'] == 1
    assert report['pq_protected_through_entry'] == 2


@needs_pq
@pytest.mark.parametrize('mutate,reason', [
    (lambda a: a.__setitem__('pq_signature', base64.b64encode(b'\x01' * 3309).decode()),
     'post-quantum signature invalid at anchor 2'),
    (lambda a: a.__setitem__('pq_signature', '!!'), 'post-quantum signature invalid at anchor 2'),
    (lambda a: a.pop('pq_signature'), 'post-quantum signature invalid at anchor 2'),
    (lambda a: a.pop('pq_key_id'), 'anchor 2 malformed'),
])
def test_core_detects_pq_field_tampering(hybrid, mutate, reason):
    anchors = _jsonl(rf_core.ANCHOR_PATH.read_bytes())
    mutate(anchors[1])
    rf_core.ANCHOR_PATH.write_bytes(_dump(anchors))
    assert rf_core.verify_anchors() == (False, reason)


@needs_pq
def test_core_detects_appended_v2_anchor_after_hybrid(hybrid):
    ed = _ed_private(hybrid['base'])
    anchors = _jsonl(rf_core.ANCHOR_PATH.read_bytes())
    core = {k: anchors[-1][k] for k in rf_core.ANCHOR_CORE_V2}
    core.update(schema='rf.anchor.v2', seq=3, prev_anchor_hash=anchors[-1]['anchor_hash'])
    h = _sha(_canon(core).encode())
    anchors.append({**core, 'anchor_hash': h,
                    'signature': base64.b64encode(ed.sign(h.encode())).decode()})
    rf_core.ANCHOR_PATH.write_bytes(_dump(anchors))
    assert rf_core.verify_anchors() == (False, 'post-quantum downgrade at anchor 3')


@needs_pq
def test_core_detects_swapped_or_missing_pq_public_key(hybrid):
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    path = rf_core.pq_public_key_path()
    original = path.read_bytes()
    path.write_bytes(MLDSA65PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert rf_core.verify_anchors() == (False, 'post-quantum key identity mismatch at anchor 1')
    path.unlink()
    assert rf_core.verify_anchors() == (False, 'post-quantum public key missing for anchor 1')
    path.write_bytes(original)
    assert rf_core.verify_anchors()[0]


@needs_pq
def test_core_pq_key_management_guards(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path)
    private, key_id = rf_core.load_or_create_pq_keypair()
    assert rf_core.load_or_create_pq_keypair()[1] == key_id
    assert rf_core.load_pq_public_key()[1] == key_id
    rf_core.pq_private_key_path().unlink()
    with pytest.raises(ValueError, match='without its private key'):
        rf_core.load_or_create_pq_keypair()
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    other = MLDSA65PrivateKey.generate()
    rf_core.pq_private_key_path().write_bytes(other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    with pytest.raises(ValueError, match='does not match private key'):
        rf_core.load_or_create_pq_keypair()


def test_core_load_pq_public_key_absent_and_unsupported(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path)
    assert rf_core.load_pq_public_key() is None
    rf_core.pq_public_key_path().write_text('not a key')
    monkeypatch.setattr(rf_core, '_pq_module', lambda: None)
    with pytest.raises(RuntimeError, match='lacks ML-DSA'):
        rf_core.load_pq_public_key()
    with pytest.raises(RuntimeError, match='unavailable'):
        rf_core.load_or_create_pq_keypair()


def test_core_probe_reports_unavailable_when_import_fails(monkeypatch):
    import cryptography.hazmat.primitives.asymmetric as asymmetric
    monkeypatch.setattr(rf_core, '_PQ_PROBE', {})
    monkeypatch.delattr(asymmetric, 'mldsa', raising=False)
    monkeypatch.setitem(sys.modules, 'cryptography.hazmat.primitives.asymmetric.mldsa', None)
    assert rf_core.pq_available() is False


@needs_pq
def test_core_rejects_non_ml_dsa_pq_key_files(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path)
    _, _, _ = rf_core.load_or_create_keypair()
    rf_core.pq_public_key_path().write_bytes(rf_core.PUBLIC_KEY_PATH.read_bytes())
    with pytest.raises(TypeError, match='not ML-DSA-65'):
        rf_core.load_pq_public_key()
    rf_core.pq_private_key_path().write_bytes(rf_core.PRIVATE_KEY_PATH.read_bytes())
    with pytest.raises(TypeError, match='not ML-DSA-65'):
        rf_core.load_or_create_pq_keypair()


# ---------------------------------------------------------------- exporter


@needs_pq
def test_exporter_writes_v2_bundle_with_pq_key(hybrid):
    m = _members(hybrid['bundle'])
    assert set(m) == set(verifier.MEMBERS_V2)
    man = json.loads(m['manifest.json'])
    assert man['schema'] == 'rf.evidence.v2'
    assert man['pq_key_id'] == hybrid['a1']['pq_key_id']
    assert all(b'PRIVATE KEY' not in blob for blob in m.values())


@needs_pq
def test_exporter_fails_closed_without_ml_dsa(hybrid, monkeypatch):
    monkeypatch.setitem(sys.modules, 'cryptography.hazmat.primitives.asymmetric.mldsa', None)
    with pytest.raises(RuntimeError, match='lacks ML-DSA'):
        exporter.export_bundle(hybrid['base'], hybrid['tmp'] / 'x.zip')


# ---------------------------------------------------------------- verifier


@needs_pq
def test_verifier_reports_hybrid_and_honours_pq_pins(hybrid):
    pq_id = hybrid['a1']['pq_key_id']
    r = verifier.verify_bundle(str(hybrid['bundle']), pin_pq_key_id=pq_id, require_pq=True)
    assert r['post_quantum'] == 'hybrid' and r['pq_anchors'] == 2
    assert r['pq_key_id'] == pq_id and r['pq_protected_through_entry'] == 5
    with pytest.raises(verifier.VerificationError, match='does not match pinned key'):
        verifier.verify_bundle(str(hybrid['bundle']), pin_pq_key_id='mldsa65:' + 'a' * 64)


def test_verifier_require_pq_rejects_ed25519_only_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    _point(monkeypatch, tmp_path / 'op')
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    bundle = tmp_path / 'v1.zip'
    exporter.export_bundle(tmp_path / 'op', bundle)
    r = verifier.verify_bundle(str(bundle))
    assert r['post_quantum'] == 'none'
    assert any('Ed25519 alone' in w for w in r['warnings'])
    with pytest.raises(verifier.VerificationError, match='--require-pq'):
        verifier.verify_bundle(str(bundle), require_pq=True)
    with pytest.raises(verifier.VerificationError, match='no ML-DSA-65 key'):
        verifier.verify_bundle(str(bundle), pin_pq_key_id='mldsa65:' + 'a' * 64)


@needs_pq
def test_quantum_forger_with_ed25519_key_is_rejected(hybrid):
    """Rewrite history and re-sign every anchor with the stolen Ed25519 key."""
    m = _members(hybrid['bundle'])
    ledger = _jsonl(m['ledger.jsonl'])
    ledger[1]['payload'] = _canon({'n': 999})
    ledger = _rechain(ledger)
    anchors = _resign_ed25519(_jsonl(m['anchors.jsonl']), ledger, _ed_private(hybrid['base']))
    forged = _write(hybrid['tmp'] / 'q.zip',
                    _reseal({**m, 'ledger.jsonl': _dump(ledger), 'anchors.jsonl': _dump(anchors)}))
    with pytest.raises(verifier.VerificationError, match='post-quantum signature invalid at anchor 1'):
        verifier.verify_bundle(str(forged))


@needs_pq
def test_partial_downgrade_is_rejected(hybrid):
    m = _members(hybrid['bundle'])
    ledger = _jsonl(m['ledger.jsonl'])
    anchors = _resign_ed25519(_jsonl(m['anchors.jsonl']), ledger, _ed_private(hybrid['base']),
                              downgrade_from=2)
    forged = _write(hybrid['tmp'] / 'd.zip', _reseal({**m, 'anchors.jsonl': _dump(anchors)}))
    with pytest.raises(verifier.VerificationError, match='post-quantum downgrade at anchor 2'):
        verifier.verify_bundle(str(forged))


@needs_pq
def test_full_downgrade_is_caught_by_require_pq(hybrid):
    m = _members(hybrid['bundle'])
    ledger = _jsonl(m['ledger.jsonl'])
    ledger[1]['payload'] = _canon({'n': 999})
    ledger = _rechain(ledger)
    anchors = _resign_ed25519(_jsonl(m['anchors.jsonl']), ledger, _ed_private(hybrid['base']),
                              downgrade_from=1)
    forged = _write(hybrid['tmp'] / 'fd.zip',
                    _reseal({**m, 'ledger.jsonl': _dump(ledger), 'anchors.jsonl': _dump(anchors)}))
    r = verifier.verify_bundle(str(forged))
    assert r['post_quantum'] == 'none'
    with pytest.raises(verifier.VerificationError, match='--require-pq'):
        verifier.verify_bundle(str(forged), require_pq=True)
    with pytest.raises(verifier.VerificationError, match='pinned anchor 1 hash mismatch'):
        verifier.verify_bundle(str(forged), pin_anchors=[(1, hybrid['a1']['anchor_hash'])])


@needs_pq
def test_substituted_pq_key_is_caught_by_pq_key_pin(hybrid, tmp_path):
    """Attacker holds both keys' replacements: new ML-DSA key, stolen Ed25519 key."""
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    m = _members(hybrid['bundle'])
    ledger = _rechain(_jsonl(m['ledger.jsonl']))
    attacker = MLDSA65PrivateKey.generate()
    pub_pem = attacker.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = attacker.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    attacker_id = 'mldsa65:' + _sha(raw)
    anchors = _jsonl(m['anchors.jsonl'])
    for a in anchors:
        a['pq_key_id'] = attacker_id
    anchors = _resign_ed25519(anchors, ledger, _ed_private(hybrid['base']))
    for a in anchors:
        a['pq_signature'] = base64.b64encode(
            attacker.sign(a['anchor_hash'].encode(), b'rf.anchor.v3')).decode()
    man = json.loads(m['manifest.json'])
    man['pq_key_id'] = attacker_id
    forged_m = _reseal({**m, 'manifest.json': _canon(man).encode(), 'anchors.jsonl': _dump(anchors),
                        verifier.PQ_MEMBER: pub_pem})
    forged = _write(tmp_path / 'sub.zip', forged_m)
    assert verifier.verify_bundle(str(forged))['post_quantum'] == 'hybrid'
    with pytest.raises(verifier.VerificationError, match='does not match pinned key'):
        verifier.verify_bundle(str(forged), pin_pq_key_id=hybrid['a1']['pq_key_id'])


@needs_pq
@pytest.mark.parametrize('case,match', [
    ('v3_in_v1_bundle', 'no ML-DSA-65 key'),
    ('members_mismatch', 'do not match bundle schema'),
    ('manifest_pq_id', 'post-quantum key summary'),
    ('legacy_claims_v3', 'without a key identity'),
    ('pq_sig_not_b64', 'pq_signature is not base64'),
    ('pq_sig_wrong_type', 'malformed pq_signature'),
    ('pq_key_id_mismatch', 'post-quantum key identity mismatch'),
    ('extra_field_on_v2', 'unexpected fields'),
    ('bad_pq_pem', 'post-quantum public key unreadable'),
    ('ed25519_as_pq_key', 'not ML-DSA-65'),
])
def test_verifier_rejects_malformed_pq_bundles(hybrid, case, match):
    m = _members(hybrid['bundle'])
    man = json.loads(m['manifest.json'])
    anchors = _jsonl(m['anchors.jsonl'])
    if case == 'v3_in_v1_bundle':
        m.pop(verifier.PQ_MEMBER)
        man['schema'] = 'rf.evidence.v1'
        man.pop('pq_key_id')
        man['files'].pop(verifier.PQ_MEMBER)
    elif case == 'members_mismatch':
        man['schema'] = 'rf.evidence.v1'
    elif case == 'manifest_pq_id':
        man['pq_key_id'] = 'mldsa65:' + 'b' * 64
    elif case == 'legacy_claims_v3':
        anchors[0].pop('key_id')
    elif case == 'pq_sig_not_b64':
        anchors[0]['pq_signature'] = '***'
    elif case == 'pq_sig_wrong_type':
        anchors[0]['pq_signature'] = 7
    elif case == 'pq_key_id_mismatch':
        # Re-sign with the stolen Ed25519 key so the anchor hash still checks out.
        anchors[0]['pq_key_id'] = 'mldsa65:' + 'c' * 64
        anchors = _resign_ed25519(anchors, _jsonl(m['ledger.jsonl']), _ed_private(hybrid['base']))
    elif case == 'extra_field_on_v2':
        anchors[0]['schema'] = 'rf.anchor.v2'
    elif case == 'bad_pq_pem':
        m[verifier.PQ_MEMBER] = b'garbage'
    elif case == 'ed25519_as_pq_key':
        m[verifier.PQ_MEMBER] = m['signing_key.pub.pem']
    m['manifest.json'] = _canon(man).encode()
    m['anchors.jsonl'] = _dump(anchors)
    forged = _write(hybrid['tmp'] / f'{case}.zip', _reseal(m))
    with pytest.raises(verifier.VerificationError, match=match):
        verifier.verify_bundle(str(forged))


@needs_pq
def test_verifier_fails_closed_without_ml_dsa(hybrid, monkeypatch):
    monkeypatch.setitem(sys.modules, 'cryptography.hazmat.primitives.asymmetric.mldsa', None)
    with pytest.raises(verifier.VerificationError, match='lacks it'):
        verifier.verify_bundle(str(hybrid['bundle']))


# ---------------------------------------------------------------- pin coverage


@needs_pq
def test_pin_coverage_is_reported_and_enforced(hybrid):
    a1, a2 = hybrid['a1'], hybrid['a2']
    old = verifier.verify_bundle(str(hybrid['bundle']), pin_anchors=[(1, a1['anchor_hash'])])
    assert old['trust_level'] == 'anchor_pinned'
    assert old['pinned_through_entry'] == 3 and old['entries_beyond_pin'] == 2
    assert any('covered only by the operator key' in w for w in old['warnings'])
    with pytest.raises(verifier.VerificationError, match='2 entries after pinned anchor'):
        verifier.verify_bundle(str(hybrid['bundle']), pin_anchors=[(1, a1['anchor_hash'])],
                               require_full_pin=True)
    full = verifier.verify_bundle(str(hybrid['bundle']), pin_anchors=[(2, a2['anchor_hash'])],
                                  require_full_pin=True)
    assert full['entries_beyond_pin'] == 0
    assert not any('operator key' in w for w in full['warnings'])
    with pytest.raises(verifier.VerificationError, match='needs at least one --pin-anchor'):
        verifier.verify_bundle(str(hybrid['bundle']), require_full_pin=True)


@needs_pq
def test_rewritten_tail_after_old_pin_is_flagged(hybrid):
    """Key-holding attacker rewrites entries after pinned anchor 1 and re-signs anchor 2."""
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    m = _members(hybrid['bundle'])
    pq_private = serialization.load_pem_private_key(
        (hybrid['base'] / rf_core.PQ_PRIVATE_KEY_NAME).read_bytes(), None)
    assert isinstance(pq_private, MLDSA65PrivateKey)
    ledger = _jsonl(m['ledger.jsonl'])
    ledger[4]['payload'] = _canon({'n': 4444})
    ledger = _rechain(ledger)
    anchors = _resign_ed25519(_jsonl(m['anchors.jsonl']), ledger, _ed_private(hybrid['base']))
    for a in anchors:
        a['pq_signature'] = base64.b64encode(
            pq_private.sign(a['anchor_hash'].encode(), b'rf.anchor.v3')).decode()
    forged = _write(hybrid['tmp'] / 'tail.zip',
                    _reseal({**m, 'ledger.jsonl': _dump(ledger), 'anchors.jsonl': _dump(anchors)}))
    pin1 = [(1, hybrid['a1']['anchor_hash'])]
    report = verifier.verify_bundle(str(forged), pin_anchors=pin1)
    assert report['entries_beyond_pin'] == 2
    with pytest.raises(verifier.VerificationError, match='entries after pinned anchor'):
        verifier.verify_bundle(str(forged), pin_anchors=pin1, require_full_pin=True)
    with pytest.raises(verifier.VerificationError, match='pinned anchor 2 hash mismatch'):
        verifier.verify_bundle(str(forged), pin_anchors=[(2, hybrid['a2']['anchor_hash'])])


@needs_pq
def test_cli_flags(hybrid, capsys):
    b = str(hybrid['bundle'])
    a2 = hybrid['a2']
    pins = ['--pin-anchor', f"1:{hybrid['a1']['anchor_hash']}"]
    assert verifier.main([b, '--require-pq', '--pin-pq-key-id', a2['pq_key_id'], '--json']) == 10
    assert verifier.main([b, *pins, '--require-full-pin']) == 1
    assert verifier.main([b, '--pin-anchor', f"2:{a2['anchor_hash']}", '--require-full-pin',
                          '--require-pq']) == 0
    out = capsys.readouterr().out
    assert 'post_quantum: hybrid' in out
