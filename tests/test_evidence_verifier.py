import base64
import hashlib
import importlib.util
import json
import sqlite3
import sys
import types
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_core  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence', 'tools/rf_export_evidence.py')
ZERO = '0' * 64


def _point(mp, base):
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)


def _build(mp, base, tag, pre=3, mid=2, post=1):
    _point(mp, base)
    for i in range(pre):
        rf_core.append_entry('evt', {'tag': tag, 'n': i})
    a1 = rf_core.create_anchor()
    for i in range(mid):
        rf_core.append_entry('evt', {'tag': tag, 'n': pre + i})
    a2 = rf_core.create_anchor()
    for i in range(post):
        rf_core.append_entry('evt', {'tag': tag, 'n': pre + mid + i})
    return a1, a2


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _ehash(e):
    return _sha(f"{e['id']}|{e['prev_hash']}|{e['ts']}|{e['entry_type']}|{e['payload']}".encode())


def _rechain(entries):
    prev = ZERO
    for e in entries:
        e['prev_hash'] = prev
        e['entry_hash'] = _ehash(e)
        prev = e['entry_hash']


def _members(path):
    with zipfile.ZipFile(path) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def _entries(m):
    return [json.loads(line) for line in m['ledger.jsonl'].decode().splitlines() if line.strip()]


def _dump(entries):
    return b''.join((json.dumps(e, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
                    for e in entries)


def _write(path, m, fix=True):
    if fix:
        man = json.loads(m['manifest.json'])
        for n in ('ledger.jsonl', 'anchors.jsonl', 'signing_key.pub.pem'):
            man['files'][n] = {'sha256': _sha(m[n]), 'bytes': len(m[n])}
        try:
            ents = _entries(m)
        except ValueError:
            ents = []
        man['ledger_count'] = len(ents)
        man['ledger_head'] = ents[-1]['entry_hash'] if ents else ZERO
        man['anchor_count'] = len([line for line in m['anchors.jsonl'].splitlines() if line.strip()])
        m['manifest.json'] = json.dumps(man, sort_keys=True).encode()
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for n, b in m.items():
            z.writestr(n, b)
    return path


@pytest.fixture
def world(tmp_path, monkeypatch):
    d = tmp_path / 'primary'
    a1, a2 = _build(monkeypatch, d, 'primary')
    bundle = tmp_path / 'bundle.zip'
    exporter.export_bundle(d, bundle)
    return types.SimpleNamespace(dir=d, bundle=bundle, a1=a1, a2=a2, tmp=tmp_path, mp=monkeypatch)


def _forge(world, name, mutate, fix=True):
    m = _members(world.bundle)
    mutate(m)
    return _write(world.tmp / name, m, fix)


def _rewrite_db(db, entry_id, new_payload):
    conn = sqlite3.connect(db)
    rows = conn.execute('SELECT id, ts, entry_type, payload FROM ledger_entries ORDER BY id').fetchall()
    prev = ZERO
    for i, ts, t, p in rows:
        if i == entry_id:
            p = new_payload
        h = _sha(f'{i}|{prev}|{ts}|{t}|{p}'.encode())
        conn.execute('UPDATE ledger_entries SET payload=?, prev_hash=?, entry_hash=? WHERE id=?', (p, prev, h, i))
        prev = h
    conn.commit()
    conn.close()


def test_happy_path_internal_only(world):
    r = verifier.verify_bundle(str(world.bundle))
    assert (r['status'], r['trust_level']) == ('VERIFIED', 'internal_only')
    assert (r['ledger_entries'], r['anchors'], r['unanchored_entries']) == (6, 2, 1)
    assert r['warnings']


def test_anchor_pinned(world):
    r = verifier.verify_bundle(str(world.bundle), pin_key_id=world.a1['key_id'],
                               pin_anchors=[(2, world.a2['anchor_hash'])], min_anchors=2)
    assert r['trust_level'] == 'anchor_pinned'


def test_cli_exit_codes(world):
    pinned = ['--pin-anchor', f"2:{world.a2['anchor_hash']}"]
    assert verifier.main([str(world.bundle)] + pinned) == 0
    assert verifier.main([str(world.bundle)]) == 10
    bad = _forge(world, 'bad.zip', lambda m: m.__setitem__('ledger.jsonl', b'not json\n'))
    assert verifier.main([str(bad)]) == 1


def test_db_tamper_detected(world):
    conn = sqlite3.connect(world.dir / 'ledger.db')
    conn.execute('UPDATE ledger_entries SET payload=? WHERE id=3', ('{"n":99}',))
    conn.commit()
    conn.close()
    out = world.tmp / 'tampered.zip'
    exporter.export_bundle(world.dir, out)
    with pytest.raises(verifier.VerificationError, match='hash mismatch at 3'):
        verifier.verify_bundle(str(out))


def test_db_delete_detected(world):
    conn = sqlite3.connect(world.dir / 'ledger.db')
    conn.execute('DELETE FROM ledger_entries WHERE id=3')
    conn.commit()
    conn.close()
    out = world.tmp / 'deleted.zip'
    exporter.export_bundle(world.dir, out)
    with pytest.raises(verifier.VerificationError, match='id discontinuity at 4'):
        verifier.verify_bundle(str(out))


def test_reorder_detected(world):
    def mutate(m):
        e = _entries(m)
        e[3], e[4] = e[4], e[3]
        m['ledger.jsonl'] = _dump(e)
    with pytest.raises(verifier.VerificationError, match='id discontinuity'):
        verifier.verify_bundle(str(_forge(world, 'reorder.zip', mutate)))


def test_rechained_rewrite_caught_by_anchor(world):
    def mutate(m):
        e = _entries(m)
        e[1]['payload'] = '{"n":1000,"tag":"forged"}'
        _rechain(e)
        m['ledger.jsonl'] = _dump(e)
    with pytest.raises(verifier.VerificationError, match='does not match ledger entry'):
        verifier.verify_bundle(str(_forge(world, 'rechain.zip', mutate)))


def test_non_canonical_payload_rejected(world):
    def mutate(m):
        e = _entries(m)
        e[0]['payload'] = '{"n": 0, "tag": "primary"}'
        _rechain(e)
        m['ledger.jsonl'] = _dump(e)
    with pytest.raises(verifier.VerificationError, match='not canonical'):
        verifier.verify_bundle(str(_forge(world, 'noncanon.zip', mutate)))


def test_truncation_below_anchor_detected(world):
    def mutate(m):
        m['ledger.jsonl'] = _dump(_entries(m)[:2])
    with pytest.raises(verifier.VerificationError, match='shorter than anchor'):
        verifier.verify_bundle(str(_forge(world, 'trunc.zip', mutate)))


def test_rollback_of_ledger_and_anchors_needs_pin(world):
    def mutate(m):
        m['ledger.jsonl'] = _dump(_entries(m)[:3])
        m['anchors.jsonl'] = m['anchors.jsonl'].splitlines(keepends=True)[0]
    path = str(_forge(world, 'rollback.zip', mutate))
    assert verifier.verify_bundle(path)['trust_level'] == 'internal_only'
    with pytest.raises(verifier.VerificationError, match='pinned anchor 2'):
        verifier.verify_bundle(path, pin_anchors=[(2, world.a2['anchor_hash'])])


def test_wholesale_regeneration_needs_pin(world):
    d2 = world.tmp / 'attacker'
    _build(world.mp, d2, 'forged')
    forged = world.tmp / 'forged.zip'
    exporter.export_bundle(d2, forged)
    assert verifier.verify_bundle(str(forged))['trust_level'] == 'internal_only'
    with pytest.raises(verifier.VerificationError, match='pinned key'):
        verifier.verify_bundle(str(forged), pin_key_id=world.a1['key_id'])
    with pytest.raises(verifier.VerificationError, match='pinned anchor 2 hash mismatch'):
        verifier.verify_bundle(str(forged), pin_anchors=[(2, world.a2['anchor_hash'])])


def test_spliced_ledger_and_anchors_rejected(world):
    d2 = world.tmp / 'attacker'
    _build(world.mp, d2, 'forged')
    other = world.tmp / 'other.zip'
    exporter.export_bundle(d2, other)
    foreign = _members(other)['ledger.jsonl']
    with pytest.raises(verifier.VerificationError, match='does not match ledger entry'):
        verifier.verify_bundle(str(_forge(world, 'splice.zip', lambda m: m.__setitem__('ledger.jsonl', foreign))))


def test_forged_signature_rejected(world):
    def mutate(m):
        lines = m['anchors.jsonl'].splitlines()
        a = json.loads(lines[1])
        a['signature'] = base64.b64encode(b'\x01' * 64).decode()
        lines[1] = json.dumps(a, sort_keys=True, separators=(',', ':')).encode()
        m['anchors.jsonl'] = b'\n'.join(lines) + b'\n'
    with pytest.raises(verifier.VerificationError, match='signature invalid at 2'):
        verifier.verify_bundle(str(_forge(world, 'sig.zip', mutate)))


def test_duplicated_anchor_rejected(world):
    def mutate(m):
        lines = m['anchors.jsonl'].splitlines(keepends=True)
        m['anchors.jsonl'] = b''.join(lines + [lines[1]])
    with pytest.raises(verifier.VerificationError, match='sequence'):
        verifier.verify_bundle(str(_forge(world, 'dup.zip', mutate)))


def test_unexpected_member_rejected(world):
    with pytest.raises(verifier.VerificationError, match='unexpected archive members'):
        verifier.verify_bundle(str(_forge(world, 'extra.zip', lambda m: m.__setitem__('../evil.txt', b'x'))))


def test_manifest_hash_mismatch_rejected(world):
    path = _forge(world, 'nofix.zip', lambda m: m.__setitem__('ledger.jsonl', m['ledger.jsonl'] + b'\n'), fix=False)
    with pytest.raises(verifier.VerificationError, match='sha256 mismatch'):
        verifier.verify_bundle(str(path))


def test_legacy_anchor_supported(world):
    priv, _pub, _kid = rf_core.load_or_create_keypair()

    def mutate(m):
        e = _entries(m)
        core = {'schema': 'rf.anchor.v1', 'seq': 1, 'created_at': rf_core._utc_now(), 'ledger_count': 3,
                'ledger_head': e[2]['entry_hash'], 'prev_anchor_hash': ZERO}
        h = _sha(json.dumps(core, sort_keys=True).encode())
        a = {**core, 'anchor_hash': h, 'signature': base64.b64encode(priv.sign(h.encode())).decode()}
        m['anchors.jsonl'] = (json.dumps(a, sort_keys=True, separators=(',', ':')) + '\n').encode()
    r = verifier.verify_bundle(str(_forge(world, 'legacy.zip', mutate)))
    assert r['anchors'] == 1 and any('legacy' in w for w in r['warnings'])


def test_exporter_is_public_only_and_refuses_overwrite(world):
    m = _members(world.bundle)
    assert set(m) in (set(verifier.MEMBERS), set(verifier.MEMBERS_V2))
    assert all(b'PRIVATE KEY' not in b for b in m.values())
    with pytest.raises(FileExistsError):
        exporter.export_bundle(world.dir, world.bundle)


def test_verifier_detects_history_rewrite_with_trailing_entries(world):
    _rewrite_db(world.dir / 'ledger.db', 2, '{"n":1000,"tag":"forged"}')
    out = world.tmp / 'rewritten.zip'
    exporter.export_bundle(world.dir, out)
    with pytest.raises(verifier.VerificationError, match='does not match ledger entry'):
        verifier.verify_bundle(str(out))


def test_core_detects_history_rewrite_with_trailing_entries(world):
    _rewrite_db(world.dir / 'ledger.db', 2, '{"n":1000,"tag":"forged"}')
    ok, _reason = rf_core.verify_anchors()
    assert not ok