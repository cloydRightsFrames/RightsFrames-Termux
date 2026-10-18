import importlib.util
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip('httpx')
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_api_v1  # noqa: E402
import rf_auth  # noqa: E402
import rf_core  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_apitest', 'verifier/rf_verify.py')
ALL = ['admin:principals', 'ledger:read', 'entries:write', 'anchor:create', 'evidence:export']


def _point(mp, base):
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)


def _h(token):
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def env(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    monkeypatch.setenv('RF_API_KEY', '')
    rf_api_v1._FAILURES.clear()
    spec = importlib.util.spec_from_file_location('rf_app_under_test', ROOT / 'core' / 'app.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['rf_app_under_test'] = module
    spec.loader.exec_module(module)
    client = TestClient(module.app, base_url='http://localhost')
    admin = rf_auth.create_principal('admin-1', ALL, 'test', 'test')
    return types.SimpleNamespace(client=client, admin=admin, tmp=tmp_path)


def _mk(env, pid, scopes):
    r = env.client.post('/v1/principals', headers=_h(env.admin), json={'id': pid, 'scopes': scopes, 'label': 't'})
    assert r.status_code == 201, r.text
    return r.json()['token']


def _entries(env, after=0, limit=1000):
    r = env.client.get('/v1/ledger/entries', headers=_h(env.admin), params={'after_id': after, 'limit': limit})
    assert r.status_code == 200, r.text
    return r.json()


def _count(env):
    return env.client.get('/v1/ledger/head', headers=_h(env.admin)).json()['ledger_count']


def test_requires_authentication(env):
    r = env.client.get('/v1/ledger/head')
    assert r.status_code == 401 and 'Bearer' in r.headers['www-authenticate']


def test_wrong_and_malformed_tokens_rejected(env):
    for token in ('x', 'rfp1.admin-1.bad', 'rfp1..', 'rfp1.nobody.' + 'a' * 43):
        assert env.client.get('/v1/ledger/head', headers=_h(token)).status_code == 401


def test_scope_enforcement(env):
    reader = _mk(env, 'reader-1', ['ledger:read'])
    assert env.client.get('/v1/ledger/head', headers=_h(reader)).status_code == 200
    assert env.client.post('/v1/entries', headers=_h(reader), json={'entry_type': 'x'}).status_code == 403
    assert env.client.post('/v1/anchors', headers=_h(reader)).status_code == 403
    assert env.client.get('/v1/evidence/export', headers=_h(reader)).status_code == 403
    assert env.client.get('/v1/principals', headers=_h(reader)).status_code == 403


def test_append_is_attributed_and_audited(env):
    writer = _mk(env, 'writer-1', ['entries:write'])
    before = _count(env)
    r = env.client.post('/v1/entries', headers=_h(writer), json={'entry_type': 'evt', 'payload': {'n': 1}})
    assert r.status_code == 201
    new = _entries(env, after=before)['entries']
    assert [e['entry_type'] for e in new] == ['audit.api', 'evt']
    import json
    audit = json.loads(new[0]['payload'])
    assert audit['principal'] == 'writer-1' and audit['action'] == 'entries.append'


def test_principal_creation_is_audited(env):
    _mk(env, 'reader-2', ['ledger:read'])
    import json
    created = [json.loads(e['payload']) for e in _entries(env)['entries']
               if e['entry_type'] == 'auth.principal.created']
    assert {'principal': 'reader-2', 'scopes': ['ledger:read'], 'label': 't', 'actor': 'admin-1'} in created


def test_idempotency(env):
    h = {**_h(env.admin), 'Idempotency-Key': 'key-0001-abcd'}
    first = env.client.post('/v1/entries', headers=h, json={'entry_type': 'evt', 'payload': {'n': 1}})
    assert first.status_code == 201
    count = _count(env)
    replay = env.client.post('/v1/entries', headers=h, json={'entry_type': 'evt', 'payload': {'n': 1}})
    assert replay.status_code == 200 and replay.json()['id'] == first.json()['id']
    assert _count(env) == count
    clash = env.client.post('/v1/entries', headers=h, json={'entry_type': 'evt', 'payload': {'n': 2}})
    assert clash.status_code == 409
    bad = env.client.post('/v1/entries', headers={**_h(env.admin), 'Idempotency-Key': 'short'},
                          json={'entry_type': 'evt'})
    assert bad.status_code == 400


def test_revocation_and_last_admin(env):
    token = _mk(env, 'reader-3', ['ledger:read'])
    assert env.client.get('/v1/ledger/head', headers=_h(token)).status_code == 200
    assert env.client.delete('/v1/principals/reader-3', headers=_h(env.admin)).status_code == 200
    assert env.client.get('/v1/ledger/head', headers=_h(token)).status_code == 401
    assert env.client.delete('/v1/principals/reader-3', headers=_h(env.admin)).status_code == 409
    assert env.client.delete('/v1/principals/admin-1', headers=_h(env.admin)).status_code == 409
    assert env.client.delete('/v1/principals/ghost-1', headers=_h(env.admin)).status_code == 404


def test_unknown_scope_rejected(env):
    r = env.client.post('/v1/principals', headers=_h(env.admin), json={'id': 'bad-1', 'scopes': ['root']})
    assert r.status_code == 400


def test_failed_auth_throttle(env):
    for _ in range(10):
        assert env.client.get('/v1/ledger/head', headers=_h('rfp1.admin-1.wrong')).status_code == 401
    assert env.client.get('/v1/ledger/head', headers=_h('rfp1.admin-1.wrong')).status_code == 429
    assert env.client.get('/v1/ledger/head', headers=_h(env.admin)).status_code == 429


def test_secret_never_stored(env):
    secret = env.admin.split('.')[2].encode()
    for path in (rf_core.DATA_DIR).glob('principals.db*'):
        assert secret not in path.read_bytes()


def test_pagination(env):
    for n in range(3):
        env.client.post('/v1/entries', headers=_h(env.admin), json={'entry_type': 'evt', 'payload': {'n': n}})
    page = _entries(env, after=0, limit=2)
    assert len(page['entries']) == 2 and page['next_after_id'] == page['entries'][-1]['id']


def test_verify_endpoint(env):
    env.client.post('/v1/anchors', headers=_h(env.admin))
    r = env.client.get('/v1/ledger/verify', headers=_h(env.admin))
    assert r.status_code == 200 and r.json()['ok'] is True


def test_anchor_and_export_verify_independently(env):
    a = env.client.post('/v1/anchors', headers=_h(env.admin))
    assert a.status_code == 201
    anchor = a.json()
    r = env.client.get('/v1/evidence/export', headers=_h(env.admin))
    assert r.status_code == 200 and r.headers['content-type'] == 'application/zip'
    path = env.tmp / 'export.zip'
    path.write_bytes(r.content)
    report = verifier.verify_bundle(str(path), pin_anchors=[(anchor['seq'], anchor['anchor_hash'])])
    assert report['trust_level'] == 'anchor_pinned'