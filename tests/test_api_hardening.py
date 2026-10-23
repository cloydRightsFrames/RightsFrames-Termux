"""API hardening: proxy-aware client identity, throttle eviction, audited legacy writes."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip('httpx')
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
sys.path.insert(0, str(ROOT))
import rf_api_v1  # noqa: E402
import rf_auth  # noqa: E402
import rf_core  # noqa: E402
from core import rf_core as packaged_rf_core  # noqa: E402

ALL = ['admin:principals', 'ledger:read', 'entries:write', 'anchor:create', 'evidence:export']


def _point(mp, module, base):
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(module, name, value)


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    _point(monkeypatch, rf_core, data)
    _point(monkeypatch, packaged_rf_core, data)
    monkeypatch.setenv('RF_API_KEY', 'legacy-secret-for-tests-0123456789')
    monkeypatch.delenv('RF_TRUSTED_PROXIES', raising=False)
    rf_api_v1._FAILURES.clear()
    spec = importlib.util.spec_from_file_location('rf_app_hardening', ROOT / 'core' / 'app.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['rf_app_hardening'] = module
    spec.loader.exec_module(module)
    client = TestClient(module.app, base_url='http://localhost')
    admin = rf_auth.create_principal('admin-1', ALL, 'test', 'test')
    return types.SimpleNamespace(client=client, admin=admin, monkeypatch=monkeypatch)


def _request(peer: str, headers: dict[str, str]):
    return types.SimpleNamespace(
        client=types.SimpleNamespace(host=peer),
        headers={k.lower(): v for k, v in headers.items()},
    )


def test_forwarded_headers_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.delenv('RF_TRUSTED_PROXIES', raising=False)
    req = _request('203.0.113.9', {'CF-Connecting-IP': '198.51.100.1',
                                   'X-Forwarded-For': '198.51.100.2'})
    assert rf_api_v1.client_address(req) == '203.0.113.9'


def test_forwarded_headers_used_from_trusted_proxy(monkeypatch):
    monkeypatch.setenv('RF_TRUSTED_PROXIES', '127.0.0.1, ::1')
    assert rf_api_v1.client_address(
        _request('127.0.0.1', {'CF-Connecting-IP': '198.51.100.1'})) == '198.51.100.1'
    assert rf_api_v1.client_address(
        _request('127.0.0.1', {'X-Forwarded-For': '10.9.9.9, 198.51.100.7'})) == '198.51.100.7'
    assert rf_api_v1.client_address(
        _request('127.0.0.1', {'CF-Connecting-IP': 'not-an-ip'})) == '127.0.0.1'


def test_throttle_eviction_never_resets_active_lockouts(monkeypatch):
    rf_api_v1._FAILURES.clear()
    monkeypatch.setattr(rf_api_v1, 'FAIL_TRACKED_CLIENTS', 50)
    for _ in range(rf_api_v1.FAIL_LIMIT):
        rf_api_v1._throttle_fail('198.51.100.66')
    for index in range(200):
        rf_api_v1._throttle_fail(f'10.0.{index // 250}.{index % 250}')
    assert len(rf_api_v1._FAILURES) <= 50
    with pytest.raises(rf_api_v1.HTTPException) as exc:
        rf_api_v1._throttle_check('198.51.100.66')
    assert exc.value.status_code == 429
    rf_api_v1._FAILURES.clear()


def test_legacy_shared_key_writes_are_audited(env):
    key = {'X-API-Key': 'legacy-secret-for-tests-0123456789'}
    r = env.client.post('/entries', headers=key, json={'entry_type': 'evt', 'payload': {'n': 1}})
    assert r.status_code == 201, r.text
    r = env.client.post('/anchor', headers=key)
    assert r.status_code == 201, r.text
    entries = env.client.get('/v1/ledger/entries', params={'after_id': 0, 'limit': 100},
                             headers={'Authorization': f'Bearer {env.admin}'}).json()['entries']
    audit = [json.loads(e['payload']) for e in entries if e['entry_type'] == 'audit.api']
    actions = [(a['principal'], a['action']) for a in audit]
    assert ('legacy-shared-api-key', 'entries.append') in actions
    assert ('legacy-shared-api-key', 'anchor.create') in actions


def test_legacy_endpoint_rejects_delimiter_in_entry_type(env):
    key = {'X-API-Key': 'legacy-secret-for-tests-0123456789'}
    r = env.client.post('/entries', headers=key, json={'entry_type': 'a|b', 'payload': {}})
    assert r.status_code == 400
