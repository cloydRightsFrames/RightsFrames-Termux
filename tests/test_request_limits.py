"""Request-size and /health cost limits of the API surface (core/app.py)."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip('httpx2')
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_core as top_rf_core  # noqa: E402  (the module rf_api_v1 uses)

import core.app as appmod  # noqa: E402
import core.rf_core as pkg_rf_core  # noqa: E402  (the module core.app uses)

KEY = 'limit-test-key-0123456789'
PATHS = (('DATA_DIR', ''), ('DB_PATH', 'ledger.db'), ('PRIVATE_KEY_PATH', 'signing_key.pem'),
         ('PUBLIC_KEY_PATH', 'signing_key.pub.pem'), ('KEY_ID_PATH', 'signing_key.id'),
         ('ANCHOR_PATH', 'anchors.jsonl'), ('LOCK_PATH', 'anchors.lock'))


def _point(monkeypatch, base):
    base.mkdir(parents=True, exist_ok=True)
    for module in (pkg_rf_core, top_rf_core):
        for name, leaf in PATHS:
            monkeypatch.setattr(module, name, base / leaf if leaf else base)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    monkeypatch.setattr(appmod, 'API_KEY', KEY)
    monkeypatch.setattr(appmod, '_HEALTH_CACHE', {})
    with TestClient(appmod.app, base_url='http://localhost') as test_client:
        yield test_client


def _entry_body(payload_bytes):
    return json.dumps({'entry_type': 'limit', 'payload': {'pad': 'A' * payload_bytes}}).encode()


def _chunks(body, size=16384):
    """A generator body is sent chunked: the request carries no Content-Length."""
    for start in range(0, len(body), size):
        yield body[start:start + size]


def _ledger_count():
    return len(pkg_rf_core._ledger_snapshot())


def test_chunked_body_over_the_limit_is_refused_even_with_a_valid_key(client):
    body = _entry_body(appmod.MAX_REQUEST_BYTES * 2)
    response = client.post('/entries', content=_chunks(body),
                           headers={'X-API-Key': KEY, 'Content-Type': 'application/json'})
    assert response.status_code == 413
    assert response.json() == {'detail': 'request body exceeds maximum size'}
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert _ledger_count() == 0


@pytest.mark.parametrize('path', ['/entries', '/v1/entries'])
def test_chunked_body_over_the_limit_is_refused_before_authentication(client, path):
    body = _entry_body(appmod.MAX_REQUEST_BYTES * 2)
    response = client.post(path, content=_chunks(body),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 413
    assert _ledger_count() == 0


def test_declared_length_over_the_limit_is_still_refused(client):
    body = _entry_body(appmod.MAX_REQUEST_BYTES * 2)
    response = client.post('/entries', content=body,
                           headers={'X-API-Key': KEY, 'Content-Type': 'application/json'})
    assert response.status_code == 413
    assert _ledger_count() == 0


def test_chunked_body_within_the_limit_is_accepted(client):
    body = _entry_body(4096)
    response = client.post('/entries', content=_chunks(body, 512),
                           headers={'X-API-Key': KEY, 'Content-Type': 'application/json'})
    assert response.status_code == 201
    assert response.json()['payload'] == {'pad': 'A' * 4096}
    assert _ledger_count() == 1
    assert pkg_rf_core.verify_chain()[0]


def test_body_limit_stops_reading_as_soon_as_the_limit_is_passed():
    """An endless body is cut off after the limit, not buffered until it ends."""
    chunk = b'x' * 1000
    limit = 10_000
    reads = 0

    async def endless_receive():
        nonlocal reads
        reads += 1
        return {'type': 'http.request', 'body': chunk, 'more_body': True}

    async def reading_app(scope, receive, send):
        while True:
            await receive()

    async def unused_send(message):
        raise AssertionError('nothing is sent by this app')

    middleware = appmod.BodyLimitMiddleware(reading_app, max_bytes=limit)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(middleware({'type': 'http'}, endless_receive, unused_send))
    assert refused.value.status_code == 413
    assert reads == limit // len(chunk) + 1


def test_body_limit_counts_exactly_and_ignores_other_messages():
    limit = 10
    seen = []
    messages = [
        {'type': 'http.request', 'body': b'12345', 'more_body': True},
        {'type': 'http.request', 'body': b'67890', 'more_body': False},
        {'type': 'http.disconnect'},
    ]

    async def receive():
        return messages.pop(0)

    async def reading_app(scope, receive, send):
        for _ in range(3):
            seen.append((await receive())['type'])

    middleware = appmod.BodyLimitMiddleware(reading_app, max_bytes=limit)
    asyncio.run(middleware({'type': 'http'}, receive, None))
    assert seen == ['http.request', 'http.request', 'http.disconnect']


def test_body_limit_leaves_non_http_scopes_alone():
    calls = []

    async def lifespan_app(scope, receive, send):
        calls.append((scope['type'], receive, send))

    middleware = appmod.BodyLimitMiddleware(lifespan_app, max_bytes=1)
    asyncio.run(middleware({'type': 'lifespan'}, 'receive', 'send'))
    assert calls == [('lifespan', 'receive', 'send')]


def test_anchor_conflict_is_reported_as_an_anchor_error(client, monkeypatch):
    def refuse():
        raise ValueError('ledger verification failed')

    monkeypatch.setattr(appmod, 'create_anchor', refuse)
    response = client.post('/anchor', headers={'X-API-Key': KEY})
    assert response.status_code == 409
    assert response.json() == {'detail': 'anchor not created'}


class _CountingHealth:
    def __init__(self, status='ok'):
        self.calls = 0
        self.status = status

    def __call__(self):
        self.calls += 1
        return {'status': self.status}


def test_health_verification_is_shared_between_callers(client, monkeypatch):
    counter = _CountingHealth()
    monkeypatch.setattr(appmod, 'health', counter)
    monkeypatch.setattr(appmod, 'HEALTH_CACHE_SECONDS', 60.0)
    for _ in range(5):
        assert client.get('/health').json() == {'status': 'ok'}
    assert counter.calls == 1


def test_health_is_verified_again_after_the_cache_expires(client, monkeypatch):
    counter = _CountingHealth()
    now = [1000.0]
    monkeypatch.setattr(appmod, 'health', counter)
    monkeypatch.setattr(appmod, 'HEALTH_CACHE_SECONDS', 5.0)
    monkeypatch.setattr(appmod.time, 'monotonic', lambda: now[0])
    client.get('/health')
    now[0] += 4.9
    client.get('/health')
    assert counter.calls == 1
    now[0] += 0.2
    counter.status = 'degraded'
    assert client.get('/health').json() == {'status': 'degraded'}
    assert counter.calls == 2


def test_health_cache_can_be_disabled(client, monkeypatch):
    counter = _CountingHealth()
    monkeypatch.setattr(appmod, 'health', counter)
    monkeypatch.setattr(appmod, 'HEALTH_CACHE_SECONDS', 0.0)
    for _ in range(3):
        client.get('/health')
    assert counter.calls == 3


def test_health_cache_is_not_reused_for_another_data_directory(client, tmp_path, monkeypatch):
    counter = _CountingHealth()
    monkeypatch.setattr(appmod, 'health', counter)
    monkeypatch.setattr(appmod, 'HEALTH_CACHE_SECONDS', 60.0)
    client.get('/health')
    _point(monkeypatch, tmp_path / 'other')
    client.get('/health')
    assert counter.calls == 2


def test_health_reports_a_tampered_ledger_once_the_cache_expires(client, monkeypatch):
    import contextlib
    import sqlite3

    now = [50.0]
    monkeypatch.setattr(appmod, 'HEALTH_CACHE_SECONDS', 5.0)
    monkeypatch.setattr(appmod.time, 'monotonic', lambda: now[0])
    pkg_rf_core.append_entry('limit', {'n': 1})
    assert client.get('/health').json()['ledger_ok'] is True

    with contextlib.closing(sqlite3.connect(pkg_rf_core.DB_PATH)) as conn:
        conn.execute("UPDATE ledger_entries SET payload='{\"n\":2}' WHERE id=1")
        conn.commit()

    now[0] += 5.1
    report = client.get('/health').json()
    assert report['ledger_ok'] is False
    assert report['status'] == 'degraded'


@pytest.mark.parametrize('raw, expected', [('', 5.0), ('0', 0.0), ('2.5', 2.5), ('300', 300.0)])
def test_health_cache_seconds_accepts_valid_settings(monkeypatch, raw, expected):
    monkeypatch.setenv('RF_HEALTH_CACHE_SECONDS', raw)
    assert appmod._health_cache_seconds() == expected


def test_health_cache_seconds_defaults_to_five(monkeypatch):
    monkeypatch.delenv('RF_HEALTH_CACHE_SECONDS', raising=False)
    assert appmod._health_cache_seconds() == 5.0


@pytest.mark.parametrize('raw', ['-1', '301', 'soon', 'nan', 'inf'])
def test_health_cache_seconds_rejects_invalid_settings(monkeypatch, raw):
    monkeypatch.setenv('RF_HEALTH_CACHE_SECONDS', raw)
    with pytest.raises(ValueError):
        appmod._health_cache_seconds()


def test_every_writing_connection_uses_full_synchronous(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'data')
    conn = pkg_rf_core._connect()
    try:
        assert conn.execute('PRAGMA synchronous').fetchone()[0] == 2
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
    finally:
        conn.close()
    with pkg_rf_core.write_transaction() as writer:
        assert writer.execute('PRAGMA synchronous').fetchone()[0] == 2
