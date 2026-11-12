"""RightsFrames hardened API surface."""

from __future__ import annotations

import hmac
import os
import threading
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, ConfigDict, Field

from core import rf_core as _rf_core
from core.rf_core import (
    MAX_ENTRY_TYPE,
    append_entry,
    create_anchor,
    health,
)

MAX_REQUEST_BYTES = 393216
API_KEY = os.environ.get('RF_API_KEY', '').strip()

# /health is unauthenticated and verifies the whole ledger and every anchor
# signature, so its cost grows with the ledger. One verification is shared by
# all callers for this many seconds (0 disables sharing), and concurrent
# callers wait for the one in flight instead of each starting their own.
HEALTH_CACHE_MAX_SECONDS = 300.0


def _health_cache_seconds() -> float:
    raw = os.environ.get('RF_HEALTH_CACHE_SECONDS', '5').strip() or '5'
    try:
        value = float(raw)
    except ValueError:
        raise ValueError('RF_HEALTH_CACHE_SECONDS must be a number of seconds') from None
    if not 0 <= value <= HEALTH_CACHE_MAX_SECONDS:
        raise ValueError(
            f'RF_HEALTH_CACHE_SECONDS must be between 0 and {HEALTH_CACHE_MAX_SECONDS:g}')
    return value


HEALTH_CACHE_SECONDS = _health_cache_seconds()
_HEALTH_LOCK = threading.Lock()
_HEALTH_CACHE: dict[str, Any] = {}

app = FastAPI(
    title='RightsFrames Core',
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Production perimeter restrictions. Deployment may override the host list
# through RF_ALLOWED_HOSTS without changing application source.
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get(
        'RF_ALLOWED_HOSTS',
        '127.0.0.1,localhost',
    ).split(',')
    if host.strip()
]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.environ.get('RF_ALLOWED_ORIGINS', '').split(',')
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=['Authorization', 'Content-Type', 'X-API-Key'],
)


class BodyLimitMiddleware:
    """Enforce MAX_REQUEST_BYTES on the bytes actually received.

    The Content-Length check in security_middleware only covers requests that
    declare a length. A chunked request declares none, so without this its
    whole body would be buffered and parsed before any size or authentication
    check ran. The body is counted as it arrives and the request is refused
    with 413 as soon as it passes the limit.
    """

    def __init__(self, app: Any, max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        limit = MAX_REQUEST_BYTES if self.max_bytes is None else self.max_bytes
        received = 0

        async def limited_receive() -> Any:
            nonlocal received
            message = await receive()
            if message['type'] == 'http.request':
                received += len(message.get('body', b''))
                if received > limit:
                    raise HTTPException(
                        status_code=413,
                        detail='request body exceeds maximum size',
                        headers={'Connection': 'close'},
                    )
            return message

        await self.app(scope, limited_receive, send)


app.add_middleware(BodyLimitMiddleware)


class EntryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    entry_type: str = Field(
        min_length=1,
        max_length=MAX_ENTRY_TYPE,
    )
    payload: dict[str, Any] = Field(default_factory=dict)


@app.middleware('http')
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get('content-length')

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    {'detail': 'request body exceeds maximum size'},
                    status_code=413,
                )
        except ValueError:
            return JSONResponse(
                {'detail': 'invalid content-length'},
                status_code=400,
            )

    response = await call_next(request)

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

    return response


def _require_api_key(
    authorization: str | None,
    x_api_key: str | None,
) -> None:
    if not API_KEY:
        raise HTTPException(
            status_code=503,
            detail='write authentication is not configured',
        )

    supplied = ''

    if x_api_key:
        supplied = x_api_key.strip()
    elif authorization and authorization.startswith('Bearer '):
        supplied = authorization[7:].strip()

    if not supplied or not hmac.compare_digest(supplied, API_KEY):
        raise HTTPException(
            status_code=401,
            detail='authentication required',
            headers={'WWW-Authenticate': 'Bearer'},
        )


def _health_report() -> dict[str, Any]:
    ttl = HEALTH_CACHE_SECONDS
    if ttl <= 0:
        return health()
    # The cached report belongs to one health function and one data directory.
    key = (health, str(_rf_core.DATA_DIR))
    with _HEALTH_LOCK:
        cached = _HEALTH_CACHE.get('entry')
        if cached is not None and cached[0] == key and time.monotonic() < cached[1]:
            return cached[2]
        report = health()
        _HEALTH_CACHE['entry'] = (key, time.monotonic() + ttl, report)
        return report


@app.get('/health')
def health_endpoint():
    report = _health_report()
    if set(report) == {'status'}:
        return {'status': report['status']}
    return {
        'service': report.get('service', 'RightsFrames'),
        'status': report.get('status', 'ok'),
        'ledger_ok': report.get('ledger', {}).get('ok', False),
        'anchors_ok': report.get('anchors', {}).get('ok', False),
    }


@app.post('/entries', status_code=201)
def create_entry(
    body: EntryRequest,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
):
    _require_api_key(authorization, x_api_key)

    try:
        return append_entry(
            body.entry_type,
            body.payload,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail='bad entry',
        ) from exc


@app.post('/anchor', status_code=201)
def anchor(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
):
    _require_api_key(authorization, x_api_key)

    try:
        return create_anchor()
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail='anchor not created',
        ) from exc

# --- API v1: per-principal credentials, scopes, audited operations ---
from rf_api_v1 import router as _api_v1_router  # noqa: E402

app.include_router(_api_v1_router)
