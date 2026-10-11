"""RightsFrames hardened API surface."""

from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, ConfigDict, Field

from rf_core import (
    MAX_ENTRY_TYPE,
    MAX_PAYLOAD_BYTES,
    append_entry,
    create_anchor,
    health,
)

MAX_REQUEST_BYTES = 393216
API_KEY = os.environ.get('RF_API_KEY', '').strip()

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


@app.get('/health')
def health_endpoint():
    return health()


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
            detail='invalid request',
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
            detail='invalid request',
        ) from exc
