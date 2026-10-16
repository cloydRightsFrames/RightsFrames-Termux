"""RightsFrames API v1: per-principal credentials, scopes, audited privileged operations.

Every state-changing operation appends an `audit.api` entry (principal, action, request
digest) to the ledger BEFORE the operation runs, so intent is recorded even if the
operation fails. Read endpoints are scope-gated but not written to the ledger.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

import rf_auth
import rf_core

router = APIRouter(prefix='/v1')

MAX_EXPORT_BYTES = 256 * 1024 * 1024
FAIL_LIMIT = 10
FAIL_WINDOW = 60.0
_FAILURES: dict[str, list[float]] = {}
_FAIL_LOCK = threading.Lock()
_KEY = re.compile(r'^[A-Za-z0-9._-]{8,128}$')
_exporter_module: Any = None


def _throttle_check(host: str) -> None:
    now = time.monotonic()
    with _FAIL_LOCK:
        recent = [t for t in _FAILURES.get(host, []) if now - t < FAIL_WINDOW]
        _FAILURES[host] = recent
        if len(recent) >= FAIL_LIMIT:
            raise HTTPException(status_code=429, detail='too many failed authentications',
                                headers={'Retry-After': str(int(FAIL_WINDOW))})


def _throttle_fail(host: str) -> None:
    with _FAIL_LOCK:
        if len(_FAILURES) > 10000:
            _FAILURES.clear()
        _FAILURES.setdefault(host, []).append(time.monotonic())


def _extract(authorization: str | None, x_api_key: str | None) -> str:
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization and authorization.startswith('Bearer '):
        return authorization[7:].strip()
    return ''


def require(scope: str) -> Callable[..., dict[str, Any]]:
    def dependency(request: Request,
                   authorization: str | None = Header(default=None),
                   x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
        host = request.client.host if request.client else 'unknown'
        _throttle_check(host)
        token = _extract(authorization, x_api_key)
        principal = rf_auth.authenticate(token) if token else None
        if principal is None:
            _throttle_fail(host)
            raise HTTPException(status_code=401, detail='authentication required',
                                headers={'WWW-Authenticate': 'Bearer'})
        if scope not in principal['scopes']:
            raise HTTPException(status_code=403, detail=f'missing scope {scope}')
        return principal
    return dependency


class EntryBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    entry_type: str = Field(min_length=1, max_length=rf_core.MAX_ENTRY_TYPE)
    payload: dict[str, Any] = Field(default_factory=dict)


class PrincipalBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[a-z0-9][a-z0-9-]{2,39}$')
    scopes: list[str] = Field(min_length=1, max_length=16)
    label: str = Field(default='', max_length=128)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _audit(principal: dict[str, Any], action: str, detail: dict[str, Any]) -> None:
    rf_core.append_entry('audit.api', {'principal': principal['id'], 'action': action, **detail})


def _head() -> tuple[int, str]:
    conn = rf_core._connect()
    try:
        row = conn.execute('SELECT id, entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1').fetchone()
    finally:
        conn.close()
    return (int(row[0]), str(row[1])) if row else (0, '0' * 64)


def _exporter() -> Any:
    global _exporter_module
    if _exporter_module is None:
        path = Path(__file__).resolve().parents[1] / 'tools' / 'rf_export_evidence.py'
        if not path.is_file():
            raise HTTPException(status_code=503, detail='exporter unavailable')
        spec = importlib.util.spec_from_file_location('rf_export_evidence_runtime', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _exporter_module = module
    return _exporter_module


@router.get('/ledger/head')
def ledger_head(principal: dict = Depends(require('ledger:read'))):
    count, head = _head()
    try:
        anchors = len(rf_core._read_anchors())
    except (ValueError, OSError):
        raise HTTPException(status_code=500, detail='anchor log unreadable') from None
    return {'ledger_count': count, 'ledger_head': head, 'anchor_count': anchors}


@router.get('/ledger/entries')
def ledger_entries(after_id: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                   principal: dict = Depends(require('ledger:read'))):
    conn = rf_core._connect()
    try:
        rows = conn.execute(
            'SELECT id, ts, entry_type, payload, prev_hash, entry_hash FROM ledger_entries '
            'WHERE id > ? ORDER BY id ASC LIMIT ?', (after_id, limit)).fetchall()
    finally:
        conn.close()
    entries = [{'id': r[0], 'ts': r[1], 'entry_type': r[2], 'payload': r[3],
                'prev_hash': r[4], 'entry_hash': r[5]} for r in rows]
    return {'entries': entries, 'next_after_id': entries[-1]['id'] if len(entries) == limit else None}


@router.get('/ledger/verify')
def ledger_verify(principal: dict = Depends(require('ledger:read'))):
    chain_ok, chain_reason = rf_core.verify_chain()
    anchors_ok, anchors_reason = rf_core.verify_anchors()
    return {'ok': chain_ok and anchors_ok,
            'chain': {'ok': chain_ok, 'detail': chain_reason},
            'anchors': {'ok': anchors_ok, 'detail': anchors_reason}}


@router.get('/anchors')
def anchors_list(after_seq: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                 principal: dict = Depends(require('ledger:read'))):
    try:
        anchors = rf_core._read_anchors()
    except (ValueError, OSError):
        raise HTTPException(status_code=500, detail='anchor log unreadable') from None
    return {'anchors': anchors[after_seq:after_seq + limit], 'total': len(anchors)}


@router.post('/anchors', status_code=201)
def anchors_create(principal: dict = Depends(require('anchor:create'))):
    _audit(principal, 'anchor.create', {})
    try:
        return rf_core.create_anchor()
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post('/entries', status_code=201)
def entries_create(body: EntryBody, response: Response,
                   principal: dict = Depends(require('entries:write')),
                   idempotency_key: str | None = Header(default=None)):
    def do_append() -> dict[str, Any]:
        _audit(principal, 'entries.append', {
            'entry_type': body.entry_type,
            'payload_sha256': _sha(rf_core._canonical_json(body.payload)),
        })
        return rf_core.append_entry(body.entry_type, body.payload)

    try:
        if idempotency_key is None:
            return do_append()
        if not _KEY.match(idempotency_key):
            raise HTTPException(status_code=400, detail='invalid Idempotency-Key')
        request_hash = _sha(rf_core._canonical_json(
            {'entry_type': body.entry_type, 'payload': body.payload}))
        result, replayed = rf_auth.idempotent_append(principal['id'], idempotency_key,
                                                     request_hash, do_append)
        if replayed:
            response.status_code = 200
            response.headers['Idempotent-Replay'] = 'true'
        return result
    except rf_auth.IdempotencyConflict:
        raise HTTPException(status_code=409,
                            detail='idempotency key reused with a different request') from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/evidence/export')
def evidence_export(principal: dict = Depends(require('evidence:export'))):
    exporter = _exporter()
    count, head = _head()
    _audit(principal, 'evidence.export', {'ledger_count': count, 'ledger_head': head})
    tmp = tempfile.mkdtemp(prefix='rf-export-')
    try:
        out = Path(tmp) / 'bundle.zip'
        manifest = exporter.export_bundle(rf_core.DATA_DIR, out)
        if out.stat().st_size > MAX_EXPORT_BYTES:
            raise HTTPException(status_code=507, detail='bundle exceeds export size limit')
        data = out.read_bytes()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    name = f"rf-evidence-{manifest['ledger_count']}-{manifest['ledger_head'][:12]}.zip"
    return Response(content=data, media_type='application/zip', headers={
        'Content-Disposition': f'attachment; filename="{name}"',
        'X-RF-Ledger-Head': manifest['ledger_head'],
        'X-RF-Anchor-Count': str(manifest['anchor_count']),
    })


@router.get('/principals')
def principals_list(principal: dict = Depends(require('admin:principals'))):
    return {'principals': rf_auth.list_principals()}


@router.post('/principals', status_code=201)
def principals_create(body: PrincipalBody, principal: dict = Depends(require('admin:principals'))):
    try:
        token = rf_auth.create_principal(body.id, body.scopes, body.label, actor=principal['id'])
    except rf_auth.Conflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'principal': body.id, 'scopes': sorted(set(body.scopes)), 'token': token}


@router.delete('/principals/{principal_id}')
def principals_revoke(principal_id: str, principal: dict = Depends(require('admin:principals'))):
    if not rf_auth.valid_principal_id(principal_id):
        raise HTTPException(status_code=404, detail='principal not found')
    try:
        rf_auth.revoke_principal(principal_id, actor=principal['id'])
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except rf_auth.Conflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {'revoked': principal_id}