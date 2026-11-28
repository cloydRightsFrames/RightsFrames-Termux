"""Opt-in RightsFrames agent evidence API.

Run with `uvicorn core.rf_agent_service:app --host 127.0.0.1 --port 18888`.
No route added to the legacy production app unless this module is selected.
The service never executes agent tools: successful authorization records evidence only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .app import app
from . import rf_agent_gate
from .rf_api_v1 import require

router = APIRouter(prefix="/v1/agent", tags=["Agent Evidence Gate"])


class AgentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any]
    agent: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=128)
    event: dict[str, Any]


class AgentRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nonce: str = Field(min_length=32, max_length=32)
    reason: str = Field(min_length=1, max_length=160)


def _load_config() -> tuple[Ed25519PublicKey, dict]:
    pub_path = os.environ.get("RF_AGENT_APPROVER_PUBKEY")
    policy_path = os.environ.get("RF_AGENT_POLICY_FILE")
    if not pub_path or not policy_path:
        raise HTTPException(503, "agent gate not configured")
    try:
        pub = Path(pub_path).resolve(strict=True)
        pol = Path(policy_path).resolve(strict=True)
        if not pub.is_file() or not pol.is_file() or pub.stat().st_size > 8192 or pol.stat().st_size > 131072:
            raise ValueError("invalid configuration files")
        key = serialization.load_pem_public_key(pub.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("approver key must be Ed25519")
        policy = json.loads(pol.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            raise ValueError("invalid policy")
        return key, policy
    except (OSError, ValueError, TypeError):
        raise HTTPException(503, "agent gate configuration invalid") from None


@router.post("/record", status_code=201)
def record(body: AgentRecord, principal: dict = Depends(require("entries:write"))):
    public, policy = _load_config()
    try:
        out = rf_agent_gate.authorize_and_record(body.token, public, policy,
                                                 body.event, body.agent, body.action, body.resource,
                                                 requester=principal["id"])
        return {**out, "api_principal": principal["id"],
                "note": "authorization intent recorded; external tool execution not attested"}
    except rf_agent_gate.GateDenied:
        raise HTTPException(403, "authorization denied") from None
    except (ValueError, OSError):
        raise HTTPException(503, "agent evidence gate unavailable") from None


@router.post("/revoke", status_code=201)
def revoke(body: AgentRevoke, principal: dict = Depends(require("admin:principals"))):
    _load_config()  # fail closed if approved signer / policy is removed
    try:
        return rf_agent_gate.revoke_nonce(body.nonce, f"{principal['id']}: {body.reason}")
    except rf_agent_gate.GateDenied:
        raise HTTPException(409, "nonce invalid or already used/revoked") from None
    except (ValueError, OSError):
        raise HTTPException(503, "agent evidence gate unavailable") from None


app.include_router(router)
