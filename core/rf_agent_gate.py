"""RightsFrames Agent Evidence Gate v0.1.

Explicitly approved agent decisions are committed atomically with single-use
nonces to the RightsFrames ledger. Never executes external tools. Integration:
call authorize_and_record() BEFORE the caller executes an independently
allowlisted operation, and fail closed on any error. Do not treat a recorded
intent as proof that an external operation was truthful or completed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOMAIN = b"rightsframes.agent.grant.v1\x00"
SCHEMA = "rf.agent.grant.v1"
NONCE = re.compile(r"[0-9a-f]{32}\Z")
LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}\Z")
KEYS = frozenset({"schema", "agent", "action", "resource", "policy_sha256", "event_sha256", "issued", "expires", "nonce", "signer_id"})
MAX_TTL = 300
MAX_SKEW = 30


class GateDenied(PermissionError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def public_identity(public: Ed25519PublicKey) -> str:
    return "ed25519:" + hashlib.sha256(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def _policy_allows(policy: Any, agent: str, action: str, resource: str) -> None:
    if not isinstance(policy, dict) or set(policy) != {"version", "rules"} or type(policy["version"]) is not int or policy["version"] != 1:
        raise GateDenied("invalid policy")
    rules = policy["rules"]
    if not isinstance(rules, list) or len(rules) > 10000:
        raise GateDenied("invalid policy rules")
    if not any(isinstance(r, dict) and set(r) == {"agent", "action", "resource"} and
               r["agent"] == agent and r["action"] == action and r["resource"] == resource
               for r in rules):
        raise GateDenied("policy denies requested action")


def issue(signer: Any, policy: dict, agent: str, action: str, resource: str, event: dict, ttl: int = 120,
          now: int | None = None) -> dict:
    for field in (agent, action, resource):
        if not isinstance(field, str) or not LABEL.fullmatch(field):
            raise ValueError("invalid agent/action/resource")
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise ValueError("invalid ttl")
    if not isinstance(event, dict) or len(_canonical(event)) > 262144:
        raise ValueError("invalid event")
    _policy_allows(policy, agent, action, resource)
    current = int(time.time()) if now is None else now
    import secrets
    body = {"schema": SCHEMA, "agent": agent, "action": action, "resource": resource,
            "policy_sha256": _hash(policy), "event_sha256": _hash(event),
            "issued": current, "expires": current + ttl, "nonce": secrets.token_hex(16),
            "signer_id": public_identity(signer.public_key())}
    signature = base64.b64encode(signer.sign(DOMAIN + _canonical(body))).decode("ascii")
    return {"grant": body, "signature": signature}


def verify(token: Any, trusted_public: Ed25519PublicKey, policy: dict, event: dict,
           agent: str, action: str, resource: str, now: int | None = None) -> dict:
    try:
        if not isinstance(token, dict) or set(token) != {"grant", "signature"}:
            raise GateDenied("invalid token shape")
        body = token["grant"]
        if not isinstance(body, dict) or set(body) != KEYS:
            raise GateDenied("invalid grant fields")
        if not isinstance(token["signature"], str) or len(token["signature"]) > 256:
            raise GateDenied("invalid signature encoding")
        sig = base64.b64decode(token["signature"], validate=True)
        trusted_public.verify(sig, DOMAIN + _canonical(body))
        if not all(isinstance(x, str) and LABEL.fullmatch(x) for x in (agent, action, resource)):
            raise GateDenied("invalid requested operation")
        if body["schema"] != SCHEMA or body["signer_id"] != public_identity(trusted_public):
            raise GateDenied("schema or signer mismatch")
        if not isinstance(body["nonce"], str) or not NONCE.fullmatch(body["nonce"]):
            raise GateDenied("invalid nonce")
        if any(body[k] != v for k, v in {"agent": agent, "action": action, "resource": resource,
                                           "policy_sha256": _hash(policy), "event_sha256": _hash(event)}.items()):
            raise GateDenied("scope, policy or event mismatch")
        if any(not isinstance(body[k], str) or not re.fullmatch(r"[0-9a-f]{64}", body[k]) for k in ("policy_sha256", "event_sha256")):
            raise GateDenied("invalid digest")
        issued, expires = body["issued"], body["expires"]
        current = int(time.time()) if now is None else now
        if type(issued) is not int or type(expires) is not int or type(current) is not int:
            raise GateDenied("invalid timestamp")
        if issued > current + MAX_SKEW or expires <= current or expires <= issued or expires - issued > MAX_TTL:
            raise GateDenied("expired, premature or overlong authorization")
        _policy_allows(policy, agent, action, resource)
        return dict(body)
    except (InvalidSignature, ValueError, TypeError, KeyError, binascii.Error, OverflowError) as exc:
        raise GateDenied("signature or grant invalid") from exc


def _init_nonce_table(conn: Any) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS rf_agent_gate_nonces
                 (nonce TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('used','revoked')),
                 grant_sha256 TEXT NOT NULL)""")


def authorize_and_record(token: dict, trusted_public: Ed25519PublicKey, policy: dict,
                         event: dict, agent: str, action: str, resource: str, now: int | None = None,
                         requester: str = "") -> dict:
    """Atomically reserve one grant nonce and record approved intent in the REAL ledger.

    This is pre-execution authorization evidence, not an external tool executor.
    """
    grant = verify(token, trusted_public, policy, event, agent, action, resource, now)
    from core import rf_core
    import sqlite3
    with rf_core.write_transaction() as conn:
        _init_nonce_table(conn)
        digest = _hash(grant)
        try:
            conn.execute("INSERT INTO rf_agent_gate_nonces(nonce,status,grant_sha256) VALUES (?,?,?)",
                         (grant["nonce"], "used", digest))
        except sqlite3.IntegrityError as exc:
            raise GateDenied("grant revoked or already used") from exc
        record = rf_core.append_entry_in(conn, "agent.authorization.accepted", {
            "agent": agent, "action": action, "resource": resource,
            "event_sha256": _hash(event), "policy_sha256": grant["policy_sha256"],
            "grant_sha256": digest, "signer_id": grant["signer_id"], "nonce": grant["nonce"],
            "requester": requester})
    return {"status": "authorized_recorded", "ledger_entry_id": record["id"],
            "entry_hash": record["entry_hash"], "receipt_pending_anchor": True}


def revoke_nonce(nonce: str, reason: str) -> dict:
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise GateDenied("invalid nonce")
    if not isinstance(reason, str) or not 1 <= len(reason) <= 160:
        raise GateDenied("reason required")
    from core import rf_core
    import sqlite3
    with rf_core.write_transaction() as conn:
        _init_nonce_table(conn)
        try:
            conn.execute("INSERT INTO rf_agent_gate_nonces(nonce,status,grant_sha256) VALUES (?,?,?)",
                         (nonce, "revoked", ""))
        except sqlite3.IntegrityError as exc:
            raise GateDenied("already used or revoked") from exc
        entry = rf_core.append_entry_in(conn, "agent.authorization.revoked", {"nonce": nonce, "reason": reason})
    return {"status": "revoked", "ledger_entry_id": entry["id"]}
