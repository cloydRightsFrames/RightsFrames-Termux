"""Opt-in, fail-closed Python adapter for a caller-controlled tool/action.

An agent integration MUST call this before the actual tool call and must not offer
an alternative path around it. The adapter cannot sandbox arbitrary code or
prevent another process from bypassing it. Actual operations and evidence DB
commits cannot form one distributed transaction.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, TypeVar

from . import rf_agent_gate

T = TypeVar("T")


class EvidencePersistenceError(RuntimeError):
    """The callback may already have run, but the outcome could not be committed."""


def _digest(value: Any) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True,
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > 262144:
        raise ValueError("result summary too large")
    return hashlib.sha256(raw).hexdigest()


def run_guarded(*, grant: dict, approver_public: Any, policy: dict,
                agent: str, action: str, resource: str, intent: dict,
                callback: Callable[[], T], result_summary: Callable[[T], dict],
                requester: str = "") -> tuple[T, dict]:
    """Authorize and record the intent before invoking a concrete allowlisted callback.

    The callback is invoked at most once in this process. A nonce is durably
    consumed before callback invocation. A failing callback is recorded as
    an observed error type without disclosing exception messages/arguments.
    Successful results store a digest of a JSON summary, not raw outputs.
    """
    if not callable(callback) or not callable(result_summary):
        raise TypeError("callback and result_summary must be callable")
    # Refuse invalid local contracts *before* consuming a grant.
    if not isinstance(intent, dict):
        raise TypeError("intent must be a JSON object")
    from . import rf_core
    authorization = rf_agent_gate.authorize_and_record(
        grant, approver_public, policy, intent, agent, action, resource,
        requester=requester)
    start = time.monotonic_ns()
    try:
        result = callback()
    except Exception as exc:
        record = {
            "authorization_entry_id": authorization["ledger_entry_id"],
            "agent": agent, "action": action, "resource": resource,
            "outcome": "raised", "error_type": type(exc).__name__,
            "duration_ms": min(86400000, max(0, (time.monotonic_ns()-start)//1000000))}
        try:
            rf_core.append_entry("agent.execution.observed", record)
        except Exception as write_err:
            raise EvidencePersistenceError(
                "callback raised and failure evidence could not be persisted") from write_err
        raise
    try:
        summary = result_summary(result)
        if not isinstance(summary, dict):
            raise ValueError("result_summary must return a dict")
        proof = _digest(summary)
        record = {
            "authorization_entry_id": authorization["ledger_entry_id"],
            "agent": agent, "action": action, "resource": resource,
            "outcome": "returned", "result_summary_sha256": proof,
            "duration_ms": min(86400000, max(0, (time.monotonic_ns()-start)//1000000))}
        recorded = rf_core.append_entry("agent.execution.observed", record)
    except Exception as exc:
        raise EvidencePersistenceError(
            "callback returned but result evidence could not be persisted") from exc
    return result, {"authorization": authorization,
                    "observed_result_entry_id": recorded["id"],
                    "observed_result_entry_hash": recorded["entry_hash"],
                    "result_summary_sha256": proof}
