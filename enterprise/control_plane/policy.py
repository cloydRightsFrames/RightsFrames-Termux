from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_POLICY = {
    "schema": "rf.policy.v1",
    "mode": "fail-closed",
    "required": {
        "clean_worktree": True,
        "immutable_actions": True,
        "pinned_dependencies": True,
        "tests_pass": True,
        "provenance_record": True,
    },
}

def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        return DEFAULT_POLICY.copy()

    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if data.get("schema") != "rf.policy.v1":
        raise ValueError("unsupported policy schema")

    if data.get("mode") != "fail-closed":
        raise ValueError("enterprise policy must be fail-closed")

    return data

def evaluate(policy: dict[str, Any], facts: dict[str, bool]) -> dict[str, Any]:
    failures = sorted(
        name
        for name, required in policy.get("required", {}).items()
        if required and facts.get(name) is not True
    )

    return {
        "schema": "rf.policy-result.v1",
        "mode": policy["mode"],
        "allowed": not failures,
        "failures": failures,
        "facts": {
            key: bool(value)
            for key, value in sorted(facts.items())
        },
    }
