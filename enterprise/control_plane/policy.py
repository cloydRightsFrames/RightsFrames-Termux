from __future__ import annotations

import json
from copy import deepcopy
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

def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data, dict) or data.get("schema") != "rf.policy.v1":
        raise ValueError("unsupported policy schema")

    if data.get("mode") != "fail-closed":
        raise ValueError("enterprise policy must be fail-closed")

    required = data.get("required")
    if (not isinstance(required, dict) or not any(required.values())
            or not all(isinstance(value, bool) for value in required.values())):
        raise ValueError("policy.required must contain boolean controls and enable at least one")


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    data = deepcopy(DEFAULT_POLICY) if path is None else json.loads(Path(path).read_text(encoding="utf-8"))
    _validate(data)
    return data

def evaluate(policy: dict[str, Any], facts: dict[str, bool]) -> dict[str, Any]:
    _validate(policy)
    failures = sorted(
        name
        for name, required in policy["required"].items()
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
