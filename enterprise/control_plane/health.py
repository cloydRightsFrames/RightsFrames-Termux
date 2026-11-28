from __future__ import annotations

from typing import Any, Callable

def check(name: str, probe: Callable[[], Any]) -> dict[str, Any]:
    try:
        detail = probe()
        return {
            "name": name,
            "status": "fail" if detail is False or detail is None else "pass",
            "detail": detail,
        }
    except Exception as exc:
        return {
            "name": name,
            "status": "fail",
            "detail": str(exc),
        }

def readiness(probes: dict[str, Callable[[], Any]]) -> dict[str, Any]:
    checks = [
        check(name, probe)
        for name, probe in sorted(probes.items())
    ]

    return {
        "schema": "rf.readiness.v1",
        "ready": bool(checks) and all(item["status"] == "pass" for item in checks),
        "checks": checks,
    }
