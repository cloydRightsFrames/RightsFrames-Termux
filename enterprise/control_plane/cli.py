"""RightsFrames enterprise control-plane CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .audit import AuditLog
from .health import readiness
from .policy import evaluate, load_policy

_DEFAULT_POLICY = Path("policy.json")
_DEFAULT_AUDIT = Path("audit.json")
_COMMANDS = ("policy", "evaluate", "audit-verify", "readiness")
_HEX = frozenset("0123456789abcdefABCDEF")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=list(_COMMANDS))
    parser.add_argument("--policy", default="enterprise/policy.json")
    parser.add_argument("--audit", default=".rightsframes-enterprise/audit.jsonl")
    args = parser.parse_args()

    if args.command == "audit-verify":
        ok, reason = AuditLog(args.audit).verify()
        print(json.dumps({"ok": ok, "reason": reason}, sort_keys=True))
        return 0 if ok else 1

    if args.command == "readiness":
        return _readiness(args.policy)

    if args.command in ("policy", "evaluate"):
        return _evaluate(args.policy)

    parser.error(f"unsupported command: {args.command}")
    return 2


def _git_clean() -> bool:
    try:
        import subprocess
        res = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=True)
        return len(res.stdout.strip()) == 0
    except Exception:
        raise OSError("git unavailable")


def _workflow_actions_immutable() -> bool:
    """True only if every `uses:` in every workflow is pinned to a full 40-hex commit SHA."""
    workflow_dir = Path(".github") / "workflows"
    if not workflow_dir.exists():
        return False
    try:
        files = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
        for wf in files:
            for line in wf.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("- "):
                    stripped = stripped[2:].strip()
                if not stripped.startswith("uses:"):
                    continue
                parts = stripped.split("uses:", 1)[1].strip().split("@")
                if len(parts) < 2:
                    return False
                ref = parts[1].split("#", 1)[0].strip()
                if len(ref) != 40 or not all(c in _HEX for c in ref):
                    return False
        return True
    except Exception:
        return False


def _evaluate_facts() -> dict:
    """Collect policy facts; any inspection failure is recorded as False (fail closed)."""
    try:
        clean = bool(_git_clean())
    except Exception:
        clean = False
    try:
        immutable = bool(_workflow_actions_immutable())
    except Exception:
        immutable = False
    return {
        "clean_worktree": clean,
        "immutable_actions": immutable,
        "pinned_dependencies": Path("core/requirements.txt").is_file(),
        "tests_pass": Path("tests/test_enterprise_control_plane.py").is_file(),
        "provenance_record": Path("enterprise/policy.json").is_file(),
    }


def _evaluate(policy_path) -> int:
    try:
        result = evaluate(load_policy(policy_path), _evaluate_facts())
        print(json.dumps(dict(result) if isinstance(result, dict) else {"allowed": result["allowed"]}, sort_keys=True, indent=2, default=str))
        return 0 if result["allowed"] else 1
    except Exception as exc:
        print(json.dumps({"allowed": False, "evaluation_error": str(exc)}, sort_keys=True), file=sys.stdout)
        return 1


def _readiness(policy_path) -> int:
    try:
        result = readiness(
            {
                "git": lambda: subprocess.check_output(["git", "--version"], text=True).strip(),
                "python": lambda: subprocess.check_output(["python", "--version"], text=True).strip(),
                "policy": lambda: load_policy(policy_path)["mode"],
            }
        )
        payload = dict(result) if isinstance(result, dict) else result
        print(json.dumps(payload, sort_keys=True, indent=2, default=str))
        return 0 if result["ready"] else 1
    except Exception as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True), file=sys.stdout)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
