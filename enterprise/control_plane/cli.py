"""RightsFrames enterprise control-plane CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from .audit import AuditLog
from .health import check, readiness
from .policy import evaluate, load_policy
from .provenance import git_identity
from tools.rf_release_sbom import parse_lock

_DEFAULT_POLICY = Path("enterprise/policy.json")
_DEFAULT_AUDIT = Path(".rightsframes-enterprise/audit.jsonl")
_COMMANDS = ("policy", "evaluate", "audit-verify", "readiness")
_HEX = frozenset("0123456789abcdefABCDEF")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=list(_COMMANDS))
    parser.add_argument("--policy", default=str(_DEFAULT_POLICY))
    parser.add_argument("--audit", default=str(_DEFAULT_AUDIT))
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
    res = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"],
                         capture_output=True, text=True, check=True)
    return not res.stdout.strip()


def _immutable_reference(value: str) -> bool:
    """True if one `uses:` value cannot change after it was reviewed.

    * ``owner/repo[/path]@<40-hex commit SHA>`` - an exact commit.
    * ``./path`` - a local action or reusable workflow; GitHub resolves it
      from the same commit as the calling workflow, so it is pinned by the
      commit being verified.
    * ``docker://image@sha256:<64 hex>`` - an exact image digest.

    Anything else (a branch, a tag, a short SHA, a docker tag) can move.
    """
    value = value.split("#", 1)[0].strip().strip("'\"")
    if value.startswith("./"):
        return len(value) > 2 and "@" not in value
    if value.startswith("docker://"):
        image, sep, digest = value.rpartition("@sha256:")
        return bool(sep) and len(image) > len("docker://") and len(digest) == 64 and all(
            c in _HEX for c in digest
        )
    action, sep, ref = value.partition("@")
    if not sep or not action or "@" in ref:
        return False
    return len(ref) == 40 and all(c in _HEX for c in ref)


def _workflow_actions_immutable() -> bool:
    """True only if every `uses:` in every workflow is immutable (see _immutable_reference)."""
    workflow_dir = Path(".github") / "workflows"
    if not workflow_dir.exists():
        return False
    try:
        files = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
        if not files:
            return False
        for wf in files:
            for line in wf.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("- "):
                    stripped = stripped[2:].strip()
                if not stripped.startswith("uses:"):
                    continue
                if not _immutable_reference(stripped.split("uses:", 1)[1]):
                    return False
        return True
    except Exception:
        return False


def _check_locks() -> dict:
    locks = {}
    for name in ("core/requirements.txt", "core/requirements-test.txt"):
        data = Path(name).read_bytes()
        packages = parse_lock(data.decode("utf-8"))
        locks[name] = {"packages": len(packages), "sha256": hashlib.sha256(data).hexdigest()}
    return locks


def _run_control_plane_tests() -> dict:
    root = Path(__file__).resolve().parents[2]
    if Path.cwd().resolve() != root:
        raise ValueError("run the enterprise gate from the RightsFrames checkout")
    name = "test_enterprise_control_plane.py"
    suite = unittest.TestLoader().discover(str(root / "tests"), pattern=name)
    result = unittest.TextTestRunner(stream=sys.stderr).run(suite)
    if (not result.testsRun or not result.wasSuccessful() or result.skipped
            or result.expectedFailures):
        raise ValueError(f"{name} did not complete with every test passing (ran {result.testsRun})")
    return {"suite": "tests/" + name, "passed": result.testsRun}


def _evaluate_facts(evidence: dict | None = None) -> dict:
    """Measure the checkout and attach local evidence for each policy fact."""
    if evidence is None:
        evidence = {}
    source = check("source_revision", git_identity)
    clean_before = check("clean_worktree", _git_clean)
    evidence["pinned_dependencies"] = check("pinned_dependencies", _check_locks)
    evidence["immutable_actions"] = check("immutable_actions", _workflow_actions_immutable)
    evidence["tests_pass"] = check("tests_pass", _run_control_plane_tests)
    end_source = check("source_revision", git_identity)
    if source != end_source:
        source = {"name": "source_revision", "status": "fail", "detail": "HEAD changed during the gate"}
    evidence["provenance_record"] = source
    evidence["clean_worktree"] = (check("clean_worktree", _git_clean)
                                 if clean_before["status"] == "pass" else clean_before)
    return {
        name: observation["status"] == "pass" for name, observation in evidence.items()
    }


def _evaluate(policy_path) -> int:
    try:
        evidence: dict = {}
        result = evaluate(load_policy(policy_path), _evaluate_facts(evidence))
        report = dict(result) if isinstance(result, dict) else {"allowed": result["allowed"]}
        report["evidence"] = evidence
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if result["allowed"] else 1
    except Exception as exc:
        print(json.dumps({"allowed": False, "evaluation_error": str(exc)}, sort_keys=True), file=sys.stdout)
        return 1


def _readiness(policy_path) -> int:
    try:
        result = readiness(
            {
                "git": lambda: subprocess.check_output(["git", "--version"], text=True).strip(),
                "python": lambda: sys.version.split()[0],
                "policy": lambda: load_policy(policy_path)["mode"],
            }
        )
        print(json.dumps(dict(result), sort_keys=True, indent=2, default=str))
        return 0 if result["ready"] else 1
    except Exception as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True), file=sys.stdout)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
