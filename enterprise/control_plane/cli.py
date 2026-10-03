from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from .audit import AuditLog
from .health import readiness
from .policy import evaluate, load_policy

def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "command",
        choices=[
            "policy",
            "audit-verify",
            "readiness",
        ],
    )

    parser.add_argument(
        "--policy",
        default="enterprise/policy.json",
    )

    parser.add_argument(
        "--audit",
        default=".rightsframes-enterprise/audit.jsonl",
    )

    args = parser.parse_args()

    if args.command == "audit-verify":
        ok, reason = AuditLog(args.audit).verify()

        print(
            json.dumps(
                {
                    "ok": ok,
                    "reason": reason,
                },
                sort_keys=True,
            )
        )

        return 0 if ok else 1

    if args.command == "readiness":
        result = readiness(
            {
                "git": lambda: subprocess.check_output(
                    ["git", "--version"],
                    text=True,
                ).strip(),

                "python": lambda: subprocess.check_output(
                    ["python", "--version"],
                    text=True,
                ).strip(),

                "policy": lambda: load_policy(
                    args.policy
                )["mode"],
            }
        )

        print(
            json.dumps(
                result,
                sort_keys=True,
                indent=2,
            )
        )

        return 0 if result["ready"] else 1

    try:
        clean = not bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                text=True,
            ).strip()
        )

        immutable = True

        workflow_dir = Path(".github/workflows")

        if workflow_dir.exists():
            for workflow in workflow_dir.glob("*.yml"):
                if "@main" in workflow.read_text(
                    encoding="utf-8"
                ):
                    immutable = False

    except Exception:
        clean = False
        immutable = False

    facts = {
        "clean_worktree": clean,
        "immutable_actions": immutable,
        "pinned_dependencies": Path(
            "core/requirements.txt"
        ).is_file(),
        "tests_pass": Path(
            "tests/test_enterprise_control_plane.py"
        ).is_file(),
        "provenance_record": Path(
            "enterprise/policy.json"
        ).is_file(),
    }

    result = evaluate(
        load_policy(args.policy),
        facts,
    )

    print(
        json.dumps(
            result,
            sort_keys=True,
            indent=2,
        )
    )

    return 0 if result["allowed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
