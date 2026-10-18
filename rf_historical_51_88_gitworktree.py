#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path.cwd()
ARTIFACTS = REPO / "artifacts" / "historical-51-88-gitworktree"
INVENTORY = ARTIFACTS / "all-reachable-commits.txt"
SUMMARY = ARTIFACTS / "summary.json"

EXPECTED_TOTAL = 88
START_ORDINAL = 51
END_ORDINAL = 88


def run(command, cwd=REPO, timeout=300, env=None):
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timeout": False,
            "seconds": round(time.monotonic() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return {
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timeout": True,
            "seconds": round(time.monotonic() - started, 3),
        }


def fail(message):
    print(f"FATAL={message}")
    raise SystemExit(1)


def git(*args, cwd=REPO, timeout=300):
    return run(["git", *args], cwd=cwd, timeout=timeout)


def current_state():
    head = git("rev-parse", "HEAD")
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    return head["stdout"].strip(), branch["stdout"].strip() if branch["returncode"] == 0 else "DETACHED"


def pytest_environment(root):
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(root) + os.pathsep + existing
        if existing
        else str(root)
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def write_log(path, command, result):
    path.write_text(
        "COMMAND\n"
        + " ".join(command)
        + "\n\nSTDOUT\n"
        + result["stdout"]
        + "\nSTDERR\n"
        + result["stderr"],
        encoding="utf-8",
    )


def pytest(root, args, timeout, log):
    command = [sys.executable, "-m", "pytest", *args]
    result = run(
        command,
        cwd=root,
        timeout=timeout,
        env=pytest_environment(root),
    )
    write_log(log, command, result)
    return result


def compile_source(root, log):
    command = [
        sys.executable,
        "-m",
        "compileall",
        "-q",
        "-f",
        "core",
        "enterprise",
        "provenance",
        "verifier",
        "tests",
    ]
    result = run(
        command,
        cwd=root,
        timeout=120,
        env=pytest_environment(root),
    )
    write_log(log, command, result)
    return result


def package_probe(root, log):
    code = (
        "import sys,platform\n"
        "print('PYTHON='+sys.version.replace(chr(10),' '))\n"
        "print('IMPLEMENTATION='+platform.python_implementation())\n"
        "import importlib.metadata as m\n"
        "mods=['pytest','pytest-cov','coverage','fastapi','starlette','cryptography','pydantic']\n"
        "for x in mods:\n"
        "    try:\n"
        "        print(x+'='+m.version(x))\n"
        "    except Exception:\n"
        "        print(x+'=NOT_INSTALLED')\n"
    )
    command = [sys.executable, "-c", code]
    result = run(
        command,
        cwd=root,
        timeout=30,
        env=pytest_environment(root),
    )
    write_log(log, command, result)
    return result


def source_manifest(root, destination):
    command = [
        "git",
        "ls-files",
        "-z",
    ]
    result = run(command, cwd=root, timeout=30)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"])

    files = sorted(
        item
        for item in result["stdout"].split("\x00")
        if item
    )

    destination.write_text(
        json.dumps(
            {
                "tracked_file_count": len(files),
                "tracked_files": files,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def remove_worktree(path):
    if not path.exists():
        return

    result = git(
        "worktree",
        "remove",
        "--force",
        str(path),
        timeout=120,
    )

    if result["returncode"] != 0 and path.exists():
        shutil.rmtree(path)


def main():
    if not (REPO / ".git").exists():
        fail("NOT_A_GIT_REPOSITORY")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    original_head, original_branch = current_state()

    rev_list = git("rev-list", "--all", "--reverse", timeout=60)
    if rev_list["returncode"] != 0:
        fail("GIT_REV_LIST_FAILED")

    commits = [
        line.strip()
        for line in rev_list["stdout"].splitlines()
        if line.strip()
    ]

    INVENTORY.write_text(
        "\n".join(commits) + "\n",
        encoding="utf-8",
    )

    total = len(commits)

    print(f"HISTORICAL_GRAPH={'PASS' if total == EXPECTED_TOTAL else 'FAIL'}")
    print(f"TOTAL_REACHABLE_COMMITS={total}")
    print(f"VERIFYING_COMMITS={START_ORDINAL}-{END_ORDINAL}")

    if total != EXPECTED_TOTAL:
        fail(f"EXPECTED_88_REACHABLE_COMMITS_FOUND_{total}")

    selected = list(enumerate(commits, start=1))[START_ORDINAL - 1:END_ORDINAL]

    if len(selected) != 38:
        fail(f"EXPECTED_38_SELECTED_COMMITS_FOUND_{len(selected)}")

    if selected[0][1] != "8eb19de6233e40fbf271b1dbfd0d1f1104fd12ef":
        fail("ORDINAL_51_SHA_MISMATCH")

    if selected[-1][1] != "00cfd6ed62b97503b49e4e84f7378119cc929f51":
        fail("ORDINAL_88_SHA_MISMATCH")

    print(f"SELECTED_COMMITS={len(selected)}")
    print(f"HEAD_PRESERVED={original_head}")
    print(f"BRANCH_PRESERVED={original_branch}")

    results = []

    for ordinal, sha in selected:
        short_sha = sha[:12]
        name = f"{ordinal:03d}-{sha}"
        artifact = ARTIFACTS / name
        artifact.mkdir(parents=True, exist_ok=True)

        worktree = Path(
            tempfile.mkdtemp(
                prefix=f"rf-historical-{ordinal:03d}-",
                dir=ARTIFACTS,
            )
        )

        record = {
            "ordinal": ordinal,
            "sha": sha,
            "subject": "",
            "environment": "CURRENT_TERMUX_GIT_WORKTREE",
            "worktree": str(worktree),
            "syntax": "NOT_RUN",
            "collection": "NOT_RUN",
            "tests": "NOT_RUN",
            "coverage": {},
            "overall": "NOT_RUN",
            "failure_class": None,
            "seconds": 0,
        }

        started = time.monotonic()

        try:
            subject = git(
                "show",
                "-s",
                "--format=%s",
                sha,
                timeout=30,
            )
            if subject["returncode"] != 0:
                raise RuntimeError("SUBJECT_LOOKUP_FAILED")

            record["subject"] = subject["stdout"].strip()

            add = git(
                "worktree",
                "add",
                "--detach",
                str(worktree),
                sha,
                timeout=180,
            )

            if add["returncode"] != 0:
                record["failure_class"] = "WORKTREE_CREATION_FAILURE"
                record["overall"] = "WORKTREE_CREATION_FAILURE"
                (artifact / "worktree.log").write_text(
                    add["stdout"] + "\n" + add["stderr"],
                    encoding="utf-8",
                )
                results.append(record)
                print(
                    f"[{ordinal}/88] {short_sha} "
                    f"STATUS=WORKTREE_CREATION_FAILURE"
                )
                continue

            source_manifest(
                worktree,
                artifact / "source-manifest.json",
            )

            package_probe(
                worktree,
                artifact / "environment.log",
            )

            syntax = compile_source(
                worktree,
                artifact / "syntax.log",
            )

            if syntax["returncode"] != 0:
                record["syntax"] = "FAIL"
                record["overall"] = "SOURCE_SYNTAX_FAILURE"
                record["failure_class"] = "SOURCE_SYNTAX_FAILURE"
                results.append(record)
                print(
                    f"[{ordinal}/88] {short_sha} "
                    f"STATUS=SOURCE_SYNTAX_FAILURE"
                )
                continue

            record["syntax"] = "PASS"

            tests_dir = worktree / "tests"
            if not tests_dir.is_dir():
                record["collection"] = "FAIL"
                record["overall"] = "TEST_COLLECTION_FAILURE"
                record["failure_class"] = "TEST_DIRECTORY_MISSING"
                results.append(record)
                print(
                    f"[{ordinal}/88] {short_sha} "
                    f"STATUS=TEST_COLLECTION_FAILURE"
                )
                continue

            collect = pytest(
                worktree,
                [
                    "--collect-only",
                    "-q",
                    "tests",
                ],
                180,
                artifact / "collection.log",
            )

            if collect["returncode"] != 0:
                record["collection"] = "FAIL"
                record["overall"] = "TEST_COLLECTION_FAILURE"
                record["failure_class"] = "TEST_COLLECTION_FAILURE"
                results.append(record)
                print(
                    f"[{ordinal}/88] {short_sha} "
                    f"STATUS=TEST_COLLECTION_FAILURE"
                )
                continue

            record["collection"] = "PASS"

            pytest_args = [
                "-q",
                "--cov=core",
                "--cov=enterprise",
                "--cov=provenance",
                "--cov=verifier",
                "--cov-branch",
                "--cov-report=term-missing",
                "--cov-report=json:coverage.json",
                "tests",
            ]

            test_result = pytest(
                worktree,
                pytest_args,
                600,
                artifact / "pytest.log",
            )

            coverage_file = worktree / "coverage.json"

            if coverage_file.exists():
                coverage_data = json.loads(
                    coverage_file.read_text(encoding="utf-8")
                )

                total_coverage = coverage_data.get("totals", {})
                record["coverage"] = {
                    "percent": total_coverage.get("percent_covered"),
                    "statements": total_coverage.get("num_statements"),
                    "missing": total_coverage.get("missing_lines"),
                    "branches": total_coverage.get("num_branches"),
                    "covered_branches": total_coverage.get(
                        "covered_branches"
                    ),
                    "partial_branches": total_coverage.get(
                        "num_partial_branches"
                    ),
                }

                shutil.copy2(
                    coverage_file,
                    artifact / "coverage.json",
                )

            if test_result["timeout"]:
                record["tests"] = "TIMEOUT"
                record["overall"] = "TEST_TIMEOUT"
                record["failure_class"] = "TEST_TIMEOUT"

            elif test_result["returncode"] == 0:
                record["tests"] = "PASS"
                record["overall"] = "PASS"

            elif test_result["returncode"] == 5:
                record["tests"] = "NO_TESTS"
                record["overall"] = "TEST_EXECUTION_FAILURE"
                record["failure_class"] = "NO_TESTS"

            else:
                record["tests"] = "FAIL"
                record["overall"] = "TEST_EXECUTION_FAILURE"
                record["failure_class"] = "TEST_EXECUTION_FAILURE"

            record["seconds"] = round(
                time.monotonic() - started,
                3,
            )

            results.append(record)

            print(
                f"[{ordinal}/88] {short_sha} "
                f"STATUS={record['overall']} "
                f"TESTS={record['tests']} "
                f"COVERAGE={record['coverage'].get('percent', 'NOT_REPORTED')} "
                f"SYNTAX={record['syntax']} "
                f"COLLECTION={record['collection']}"
            )

        except Exception as exc:
            record["overall"] = "VERIFIER_FAILURE"
            record["failure_class"] = type(exc).__name__
            record["seconds"] = round(
                time.monotonic() - started,
                3,
            )

            (artifact / "verifier-error.log").write_text(
                f"{type(exc).__name__}: {exc}\n",
                encoding="utf-8",
            )

            results.append(record)

            print(
                f"[{ordinal}/88] {short_sha} "
                f"STATUS=VERIFIER_FAILURE "
                f"FAILURE={type(exc).__name__}"
            )

        finally:
            remove_worktree(worktree)

        (artifact / "result.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    final_head, final_branch = current_state()

    preservation = {
        "original_head": original_head,
        "final_head": final_head,
        "original_branch": original_branch,
        "final_branch": final_branch,
        "preserved": (
            original_head == final_head
            and original_branch == final_branch
        ),
    }

    summary = {
        "historical_graph": {
            "total_reachable_commits": total,
            "start_ordinal": START_ORDINAL,
            "end_ordinal": END_ORDINAL,
            "selected": len(selected),
        },
        "preservation": preservation,
        "results": results,
    }

    SUMMARY.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    counts = {}
    for result in results:
        key = result["overall"]
        counts[key] = counts.get(key, 0) + 1

    print("SUMMARY:")
    print(f"RESULTS={len(results)}")
    print(f"PASS={counts.get('PASS', 0)}")
    print(
        "SOURCE_SYNTAX_FAILURE="
        f"{counts.get('SOURCE_SYNTAX_FAILURE', 0)}"
    )
    print(
        "TEST_COLLECTION_FAILURE="
        f"{counts.get('TEST_COLLECTION_FAILURE', 0)}"
    )
    print(
        "TEST_EXECUTION_FAILURE="
        f"{counts.get('TEST_EXECUTION_FAILURE', 0)}"
    )
    print(f"TEST_TIMEOUT={counts.get('TEST_TIMEOUT', 0)}")
    print(f"VERIFIER_FAILURE={counts.get('VERIFIER_FAILURE', 0)}")
    print(f"HEAD_PRESERVED={preservation['preserved']}")
    print(f"ARTIFACTS={ARTIFACTS}")
    print(f"SUMMARY_FILE={SUMMARY}")

    if not preservation["preserved"]:
        raise SystemExit(2)

    if len(results) != 38:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
