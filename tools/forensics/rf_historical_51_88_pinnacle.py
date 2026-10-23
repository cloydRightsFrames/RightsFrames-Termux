#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


REPO = Path.cwd()
ARTIFACTS = REPO / "artifacts" / "historical-51-88-pinnacle"
INVENTORY = ARTIFACTS / "commits.txt"
SUMMARY = ARTIFACTS / "summary.json"
ENVIRONMENT = ARTIFACTS / "environment.json"

START = 51
END = 88

ARTIFACTS.mkdir(parents=True, exist_ok=True)


def run(
    argv: list[str],
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> dict:
    started = time.monotonic()
    try:
        p = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "timeout": False,
            "seconds": round(time.monotonic() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timeout": True,
            "seconds": round(time.monotonic() - started, 3),
        }


def git(*args: str, cwd: Path = REPO, timeout: int = 30) -> dict:
    return run(["git", *args], cwd, timeout)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git_text(*args: str) -> str:
    result = git(*args)
    if result["returncode"] != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed\n"
            f"{result['stdout']}\n{result['stderr']}"
        )
    return result["stdout"]


def source_files(root: Path) -> list[str]:
    found = []
    for name in ("core", "enterprise", "provenance", "verifier"):
        path = root / name
        if path.is_dir():
            found.append(name)
    return found


def archive_commit(sha: str, destination: Path) -> None:
    archive = destination.with_suffix(".tar")
    result = subprocess.run(
        ["git", "archive", "--format=tar", sha],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git archive failed for {sha}\\n"
            f"{result.stderr.decode("utf-8", "replace")}"
        )

    archive.write_bytes(result.stdout)
    try:
        with tarfile.open(archive, "r") as tf:
            tf.extractall(destination, filter="data")
    finally:
        archive.unlink(missing_ok=True)

def compile_tree(root: Path, log: Path) -> tuple[str, dict]:
    result = run(
        [sys.executable, "-m", "compileall", "-q", "-f", "."],
        root,
        180,
    )
    log.write_text(
        "STDOUT\n"
        + result["stdout"]
        + "\nSTDERR\n"
        + result["stderr"],
        encoding="utf-8",
    )

    if result["timeout"]:
        return "TIMEOUT", result

    if result["returncode"] != 0:
        return "FAIL", result

    return "PASS", result


def pytest_environment(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    old_pythonpath = env.get("PYTHONPATH")
    if old_pythonpath:
        env["PYTHONPATH"] = str(root) + os.pathsep + old_pythonpath
    else:
        env["PYTHONPATH"] = str(root)

    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = env.get(
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "",
    )
    return env


def run_pytest(
    root: Path,
    args: list[str],
    timeout: int,
    log: Path,
) -> dict:
    env = pytest_environment(root)
    result = run(
        [sys.executable, "-m", "pytest", *args],
        root,
        timeout,
        env,
    )

    log.write_text(
        "COMMAND\n"
        + " ".join([sys.executable, "-m", "pytest", *args])
        + "\n\nSTDOUT\n"
        + result["stdout"]
        + "\nSTDERR\n"
        + result["stderr"],
        encoding="utf-8",
    )
    return result


def package_probe(root: Path, log: Path) -> dict:
    env = pytest_environment(root)

    code = (
        "import sys,platform\n"
        "print('PYTHON='+sys.version.replace(chr(10),' '))\n"
        "print('IMPLEMENTATION='+platform.python_implementation())\n"
        "mods=['pytest','pytest_cov','coverage','fastapi','starlette','cryptography','pydantic']\n"
        "import importlib.metadata as m\n"
        "for x in mods:\n"
        "    try: print(x+'='+m.version(x))\n"
        "    except Exception: print(x+'=NOT_INSTALLED')\n"
    )

    result = run(
        [sys.executable, "-c", code],
        root,
        30,
        env,
    )

    log.write_text(
        result["stdout"] + "\n" + result["stderr"],
        encoding="utf-8",
    )

    return result


def classify_pytest(result: dict) -> str:
    if result["timeout"]:
        return "TIMEOUT"
    if result["returncode"] == 0:
        return "PASS"
    if result["returncode"] == 5:
        return "NO_TESTS"
    if result["returncode"] == 2:
        return "COLLECTION_OR_USAGE_FAILURE"
    return "FAIL"


def collect_environment() -> dict:
    commands = {
        "git_version": ["git", "--version"],
        "python_version": [sys.executable, "--version"],
    }

    result = {
        "timestamp_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "repo": str(REPO),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "cwd": str(REPO),
        "commands": {},
    }

    for name, argv in commands.items():
        p = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        result["commands"][name] = {
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }

    packages = {}
    package_code = (
        "import importlib.metadata as m\n"
        "for x in sorted(m.packages_distributions()):\n"
        "    pass\n"
        "for x in ['pytest','pytest-cov','coverage','fastapi','starlette',"
        "'cryptography','pydantic','pydantic-core','httpx','anyio']:\n"
        "    try: print(x+'='+m.version(x))\n"
        "    except Exception: print(x+'=NOT_INSTALLED')\n"
    )

    p = subprocess.run(
        [sys.executable, "-c", package_code],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            packages[k] = v

    result["packages"] = packages
    return result


def main() -> int:
    if not (REPO / ".git").exists():
        print("FATAL=NOT_A_GIT_REPOSITORY")
        return 2

    status = git("status", "--porcelain")
    if status["returncode"] != 0:
        print("FATAL=GIT_STATUS_FAILED")
        return 2

    original_head = git_text("rev-parse", "HEAD").strip()
    original_branch = git_text(
        "symbolic-ref",
        "--quiet",
        "--short",
    ).strip() if git("symbolic-ref", "--quiet", "--short")["returncode"] == 0 else "DETACHED"

    commits = git_text(
        "rev-list",
        "--all",
        "--reverse",
    ).splitlines()

    if len(commits) != 88:
        print(f"FATAL=EXPECTED_88_REACHABLE_COMMITS_ACTUAL={len(commits)}")
        return 3

    selected = commits[START - 1:END]

    if len(selected) != 38:
        print(f"FATAL=EXPECTED_38_SELECTED_COMMITS_ACTUAL={len(selected)}")
        return 3

    known_51 = "8eb19de6233e40fbf271b1dbfd0d1f1104fd12ef"

    if selected[0] != known_51:
        print(
            "FATAL=HISTORICAL_51_MISMATCH"
            f"\nEXPECTED={known_51}"
            f"\nACTUAL={selected[0]}"
        )
        return 4

    INVENTORY.write_text(
        "\n".join(
            f"{i} {sha} "
            f"{git_text('show', '-s', '--format=%s', sha).strip()}"
            for i, sha in enumerate(selected, START)
        )
        + "\n",
        encoding="utf-8",
    )

    ENVIRONMENT.write_text(
        json.dumps(
            collect_environment(),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print("HISTORICAL_GRAPH=PASS")
    print("TOTAL_REACHABLE_COMMITS=88")
    print("VERIFYING_COMMITS=51-88")
    print("SELECTED_COMMITS=38")
    print(f"HEAD_PRESERVED={original_head}")
    print(f"BRANCH_PRESERVED={original_branch}")
    print()

    results = []

    for ordinal, sha in zip(range(START, END + 1), selected):
        subject = git_text(
            "show",
            "-s",
            "--format=%s",
            sha,
        ).strip()

        commit_dir = ARTIFACTS / f"{ordinal:03d}-{sha}"
        commit_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            prefix=f"rf-historical-{ordinal:03d}-",
            dir=ARTIFACTS,
        ) as tmp:
            root = Path(tmp) / "source"
            root.mkdir()

            started = time.monotonic()

            record = {
                "ordinal": ordinal,
                "sha": sha,
                "subject": subject,
                "started_epoch": time.time(),
                "syntax": "NOT_RUN",
                "collection": "NOT_RUN",
                "tests": "NOT_RUN",
                "coverage": "NOT_RUN",
                "overall": "FAIL",
                "environment": "CURRENT_TERMUX",
            }

            try:
                archive_commit(
                    sha,
                    root,
                )

                manifest = []
                for p in sorted(root.rglob("*")):
                    if p.is_file():
                        rel = p.relative_to(root).as_posix()
                        manifest.append(
                            {
                                "path": rel,
                                "sha256": sha256_file(p),
                                "size": p.stat().st_size,
                            }
                        )

                (commit_dir / "source-manifest.json").write_text(
                    json.dumps(
                        manifest,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )

                syntax_status, syntax_result = compile_tree(
                    root,
                    commit_dir / "syntax.log",
                )
                record["syntax"] = syntax_status

                if syntax_status != "PASS":
                    record["overall"] = "SOURCE_SYNTAX_FAILURE"
                    record["failure_class"] = "SOURCE_SYNTAX_FAILURE"
                    results.append(record)
                    print(
                        f"[{ordinal}/88] {sha[:12]} "
                        f"STATUS={record['overall']} "
                        f"SUBJECT={subject}"
                    )
                    continue

                package_probe(
                    root,
                    commit_dir / "environment.log",
                )

                tests_dir = root / "tests"
                if not tests_dir.is_dir():
                    record["collection"] = "NO_TEST_DIRECTORY"
                    record["tests"] = "NO_TEST_DIRECTORY"
                    record["overall"] = "NO_TEST_DIRECTORY"
                    record["failure_class"] = "NO_TEST_DIRECTORY"
                    results.append(record)
                    print(
                        f"[{ordinal}/88] {sha[:12]} "
                        f"STATUS={record['overall']} "
                        f"SUBJECT={subject}"
                    )
                    continue

                collect_result = run_pytest(
                    root,
                    [
                        "-q",
                        "--collect-only",
                        "tests",
                    ],
                    180,
                    commit_dir / "collection.log",
                )

                record["collection"] = classify_pytest(
                    collect_result
                )

                if record["collection"] != "PASS":
                    record["tests"] = "NOT_RUN"
                    record["overall"] = "COLLECTION_FAILURE"
                    record["failure_class"] = (
                        "TEST_COLLECTION_FAILURE"
                    )
                    results.append(record)
                    print(
                        f"[{ordinal}/88] {sha[:12]} "
                        f"STATUS={record['overall']} "
                        f"SUBJECT={subject}"
                    )
                    continue

                coverage_targets = source_files(root)

                pytest_args = [
                    "-q",
                    "tests",
                ]

                if coverage_targets:
                    pytest_args[0:0] = [
                        "--cov=" + target
                        for target in coverage_targets
                    ]
                    pytest_args[0:0] = [
                        "--cov-report=term-missing",
                        "--cov-report=json:coverage.json",
                    ]

                test_result = run_pytest(
                    root,
                    pytest_args,
                    600,
                    commit_dir / "pytest.log",
                )

                record["tests"] = classify_pytest(
                    test_result
                )

                coverage_path = root / "coverage.json"

                if coverage_path.exists():
                    try:
                        coverage_data = json.loads(
                            coverage_path.read_text(
                                encoding="utf-8"
                            )
                        )

                        totals = coverage_data.get(
                            "totals",
                            {},
                        )

                        record["coverage"] = {
                            "percent_covered": totals.get(
                                "percent_covered"
                            ),
                            "percent_covered_display": totals.get(
                                "percent_covered_display"
                            ),
                            "covered_lines": totals.get(
                                "covered_lines"
                            ),
                            "missing_lines": totals.get(
                                "missing_lines"
                            ),
                            "num_statements": totals.get(
                                "num_statements"
                            ),
                            "num_branches": totals.get(
                                "num_branches"
                            ),
                            "covered_branches": totals.get(
                                "covered_branches"
                            ),
                            "missing_branches": totals.get(
                                "missing_branches"
                            ),
                        }

                        shutil.copy2(
                            coverage_path,
                            commit_dir / "coverage.json",
                        )
                    except Exception as exc:
                        record["coverage"] = (
                            "COVERAGE_PARSE_FAILURE"
                            f":{type(exc).__name__}"
                        )
                else:
                    record["coverage"] = "NOT_GENERATED"

                if record["tests"] == "PASS":
                    record["overall"] = "PASS"
                    record["failure_class"] = "NONE"
                elif record["tests"] == "TIMEOUT":
                    record["overall"] = "TEST_TIMEOUT"
                    record["failure_class"] = "TEST_TIMEOUT"
                else:
                    record["overall"] = "TEST_EXECUTION_FAILURE"
                    record["failure_class"] = (
                        "TEST_EXECUTION_FAILURE"
                    )

            except Exception as exc:
                record["overall"] = "VERIFIER_FAILURE"
                record["failure_class"] = (
                    type(exc).__name__
                )
                record["exception"] = repr(exc)

            record["seconds"] = round(
                time.monotonic() - started,
                3,
            )

            (commit_dir / "result.json").write_text(
                json.dumps(
                    record,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            results.append(record)

            print(
                f"[{ordinal}/88] {sha[:12]} "
                f"STATUS={record['overall']} "
                f"SYNTAX={record['syntax']} "
                f"COLLECTION={record['collection']} "
                f"TESTS={record['tests']} "
                f"COVERAGE={record['coverage']} "
                f"SECONDS={record['seconds']} "
                f"SUBJECT={subject}"
            )

    passed = sum(
        r["overall"] == "PASS"
        for r in results
    )

    syntax_failures = sum(
        r["failure_class"] == "SOURCE_SYNTAX_FAILURE"
        for r in results
    )

    collection_failures = sum(
        r["failure_class"] == "TEST_COLLECTION_FAILURE"
        for r in results
    )

    test_failures = sum(
        r["failure_class"] == "TEST_EXECUTION_FAILURE"
        for r in results
    )

    timeouts = sum(
        r["failure_class"] == "TEST_TIMEOUT"
        for r in results
    )

    verifier_failures = sum(
        r["failure_class"] not in {
            "NONE",
            "SOURCE_SYNTAX_FAILURE",
            "TEST_COLLECTION_FAILURE",
            "TEST_EXECUTION_FAILURE",
            "TEST_TIMEOUT",
        }
        for r in results
    )

    final = {
        "graph": {
            "total_reachable_commits": 88,
            "start": START,
            "end": END,
            "selected": len(selected),
            "first_selected": selected[0],
            "last_selected": selected[-1],
        },
        "execution": {
            "results": len(results),
            "passed": passed,
            "syntax_failures": syntax_failures,
            "collection_failures": collection_failures,
            "test_failures": test_failures,
            "timeouts": timeouts,
            "verifier_failures": verifier_failures,
        },
        "working_tree": {
            "head_before": original_head,
            "branch_before": original_branch,
            "status_before": status["stdout"],
            "head_after": git_text(
                "rev-parse",
                "HEAD",
            ).strip(),
            "status_after": git(
                "status",
                "--porcelain",
            )["stdout"],
        },
        "results": results,
    }

    SUMMARY.write_text(
        json.dumps(
            final,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print("SUMMARY")
    print("=======")
    print(f"RESULTS={len(results)}")
    print(f"PASS={passed}")
    print(f"SOURCE_SYNTAX_FAILURE={syntax_failures}")
    print(f"TEST_COLLECTION_FAILURE={collection_failures}")
    print(f"TEST_EXECUTION_FAILURE={test_failures}")
    print(f"TEST_TIMEOUT={timeouts}")
    print(f"VERIFIER_FAILURE={verifier_failures}")
    print(f"SUMMARY={SUMMARY}")
    print(f"INVENTORY={INVENTORY}")
    print(f"HEAD_BEFORE={original_head}")
    print(
        "HEAD_AFTER="
        + final["working_tree"]["head_after"]
    )
    print(
        "WORKTREE_AFTER="
        + (
            "CLEAN"
            if not final["working_tree"]["status_after"]
            else "UNCHANGED_DIRTY_STATE"
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
