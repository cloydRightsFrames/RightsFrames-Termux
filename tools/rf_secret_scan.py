"""Blocks committing secrets. Findings report file:line:rule only, never the secret itself."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

PATTERNS = (
    ("rightsframes-api-token", re.compile(r"rfp1\.[a-z0-9][a-z0-9-]{2,39}\.[A-Za-z0-9_-]{43}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
MAX_BYTES = 2097152


def scan_text(text: str) -> list[tuple[int, str]]:
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((number, name))
    return findings


def _git_z(args: list[str]) -> list[str]:
    out = subprocess.run(["git", *args], capture_output=True, check=True).stdout
    return [os.fsdecode(p) for p in out.split(b"\0") if p]


def _scan_blob(path: str, data: bytes) -> list[str]:
    if len(data) > MAX_BYTES:
        return [f"{path}:1: file-too-large-to-scan"]
    if b"\0" in data:
        return []
    return [f"{path}:{line}: {rule}" for line, rule in scan_text(data.decode("utf-8", errors="replace"))]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan staged or tracked working-tree files for common secret patterns.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--staged", action="store_true")
    group.add_argument("--all", action="store_true", help="scan tracked working-tree files; does not scan Git history")
    args = parser.parse_args(argv)
    findings = []
    if args.staged:
        for path in _git_z(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"]):
            blob = subprocess.run(["git", "show", f":{path}"], capture_output=True)
            if blob.returncode != 0:
                raise RuntimeError(f"Unable to read staged blob for {path}; refusing to pass scan")
            findings += _scan_blob(path, blob.stdout)
    else:
        for path in _git_z(["ls-files", "-z"]):
            try:
                with open(path, "rb") as handle:
                    findings += _scan_blob(path, handle.read(MAX_BYTES + 1))
            except OSError as exc:
                findings.append(f"{path}:1: scan-read-error-{type(exc).__name__}")
    if findings:
        print("SECRET SCAN FAILED:", file=sys.stderr)
        for item in findings:
            print("  " + item, file=sys.stderr)
        print("Remove the secret (and rotate it if it was ever real).", file=sys.stderr)
        return 1
    print("secret scan clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
