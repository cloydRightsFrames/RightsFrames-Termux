#!/usr/bin/env python3
"""Fail-closed staged secret scanner using Gitleaks."""
import shutil
import subprocess
import sys

def main():
    if sys.argv[1:] != ["--staged"]:
        print("rf-secret-scan: expected --staged", file=sys.stderr)
        return 2
    executable = shutil.which("gitleaks")
    if executable is None:
        print("rf-secret-scan: gitleaks missing; refusing commit", file=sys.stderr)
        return 2
    try:
        return subprocess.run([executable, "git", "--staged", "--no-banner", "--redact=100"], check=False).returncode
    except OSError as exc:
        print(f"rf-secret-scan: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
