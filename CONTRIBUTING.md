# Contributing

Any change to core/rf_core.py touching hash-chain, anchor, or signature
logic must ship with a test proving it still catches tampering.

## Set up

Python 3.12, 3.13 or 3.14. Every install is hash-locked:

    python -m venv .venv && . .venv/bin/activate
    python -m pip install --require-hashes -r core/requirements.txt -r core/requirements-test.txt

## Before opening a pull request

    python -m pytest -q
    python -m pip install --require-hashes -r .github/scripts/requirements-lint.txt
    ruff check .
    python3 tools/verify_supply_chain_policy.py

`tools/verify_supply_chain_policy.py` is the same gate CI runs. It fails if
a workflow uses an action that is not pinned to a full commit SHA, runs
`pip install` without `--require-hashes`, has a job without
`timeout-minutes`, lacks top-level `permissions`, uses
`pull_request_target`, or drops one of the release controls (reproducible
builds, SLSA provenance, release SBOM).

## Dependencies

Edit the `.in` file, then regenerate the lock with the exact command in the
header of the `.txt` file. They are universal locks (every platform's
wheels), so the same file installs on Linux, Windows, macOS and Termux:

    uv pip compile core/requirements.in --universal --generate-hashes \
      --python-version 3.12 -o core/requirements.txt
    uv pip compile core/requirements-test.in --constraint core/requirements.txt \
      --universal --generate-hashes --python-version 3.12 -o core/requirements-test.txt

The CI tool locks live in `.github/scripts/requirements-*.in` and are
regenerated the same way. Prefer versions published at least 7 days ago,
matching the Dependabot cooldown (`uv pip compile --exclude-newer <date>`).
The Semgrep lock is in `.github/semgrep/`: Semgrep pins packages that
have published advisories, so its lock overrides them (`overrides.txt`),
is installed with `--no-deps`, and is kept out of the Dependabot-managed
`.github/scripts` tree (Dependabot also reads subdirectories there), so an
automated regeneration cannot drop the overrides or fail on them.

Every lock file (runtime, tests and CI tools) is audited by the
"Dependency audit (pip-audit)" job on every change and weekly.

## Workflows

- Pin every action to a full 40-character commit SHA and note the version in
  a comment.
- Give every job `timeout-minutes` and the narrowest `permissions` it needs;
  check out with `persist-credentials: false` unless the job must push.
- Keep the names of required checks unchanged; renaming a job blocks merges
  until the ruleset is updated.

## Review and merge

`main` requires two approvals, the last push approved by someone other than
its author, and every required check green and up to date. Merges are
squash-only. Releases are cut by pushing an annotated `v*` tag on a green
`main` commit; `provenance-gate.yml` does the rest.

## Commit messages

Conventional prefixes: `feat`, `fix`, `ci`, `build`, `chore`, `docs`,
`test`, `security`, with an optional scope, e.g. `ci(deps): ...`.
