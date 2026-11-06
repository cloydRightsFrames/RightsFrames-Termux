# RightsFrames

[![Verify Ledger Integrity](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/verify.yml)
[![Provenance Gate](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/provenance-gate.yml/badge.svg?branch=main)](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/provenance-gate.yml)
[![Container Verification](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/container.yml/badge.svg?branch=main)](https://github.com/cloydRightsFrames/RightsFrames-Termux/actions/workflows/container.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cloydRightsFrames/RightsFrames-Termux/badge)](https://scorecard.dev/viewer/?uri=github.com/cloydRightsFrames/RightsFrames-Termux)

A tamper-evident governance ledger. Every event is cryptographically
hash-chained, independently anchored against truncation, and signed against
forgery with a hybrid of Ed25519 and the post-quantum ML-DSA-65 (NIST FIPS 204)
— verifiable by any third party with Python and the `cryptography` package. The independent verifier
imports nothing from RightsFrames itself. No trust in the operator required
once an anchor hash is held outside the operator's infrastructure.

## Prove It Yourself (one command)

    python -m pip install --require-hashes -r core/requirements.txt
    python tools/rf_demo.py

The demo builds a fresh ledger, exports a signed evidence bundle, verifies it
with `verifier/rf_verify.py` in a separate isolated process, then forges it
five ways — each attacker recomputes every hash and manifest field it can
without the private key. Every forgery is rejected; a fully rewritten history
under an attacker key is reported only as `internal_only` until checked
against the operator's pinned anchor, where it fails. Two post-quantum attacks
follow: a forger holding the operator's Ed25519 key (as a quantum computer
could recover it) re-signs rewritten history, and a downgrade strips the
ML-DSA-65 signatures; both are rejected without any anchor pin. Exit status 0
means every expectation held. See [docs/EVALUATION.md](docs/EVALUATION.md) for the
threat model, verification paths, and known limitations.

## AI-Assisted Development — Disclosure

This project was built through extensive AI-assisted development. Every
security claim below was independently adversarially tested — not just
described — with the test scripts included in this repo.

## How It Works

| Layer | Protects Against | Verified By |
|---|---|---|
| Content-hash chain | Editing a past entry | verify_chain() |
| Anchor chain | Truncating/deleting recent history | verify_anchors() |
| Ed25519 signatures | Forgery, even with full database access | Signature check against a public key only |
| ML-DSA-65 co-signature (`rf.anchor.v3`) | Forgery by an attacker who can break or steal Ed25519 | Both signatures must verify; downgrade is rejected |

## Quick Start (API in Docker)

    cd core
    RF_API_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
        docker compose up --build
    curl http://127.0.0.1:8000/health

The compose file builds from the repository root (the API needs `core/` and
`tools/rf_export_evidence.py`) and publishes the port on 127.0.0.1 only.
Writes require `X-API-Key: $RF_API_KEY`. The container runs as a non-root
user with a read-only root filesystem, no Linux capabilities and
`no-new-privileges`; the ledger and keys live in the `rf_data` volume. The
image applies Debian security updates at build time and ships without pip.

Supported Python versions: 3.12, 3.13 and 3.14 (tested in CI on Linux,
plus 3.12 on Windows and macOS).

## Engineering Assurance

Every change to `main` needs two approvals (the last push approved by
someone other than its author) and these checks, all enforced in CI:

| Control | Where |
|---|---|
| Full test suite on Linux and Windows (Python 3.12), plus Python 3.13 and 3.14 on Linux and 3.12 on macOS | `verify.yml` |
| Lint gate for correctness (pyflakes rules, syntax errors) | `verify.yml`, `ruff.toml` |
| CodeQL, Semgrep, OWASP Dependency-Check, pip-audit of every lock file (runtime, tests, CI tools), Trivy filesystem scan, TruffleHog and GitGuardian secret scanning | `codeql-advanced.yml` |
| Container built as documented, run read-only, non-root, with no Linux capabilities, auth and restart durability tested, image scanned by Trivy | `container.yml` |
| Supply-chain policy as code: every action pinned to a commit SHA, every `pip install` hash-locked, least-privilege `permissions`, a timeout on every job, no `pull_request_target`, release controls present | `tools/verify_supply_chain_policy.py` |
| Release: annotated tag, two independent builds that must match byte for byte, SLSA Build L3 provenance, a reproducible CycloneDX SBOM attested to the release artifact, and an hourly re-verification of the latest release | `provenance-gate.yml`, `continuous-release-integrity.yml` |
| OpenSSF Scorecard published weekly | `scorecard.yml` |

Every dependency, including the CI tools, is installed from a hash-locked
file, and Dependabot waits 7 days after a release before proposing it.

### Verify a release yourself

    git clone https://github.com/cloydRightsFrames/RightsFrames-Termux.git
    cd RightsFrames-Termux
    bash tools/verify_release_external.sh v0.3.0

It checks the checksums, the tag, an exact rebuild from public source, the
SLSA provenance, and (from v0.3.0) that the published SBOM lists exactly
the hash-locked runtime dependencies and is the one signed for the release.
See [docs/EXTERNAL-VERIFICATION.md](docs/EXTERNAL-VERIFICATION.md).

## What's Intentionally Not Here

The full production deployment (IDS, threat-intel feeds, automated backup
verification, self-healing process supervision) runs as a personal
Android/Termux stack and is not included here.

## Termux Node: Self-Healing Installer

`termux/rf-pinnacle.sh` hardens the Android/Termux node in one idempotent run:
waits out PostgreSQL crash recovery (and clears a provably stale
`postmaster.pid`), installs the `rf-watchdog` and `rf-wifi-watch` runit
services, supervises Threat Intel / Aletheia with crash-loop backoff, and
diagnoses whole-stack restarts (Android phantom-process killer, memory
pressure). Every change is backed up; `--dry-run` shows them first.

    cd ~/RightsFrames-Termux && git pull
    bash termux/rf-pinnacle.sh --dry-run   # preview
    bash termux/rf-pinnacle.sh             # apply
    bash termux/rf-pinnacle.sh status      # live watchdog view

## Honest Limitations

This proves the ledger's integrity, not the security of whatever system
writes to it. Local anchoring resists a database-only attacker. An attacker
who holds the operator's signing keys can rewrite history consistently; only
anchor hashes pinned outside the operator's infrastructure (`pins/`,
`--pin-anchor`) detect that. Entries written after the newest anchor are not
covered by any signature until the next anchor. No third-party security
audit has been performed yet.

## License

MIT — see LICENSE.

## Contact

Charlie Loyd — charlieloydrightsframes2027@gmail.com
