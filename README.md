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
ML-DSA-65 signatures; both are rejected without any anchor pin. Four
single-entry receipt checks close the run: an honest receipt verifies, and an
edited entry, a quantum-forged receipt and an attacker ledger's receipt are
rejected. Exit status 0 means every expectation held. See [docs/EVALUATION.md](docs/EVALUATION.md) for the
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
| ML-DSA-65 co-signature (`rf.anchor.v3`, `rf.anchor.v4`) | Forgery by an attacker who can break or steal Ed25519 | Both signatures must verify; downgrade is rejected |
| RFC 9162 Merkle root in every hybrid anchor (`rf.anchor.v4`) | Proving one entry without exposing the others | O(log n) inclusion receipt, `rf_verify.py --receipt` |
| Signing keys sealed at rest (`rf.sealed-key.v1`) | Key theft from disks, backups and copies of the data directory | Argon2id/scrypt + AES-256-GCM; `RF_REQUIRE_SEALED_KEYS=1` fails closed |

## Prove One Entry, Disclose Nothing Else

Every hybrid anchor signs an RFC 9162 Merkle root over the entries it covers.
A receipt carries one entry, its inclusion path (about log2(n) hashes), the
signed anchor and the public keys, so a single record can be handed to an
auditor, court or counterparty without revealing any other record:

    python tools/rf_export_receipt.py --data-dir /data --entry-id 42 --out receipt-42.json
    python verifier/rf_verify.py receipt-42.json --receipt --pin-anchor SEQ:HASH

The API serves the same receipt at `GET /v1/entries/{id}/receipt` (scope
`ledger:read`). The verifier rejects any edit to the entry, the path, the root or
either signature; a receipt re-signed with a stolen Ed25519 key fails the
ML-DSA-65 check, and one forged with both keys fails against the pinned anchor.

## Signing Keys Sealed at Rest

Point `RF_KEY_PASSPHRASE_FILE` at an owner-only file (at least 16 characters).
New keys are then written sealed: Argon2id (RFC 9106: t=3, p=4, 64 MiB; scrypt
N=2^17 where the OpenSSL build lacks Argon2id) and AES-256-GCM, with the key role
and every KDF parameter bound as authenticated data. Existing keys are sealed in
place without changing their identity, so anchors and pins stay valid:

    RF_KEY_PASSPHRASE_FILE=/run/secrets/rf_key_passphrase \
        python tools/rf_seal_keys.py --data-dir /data
    python tools/rf_seal_keys.py --data-dir /data --status

Set `RF_REQUIRE_SEALED_KEYS=1` to refuse plaintext keys. Sealing protects keys
at rest, not against an attacker who can read the running process's memory.

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

## Termux Node: Safe Pull and Sync

`termux/rf-sync.sh` updates the node's checkout from GitHub `main` and re-syncs what
depends on it. It only fast-forwards, refuses a remote other than this repository or
rewritten history, keeps uncommitted edits (re-applied after the update, or the
checkout is rolled back exactly if they conflict), retries flaky fetches, takes the
Termux wake lock and leaves it held for the stack (`RF_SYNC_RELEASE_WAKE_LOCK=1`
releases it afterwards), and will not start below 10% battery while discharging. After updating it
reinstalls the hash-locked dependencies when they changed, byte-compiles the code,
checks the anchor log for a torn write and verifies the ledger in `RF_DATA_DIR`, and
restarts any runit services you name.

    bash ~/RightsFrames-Termux/termux/rf-sync.sh --install   # once: adds the rf-sync command
    rf-sync --dry-run                                         # incoming commits, no changes
    rf-sync                                                   # pull and sync
    RF_DATA_DIR=~/rightsframes-data rf-sync --restart rf-api  # also verify ledger, restart a service
    rf-sync status

Exit codes: 0 synced, 2 local edits conflict (rolled back), 3 histories diverged,
4 code updated but post-sync verification needs attention, 1 any other error.

## Honest Limitations

This proves the ledger's integrity, not the security of whatever system
writes to it. Local anchoring resists a database-only attacker. An attacker
who holds the operator's signing keys (and, for sealed keys, the passphrase)
can rewrite history consistently; only
anchor hashes pinned outside the operator's infrastructure (`pins/`,
`--pin-anchor`) detect that. Entries written after the newest anchor are not
covered by any signature until the next anchor. No third-party security
audit has been performed yet; [docs/INDEPENDENT-REVIEW-SCOPE.md](docs/INDEPENDENT-REVIEW-SCOPE.md)
is the statement of work for one.

## License

MIT — see LICENSE.

## Contact

Charlie Loyd — charlieloydrightsframes2027@gmail.com
