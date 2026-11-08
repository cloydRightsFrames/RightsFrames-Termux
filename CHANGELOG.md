# Changelog

All notable changes to this project. Versions follow semantic versioning;
every release is an annotated tag built, reproduced and attested by
`.github/workflows/provenance-gate.yml`.

## Unreleased (v0.4.0)

### Added
- `rf.anchor.v4`: every hybrid (Ed25519 + ML-DSA-65) anchor now also signs an RFC 9162
  Merkle root over the entries it covers (`core/rf_merkle.py`), with its own ML-DSA
  context string. The core and the independent verifier recompute every root; after a
  v4 anchor, any v3 or v2 anchor is rejected as a downgrade. Existing v3 ledgers keep
  verifying and continue with v4.
- Single-entry inclusion receipts (`rf.receipt.v1`): prove one entry against a signed
  Merkle root in O(log n) hashes without disclosing any other entry. New
  `core/rf_receipt.py`, `tools/rf_export_receipt.py`, `rf_verify.py --receipt`, and
  `GET /v1/entries/{id}/receipt`. The exporter refuses to emit a receipt whose root or
  key identities do not match the anchor.
- Signing keys sealed at rest (`rf.sealed-key.v1`, `core/rf_keyseal.py`): Argon2id
  (RFC 9106, 64 MiB) or scrypt, AES-256-GCM, key role and KDF parameters bound as
  authenticated data, hostile parameters rejected before key derivation. Configured with
  `RF_KEY_PASSPHRASE_FILE` (owner-only file) or `RF_KEY_PASSPHRASE`;
  `RF_REQUIRE_SEALED_KEYS=1` refuses plaintext keys. `tools/rf_seal_keys.py` seals or
  re-keys both keys as one all-or-nothing step under the anchor lock, keeping key ids,
  anchors and pins valid. Opened keys are cached per process, so `/health` cannot be
  used to force repeated memory-hard key derivations.
- Demo: four receipt checks (14 expectations with ML-DSA-65).

### Fixed
- `core/merkle.py` and `core/evidence/merkle.py` paired an odd trailing node with a copy
  of itself, so `[a, b, c]` and `[a, b, c, c]` had the same root (CVE-2012-2459 class).
  Odd nodes are now carried up unchanged (the RFC 9162 tree shape) and proofs check
  their exact length.

## v0.3.0

### Added
- Release SBOM: every release publishes `RightsFrames-Termux-<tag>.cdx.json`, a
  CycloneDX 1.6 SBOM of the hash-locked runtime dependencies. It is generated twice
  and must be byte-identical, checked to list exactly the locked packages, versions
  and SHA-256 hashes, attested to the release artifact (predicate type
  `https://cyclonedx.org/bom`), recorded in `release-manifest.json`, and verified
  before publication, hourly by `continuous-release-integrity.yml`, and by
  `tools/verify_release_external.sh`. New tool: `tools/rf_release_sbom.py`.
- Container verification (`container.yml`): builds and starts the API with
  `docker compose` exactly as documented, proves it is healthy, non-root, read-only,
  capability-free and `no-new-privileges`, that writes require the API key, that
  the ledger survives a restart and that pip is absent; then scans the image with
  Trivy (fixed CRITICAL/HIGH vulnerabilities fail the build).
- Python 3.13 and 3.14 on Linux and Python 3.12 on macOS in CI, in addition to
  3.12 on Linux and Windows.
- Lint gate (`ruff`, correctness rules only) with a hash-locked ruff.
- Dependency audit: `pip-audit` (hash-locked) checks every requirements lock in the
  repository, runtime, tests and CI tools, on every change and weekly. OWASP
  Dependency-Check keeps scanning the product's runtime and test dependencies; the CI
  tool locks are left out of its scan copy (its pip analyzer cannot read their hashed
  multi-line format) and recorded in its evidence as audited by pip-audit.
- OpenSSF Scorecard workflow with a published badge.
- `CODEOWNERS`, pull request template and issue forms; `SECURITY.md` now states
  supported versions, response timelines and coordinated disclosure.

### Changed
- Supply-chain policy (`tools/verify_supply_chain_policy.py`) now enforces, for every
  workflow: actions pinned to full commit SHAs (local reusable workflows and docker
  digests allowed), `pip install` only with `--require-hashes`, top-level
  `permissions`, `timeout-minutes` on every job, plus the release SBOM controls. It
  takes `--root` and is covered by tests.
- Semgrep is installed from a hash-locked file; CodeQL uses the toolchain bundled
  with the pinned action instead of "latest"; every checkout drops its credentials.
- Docker image: Debian security updates are applied on top of the pinned base at
  build time (the first image scan found fixed HIGH vulnerabilities in apt and pcre2
  in the pinned base), and pip is removed after installing the locked runtime set;
  `docker-compose.yml` runs the service read-only, with all capabilities dropped and
  `no-new-privileges`.
- Dependabot: valid conventional commit prefixes, reviewers from `CODEOWNERS`, and
  weekly grouped updates for the CI tool locks.

### Fixed
- `python -m enterprise.control_plane.cli evaluate` reported `immutable_actions: false`
  for this repository because it rejected the local reusable workflow reference
  `./.github/workflows/slsa-build-l3.yml`. Local references and docker digests are now
  recognised as immutable; CI now runs `evaluate`, so a regression fails the build.
- Removed an unreachable expression in the control-plane `readiness` command that
  referenced an undefined name, and unused imports across the tools and tests.
- The Semgrep CLI lock carried mcp 1.29.0 (four advisories, fixed in 1.30.0) and
  opentelemetry-api 1.37.0 (CVE-2026-114603, fixed in 1.45.1), pinned by every Semgrep
  release. The lock now overrides them to fixed versions and is installed with
  `--no-deps`; the scan was re-verified with them.
- `verify_anchors` now compares each ledger entry with the anchor head it parsed
  instead of parsing the head, discarding it and reading it again.

## Earlier releases

v0.2.0, v0.1.3 and v0.1.2: see the
[GitHub Releases](https://github.com/cloydRightsFrames/RightsFrames-Termux/releases).
