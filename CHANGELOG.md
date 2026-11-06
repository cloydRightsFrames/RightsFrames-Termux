# Changelog

All notable changes to this project. Versions follow semantic versioning;
every release is an annotated tag built, reproduced and attested by
`.github/workflows/provenance-gate.yml`.

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
  capability-free and `no-new-privileges`, that writes require the API key, and that
  the ledger survives a restart; then scans the image with Trivy (CRITICAL/HIGH,
  fixed vulnerabilities fail the build).
- Python 3.13 and 3.14 on Linux and Python 3.12 on macOS in CI, in addition to
  3.12 on Linux and Windows.
- Lint gate (`ruff`, correctness rules only) with a hash-locked ruff.
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
- Docker image: pip is removed after installing the locked runtime set;
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

## Earlier releases

v0.2.0, v0.1.3 and v0.1.2: see the
[GitHub Releases](https://github.com/cloydRightsFrames/RightsFrames-Termux/releases).
