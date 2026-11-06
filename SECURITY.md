# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Latest release (`v0.3.x`) | Yes: security fixes are released as a new patch version |
| Older releases | No: upgrade to the latest release |

Every release can be verified independently, without trusting this
repository's owner: see [docs/EXTERNAL-VERIFICATION.md](docs/EXTERNAL-VERIFICATION.md).

## Reporting a vulnerability

If you find a real flaw in the hash-chain, anchor, or signature logic —
something that lets a tampered ledger or evidence bundle pass verification —
report it privately. Do not open a public issue.

Email: charlieloydrightsframes2027@gmail.com

Include:

- The specific claim being broken (e.g., "content-hash chain fails to detect X")
- A minimal reproduction, ideally a script like the attacks in
  `tools/rf_demo.py` or the tests in `tests/`
- Your assessment of severity
- Whether and when you intend to publish

## What happens next

1. Acknowledgement within 5 days.
2. An assessment (confirmed or not, and severity) within 14 days of the
   acknowledgement.
3. For a confirmed flaw, a fix released as soon as it is ready, with a
   regression test that proves the attack is now detected, and a GitHub
   security advisory crediting you unless you prefer otherwise.
4. Coordinated disclosure: please allow up to 90 days from your report, or
   the release of the fix if sooner, before publishing details.

This is a solo project, not a funded security team; the timelines above are
commitments, not marketing.

## Scope

In scope:

- `core/rf_core.py` and its verification logic
- `verifier/rf_verify.py` (independent evidence-bundle verifier)
- `tools/rf_export_evidence.py` (evidence-bundle exporter)
- Release verification: `tools/verify_release_external.sh`,
  `.github/workflows/provenance-gate.yml`, `.github/workflows/slsa-build-l3.yml`
- Release SBOM generation and verification: `tools/rf_release_sbom.py`
- The container image and its runtime hardening (`core/Dockerfile`,
  `core/docker-compose.yml`)
- Supply-chain policy enforcement: `tools/verify_supply_chain_policy.py`

Out of scope: the FastAPI wrapper's own web-framework security (report those
upstream to FastAPI/Starlette if not specific to this project), and the
personal Android/Termux deployment described in the README.
