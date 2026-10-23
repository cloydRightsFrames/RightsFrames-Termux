# Security Policy

## Reporting a vulnerability

Report flaws privately before opening a public issue:
CharlieLoyd@RightsFrames.onmicrosoft.com (or GitHub private vulnerability reporting, if enabled
on the repository).

Please include:

- the specific guarantee broken (for example: "a truncated ledger verifies as anchor_pinned"
  or "a bundle signed by an unpinned key is accepted");
- a minimal reproduction, ideally a pytest case in the style of
  `tests/test_adversarial_evidence.py`;
- your severity assessment.

## Scope

In scope:

- `core/rf_core.py` — hash chain, anchors, verification
- `core/evidence/` — canonical JSON, Merkle trees, signatures, checkpoints
- `verifier/rf_verify.py`, `verifier/evidence_verifier.py` — independent verifiers
- `core/rf_auth.py`, `core/rf_api_v1.py`, `core/app.py` — authentication, scopes, audit trail
- `tools/rf_export_evidence.py`, `tools/rf_pin_anchor.py`, `tools/rf_principal.py`
- release provenance workflows under `.github/workflows/`

Out of scope: vulnerabilities in FastAPI, Starlette, uvicorn or `cryptography` themselves
(report upstream), and denial of service requiring local filesystem access.

## Security model in one paragraph

Verification never trusts the operator. A bundle that is merely self-consistent proves
nothing about history; guarantees start at an off-box pin (anchor hash or key id) held by the
relying party. Verification code paths are read-only: they never create keys or modify data.

## Response

This is a small project, not a funded security team. Real reports are acknowledged within a
few days; fixes for verification bypasses take priority over everything else.
