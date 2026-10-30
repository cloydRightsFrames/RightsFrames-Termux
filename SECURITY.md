# Security Policy

## Reporting a Vulnerability

If you find a real flaw in the hash-chain, anchor, or signature logic —
something that lets a tampered ledger or evidence bundle pass verification —
please report it privately before opening a public issue:

charlieloydrightsframes2027@gmail.com

Include:

- The specific claim being broken (e.g., "content-hash chain fails to detect X")
- A minimal reproduction, ideally a script like the attacks in
  `tools/rf_demo.py` or the tests in `tests/`
- Your assessment of severity

## Scope

In scope:

- `core/rf_core.py` and its verification logic
- `verifier/rf_verify.py` (independent evidence-bundle verifier)
- `tools/rf_export_evidence.py` (evidence-bundle exporter)
- Release verification: `tools/verify_release_external.sh`, `.github/workflows/slsa-build-l3.yml`

Out of scope: the FastAPI wrapper's own web-framework security (report those
upstream to FastAPI/Starlette if not specific to this project).

## Response

I'll acknowledge real reports within a few days. This is a solo project, not
a funded security team — response time reflects that honestly.
