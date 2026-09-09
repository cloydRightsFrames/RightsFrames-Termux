Security Policy
Reporting a Vulnerability
If you find a real flaw in the hash-chain, anchor, or signature logic —
something that lets a tampered ledger pass verification — please report
it privately before opening a public issue:
CharlieLoyd@RightsFrames.onmicrosoft.com
Include:
The specific claim being broken (e.g., "content-hash chain fails to
detect X")
A minimal reproduction, ideally as a script similar to the ones in
core/tests/
Your assessment of severity
Scope
In scope: core/rf_core.py and its verification logic.
Out of scope: the FastAPI wrapper's own web-framework security (report
those upstream to FastAPI/Starlette if not specific to this project).
Response
I'll acknowledge real reports within a few days. This is a solo project,
not a funded security team — response time reflects that honestly.
