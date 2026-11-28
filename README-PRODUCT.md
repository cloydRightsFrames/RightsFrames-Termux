# RightsFrames Agent Evidence Gate — RC2 (27 November 2026)

This is a tested **candidate** implementation, not a certification or a claimed world-first.

## Components

- `core/rf_agent_gate.py`: Ed25519 signed grants, policy digests, expiry, replay and revocation with atomic RightsFrames ledger writes.
- `core/rf_agent_service.py`: opt-in authenticated FastAPI endpoints (`/v1/agent/record`, `/v1/agent/revoke`).
- `core/rf_agent_sdk.py`: optional pre-execution guard for a trusted Python tool adapter with separately recorded observed outcome.
- `tools/rf_agent_sign.py`: offline signer for encrypted Ed25519 approval keys (human passphrase required).
- `tools/rf_agent_acceptance.py`: real HTTP/SQLite/receipt/adversarial test, loopback and temporary keys only.
- `tools/rf_product_validate.sh`: private Pydantic overlay matching Android compiled `pydantic-core 2.50.5`; hash-locked pure-Python install, never global package mutation.
- `tests/`: grant and SDK tests.
- `docs/`: threat model, deployment constraints, buyer acceptance criteria.

## Exact status

Eight pure grant tests, a mocked SDK smoke test, syntax checks, and shell parsing were run in the authoring environment. Prior nine grant/ledger tests were observed passing on the user's Android device. **The new RC2 full HTTP suite has not yet been run on that device.** It will report `FULL_HTTP_PASS` only after independent v4 receipt verification and forged-proof rejection.

The code does not execute arbitrary external agent tools or make a claim of independent witnessing. All production operation requires reviewed integration, privately controlled signing keys, and an approved deployment configuration.

## RC3 hardening amendments (2026-11-27)

- The acceptance HTTP worker now uses a constrained multiprocessing spawn with
  process-specific termination, avoiding the source-wide prohibited Popen primitive.
- The acceptance worker inherits only allowlisted runtime variables, not unrelated
  production Redis, GitHub or API tokens.
- The validator now creates a dedicated --system-site-packages Python virtual
  environment and installs hash-locked Pydantic 2.14.4 **inside that venv**.
  Fresh Python subprocesses removing PYTHONPATH still import that matching copy.
- No existing application, signing key, global Python package or service is modified.

Do not use this as a claim of independent audit or production certification.
