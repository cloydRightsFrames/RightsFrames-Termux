# Changelog

## Unreleased — evidence hardening

Security fixes (each has a regression test in `tests/test_adversarial_evidence.py` or
`tests/test_api_hardening.py`):

- Merkle trees (`core/evidence/merkle.py`, `core/merkle.py`) duplicated the last node of odd
  levels, so `[a, b, c]` and `[a, b, c, c]` shared a root. Replaced with the RFC 9162
  construction (verified against RFC 6962 reference roots); added consistency proofs and
  signed checkpoints (`rf.merkle.checkpoint.v2`). Release manifests move to
  `rightsframes.manifest.v2`; v1 manifests still verify.
- `verifier/evidence_verifier.py` accepted the public key and Merkle root supplied inside the
  file being verified, so an attacker-made signature or proof printed PASS. Trust now comes
  only from `--trusted-key`, `--trusted-key-id`, `--trusted-root` or a pinned checkpoint.
- Canonical JSON silently coerced non-string keys (`{1: x}` hashed like `{"1": x}`) and
  allowed floats; parsing kept the last duplicate key. Now rejected (`rf-cjson-1`).
- `rf_core.verify_anchors` generated a new keypair when keys were missing, so verification of
  a wiped data directory had side effects. Verification is now read-only; optional
  `RF_PINNED_KEY_ID` pins the anchor key.
- New entries can no longer put `|` or control characters in `entry_type` (the hashed record
  is `|`-delimited).
- Signatures require canonical unpadded base64url.

Operational fixes:

- Docker image could not start (`ModuleNotFoundError: core`, missing API modules and
  exporter). Rebuilt from the repository root with a hardened compose file.
- `core/requirements.txt` carried one wheel hash per package, so `--require-hashes` failed on
  any other Python version or architecture. Now locked with every wheel and sdist hash;
  test and yamllint dependencies are hash-locked too.
- `tools/rf_principal.py create` discarded the one-time token. It now writes it to a new 0600
  file (`--token-file`) or prints it (`--print-token`).
- Failed-auth throttling behind cloudflared keyed every client to 127.0.0.1 and could be reset
  by address spraying. Added `RF_TRUSTED_PROXIES` and lockout-preserving eviction.
- Legacy shared-key endpoints now write `audit.api` entries.
- Dependabot pointed at `/` and never saw `core/requirements.txt` or `core/Dockerfile`.
- CI: Python 3.11/3.12/3.13 matrix, container build-and-run job, end-to-end export + pinned
  verification, hash-locked test dependencies.
- Root-level one-off audit scripts moved to `tools/forensics/` and `tools/legacy/`.
