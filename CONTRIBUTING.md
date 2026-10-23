# Contributing

1. Any change touching the hash chain, anchors, signatures, canonical JSON, Merkle code or a
   verifier must ship with a test that proves tampering is still detected. Put attack
   reproductions in `tests/test_adversarial_evidence.py`.
2. Verification must stay side-effect free: no key generation, file creation or writes.
3. Never change how an existing stored record is hashed. Introduce a new schema version and
   keep verifying the old one (see `core/manifest.py` v1/v2 for the pattern).
4. Dependencies: edit `core/requirements.in` (or `requirements-dev.in`) and regenerate the
   locked file with the `uv pip compile` command at the top of that file. Never hand-edit
   hashes.
5. GitHub Actions must be pinned to full commit SHAs.
6. Run before pushing:

   ```bash
   python -m pip install --require-hashes -r core/requirements.txt -r core/requirements-dev.txt
   RF_DATA_DIR="$(mktemp -d)" python -m pytest -q
   ```

Pull requests need two approving reviews.
