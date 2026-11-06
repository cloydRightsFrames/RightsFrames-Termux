## What changes and why

<!-- One paragraph: the problem, the change, and the user-visible effect. -->

## Security impact

- [ ] No change to hash-chain, anchor, signature, verifier or release logic
- [ ] Changes one of those; a test proves tampering is still detected (see CONTRIBUTING.md)

## Evidence

- [ ] `python -m pytest -q` passes locally
- [ ] `ruff check .` passes
- [ ] `python3 tools/verify_supply_chain_policy.py` passes
- [ ] New or updated dependencies are hash-locked (`--require-hashes`), and lock files were regenerated with the command in their header
- [ ] New workflow steps pin actions to a full commit SHA, set `timeout-minutes`, and use least-privilege `permissions`

## Notes for reviewers

<!-- Anything a reviewer should check by hand, and how to reproduce it. -->
