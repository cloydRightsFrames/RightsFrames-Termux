# Independent Security Review: Scope and Statement of Work

RightsFrames makes specific, testable integrity claims. Until someone other than its
author has tried to break them, they are the author's claims. This document defines a
narrowly scoped independent review that can confirm or refute them, so that any
security statement made about RightsFrames afterwards rests on that review rather than
on self-assessment.

It is written to be sent as-is to a prospective reviewer.

## 1. Objective

Determine whether an attacker with the capabilities in section 4 can make tampered,
truncated, reordered or forged ledger history pass verification by the independent
verifier, `verifier/rf_verify.py`, at a trust level it should not reach.

The review is of the **ledger and verifier**, not of deployments, hosting, or the
Android/Termux node.

## 2. In scope

About 2,700 lines of Python, pinned to one commit of
`github.com/cloydRightsFrames/RightsFrames-Termux` named in the engagement letter.

| Component | Path | Lines | Review focus |
|---|---|---|---|
| Independent verifier | `verifier/rf_verify.py` | ~700 | Every check; fail-closed behaviour; parser strictness; trust-level logic |
| Ledger core | `core/rf_core.py` | ~970 | Entry hashing, anchor creation and verification, downgrade rules, snapshot use, crash consistency, key loading |
| Merkle tree | `core/rf_merkle.py` | ~180 | RFC 9162 conformance (tree head, inclusion paths) |
| Inclusion receipts | `core/rf_receipt.py`, `tools/rf_export_receipt.py` | ~230 | That a receipt proves exactly what the verifier reports |
| Sealed keys | `core/rf_keyseal.py` | ~280 | KDF and AEAD use, header binding, parameter bounds, failure modes |
| Exporter | `tools/rf_export_evidence.py` | ~150 | Snapshot ordering of anchors versus ledger |
| Auth store (secondary) | `core/rf_auth.py` | ~290 | Token hashing, transaction atomicity of credential changes and audit entries |

Formats: [EVIDENCE-BUNDLE-SPEC.md](EVIDENCE-BUNDLE-SPEC.md) (`rf.evidence.v1/v2`,
`rf.anchor.v2/v3/v4`, `rf.receipt.v1`). A reviewer may treat the specification as
normative and report any divergence in either direction.

## 3. Claims to test

Each claim is falsifiable. A finding is any input that violates one.

1. **Content integrity.** Any change to a past entry's `id`, `ts`, `entry_type`,
   `payload`, `prev_hash` or `entry_hash` makes bundle verification fail, unless the
   attacker also re-signs anchors (claim 4).
2. **Truncation and reordering.** Removing, duplicating or reordering anchored entries
   or anchors makes verification fail.
3. **Anchor pinning.** With a correct `--pin-anchor SEQ:HASH` obtained outside the
   operator's infrastructure, no bundle or receipt that differs from the operator's
   history through entry `ledger_count` of that anchor verifies as `anchor_pinned`,
   even if the attacker holds both private keys.
4. **Hybrid signatures.** A `rf.anchor.v3`/`v4` anchor verifies only if both the
   Ed25519 and the ML-DSA-65 signatures verify over the anchor hash, under the
   ML-DSA context string equal to the anchor's schema. Holding only the Ed25519 key
   (a "quantum forger") is insufficient to produce a verifying v3/v4 anchor.
5. **No downgrade.** After a v3 or v4 anchor, a v2 anchor is rejected; after a v4
   anchor, a v3 or v2 anchor is rejected. `--require-pq` rejects bundles whose newest
   anchor is not hybrid.
6. **Merkle commitment.** Every `merkle_root` in a v4 anchor equals the RFC 9162 tree
   head over entry hashes 1..`ledger_count`; the verifier and the core both reject
   any other value, including one signed with both keys.
7. **Receipts.** A `rf.receipt.v1` verifies only if its entry is, byte for byte, entry
   `id` of a ledger whose first `tree_size` entries produce the signed `merkle_root`.
   No two different entries can verify at the same position against the same root.
8. **Trust levels.** Exit code 0 is returned only for `anchor_pinned`. No input makes
   the verifier report a higher trust level than its pins justify, or crash in a way
   that is reported as success.
9. **Snapshot consistency.** `create_anchor` signs only ledger state it has verified,
   from one database snapshot, under concurrent appends. It never appends an anchor
   that the verifier would reject after its predecessor: not over a ledger that is
   shorter than, or differs at, the position its newest anchor signed, and not with
   a `created_at` earlier than that anchor's. (This guards the signer against
   corruption, restores and clock steps; it is not a defence against an attacker who
   can rewrite the anchor log, which only pins detect.)
10. **Crash consistency.** An interrupted anchor append is detected, never silently
    extended, and recoverable with `tools/rf_repair_anchor_log.py` without losing a
    signed anchor or evidence of the fragment.
11. **Sealed keys.** Without the passphrase, a `rf.sealed-key.v1` file yields no
    information about the key beyond its role and KDF parameters; header tampering,
    role substitution and parameter downgrade are detected before or by decryption;
    hostile parameters cannot make the loader allocate unbounded memory or CPU.
12. **Auth atomicity (secondary).** A credential change and its ledger audit entry
    commit in one transaction; an idempotent write is applied at most once.

## 4. Attacker model

Assume an attacker who can do any of the following, alone or together, except where a
claim says otherwise:

- read and write every file in the operator's data directory (`ledger.db`,
  `anchors.jsonl`, public keys, sealed private keys) **but not** a pinned anchor hash
  held elsewhere;
- hold the Ed25519 private key (claim 4), or both private keys (claim 3);
- craft arbitrary bundle ZIPs and receipt JSON, including malformed, oversized,
  duplicate-key and non-canonical inputs;
- interleave writes with `append_entry` and `create_anchor` (claims 9 and 12);
- interrupt the process at any instruction (claim 10).

Not assumed: compromise of the verifying party's machine, of Python, or of the
`cryptography` package and its OpenSSL backend; side channels on the operator's host.

## 5. Out of scope

- The Android/Termux node, `termux/`, nginx, Cloudflare, DreamHost and any website.
- `enterprise/`, `integrations/`, the release workflows and supply-chain tooling
  (covered separately by SLSA provenance and OpenSSF Scorecard).
- Root-level one-off maintenance scripts (`rf_historical_51_88_*.py`, `verify_51_88*.py`,
  `rf_verify_all_commits_continue.sh`).
- Truthfulness of what is logged: the ledger proves integrity, not accuracy.
- Correctness of Ed25519, ML-DSA-65, SHA-256, Argon2id, scrypt and AES-GCM themselves.

## 6. What the reviewer receives

- The pinned commit, and this document.
- `python tools/rf_demo.py`: builds a ledger and mounts 14 attacks against the
  verifier in under a minute.
- The test suite (`python -m pytest -q`), including the adversarial tests in
  `tests/test_post_quantum.py`, `tests/test_merkle_receipts.py`,
  `tests/test_key_sealing.py` and `tests/test_transaction_consistency.py`.
- [EVALUATION.md](EVALUATION.md): known limitations already acknowledged by the
  author (these are not findings unless the review shows them to be worse than stated).

Setup:

    python -m pip install --require-hashes -r core/requirements.txt -r core/requirements-test.txt
    python -m pytest -q && python tools/rf_demo.py

## 7. Deliverables

1. A written report listing each finding with severity, the claim it violates, a
   reproducing input or script, and a recommended fix.
2. For each claim in section 3: confirmed, refuted (with the finding), or not
   assessed (with the reason).
3. A short re-test of the fixes, against a second pinned commit.
4. Permission for RightsFrames to publish the report, or a public summary, after fixes
   ship (coordinated per [SECURITY.md](../SECURITY.md)).

## 8. Effort and reviewer profile

The author's estimate is 8 to 12 reviewer-days for sections 3.1 to 3.11, plus 1 to 2
days for the re-test; the reviewer should give their own estimate. The reviewer should
have prior published work on applied cryptography or transparency-log
implementations (for example Certificate Transparency or Sigstore-style logs).

Open-source projects can apply for audit funding through the Open Source Technology
Improvement Fund (OSTIF) and similar programmes.

## 9. Statement of status

Until a report under this scope is published, RightsFrames makes no claim of having
been independently audited, certified or validated, and its documentation says so.
