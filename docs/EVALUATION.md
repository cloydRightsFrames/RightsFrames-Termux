# Evaluating RightsFrames

This page is for reviewers, auditors, and prospective adopters. It states what
RightsFrames claims, how to check each claim yourself, and what it does not
claim.

## What it is

An append-only ledger for governance and audit events (for example, the
actions of an AI agent or an operator) that produces **evidence bundles** a
third party can verify offline, without trusting the operator.

| Component | Path | Role |
|---|---|---|
| Ledger core | `core/rf_core.py` | SQLite-backed hash chain; signed anchor chain |
| HTTP API | `core/app.py`, `core/rf_api_v1.py`, `core/rf_auth.py` | Append, anchor, scoped per-principal v1 API |
| Exporter | `tools/rf_export_evidence.py` | Writes `rf.evidence.v1` / `rf.evidence.v2` bundles (zip) |
| Independent verifier | `verifier/rf_verify.py` | Verifies bundles; imports nothing from RightsFrames |
| Anchor pinning | `tools/rf_pin_anchor.py`, `pins/` | Records anchor hashes outside the operator's control |
| Merkle tree | `core/rf_merkle.py` | RFC 9162 roots and inclusion paths over entry hashes |
| Inclusion receipts | `core/rf_receipt.py`, `tools/rf_export_receipt.py` | `rf.receipt.v1`: proves one entry without the rest |
| Consistency proofs | `core/rf_consistency.py`, `tools/rf_export_consistency.py` | `rf.consistency.v1`: proves a later anchor only appended to an earlier one, with no entries |
| Key sealing | `core/rf_keyseal.py`, `tools/rf_seal_keys.py` | `rf.sealed-key.v1`: private keys encrypted at rest |
| Release provenance | `.github/workflows/slsa-build-l3.yml`, `tools/verify_release_external.sh` | Reproducible release tarball with SLSA provenance |

## Security model

- **Entry hash**: `sha256(id | prev_hash | ts | entry_type | canonical_payload)`.
  The verifier recomputes it from content; it does not trust stored hashes.
- **Anchor**: a canonical JSON record committing to `ledger_count`,
  `ledger_head`, the previous anchor hash and the signing key id, signed with
  Ed25519 by the operator key.
- **Post-quantum co-signature**: when the installed `cryptography` supports
  ML-DSA-65 (NIST FIPS 204), new anchors are `rf.anchor.v3` and also commit to
  an ML-DSA-65 key id and carry an ML-DSA-65 signature over the same hash. Both
  signatures must verify, so an anchor stays unforgeable while either scheme
  holds. Once a ledger has a v3 anchor, the core refuses to write — and the
  verifier refuses to accept — any later non-v3 anchor. `RF_PQ_SIGNING`
  selects `auto` (default: hybrid when available), `on` (require it) or `off`.
- **Merkle commitment**: from v0.4.0 hybrid anchors are `rf.anchor.v4`, which add
  `merkle_root`, the RFC 9162 tree head over the entry hashes they cover, and sign
  under the ML-DSA context `rf.anchor.v4`. Core and verifier recompute every root;
  after a v4 anchor, a v3 or v2 anchor is a downgrade and fails. Existing v3
  ledgers keep verifying and continue with v4.
- **Inclusion receipts**: `rf.receipt.v1` proves one entry against a signed
  `merkle_root` in O(log n) hashes and discloses no other entry
  (`verifier/rf_verify.py --receipt`).
- **Consistency proofs**: `rf.consistency.v1` carries two `rf.anchor.v4` anchors and an
  RFC 9162 consistency path between their signed `merkle_root`s. The verifier checks
  both hybrid signatures and that the path reproduces both roots, which holds only if
  the later ledger is the earlier one with entries appended. It contains no entry. A
  pin for the earlier anchor makes the result `anchor_pinned`, and `next_pin` names the
  later anchor (`verifier/rf_verify.py --consistency`). It does not show that the
  later anchor's `ledger_head` or any entry content is correct; a bundle or receipt
  checked against the new pin does that.
- **Keys at rest**: with `RF_KEY_PASSPHRASE_FILE` (or `RF_KEY_PASSPHRASE`) both
  private keys are stored as `rf.sealed-key.v1`: Argon2id or scrypt, AES-256-GCM,
  role and parameters authenticated, hostile parameters rejected before any key
  derivation. `RF_REQUIRE_SEALED_KEYS=1` refuses plaintext keys.
- **Bundle manifest**: digests and summaries of the bundle members. It is not
  signed; integrity comes from the content hashes and the signed anchors, and
  the verifier cross-checks every manifest field against them.

Trust levels reported by the verifier (exit code in brackets):

| Level | Meaning |
|---|---|
| `internal_only` [10] | Bundle is self-consistent. Anyone holding the operator's data directory, or any attacker key, can produce this. Proves nothing about history on its own. |
| `key_pinned` [10] | As above, and the signing key matches a key id supplied by the verifier. |
| `anchor_pinned` [0] | Every supplied `SEQ:HASH` anchor pin, held outside the operator's infrastructure, matches. History is pinned through `pinned_through_entry`; later entries are reported as `entries_beyond_pin`. Pin the newest anchor. |
| `FAILED` [1] | Any inconsistency. The verifier fails closed on unexpected errors. |

Strict flags for auditors:

| Flag | Fails unless |
|---|---|
| `--require-full-pin` | every entry is covered by a pinned anchor |
| `--require-pq` | the newest anchor carries a valid ML-DSA-65 signature |
| `--pin-pq-key-id mldsa65:…` | the bundle's ML-DSA-65 key matches |

## How to check the claims

1. **One-command tamper demo** (a few seconds):

       python -m pip install --require-hashes -r core/requirements.txt
       python tools/rf_demo.py

   Fourteen expectations: an honest bundle verifies as `anchor_pinned`; five
   forgeries are rejected (content edit with stored hashes kept, content edit
   with every hash recomputed, deletion of an anchored entry, stripping of
   all anchors, full history rewrite under an attacker key); the rewrite is
   reported as `internal_only` without pins; and two post-quantum attacks are
   rejected with no anchor pin at all — a "quantum forger" holding the
   operator's Ed25519 private key (but not the ML-DSA-65 key) who rewrites
   history and re-signs every anchor, and a downgrade that strips the ML-DSA-65
   signatures. Four receipt checks follow: an honest single-entry receipt
   verifies as `anchor_pinned`; a receipt whose entry is edited and re-hashed,
   one re-rooted and re-signed by the quantum forger, and an attacker ledger's
   receipt against the operator pin are rejected. Without ML-DSA support the
   post-quantum and receipt checks are skipped (eight expectations). Exit status 0 means all held. `--keep DIR` keeps every
   forged bundle for inspection.

2. **Full test suite**:

       python -m pip install --require-hashes -r core/requirements.txt -r core/requirements-test.txt
       python -m pytest -q

   CI runs the same suite on Ubuntu and Windows (`.github/workflows/verify.yml`).

3. **Coverage**:

       python -m pip install coverage
       python -m coverage run --source=core,verifier,cli,enterprise,tools -m pytest -q
       python -m coverage report

4. **Release provenance**: follow [EXTERNAL-VERIFICATION.md](EXTERNAL-VERIFICATION.md)
   to verify a release tarball's attestation, checksum, tag object, and
   byte-for-byte reproduction from the public source tree.

5. **Bundle format**: [EVIDENCE-BUNDLE-SPEC.md](EVIDENCE-BUNDLE-SPEC.md).
   The verifier, receipts and consistency proofs included, is under 900 lines and can be re-implemented independently.

## Known limitations

- **No third-party security audit yet.** The claims above are tested by the
  author's adversarial tests and the demo, not by an independent reviewer.
  [INDEPENDENT-REVIEW-SCOPE.md](INDEPENDENT-REVIEW-SCOPE.md) defines the review
  that would change this, with the twelve claims it must confirm or refute.
- **Key custody.** The operator's Ed25519 and ML-DSA-65 private keys live on
  the operator's host, sealed at rest when a passphrase is configured. An
  attacker with both keys (and, if sealed, the passphrase or the running
  process's memory) can rewrite history consistently; only anchor pins held
  elsewhere detect it. Hardware-backed keys (HSM, TPM, Android Keystore) are
  not supported: ML-DSA-65 is not yet available in them.
- **Key rotation.** A ledger is bound to one Ed25519 and one ML-DSA-65 key
  pair; there is no signed key-rotation record yet.
- **Post-quantum scope.** ML-DSA-65 protects anchor signatures. Entry and
  anchor hashing use SHA-256, which keeps a large margin against known quantum
  attacks. Ledgers anchored before upgrading stay Ed25519-only until the first
  hybrid anchor, which then covers all earlier history. Builds of
  `cryptography` without ML-DSA (some Termux packages) fall back to Ed25519
  anchors; once a ledger has hybrid anchors, such a build refuses to anchor or
  verify it rather than downgrade.
- **Crash consistency.** Ledger entries and credential changes are SQLite
  transactions (WAL, `synchronous=FULL`). The anchor log is an append-only file: an
  append cut short by a crash is detected and must be repaired with
  `tools/rf_repair_anchor_log.py`, which keeps the fragment and records the repair
  in the ledger.
- **Unanchored tail.** Entries written after the newest anchor carry no
  signature, and no inclusion receipt can be issued for them, until the next
  anchor is created and pinned.
- **Integrity, not truth.** The ledger proves records were not altered after
  the fact. It does not prove the writing system recorded events truthfully.
- **Not yet interoperable** with IETF SCITT transparency services or COSE
  receipts. The Merkle tree and inclusion proofs follow RFC 9162, but bundles
  and receipts use the project's own JSON formats. Consistency proofs are produced by
  the operator on request; there is no independent witness that cosigns anchors, so
  showing different histories to different pin holders is detected only when they
  compare pins.
- **Solo maintainer.** Response times reflect a one-person project
  (see [SECURITY.md](../SECURITY.md)).
- **Production Termux stack excluded.** The IDS, threat-intel feeds, backup
  verification, and process supervision used on the author's Android node are
  not in this repository; `termux/rf-pinnacle.sh` is the node installer only.
- **Maintenance scripts.** Root-level `rf_historical_51_88_*.py`,
  `verify_51_88*.py` and `rf_verify_all_commits_continue.sh` are one-off
  history-verification utilities and are not part of the product surface.

## License and contact

MIT — see [LICENSE](../LICENSE). Charlie Loyd —
charlieloydrightsframes2027@gmail.com
