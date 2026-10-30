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

   Ten expectations: an honest bundle verifies as `anchor_pinned`; five
   forgeries are rejected (content edit with stored hashes kept, content edit
   with every hash recomputed, deletion of an anchored entry, stripping of
   all anchors, full history rewrite under an attacker key); the rewrite is
   reported as `internal_only` without pins; and two post-quantum attacks are
   rejected with no anchor pin at all — a "quantum forger" holding the
   operator's Ed25519 private key (but not the ML-DSA-65 key) who rewrites
   history and re-signs every anchor, and a downgrade that strips the ML-DSA-65
   signatures. Without ML-DSA support the two post-quantum checks are skipped
   (eight expectations). Exit status 0 means all held. `--keep DIR` keeps every
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
   The verifier is under 500 lines and can be re-implemented independently.

## Known limitations

- **No third-party security audit yet.** The claims above are tested by the
  author's adversarial tests and the demo, not by an independent reviewer.
- **Key custody.** The operator's Ed25519 and ML-DSA-65 private keys live on
  the operator's host. An attacker with both keys can rewrite history
  consistently; only anchor pins held elsewhere detect it.
- **Post-quantum scope.** ML-DSA-65 protects anchor signatures. Entry and
  anchor hashing use SHA-256, which keeps a large margin against known quantum
  attacks. Ledgers anchored before upgrading stay Ed25519-only until the first
  hybrid anchor, which then covers all earlier history. Builds of
  `cryptography` without ML-DSA (some Termux packages) fall back to Ed25519
  anchors; once a ledger has hybrid anchors, such a build refuses to anchor or
  verify it rather than downgrade.
- **Unanchored tail.** Entries written after the newest anchor carry no
  signature until the next anchor is created and pinned.
- **Integrity, not truth.** The ledger proves records were not altered after
  the fact. It does not prove the writing system recorded events truthfully.
- **Not yet interoperable** with IETF SCITT transparency services or COSE
  receipts; bundles use the project's own `rf.evidence.v1` format.
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
