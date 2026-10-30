# RightsFrames Evidence Bundle (rf.evidence.v1 / rf.evidence.v2)

ZIP with exactly these members:

- `rf.evidence.v1`: `manifest.json`, `ledger.jsonl`, `anchors.jsonl`, `signing_key.pub.pem`.
- `rf.evidence.v2`: the v1 members plus `signing_key_mldsa65.pub.pem` (ML-DSA-65 SPKI PEM).
  The exporter writes v2 whenever the data directory holds an ML-DSA-65 public key.

Members:

- `ledger.jsonl`: one canonical JSON object per line: `id, ts, entry_type, payload (string), prev_hash, entry_hash`.
  `entry_hash = SHA-256("{id}|{prev_hash}|{ts}|{entry_type}|{payload}")`, genesis `prev_hash` = 64 zeros.
  `payload` is canonical JSON: sorted keys, separators `,` `:`, UTF-8 not ASCII-escaped, no NaN/Infinity.
- `anchors.jsonl`: one anchor per line. `anchor_hash = SHA-256(canonical JSON of the core fields)`.
  - `rf.anchor.v2` core: `schema, seq, created_at, ledger_count, ledger_head, prev_anchor_hash, key_id`;
    Ed25519 `signature` over the ASCII `anchor_hash`.
  - `rf.anchor.v3` (hybrid, post-quantum) core: v2 core plus `pq_key_id`; carries the Ed25519
    `signature` AND `pq_signature`, an ML-DSA-65 (NIST FIPS 204) signature over the same ASCII
    `anchor_hash` with context string `rf.anchor.v3`. Both signatures must verify.
  - Legacy anchors (no `key_id`) hash `json.dumps(core, sort_keys=True)` and may not claim `rf.anchor.v3`.
  - Each anchor must satisfy `ledger_head == entry_hash of entry[ledger_count]` and chain to its
    predecessor through `prev_anchor_hash`.
  - No downgrade: once a v3 anchor appears, every later anchor must be v3.
- `signing_key.pub.pem`: Ed25519 SPKI PEM. `key_id = "ed25519:" + SHA-256(raw 32-byte public key)`.
- `signing_key_mldsa65.pub.pem` (v2 only): `pq_key_id = "mldsa65:" + SHA-256(raw 1952-byte public key)`.
- `manifest.json`: member hashes/sizes and ledger/anchor summary (`pq_key_id` in v2). Integrity metadata
  only, not a trust anchor; the verifier cross-checks every field against the members.

Trust levels: `internal_only` (self-consistent), `key_pinned`, `anchor_pinned` (only level with exit code 0).
An anchor pin also pins `key_id` and `pq_key_id`, because the anchor hash commits to both.

Guarantee: modification, deletion, reordering or truncation of anchored history is detected IF an anchor hash
recorded outside the operator's infrastructure is supplied. Without a pin, nothing is proven about history.
History is pinned only up to the newest pinned anchor (`pinned_through_entry`); later entries are reported as
`entries_beyond_pin`, and `--require-full-pin` fails if any exist.

Post-quantum: the newest v3 anchor protects every entry up to its `ledger_count`
(`pq_protected_through_entry`), because it hash-commits to the ledger head and the whole anchor chain.
`--require-pq` fails unless the newest anchor is v3; `--pin-pq-key-id` pins the ML-DSA-65 key.

Not covered: entries after the last anchor; truthfulness of what was logged; key compromise before revocation.
