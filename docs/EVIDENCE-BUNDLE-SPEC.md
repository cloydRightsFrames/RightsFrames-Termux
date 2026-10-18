# RightsFrames Evidence Bundle (rf.evidence.v1)

ZIP with exactly four members: `manifest.json`, `ledger.jsonl`, `anchors.jsonl`, `signing_key.pub.pem`.

- `ledger.jsonl`: one canonical JSON object per line: `id, ts, entry_type, payload (string), prev_hash, entry_hash`.
  `entry_hash = SHA-256("{id}|{prev_hash}|{ts}|{entry_type}|{payload}")`, genesis `prev_hash` = 64 zeros.
  `payload` is canonical JSON: sorted keys, separators `,` `:`, UTF-8 not ASCII-escaped, no NaN/Infinity.
- `anchors.jsonl`: `rf.anchor.v2` objects. `anchor_hash = SHA-256(canonical JSON of core fields)`;
  Ed25519 signature over the ASCII anchor_hash. Legacy anchors (no `key_id`) hash `json.dumps(core, sort_keys=True)`.
  Each anchor must satisfy `ledger_head == entry_hash of entry[ledger_count]`.
- `signing_key.pub.pem`: Ed25519 SPKI PEM. `key_id = "ed25519:" + SHA-256(raw 32-byte public key)`.
- `manifest.json`: member hashes/sizes and ledger/anchor summary. Integrity metadata only, not a trust anchor.

Trust levels: `internal_only` (self-consistent), `key_pinned`, `anchor_pinned` (only level with exit code 0).
Guarantee: modification, deletion, reordering or truncation of anchored history is detected IF an anchor hash
recorded outside the operator's infrastructure is supplied. Without a pin, nothing is proven about history.
Not covered: entries after the last anchor; truthfulness of what was logged; key compromise before revocation.