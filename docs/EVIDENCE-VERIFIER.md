# Evidence verifier (`verifier/evidence_verifier.py`)

Verifies rf.evidence.v1 envelopes, rf.ledger.record.v1 chains, RFC 9162 Merkle inclusion and
consistency proofs, signed rf.merkle.checkpoint.v2 checkpoints and detached rf.signature.v1
signatures. Exit code 0 only if every requested check passes; 1 on any failure; 2 on usage.

## Trust inputs

Nothing inside a file under verification can vouch for itself. Trust enters only via:

| Flag | Meaning |
|---|---|
| `--trusted-key HEX` | raw 32-byte Ed25519 public key, hex (repeatable) |
| `--trusted-key-id ed25519:HEX` | SHA-256 of the raw public key (repeatable) |
| `--trusted-root HEX` | Merkle root recorded out of band (repeatable) |

A checkpoint that verifies against a pinned key adds its root to the trusted roots.

## Checks

| Check | Passes when |
|---|---|
| `CHECKPOINT_SIGNATURE` | schema is rf.merkle.checkpoint.v2, key is pinned, `signature.key_id` equals the key's id, Ed25519 signature over `checkpoint_bytes` is valid |
| `ENVELOPE_INTEGRITY` | unkeyed SHA-256 digest matches the canonical envelope. Integrity only, **not** authenticity |
| `LEDGER_CONTINUITY` | contiguous sequence numbers, each record links to and rehashes from its predecessor |
| `LEDGER_CHECKPOINT_BINDING` | the first `tree_size` record digests hash to the signed root (detects truncation, substitution, regeneration); later records are reported as unverified |
| `MERKLE_INCLUSION` | proof verifies to a trusted root; with `record_digest` the leaf hash is recomputed, not taken from the file |
| `MERKLE_CONSISTENCY` | old and new roots are both trusted and the old tree is a prefix of the new one |
| `SIGNATURE_VALIDITY` | key is pinned, a declared `ed25519:` key id matches the key, signature valid |

## Formats

- Canonical JSON profile `rf-cjson-1`: string keys sorted by code point, no duplicate keys,
  integers within ±(2^53−1), no floats/NaN/Infinity, UTF-8 without escaping, no lone
  surrogates, no whitespace. Parsing rejects duplicate keys and float literals.
- Merkle tree: RFC 9162 §2.1; leaves are raw 32-byte record digests; `0x00` leaf and `0x01`
  node prefixes; empty tree root is SHA-256 of the empty string.
- Checkpoint document:
  `{"checkpoint": {"schema", "tree_algorithm", "tree_size", "root_hash", "previous_root"},
  "public_key": HEX, "signature": rf.signature.v1}`; produced by
  `core/evidence/checkpoint.py:sign_checkpoint`.
- Signatures: unpadded base64url, canonical encoding enforced.

## Example

```bash
python -m verifier.evidence_verifier \
  --checkpoint checkpoint.json --ledger ledger.json --proof proof.json \
  --trusted-key-id ed25519:<pinned id>
```
