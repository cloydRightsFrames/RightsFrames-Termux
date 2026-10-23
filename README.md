# RightsFrames

A tamper-evident governance ledger with an independent verifier. Every entry is
hash-chained, ledger heads are committed to Ed25519-signed anchors, and an exported evidence
bundle can be verified offline by a third party who trusts nothing the operator runs — only
a key id or anchor hash they recorded somewhere the operator cannot rewrite.

## What it proves, and what it does not

| Property | Mechanism | Holds against | Checked by |
|---|---|---|---|
| Past entries were not edited, reordered or deleted | SHA-256 content-hash chain | anyone without the ability to recompute the whole chain | `rf_core.verify_chain`, `verifier/rf_verify.py` |
| History was not truncated or rolled back | signed anchors chained to each other, each committing to a ledger head | an attacker with the database but not the signing key | `rf_core.verify_anchors` |
| History was not regenerated wholesale | anchor hash or key id pinned **off-box** | an attacker with the full data directory, including the private key | `verifier/rf_verify.py --pin-anchor` (exit 0 only at `anchor_pinned`) |
| A record is in a signed tree; a later tree extends an earlier one | RFC 9162 Merkle inclusion and consistency proofs, signed checkpoints | forked or substituted histories | `verifier/evidence_verifier.py` |

Not proven: that what was logged is true, entries written after the newest pinned anchor, or
anything after a signing-key compromise that predates the pin. Tamper-evident is not
immutable: an attacker with write access can change data; they cannot do it undetected by a
verifier holding an off-box pin.

## Quick start (container)

```bash
export RF_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose -f core/docker-compose.yml up --build -d
curl -s http://127.0.0.1:8000/health
curl -s -X POST http://127.0.0.1:8000/entries -H "X-API-Key: $RF_API_KEY" \
     -H 'content-type: application/json' -d '{"entry_type":"demo.event","payload":{"n":1}}'
curl -s -X POST http://127.0.0.1:8000/anchor -H "X-API-Key: $RF_API_KEY"
```

The port binds to loopback only. The container runs as uid 10001 with a read-only root
filesystem, all capabilities dropped and `no-new-privileges`.

## Quick start (Termux / bare Python 3.11+)

```bash
python -m pip install --require-hashes -r core/requirements.txt
export RF_DATA_DIR="$HOME/.rightsframes/core"
python tools/rf_principal.py create --id admin-1 \
  --scopes admin:principals,ledger:read,entries:write,anchor:create,evidence:export \
  --token-file "$HOME/.rightsframes/admin-1.token"
PYTHONPATH=.:core uvicorn core.app:app --host 127.0.0.1 --port 8888
```

## Independent verification

```bash
# Operator: anchor, then publish the anchor hash somewhere outside the operator's control.
RF_DATA_DIR=... python tools/rf_pin_anchor.py pin --pins pins/anchor-pins.jsonl --create-anchor

# Anyone: export (or receive) a bundle and verify it against the off-box pin.
python tools/rf_export_evidence.py --data-dir "$RF_DATA_DIR" --out bundle.zip
python verifier/rf_verify.py bundle.zip --pin-anchor 2:<anchor_hash>   # exit 0 = anchor_pinned
```

`verifier/rf_verify.py` imports nothing from RightsFrames and needs only Python and
`cryptography`, so it can be audited or rewritten independently. See
[docs/EVIDENCE-BUNDLE-SPEC.md](docs/EVIDENCE-BUNDLE-SPEC.md) and
[docs/EVIDENCE-VERIFIER.md](docs/EVIDENCE-VERIFIER.md).

## Repository map

| Path | Purpose |
|---|---|
| `core/rf_core.py` | ledger, anchors, read-only verification |
| `core/app.py`, `core/rf_api_v1.py`, `core/rf_auth.py` | HTTP API, per-principal scoped tokens, idempotency, audit |
| `core/evidence/` | rf.evidence.v1 envelopes, canonical JSON, RFC 9162 Merkle tree, signed checkpoints |
| `verifier/rf_verify.py` | standalone bundle verifier (trust levels, off-box pins) |
| `verifier/evidence_verifier.py` | envelope / ledger / proof / checkpoint / signature verifier with pinned trust |
| `tools/rf_export_evidence.py`, `tools/rf_pin_anchor.py`, `tools/rf_principal.py` | export, pinning, principal admin |
| `enterprise/`, `provenance/`, `.github/workflows/` | release provenance, SLSA build, supply-chain policy gates |
| `tools/forensics/`, `tools/legacy/` | one-off historical audit scripts kept for the record |

## Development

```bash
python -m pip install --require-hashes -r core/requirements.txt -r core/requirements-dev.txt
RF_DATA_DIR="$(mktemp -d)" python -m pytest -q
```

`tests/test_adversarial_evidence.py` reproduces attacks that worked against earlier
revisions; a passing attack there is a security regression. Dependencies are locked with
hashes for every platform wheel and sdist (`core/requirements.in` documents regeneration).

## AI-assisted development

Built with extensive AI assistance. Security claims are backed by the adversarial tests in
this repository rather than by description; where a claim has no test, treat it as unproven.

## License and contact

MIT — see [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
Charlie Loyd — CharlieLoyd@RightsFrames.onmicrosoft.com
