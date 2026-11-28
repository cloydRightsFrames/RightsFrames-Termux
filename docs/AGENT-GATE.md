# RightsFrames Agent Evidence Gate — v0.1.0 (opt-in candidate)

## Product capability

This code adds a **separately launched** FastAPI surface for collecting
cryptographically authorized *agent-intent evidence* in the existing RightsFrames
ledger. An authorized agent statement requires:

- a scoped RightsFrames v1 principal (`entries:write`);
- an Ed25519 grant from the configured approval key (not from the agent);
- an exact-match allowlist policy (agent, action, resource);
- a signed digest binding the specific event payload and current policy;
- a short expiry (maximum 300 seconds);
- a unique 128-bit nonce, consumed in the **same SQLite transaction** as the
  recorded evidence; and
- no prior use or revocation of that nonce.

A revocation endpoint requires `admin:principals`, and records revocation
atomically. The evidence record stores a digest of the event rather than its
contents to reduce accidental disclosure. It records the scoped API principal.

**No external agent tools are executed by this service.** It establishes a
fail-closed pre-execution authorization and evidence endpoint, not a universal
sandbox or attestation of what an agent actually did. Tool integrators must
call this gate before executing any separately authorized tool and must
implement their own safe execution and result attestation.

## Local-only validation (no secrets / production changes)

From the repository root, with dependencies already installed:

```
python -m unittest discover -s tests -p 'test_rf_agent_gate.py' -v
python tools/rf_agent_pilot.py
```

The pilot constructs an ephemeral ledger under a temporary directory; generates
and holds temporary keys in memory; tests unauthorized access, authorized
recording, replay rejection, changed-event rejection, revocation, ledger
integrity, signed anchor creation and an inclusion-receipt endpoint. It then
destroys the temporary ledger and key material. Full PASS requires a compatible
ML-DSA-65 runtime for `rf.anchor.v4` and receipts.

## Deployment (not automatic)

The opt-in application module is `core.rf_agent_service:app`. It extends the
existing hardened RightsFrames FastAPI application, without changing the
production default `core.app:app`.

Bind locally unless a reviewed TLS gateway and network policy are in place:

```
python -m uvicorn core.rf_agent_service:app --host 127.0.0.1 --port 18888
```

Requires `RF_DATA_DIR` (a dedicated isolated deployment),
`RF_AGENT_APPROVER_PUBKEY` (PEM Ed25519 public key),
`RF_AGENT_POLICY_FILE` (operator-controlled JSON allowlist), and the existing
RightsFrames v1 principals and production requirements. No key or policy is
automatically generated for production. Example policy:

```
{"version":1,"rules":[{"agent":"review-bot","action":"read","resource":"invoice/42"}]}
```

The approver should sign grants in a different trust domain from the agent and
gateway. Library API: `core.rf_agent_gate.issue(private_key, policy, agent,
action, resource, event, ttl=120)`. Never distribute the approver's private key
to an untrusted agent. Avoid storing the private key in Android Downloads.

Routes, using existing scoped authentication:

- `POST /v1/agent/record` — `{token, agent, action, resource, event}`, requires
  `entries:write`. Responds with the ledger entry ID and hash on success.
- `POST /v1/agent/revoke` — `{nonce, reason}`, requires `admin:principals`.

Entries are not immediately receiptable: call the existing `POST /v1/anchors`
afterward, retain a pinned anchor externally, and retrieve the receipt at the
existing `GET /v1/entries/{entry_id}/receipt`.

## Limits and release gates

- Single issuer trust root and manual key replacement; no distributed revocation
  protocol or HSM support.
- Replays are denied rather than transparently returning the prior response.
- Grant expiration assumes system clocks within 30 seconds of actual time.
- Does not attest to external tool execution, truthfulness, or confidentiality
  of transmitted event bodies.
- Not an independent audit, compliance certification, SCITT interoperability
  claim, or proof of unique intellectual property.
- Have independent reviewers validate the authorization trust model, principal
  policy, replay behavior, key management, and ledger-integrity assumptions.
- Resolve outstanding source-license and filesystem-hardening reviews before
  commercial release. Respect the repository's two-party review rules.
