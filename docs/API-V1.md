# RightsFrames API v1

Auth: `Authorization: Bearer rfp1.<principal>.<secret>` or `X-API-Key`. Failed auth: 10 per 60 s per client, then 429.
Scopes: `entries:write`, `ledger:read`, `anchor:create`, `evidence:export`, `admin:principals`.

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET | /v1/ledger/head | ledger:read | count, head, anchor count |
| GET | /v1/ledger/entries?after_id&limit | ledger:read | stored payload string; limit 1..1000 |
| GET | /v1/ledger/verify | ledger:read | chain + anchors |
| GET | /v1/anchors?after_seq&limit | ledger:read | |
| POST | /v1/anchors | anchor:create | audited first |
| POST | /v1/entries | entries:write | optional `Idempotency-Key` (8-128 chars); replay returns 200 |
| GET | /v1/entries/{id}/receipt?anchor_seq | ledger:read | rf.receipt.v1 inclusion receipt; 409 until a v4 anchor covers the entry |
| GET | /v1/anchors/{seq}/consistency?to_seq | ledger:read | rf.consistency.v1 append-only proof from anchor `seq` to `to_seq` (default newest), no entries; 404 unknown anchor, 409 if `to_seq` is not later or either anchor is not v4 |
| GET | /v1/evidence/export | evidence:export | rf.evidence.v1 / v2 zip; audited first |
| GET/POST/DELETE | /v1/principals[/id] | admin:principals | token returned once; last admin cannot be revoked |

Writes append `audit.api` (principal, action, payload digest) before acting. Reads are not ledger-audited.
With `Idempotency-Key`, the `audit.api` entry, the new entry and the idempotency record commit in one
transaction: a retry after a crash never appends twice. Principal creation and revocation commit together
with their `auth.principal.*` ledger entries. Principals are stored in `ledger.db`; a pre-0.4 `principals.db`
is migrated once on first use and renamed `principals.db.migrated`.