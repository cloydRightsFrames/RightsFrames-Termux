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
| GET | /v1/evidence/export | evidence:export | rf.evidence.v1 zip; audited first |
| GET/POST/DELETE | /v1/principals[/id] | admin:principals | token returned once; last admin cannot be revoked |

Writes append `audit.api` (principal, action, payload digest) before acting. Reads are not ledger-audited.