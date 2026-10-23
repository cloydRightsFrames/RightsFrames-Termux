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

## Operations

- First admin: `RF_DATA_DIR=... python tools/rf_principal.py create --id admin-1 --scopes admin:principals,... --token-file PATH` (token shown once; only its PBKDF2 hash is stored).
- Behind cloudflared or a reverse proxy set `RF_TRUSTED_PROXIES=127.0.0.1` so the failed-auth throttle keys on `CF-Connecting-IP` / the last `X-Forwarded-For` hop instead of the proxy address. Forwarded headers from any other peer are ignored.
- The legacy `POST /entries` and `POST /anchor` (shared `RF_API_KEY`) append an `audit.api` entry under principal `legacy-shared-api-key` before acting. Prefer v1 principal tokens.
- `RF_PINNED_KEY_ID` makes `/health` and `/v1/ledger/verify` fail if anchors are signed by any other key.
