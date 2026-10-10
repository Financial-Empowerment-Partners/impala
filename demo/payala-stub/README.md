# payala-stub — the Payala side of the demo, stubbed

The demo's relays (`../scripts/payala/*`) move money between the Impala bridge and a Payala backend.
The real Payala API is proprietary and is **not** part of this repository or this demo. This directory is a
small clean-room stub of the subset the relays use — one dependency-free Node module (`server.mjs`, Node ≥ 20)
that runs from the public `docker.io/library/node:22-alpine` image with this directory bind-mounted
(compose service `payala-stub`, host port `PAYALA_PORT`, default 4000). No image is built, nothing is
downloaded beyond that base image, and the Payala source tree is never needed.

What it implements, written from the wire contract documented in `../scripts/payala/payala-order.sh`:

| Endpoint | Behaviour |
|---|---|
| `GET /` | health: `{service:"payala-stub", status, users, transfers, seeded_at, persistent}` |
| `GET /users`, `GET /users/:id` | the seeded users (`{"Data":[…]}` / one user) with integer `balance` in cents |
| `POST /transfers/order` | a remote transfer ("Order") the server signs itself: validates the 256-byte preimage hash and that `sender_public_key` is the sender card's P-256 signing key, refuses a self-transfer, moves the balances in one step and only after the state file was written (`503 persistence_failed` otherwise, nothing applied), answers the transfer with `counter: -1`; the same `hash` replays the stored transfer (`replayed: true`) and never moves money twice; `null` for a cardless sender; `422 insufficient_balance` |
| `GET /transfers` | the ledger, filterable by `since` (+ `overlap` seconds), `device_id`, `hash` (hex, base64 or base64url), `sender_id`, `recipient_id`, `limit` |
| `GET /__stub/requests` | the stub's own evidence, not Payala API: an in-memory request journal (method, path, status, whether an `Authorization` header was sent, the ids of each order), newest 2000 entries; `/__stub/*` requests are not journaled |
| `GET /__stub/state` | counters (`requests_total`, `authorization_requests` — monotonic since start, every request counted), the seeded cards and their key hex (public keys; `up.sh` compares them with the rendered seed), journal size and sequence |
| `GET /__stub/healthz` | the compose healthcheck target (not journaled) |

Money is integer minor units throughout (`Number.isSafeInteger` guards every balance update). State lives in
memory and is persisted to `PAYALA_STUB_STATE` (the `payala-stub-data` volume) before a mutation is committed,
so `down`/`up` keeps the ledger and `reset.sh` (`compose down -v`) clears it; the seed (`PAYALA_STUB_SEED`,
rendered by `../scripts/prepare.sh` from the ids in `.env` and the P-256 keys in `../state/keys`) only adds
users that do not exist yet — a changed id or regenerated key after the first start is reported by `up.sh`
and needs `reset.sh`. The journal and the counters are not persisted (a restart starts them empty), which is
why scenario 08 scopes its journal assertions to its own run and reads the counters for the "never" claims.
The request handler is catch-all (a malformed request target answers 400, an oversized body a real 413), so
no request can stop the process, which is PID 1 in its container.

```bash
node --test demo/payala-stub/server.test.mjs      # unit + HTTP tests (also run by .github/workflows/demo.yml)
PAYALA_STUB_SEED=demo/build/payala-stub/seed.json node demo/payala-stub/server.mjs   # on the host, port 4000
```
