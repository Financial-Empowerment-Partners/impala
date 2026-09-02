# Runbook — Triage: logs, errors and common failures

**Audience:** anyone holding a symptom — a failing request, a stuck order, a
service that will not start — and needing to get to a cause.

**Goal:** turn an observation into a named cause fast, using the exact strings
the bridge actually emits.

**Scope:** this is the reference the other runbooks point at. For the *response*
process (severity, comms, escalation) see
[`incident-response.md`](./incident-response.md); this document is the lookup
table underneath it.

---

## 0. Read this first: the bridge may not be logging at all

The bridge logs through the `log` crate. At startup it installs **one** of two
loggers, and if neither installs, every `error!`/`warn!`/`info!` in the process
becomes a silent no-op.

| Condition | What happens |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` is set | `tracing-subscriber` is installed: logs go to stdout **and** OTLP. Level: `debug` if `DEBUG_MODE=true`, else `info`. |
| Otherwise | The process tries `syslog::unix` (facility `LOG_DAEMON`, tag `impala-bridge`). |
| …and the syslog socket is missing | It prints `Failed to connect to syslog: <err>, falling back to stderr` on stderr — and then **installs no logger at all**. |

That last row is the trap. The message says "falling back to stderr", but no
stderr logger is installed — `log` macros with no registered logger do nothing.
The runtime image (`debian:trixie-slim`, see `impala-bridge/Dockerfile`) ships no
syslog daemon and no `/dev/log`, so a container with `OTEL_EXPORTER_OTLP_ENDPOINT`
unset produces **no application logs whatsoever** — only that one stderr line,
plus panic output.

**Check it first, before you conclude "there is nothing in the logs":**

```
# In the task's log stream, the presence of this line means you are blind:
Failed to connect to syslog
```

If you see it, set `OTEL_EXPORTER_OTLP_ENDPOINT` and redeploy before spending
any more time on the incident. Nothing below this section is greppable until
you do.

**There is no `RUST_LOG`.** The level is `DEBUG_MODE` (`true` → debug, else
info) and nothing else. Setting `RUST_LOG` has no effect.

**There is no `/metrics` endpoint.** Metrics are pushed over OTLP and are no-ops
when OTEL is unconfigured. You cannot scrape the bridge.

---

## 1. The error envelope

Every handled error is rendered by `AppError` (`src/error.rs`) into exactly this
shape:

```json
{"error": {"code": "forbidden", "message": "Access denied"}}
```

| Code | Status | Message the client sees |
|---|---|---|
| `unauthorized` | 401 | `Authentication required` (fixed) |
| `forbidden` | 403 | `Access denied` (fixed) |
| `bad_request` | 400 | varies — carries the reason |
| `not_found` | 404 | varies |
| `conflict` | 409 | varies — carries the reason (last-admin, reserve and sync-mode guards) |
| `rate_limited` | 429 | `Too many requests, please try again later` + `Retry-After` header |
| `internal_error` | 500 | varies — often a generic string, with the detail in the logs |

`impalactl` renders these verbatim as `error: [403 forbidden] Access denied`,
and adds `(retry after Ns)` on a 429.

> **`[502 http_error]` from `impalactl` means you never reached the bridge.**
> The CLI falls back to `http_error` when the body is not this envelope — an
> HTML error page from a proxy, ALB or CloudFlare. Debug the edge, not the app.

### The 401/403 blind spot

**`src/auth.rs` contains no logging of any kind.** Every rejection returns a
fixed string, so neither the response nor the logs tell you *why*:

- every 401 is `Authentication required`
- every 403 is `Access denied`

You must disambiguate from the request shape instead. The auth middleware
(`validate_request_auth`) picks a path on the presence of an `Authorization`
header:

**Bearer path** (header present) — 401 if any of:
- the header does not start with `Bearer `
- the JWT fails HS256 / issuer / audience / key selection, or is not a
  *temporal* token (a refresh token sent as a bearer fails here)
- the JTI was revoked by `logout`, its family was revoked by refresh-token
  reuse, or the account's logout-everywhere epoch is newer than the token's `iat`
- **Redis is unreachable** — these checks are fail-closed

**Cookie path** (no `Authorization` header) — 401 if any of:
- no session cookie (note: cookie *name* depends on `SESSION_COOKIE_SECURE`)
- the session is absent from Redis, or expired, or predates a logout-everywhere epoch
- **Redis is unreachable**

403 comes from three checks, all after successful authentication:
`require_owner` (the account in the path is not the caller's),
`require_admin` (`role != "admin"` — the governance endpoints: role grants,
account deletion, sync, webhook register/delete/test, transaction review),
and the **capability matrix** (`role_has_capability` in `src/auth.rs`) that
gates the split privileged surfaces — reserve, keys, cross-account reads,
the event feed. A treasurer on `/admin/keys`, an auditor POSTing a
disbursement, or a key-custodian on `/admin/exchange-reserve` all get the
same fixed `Access denied`; the rejection deliberately does not say which
gate fired. Check the caller's role (`impalactl whoami`) against the matrix.

> **A JWT minted before the role claim existed decodes to `view-only` and fails
> every admin and capability check with a 403.** After deploying the role
> migrations, existing sessions must refresh or re-login. See
> [`deploy.md`](./deploy.md).

> **Redis down looks exactly like bad credentials.** Auth is fail-closed on
> Redis, so a Redis outage presents as a fleet-wide 401 storm with nothing in
> the logs. Confirm with `/health` (below) before chasing a credential problem.

---

## 2. Health endpoints

| Endpoint | Behavior |
|---|---|
| `GET /healthz` | **Unconditionally 200.** Liveness only — it proves the listener is up and nothing else. |
| `GET /readyz` | 200 if `SELECT 1` **and** Redis `PING` both succeed, else 503. **Empty body either way.** |
| `GET /health` | JSON: `{"status": ..., "database": ..., "redis": ...}` — this is the one that tells you *which* dependency is down. |
| `GET /version` | Build info + `current_version` read from the `impala_schema` table. |
| `GET /network` | Which Stellar network this bridge serves (`testnet` / `pubnet`). |

> `incident-response.md` says to read the failing dependency from `/readyz`'s
> response body. That is stale — **`/readyz` has no body.** Use `/health`.

Container healthcheck (`Dockerfile`) polls `/health`, not `/readyz`.

---

## 3. Log prefix index

Log lines are prefixed by subsystem, so grep is the primary tool. These are the
prefixes worth knowing:

| Grep for | Subsystem | Typical meaning |
|---|---|---|
| `reserve watcher:` | `exchange/reserve_watch.rs` | Watcher tick / advisory-lock problems |
| `reserve deposit:` | reserve deposit matching | Inbound payment could not be booked |
| `reserve payout ` | reserve payout leg | An outgoing pool payment failed |
| `reserve refund ` | reserve refunds | Refund send/freeze problems |
| `reserve expiry ` | order expiry sweep | Expiry could not release a hold |
| `reserve order <id> frozen on_hold:` | reserve | **An order stopped with funds held** |
| `reserve stale freeze` | stale sweep | An order sat too long and was frozen |
| `replenish ` | `exchange/replenish.rs` | Float-selling cycle |
| `replenish cycle <id> frozen:` | replenish | **A cycle stopped with XLM held** |
| `exchange_reconcile:` | `exchange/reconcile.rs` | Provider order polling / drift |
| `exchange_webhook:` | webhook ingest | Database errors applying an update |
| `owlpay_webhook:` / `changelly_webhook:` | webhook auth | Signature/header rejections |
| `load_protected_seed:` | custodial signing | **Seed could not be opened or does not match** |
| `store_managed_account:` | custodial provisioning | Account/seed insert failed |
| `health_check:` | health | Which dependency failed the probe |
| `worker:` | `worker.rs` | SQS poll loop and job outcomes |
| `enroll_mfa:` / `verify_mfa:` | MFA | Enrollment/verification failures |
| `issue_verification:` | SMS enrollment | A code was minted; `sent=false` means nothing went out |
| `try_issue_verification:` | SMS enrollment | Code could not be issued on a create/update — the row saved unverified |
| `verify_notify:` | SMS enrollment | Wrong/expired code, spent attempt budget, or a number changed mid-flight |

### Ledger-integrity alarms — page on these

Any log line containing **`drift`** or **`underflow`** means the ledger and the
computed balance disagree. These are not transient:

```
reserve refund <id>: reversal underflow (drift)
reserve expiry <id>: held underflow (drift)
replenish cycle <id>: held underflow (drift)
reserve expiry <id>: hold entry missing
reserve deposit: bucket <currency> missing
```

Do not "retry" these. Stop, capture the row, and reconcile by hand — see
[`conversion-reserve.md`](./conversion-reserve.md).

---

## 4. The bridge will not start

Every one of these exits the process. The exact strings, in the order they can
occur (`src/main.rs`):

| Message | Cause | Fix |
|---|---|---|
| `Failed to unwrap DATABASE_URL from Vault/OpenBao: <err>` | `DATABASE_URL_WRAPPED` is set but the wrapping token is expired, already used, or Vault is sealed/unreachable | Re-wrap and redeploy with a fresh token. A wrapping token is **single-use** — a task that restarts twice on the same token fails the second time. |
| `database_url field not found in unwrapped secret` | The unwrapped secret has no `database_url` key | Fix the secret's shape in Vault/OpenBao |
| `Either DATABASE_URL or DATABASE_URL_WRAPPED must be set` | Neither is set | Supply one |
| `Failed to connect to database` | Bad URL, wrong credentials, SG/network path, RDS down | Check the security group first — it is the usual cause of a sudden failure with unchanged config |
| `Failed to create Redis connection pool` | Malformed `REDIS_URL` (this is pool *construction*, not connectivity) | Check the URL syntax, including the password form `redis://:<pw>@host:6379` |
| `Failed to run migrations` (only when `RUN_MODE=migrate`) | A migration failed or the schema is in an unexpected state | **Do not re-run blindly.** Inspect what the partial run left behind first |
| `JWT_SECRET environment variable must be set` | Unset | Supply it |
| *(JWT key error, message varies)* | `JWT_SECRET` / `JWT_SECRET_PREVIOUS` rejected by `JwtKeys::new` (e.g. too short) | Fix the secret value |
| *(CORS policy error, message varies)* | **A wildcard CORS origin on `pubnet` is a hard startup failure.** Allowed on testnet with an info log | Set `CORS_ALLOWED_ORIGINS` to explicit origins |
| `Failed to initialize seed protector: <err>` | `SEED_PROTECTION_BACKEND` misconfigured — sealed Vault, missing `BAO_ADDR`/`VAULT_ADDR`, missing transit key, KMS denied | See §5 |
| `Failed to initialize the '<kind>' provider from the environment: <err>` | A provider credential supplied **via environment variables** is malformed | Fix the value. Fails closed deliberately: a half-configured money path must not boot |
| `Failed to initialize conversion reserve: <err>` | `RESERVE_ACCOUNT_ID` names an account with no managed seed, or the seed cannot be opened | See [`conversion-reserve.md`](./conversion-reserve.md) |
| `Failed to bind SERVICE_ADDRESS` | Port in use or address unbindable | Check `SERVICE_ADDRESS` |
| `SQS_QUEUE_URL must be set when RUN_MODE=worker` | Worker started without a queue | Supply it |

### The one that does *not* stop startup

```
Failed to build the '<kind>' provider from its stored credential: <err>.
The provider is DISABLED for this process.
```

An **imported** credential that fails to build only disables that provider; the
bridge boots. An **environment-supplied** one is fatal. This asymmetry is
deliberate, and it means a provider can be silently absent on a healthy-looking
service. `GET /admin/keys` (or `impalactl keys list`) shows the resolution and
its error.

### Confirming what it started as

```
impala-bridge starting up (mode=<server|worker|migrate>)
```

`RUN_MODE` defaults to `server`. Also useful at boot:
`Custodial seed protection backend: <backend>`,
`Conversion reserve enabled: account=… address=… usdc=…`,
`Redis connection pool created (max_size=…)`.

---

## 5. Keys, seeds and signing

| Symptom | Cause |
|---|---|
| 500 `seed protection backend mismatch`, log `load_protected_seed: seed backend '<a>' != configured backend '<b>'` | The seed was sealed under a different backend than `SEED_PROTECTION_BACKEND` now names. Point the service back at the original backend — you cannot open it with the new one. |
| 500 `seed does not match its account record` | **Stop.** The decrypted seed derives a different Stellar address than its row claims. The bridge refuses to sign. This means the row was tampered with or a seed was replaced out of band. Treat as a security event. |
| 500 `Corrupt seed record` | The stored backend tag is unrecognizable |
| Import refused until `--replace` + a confirmation phrase | Something is already in effect — **including a credential supplied by environment variables**. See [`import-keys.md`](./import-keys.md) |
| An import "worked" but behavior is unchanged | Expected. Credentials resolve **once per process**. `pending_restart` in `GET /admin/keys` is the normal gap; roll the deployment to activate |

**Two different env namespaces, easily confused:**

- The **bridge** reads provider credentials from `OWLPAY_API_KEY`,
  `OWLPAY_WEBHOOK_SECRET`, `CHANGELLY_API_KEY`, `CHANGELLY_PRIVATE_KEY`
  (or `CHANGELLY_PRIVATE_KEY_FILE`), `CHANGELLY_FIAT_API_KEY`,
  `CHANGELLY_FIAT_PRIVATE_KEY` (or `..._FILE`),
  `CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY`.
- **`impalactl`** reads the values you are *importing* from
  `IMPALA_KEY_<KIND>_<PART>` — e.g. `IMPALA_KEY_OWLPAY_API_KEY`,
  `IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY`.

> The CLI's own `--help` text says `$IMPALA_KEY_<PART>`. That is wrong — the
> kind is included (`keys_cmd.go:379`), deliberately, so a value exported for
> one provider cannot be submitted to another.

Vault/OpenBao variables accept either spelling, `BAO_*` winning:
`BAO_ADDR`/`VAULT_ADDR`, `BAO_TOKEN`/`VAULT_TOKEN`,
`BAO_TRANSIT_KEY`/`VAULT_TRANSIT_KEY`.

---

## 6. Webhooks from the exchange

| Symptom | Cause |
|---|---|
| `owlpay_webhook: missing harbor-signature header` | Not a real OwlPay call, or a proxy stripped the header |
| `owlpay_webhook: signed payload is not valid JSON: <err>` | Signature verified, body did not parse |
| `changelly_webhook: <header> mismatch` | API-key header does not match the active credential — commonly a credential rotated on one side only |
| Uniform 401 with nothing else | Signature verification failed, including the replay window |

Headers: OwlPay uses `harbor-signature` (`t=<unix>,v1=<hex>`); Changelly uses
`x-callback-signature` plus an API-key header. Unverified requests are
rate-limited per source *before* any crypto work, so a flood shows up as 429s
rather than CPU burn.

Webhooks are monotonic: a replayed or late webhook can never regress a final
state. A "missing" webhook is usually better fixed by letting
`exchange_reconcile` catch up than by replaying.

---

## 7. Symptom index

**Everything 401s, no logs.** Redis. Check `/health`. Auth is fail-closed on
Redis for revocation, epoch and session lookups.

**One operator gets 403 on privileged routes; others fine.** Their token
predates the role claim, their DB role does not carry the capability (a
treasurer on the keys surface, an auditor on any mutation), or the endpoint
is governance and they are not `admin`. `impalactl whoami` shows the role in
the stored token without a network call. For a read-only investigation, an
auditor token covers the whole privileged surface — mint that rather than an
admin token.

**One account starts 401ing right after a role change.** Expected: a role
grant (and account deletion) revokes the target's tokens and sessions on the
spot. They sign in again and receive the new role — refresh alone will not
resurrect the old credentials.

**429s from one account.** Per-account API rate limit, charged only after
successful authentication. `Retry-After` carries the delay.

**`csrf_rejected` metric climbing.** Cookie-path requests missing the CSRF
header. CSRF is enforced on the cookie path only — bearer requests carry no
ambient credential. Usually a UI served from an unexpected origin.

**Orders route to the provider instead of the reserve.** Expected for anything
that does not qualify. The `reserve.fallbacks` metric is labelled by reason.
`changelly_fiat` can never divert.

**Notification backlog.** Worker-side. Grep `worker:` — `poll error`,
`invalid JSON`, `failed to delete message`. See `incident-response.md` for the
DLQ procedure.

**A user says they get no SMS notifications.** Most likely the number is not
confirmed. `GET /notify` shows `mobile_verified_at` — null means
`dispatch_event` skips it by design. Have them request a fresh code with
`POST /notify/verify/send` and submit it to `POST /notify/verify`. Note that
**changing the number clears the confirmation** (a database trigger does it), so
an edit silently returns the row to unverified until re-confirmed.

**Codes are never delivered.** Verification uses the same Twilio path as every
other SMS, so it needs `TWILIO_SID`/`TWILIO_TOKEN`/`TWILIO_NUMBER` **and** a
worker consuming SQS. Where SNS is unconfigured the write still succeeds but
answers `verification_sent: false` — check for `try_issue_verification:` in the
logs, and `notification.verification_sent` with `outcome=not_sent`.

**Verification 429s.** Sends are capped per row and per account (each one is a
billed message). Submissions are capped separately, so a burst of guesses
cannot lock someone out of requesting a new code.

**`GET /exchange/*` returns 400.** The provider is unconfigured. Empty
credential env vars mean "not configured"; the routes answer 400 rather than
failing at boot.

**A set-but-empty env var overrides a config file value.** `CONFIG_FILE` (JSON)
is read first and environment variables win — *including when set to the empty
string*. The bridge compose file warns about exactly this for
`SSO_PROVIDERS`/`OPENBAO_*`. If a config-file value seems ignored, check for an
empty env var shadowing it.

---

## 8. Metrics

Exported over OTLP only, and no-ops without `OTEL_EXPORTER_OTLP_ENDPOINT`.
Names (from `src/telemetry.rs`):

`http.server.request.duration`, `http.server.active_requests`,
`auth.attempts`, `auth.token_exchange`, `auth.token_reuse_detected`,
`session.created`, `session.csrf_rejected`,
`transaction.created`, `payment.settled_unrecorded`,
`mfa.enrollment`, `mfa.verification`,
`notification.dispatched`, `notification.delivered`, `notification.delivery.duration`,
`notification.verification_sent`, `notification.verification_result`,
`worker.job.processed`, `worker.job.duration`, `worker.job.active`,
`stellar.reconcile.transactions`, `batch_sync.accounts`,
`payala_sync.batches`, `payala_sync.items`,
`exchange.orders_created`, `exchange.order_updates`,
`reserve.orders_diverted`, `reserve.fallbacks`, `reserve.deposits_matched`,
`reserve.fulfillments`, `reserve.payout_failures`, `reserve.expiries`,
`reserve.unmatched_deposits`, `reserve.manual_entries`,
`reserve.refunds_queued`, `reserve.refunds_sent`, `reserve.refund_failures`,
`reserve.quotes_issued`, `reserve.quotes_consumed`, `reserve.quote_expiries`,
`reserve.replenish_cycles`, `reserve.replenish_skips`.

Two worth alerting on directly: `auth.token_reuse_detected` (a refresh token was
replayed — the bridge revokes the whole family) and `reserve.payout_failures`.

## 9. Correlating a single request

Every request gets an `x-request-id` (generated as a UUID if absent) and it is
echoed on the response. Capture it from the client and grep for it. Requests are
traced via `TraceLayer`, and path labels are normalized (numeric and UUID
segments collapsed) so per-endpoint metrics do not explode by id.

## Gotchas

- **`/healthz` proves almost nothing.** It is a constant 200. A bridge with a
  dead database passes it.
- **Migrations run two different ways.** In production, a one-off task with
  `RUN_MODE=migrate`. In local compose, Postgres itself applies
  `./migrations` via `docker-entrypoint-initdb.d` — but **only on a fresh
  volume**. An existing `pgdata` volume silently skips them.
- **`DEBUG_MODE=true` widens logging to `debug`.** `Config` has a redacting
  `Debug` impl so secrets are not printed, but treat debug logs as sensitive
  and turn it back off.
- **`impalactl` validates client-side too.** An address or amount rejected
  without a round trip is the CLI's own check, not the bridge's verdict.
