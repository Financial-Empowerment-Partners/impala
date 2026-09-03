# Runbook — Incident Response

**Audience:** on-call engineer for impala-bridge.

**Goal:** triage, stabilize, and root-cause production incidents quickly.

## Severity guide

| Sev | Criteria | Response |
|---|---|---|
| 1 | Total outage (`/healthz` or `/readyz` failing from multiple regions) OR suspected compromise | Page everyone, start an incident channel, consider DR failover |
| 2 | Partial outage: one capability down (auth, transactions, notifications) | Page on-call, mitigate within 30 min |
| 3 | Degraded: elevated errors/latency but no capability down | Investigate within 2 hours; fix within the day |
| 4 | Cosmetic / logging only | File an issue; fix during normal business hours |

## First 10 minutes

1. **Check dashboards.** CloudWatch dashboard
   `<project>-<environment>-dashboard` (e.g. `impala-bridge-staging-dashboard`;
   URL in `terraform output -raw cloudwatch_dashboard_url`) and SigNoz service
   `impala-bridge`. Look for an obvious spike: 5xx rate, latency p99, CPU,
   memory, DB connections, Redis errors, SQS backlog, DLQ depth.
2. **Check `/healthz` and `/readyz`** from outside the VPC (e.g. your
   laptop). Both return only a status code, no body. If `/readyz` is 503,
   `GET /health` identifies the failing dependency — its response carries
   `database` and `redis` fields (`ok`/`error`).
3. **Check ECS task count.** Lower-than-desired = tasks are crash-looping.
   Same-as-desired but with elevated errors = application bug, not infra.
4. **Announce in the incident channel** what you see, with timestamp.
5. **Do not change prod configuration yet.** Observe first.

## Suspected credential compromise

If an exchange provider key or a custodial Stellar seed may be exposed, follow
`import-keys.md` — the order matters, and two steps are easy to miss:

1. **Revoke at the provider first.** `impalactl keys revoke` stops the bridge
   using a key; it does not invalidate it upstream.
2. **Scrub the environment variables too.** A stored credential shadows them,
   but `KEY_IMPORT_ENABLED=false` — including the break-glass path — reverts
   the fleet to whatever they still hold.

Then check `GET /admin/events` for `bridge.key_imported`, `bridge.key_revoked`
and `bridge.seed_provisioned` entries nobody can account for.

## Common failure modes

### `/readyz` is 503

The probe fails if either the Postgres SELECT 1 query or the Redis PING
fails. `/readyz` itself returns no body — call `GET /health` and read its
`database` / `redis` fields to identify which.

- **DB unhealthy:** check RDS status in console. Failover if Multi-AZ hasn't
  already (it should be automatic). If RDS is healthy, look at the ECS
  security group — a SG change could have severed the egress path.
- **Redis unhealthy:** check ElastiCache status. The application is
  fail-closed on Redis (rate limits, lockouts, token revocation all fail
  with 5xx when Redis is down). Auth will be impacted immediately. If the
  fix involved a failover, replacement, flush, or restore, the data is gone
  or stale — do the "Redis lost its data" steps below **before** declaring
  the incident over.

### Redis lost its data (DR failover onto the empty DR group, a flush, a restore from snapshot)

Redis is the *only* store for token revocation (`impala:revoked:*`),
refresh-token rotation and family revocation (`impala:rotated:*`,
`impala:revoked_family:*`), the per-account auth epochs behind
logout-everywhere, role changes and account deletion (`impala:auth_epoch:*`),
and the `__Host-` sessions (`impala:session:*`). Losing it does not break
auth — it silently **un-revokes**: every bearer token that was revoked,
rotated away, or minted before a demotion verifies again for the rest of its
lifetime (temporal tokens up to 1 h, refresh tokens up to 14 days), and a
stolen refresh token that had been rotated away mints a fresh pair again
without tripping reuse detection until a second presentation of the same
token collides. Nothing in the logs flags this; it has to be procedure.

**Mandatory, before or immediately after serving traffic from the affected
Redis:**

1. Rotate `JWT_SECRET` **without** `JWT_SECRET_PREVIOUS` — the emergency
   procedure in
   [`rotate-secrets.md`](./rotate-secrets.md#emergency-rotation-suspected-compromise).
   Every refresh and temporal token dies at once; API clients and admins
   re-authenticate. This is the *only* global kill switch for bearer
   tokens: the auth epoch is per account and lives in the Redis you just
   lost.
2. Force cookie re-login. An empty Redis has already done this (sessions
   live only there). A *stale* Redis — restored from a snapshot — has not:
   delete `impala:session:*` (SCAN + DEL; never `KEYS` on a live node).
3. Treat the login lockout and rate-limit counters as reset: watch
   `POST /token` and `POST /authenticate` for credential-stuffing bursts
   over the following hour.

If this was a regional failover, the same step sits in the DR procedure in
[`deploy.md`](./deploy.md#cross-region-dr-failover).

### Elevated 5xx with DB and Redis healthy

Look for patterns:
- **All endpoints:** likely an application panic. Check CloudWatch log group
  for stack traces. Roll back if you see a new release correlated.
- **One endpoint:** likely a handler bug in a recent PR. Identify the PR and
  roll back per `deploy.md`.
- **One tenant:** look for rate-limit 429s; a misbehaving client can flood
  the endpoint and trip the lockout for their own account.

### Notification backlog growing (SQS)

1. Check SQS queue + DLQ depth in CloudWatch.
2. If the main queue is growing but the worker service has enough tasks,
   the bottleneck is downstream (Twilio, SES, FCM). Look for elevated
   errors in worker logs.
3. If messages are in the DLQ, they've exhausted retries. Inspect a sample:
    ```
    aws sqs receive-message \
      --queue-url $(cd terraform && terraform output -raw sqs_dlq_url) \
      --max-number-of-messages 1 \
      --visibility-timeout 600
    ```
   Decide whether to fix-and-replay (manually re-enqueue to the main queue
   after the underlying issue is fixed) or purge if the payload is
   irredeemable.

### Auth is broken (users can't log in)

1. **Check Redis health.** Auth rate limit and lockout checks fail-closed.
2. **Check JWT_SECRET.** If it was just rotated *without* the
   `JWT_SECRET_PREVIOUS` overlap, all existing tokens are invalidated —
   users need to log in again. That is *expected* for an emergency rotation,
   not an incident; a scheduled rotation done with the overlap logs nobody
   out. If a partial rotation left services with mismatched secrets, see
   `rotate-secrets.md`.
3. **Check SSO providers** via `/auth/sso/<provider>/config` (e.g. `/auth/sso/okta/config`).
   If a provider that should be enabled reports `{"enabled":false}`, its discovery/JWKS
   fetch failed at startup — check the `oidc[<provider>]` logs and issuer/JWKS reachability.
4. **Check `POST /token` logs** for "invalid refresh token" bursts — could
   indicate a client bug or a scripted login attempt.

### Stellar submissions failing

1. Check the Stellar network status page.
2. `curl /network` on the bridge to confirm it's pointed at the expected
   Horizon / Soroban-RPC URLs.
3. Check the `stellar_reconcile` job logs in CloudWatch; transient errors
   should retry — persistent errors require Stellar-side investigation.

## Suspected compromise

Treat as Sev 1 regardless of impact.

1. **Do not close the attacker's session** until forensics has captured
   logs. Snapshot relevant CloudWatch log streams and RDS if feasible.
2. **Rotate `JWT_SECRET`** (see `rotate-secrets.md`) — this invalidates all
   existing tokens and forces every user to re-authenticate.
3. **Rotate all other secrets** that may have been reachable from the same
   blast radius: DB URL, Vault/OpenBao wrapping & Transit tokens, Twilio, SES,
   FCM, and `DUO_2FA_CLIENT_SECRET` if Duo 2FA is enabled. (The OIDC SSO
   providers use no bridge-side client secret — public PKCE clients.)
4. **Review access logs.** ALB access logs are in the S3 bucket wired by
   `terraform/alb.tf`.
5. **Open a security issue** (private) with the forensic snapshot and
   containment steps taken.

## Logging and telemetry locations

Resource names below use `<prefix>` = `<project>-<environment>` (defaults:
`impala-bridge-staging`).

| Signal | Where | Notes |
|---|---|---|
| Structured app logs | CloudWatch log groups `/ecs/<prefix>-server` and `/ecs/<prefix>-worker` (`terraform output -raw server_log_group` / `worker_log_group`) | JSON; filter with Logs Insights |
| Traces | SigNoz (if `signoz_endpoint` configured) | Service: `impala-bridge` |
| Metrics | CloudWatch or SigNoz | Key metrics in `telemetry.rs::AppMetrics` |
| ALB access logs | S3 bucket `<prefix>-alb-logs-<account-id>` (`terraform/s3.tf`; there is no Terraform output for it) | Partitioned by date under the `alb/` prefix |
| VPC flow logs | CloudWatch log group `/vpc/<prefix>-flow-logs` | REJECT traffic only |
| WAF | CloudWatch dashboards | Blocked request details |
| SQS DLQ | CloudWatch alarm `<prefix>-worker-dlq` (when alert_email is set) | |

## Escalation

- Infrastructure / AWS: cloud platform on-call.
- Stellar network issues: Stellar status + upstream operators.
- Third-party notification providers (Twilio, SES, FCM): their status pages.
- Security: see `impala-bridge/SECURITY.md` for the security-reporting path.
