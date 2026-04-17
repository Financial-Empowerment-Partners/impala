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

1. **Check dashboards.** CloudWatch `impala-bridge-ops` and SigNoz service
   `impala-bridge`. Look for an obvious spike: 5xx rate, latency p99, CPU,
   memory, DB connections, Redis errors, SQS backlog, DLQ depth.
2. **Check `/healthz` and `/readyz`** from outside the VPC (e.g. your
   laptop). If one fails, note which of `database` or `redis` in the
   response body is `error`.
3. **Check ECS task count.** Lower-than-desired = tasks are crash-looping.
   Same-as-desired but with elevated errors = application bug, not infra.
4. **Announce in the incident channel** what you see, with timestamp.
5. **Do not change prod configuration yet.** Observe first.

## Common failure modes

### `/readyz` is 503

The probe fails if either the Postgres SELECT 1 query or the Redis PING
fails. Check the response body to identify which.

- **DB unhealthy:** check RDS status in console. Failover if Multi-AZ hasn't
  already (it should be automatic). If RDS is healthy, look at the ECS
  security group — a SG change could have severed the egress path.
- **Redis unhealthy:** check ElastiCache status. The application is
  fail-closed on Redis (rate limits, lockouts, token revocation all fail
  with 5xx when Redis is down). Auth will be impacted immediately.

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
2. **Check JWT_SECRET.** If it was just rotated, all existing tokens are
   invalidated — users need to log in again. This is *expected*, not an
   incident. If a partial rotation left services with mismatched secrets,
   see `rotate-secrets.md`.
3. **Check Okta provider** via `/auth/okta/config`. If it returns 500, the
   bridge couldn't refresh the JWKS.
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
   blast radius: DB URL, Vault wrapping tokens, Twilio, SES, FCM, Okta
   client secret.
4. **Review access logs.** ALB access logs are in the S3 bucket wired by
   `terraform/alb.tf`.
5. **Open a security issue** (private) with the forensic snapshot and
   containment steps taken.

## Logging and telemetry locations

| Signal | Where | Notes |
|---|---|---|
| Structured app logs | CloudWatch log group `/ecs/impala-bridge` | JSON; filter with Logs Insights |
| Traces | SigNoz (if `signoz_endpoint` configured) | Service: `impala-bridge` |
| Metrics | CloudWatch or SigNoz | Key metrics in `telemetry.rs::AppMetrics` |
| ALB access logs | S3 bucket (see `terraform output -raw alb_logs_bucket`) | Partitioned by date |
| VPC flow logs | CloudWatch log group `/vpc/flow-logs` | REJECT traffic only |
| WAF | CloudWatch dashboards | Blocked request details |
| SQS DLQ | CloudWatch alarm `impala-bridge-dlq-depth` (when alert_email is set) | |

## Escalation

- Infrastructure / AWS: cloud platform on-call.
- Stellar network issues: Stellar status + upstream operators.
- Third-party notification providers (Twilio, SES, FCM): their status pages.
- Security: see `impala-bridge/SECURITY.md` for the security-reporting path.
