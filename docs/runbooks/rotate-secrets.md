# Runbook — Rotating secrets

**Audience:** engineer executing a scheduled rotation OR incident-response
containment.

**Blast radius matters.** Plan rotations so they don't log everyone out at
once unless that's the intent.

## Inventory

| Secret | Purpose | Blast radius on rotation |
|---|---|---|
| `JWT_SECRET` | HMAC-SHA256 key for all bridge-issued JWTs | All refresh + temporal tokens invalidated; every user must re-auth |
| `DATABASE_URL` (or the password inside it) | Bridge → RDS auth | Bridge tasks restart on refresh |
| `REDIS_AUTH_TOKEN` (if ElastiCache AUTH is enabled) | Bridge → Redis auth | Same as DB |
| `OKTA_CLIENT_SECRET` | OIDC client secret for Okta SSO | Okta-authenticated users cannot log in until both sides are aligned |
| `TWILIO_TOKEN` | Outbound SMS | SMS notifications silently fail until rotated on both ends |
| `FCM_SERVICE_ACCOUNT_KEY` | Mobile push notifications | Push notifications fail |
| `SES identity credentials` | Outbound email | Email notifications fail |
| `VAULT wrapping token` | Unwraps DB URL from Vault on startup | Bridge fails to start on next restart |

## General rotation workflow

Rotations happen in two phases: **prepare** (update the secret manager
entry with the new value; do *not* restart the app) and **activate**
(restart the ECS service so tasks pick up the new value). Some secrets
need an overlap window (both old and new accepted simultaneously).

### JWT_SECRET

**There is no overlap window.** Rotating this secret invalidates every
existing token. Choose a maintenance window OR accept that all users will
be logged out.

1. Generate a new secret:
    ```
    openssl rand -hex 32
    ```
2. Write it to Secrets Manager:
    ```
    aws secretsmanager put-secret-value \
      --secret-id impala-bridge/jwt-secret \
      --secret-string <new>
    ```
3. Force a new ECS deployment so tasks pick up the new value:
    ```
    aws ecs update-service \
      --cluster impala-bridge \
      --service impala-bridge-server \
      --force-new-deployment
    aws ecs update-service \
      --cluster impala-bridge \
      --service impala-bridge-worker \
      --force-new-deployment
    ```
4. Announce to users that they need to log in again.
5. Confirm via `/healthz` + a sample login flow.

### DATABASE_URL (password rotation)

1. In RDS console, **modify master password** (or use `ALTER USER
   impala_bridge WITH PASSWORD '<new>'` if you use a non-master user).
2. Update the `DATABASE_URL` secret in Secrets Manager to the new password.
3. Force ECS redeploy as above. Task-defs reference the secret; new tasks
   pick up the new value on start.
4. Confirm via `/healthz`.

If using Vault unwrapping (`DATABASE_URL_WRAPPED`): write the new URL into
Vault, re-wrap it, set `DATABASE_URL_WRAPPED` env-var on the task to the
new wrapping token, redeploy.

### OKTA_CLIENT_SECRET

1. In the Okta admin console, **generate** a new client secret for the
   bridge's OIDC application. Okta retains both for a short overlap.
2. Update Secrets Manager, redeploy ECS. New logins work immediately with
   the new secret.
3. Wait until no existing sessions are using Okta-issued tokens (check
   `/auth/okta` usage in logs), then **revoke** the old secret in Okta.
4. Smoke-test: log out, log back in via Okta.

### TWILIO_TOKEN / SES credentials / FCM_SERVICE_ACCOUNT_KEY

These are delivery-side credentials. Notifications in flight at rotation
time will fail — not ideal, but the blast radius is narrow.

1. Generate new credential on the provider side.
2. Update Secrets Manager.
3. Force ECS worker redeployment.
4. Send a test notification (e.g. by triggering a login event on a test
   account with an SMS subscription).
5. Revoke the old credential on the provider side.

## Emergency rotation (suspected compromise)

Skip all overlap windows. Do the rotations in parallel across all
candidates for the breach, then force a full ECS redeploy. Every user will
be logged out; every in-flight notification will fail. This is preferable
to letting an attacker with stolen credentials continue.

Order suggested:
1. `JWT_SECRET` (kills all tokens).
2. `DATABASE_URL` password.
3. Okta, Twilio, SES, FCM, Vault.
4. Rotate IAM keys (if any) for the bridge's task role — AWS console →
   IAM → Roles → impala-bridge-task-role → Security credentials.

After rotation: see `incident-response.md` for forensic capture and
post-mortem steps.
