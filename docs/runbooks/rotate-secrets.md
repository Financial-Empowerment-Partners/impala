# Runbook — Rotating secrets

**Audience:** engineer executing a scheduled rotation OR incident-response
containment.

**Blast radius matters.** Plan rotations so they don't log everyone out at
once unless that's the intent.

## Inventory

| Secret | Purpose | Blast radius on rotation |
|---|---|---|
| `JWT_SECRET` | HMAC-SHA256 key for all bridge-issued JWTs | None if rotated with the `JWT_SECRET_PREVIOUS` overlap (below); rotating without it invalidates every token and logs every user out |
| `DATABASE_URL` (or the password inside it) | Bridge → RDS auth | Bridge tasks restart on refresh |
| `REDIS_AUTH_TOKEN` (if ElastiCache AUTH is enabled) | Bridge → Redis auth | Same as DB |
| `TWILIO_TOKEN` | Outbound SMS | SMS notifications silently fail until rotated on both ends |
| `FCM_SERVICE_ACCOUNT_KEY` | Mobile push notifications | Push notifications fail |
| `SES identity credentials` | Outbound email | Email notifications fail |
| `Vault/OpenBao wrapping token` | Unwraps DB URL from Vault/OpenBao on startup | Bridge fails to start on next restart |
| `Vault/OpenBao Transit token` | Seed encrypt/decrypt (`SEED_PROTECTION_BACKEND=vault\|openbao`) | Custodial sign/import fails until rotated |

> **Exchange provider credentials and custodial Stellar seeds are not in this
> table.** When `KEY_IMPORT_ENABLED=true` they are rotated through
> `/admin/keys/*` and `/admin/stellar-seeds/*` rather than through the secret
> manager, and the rules are different enough to warrant their own runbook —
> including the one that catches people out: **a rotation is not finished until
> the old environment variable is removed**, because turning `KEY_IMPORT_ENABLED`
> off reverts the whole fleet to it. See `import-keys.md`.

## General rotation workflow

Rotations happen in two phases: **prepare** (update the secret manager
entry with the new value; do *not* restart the app) and **activate**
(restart the ECS service so tasks pick up the new value). Some secrets
need an overlap window (both old and new accepted simultaneously).

### JWT_SECRET

**Scheduled rotation is zero-downtime.** The bridge supports a verify-only
overlap secret: `JWT_SECRET` signs and verifies every new token, and the
optional `JWT_SECRET_PREVIOUS` is **verify-only** — tokens signed with the
old secret keep verifying while they age out. Verification selects the key
by the token's `kid` header (`impala-bridge/src/jwt.rs`; the env var is
read at startup in `main.rs`). Startup validates both secrets: ≥ 32
characters, and the two must differ. Nobody gets logged out.

**Step 1 — deploy the overlap:**

1. Generate a new secret:
    ```
    openssl rand -hex 32
    ```
2. Set `JWT_SECRET=<new>` and `JWT_SECRET_PREVIOUS=<old>` in the task
   environment, then force a new ECS deployment so tasks pick up both:
    ```
    aws secretsmanager put-secret-value \
      --secret-id impala-bridge/jwt-secret \
      --secret-string <new>
    aws ecs update-service \
      --cluster impala-bridge \
      --service impala-bridge-server \
      --force-new-deployment
    aws ecs update-service \
      --cluster impala-bridge \
      --service impala-bridge-worker \
      --force-new-deployment
    ```
3. Confirm via `/healthz` + a sample login flow, and confirm an
   already-logged-in session still refreshes.

**Step 2 — retire the old secret:** after all tokens signed with the old
secret have aged out — at most the 14-day refresh-token TTL — unset
`JWT_SECRET_PREVIOUS` and redeploy. The rotation is not finished until the
previous secret is removed (the bridge refuses to start if the two secrets
are equal, so a forgotten `JWT_SECRET_PREVIOUS` surfaces on the *next*
rotation at the latest).

> **Known gap:** the Terraform task definitions currently plumb only
> `JWT_SECRET` (`terraform/ecs.tf`, `terraform/modules/ecs-stack/main.tf`)
> — there is no `JWT_SECRET_PREVIOUS` entry to populate. To use the overlap
> on ECS you must add the variable to the task definition (or Terraform)
> yourself; `impala-bridge/docker-compose.yml` already passes it through
> for local stacks.

**No-overlap variant:** rotating `JWT_SECRET` *without* setting
`JWT_SECRET_PREVIOUS` invalidates every refresh and temporal token at once
and logs every user, admin session, and API client out. That is the correct
move for a suspected secret compromise (see "Emergency rotation" below) —
not for scheduled rotation. It is also **mandatory after any Redis data
loss** (DR failover onto the empty DR group, a flush, a restore from
snapshot): Redis is the sole store of token revocations, refresh rotations
and auth epochs, so losing it silently resurrects every token they had
killed, and this rotation is the only global kill. See "Redis lost its data"
in `incident-response.md`.

This matches the rotation runbook in `impala-bridge/SECURITY.md`
("Authentication" section) and the notes in
`impala-bridge/examples/api_examples.sh`.

### DATABASE_URL (password rotation)

1. In RDS console, **modify master password** (or use `ALTER USER
   impala_bridge WITH PASSWORD '<new>'` if you use a non-master user).
2. Update the `DATABASE_URL` secret in Secrets Manager to the new password.
3. Force ECS redeploy as above. Task-defs reference the secret; new tasks
   pick up the new value on start.
4. Confirm via `/healthz`.

If using Vault/OpenBao unwrapping (`DATABASE_URL_WRAPPED`): write the new URL into
Vault/OpenBao, re-wrap it, set `DATABASE_URL_WRAPPED` env-var on the task to the
new wrapping token, redeploy.

### OIDC signing keys (Okta / Auth0 / Duo SSO)

**Nothing to rotate bridge-side.** The web SSO flow is a **public PKCE client**
— the bridge holds **no OIDC client secret** (it reads only
`{PROVIDER}_ISSUER_URL` / `{PROVIDER}_CLIENT_ID` / `{PROVIDER}_AUDIENCE`, all
non-secret). Token signing keys are owned and rotated by the IdP, and the bridge
picks up new keys automatically via its JWKS refresh (`{PROVIDER}_JWKS_REFRESH_SECS`,
plus a one-shot refresh on an unknown `kid`). No redeploy is required when an IdP
rotates keys.

> Exception: the **Duo 2FA (Universal Prompt / OIDC Auth API)** integration *is* a
> confidential client with a `DUO_2FA_CLIENT_SECRET`. Rotate it in the Duo Admin
> Panel, update Secrets Manager, and redeploy — Duo retains the old secret for a
> short overlap.

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
1. `JWT_SECRET` — rotate **without** `JWT_SECRET_PREVIOUS` (kills all tokens,
   including any the attacker minted).
2. `DATABASE_URL` password.
3. Exchange provider credentials — **revoke at the provider first**, then
   `impalactl keys revoke <kind>`, then scrub the environment variables (see
   `import-keys.md`). Bridge-side revocation does not invalidate a key upstream.
4. Twilio, SES, FCM, Vault/OpenBao, `DUO_2FA_CLIENT_SECRET` (if Duo 2FA is enabled).
5. Rotate IAM keys (if any) for the bridge's task role — AWS console →
   IAM → Roles → impala-bridge-task-role → Security credentials.

After rotation: see `incident-response.md` for forensic capture and
post-mortem steps.
