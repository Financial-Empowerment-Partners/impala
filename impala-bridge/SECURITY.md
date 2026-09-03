# Security Architecture

## Authentication

### Two-Token JWT Strategy

impala-bridge uses a two-token JWT approach:

- **Refresh token** (14-day TTL): Issued via `POST /token` with username/password (the response also includes a temporal token, saving clients a round trip). Used only to obtain temporal tokens, and **single-use** (see Refresh-Token Rotation below).
- **Temporal token** (1-hour TTL): Issued via `POST /token` with a valid refresh token. Used for all authenticated API calls.

Both tokens use HS256 with a mandatory 32+ character secret (`JWT_SECRET`) and carry: a unique JTI, issuer `impala-bridge` (validated), audience `impala-bridge-api` (validated), a family id `fid` (shared by every token descended from one credential login), and a `kid` header fingerprinting the signing secret. Tokens minted before the aud/fid rollout fail to decode by design (hard cutover — one forced re-login).

### JWT Secret Rotation

`JWT_SECRET` signs and verifies; the optional `JWT_SECRET_PREVIOUS` is **verify-only**. Rotation runbook: set `JWT_SECRET_PREVIOUS` to the old secret and `JWT_SECRET` to the new one, run until tokens signed with the old secret have aged out (≤ 14 days), then unset `JWT_SECRET_PREVIOUS`. Verification selects the key by the token's `kid` header (kid-less legacy tokens fall back to try-primary-then-previous only on an invalid-signature error). Startup validates both secrets (≥ 32 chars, must differ).

### Refresh-Token Rotation & Reuse Detection

Refresh tokens are strictly single-use. Every `POST /token {refresh_token}` exchange:

1. Validates the token (signature, issuer, audience, expiry, type) and checks the revocation surfaces below.
2. Marks the presented JTI as rotated in Redis (`impala:rotated:{jti}`, fail-closed — if the marker write fails, nothing is minted, so two live refresh tokens can never coexist).
3. Mints a replacement refresh + temporal pair inside the **same family** (`fid` inherited).

Presenting a rotated-out refresh token again is treated as theft: the entire family is revoked (`impala:revoked_family:{fid}`), the `auth.token_reuse_detected` metric increments, and the request gets a 401. There is deliberately **no grace window** — in-repo clients refresh serially, and a lost race logs the whole family out, which is the safe failure mode.

### Token Revocation

`POST /logout` revokes the presented token by adding its JTI to a Redis blacklist (strict: a logout that fails to record the revocation returns an error, never a silent success). The blacklist entry expires when the token would have expired naturally. Every authenticated request checks — in one pipelined, fail-closed Redis round trip — the revoked-JTI list, the revoked-family list, and the account's logout-everywhere epoch.

### Logout Everywhere

`POST /logout/all` (authenticated via bearer or cookie session) bumps the account's auth epoch (`impala:auth_epoch:{account_id}`, TTL = the 14-day refresh lifetime). Every JWT with `iat <=` epoch and every session created at or before it is rejected from then on — this retroactively kills all outstanding tokens on all devices. Caveat: the epoch lives in Redis; a Redis flush/failover before the key's TTL re-enables not-yet-expired tokens. Run Redis with `noeviction` (the Terraform ElastiCache parameter group does this) and treat a Redis rebuild as a `JWT_SECRET` rotation event.

### Browser Cookie Sessions & CSRF

Browser clients (the impala-ui dashboard) authenticate with an HttpOnly cookie session instead of bearer tokens, so credentials are out of reach of any script (XSS):

- **`POST /session/login {username, password}`** — same credential check, rate limits, and lockout as `/authenticate`; sets the session cookie and returns `{account_id, is_admin, csrf_token}`. The Okta exchange supports the same via `POST /auth/okta {okta_token, cookie_mode: true}`.
- **Cookie**: `__Host-impala_session` with `HttpOnly; Secure; SameSite=Strict; Path=/` and no Max-Age (browser-session cookie). `SESSION_COOKIE_SECURE=false` (local plain-HTTP development only) drops `Secure` and the `__Host-` prefix.
- **Server-side record**: a Redis hash keyed by `sha256(session id)` — a Redis dump never yields usable cookies — holding the account id, CSRF token, creation time, and admin flag. Sliding 30-minute idle TTL, capped at a 12-hour absolute lifetime. `GET /session/me` returns the identity + CSRF token (page-reload rehydration); `POST /session/logout` deletes the record (fail-closed).
- **CSRF**: a server-stored synchronizer token, required as `X-CSRF-Token` on every cookie-authenticated unsafe-method request and compared in constant time. The check runs inside the shared auth extractor, so no cookie-authenticated route can skip it. Bearer requests are exempt (they carry no ambient credential). Rejections increment `session.csrf_rejected`.
- **No downgrade**: when an `Authorization` header is present it must validate as a temporal JWT — there is no fallback to the cookie path on a bad bearer token.
- **Admin freshness**: the session path re-derives `is_admin` from the `ADMIN_ACCOUNT_IDS` allowlist on every request, so admin revocation is immediate for browser sessions (vs ≤ 1 h staleness on the JWT path).

### Federated Token Exchange (Okta / Google / GitHub)

Federated identities are exchanged for local refresh + temporal token pairs —
the response shape is identical to `POST /token`:

- **`POST /auth/okta {okta_token}`**: the access token is validated against the
  Okta org's JWKS (RS256, issuer, audience = `OKTA_CLIENT_ID`). Account id:
  email > `preferred_username` > `okta:{sub}`.
- **`POST /auth/google {id_token}`**: the ID token is validated against
  Google's JWKS (RS256, issuer `https://accounts.google.com` or
  `accounts.google.com`, audience = `GOOGLE_CLIENT_ID`, expiry). Account id:
  the lowercased email **only when Google asserts `email_verified == true`**,
  otherwise `google:{sub}` — an unverified attacker-chosen email can never
  claim an existing email-keyed account. `GET /auth/google/config` exposes
  `{enabled, client_id}` to clients.
- **`POST /auth/github`** (gated on `GITHUB_AUTH_ENABLED`) accepts two shapes:
  `{code, redirect_uri}` — the bridge exchanges the OAuth authorization code
  at GitHub's token endpoint using `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`,
  so the **client secret never ships in a client binary** — or legacy
  `{access_token}`. Either way the resulting token is verified by calling
  `GET {GITHUB_API_URL}/user`; account id is the immutable `github:{id}`
  (numeric user id — logins can be renamed/reused). Before any outbound
  GitHub call, a **pre-call rate limit keyed on `hex(sha256(credential))[..16]`**
  bounds how often any one credential can make the bridge relay requests to
  GitHub (DoS/relay guard); the raw credential never appears in Redis keys or
  logs. The response adds optional `login`/`display_name` fields.

All three handlers share okta-pattern auto-provisioning: account + auth rows
are upserted in one transaction with a **random argon2 hash** (federated users
have no usable password) and `auth_provider` set to the provider name.

**Legacy migration**: older clients derived a password as
`SHA-256(token_or_card_id).take(32)` and used the username+password path. The
first federated login for such an account flips `auth_provider` away from
`local`, and `/authenticate` rejects password login for non-`local` providers —
so the derived-password path is disabled **one-way** on first exchange. Do not
add new consumers of the derived-password scheme.

### Card Challenge-Response Authentication

Physical cards authenticate via a challenge-response exchange
(`src/handlers/card_auth.rs`):

1. **`POST /auth/card/challenge {card_id}`** → `{success, challenge, expires_in: 60}`.
   The 32-byte challenge (64 hex chars) is generated from a CSPRNG and joins
   the card's **bounded set of outstanding challenges** in Redis
   (`impala:card_challenges:{card_id}`: at most 5 live at once, each with its
   own 60s expiry, the oldest evicted on overflow), stored **fail-closed** (no
   challenge is issued if Redis is down). A set rather than a single slot
   because a card UID is public (readable over NFC): with one overwritable
   slot, anyone who knew a UID could clobber or consume the legitimate
   holder's challenge from anywhere. Challenges are issued unconditionally —
   the response never reveals whether a card is registered (no enumeration
   oracle).
2. The card signs ECDSA-SHA256 (secp256r1, ASN.1 DER) over exactly
   `"IMPALA-AUTH:" (12 bytes) || accountId (16 bytes, RFC-4122 big-endian) ||
   challenge` — the pinned cross-stream contract (`CARD_AUTH_DOMAIN_PREFIX` in
   `src/constants.rs` ⇄ `AUTH_DOMAIN_TAG` in `ImpalaApplet.java`). The domain
   prefix guarantees an auth signature can never be replayed as a transfer
   signature.
3. **`POST /auth/card {card_id, signature}`**: the live challenges are read
   without consuming anything, the active card row supplies the account id
   and the 65-byte uncompressed SEC1 public key, and the signature is verified
   with aws-lc-rs against each live challenge (newest first — one signature
   can verify against at most one 32-byte random challenge). The challenge
   that verifies is then consumed atomically with Redis `LREM` (**single-use**
   — of two concurrent presentations of the same signature exactly one
   removes the entry; the other finds it gone and is refused as a replay).
   Success returns the standard token pair. Every failure mode (unknown card,
   no live challenge, bad signature, replay) returns the same generic 401, but
   **only a bad signature over a live challenge counts** toward the
   `(card, client source)` lockout (5 failures → 15 minutes; see Account
   Lockout). A missing challenge or an unknown card is not a guess — counting
   those let anyone who knew a UID lock the holder out with empty
   submissions. Success clears the counter for that source.

There is **no auto-provisioning** on the card path: a registered card implies
an existing account (FK from migration 017), and card registration itself
requires an authenticated session. Card-auth accounts must use UUID account
ids (the signed message embeds the on-card 16-byte account UUID).

### Account Lockout

After 5 failed attempts, the identity is locked for 15 minutes **for the
client source the failures came from**. Counters live in Redis under
`impala:lockout:{identity}:{sha256(source)[..16]}` — per account ID for the
password paths, per card ID for `/auth/card`, and per account/MFA-type pair
for `/mfa/verify` (`impala:mfa_attempts:{account}:{type}:{digest}`). A
successful login from a source clears that source's counter.

Only a **real guess** counts: a wrong password against a stored one, a bad
signature over a live card challenge, a wrong MFA code against an outstanding
factor. An unknown username, a federated (SSO) account presented a password,
an unknown card, a missing challenge, an absent or disabled MFA enrollment
and a never-issued SMS code all get the same generic response and the same
argon2 cost as a wrong password (nothing is observable on the wire), but do
not increment anything — counting them let a caller pre-lock an identity that
had not been provisioned yet, or lock a federated account's SSO path with
passwords it does not have.

The federated exchanges (`/auth/okta`, `/auth/google`, `/auth/github`,
`/auth/sso/{provider}`) never increment the counter (they prove an IdP token)
but honour it for the same `(account, source)` pair, so a source that earned
a lock on an account is refused every login path for that account.

**Trade-off, stated plainly.** Keying on `(identity, source)` means a guesser
locks an identity only for itself. What bounds a guesser spread across many
sources is the **per-identity rate limit** (10 requests / 60 s per username,
card, or account+MFA-type), not the lockout: at most 10 guesses a minute
against any one identity, from anywhere. The residual exposure is the shared
NAT: peers behind one egress IP share a source, so a guesser on an office
network can still lock an identity for everyone on that network for 15
minutes. That is the previous behaviour confined to the guesser's own
network instead of the whole internet, and it is accepted.

The source is attributed by `client_source.rs` (the `ClientSource`
extractor): with `TRUSTED_PROXY_HOPS = N` (default 1, the ALB) it is the
N-th `X-Forwarded-For` entry **from the right** — the address the outermost
trusted proxy appended — never the leftmost entry or `X-Real-Ip`, both of
which the sender writes. With `TRUSTED_PROXY_HOPS = 0` (a directly exposed
bridge, local docker-compose) the header is ignored and the TCP peer is the
source. A chain shorter than N falls back to the peer; a value that is not an
IP address lands in a single narrow `unknown` bucket rather than minting a
fresh one per forged header.

### Rate Limiting

Authentication endpoints (`/authenticate`, `/token`, `/session/login`, `/auth/okta`, `/auth/google`, `/auth/github`, `/auth/card`, `/auth/card/challenge`, `/auth/sso/{provider}`) enforce per-identity rate limits of 10 requests per 60-second window via Redis (SSO is rate-limited per provider; lockout is per `(account, source)` across providers). `/auth/github` additionally rate-limits per credential hash **before** calling the GitHub API.

The pre-auth endpoints that accept a caller-chosen identity (`/token` password
flow — not refresh rotation — `/session/login`, `/authenticate`,
`/auth/card/challenge`, `/auth/card`, `/mfa/verify`) additionally share a
**per-client-source** budget of 30 requests / 60 s (`impala:rate:preauth_src:{source}`,
source attributed as described under Account Lockout), checked before any
per-identity budget is spent. This bounds how many identities one source can
touch per minute, which the WAF's coarse per-IP rule (thousands per five
minutes) cannot, and it is what stops a single source from walking the
username space at a trickle. The unverified-webhook limit on `/webhooks/*`
keys on the same attribution.

All authenticated endpoints (GET included) additionally enforce a per-account limit of 100 requests / 60 s, keyed on the validated identity and enforced inside the shared auth-validation path after full validation — only valid credentials consume quota. Rejections return 429 with `Retry-After`.

MFA verification (`/mfa/verify`) enforces brute force protection with a lockout after 5 failed attempts per account/MFA-type pair, per client source.

### Password verification cost bound and timing equalization

Every password check is an argon2id run (~19 MiB, ~10 ms). Because the
per-identity rate limits are keyed on the *submitted username*, a caller who
rotates usernames gets a fresh budget each time (the per-source budget above
caps that at 30 a minute per source, but not across sources) — so the argon2
work itself is bounded process-wide (`ARGON2_MAX_CONCURRENT`, 8 concurrent runs; a request
waits up to `ARGON2_QUEUE_WAIT_SECS` for a slot and is otherwise shed with
503 `service_unavailable`). The permit is held by the blocking thread that
does the work, not by the request future, so a request timeout cannot
release it early. This is what stops an unauthenticated client from driving
the task out of memory.

Account existence is not observable from timing or status: the
account-not-found and federated-account branches run exactly one verify
against a precomputed dummy hash of the same cost as a real verify (a single
run — the earlier generate-and-verify pair took twice as long), return the
same generic body (`/token`: 200 `success:false`; `/session/login`,
`/authenticate`: the same generic failure as a wrong password), and shed
identically under saturation.

All Redis-backed checks above are **fail-closed**: when Redis is unreachable the request is rejected, never silently allowed.

## Authorization

All data-modifying endpoints enforce account ownership:

- **Card, MFA, Notify endpoints**: Verify `payload.account_id == user.account_id` before processing.
- **Account endpoints**: `GET /account` scopes queries to the authenticated user's account. `PUT /account` enforces ownership via SQL constraints.
- **Delete operations**: Card deletion and notify updates include `account_id` in the SQL WHERE clause to prevent cross-account modification.
- **Notification subscriptions**: All CRUD operations are scoped to `user.account_id`.

The `require_owner()` helper in `auth.rs` provides consistent ownership checks across handlers. The dynamic UPDATE statements for `PUT /account` and `PUT /notify` are generated by `sqlx::QueryBuilder` helpers whose ownership-WHERE invariant (every generated statement pins the caller's account id) is pinned by unit tests over every field combination.

`rows_affected` in update responses is deliberately retained: the ownership WHERE invariant scopes every update to the caller's own rows, so the value is always 0 or 1 for the caller's own data and discloses exactly the same bit as the `success` field — it cannot probe other accounts' existence.

### Payala Sync (reserve/mirror)

`POST /sync/payala` ingests batches of offline Payala transactions as **unverified
client assertions**: amounts, currencies, and digests are taken on the caller's
word, gated only by JWT ownership (`require_owner`) and rate limiting. Because
writes are strictly owner-scoped, a caller can only fabricate *their own*
reserve balances or mirrored history. The bridge performs no verification of
the card's ECDSA transfer signatures, and nothing recorded by sync is ever
submitted to Horizon or Soroban — reserve balances and mirrored rows must stay
quarantined from anything that moves value until a server-side verification
step exists. Batches are idempotent per `(account, payala_tx_id)`; replays
whose stored amount/currency differ from the submission are surfaced as
`conflicting` and logged as a tamper/corruption signal. Mirror-mode rows are
tagged `origin = 'payala_sync'` server-side (never settable via any request
body) so they remain distinguishable from client-posted `POST /transaction`
rows. Relatedly, non-admin `POST /transaction` callers may only supply a
`source_account` they own, so one account cannot plant rows in another
account's transaction listing.

## Input Validation

- **Stellar account IDs**: Must be 56 characters, start with 'G', alphanumeric only.
- **Email addresses**: RFC-compliant format validation (local@domain.tld).
- **Phone numbers**: E.164 format required (+country digits, 8-16 chars).
- **Callback URLs**: SSRF prevention blocks localhost, private IPs, link-local, and cloud metadata endpoints.
- **LDAP inputs**: Special characters escaped per RFC 4515.
- **Name fields**: Limited to 64 characters.

## Request Limits

- **Body size**: 1 MB maximum enforced via `RequestBodyLimitLayer`.
- **Request timeout**: global 30 s deadline (`REQUEST_TIMEOUT_SECS`), enforced via tower-http's `TimeoutLayer` (408 on expiry). Safe because the bridge serves only request/response JSON — the SSE/TCP streams are outbound consumers, not server-streamed responses.
- **Rate limiting**: Per-endpoint Redis-backed counters with configurable windows.

## Transport Security

### HTTP Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### CORS

CORS is configurable via `CORS_ALLOWED_ORIGINS`. Wildcard (`*`) is a **hard startup error** when `STELLAR_NETWORK=pubnet` (the process exits); it is allowed, with an info log, on testnet. Production deployments must specify explicit origins.

### TLS

TLS is terminated at the ALB with an ACM certificate. When `certificate_arn` is set, HTTP traffic is redirected to HTTPS via 301.

## Infrastructure Security

### Network

- **VPC**: Private subnets for ECS tasks, RDS, and ElastiCache. NAT gateway per AZ for outbound traffic.
- **Security groups**: ECS egress restricted to specific ports (5432 for RDS, 6379 for Redis, 443 for HTTPS).
- **WAF**: AWS WAFv2 web ACL on every ALB (Terraform toggle `waf_enabled`, **default on**) with managed rule groups (Common, Known Bad Inputs, SQLi) and an IP rate-based block rule.
- **VPC Flow Logs**: REJECT traffic logged to CloudWatch on the testnet/live stacks (Terraform toggle `flow_logs_enabled`, enabled in both stack files); the impala stack logs ALL traffic.

### Encryption

- **At rest**: RDS (KMS), S3 (KMS), ElastiCache (at-rest encryption enabled).
- **In transit**: ALB (TLS), ElastiCache (transit encryption enabled via `rediss://` TLS connections).

### Secrets Management

- JWT secret and database URL stored in AWS Secrets Manager.
- Optional HashiCorp Vault / OpenBao integration for database credentials (cubbyhole response unwrapping) and custodial-seed Transit encryption. OpenBao is an API-compatible Vault fork; `BAO_*` env names are accepted alongside `VAULT_*`.
- `JWT_SECRET` requires minimum 32 characters (enforced at startup); `JWT_SECRET_PREVIOUS` enables zero-downtime rotation (see the rotation runbook under Authentication).
- `GITHUB_CLIENT_SECRET` (OAuth code exchange) lives only on the bridge — never in client binaries.

### Container Security

- Non-root user (UID 1000) in Docker image.
- Read-only root filesystem on ECS tasks.
- Health checks configured for container monitoring.
- ECR image scanning enabled; immutable tags prevent tag overwriting.

### Disaster Recovery

- Cross-region RDS read replica (when `dr_enabled = true`).
- S3 cross-region replication for backups.
- ECR cross-region replication.
- Route 53 failover DNS with health checks.
- Full DR region ECS cluster with independent ALB.

## Incident Response

### Token Compromise

1. User calls `POST /logout` to revoke the compromised token, or `POST /logout/all` to revoke every outstanding token and session for the account at once.
2. Refresh-token theft is also detected automatically: any reuse of a rotated-out refresh token revokes the whole token family.
3. For a suspected `JWT_SECRET` compromise, rotate the secret via `JWT_SECRET` + `JWT_SECRET_PREVIOUS` (or rotate without the previous secret to invalidate all tokens immediately).

### Account Compromise

1. Account lockout engages automatically after 5 failed attempts from a client source.
2. MFA verification lockout prevents brute force of TOTP/SMS codes.

### Dependency Vulnerabilities

`cargo audit` runs in CI to check for known vulnerabilities in dependencies. Address findings promptly.

## Admin role & webhook event feed

### Admin authorization

Admin privilege is carried by an `is_admin` JWT claim. It is **server-derived**
at every token issuance from the `ADMIN_ACCOUNT_IDS` allowlist (comma-separated
account IDs) — clients cannot set it because tokens are HS256-signed. It is
re-derived on each issuance (including refresh→temporal rotation), so adding or
removing an admin takes effect within one temporal-token lifetime (≤1h) even for
a long-lived refresh token; for immediate revocation, revoke the token's JTI via
`POST /logout`.

The `AdminUser` extractor gates every `/admin/*` route plus the `/sync` and
`/subscribe` endpoints. It applies the same checks as `AuthenticatedUser`
(temporal token, issuer, fail-closed JTI revocation) and additionally requires
`is_admin == true`, returning `403 Forbidden` otherwise. Because the gate is an
extractor, an admin route cannot accidentally omit the check.

### Webhook delivery security

Account/transaction state changes are appended to a durable `event_outbox` (in
the same DB transaction as the change) and delivered to admin-registered webhooks
by an in-process worker:

- **Signing**: every POST carries `X-Impala-Signature: sha256=<hex>` where the
  value is `HMAC_SHA256(secret, "{X-Impala-Timestamp}.{raw_body}")`. The secret is
  generated server-side and returned **once** at registration. Receivers must
  recompute the HMAC over the raw body and the `X-Impala-Timestamp` header,
  compare in **constant time**, and reject timestamps outside a ±5-minute window
  (replay protection).
- **SSRF**: webhook URLs are validated (localhost, private/link-local IPs, cloud
  metadata, non-HTTP schemes blocked) at registration **and** before every
  delivery (DNS-rebinding defense).
- **Delivery**: at-least-once with exponential backoff; a delivery is marked
  `failed` after `ADMIN_WEBHOOK_MAX_ATTEMPTS`, and a webhook is auto-disabled
  after `ADMIN_WEBHOOK_DISABLE_THRESHOLD` consecutive failures. Pending
  deliveries are leased (`FOR UPDATE ... SKIP LOCKED`, `next_attempt_at`
  pushed out) so the worker on every server task claims disjoint rows, but a
  lost response or a lapsed lease can still re-POST an event: receivers must
  deduplicate on `X-Impala-Event-Id`, which is stable across retries.
- **Least disclosure**: payloads never include secrets/PII — no MFA secret, no
  raw device token (platform only). The signing secret is never returned by
  `GET /admin/webhooks`. Store it in Vault/KMS for production.
