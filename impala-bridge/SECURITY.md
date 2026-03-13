# Security Architecture

## Authentication

### Two-Token JWT Strategy

impala-bridge uses a two-token JWT approach:

- **Refresh token** (30-day TTL): Issued via `POST /token` with username/password. Used only to obtain temporal tokens.
- **Temporal token** (1-hour TTL): Issued via `POST /token` with a valid refresh token. Used for all authenticated API calls.

Both tokens use HS256 with a mandatory 32+ character secret (`JWT_SECRET`), include a unique JTI (JWT ID), and are validated for issuer (`impala-bridge`) and algorithm.

### Token Revocation

`POST /logout` revokes the current token by adding its JTI to a Redis blacklist. The blacklist entry expires when the token would have expired naturally. Every authenticated request checks the revocation list before proceeding.

### Account Lockout

After 5 failed login attempts, the account is locked for 15 minutes. Failed attempts are tracked in Redis per account ID.

### Rate Limiting

Authentication endpoints (`/authenticate`, `/token`, `/auth/okta`) enforce per-account rate limits of 10 requests per 60-second window via Redis.

MFA verification (`/mfa/verify`) enforces brute force protection with a lockout after 5 failed attempts per account/MFA-type pair.

## Authorization

All data-modifying endpoints enforce account ownership:

- **Card, MFA, Notify endpoints**: Verify `payload.account_id == user.account_id` before processing.
- **Account endpoints**: `GET /account` scopes queries to the authenticated user's account. `PUT /account` enforces ownership via SQL constraints.
- **Delete operations**: Card deletion and notify updates include `account_id` in the SQL WHERE clause to prevent cross-account modification.
- **Notification subscriptions**: All CRUD operations are scoped to `user.account_id`.

The `require_owner()` helper in `auth.rs` provides consistent ownership checks across handlers.

## Input Validation

- **Stellar account IDs**: Must be 56 characters, start with 'G', alphanumeric only.
- **Email addresses**: RFC-compliant format validation (local@domain.tld).
- **Phone numbers**: E.164 format required (+country digits, 8-16 chars).
- **Callback URLs**: SSRF prevention blocks localhost, private IPs, link-local, and cloud metadata endpoints.
- **LDAP inputs**: Special characters escaped per RFC 4515.
- **Name fields**: Limited to 64 characters.

## Request Limits

- **Body size**: 1 MB maximum enforced via `RequestBodyLimitLayer`.
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

CORS is configurable via `CORS_ALLOWED_ORIGINS`. Wildcard (`*`) triggers a startup warning. Production deployments should specify explicit origins.

### TLS

TLS is terminated at the ALB with an ACM certificate. When `certificate_arn` is set, HTTP traffic is redirected to HTTPS via 301.

## Infrastructure Security

### Network

- **VPC**: Private subnets for ECS tasks, RDS, and ElastiCache. NAT gateway per AZ for outbound traffic.
- **Security groups**: ECS egress restricted to specific ports (5432 for RDS, 6379 for Redis, 443 for HTTPS).
- **WAF**: AWS WAF on ALB with managed rule groups (Common, Known Bad Inputs, SQLi) and IP-based rate limiting.
- **VPC Flow Logs**: REJECT traffic logged to CloudWatch for security analysis.

### Encryption

- **At rest**: RDS (KMS), S3 (KMS), ElastiCache (at-rest encryption enabled).
- **In transit**: ALB (TLS), ElastiCache (transit encryption).

### Secrets Management

- JWT secret and database URL stored in AWS Secrets Manager.
- Optional HashiCorp Vault integration for database credentials (cubbyhole response unwrapping).
- `JWT_SECRET` requires minimum 32 characters (enforced at startup).

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

1. User calls `POST /logout` to revoke the compromised token.
2. If refresh token is compromised, rotate the JWT_SECRET (invalidates all tokens).

### Account Compromise

1. Account lockout engages automatically after 5 failed attempts.
2. MFA verification lockout prevents brute force of TOTP/SMS codes.

### Dependency Vulnerabilities

`cargo audit` runs in CI to check for known vulnerabilities in dependencies. Address findings promptly.
