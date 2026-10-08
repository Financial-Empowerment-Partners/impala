# SEP-10 Web Authentication — Design and Worked Scenario

> **Status: design, not implemented.** Nothing in this document exists in the
> code yet. It records the agreed shape of SEP-10 sign-in for impala-bridge —
> including Android Keystore "device keys" and what a Secure Element can and
> cannot honestly do for a Stellar key — so the work can be picked up without
> re-deriving it. Written 2026-10-07 against `main` @ `6f60935` plus the
> uncommitted card lane (card login, issuance tool, scardutil fleet files).
> Part B is a worked pilot scenario; every command in it that is not marked
> *(physical card)* or *(this design)* was run while writing.

**In one paragraph.** The bridge gains a standards-compliant
[SEP-10 v3.4.1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md)
endpoint (`GET`/`POST /auth/sep10`, `/.well-known/stellar.toml`). A holder
proves control of an Ed25519 key by signing a bridge-issued challenge
transaction and receives **house tokens** minted through the same path every
other login uses (`auth::issuance_role` → `jwt::encode_token_pair`) — but in a
**restricted audience** that old binaries reject and that only a pinned
allow-list of handlers accepts. Keys are never discovered from
`impala_account.stellar_account_id`; a key is a login credential only after
its owner **links** it from a fresh, full-strength session with proof of
possession, and the link table is the only identity source. Phase 1 serves
Android Keystore Ed25519 keys held in the TEE and gated by biometrics or the
device credential; standard wallets follow on testnet. SEP-10 is **session
authentication only**: a SEP-10 session can read its account and submit a
card-signed redemption, and nothing else — moving stored value still needs the
JavaCard's `SIGN_TRANSFER_V2` with the user PIN, custodial payments, credential
changes and "sign out everywhere" need a password, SSO or card session, and
losing the phone is a per-credential revocation, not a compromise.

Related documents: [`ARCHITECTURE.md`](../ARCHITECTURE.md) (auth paths, token
lifecycle), [`impala-bridge/SECURITY.md`](../impala-bridge/SECURITY.md),
[`impala-card/docs/transfer-protocol.md`](../impala-card/docs/transfer-protocol.md)
(card authorization), [`impala-card/scardutil/README.md`](../impala-card/scardutil/README.md)
(fleet testing), [`impala-card/docs/jdk21-javacard-kit-upgrade.md`](../impala-card/docs/jdk21-javacard-kit-upgrade.md).

---

## Part A — Design

**How this design was produced.** Four independent designs were written
against the code (security-first, standards-first, device-first and
minimal-change), each was attacked through two merged lenses (protocol and
identity; Android, tokens and operations — 63 findings, 58 accepted, 5
adjudicated as already handled), and the result was judged and merged with
repairs. The security-first design is the base: restricted-audience tokens,
credential-scoped revocation and a default-deny allow-list. Grafted onto it:
MAC-bound **stateless** login challenges (no unauthenticated Redis writes);
**signer sets pinned at enrollment** (Horizon may narrow a pinned set, never
grow it); **master-signature-first** verification (closes the enumeration and
Horizon-amplification oracles); a **two-phase key-activation** fence; **link
challenges that a standard wallet cannot sign**; and the device design's
Android fleet honesty plus the in-repo fleet sequence. Where the brief and the
code disagreed, the code won (§1). The cardlet stays the only authorizer of
stored-value transfers.

## 1. Facts verified for this design (code wins over the brief)

| # | Fact | Evidence | Consequence |
|---|---|---|---|
| F1 | Card pre-auth order is preauth_src, then (identity, source) lockout, then per-identity scope | `handlers/card_auth.rs:225-242` | Keep all three gates in that order. §8 says where each is charged. |
| F2 | `AuthContext` is a public extractor that returns raw claims. `logout_all` uses it and bumps the account epoch | `auth.rs:440-449`, `handlers/logout.rs:58-71` | The restriction is enforced inside `validate_request_auth`, not only in the wrapper extractors. |
| F3 | `TokenResponse.refresh_token` and `temporal_token` are `Option` with `skip_serializing_if` | `models.rs:627-634` | Wallet logins can omit the refresh token without a schema break. |
| F4 | `base_validation` pins `set_audience(&[JWT_AUDIENCE])`. `Claims` has no `deny_unknown_fields` | `jwt.rs:85-90`, `models.rs:7` | Older binaries reject a new audience but silently ignore a new claim. The restriction therefore rides on the audience. |
| F5 | Refresh re-derives the role through `issuance_role` on every rotation | `handlers/token.rs:185-187` | Every SEP-10 policy check has to be re-run at refresh too. |
| F6 | The default role is `view-only`, which holds no capability (`Capability::ALL` at `auth.rs:152`) | `migrations/023:5`, `auth.rs:173-188` | Clamping restricted tokens to view-only removes nothing a holder had. |
| F7 | `StellarNetwork::from_str` maps every unknown or unset value to Testnet | `config.rs:13-18` | A "testnet only" gate must test the passphrase, not the enum. |
| F8 | Redis runs `maxmemory-policy=noeviction` | `terraform/modules/ecs-stack/main.tf:430-452` | An unauthenticated per-GET Redis write is a global auth outage. Login GETs write nothing. |
| F9 | `normalize_ip` keeps the full IPv6 /128 | `client_source.rs:91-99` | SEP-10 source buckets aggregate IPv6 to /64. |
| F10 | `fetch_account_details` maps any HTTP 404 to `exists:false` | `stellar/account.rs:119-121` | A new strict fetch accepts only a Horizon problem+json `not_found`. |
| F11 | Two bridges sit behind one nginx origin at `/api/testnet/` and `/api/mainnet/`, with `location /` serving static files | `impala-ui/nginx.conf:54-76` | SEP-10 needs a dedicated per-network host. The shared proxy is unsupported. |
| F12 | Global layers wrap existing routes in this order: `.layer(cors)`, then a 1 MB body limit, then Timeout | `main.rs:879-887` | The public router is merged after Timeout and carries its own limit and timeout, so 413 and 408 carry ACAO. |
| F13 | Plaintext CLA 0x84 answers **6985** (`SCP03.unwrapCommand`). 6E00 only appears inside an applet SCP03 session | `SCP03.java:344-346`; `impala-card/scardutil/impala-dispatch.md` | The fleet sequence expects 6985. |
| F14 | `der` 0.7.10 refuses tag numbers above 30 | `der-0.7.10/src/tag/number.rs:14-19` | KeyDescription `[7xx]` tags need a hand-written bounded reader. |
| F15 | `admin.rs:221-229` bumps the epoch before commit. `card.rs:97-140` delete never bumps | — | SEP-10 revokes per credential (`cid`). The card gap is an open item. |
| F16 | The events FROZEN list pins 29 types | `events.rs:1154-1185` | Append only, and confirm the catch-up with the owners. |

## 2. Decisions at a glance

| ID | Choice |
|---|---|
| D1 | Compliant SEP-10 v3.4.1 at `GET/POST /auth/sep10`. The bridge renders `/.well-known/stellar.toml`. Each network has its own dedicated host, with home_domain = web_auth_domain. Wildcard CORS applies only on an exact three-route sub-router. |
| D2 | House JWT in a restricted audience `impala-bridge-api-sep10` with `cid`. Role is clamped to view-only. Device links get a refresh token with a fixed 24 h deadline; wallet links get the temporal token only. A new `auth_time` claim exists. No cookie mode. |
| D3 | `stellar_login_key` holds pinned signer sets. Enrollment needs a fresh full session and a link challenge that standard wallets refuse to sign. A valid proof transfers the address. Revocation is per credential. No auto-provisioning. |
| D4 | G-addresses only, v1 envelopes, exact shape. The master signature is checked first, purely. The ledger rule applies to every link that is not bridge-verified `tee`, and Horizon can only narrow the pinned set. No muxed accounts, memos, fee-bump or client_domain. |
| D5 | Generate-only `sep10_signing_key` (the 039 shape) with states pending, active, superseded, revoked. A background ring decrypts once per version per replica. Activation is fenced by `activate_at`. |
| D6 | TTL 300 s. Nonce = 16 random bytes ‖ 32-byte HMAC. Login challenges are stateless. A single-use claim on the tx hash runs until maxTime + 120 s. Lockout key is `sep10:{G}`. |
| D7 | Offered only on API ≥ 33 with FEATURE_HARDWARE_KEYSTORE ≥ 200 and a secure lock. The key is TEE Ed25519, attested from day one, with 30 s time-bound auth. Biometric sits outside the 15 s budget. DeviceKeyStore survives logout. |
| D8 | StrongBox P-256 binds refresh tokens (RFC 9449 §5) in phase 4. Nothing SE-backed is claimed for Stellar. |
| D9 | A Rust verifier in phase 3. It gates pubnet device links at `tee` and decides the Horizon bypass. Revocation is rescanned continuously. |
| D10 | Sessions authenticate. The card PIN signature or custodial policy authorizes. SEP-10 sessions are restricted to a pinned allow-list. |
| D11 | Android flow; `lumencli sep10 login` and `link-sign`, with the Go SDK as oracle; impalactl operator and transport commands; vectors in both directions; nightly live lane and emulator Keystore lane. |
| D12 | Phases 0–4. One migration `04N`, numbered at merge, run **before** the binary. |
| D13 | Fleet sequence (in repo), E2E-1, E2E-2, and the SEP-10 variant with card step-up. |

## 3. D10: Authorization model (the statement everything else serves)

**Session authentication** answers *who is calling*: password, SSO, card `SIGN_AUTH`, or SEP-10. Every path ends in `auth::issuance_role` followed by `jwt::encode_token_pair` (`auth.rs:280-295`, `jwt.rs:204-216`).

**Transaction authorization** answers *did the owner approve this value movement*. There are exactly two authorizers:

1. **Stored value.** The card's `SIGN_TRANSFER_V2` with the user PIN, over the 89-byte XFER message. The bridge verifies it against the bridge-issued card certificate. It is never re-signed, and ambiguity is surfaced as ambiguity.
2. **Custodial.** `POST /managed-account/sign` under custodial policy (037: brake, caps, per-account limit, idempotency, write-ahead intents). It requires a **full** session.

A SEP-10 login never authorizes anything. It yields a **restricted session**:

| Operation | Full session (password/SSO/card) | SEP-10 session |
|---|---|---|
| Read own account, on-chain view, transactions, intents, login keys | yes | yes (`AnyAuthUser`; role clamped to view-only) |
| Revoke itself (`POST /logout`, `DELETE /account/stellar-keys/current`) | yes | yes |
| Submit a card-signed redemption tuple (lane C2) | yes | yes. The card and PIN authorize, and the credited account must equal card owner = tuple account = session `sub` |
| `/managed-account/*`, `/exchange/*` writes, `POST /transaction`, `PUT /account` | yes, under policy | **403 `step_up_required`** |
| Add or remove a card, MFA, login key, device token, notify channel | yes | **403** (only self-unlink is allowed) |
| `POST /logout/all` (account epoch) | yes | **403**. A restricted session cannot sign the owner out everywhere. |
| `Privileged<C>`, `AdminUser` | by role | no: the token carries view-only and the restriction runs first |

**No operation requires a hardware-backed session key.** Hardware level describes key storage, not user intent. Transfers already have a hardware authorizer (the card).

The verified level is consumed in exactly two places:

- whether a device link may exist on pubnet;
- whether a link may skip the Horizon ledger rule (D4).

**Enforcement is default-deny.**

- `validate_request_auth` refuses any token whose `aud` is the SEP-10 audience with `AppError::StepUpRequired` (403, house envelope, code `step_up_required`). The only exception is `AnyAuthUser`, which calls `validate_request_auth_allowing_restricted`.
- `AuthContext`, `AuthenticatedUser`, `SessionUser`, `AdminUser` and `Privileged<C>` all inherit the refusal (F2), so every current and future handler fails closed.

The allow-list is pinned by name in a new tripwire, `any_auth_user_allow_list_is_exact`, beside the extractor table at `auth.rs:981`:

- `get_account`, `get_account_onchain`
- `list_transactions`, `get_transaction`
- `list_intents`, `get_intent`
- `list_stellar_keys`, `unlink_current_stellar_key`

C2 appends its redemption-submit and read handlers by name. Issuance and load handlers stay on `AuthenticatedUser`. `POST /logout` decodes its token directly (`logout.rs:26-35`) and so accepts both audiences.

A second tripwire, `no_handler_takes_raw_auth_context_except_logout_all`, keeps `AuthContext` from becoming a side door.

## 4. D1: Standards posture and wire contract

### 4.1 Routes

| Route | Auth | CORS | Notes |
|---|---|---|---|
| `GET /.well-known/stellar.toml` | none | `*` | `NETWORK_PASSPHRASE`, `SIGNING_KEY`, `WEB_AUTH_ENDPOINT` only. `text/plain`, `max-age=60`. 503 when no key is active |
| `GET /auth/sep10?account=G…[&home_domain=]` | none | `*` | `{transaction, network_passphrase}`, `no-store` |
| `POST /auth/sep10` | none | `*` | JSON or form `{transaction}` → `Sep10TokenResponse` |
| `POST /account/stellar-keys/enrollments` | `AuthenticatedUser` + owner + fresh | global | §6.3 |
| `POST /account/stellar-keys/enrollments/{enrollment_id}/challenge` | same | global | §6.3 |
| `POST /account/stellar-keys` | same | global | completes a link |
| `GET /account/stellar-keys` | `AnyAuthUser` + owner | global | |
| `DELETE /account/stellar-keys/current` | `AnyAuthUser` (session `cid`) | global | self-unlink |
| `DELETE /account/stellar-keys/{id}` | `AuthenticatedUser` + owner | global | |
| `POST /account/stellar-keys/revoke-all` | `AuthenticatedUser` + owner | global | |
| `GET /admin/sep10/signing-keys` | `Privileged<ReadKeys>` | global | |
| `POST /admin/sep10/signing-keys/generate` | `Privileged<ManageKeys>` | global | creates `pending` |
| `POST /admin/sep10/signing-keys/{version}/activate` | `Privileged<ManageKeys>` | global | CAS + phrase |
| `POST /admin/sep10/signing-keys/{version}/revoke` | `Privileged<ManageKeys>` | global | phrase |
| `GET /admin/accounts/{id}/stellar-keys` | `Privileged<ReadAccounts>` | global | |
| `DELETE /admin/accounts/{id}/stellar-keys/{key_id}` | `AdminUser` | global | support unlink |
| `POST /admin/sep10/revoke-sessions` | `AdminUser` | global | bumps `impala:sep10_epoch` (kill switch) |

**Mounting.** Admin routes are always mounted, because the key must exist before enablement. Public and account routes mount only when `SEP10_ENABLED=true`.

**Why `/auth/sep10`.** The path contains `/auth/`, so the Android `AuthInterceptor.kt:33` and `TokenAuthenticator.kt:30` already exempt it. The bare `/auth` is not exempt. `/account/stellar-keys*` is deliberately *not* exempt, so the bearer token is attached. Paths carry UUIDs, never addresses, which keeps `http.route` labels flat.

### 4.2 Domains and stellar.toml (fixes the shared-origin topology, F11)

**Configuration.**

- `SEP10_WEB_AUTH_ENDPOINT` is **mandatory, with no default**.
- home_domain = web_auth_domain = its authority (`host[:port]`).

**Boot validation** (`config::validate_sep10_policy`, beside `validate_cors_policy` at `config.rs:388`). The bridge refuses to start when:

- the path is not exactly `/auth/sep10`;
- the scheme is not `https`, unless the host is `localhost`, `127.0.0.1` or `10.0.2.2`;
- the host is not lowercase `[a-z0-9.-]` plus an optional port, or is longer than 59 bytes (so that `"<home> auth"` and `"<home> link"` fit in 64);
- `PUBLIC_ENDPOINT`, when set, has a different authority;
- `SEED_PROTECTION_BACKEND=none`;
- **phase 1–2 only:** `STELLAR_NETWORK` is not explicitly `testnet`, or `StellarConfig.network_passphrase` is not byte-equal to the testnet passphrase (F7).

**Values.**

| Network | Host |
|---|---|
| testnet | `api-testnet.<domain>` |
| pubnet (phase 3) | `api.<domain>` |
| CI | `127.0.0.1:8080` |
| emulator | `10.0.2.2:8080` |

The networks stay apart through separate hosts, separate keys, and the passphrase inside every signed hash.

**Topology.** The `/api/<network>/` proxy on the UI origin is documented as unsupported for SEP-10. An operator who fronts with nginx adds a per-host server block that proxies the host root, including `/.well-known/stellar.toml`, to the bridge.

**stellar.toml.**

- The bridge renders it from the ring's *active* key at request time, so it can never drift from the signing key.
- Serving it from impala-ui nginx or an external domain was rejected: manual sync on rotation, a second trust root, and the wrong origin.
- External publication is deferred. If ever adopted, `impalactl sep10-key verify-toml` compares the two.

### 4.3 CORS exception, scoped by construction

`handlers::sep10_auth::public_router()` holds **exactly** these three routes: GET `/.well-known/stellar.toml`, GET `/auth/sep10`, POST `/auth/sep10`. Inside, it applies:

- `RequestBodyLimitLayer(16 KiB)`;
- its own `TimeoutLayer(10 s, 408)`;
- an outer `CorsLayer::new().allow_origin(Any).allow_methods([GET, POST, OPTIONS]).allow_headers([CONTENT_TYPE, AUTHORIZATION])`, never with `allow_credentials`.

**Merge position.** `main.rs` merges it **after** the global `TimeoutLayer` (F12) and before `CompressionLayer`, the request-id, metrics, security-header and `Extension` layers. As a result:

- the global CORS allow-list, the 1 MB limit and the global timeout never wrap it, so every response, including 400/401/408/413/429/500/503, carries `Access-Control-Allow-Origin: *`;
- the Extension layers still reach its handlers.

`validate_cors_policy` and the pubnet wildcard ban stay global and unchanged.

**Why the wildcard is safe here.** These handlers take no auth extractor and read no `Cookie` or `Authorization` header. The optional v3.4 GET JWT is ignored. A browser therefore gains nothing that curl does not already have.

**Tripwires** (`main.rs` and `sep10_auth.rs` source pins):

- the exact path and method set;
- no `AuthenticatedUser|AnyAuthUser|Privileged|AdminUser|CookieJar|HeaderMap` in the three handler signatures;
- no `allow_credentials` anywhere;
- `allow_origin(Any)` appears only in `main.rs`'s testnet branch (`main.rs:490-492`) and in `public_router`;
- the merge line follows the global `TimeoutLayer`.

A `tower::ServiceExt::oneshot` test asserts ACAO on an OPTIONS preflight, a 400, a 401 and an oversize-body 413.

### 4.4 Bodies and errors

**GET.**

- `account` must pass `validate_stellar_account_id_checksum` (`validate.rs:36-55`).
- An `M…` address or any `memo` → 400 "muxed accounts and memos are not supported".
- A `home_domain` other than the configured one → 400.
- An `account` equal to any ring key → 400.
- `client_domain` is ignored, as the spec's parameter table allows.

**POST.**

- `Content-Type` is `application/json` or `application/x-www-form-urlencoded`; anything else → 400.
- In form bodies, decoded spaces in `transaction` are mapped back to `+`.
- `transaction` is at most 8192 characters.

**Errors** keep the house envelope; the SEP-10 `{"error": …}` body is only an example, and the deviation is documented in openapi.

| Status | Cause |
|---|---|
| 400 | byte or format errors only |
| 401 | generic, for every verification failure |
| 429 | with `Retry-After` |
| 500 | Redis or DB failure (fail-closed, never 401) |
| 503 | no active key, or Horizon unavailable (reachable only by a key holder, §7) |

**Compliance table** (in openapi and the runbook):

| Requirement | Status |
|---|---|
| ACAO `*` including errors; form + JSON; seq 0; server signature; timebounds on POST; unexpected ops and signatures rejected; one JWT per challenge | compliant |
| M accounts, memo, client_domain, GET JWT | optional features, declined |
| 900 s lifetime | 300 s (allowed: the spec says "recommend") |
| `sub` = G, `iss` URI | deviation (§5) |
| Device links that skip the ledger rule after verified attestation | deviation (§7), harmless for non-exportable TEE-generated keys |

## 5. D2: Token shape and session model

**Response.**

```json
{"token": "<T>", "success": true, "message": "SEP-10 authentication successful",
 "temporal_token": "<T>", "refresh_token": "<R, device links only>"}
```

`Sep10TokenResponse { token: String, #[serde(flatten)] house: models::TokenResponse }`. `token` is byte-identical to `temporal_token`. The openapi change is append-only. Android's Gson `TokenResponse` gains a nullable `token`.

**Claims.** HS256, `iss impala-bridge`, `sub` = payala account id, type pinned, `jti`, `fid`, plus:

- `aud = "impala-bridge-api-sep10"` (new constant `JWT_AUDIENCE_SEP10`);
- `cid` = the link UUID: `#[serde(default, skip_serializing_if = "Option::is_none")] cid: Option<String>`;
- `role = "view-only"`, always;
- `auth_time: u64`: `#[serde(default, skip_serializing_if = "is_zero")]`. It is set at every full login and copied on refresh. Tokens minted before rollout decode as 0 and cannot enroll until the user logs in again.

`base_validation` accepts both audiences and then enforces `aud == SEP10 ⇔ cid.is_some()`.

**Documented deviation.** `sub` is not a G-address and `iss` is not a URI. The token is opaque to clients and accepted only by this bridge. The bridge accepts no foreign SEP-10 JWT.

**Why an audience rather than an `amr` claim.** Old binaries ignore unknown claims (F4) but enforce the audience. During deploy skew or rollback, a restricted token is therefore dead on old replicas instead of silently becoming full-strength. This also defeats claim laundering through an old replica's `/token`.

**`TokenProfile`.** It is a required argument of `encode_token_pair` and `encode_token_pair_with_family`, so the compiler forces every mint site to choose:

- `Full { auth_time }`: existing callers pass the login time.
- `Sep10 { cid, deadline, refresh: bool }`: temporal `exp = min(now + 3600, deadline)`. When `refresh` is set, the refresh token's `exp = deadline`, fixed.

Device links use `deadline = login + SEP10_SESSION_MAX_SECS` (86400) with `refresh = true`. Wallet links use `refresh = false`: one JWT per challenge, the SEP-10 norm. The `refresh_token` field is then omitted (F3), so no long-lived credential leaves through the wildcard-CORS route.

**Role.** `issuance_role(pool, admin_ids, account)` is called on every SEP-10 mint and refresh. Its result decides refusal: an allowlisted id, or `role_is_privileged(role)` (true when any `Capability::ALL` entry holds), returns a generic 401. The token itself carries `auth::sep10_session_role()`, which is the constant `ROLE_VIEW_ONLY` (F6). The JWT never says admin for a restricted session.

**Refresh** (`token.rs:126-199`). When the presented refresh token has the SEP-10 audience:

1. Load the link `WHERE id=$cid AND payala_account_id=$sub AND state='active'`.
2. Re-run the eligibility gate (§6.4) and the role gate above.
3. On any failure: revoke the family and return 401.
4. Otherwise mint `Sep10 { same cid, same deadline }` with the same `fid`.

The deadline is never extended, and a test pins this. Full-profile refresh copies `auth_time`.

**Revocation.** `check_bearer_token_validity` (`redis_helpers.rs:707-747`) keeps its jti, fid and account-epoch checks. When `cid` is present, the same pipeline adds `EXISTS impala:revoked_cred:{cid}` and `GET impala:sep10_epoch` (a token is dead when `iat <= sep10_epoch`). Both fail closed. Logout, account delete and role change all still apply.

**Cookie mode: none.** Cookies carry only admin or view-only (`auth.rs:407-416`). A restricted cookie would split the two credential paths, and credentialed CORS cannot use `*`.

## 6. D3: Identity mapping

### 6.1 Schema: `migrations/04N_sep10_web_auth.sql` (one file, three tables)

```sql
CREATE TABLE IF NOT EXISTS sep10_signing_key (           -- 039 card_issuer_key shape
  version INTEGER PRIMARY KEY CHECK (version > 0),
  state VARCHAR(16) NOT NULL,
  backend VARCHAR(16) NOT NULL, ciphertext BYTEA, wrapped_data_key BYTEA, nonce BYTEA,
  key_id VARCHAR(256), key_version VARCHAR(32),
  public_address CHAR(56) NOT NULL UNIQUE, fingerprint VARCHAR(64) NOT NULL,
  generated_by VARCHAR(64) NOT NULL, generated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  activate_at TIMESTAMPTZ, superseded_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, scrubbed_at TIMESTAMPTZ,
  CONSTRAINT chk_ssk_state CHECK (state IN ('pending','active','superseded','revoked')),
  CONSTRAINT chk_ssk_material CHECK (state NOT IN ('pending','active') OR ciphertext IS NOT NULL),
  CONSTRAINT chk_ssk_scrub CHECK (scrubbed_at IS NULL OR (ciphertext IS NULL AND wrapped_data_key IS NULL AND nonce IS NULL)),
  CONSTRAINT chk_ssk_revoked CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS uq_sep10_signing_key_active  ON sep10_signing_key((true)) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_sep10_signing_key_pending ON sep10_signing_key((true)) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS stellar_login_key (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  payala_account_id VARCHAR(64) NOT NULL REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
  stellar_address CHAR(56) NOT NULL CHECK (stellar_address ~ '^G[A-Z2-7]{55}$'),
  key_kind VARCHAR(16) NOT NULL CHECK (key_kind IN ('device','wallet')),
  state VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
  security_level VARCHAR(16) NOT NULL DEFAULT 'unverified' CHECK (security_level IN ('unverified','software','tee')),
  user_auth VARCHAR(16) NOT NULL DEFAULT 'unknown' CHECK (user_auth IN ('unknown','per_use','timeout','none')),
  signer_keys TEXT[] NOT NULL CHECK (cardinality(signer_keys) BETWEEN 1 AND 20),
  ledger_state_at_enrollment VARCHAR(16) NOT NULL CHECK (ledger_state_at_enrollment IN ('unfunded','funded')),
  proof_tx_hash CHAR(64) NOT NULL, device_label VARCHAR(64), install_id CHAR(32),
  verified_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ, revoked_reason VARCHAR(24), revoked_by VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT chk_slk_reason CHECK (revoked_reason IS NULL OR revoked_reason IN
    ('owner','owner_all','self','admin','transferred','custody_conflict','attestation_revoked','policy')),
  CONSTRAINT chk_slk_revoked CHECK ((state = 'revoked') = (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)),
  CONSTRAINT chk_slk_wallet_unattested CHECK (key_kind = 'device' OR security_level = 'unverified'),
  CONSTRAINT chk_slk_device_unfunded CHECK (key_kind = 'wallet' OR ledger_state_at_enrollment = 'unfunded'));
CREATE UNIQUE INDEX IF NOT EXISTS uq_slk_active_address ON stellar_login_key(stellar_address) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_slk_active_install ON stellar_login_key(payala_account_id, install_id)
  WHERE state = 'active' AND install_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_slk_account_active ON stellar_login_key(payala_account_id) WHERE state = 'active';
-- + update_updated_at_column() trigger (002:18-28)

CREATE TABLE IF NOT EXISTS stellar_login_key_attestation (
  id BIGSERIAL PRIMARY KEY,
  link_id UUID NOT NULL REFERENCES stellar_login_key(id) ON DELETE CASCADE,
  challenge_sha256 CHAR(64) NOT NULL, chain_der BYTEA[] NOT NULL CHECK (cardinality(chain_der) BETWEEN 1 AND 10),
  cert_serials TEXT[] NOT NULL DEFAULT '{}',
  received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  verdict VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (verdict IN ('pending','verified','rejected')),
  verified_at TIMESTAMPTZ, verifier_version INTEGER, reason VARCHAR(64), root_fingerprint CHAR(64),
  rkp BOOLEAN, boot_state VARCHAR(16), os_patch_level INTEGER, attested_auth_timeout INTEGER);
CREATE INDEX IF NOT EXISTS ix_slka_serials ON stellar_login_key_attestation USING GIN (cert_serials);
```

**Deliberate choices.**

- There is no `strongbox` level, because the HAL offers StrongBox only P-256. A tripwire keeps it out of the CHECK and the constants.
- Uniqueness covers active rows only. Revoked rows stay for audit, so an address freed by revocation can be proven again.
- `impala_auth`, `auth_provider`, `impala_account.stellar_account_id`, the six `INSERT INTO impala_account` sites and the bootstrap trigger (023) are untouched.
- The account FK cascades. `delete_account` (`admin.rs:507-524`) already bumps the epoch and needs no change.
- Renaming the account is blocked by the FK, as for `card`.

### 6.2 Identity source

SEP-10 identity comes **only** from `stellar_login_key`. The login key is not the money address, and nothing reads links for payments or transaction ownership.

**Auto-provisioning is never offered.** The reasons:

- the first-account-becomes-admin trigger;
- `first_name VARCHAR(32)` cannot hold a G-address;
- accounts without `impala_auth` are claimable under open registration;
- `ON CONFLICT` adoption of existing rows;
- free keypairs would let anyone mint accounts;
- it would be a seventh INSERT site.

### 6.3 Enrollment: three calls from a fresh full session

Every call requires `AuthenticatedUser` + `require_owner` (so restricted sessions get 403) and `auth_time ≥ now − 600`, otherwise 403 `reauth_required`. The scope is `sep10_enroll` per account (10/60 s).

Enrollment is refused for:

- an `ADMIN_ACCOUNT_IDS` account (break-glass, incompatible with granular scoping);
- the `RESERVE_ACCOUNT_ID` account (`ReserveAccountGuard`, `managed_seed.rs:63-76`);
- `role_is_privileged(issuance_role(...))`.

The response is 403 `sep10_not_allowed`, with a tripwire that `stellar_keys.rs` calls `ReserveAccountGuard`.

1. **`POST /account/stellar-keys/enrollments`** `{payala_account_id, key_kind, device_label?, install_id?}` → 201 `{enrollment_id, attestation_nonce?, expires_at}`.
   - `wallet` is refused unless `SEP10_WALLET_KEYS` is on (testnet default on, pubnet default off).
   - At 5 active links the call returns 409 `too_many_login_keys`.
   - The Redis record `impala:sep10:enroll:{enrollment_id}` = `{account, kind, att_nonce_sha256, label, install_id, link_hash?}` is written `EX 600`, failing closed.
   - Device kind gets 32 random bytes as `attestation_nonce`.
   - This record is authenticated, per-account-limited state, unlike login GETs.
2. **`POST …/enrollments/{id}/challenge`** `{stellar_address}` → `{transaction, network_passphrase}`. The call:
   - refuses ineligible addresses (§6.4) with 400 `address_not_eligible`. Only the owner sees this;
   - builds a **link challenge**, which standard SEP-10 clients refuse:

     | Op | Source | Name | Value |
     |---|---|---|---|
     | op0 | G | `"<home> link"` | MAC-bound 48-byte nonce, base64 |
     | op1 | server | `web_auth_domain` | the web_auth_domain |
     | op2 | server | `impala_link_account` | the payala_account_id **in clear** (≤ 64 bytes) |

   - stores its tx hash in the enrollment record.

   Go `ReadChallengeTx` and every SEP-10 wallet look for `"<home> auth"`, so they refuse op0. A phishing page therefore cannot relay a link challenge through a standard wallet. Only the Impala app (which checks that op2 equals its own logged-in account) and `lumencli sep10 link-sign --expect-account` sign it.
3. **`POST /account/stellar-keys`** `{enrollment_id, transaction, attestation_chain?: [base64 DER, leaf first], device_label?}` → 201 `{id, stellar_address, key_kind, security_level, transferred}`. In order:
   1. Run the §7 pure checks with purpose `link`. The tx hash must equal the record's `link_hash`, and op2 must equal the session account.
   2. Verify the master signature by G.
   3. Run the ledger check through `LedgerSigners`.
      - `device` requires a genuine Horizon problem+json `not_found`, so `ledger_state_at_enrollment='unfunded'` and `signer_keys=[G]`. Otherwise 409 `device_key_on_ledger`.
      - `wallet`: on 404 → `unfunded`, `signer_keys=[G]`. On 200 → `funded`. `signer_keys` = the distinct ed25519 keys whose signatures verified, which must include G, and their on-chain weight must be ≥ max(med, 1); otherwise 401. Any other Horizon outcome → 503 and the challenge is not burned.
   4. Claim `impala:sep10:claim:{hash}` (`SET NX`).
   5. In one transaction:
      - `SELECT … FROM impala_account WHERE payala_account_id=$1 FOR UPDATE`;
      - re-count active links (< 5);
      - re-check eligibility;
      - if `install_id` matches an active link of this account, revoke that link (`reason=self`);
      - if the address is active on **another** account, revoke that row with `reason=transferred` and `SET impala:revoked_cred:{old_id}` before commit (the latest key holder wins, because the proof is a fresh signature by the key itself);
      - insert the new row;
      - insert the attestation row (`verdict=pending`; phase 3 verifies);
      - emit the events;
      - `DEL` the enrollment record;
      - commit.
   6. Notify the owner, and on a transfer also the previous account, through `notifications.rs` with a new variant `LoginKeyLinked { account_id, key_fingerprint, transferred }` on the same channels as `LoginSuccess`.

   Re-posting an already-claimed link challenge returns 409 `already_completed` together with the existing link, so a lost response is reconcilable.

### 6.4 Eligibility (enrollment, every login, every refresh)

All of the following must hold:

- The address is a checksum-valid G and not a weak Ed25519 point (ed25519-dalek, already in the lockfile).
- The address is not in `managed_seed.stellar_account_id`, which also covers the reserve address (`reserve.rs:492`).
- It is not any `sep10_signing_key.public_address`, and not a configured issuer.
- The account is not reserve, not allowlisted, and not privileged.

At login, a failure on an existing link raises `sep10.custody_conflict` and returns 401.

**Cross-guard.** Custodial generate and import (`managed_seed.rs`, `admin_keys.rs`, `/admin/stellar-seeds/import` at `main.rs:721`) refuse an address that is an active login key. This query always runs, which is why the migration must precede the binary (§13).

### 6.5 Unlink and revocation

**Owner unlink** (`DELETE /account/stellar-keys/{id}`, full session):

1. Guarded `UPDATE … SET state='revoked', revoked_reason='owner' WHERE id=$1 AND payala_account_id=$2 AND state='active'`.
2. `SET impala:revoked_cred:{id} 1 EX 172800` **before commit**. A Redis failure rolls back, as in `admin.rs:221-229`.
3. Commit.

There is no account epoch bump: the unlinking user's own full session survives, and `cid` revocation is exact.

**Why there is no race.** Every token a link ever minted carries `cid`, and the key outlives the 24 h deadline. A login that read the row as active just before the unlink mints a token that is already dead. There is no iat-second race (unlike epoch revocation), and refresh re-checks the DB.

**Other paths.**

- **`DELETE /account/stellar-keys/current`** (restricted allowed): revokes only the session's own `cid` link with `reason=self`, plus its `fid`.
- **`POST /account/stellar-keys/revoke-all`** (full session): revokes every active link (`owner_all`). Android's "Sign out everywhere" calls this and `/logout/all`.
- **Admin `DELETE`**: `reason=admin`.
- **`POST /admin/sep10/revoke-sessions`**: bumps `impala:sep10_epoch` (incident kill switch, and the rollback step).

Events: `account.stellar_login_key_unlinked {link_id, payala_account_id, reason}`.

## 7. D4: Which accounts may authenticate, and the verifier

**Module.** `src/sep10/verify.rs` is pure (no I/O, injected `now`, ring, config). It works in layers.

1. **Decode.**
   - Strict base64 STANDARD decode.
   - `stellar_base::xdr::TransactionEnvelope::from_xdr(&bytes, Limits { depth: 32, len: bytes.len() })`. This is strict and EOF-checked. The compatibility parser (`Limits::none()`, trailing bytes accepted) never touches client input.
   - The raw discriminant must be `Tx`. `TxV0` (stellar-base converts it silently) and `TxFeeBump` (its hash covers the wrapper) → 400. This is checked before any typed accessor.
2. **Issued-challenge check** (failure → 401, not counted).
   - The source is `MuxedAccount::Ed25519` and equals a ring key version that is active, pending-after-activate, or superseded within `superseded_at + TTL + 120 s`. A revoked key is never accepted.
   - `seq_num = 0`; `fee = 100 × ops`; memo `None`; ext `V0`.
   - `cond` is `Preconditions::Time` with both bounds nonzero, `max − min == TTL`, and `min − 30 ≤ now ≤ max`. PreconditionsV2 is refused.
   - Ops exact, names compared as raw `StringM` bytes. Login: `["<home> auth" (G), web_auth_domain (server)]`. Link: the §6.3 triple.
   - The nonce is 64 base64 bytes that decode to 48 = `r16 ‖ HMAC-SHA256(k_mac[version], "impala-sep10-chal-v1" ‖ purpose ‖ G32 ‖ minTime_be64 ‖ maxTime_be64 ‖ version_be32 ‖ network_id32 ‖ r16)`, compared in constant time.
   - There are 2–20 decorated signatures, and exactly one verifies as the server key, chosen by hint, over `hash = SHA-256(TransactionSignaturePayload{network_id, Tx(tx)})`. The probe confirms this equals stellar-base's hash. Ed25519 is verified with `aws_lc_rs::signature::UnparsedPublicKey::new(&ED25519, pk)` (the `card_auth.rs:78-83` pattern).
   - G is not a ring key.
3. **Master check** (pure). One remaining signature with hint = G[28..32] verifies under G. Failure is **the only counted failure**. It is decided without any lookup, so linked and unlinked addresses behave identically and a stranger cannot learn linkage from 429 versus 401.
4. **Pinned-signer check** (after the DB read). Every remaining signature maps, by hint and verify, to a distinct key in `signer_keys`. An unknown or duplicate signature → 401, not counted (only the key holder can reach this step).
5. **Ledger rule** (`LedgerSigners` trait; the Horizon implementation `fetch_signing_authority` sits beside `stellar/account.rs:105`; the lenient display parser stays as it is).
   - `security_level='tee'`, set only by bridge-verified attestation in phase 3, means the key is non-exportable and TEE-generated, so only it can change signers. The link skips Horizon.
   - Every other link, device or wallet, goes through Horizon:
     - **404**: honoured only when the body is problem+json with type `https://stellar.org/horizon-errors/not_found`, **and** the link was enrolled `unfunded`. A funded-then-merged account → 401: compromise remediation by merge revokes Impala access.
     - **200**: strict parse. `id` must equal G; all three thresholds must be in 0..=255; signers must be typed. The weight of the verified pinned signers that are still on-chain `ed25519_public_key` signers (the master at `thresholds.master_key_weight`) must be ≥ `max(med_threshold, 1)`. Horizon only *narrows*: a signer added on-chain after enrollment never counts. Setting master weight to 0 revokes a leaked master key.
     - **Anything else** → 503, not counted.
   - **Horizon isolation.** Lookups happen only after a master signature has verified. They go through a dedicated `tokio::Semaphore(SEP10_HORIZON_CONCURRENCY=4)`, a global budget of `SEP10_HORIZON_MAX_PER_MIN=120` (503 when exhausted), and a 30 s cache `impala:sep10:signers:{G}` (public data). They never share the payout or watch clients' concurrency.

**Refused, and why.**

- **M-addresses and memos:** shared custody that the link, lockout and claim do not model. The Java SDK rejects them, `payala_account_id` cannot carry them, and muxed senders are already a hard stop.
- **client_domain:** the Go SDK cannot verify it, and fetching a toml server-side on an unauthenticated path is an SSRF surface.
- **v0, fee-bump, V2 preconditions:** as above.

**The device-path deviation** (no ledger lookup) applies **only** after verified attestation shows origin GENERATED and the attested SPKI equals G. Before phase 3, no client-chosen `key_kind` skips the ledger.

**`POST /auth/sep10` order.** Card order (F1). The per-identity scope is charged only for requests that carry a verified master signature, because a G-address, unlike a card id, is public. The whole handler runs inside `record_token_exchange("sep10", …)` (`card_auth.rs:192-205`).

1. `check_rate_limit("preauth_src", sep10_bucket(source), 30, 60)`. `sep10_bucket` aggregates IPv6 to /64 (F9).
2. Decode (400 only here).
3. Issued-challenge check → 401.
4. `check_lockout("sep10:{G}", source)` → 429.
5. Master check → on failure `increment_lockout`, then 401.
6. `check_rate_limit("sep10", G, 10, 60)`.
7. Link read with eligibility (§6.4) → 401.
8. Pinned-signer check → 401.
9. Ledger rule → 401 or 503.
10. `SET impala:sep10:claim:{hex(hash)} 1 NX EX (maxTime − now + 120)`. A lost claim is a replay → 401. The hash excludes signatures, so a malleated signature cannot mint twice.
11. `clear_lockout`.
12. `issuance_role` → refuse if allowlisted or privileged (401). Then `encode_token_pair(…, sep10_session_role(), TokenProfile::Sep10{…})`.
13. `UPDATE stellar_login_key SET last_used_at=now()`, best effort.
14. 200.

**GET order.**

1. `preauth_src`.
2. `INCR sep10_challenge_global`: at most `SEP10_CHALLENGE_GLOBAL_MAX=600` per 60 s, then 503. One shared key, failing closed.
3. Validate parameters.
4. Build and sign.

GET writes no per-request state, does no per-G scope (anyone could exhaust a public address's budget), and does no DB read. The response is identical for every address.

## 8. D5: Server signing key custody

**Material.**

- The key is generated with `DalekKeyPair::random()`, taking `inner().to_bytes()` (never `secret_seed()`, which returns an unzeroized String).
- `k_mac` is 32 bytes from `aws_lc_rs::rand`.
- Sealed plaintext = `"impala-sep10-v1\n{version}\n" ‖ seed32 ‖ k_mac32`, held in `Zeroizing`. It is sealed with the seed protector (KMS, Vault or OpenBao); there is no plaintext-at-rest path.
- **Open** checks backend, header and version, then that the derived G equals `public_address`. Errors are fixed strings (`offline/issuer.rs:104-150`). `Debug` prints `Sep10Key([REDACTED])`.
- Fingerprint: `keys::fingerprint("sep10_signing", "public_key", raw32)` (`keys/mod.rs:402`).
- `SEP10_KEY_HEADER_MAGIC` joins `header_magics_are_pairwise_distinct_and_versioned` (`constants.rs:1396-1408`).

**Admin** (`handlers/admin_sep10.rs`, copying `admin_card_issuer.rs:46-79,107-200`).

- `generate`:
  - checks `require_enabled` (`KEY_IMPORT_ENABLED` plus a real protector, `admin_keys.rs:82-94`) and `KEY_IMPORT_RATE_LIMIT_SCOPE`;
  - creates **`pending`**, with `drop(seed)` after sealing;
  - refuses if a pending version already exists;
  - emits `custody.sep10_key_generated {version, fingerprint}`.
- `activate {confirm_supersede: <active fingerprint or "none">, confirm_phrase: "activate sep10-signing {network}"}`:
  - compares with `keys::tokens_match` under `FOR UPDATE`;
  - sets `activate_at = now + SEP10_KEY_ACTIVATION_DELAY_SECS` (120);
  - at `activate_at` the pending row becomes active and the previous one superseded. Each replica's ring applies the swap by DB clock: it reads `activate_at` and switches at that instant;
  - emits `custody.sep10_key_activated`.
- `revoke {confirm_phrase: "revoke sep10-signing {network} v{version}"}`:
  - takes effect at the next poll; POST refuses the version at once from the ring's cached state;
  - emits `custody.sep10_key_revoked`. Revoking the active key leaves SEP-10 answering 503 until another key is activated.
- Use of the key is not `KEY_IMPORT_ENABLED`-gated, as with the issuer key at `admin_card_issuer.rs:286`.
- **Tripwires** (the `admin_card_issuer.rs:476-502` set):
  - no `import` function or route;
  - `drop(seed);` present;
  - no `seed:`, `private` or `ciphertext:` in response structs.

**Runtime ring** (`src/sep10/key.rs`).

- `Sep10KeyRing` lives behind `ArcSwap`, provided as an `Extension`.
- A background task polls `(version, state, activate_at, fingerprint)` every 30 s. It decrypts **only versions it has not seen**, single-flight per version. A failed decrypt is negatively cached with exponential backoff from 5 s to 60 s. Result: protector calls equal versions × replicas, never per request.
- Handlers only read the `ArcSwap`. With no usable active key, the public routes answer 503 without touching the protector. A unit test checks that 1000 concurrent GETs against a failing protector cause at most one open per backoff window.
- If the DB is unreachable for more than 5 minutes, the ring marks itself stale and SEP-10 returns 503.
- The ring exposes only `sign_challenge` and `mac`, never the seed.
- `sep10` sources never reference `load_protected_seed`, the `managed_seed` loaders or `StellarSigner` (tripwire). No bridge-held custodial seed can sign a challenge as a client.
- `SEP10_ENABLED=true` requires a non-`none` protector. A missing table fails boot with `SELECT 1 FROM sep10_signing_key LIMIT 0`.

**Why decrypt once is acceptable.** Per-request decryption would let unauthenticated GETs drive the KMS or Vault quota that reserve payouts use. A memory dump yields a key that:

- cannot forge client signatures;
- moves no funds (the server account is never funded and never added as a signer; runbook rule);
- can only mint TTL-exact challenges.

**Rejected.** A managed_seed service account (it creates an `impala_account` row reachable through `/managed-account/*`, and has no versioning). An env or plaintext seed. An import route. Boot-only loading (replicas disagree during a rolling restart).

**Publication and pinning.**

- The toml follows the ring's active key, which is synchronized by `activate_at` across replicas, with `max-age=60`. The activation delay covers poll interval × 2 plus toml max-age, so a client can no longer get a new-key toml and an old-key challenge from different replicas.
- Android fetches the toml from `https://{SEP10_HOME_DOMAIN}/.well-known/stellar.toml` with an interceptor-free client.
- lumencli takes the toml, and an optional `--server-key` pin refuses on conflict.
- The conformance lane compares the operator pin with the toml.
- No client takes the key from the challenge endpoint.

## 9. D6: Challenge lifecycle

| Parameter | Value |
|---|---|
| TTL | `SEP10_CHALLENGE_TTL_SECS=300`, configurable 60–900. Long enough for wallet approval or a biometric; a third of the spec's relay window |
| Build | `Transaction::builder(server_pk, 0, Stroops::new(100))` with `TimeBounds::always_valid().with_lower(now)?.with_upper(now+ttl)?`, never `valid_for` (which leaves minTime unset, `signer.rs:379-381`). Signed under `Network::new(StellarConfig.network_passphrase)` (boot-verified). Fee 100 per op |
| Nonce | 48 bytes = 16 CSPRNG ‖ 32 HMAC → 64 base64 characters |
| Login state | none at issuance |
| Link state | `impala:sep10:enroll:{id}` (authenticated, EX 600) |
| Single use | `impala:sep10:claim:{txhash}` `SET NX EX (maxTime−now+120)`. The 120 s margin outlives replica clock skew, so a fast replica's claim cannot expire before a slow replica stops accepting. Login and link share the namespace |
| Skew | maxTime strict; minTime −30 s server grace. The app accepts `[min−300, max]` |
| Scopes | `preauth_src` 30/60 s per /64-aggregated source; `sep10` 10/60 s per G, charged only after a verified master signature; `sep10_enroll` 10/60 s per account; `sep10_challenge_global` 600/60 s |
| Lockout | `"sep10:{G}"` × `source_fingerprint(source)`, threshold `LOCKOUT_THRESHOLD`. Counts only master-signature failures over live, issued challenges |
| Reserved names | `parse_sso_providers` (`config.rs:89`) refuses provider names `card`, `token`, `auth`, `api`, `session_login`, `preauth_src`, `sep10*` (SSO names become scopes verbatim) |
| Metrics | `token_exchange{provider="sep10"}`; `sep10_challenges_total{purpose}`; `sep10_rejections_total{reason}`, with reason ∈ {malformed, not_issued, expired, mac, server_signature, bad_master_signature, unknown_signer, ineligible, insufficient_weight, ledger_unavailable, replay, role_refused}. Never an address label. The account rides in the query string, which MetricsLayer drops (`middleware.rs:59`) |

**Rejected.**

- A per-hash record written on every GET (F8: Redis-fill DoS).
- A card-style per-identity list (evictable by anyone who knows the public address).
- Stateless challenges *without* a MAC (a leaked signing key alone could mint acceptable challenges).
- A 900 s TTL.
- A 60 s TTL.

## 10. D7: Android device key

**Eligibility** (`DeviceKeyCapability`, injectable, because minSdk is 24):

| Device | Offered? |
|---|---|
| API 24–32 | Hidden: "Needs Android 13 or later" |
| API ≥ 33 with `FEATURE_HARDWARE_KEYSTORE` < 200 | Hidden: keystore2 silently emulates Curve25519 in software |
| No secure lock | Disabled: "Set a screen lock first" |
| Otherwise | Offered |

There is no software fallback in any APK. The UI never says "secure element". It shows the level the bridge verified.

**Key generation** (`KeystoreDeviceAuthKey`, `@RequiresApi(33)`, alias `impala.sep10.<sha256(bridgeUrl)[0..8]>.<install_id>`):

```kotlin
KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
  .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
  .setDigests(KeyProperties.DIGEST_NONE)
  .setAttestationChallenge(attestationNonce)                       // from POST …/enrollments, phase 1 on
  .setUserAuthenticationRequired(true)
  .setUserAuthenticationParameters(30, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)
  .setInvalidatedByBiometricEnrollment(false)                      // explicit, not assumed
  .setIsStrongBoxBacked(false)                                     // HAL: StrongBox is P-256 only
  .apply { if (SDK_INT >= 35) setUnlockedDeviceRequired(true) }    // buggy before 15
  .build()  // KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
```

**After generation.**

- `KeyInfo.securityLevel` must be `TRUSTED_ENVIRONMENT`, otherwise the app deletes the key and hides the mode. This is a UX gate only; it is never sent to the bridge.
- `getEncoded()` must start with the SPKI prefix `302a300506032b6570032100`. The remaining 32 bytes become G through the main-source `StrKey` in impala-lib, golden-tested.
- `Signature.getInstance("Ed25519")` signs the 32-byte tx hash, and the app appends a `DecoratedSignature` with hint = G[28..32].

**User authentication.**

- Time-bound: `BiometricPrompt` (androidx.biometric) runs without a `CryptoObject`. Per-use CryptoObject auth with Ed25519 is source-evidenced only, so it is deferred to a device matrix (phase 3).
- `UserNotAuthenticatedException` → prompt again.
- `KeyPermanentlyInvalidatedException` (lock removed) → delete the key and `DeviceKeyStore`, then show `DEVICE_KEY_RESET` ("sign in another way and turn phone sign-in on again").
- No other exception at login ever deletes the key.
- The enrollment screen states: "Anyone who can unlock this phone can sign in to your Impala account (read-only; payments still need your card)."

**On-device challenge codec** (`impala-lib` `com.payala.impala.auth.sep10.Sep10Challenge`, about 250 lines of strict XDR, no Stellar SDK). It accepts exactly:

- envelope type 2 and EOF;
- source = the toml `SIGNING_KEY`;
- seq 0, fee = 100 × ops, `PRECOND_TIME` with `min − 300 ≤ now ≤ max` and span ≤ 900, no memo, ext v0;
- login pair or link triple, op0 sourced by its own G;
- `web_auth_domain` = `BuildConfig.SEP10_HOME_DOMAIN` (explicit per flavor, not derived from `BRIDGE_BASE_URL`, F11);
- for link: `impala_link_account` = `TokenManager.getAccountId()`;
- exactly one signature, the server's, verified with platform `Signature("Ed25519")`;
- toml `NETWORK_PASSPHRASE`, response `network_passphrase` and the flavor passphrase all equal.

It hashes `SHA-256(networkId ‖ 00000002 ‖ sliced tx bytes)` without re-encoding. Only a `VerifiedChallenge` can reach the signer.

The Java SDK (`network.lightsail:stellar-sdk` 5.0.0) is rejected: about 13 MB with bcprov, and OkHttp 4 against the app's OkHttp 5. It is used only as a test-scope oracle.

**Signature-mismatch rule.**

- If the server signature fails against the cached `SIGNING_KEY`, refetch the toml once, bypassing the cache, inside step A.
- If it still fails → `SERVER_IDENTITY` ("do not continue").
- This never counts toward any "remove phone sign-in" prompt.
- This is TLS trust in the flavor host, documented as such, not an independent pin.

**Flows.**

- **Enrollment** (Settings → Phone sign-in, full session):
  1. `POST enrollments` (nonce)
  2. key generation
  3. `POST …/challenge`
  4. validate
  5. prompt
  6. sign
  7. `POST /account/stellar-keys` with the attestation chain (`KeyStore.getCertificateChain(alias)`)
  8. save to `DeviceKeyStore`

  An IOException or timeout on step 7 is **ambiguous**: the app keeps the key, calls `GET /account/stellar-keys` and reconciles by address. It deletes locally only on a definite 4xx when the address is absent.
- **Login** (mirrors the card split, `LoginViewModel.kt:296-302`):
  - (A) `withTimeout(LOGIN_TIMEOUT_MS)`: toml (cache ≤ 60 s), then `GET auth/sep10?account=G`, then validate.
  - (B) the prompt, outside any timer. The challenge must still have ≥ 30 s before maxTime, else "That took too long, try again".
  - (C) `runLogin("sep10") { sign; POST auth/sep10; completeTokenFlow(provider = "sep10") }` within the 15 s budget (`LoginViewModel.kt:67,415-431,441-472`).
  - An `AtomicBoolean` blocks double taps.
- **RetryInterceptor**, which retries every method on IOException (contrary to its KDoc), exempts `POST auth/sep10` and `POST account/stellar-keys*`.

**Storage.**

- `TokenManager` holds the tokens and `auth_provider="sep10"`, and is cleared on logout (`TokenManager.kt:174-181`).
- `DeviceKeyStore` is a new prefs file `impala_device_key`, written with `commit()` + `check()` (`PendingTransferStore.kt:137-187`) and excluded from backup. It holds alias, G, link id, account id, install_id, label, bridge-URL hash and cached `SIGNING_KEY`, and survives logout.
- Keys never restore (`allowBackup=false`).

**Recovery.** On a new phone, log in by password, card or SSO and re-enroll; `install_id` replaces the old link. A lost phone is unlinked from any full session.

**Errors.**

| Response | Error type |
|---|---|
| 401 | `DEVICE_KEY_REJECTED` |
| 403 `step_up_required` | `STEP_UP_REQUIRED` (offers card or password login) |
| 403 `reauth_required` | prompts a fresh login |
| 429 | `LOCKED_OUT` (the provider check at `:116-128` is extended to `"sep10"`) |
| 503 | `SERVER_ERROR` |

Local errors are `SERVER_IDENTITY` and `DEVICE_KEY_RESET`. Each new type gets strings and a branch in the exhaustive `mapErrorToMessage` (`LoginActivity.kt:286-301`). `btnDeviceKey` joins all four state branches (`LoginActivity.kt:127-163`).

**DTOs** live in `com.payala.impala.demo.model.Sep10Models.kt`, snake_case: `Sep10ChallengeResponse`, `Sep10TokenRequest`, `StellarKeyEnrollmentRequest/Response`, `StellarKeyChallengeRequest`, `StellarKeyLinkRequest/Response`, `StellarKeyDto`, and `TokenResponse.token: String?`.

**Seams and tests.**

- `DeviceAuthKey` (`publicKey(): ByteArray`, `sign(hash: ByteArray): ByteArray`, `attestationChain()`) with `KeystoreDeviceAuthKey` and a JCA JDK-21 `SoftwareDeviceAuthKey`, because Robolectric has no AndroidKeyStore.
- Tests: `Sep10ChallengeTest` (shared vectors plus every rejection), `StrKeyTest`, `StellarTomlTest` (strict `KEY = "value"` lines, each key once), `DeviceKeyStoreTest`, `LoginViewModelTest`, and `TokenRefreshTest`, which asserts that `auth/sep10` is exempt and `account/stellar-keys` is not.
- **Emulator lane** (androidTest on the existing API 33+ emulator matrix):
  1. `adb shell locksettings set-pin`, then unlock.
  2. Generate the real Keystore key.
  3. Sign the shared vector and verify the bytes.
  4. Exercise the 30 s expiry.
  5. Assert that platform Ed25519 *verify* of a non-Keystore public key exists.

  It asserts no security level (the emulator has no real TEE). Physical runs on two or more OEMs are a phase-2 exit criterion.

## 11. D8: Secure element role

StrongBox supports P-256 and no other curves, so it can never sign for a G-account. **No design claims a secure-element-backed Stellar key.**

StrongBox's one honest job is **refresh-token binding (RFC 9449 §5)**. It is specified now and built in phase 4, after attestation. It is not built earlier because restricted SEP-10 sessions already cannot move value, are capped at 24 h, and are revocable per credential. The larger target is the 14-day refresh token that *full* password, card and SSO sessions carry, which can drive custodial signing under policy.

**Key.** P-256 with `setIsStrongBoxBacked(true)`, falling back to the TEE on `StrongBoxUnavailableException` (the fallback is recorded). No user authentication, so background refresh keeps working. Attested at bind time.

**Proof.**

- Header: `typ=dpop+jwt`, `alg=ES256`, `jwk{kty,crv,x,y}`.
- Claims: `jti` ≥ 96 bits, `htm=POST`, `htu=PUBLIC_ENDPOINT+"/token"`, `iat` within ±60 s, and `nonce` = a stateless HMAC over a 5-minute bucket, sent as `DPoP-Nonce` with 400 `use_dpop_nonce`. There is no `ath`, because no access token is presented at `/token`.
- A strict DER→64-byte R‖S converter.

**Binding.**

- Refresh tokens gain a serde-defaulted `cnf: Option<Cnf{jkt}>` (RFC 7638 thumbprint over `{crv,kty,x,y}`). The family is bound on its first rotation.
- A bound family requires a matching proof.
- The jti cache uses `SET NX EX 120`, failing closed.
- A failed proof → 401 without consuming the rotation.

**Untouched.** Temporal tokens stay `Bearer`. The `"Bearer "` path (`auth.rs:330`), the cookie path, impala-ui and impalactl, and their tests are not changed.

**Rejected.**

- DPoP on every request (it changes the pinned Bearer rule on both paths and adds StrongBox latency per call).
- SEP-45 secp256r1 (Draft).
- A StrongBox AES wrap of TokenManager (marginal gain).

## 12. D9: Bridge-side attestation verification (phase 3; chains collected from phase 1)

**Crates.**

- `x509-cert` for the certificates (`der` and `spki` are already in the lockfile).
- A bounded, hand-written DER reader for `KeyDescription` (OID `1.3.6.1.4.1.11129.2.1.17`), with high-tag-number support (F14), fuzzed with `cargo-fuzz`.
- `aws-lc-rs` for RSA PKCS#1 SHA-256 (2048–8192 bits) and ECDSA P-256/P-384.

**Roots.** Pinned by SPKI SHA-256 at build time, with a fingerprint tripwire:

- Google RSA-4096 (subject serialNumber `f92009e853b6b045`, pinned by key because several certificates carry it);
- ECDSA P-384 "Key Attestation CA1" (signs chains since 2026-02-01).

**Chain rules.**

- At most 10 certificates of at most 8 KiB each; every link verifies; the chain ends at a pinned root.
- **Validity is evaluated at `received_at`** (server-stamped, nonce already consumed), never at re-check time.
  - Leaf validity is ignored (some TEEs stamp it from an unsynchronized clock).
  - Validity is enforced on RKP intermediates (provisioning extension `…2.1.30`).
  - Validity is ignored on legacy RSA-root factory chains, as Google advises.

**KeyDescription.** Only the occurrence nearest the root counts; a second occurrence → reject. The verifier requires all of:

- `attestationChallenge` = the enrollment nonce;
- the leaf SPKI = the enrolled G (`1.3.101.112`);
- `attestationVersion` ≥ 200;
- attestation and KeyMint security levels both TrustedEnvironment (StrongBox claimed for Curve25519 → reject as inconsistent);
- origin GENERATED, purpose SIGN, curve CURVE_25519, no `noAuthRequired`;
- `rootOfTrust` Verified and `deviceLocked`, otherwise the level is `software`;
- `osPatchLevel` within `SEP10_ATTEST_MAX_PATCH_AGE_MONTHS=24`;
- `attestationApplicationId` package and signer digest ∈ `SEP10_ANDROID_APPS`.

`userAuthType` and `authTimeout` are recorded into `user_auth`.

**Revocation.**

- `android.googleapis.com/attestation/status` is cached per Cache-Control. Once older than max-age + 6 h it counts as unavailable, and device enrollment returns 503. Logins are unaffected.
- Each chain's serials are stored in `cert_serials`.
- `attestation_rescan` is a single-flight job (Redis lock `impala:sep10:attest_rescan`). On every list refresh it revokes active links whose chain contains a newly revoked serial (`revoked_reason='attestation_revoked'`, `revoked_cred` set, event emitted). It alerts if the list is stale beyond its cap.

**Policy consumers.**

- `SEP10_DEVICE_MIN_LEVEL`: pubnet is forced to `tee`; testnet default `unverified`.
- `SEP10_DEVICE_REQUIRE_USER_AUTH`: pubnet requires `per_use` or `timeout ≤ 30`.
- The Horizon bypass in §7.

Phase 1–2 chains are verified retroactively at rollout. Keys enrolled earlier never need re-enrollment because the nonce was bound from day one. Nothing gates on a client-reported level.

**Differential corpus.** Chains from KeyMint v2 TEE, RKP-only Android 16, KeyMint v1 emulated Curve25519, and an unlocked bootloader must get the same verdict from Google's `android/keyattestation` and the Rust verifier.

**Rejected.** A JVM sidecar (new runtime on the money host; the library is pre-1.0). webpki (it enforces factory-chain validity and cannot parse the extension). Play Integrity (no key binding). Client `KeyInfo`.

## 13. D11: Clients and conformance

**lumencli** (charter amended in its README: Horizon plus generic SEP-1 and SEP-10, never bridge-specific APIs).

`lumencli [--network N] sep10 login --home-domain D [--server-key G] [--insecure-loopback]`:

1. Fetch `https://D/.well-known/stellar.toml` via go-stellar-sdk `clients/stellartoml` (adds BurntSushi/toml, under govulncheck).
2. Refuse if `--server-key` is given and differs from the toml key.
3. `GET WEB_AUTH_ENDPOINT?account=G`.
4. Refuse before signing unless the response passphrase, the toml `NETWORK_PASSPHRASE` and the selected network's passphrase agree. The error names the network.
5. `txnbuild.ReadChallengeTx(xdr, key, passphrase, host(WEB_AUTH_ENDPOINT), []string{D})`; require that the client account is the seed's address and that there is no memo.
6. Sign with the seed from `LUMEN_SECRET`, a no-echo TTY prompt, or one stdin line (`secret.go:23-52`).
7. Self-check with `VerifyChallengeTxSigners`, asserting both the error and the signer slice.
8. POST JSON.

Output: the response body as one JSON line on stdout, with a credential notice on stderr. Exit codes 0, 1 or 2, never 3. A new golden covers it.

`lumencli sep10 link-sign --server-key G --home-domain D --expect-account ID [--challenge-file F|-]` is offline. It parses the link triple manually (ReadChallengeTx refuses it by design), refuses unless op2 equals `--expect-account`, prints the target account on stderr, and requires typed confirmation of the account id on a TTY. It prints the signed XDR on stdout.

There is **no generic offline `sep10 sign` for login challenges**: an offline signer of relayed login challenges would be a phishing primitive.

**impalactl** stays SDK-free (x/term only):

- `sep10-key status|generate|activate|revoke|verify-toml`;
- `stellar-keys list|unlink|revoke-all`;
- `stellar-keys enroll-wallet --address G` (creates the enrollment and prints the link challenge on stdout), then `stellar-keys complete --enrollment-id X` (signed XDR on stdin).

impalactl has no SEP-10 login: operators are privileged, and SEP-10 refuses privileged accounts.

**Golden vectors** (`lumencli/internal/sep10`; `go test ./internal/sep10 -update` writes `lumencli/testdata/sep10/vectors.json`; the bridge reads it with `include_str!`, the cross-project fixture precedent of `impala-ui/tests/fixtures/role-capabilities.json`):

| Set | Built by | Bridge must |
|---|---|---|
| A | `BuildChallengeTx` plus a client signature | accept at the shape, server and client layers, with the MAC layer disabled by a test-only flag (documented) |
| B | `txnbuild.NewTransaction` with a MAC'd nonce from a fixed test key | produce byte-identical Rust output and fully accept it under the recorded clock |
| C | mutations | reject each: extra, duplicate, foreign or misordered signatures, wrong hint, missing server signature, fee-bump, v0, V2, trailing bytes, tampered nonce or MAC, wrong passphrase, seq ≠ 0, memo, muxed source, client_domain op, wrong domains, `auth`↔`link` op swap, span ≠ TTL, expired |

Set D goes the other way. `impala-bridge/tests/fixtures/sep10/bridge_vectors.json` holds bridge-built challenges with maxTime in 2099, which the Go test checks with `ReadChallengeTx` and `VerifyChallengeTxSigners` (this sidesteps the SDK's lack of clock injection). The Kotlin `Sep10ChallengeTest` consumes the same files.

**CI.**

- `.github/workflows/sep10-interop.yml` (its path filter includes itself and both fixture paths):
  - **On PR:** Rust emits a fresh challenge, Go signs it after `ReadChallengeTx`, Rust verifies it.
  - **Nightly and dispatch:** compose with bridge, Postgres 16, Redis 7 and OpenBao dev; `RUN_MODE=migrate`; generate and activate the key; `lumencli/scripts/sep10-conformance.sh`.
- The conformance script covers:
  - the toml against `IMPALA_SEP10_SERVER_KEY`;
  - ACAO on 200, 401 and 413;
  - a wallet link via `impalactl stellar-keys enroll-wallet | lumencli sep10 link-sign | impalactl stellar-keys complete`;
  - `lumencli sep10 login` with JSON and with form;
  - negatives: replay, expiry (`SLOW=1`), tamper, wrong passphrase, M address, memo, identical 401/429 sequences for linked and unlinked G, `/managed-account/sign` from a SEP-10 session → 403, unlink → 401, rotation during a login, revoke → no grace.
- `impala-android.yml` `card-e2e` adds `Sep10AuthE2ETest` (env allowlist at `build.gradle.kts:232-235`) plus the emulator Keystore lane.

## 14. D12: Implementation plan

**Migration numbering.** One file, `04N_sep10_web_auth.sql`, numbered at merge: 040 if lane C2's offline ledger has not merged, otherwise 041. The two share no table. An applied number is never renamed, because sqlx records version and checksum (037's stale "038" references show what pre-assignment costs). `include_str!` paths change in the same commit. A new test `migration_numbers_unique_and_contiguous` guards this.

**Rollout order (house rule).** The custody cross-guard queries `stellar_login_key` unconditionally.

1. `RUN_MODE=migrate`. The migration is additive.
2. Roll the binary with `SEP10_ENABLED=false`.
3. `impalactl sep10-key generate`, then `activate`.
4. Set `SEP10_ENABLED=true` and roll.

**Rollback:** `POST /admin/sep10/revoke-sessions`, then disable. Old binaries already reject the restricted audience.

| Phase | Content | Exit |
|---|---|---|
| 0 | Reserved SSO names. FROZEN catch-up (append the ~12 missing existing types plus a converse check; confirm with owners). Migration-number test. `auth_time` claim plus `AuthContext.auth_time` on both paths. `TokenProfile` plumbing. Strict `LedgerSigners`. Run the fleet sequence (Part B, stage 1) | `cargo test`, clippy, DB lane green |
| 1 (testnet) | Migration. `src/sep10/{mod,verify,build,key,ledger}.rs`. `handlers/{sep10_auth,stellar_keys,admin_sep10}.rs`. jwt/models/auth restriction, `AnyAuthUser`, `StepUpRequired`. token.rs refresh. Redis helpers. Config validation. main.rs merge. Custody cross-guards. Notifications. Events. openapi. `docs/runbooks/sep10.md`. SECURITY.md, ARCHITECTURE.md, `accounts-and-roles.md`, `rotate-secrets.md`. Android impala-lib codec and StrKey; app enrollment, login, DeviceKeyStore, e2e and emulator lane. lumencli `sep10 login`/`link-sign` and vectors. impalactl commands. sep10-interop workflow | Vectors, e2e and nightly lane green on testnet |
| 2 | Physical device matrix (two or more OEMs). Wallet-link soak. `attestation_rescan` scaffolding | Device report filed |
| 3 | `src/attestation/`, roots, status cache, rescan, corpus. `SEP10_DEVICE_MIN_LEVEL=tee`. Lift the pubnet refusal (wallet keys default off on pubnet). Per-use CryptoObject if the matrix confirms | Verdicts match Google's library; staging on pubnet passphrase |
| 4 | Refresh-token binding (§11) | T3 on two StrongBox devices |

**Deferred, with reasons.**

- client_domain (no Go verification).
- Muxed accounts and memos (no use case).
- The GET JWT.
- SEP-45 and the anchor role (would need `sub=G` tokens).
- Stellar RPC `getLedgerEntries` once Horizon retires, keeping the genuine-not-found rule.
- External toml publication.
- impala-ui wallet linking (it would trigger request-wide DPoP).
- Card-delete revocation and `auth_time` on `POST /card` (pre-existing gaps, separate change).

**Tests and tripwires (phase 0–1).**

- **Verifier:** `challenge_matches_go_txnbuild_vector`, `verifier_accepts_go_signed_vector`, the mutation matrix, `rejects_trailing_bytes`, `server_signature_never_counts`, `weight_floor_is_one`, `horizon_only_narrows_pinned_set`, `horizon_404_requires_problem_doc`, `funded_then_merged_refused`, `horizon_error_is_503`, `claim_outlives_replica_skew` (injected replica clocks).
- **Order pins:**
  - `increment_lockout` appears once, in the master-signature arm (`token.rs:305-325` style);
  - `check_rate_limit("sep10"` comes after `verify_master`;
  - `linked_and_unlinked_status_sequences_identical`.
- **Tokens:** `sep10_aud_requires_cid`, `legacy_validation_rejects_sep10_aud`, `refresh_preserves_profile_and_deadline`, `refresh_rechecks_link_allowlist_reserve_privileged`, `sep10_token_role_is_view_only`, `wallet_login_has_no_refresh_token`.
- **Extractors:** `authenticated_user_refuses_restricted`, `auth_context_refuses_restricted`, `any_auth_user_allow_list_is_exact`, `no_handler_takes_raw_auth_context_except_logout_all`, `revoked_cred_fails_closed`.
- **Extractor table** (`auth.rs:981`): add `admin_sep10`: 7 handlers, list → `Privileged<ReadKeys>`, generate/activate/revoke → `Privileged<ManageKeys>`, account list → `Privileged<ReadAccounts>`, exactly two `: AdminUser` (support unlink, revoke-sessions). Add `stellar_keys` per-handler extractors, and `sep10_auth` with no extractor.
- **Custody:** header-magic pairwise; generate-only (no import route, `drop(seed)`, no secret fields); `sep10` never references `load_protected_seed`, managed_seed loaders or `StellarSigner`; the `StellarSigner` method list is pinned.
- **Schema:** CHECK vocabularies against constants (`constants.rs:1411` pattern, no `strongbox`); bind counts for every new INSERT; SQL-columns-exist (`offline/issuer.rs:277-307` style).
- **Events:** FROZEN gains `account.stellar_login_key_linked`, `account.stellar_login_key_unlinked`, `custody.sep10_key_generated`, `custody.sep10_key_activated`, `custody.sep10_key_revoked`, `auth.sep10_sessions_revoked`. Payloads carry fingerprints, never addresses or labels.
- **Routing and config:** CORS and route pins (§4.3); `sep10_refused_unless_testnet_passphrase`; reserved SSO names; openapi path strings.
- **DB lane** (`tests/db/sep10.rs`): one active address, one pending and one active key, cascade, revocation coherence, the transfer path.


## 15. Threat table

| # | Threat | Control | Residual |
|---|---|---|---|
| T1 | Identity resolved from unverified `stellar_account_id` | Never read; only `stellar_login_key` | — |
| T2 | Custodial, reserve or bridge key logs in; a bridge seed signs as client | Eligibility at enroll, login and refresh; cross-guard on import; ring exposes only `sign_challenge`; tripwire | — |
| T3 | Replay or two tokens per challenge | `SET NX` claim on tx hash until maxTime + 120 s | Redis failover may drop a claim (same class as refresh claims) |
| T4 | Tampered or forged challenge | v1-only strict XDR, exact shape, MAC-bound nonce, server signature | — |
| T5 | Unauthenticated Redis fill (noeviction) | Login GET writes nothing per request; global ceiling; /64 buckets | Global ceiling can be exhausted → 503 for SEP-10 only |
| T6 | Linkage enumeration (429 vs 401, 503, timing) | Master signature checked before any lookup; Horizon only after a valid signature | — |
| T7 | Per-identity DoS on a public address | No per-G GET scope; per-G POST scope charged only after a verified signature; lockout per (G, source) | CGNAT neighbours of an attacker |
| T8 | Horizon amplification starving money paths | Signature first, semaphore, budget, 30 s cache | Key holders can still spend the SEP-10 budget |
| T9 | Phished link signature squats or hijacks a wallet | `"<home> link"` op0 that standard wallets refuse; account id in clear; `--expect-account` plus typed confirmation; app checks binding; transfer-by-proof; notifications | A user who confirms a foreign id |
| T10 | Login relay phishing | Domain ops, toml-pinned key, 300 s TTL, restricted session, wallet keys off on pubnet | Restricted read of PII for one hour |
| T11 | Restricted session reaches value, privilege or credentials | Restriction in `validate_request_auth`; pinned allow-list; view-only role; `logout_all` excluded | — |
| T12 | Escalation or laundering through refresh, skew or rollback | Restricted aud rejected by old binaries; profile-aware refresh re-runs every gate; fixed deadline | — |
| T13 | Stolen full token plants a key | `auth_time ≤ 600 s`, full session only, notifications, revoke-all | A thief within 10 min of a real login |
| T14 | Stolen phone | TEE key, 30 s user auth, restricted session, `cid` unlink from any full session, 24 h cap | Attacker who can unlock the phone: read-only access until unlink |
| T15 | Leaked wallet master key | Ledger rule with pinned set: zeroing the master weight or merging revokes | Until the holder acts on-chain |
| T16 | Client-asserted device kind skips the ledger | Bypass only for bridge-verified `tee` | — |
| T17 | Software key presented as hardware; leaked keybox | Bridge verification, serial persistence, continuous rescan | A compromised TEE until revocation |
| T18 | Signing-key compromise | Generate-only, sealed, MAC key needed too, TTL-exact, revoke and activate | Memory dump of a replica yields both |
| T19 | KMS/Vault amplification | Background single-flight decrypt, negative cache | — |
| T20 | Rotation mismatch training users past SERVER_IDENTITY | `activate_at` fence, toml max-age 60, refetch-once | Clients caching tomls beyond max-age |
| T21 | Wildcard CORS spill or missing ACAO | Exact three-route router merged after Timeout, own limits, no credentials, tripwires | — |
| T22 | Network confusion or a mis-set enum enabling pubnet early | Passphrase in hash; per-network hosts; passphrase-based gate | — |
| T23 | Shared-origin topology misroutes discovery | Mandatory endpoint, boot validation, explicit Android home domain | — |
| T24 | Device tricked into signing a payment | Strict on-device codec; only `VerifiedChallenge` signable | — |
| T25 | Ambiguous enrollment orphaning keys | Retry exemption; reconcile by GET | — |

---

## Part B — Worked scenario

Four stages, in the order a pilot runs them. Stages 1–3 exist today (the card
lane); stage 4 is what Part A adds. Every command below was run while writing
this document unless marked *(physical card)* or *(this design)*. Paths are
relative to `impala-card/` unless shown otherwise.

### Stage 1 — Fleet compatibility of the Impala CAP (scardutil)

**Goal.** Before any card is issued, know which card models run the Impala
applet identically. The oracle is `scardutil/impala-dispatch.md`: plaintext
commands only, so the same file runs on a physical card (install → checks →
delete) and on the simulator target, where the CAP steps are skipped.
[scardutil](https://github.com/Financial-Empowerment-Partners/scardutil)
(v0.1.0) drives GlobalPlatformPro/GPShell and raw PC/SC across many readers at
once; `scardutil/README.md` has the command cheat-sheet.

**1a. Read the CAP offline.** What the build declares, independent of any card:

```
$ scardutil cap-info applet/build/ImpalaApplet.cap
CAP: applet/build/ImpalaApplet.cap
  Package                com.impala.applet
  Package AID            0102030405060708
  Package version        0.4
  Applet AID             01020304050607080102 (ImpalaApplet)
  Application type       classic-applet
  CAP format             2.1
  Converter              [v3.1.0]
  Dependencies (imported packages):
      A0000000620001 v1.0  java.lang
      A0000000620201 v1.6  javacardx.crypto
      A0000000620102 v1.6  javacard.security
      A0000000620101 v1.6  javacard.framework
  Components (12489 bytes total): … Method.cap 7609 B …
```

The API-1.6 imports are the Java Card 3.0.5 surface the applet targets; a card
whose `profile` reports an older platform, no SCP03, or less free persistent
memory than the CAP plus the applet's state needs is ruled out here, before a
reader is touched.

**1b. Author the checks once.** The sequence is written in Markdown and
converted (`scardutil make-sequence scardutil/impala-dispatch.md -o impala-dispatch.json --cap-dir applet/build`).
The checks and the behaviour they pin:

| Step | APDU | Expect | What it proves |
|---|---|---|---|
| GET_VERSION | `00 64 00 00 00` | `9000`, data contains `00000002` | applet 0.2 |
| GET_PERSONALIZATION | `00 34 00 00 00` | `9000`, data starts `00 08` | blank state, SCP03 keys default |
| GET_EC_PUB_KEY before INITIALIZE | `00 24 00 00 00` | `6230` | no key yet |
| SIGN_AUTH before INITIALIZE | `00 25 00 00 08 …` | `6234` | personalization guard fires first |
| retired INS 06 / 14 | `00 06 …`, `00 14 …` | `6D00` | v0 transfer INS stay burned |
| non-SCP03 INS at CLA 80 | `80 30 …` | `6D00` | CLA 80 carries only SCP03 |
| transfer / read at CLA 84, no session | `84 30 …`, `84 34 …` | `6985` | secured CLA needs an open channel (not `6E00`: `SCP03.unwrapCommand` refuses before any INS is dispatched) |
| INITIALIZE, then again | `00 2C 00 00 04 …` ×2 | `9000`, then `6686` | one-shot key generation |
| GET_EC_PUB_KEY, GET_USER_DATA | `00 24 …`, `00 1E …` | `9000` | 65-byte `04‖X‖Y`, 32+ bytes of identity |
| SIGN_AUTH, initialized but unissued | `00 25 …` | `6234` | login impossible before PERSONALIZE |
| GET_RECEIVE_STATE, GET_LAST_TRANSFER | `00 35 …`, `00 36 …` | `9000`, `6A83` | counter 0, nothing signed |

**1c. Run it on the simulator target.** jcardsim's own `VSmartCard` only
*loads* applets from its config and never instantiates them (that is left to a
GlobalPlatform extension), so with the stock jar every SELECT answers `6999`.
`scripts/vpcd-sim.sh` (`VpcdSimulator`, simulator module) hosts the real
`ImpalaApplet` the way the SDK tests do and speaks the same vsmartcard
protocol scardutil expects:

```
$ scardutil test-sequence impala-dispatch.json --sim-cfg scardutil/impala-sim.cfg \
      --jcardsim "bash scripts/vpcd-sim.sh" --no-cap-info
Sequence: Impala applet 0.2 plaintext dispatch
  [SKIP] delete 0102030405060708  needs a card-management backend … skipped on a raw transport
  [SKIP] install ImpalaApplet.cap  needs a card-management backend … skipped on a raw transport
  [PASS] apdu 0064000000 -> 9000 (Success -- command completed normally)
         data: 00000002000000000000
  [PASS] apdu 0034000000 -> 9000 (Success -- command completed normally)
         data: 0008000000…
  [PASS] apdu 0024000000 -> 6230 (Warning -- non-volatile memory unchanged)
  [PASS] apdu 00250000080102030405060708 -> 6234 (Warning -- non-volatile memory unchanged)
  [PASS] apdu 0006000000 -> 6D00 (Instruction (INS) not supported or invalid)
  [PASS] apdu 0014000000 -> 6D00 (Instruction (INS) not supported or invalid)
  [PASS] apdu 8030000000 -> 6D00 (Instruction (INS) not supported or invalid)
  [PASS] apdu 8430000000 -> 6985 (Conditions of use not satisfied (wrong lifecycle state))
  [PASS] apdu 8434000000 -> 6985 (Conditions of use not satisfied (wrong lifecycle state))
  [PASS] apdu 002C00000400112233 -> 9000 (Success -- command completed normally)
  [PASS] apdu 002C00000400112233 -> 6686 (Security-related error)
  [PASS] apdu 0024000000 -> 9000 (Success -- command completed normally)
         data: 045BBD69B59B2EC33377CB62B8237D55CE8352A391DB7204DD445CB60BB5110D0DD75F5B78…
  [PASS] apdu 001E000000 -> 9000 (Success -- command completed normally)
         data: 0000000000000000000000000000000051D6342CFE534643FADA84D54BF179EC
  [PASS] apdu 00250000080102030405060708 -> 6234 (Warning -- non-volatile memory unchanged)
  [PASS] apdu 0035000000 -> 9000 (Success -- command completed normally)
         data: 0000000000000000…
  [PASS] apdu 0036000000 -> 6A83 (Record not found)
  [SKIP] delete 0102030405060708  needs a card-management backend … skipped on a raw transport
19 steps: 16 passed, 0 failed, 3 skipped
```

Two readings of that output matter later: `GET_USER_DATA` shows the all-zero
account UUID of an unissued card followed by its random card UUID (the
`card_id` wire form the bridge will see is those 16 bytes as 32 hex), and
`SIGN_AUTH` is refused until PERSONALIZE part C has landed — which is exactly
why the app checks personalization before it spends a login challenge.

**1d. The fleet.** `scardutil/fleet.example.json` declares the simulator plus
two readers; `"wait": 60` per reader turns one reader into a stack-of-cards
workflow (insert the next card when prompted). `evaluate` opens each target
once, runs the sequence for every CAP in the directory, and prints the matrix;
when targets disagree, its **Divergence** section lists the candidate and the
targets that differ, which is the compatibility finding the run exists to
produce.

```
$ cd scardutil && scardutil evaluate ../applet/build --targets fleet.example.json \
      --sequence impala-dispatch.json --cleanup --report-dir ../build/fleet-reports/
CAP evaluation matrix: …/impala-card/applet/build

                  jcardsim
ImpalaApplet.cap      PASS

== jcardsim  (simulator: managed, cfg …/scardutil/impala-sim.cfg)  [PASS]
   [PASS] ImpalaApplet.cap   (impala-dispatch.json)
   1/1 CAP file(s) passed

1/1 target(s) passed
```

*(physical card)* With readers present the same invocation adds a column per
card. Per card, also capture
`scardutil card-info --report-dir build/fleet-reports/<card-model>/ -r <n>`
(readers, `profile` with the JavaCard/GP versions, SCP03 options and free
memory, triage) — that report, plus the matrix row, is the entry for
`impala-card/docs/physical-evidence/` required by the card plan's A-4 item. The
`--cleanup` flag deletes the package afterwards so a card leaves the bench
blank. Use only blank, labelled test cards: the install step destroys any
instance and the value it holds. A card OS that intercepts CLA `80`/`84`, or
answers `61xx`/`6Cxx` on `GET_VERSION`, shows up in Divergence as a finding
about that card, not a test to relax.

**Boundary.** The applet implements SCP03 *inside itself* (CLA `84`:
INITIALIZE UPDATE `50`, EXTERNAL AUTHENTICATE `82`, PROVISION_PIN `70`,
APPLET_UPDATE `71`, PERSONALIZE `72`, TERMINATE `73`). scardutil's `secure:
true` steps and its `-k` keys address the GlobalPlatform *Issuer Security
Domain*, a different channel. So scardutil owns install, plaintext checks,
profiling and the matrix; issuance (stage 2) owns everything under CLA `84`.

### Stage 2 — Issue a card to a holder (issuance tool + bridge)

Prerequisites on the bridge: migrations ≥ 039, `KEY_IMPORT_ENABLED=true` with a
real protector, an issuer key (`POST /admin/card-issuer/generate`, once), and
the holder's account. The operator runs, per card:

```
export IMPALA_ISSUE_KMK=…            # 32 hex; per-card SCP03 keys = AES-CMAC(KMK, cardId‖label)
export IMPALA_HOLDER_TOKEN=…         # the holder's bearer: POST /card
export IMPALA_OPERATOR_TOKEN=…       # ManageKeys: the certificate
./gradlew :tools:issue:run --args="--transport pcsc --reader 'ACS ACR1252' \
    --account <holder uuid> --bridge https://bridge.example --currency XLM"
```

The ceremony (idempotent per step) verifies applet 0.2 and the blank state,
INITIALIZEs with host entropy, reads `cardId` and the card key, rotates SCP03
to the per-card keys, registers the key (`POST /card {account_id, card_id,
ec_pubkey}` — no `rsa_pubkey` since migration 038), obtains the bridge
certificate (`POST /admin/cards/{card_id}/certificate` → `program_id_hex`,
`issuer_public_key_hex`, `issuer_cert_hex`), runs PERSONALIZE A, B, C over the
per-card channel, provisions the master and user PINs, and prints the
signed-off record (`card_id`, account UUID, program id, currency, `cert_id`,
applet version, CAP sha256). A second run prints the same record and changes
nothing. The same tool with `--transport tcp:127.0.0.1:9443` issues the
simulated card the e2e lane uses.

### Stage 3 — Card login and a card-authorized transfer (Android demo)

**Login (E2E-1).** "Sign in with Card" arms reader mode; the tap is handled on
the NFC binder thread with the card still in the field:

1. `CardIdentity.read`: `GET_VERSION` (a 0.1 applet is refused before any V2
   command), `GET_PERSONALIZATION` (an unissued card is refused **here**, so it
   never spends the card's challenge budget), `GET_USER_DATA`, `GET_EC_PUB_KEY`.
2. `POST /auth/card/challenge {card_id}` — 32 bytes, 60 s TTL, at most five
   outstanding per card; fetched inside the login timeout so a slow network
   aborts before signing.
3. `SIGN_AUTH`: ECDSA-P256 over `"IMPALA-AUTH:" ‖ accountId(16) ‖ challenge`.
4. Main thread: `POST /auth/card {card_id, signature}` → refresh token →
   `POST /token` → temporal token. The bridge stamps the role from the DB and
   the allowlist; the session is indistinguishable from a password session.

This runs green against a live bridge on jcardsim in CI's `card-e2e` job
(`CardAuthE2ETest`: login, single-use challenge, unregistered card → generic
401, account mismatch refused client-side, 60 s expiry, five bad signatures →
lockout).

**Transfer (E2E-2).** The holder redeems stored value back to their custodial
Stellar account. The card, not the session, authorizes it:

1. Prepare (main thread): `GET /card-issuer` for the `redemption_uuid`,
   `GET /offline/cards/{card_id}` for the card's last redeemed counter; refuse
   if the issuer is unconfigured or the card is not certified.
2. Tap (binder thread): read and gate the identity; `GET_LAST_TRANSFER` for the
   previous send sequence; compose the 60-byte signable with
   `recipient = redemption_uuid`, `counter = last + 1`, `dateTime = max(prev + 1,
   now)`; **persist the slot to disk**; `SIGN_TRANSFER_V2` with the 4-digit user
   PIN (`0000` refused — the PIN-less path is a card policy, not a user choice);
   persist the tuple `(signable, DER signature, card pubkey, card certificate)`.
3. Submit: `POST /offline/redemptions` with those exact bytes; `202` records the
   id; a `202` replay or `409 counter_consumed` means the bridge already holds
   the debit; any other 4xx leaves a *stranded, not lost* tuple shown as "needs
   operator". The bridge verifies the 114-byte CERT message under the issuer
   key and the 89-byte XFER signature under the card key, then pays the
   holder's custodial account through the reserve watcher.
4. Track: poll until `paid` (with `btxid`), `failed`, or `cancelled`; `frozen`
   is shown as "outcome unknown — do not repeat" and blocks new redemptions
   from that card. A tuple lost to a crash is rebuilt from `GET_LAST_TRANSFER`
   and never re-signed.

The client half is built and tested against jcardsim with a mocked bridge
(`RedemptionViewModelTest`, `IssuanceViewModelTest`); the bridge's
`/offline/*` lane (plan item D-3) is still to be built, so the live transfer
tests skip until it exists.

### Stage 4 — SEP-10 sign-in with step-up to the card *(this design)*

**4a. Enable on the testnet bridge.** Run migration `04N` first, roll the
binary with `SEP10_ENABLED=false`, then as an operator with `ManageKeys`:

```
export SEP10_ENABLED=true
export SEP10_WEB_AUTH_ENDPOINT=http://10.0.2.2:8080/auth/sep10   # emulator → host; a pilot uses https://api-testnet.<org>/auth/sep10
impalactl sep10-key generate                                     # → version 1, state pending, fingerprint F1
impalactl sep10-key activate --confirm-supersede none            # phrase: "activate sep10-signing testnet"; live at activate_at = now + 120 s
impalactl sep10-key verify-toml                                  # fetches /.well-known/stellar.toml, compares SIGNING_KEY with the admin read
curl -s http://10.0.2.2:8080/.well-known/stellar.toml
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
WEB_AUTH_ENDPOINT="http://10.0.2.2:8080/auth/sep10"
SIGNING_KEY="GS…"
```

The bridge refuses to start with these set unless `STELLAR_NETWORK` is
explicitly `testnet` and the boot-verified passphrase is the testnet one
(§4.2). Conformance of the shape, before any key is linked: `lumencli account
new` (an unfunded key `GU…`), then
`lumencli --network testnet sep10 login --home-domain 10.0.2.2:8080 --insecure-loopback`.
The Go SDK's `ReadChallengeTx` accepts the challenge (server source, seq 0,
exact bounds, `"10.0.2.2:8080 auth"`, `web_auth_domain`, one server
signature); the `POST` answers a generic 401 because `GU…` is not linked — and
it is **not counted** toward any lockout, because the master signature was
valid (§7 step 5 counts only a bad master signature).

**4b. Link the phone.** Holder H signs in with the card (stage 3) — a full
session whose `auth_time` is seconds old. Settings → *Phone sign-in*:

1. Gate: API ≥ 33, `FEATURE_HARDWARE_KEYSTORE` ≥ 200, secure lock screen.
   `POST /account/stellar-keys/enrollments {key_kind: "device", device_label: "Pixel 8", install_id}`
   → `{enrollment_id, attestation_nonce, expires_at}`.
2. The app generates the Ed25519 key with `setAttestationChallenge(nonce)`,
   checks `KeyInfo.securityLevel == TRUSTED_ENVIRONMENT`, derives `GD…` from
   the SPKI, and calls `POST …/enrollments/{id}/challenge {stellar_address: "GD…"}`.
   The reader validates the **link** challenge: op0 `"10.0.2.2:8080 link"`
   sourced by `GD…`, `web_auth_domain = 10.0.2.2:8080`,
   `impala_link_account` = H's id (shown on screen), one server signature under
   `SIGNING_KEY`, passphrase = testnet.
3. `BiometricPrompt` ("Turn on phone sign-in — anyone who can unlock this
   phone can sign in to your Impala account (read-only; payments still need
   your card)"), sign the hash, `POST /account/stellar-keys {enrollment_id,
   transaction, attestation_chain}`. The bridge verifies the link challenge,
   sees a genuine Horizon `not_found` problem document for `GD…`, inserts the
   link as `device` / `unfunded` / `unverified` with the chain stored
   `pending` (verified retroactively in phase 3), emits
   `account.stellar_login_key_linked`, notifies H, and answers 201.
   `DeviceKeyStore.commit()`; the screen says *"Phone sign-in is on — hardware
   protection not yet verified"*.

A lost response on the last call is treated as **ambiguous**: the app keeps the
key, lists `GET /account/stellar-keys` and reconciles by address.

**4c. Sign in with this phone.** Log out: `TokenManager` is cleared,
`DeviceKeyStore` is kept, the button stays. Tap *Sign in with this phone*:
step A inside the 15 s budget (toml cached ≤ 60 s → `GET /auth/sep10?account=GD…`
→ validate: `" auth"`, exact bounds, server signature, passphrase) → the
prompt, outside any timer → step C (`sign` → `POST /auth/sep10` →
`{token, temporal_token, refresh_token}` → `completeTokenFlow("sep10")`). The
bridge verified the master signature before any lookup, read the link, ran
the ledger rule (a Horizon `not_found` for `GD…` — until a bridge-verified
`tee` level lets an attested key skip it), claimed the challenge hash and
minted a **restricted** session: `aud = impala-bridge-api-sep10`, `cid` =
the link id, `role = view-only`, `sub = H`, refresh token with a fixed 24 h
deadline. Main shows H's account and transactions.

**4d. Step up to the card.** The SEP-10 session identifies the payee account
and nothing more:

- Transfers → *Redeem from card*: the app asks for the tap and the PIN; the
  card's `SIGN_TRANSFER_V2` produces the tuple; the submit is on the
  `AnyAuthUser` allow-list; the bridge verifies the certificate and the XFER
  signature exactly as for a password session and credits only
  H = card owner = tuple account = `sub` (still blocked live by lane D-3, as
  in stage 3).
- Transfers → *Load card* (`/managed-account/sign`) → `403 step_up_required`;
  the app offers card or password login.
- Settings → *Add a card*, *Phone sign-in* on another phone, MFA, notification
  channels, *Sign out everywhere* → `403`. A phone alone can never add or
  remove credentials; the only mutation it may make is
  `DELETE /account/stellar-keys/current`, revoking itself.

**4e. Lost phone.** From any full session (`impalactl stellar-keys unlink <id>`
after a password login, the admin support route, or `revoke-all`): the link
row is revoked and `impala:revoked_cred:{cid}` is written before commit. The
phone's very next request answers 401 — there is no epoch bump and no
`iat`-second race, because every token that link ever minted carries its
`cid` — and the owner's other sessions survive. The phone's *Sign in with this
phone* now answers a generic 401, uncounted (its master signature is still
valid; the link is gone). H receives the unlink notification.

**4f. Negatives the pilot records.**

| Case | Expected |
|---|---|
| Replay the captured `POST` | 401 (claim exists), uncounted |
| Tamper one nonce byte | 401 (MAC and server signature fail), uncounted |
| Six bad client signatures from one source, for `GD…` and for an unlinked `G…` | identical 401 ×5 then 429 sequences; the holder signs in from another source unaffected |
| Validly signed challenge for an unlinked key | 401, uncounted |
| `GET /auth/sep10?account=M…`, or with `memo` | 400 |
| A login challenge presented to `POST /account/stellar-keys`, or a link challenge to `POST /auth/sep10` | 401 (op set and MAC purpose) |
| Link attempt from a SEP-10 session | 403 `step_up_required` |
| Link attempt by a treasurer, admin or allowlisted account; or a session older than 600 s | 403 `sep10_not_allowed` / `reauth_required` |
| Device link for a funded key | 409 `device_key_on_ledger` |
| SEP-10 session calls `/managed-account/sign`, `POST /logout/all`, `DELETE /card` | 403 |
| Key rotation (`generate` + `activate`) between `GET` and `POST` | 200 (superseded grace) |
| Horizon down | 503 for logins that need the ledger rule (every link until it is bridge-verified `tee`); linking answers 503 and does not burn the challenge |
| Unlink during a login in flight | the minted token is already dead (`cid`) |

**4g. Wallet path (testnet, phase 1 opt-in).**
`impalactl stellar-keys enroll-wallet --address G_W | lumencli sep10 link-sign --expect-account $H --server-key GS… --home-domain 10.0.2.2:8080 | impalactl stellar-keys complete --enrollment-id …`,
then `lumencli --network testnet sep10 login --home-domain 10.0.2.2:8080 --insecure-loopback`.
The result is a **temporal-only** restricted token (no refresh token for
wallet links) that works on `GET /account`; a signer added to `G_W` on-chain
afterwards cannot log in, because Horizon may only narrow the pinned set.

**What the pilot proves.** Stage 1 that the applet behaves identically across
the fleet before any value is loaded; stage 2 that issuance is a repeatable,
auditable ceremony; stage 3 that the card can both authenticate and authorize;
stage 4 that a phone can authenticate as conveniently as a password while the
card, not the phone, keeps authorizing value — and that losing the phone is a
revocation, not a compromise.
