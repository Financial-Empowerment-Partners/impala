# Changelog

All notable changes to this repository are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
first tagged release exists.

## [Unreleased]

### Added
- **Admin console: server-side roles, account management, transaction review, directory sync, and on-chain refresh.** The bridge gains a server-side `role` claim (`view-only`/`device`/`token`/`admin`) embedded in the JWT and enforced via a new `require_admin` guard — the web UI now reads the role from the token instead of browser `localStorage`. New migrations `019_add_account_role.sql` (role column + first-account-admin bootstrap trigger + backfill), `020_add_profile_source.sql` (`profile_source`/`profile_synced_at`), and `021_create_transaction_review.sql` (1:1 review table). New admin-only endpoints `GET /accounts` (paginated/searchable list), `DELETE /admin/accounts/:id` (transactional, with last-admin/self guards), `PUT /admin/accounts/:id/role`, and `POST /admin/accounts/:id/sync-profile` (force LDAP directory re-pull, writing name/affiliation back to `impala_account`). New transaction endpoints `GET /transactions` (admin=all, owner=own via `source_account`↔`stellar_account_id`), `GET /transaction/:btxid`, and `PUT /transaction/:btxid/review` (flag/status/note, admin-only). New `GET /account/onchain` returns live Horizon balances/sequence/signers for this bridge's configured network. `GET /account` is now enriched (role, profile source, stellar id, timestamps) and admins may read/create/update any account. The admin web UI (`impala-ui`) is rebuilt accordingly with a refreshed token-based theme + dark mode, a real account console, server-backed transaction flagging, a force-sync action, and a testnet/mainnet network selector that routes `/api/<network>/*` to the matching bridge deployment (tokens namespaced per network).
- **`impala-ui` frontend rebuild (Workstream B).** New IIFE modules `config.js` (ops-editable `window.IMPALA_CONFIG`), `net-config.js` (pure base/key resolution + per-network token-key namespacing), `net.js` (network selector + `GET /network` live confirmation), `theme.js` (light/dark, two-tier CSS token system), `modal.js`/`drawer.js` (framework-free accessible overlays — no jQuery/Foundation JS), and `tx-filter.js` (pure `GET /transactions` query builder). `roles.js` is now server-driven (reads the JWT `role` claim, no `localStorage` store) with new permissions `review_transactions`/`delete_accounts`/`sync_profile`; `api.js` resolves its base path per active network and namespaces tokens (`temporal_token::<network>`). `accounts.html`/`accounts.js` are rebuilt into a paginated console with a detail drawer (role grant, force-sync, on-chain refresh) and create/edit/delete using the real bridge fields; `transactions.html`/`transactions.js` gain a filter bar + server-backed flag/annotate review modal; `admin.html`/`admin.js` become a read-only roles & permissions reference. `nginx.conf` routes `/api/testnet/` and `/api/mainnet/` to per-network bridges. Added `eslint.config.js` (flat config) + `@eslint/js`, and vitest suites `tests/net-config.test.js`, `tests/tx-filter.test.js`, `tests/roles.test.js`.
- **OpenBao support (API-compatible Vault fork) in impala-bridge.** OpenBao is now the default *local* secrets backend: `docker compose up` / `just up` starts a local OpenBao dev server and wires the bridge to it for custodial-seed Transit protection (`SEED_PROTECTION_BACKEND=openbao`), so `/managed-account/*` works locally without AWS KMS. Both the seed protector and the `DATABASE_URL_WRAPPED` unwrap accept OpenBao-native `BAO_*` env vars (`BAO_ADDR`/`BAO_TOKEN`/`BAO_TRANSIT_KEY`/`BAO_ROLE_ID`/`BAO_SECRET_ID`), falling back to `VAULT_*`. `openbao` is a selectable `seed_protection_backend` in Terraform (external server, like Vault); it canonicalizes to the existing Transit backend, so persisted seeds keep the `vault` tag and stay decryptable with no migration.
- **Custodial Stellar accounts in impala-bridge.** The bridge can now generate or import a Stellar secret seed, protect it at rest behind a pluggable backend, and sign + submit payments server-side. New endpoints: `POST /managed-account/generate`, `POST /managed-account/import`, `POST /managed-account/sign` (all `require_owner`-gated; the sign endpoint is rate-limited and server-only). New `seed_protect` module (`SeedProtector` trait + AWS KMS envelope-encryption and Vault Transit backends; seeds held only in zeroizing `SecretBytes`, fail-closed), `stellar` module (`StellarSigner` on `stellar-base 0.7`), migration `018_create_managed_seed.sql`, and `SEED_PROTECTION_BACKEND` / `KMS_SEED_KEY_ID` / `VAULT_ADDR` / `VAULT_TRANSIT_KEY` config. Terraform `seeds.tf` provisions the seed CMK (multi-Region for DR), scoped IAM grants, and injects the env into all task definitions.
- Root `CONTRIBUTING.md` with per-sub-project dev workflows, testing expectations, and commit style.
- Root `CHANGELOG.md` seeded.
- `terraform/README.md` covering init → plan → apply, secrets injection, migration task invocation, and rollback.
- Root `Justfile` exposing `just up`, `just down`, `just test`, `just lint`, `just fmt` across sub-projects.
- Compile-time assert on `REFRESH_TOKEN_TTL_SECS` in `impala-bridge/src/constants.rs` to prevent future silent TTL drift.
- CI workflows for every sub-project: `ci-card.yml`, `ci-lib.yml`, `ci-demo.yml`, `ci-soroban.yml`, `ci-ui.yml`. Previously only `impala-bridge` was built and tested in CI.
- `security.yml` workflow running gitleaks, Trivy (filesystem + Dockerfile), tfsec, and cargo-deny across three Rust crates.
- `.github/dependabot.yml` covering cargo, gradle, npm, docker, terraform, and github-actions.
- `.editorconfig` and `.pre-commit-config.yaml` for cross-language formatting hygiene.
- `impala-bridge/deny.toml` (cargo-deny configuration covering advisories, licenses, bans, and sources).
- `impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/SCP03ChannelTest.kt` — defensive unit tests for the host-side SCP03 secure-channel state machine.
- Two regression tests in `impala-soroban/integration-test/src/lib.rs` (`test_wrap_requires_signer_auth`, `test_schedule_unwrap_requires_signer_auth`) that run without `env.mock_all_auths()` to catch accidental removal of `require_auth()` calls in `verify_multisig`.
- `impala-ui/package.json`, `impala-ui/vitest.config.js`, and `impala-ui/tests/validate.test.js` — Vitest harness covering the Validate module; extended with `tests/net-config.test.js`, `tests/tx-filter.test.js`, and `tests/roles.test.js`.
- `SHUTDOWN_DRAIN_DEADLINE_SECS` constant and drain-deadline watchdog in `main.rs:shutdown_signal` that force-exits if in-flight requests haven't drained within 25 s of SIGTERM.
- `impala-bridge/openapi.yaml` — OpenAPI 3.1 specification covering all ~30 endpoints with schemas, auth, and error responses.
- `docs/runbooks/deploy.md`, `docs/runbooks/incident-response.md`, `docs/runbooks/rotate-secrets.md` — operational runbooks for day-2 work.
- `impala-card/docs/apdu.md` — central APDU command reference (INS codes, data, response, auth requirements) derived from the applet source.
- Top-level README now links to all of the above.

### Changed
- Normalized refresh-token TTL references to **14 days** (the value in `impala-bridge/src/constants.rs`) across `impala-bridge/SECURITY.md`, `impala-ui/README.md`, `impala-ui/html/js/api.js`, `impala-ui/html/js/auth.js`, `impala-android-demo/README.md`, `impala-android-demo/.../BridgeApiService.kt`, `impala-android-demo/.../TokenManager.kt`, `impala-android-demo/.../LoginViewModel.kt`. Docs previously claimed 30 days; code was always 14.
- Replaced the outdated "24 endpoints" label in `ARCHITECTURE.md` with "~30 endpoints" to reflect the actual router.
- **Global HTTP request timeout** of 30 seconds now enforced via `tower::timeout` at the router boundary; any request that exceeds it returns HTTP 408 with a JSON envelope matching the rest of the API.
- **Postgres `statement_timeout`** of 60 seconds is set per connection via a new `after_connect` hook on the sqlx pool, so no single query can wedge a connection indefinitely.
- **Rate limiting expanded** from just `/authenticate` and `/token` to also cover `POST /transaction`, `POST /card`, and `POST /mfa/verify`. Each uses the same 10-requests-per-60-second Redis-backed window keyed by the authenticated user's account id (plus the mfa_type, for MFA verification).
- `tower` dependency pulled in with the `timeout` and `util` features enabled.

### Fixed
- Documentation drift between `SECURITY.md` and `constants.rs`; docs now match the compiled value.

## Historical

Prior changes are documented in git history. Consult `git log --oneline` for
the commit-level record; this file is the authoritative surface for notable
changes going forward.
