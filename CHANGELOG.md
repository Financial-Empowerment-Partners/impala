# Changelog

All notable changes to this repository are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
first tagged release exists.

## [Unreleased]

### Added
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
- `impala-ui/package.json`, `impala-ui/vitest.config.js`, and `impala-ui/tests/validate.test.js` — Vitest harness covering the Validate module; further UI tests can be added alongside.
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
