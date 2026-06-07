# Contributing to Impala

Impala is a polyglot monorepo with six independently-built sub-projects and no
top-level build system. `cd` into the relevant sub-project before building or
testing. See [`DEVELOPMENT.md`](DEVELOPMENT.md) for environment setup and
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the system design.

## Workflow

1. Branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. Make focused changes scoped to one sub-project where possible — CI is
   path-filtered per sub-project, so unrelated changes just slow review.
3. Run the relevant checks locally (see below) before opening a PR.
4. Open a PR against `main`. CI must be green before merge.

## Per-sub-project checks (run before pushing)

| Sub-project | Commands |
|-------------|----------|
| `impala-bridge` | `cargo fmt -- --check` · `cargo clippy -- -D warnings` · `cargo test` · `cargo audit` |
| `impala-soroban` | `cargo fmt -- --check` · `cargo clippy -- -D warnings` · `cargo test` (per crate) · `cargo build --release --target wasm32-unknown-unknown` (in `integration-test`) |
| `impala-card` | `./gradlew :sdk:jvmTest` |
| `impala-lib` | `./gradlew testDebugUnitTest` |
| `impala-android-demo` | `./gradlew testTnetDebugUnitTest testLiveDebugUnitTest` |
| `impala-ui` | `npm test` (Vitest) |
| `terraform` | `terraform fmt -check -recursive` · `terraform validate` |

CI gates `cargo fmt`/`clippy -D warnings` for Rust — warnings fail the build.
Preserve the bridge's **fail-closed** Redis invariants and the `require_owner()`
authorization pattern (see [`impala-bridge/SECURITY.md`](impala-bridge/SECURITY.md)).

## Commit & PR conventions

- Keep commits scoped and described in the imperative ("Add …", "Fix …").
- Reference the affected sub-project in the PR title (e.g. `impala-bridge: …`).
- Update docs (`ARCHITECTURE.md`, sub-project READMEs, `CLAUDE.md`) when behavior,
  versions, or commands change — doc drift is treated as a defect.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. Email the maintainers
privately (see the repository owner contact). The bridge's threat model lives in
[`impala-bridge/SECURITY.md`](impala-bridge/SECURITY.md); read it before changing
auth, rate limiting, MFA, or any Redis-backed check.
