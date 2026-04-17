# Contributing to payala-impala

Thanks for your interest. This document covers local setup, per-sub-project workflows, and conventions we expect in pull requests. For architectural context read [ARCHITECTURE.md](ARCHITECTURE.md); for everyday build commands and gotchas read [CLAUDE.md](CLAUDE.md).

## Repository layout

Six sub-projects, each with its own build tool:

| Sub-project | Stack | Build tool |
|---|---|---|
| `impala-bridge` | Rust 2021 / Axum 0.4 | Cargo |
| `impala-card` | JavaCard applet + Kotlin Multiplatform SDK | Gradle + Ant |
| `impala-soroban` | Soroban smart contracts (Rust, `no_std`) | Cargo (two crates) |
| `impala-lib` | Android NFC / geolocation library | Gradle |
| `impala-android-demo` | Android demo app | Gradle |
| `impala-ui` | Vanilla JS admin dashboard | None (static + Nginx) |

The root has no workspace or umbrella build; use the root [`Justfile`](Justfile) for common recipes.

## Prerequisites

- **Rust** ≥ 1.89.0 (soroban contracts require it; bridge is happy with the same), `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- **JDK 17** (JavaCard, Kotlin, Android all require it)
- **Kotlin 2.2.10** via Gradle wrapper (no local install needed)
- **Docker** + **Docker Compose** for the bridge/UI stacks
- **Node** is *not* required yet — UI is served static.
- **`just`** command runner (optional but recommended): `brew install just`

Optional, by integration:
- `stellar` CLI for `impala-soroban/testnet-tests`
- `terraform` for deploying AWS infra
- Ant for building JavaCard `.cap` artifacts

## Local bootstrap

```bash
# Clone and enter the repo
git clone <repo-url> && cd payala-impala

# Start bridge + Postgres + Redis (required for most bridge work)
just up

# Run every sub-project's test suite
just test

# Run all linters
just lint
```

If you don't have `just`, the equivalent manual commands live in [CLAUDE.md](CLAUDE.md) under "Build Commands".

## Per-sub-project workflows

### `impala-bridge` (Rust)

```bash
cd impala-bridge
cp .env.example .env          # edit DATABASE_URL and JWT_SECRET at minimum
cargo build
cargo test                    # unit tests; integration tests require docker compose up
cargo clippy -- -D warnings
cargo fmt --check
```

- Uses Axum 0.4 — do not "upgrade" state extractors; shared state is passed via `Extension` layers.
- Uses sqlx 0.6 with raw SQL — no ORM. Queries are parameterized.
- Security-critical code in `auth.rs`, `jwt.rs`, `redis_helpers.rs`, and all `require_owner()` sites must not be weakened without review.

### `impala-card` (Kotlin Multiplatform + JavaCard)

```bash
cd impala-card
./gradlew :sdk:jvmTest                    # SDK tests, JVM target
./gradlew :applet:jvmTest                 # Applet tests via jcardsim
ant -f applet/build.xml buildJavacard     # Produce .cap file (JC 3.0.5u4)
```

The applet module has pre-existing compilation errors (missing classes that are not yet checked in). Build the SDK target only until those classes are in place.

### `impala-soroban` (Soroban contracts)

```bash
cd impala-soroban/integration-test
cargo test
cargo build --release   # emits WASM to target/wasm32-unknown-unknown/release/

cd ../testnet-tests
cargo test              # slow; needs the stellar CLI + testnet connectivity
```

Both crates are independent — no workspace root.

### `impala-lib` and `impala-android-demo`

```bash
cd impala-lib && ./gradlew test
cd ../impala-android-demo && ./gradlew assembleDebug
```

Demo app needs `app/google-services.json` (FCM; gitignored) and OAuth client IDs configured in `app/build.gradle.kts`.

### `impala-ui`

```bash
cd impala-ui
docker compose up       # Nginx on :3000; requires impala-bridge's compose network
```

There is currently no bundler or test runner — changes are live-edited under `html/`. A Vitest harness is being introduced (see `/tests/`).

## Formatting & linting

- **Rust**: `cargo fmt --check` and `cargo clippy -- -D warnings` are gated in CI.
- **Kotlin**: `kotlin.code.style=official` is declared via `gradle.properties`. Please run your IDE's formatter.
- **Terraform**: `terraform fmt -recursive` is gated in CI.
- **Markdown/YAML/JSON**: no enforced formatter; keep lines under 120 chars where reasonable.

A root `.editorconfig` captures the cross-language basics (LF endings, 4-space Kotlin/Rust, 2-space YAML/JSON).

## Testing expectations

Please add a test alongside your change when you:
- Add a new HTTP handler or route (unit test the happy path and one error path).
- Modify `require_owner()` call sites, rate-limit checks, or any Redis-backed security primitive.
- Change validation logic (`validate.rs`, `impala-ui/html/js/validate.js`).
- Introduce a new SQL query (mock via sqlx test fixtures if possible).
- Touch Soroban contract code (add schedule/execute and cancel cases).

The coverage tool for the bridge is `cargo-tarpaulin`; Kotlin uses Kover; JS uses c8. Coverage reports are advisory today, not gates.

## Commit & PR style

- **Commit messages**: imperative mood, under 72 chars for the subject. Body wraps at 80. Reference tickets with `#<id>`.
- **Branches**: `feature/<short-name>`, `fix/<short-name>`, `chore/<short-name>`.
- **PRs**: one logical change per PR. Include a short rationale, the testing you ran, and any risk notes.
- **Signing**: not required today, but do not use `--no-verify` or `-c commit.gpgsign=false` to bypass hooks.

## Security reporting

Do **not** open a public issue for suspected vulnerabilities. Email the maintainers privately. See `impala-bridge/SECURITY.md` for the bridge threat model.

## Code of conduct

Be kind, concise, and evidence-driven in reviews. When in doubt, ask before deleting or renaming.
