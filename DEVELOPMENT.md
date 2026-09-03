# Development Setup

Impala is a polyglot monorepo. Each sub-project builds and tests independently —
there is no root build system. This guide covers the prerequisites and the
local run/test loop for each component. For architecture see
[`ARCHITECTURE.md`](ARCHITECTURE.md); for build-command detail see
[`CLAUDE.md`](CLAUDE.md).

## Prerequisites

| Tool | Version | Used by |
|------|---------|---------|
| Rust | **1.91+** (workspace floor; bridge pins `rust-version = "1.91"`) | `impala-bridge`, `impala-soroban` |
| `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` | `impala-soroban` |
| JDK | 17 | all Gradle projects |
| Android SDK | compileSdk/targetSdk **36**, build-tools 35.0.0, minSdk 24 | `impala-card`, `impala-lib`, `impala-android-demo` |
| Docker + Docker Compose | recent | `impala-bridge`, `impala-ui` |
| PostgreSQL 16 / Redis 7 | (or use the bridge's `docker compose`) | `impala-bridge` |
| `stellar-cli` | recent | `impala-soroban` testnet tests (the fixture self-issues a test USDC asset — throwaway issuer, SAC deploy, trustlines, payment — no Circle faucet needed) |
| Node.js | LTS | `impala-ui` tests |

Set `ANDROID_HOME` (or `sdk.dir` in each Gradle project's `local.properties`) for
the Android builds.

## Run / test loop per component

### impala-bridge (Rust / Axum)
```bash
cd impala-bridge
cp .env.example .env          # fill in DATABASE_URL, REDIS_URL, JWT_SECRET (>=32 chars)
docker compose up --build     # full stack: Postgres 16 + Redis 7 + bridge :8080
# or, bridge only against existing services:
cargo run                     # RUN_MODE=server (default) | worker | migrate
cargo test
```
How `.env` is consumed differs between the two paths:
- `cargo run` — the binary itself loads `./.env` from its working directory at
  startup (development convenience). Variables already set in the process
  environment always win, and the runtime Docker image carries no `.env`, so
  production configuration still comes from the orchestrator.
- `docker compose up` — Compose does **not** forward `.env` wholesale. The
  bridge container sees only the explicit `environment:` map in
  `impala-bridge/docker-compose.yml`; `.env` values are used there solely to
  fill that map's `${VAR:-default}` placeholders. Anything not in the map —
  `RESERVE_*`, `KEY_IMPORT_ENABLED`, `ADMIN_ACCOUNT_IDS`,
  `CORS_ALLOWED_ORIGINS`, … — must be added to it or passed through.

At startup (server and worker modes) the bridge also asserts that the
configured Stellar network passphrase matches what the configured Horizon
serves, and exits on a mismatch or when Horizon stays unreachable.

### impala-soroban (Soroban contracts)
```bash
cd impala-soroban/integration-test
cargo build --release --target wasm32-unknown-unknown   # WASM artifact (target flag required)
cargo test                                              # in-process, no network
cd ../testnet-tests && cargo test                       # end-to-end, needs stellar-cli + network
```

### impala-card (JavaCard applet + KMP SDK)
```bash
cd impala-card
./gradlew :sdk:jvmTest            # SDK tests on JVM (jcardsim simulator)
./gradlew :applet:buildJavacard   # build the CAP file
```
iOS NFC: see [`impala-card/docs/IOS_NFC.md`](impala-card/docs/IOS_NFC.md)
(requires macOS/Xcode + a physical device to verify).

### impala-lib (Android NFC library)
```bash
cd impala-lib
./gradlew assembleDebug
./gradlew testDebugUnitTest        # Robolectric multi-SDK (24 + 36)
```

### impala-android-demo (reference app)
```bash
cd impala-android-demo
./gradlew assembleTnetDebug assembleLiveDebug          # two APKs (testnet + pubnet)
./gradlew testTnetDebugUnitTest testLiveDebugUnitTest  # JVM unit tests
```
Copy OAuth/bridge config into `local.properties` (`TESTNET_*` / `LIVE_*` keys)
before exercising auth flows.

### impala-ui (admin dashboard)
```bash
cd impala-ui
docker compose up   # Nginx :3000, proxies /api/* -> impala-bridge:8080
npm install && npm test   # Vitest unit tests
```
Bring `impala-bridge` up first so the `impala-bridge_default` Docker network exists.

### terraform
```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```
See [`terraform/README.md`](terraform/README.md) for the remote-state backend and
the module/migration runbook.
