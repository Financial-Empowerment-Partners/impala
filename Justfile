# payala-impala root recipes
# Run `just` with no arguments to list targets.

# Show all recipes.
default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# Full-stack lifecycle
# ---------------------------------------------------------------------------

# Start bridge + postgres + redis (and UI on :3000).
up:
    docker compose -f impala-bridge/docker-compose.yml up -d
    docker compose -f impala-ui/docker-compose.yml up -d

# Stop all compose stacks.
down:
    -docker compose -f impala-ui/docker-compose.yml down
    -docker compose -f impala-bridge/docker-compose.yml down

# Tail bridge logs.
logs:
    docker compose -f impala-bridge/docker-compose.yml logs -f bridge

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

# Run every sub-project's test suite.
test: test-bridge test-card test-lib test-demo test-soroban test-ui

# impala-bridge unit + integration tests.
test-bridge:
    cd impala-bridge && cargo test

# impala-card SDK tests (JVM target; applet has known-missing classes).
test-card:
    cd impala-card && ./gradlew :sdk:jvmTest

# impala-lib unit tests.
test-lib:
    cd impala-lib && ./gradlew test

# impala-android-demo unit tests.
test-demo:
    cd impala-android-demo && ./gradlew test

# impala-soroban contract tests (integration + testnet).
test-soroban:
    cd impala-soroban/integration-test && cargo test
    cd impala-soroban/testnet-tests && cargo test

# impala-ui test harness (Vitest once installed).
test-ui:
    @if [ -f impala-ui/package.json ]; then cd impala-ui && npm test; else echo "impala-ui: no test runner configured yet"; fi

# ---------------------------------------------------------------------------
# Linting and formatting
# ---------------------------------------------------------------------------

# Run every linter.
lint: lint-bridge lint-terraform lint-soroban

# Bridge: rustfmt --check + clippy -D warnings.
lint-bridge:
    cd impala-bridge && cargo fmt --check && cargo clippy -- -D warnings

# Terraform: fmt + validate.
lint-terraform:
    cd terraform && terraform fmt -check -recursive && terraform validate

# Soroban: rustfmt --check + clippy -D warnings.
lint-soroban:
    cd impala-soroban/integration-test && cargo fmt --check && cargo clippy -- -D warnings
    cd impala-soroban/testnet-tests && cargo fmt --check && cargo clippy -- -D warnings

# Format Rust and Terraform.
fmt:
    cd impala-bridge && cargo fmt
    cd impala-soroban/integration-test && cargo fmt
    cd impala-soroban/testnet-tests && cargo fmt
    cd terraform && terraform fmt -recursive

# ---------------------------------------------------------------------------
# Build artifacts
# ---------------------------------------------------------------------------

# Build every sub-project (debug).
build: build-bridge build-card build-soroban build-demo build-lib

build-bridge:
    cd impala-bridge && cargo build

build-card:
    cd impala-card && ./gradlew :sdk:jvmJar

build-soroban:
    cd impala-soroban/integration-test && cargo build --release --target wasm32-unknown-unknown

build-demo:
    cd impala-android-demo && ./gradlew assembleDebug

build-lib:
    cd impala-lib && ./gradlew build

# ---------------------------------------------------------------------------
# Security / audit
# ---------------------------------------------------------------------------

# Run cargo-audit across Rust crates (requires `cargo install cargo-audit`).
audit:
    cd impala-bridge && cargo audit
    cd impala-soroban/integration-test && cargo audit
    cd impala-soroban/testnet-tests && cargo audit

# Scan Dockerfiles with trivy (requires `brew install trivy`).
scan-docker:
    trivy config impala-bridge/Dockerfile
    trivy config impala-ui/Dockerfile 2>/dev/null || true

# Scan terraform with tfsec (requires `brew install tfsec`).
scan-tf:
    tfsec terraform
