# Payala-Impala

**A secure bridge between offline Payala payments and the Stellar network, using Soroban smart contracts, hardware-protected cryptographic primitives (JavaCard smartcard), and Android bindings.**

Impala connects the Payala offline payment system to Stellar's on-chain infrastructure through a six-component architecture. The REST API bridge handles authentication, transaction recording, and event streaming. A JavaCard applet provides a hardware root of trust with ECDSA signing, PIN-protected key storage, and SCP03 secure messaging. Soroban smart contracts enforce multisig authorization and time-locked operations for wrapping, unwrapping, and transferring assets. Android libraries and a demo app deliver NFC card communication and mobile integration out of the box.

## Components

| Component | Language / Framework | Purpose |
|---|---|---|
| **impala-bridge** | Rust / Axum | REST API server — authentication, transactions, notifications, Stellar event streaming, background job processing |
| **impala-card** | Java (JavaCard) + Kotlin Multiplatform | Smartcard applet (23 APDU commands) and cross-platform SDK for NFC card communication |
| **impala-soroban** | Rust / Soroban SDK | `MultisigAssetWrapper` smart contract with time-locked operations and multisig verification |
| **impala-lib** | Kotlin / Android | Android library for NFC (IsoDep + NDEF) and geolocation integration |
| **impala-android-demo** | Kotlin / Android | Demo app with 5 auth methods, card management, transfers, and push notifications |
| **impala-ui** | JavaScript / HTML / CSS | Admin dashboard with client-side RBAC, served via Nginx |

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Detailed system design, data flows, security architecture, API endpoint reference, APDU command reference, smart contract interface, deployment topology, and mermaid diagrams
- **[CLAUDE.md](CLAUDE.md)** — Build commands, environment variables, and development notes for all subprojects

## Quick Start

```bash
# Start the bridge with PostgreSQL and Redis
cd impala-bridge
docker compose up

# Run bridge tests
cargo test

# Run JavaCard SDK tests (JVM, no hardware needed)
cd impala-card
./gradlew :sdk:jvmTest

# Run Soroban contract tests
cd impala-soroban/integration-test
cargo test
```

See [CLAUDE.md](CLAUDE.md) for complete build instructions, required environment variables, and per-component commands.
