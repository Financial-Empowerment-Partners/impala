# Impala Soroban Smart Contracts

Soroban smart contracts for moving funds into and out of the Payala program, supporting bulk payments, offline escrow, and multi-party authorization via the Stellar network.

## Structure

Two independent Rust crates (no workspace root):

```
impala-soroban/
├── integration-test/     # MultisigAssetWrapper contract (compiles to WASM)
│   ├── Cargo.toml
│   └── src/lib.rs
└── testnet-tests/        # Integration tests against Stellar testnet
    ├── Cargo.toml
    ├── src/lib.rs         # Test utilities (CLI wrappers, identity management)
    └── tests/
        └── integration.rs # End-to-end tests
```

## Build

Requires Rust 1.89.0+ with `wasm32-unknown-unknown` target:

```bash
# Build the contract WASM
cd integration-test
cargo build --release
# Output: target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm

# Run unit tests (in-process, no network)
cargo test
```

## Testnet Tests

Requires the [Stellar CLI](https://github.com/stellar/stellar-cli) installed and the contract WASM pre-built:

```bash
# First, build the WASM (see above)
cd integration-test && cargo build --release

# Then run testnet tests
cd ../testnet-tests
cargo test
```

Tests are slow (ledger latency + timelock waits). Each test deploys fresh contract instances and identities on Stellar testnet.

### Test Cases

| Test | Description |
|------|-------------|
| `test_deploy_and_initialize` | Contract deploys and initializes with signers/threshold |
| `test_wrap_tokens` | Immediate token wrapping, balance and supply validation |
| `test_schedule_and_execute_unwrap` | Time-locked unwrap with delay, execution after expiry |
| `test_schedule_and_execute_transfer` | Time-locked transfer between addresses |
| `test_cancel_timelock` | Cancel pending timelock, verify execution blocked |
| `test_insufficient_signers_rejected` | Multisig threshold enforcement |

## Contract: MultisigAssetWrapper

Wraps a Stellar token with multisig authorization and time-locked operations. All sensitive operations (unwrap, transfer) require a schedule/execute pattern with configurable minimum delay.

### Operations

| Function | Timelocked | Description |
|----------|-----------|-------------|
| `initialize` | No | One-time setup: signers, threshold, underlying token, min lock duration |
| `wrap` | No | Immediate: transfer underlying tokens to contract, credit wrapped balance |
| `schedule_unwrap` | Yes | Schedule: burn wrapped tokens and return underlying after delay |
| `execute_unwrap` | — | Execute a matured unwrap timelock |
| `schedule_transfer` | Yes | Schedule: move wrapped tokens between addresses after delay |
| `execute_transfer` | — | Execute a matured transfer timelock |
| `cancel_timelock` | No | Cancel a pending timelock (requires multisig) |
| `balance` | No | Query wrapped token balance for an address |
| `total_supply` | No | Query total wrapped token supply |

### Multisig

All mutating operations require `threshold` authorized signers from the configured signer list. Each signer must call `require_auth()`. Operations panic if the threshold is not met.

### Events

The contract publishes events for: `wrap`, `sched_unw` (schedule unwrap), `exec_unw` (execute unwrap), `sched_tx` (schedule transfer), `exec_tx` (execute transfer), `cancel`.

### Dependencies

- `soroban-sdk 23.0.1` — the only runtime dependency
- Contract is `#![no_std]` for WASM compatibility
- All storage uses `env.storage().instance()`

See the [rs-soroban-sdk](https://github.com/stellar/rs-soroban-sdk) repository for Soroban SDK documentation.
