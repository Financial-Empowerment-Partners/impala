# Impala Soroban Smart Contracts

Soroban smart contracts for moving funds into and out of the Payala program, supporting bulk payments, offline escrow, and multi-party authorization via the Stellar network.

## Structure

Two independent Rust crates (no workspace root):

```
impala-soroban/
├── integration-test/     # MultisigUsdcWrapper contract (compiles to WASM)
│   ├── Cargo.toml
│   └── src/lib.rs
└── testnet-tests/        # Integration tests against Stellar testnet
    ├── Cargo.toml
    ├── src/lib.rs         # Test utilities (CLI wrappers, identity management)
    └── tests/
        └── integration.rs # End-to-end tests
```

> Note: the crate name (`soroban-impala-integration-test`) and WASM artifact
> name (`soroban_impala_integration_test.wasm`) are deliberately unchanged
> across the USDC rework — `testnet-tests` hardcodes the artifact path and CI
> globs `*.wasm`.

## Build

Requires Rust 1.89.0+ with `wasm32-unknown-unknown` target:

```bash
# Build the contract WASM. The --target flag is required: the crate is
# crate-type = ["cdylib"] with no .cargo/config.toml, so a bare
# `cargo build --release` produces a native .so, not the WASM.
cd integration-test
cargo build --release --target wasm32-unknown-unknown
# Output: target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm

# Run unit tests (in-process, no network)
cargo test
```

## Testnet Tests

Requires the [Stellar CLI](https://github.com/stellar/stellar-cli) installed and the contract WASM pre-built:

```bash
# First, build the WASM (see above)
cd integration-test && cargo build --release --target wasm32-unknown-unknown

# Then run testnet tests
cd ../testnet-tests
cargo test
```

Tests are slow (ledger latency + timelock waits). Each test deploys fresh contract instances and identities on Stellar testnet.

The fixture **self-issues a test USDC asset** rather than using Circle's faucet: it generates and friendbot-funds a throwaway issuer account, deploys the SAC for `USDC:<issuer>`, establishes trustlines from the signer accounts, and pays test USDC from the issuer. The SAC's `symbol()` returns the asset code, so the contract's `initialize` validation passes (which is precisely the documented limitation — the issuer is not verifiable on-chain). The setup also asserts the funded SAC balance in stroops, so a stellar-cli amount-unit change fails loudly instead of corrupting test expectations.

### Test Cases

| Test | Description |
|------|-------------|
| `test_deploy_and_initialize` | Contract deploys and initializes with signers/threshold/USDC SAC |
| `test_wrap_tokens` | Immediate USDC wrapping, balance and supply validation |
| `test_schedule_and_execute_unwrap` | Time-locked unwrap with delay, execution after expiry |
| `test_schedule_and_execute_transfer` | Time-locked transfer between addresses |
| `test_cancel_timelock` | Cancel pending timelock, verify execution blocked |
| `test_insufficient_signers_rejected` | Multisig threshold enforcement |
| `test_initialize_rejects_non_usdc_token` | Initialization with the native XLM SAC (`symbol() == "native"`) is rejected |

## Contract: MultisigUsdcWrapper

Wraps Circle's USDC Stellar asset with multisig authorization and time-locked operations. All sensitive operations (unwrap, transfer) require a schedule/execute pattern with configurable minimum delay.

### USDC per network

The USDC Stellar Asset Contract (SAC) address differs per network, so it is an `initialize` argument rather than a hardcoded constant. Resolve the SAC address for Circle's verified issuers:

```bash
# Testnet (Circle testnet issuer)
stellar contract id asset --asset USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5 --network testnet
# Pubnet (Circle issuer)
stellar contract id asset --asset USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN --network public
# Local/hermetic e2e: self-issued USDC
stellar contract asset deploy --asset USDC:<your_test_issuer_G...> --network <network>
```

`initialize` validates that the configured token actually looks like USDC — `symbol() == "USDC"` and `decimals() == 7` — before writing any state, and records the decimals. **Honest limitation**: the asset *issuer* is not verifiable on-chain from inside the contract, so these checks guard against misconfiguration (e.g. passing the XLM SAC), not against a malicious deployer pointing the contract at a look-alike token. Anyone consuming a deployed instance should verify the configured `usdc_token()` address against the official Circle SAC for that network off-chain.

In unit tests, soroban-sdk 23.5.3's `register_stellar_asset_contract_v2` hardcodes the test SAC's asset code to `aaa`, so a USDC-labelled SAC cannot be created via testutils. The tests therefore use a minimal `#[cfg(test)]` mock token contract (`MockUsdc`) — Soroban token calls dispatch dynamically by function name, so `token::Client` works against it — and use the hardcoded-`aaa` SAC as the negative test.

### Operations

| Function | Timelocked | Description |
|----------|-----------|-------------|
| `initialize` | No | One-time setup: signers (max 20, no duplicates), threshold, the network's USDC SAC address (validated: `symbol() == "USDC"`, `decimals() == 7`), min lock duration (must not exceed the 365-day max delay) |
| `wrap` | No | Immediate: transfer USDC from an explicit `depositor` to the contract, credit the depositor's wrapped balance. The depositor must `require_auth()` in addition to the multisig set but need not be a signer |
| `schedule_unwrap` | Yes | Schedule: burn wrapped tokens and return USDC after delay |
| `execute_unwrap` | — | Execute a matured unwrap timelock (entry is removed from storage afterwards) |
| `schedule_transfer` | Yes | Schedule: move wrapped tokens between addresses after delay |
| `execute_transfer` | — | Execute a matured transfer timelock (entry is removed from storage afterwards) |
| `cancel_timelock` | No | Cancel a pending timelock (requires multisig; removes the entry from storage) |
| `bump_ttl` | No | Extend the instance storage TTL (permissionless; every mutating operation also extends it) |
| `balance` | No | Query wrapped token balance for an address |
| `total_supply` | No | Query total wrapped token supply |
| `usdc_token` | No | Query the configured USDC SAC address |
| `usdc_decimals` | No | Query the recorded USDC decimals (always 7) |

### Multisig

All mutating operations require `threshold` authorized signers from the configured signer list. Each signer must call `require_auth()`. Operations panic if the threshold is not met.

Configuration-time hardening in `initialize` and `rotate_signers`: the signer set is capped at 20, duplicate signers are rejected (a duplicated configured signer could make the threshold unsatisfiable, bricking the contract), and `initialize` rejects a `min_lock_duration` above the 365-day maximum delay (which would make every schedule call panic).

**Deferred hardening (documented, not implemented)**: `initialize` is unauthenticated and therefore front-runnable — anyone observing the deployment can initialize the contract first with their own signer set. The proper fix is migrating initialization into a `__constructor` (atomic with deployment); that is an ABI-affecting change deferred until coordinated with deployment tooling. Until then, deploy and initialize in quick succession and verify the configured signers before funding the contract.

### Over-scheduling

Scheduling does **not** reserve balance. The balance check in `schedule_unwrap` / `schedule_transfer` is advisory only: multiple pending timelocks may be scheduled against the same balance, and the authoritative check happens at execution time. Over-scheduled operations simply fail at execution — funds can never be over-withdrawn, but a scheduled timelock is not a guarantee that the balance will still be available when it matures.

### Timelock lifecycle

Executed and cancelled timelock entries are **removed from instance storage** rather than flagged: replay attempts (re-execution, re-cancellation) fail with `Timelock not found`, and the storage rent for finished operations is reclaimed, so instance storage does not grow without bound. The execute paths still mark the entry as executed before performing balance updates / the external token transfer (reentrancy prevention) and prune it once the operation completes.

### Storage TTL

All state lives in instance storage, so the whole contract shares one TTL. Every mutating entry point extends the instance TTL (to ~30 days of ledgers when fewer than ~7 days remain), and the permissionless `bump_ttl` lets anyone keep an otherwise idle contract alive.

### Events

The contract publishes events for: `wrap`, `sched_unw` (schedule unwrap), `exec_unw` (execute unwrap), `sched_tx` (schedule transfer), `exec_tx` (execute transfer), `cancel`. The event topics are unchanged across the USDC rework — the event ABI is declared stable for off-chain consumers.

### Dependencies

- `soroban-sdk 23.5.3` — the only runtime dependency. Latest 23.x by design: soroban-sdk 26.x requires the `wasm32v1-none` build target (it rejects `wasm32-unknown-unknown` on rustc 1.82+), so the 26.x bump is deferred until the build/CI target migration is coordinated (see the pin comment in `integration-test/Cargo.toml`)
- Contract is `#![no_std]` for WASM compatibility
- All storage uses `env.storage().instance()`

See the [rs-soroban-sdk](https://github.com/stellar/rs-soroban-sdk) repository for Soroban SDK documentation.
