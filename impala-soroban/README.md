# Impala Soroban Smart Contracts

Soroban smart contract holding USDC under multisig control with time-locked, reservation-backed withdrawals and transfers.

The wrapper is **standalone / informational** with respect to the rest of Impala: the bridge never invokes it (`SOROBAN_CONTRACT_ID` is only echoed by `GET /network`), and event monitoring is a separate, unimplemented integration.

## Structure

Two independent Rust crates (no workspace root), plus scripts and deployment records:

```
impala-soroban/
├── integration-test/     # MultisigUsdcWrapper contract (compiles to WASM)
│   ├── Cargo.toml        # version 0.2.0 == release tag impala-soroban-v0.2.0
│   ├── deny.toml         # cargo-deny policy (security.yml)
│   ├── src/lib.rs        # contract + unit tests
│   ├── src/invariants.rs # proptest state machine
│   └── test_snapshots/   # written by Env::default() tests; no orphans allowed
├── testnet-tests/        # End-to-end tests against Stellar testnet (stellar-cli)
│   ├── src/lib.rs         # CLI wrappers, identity management, constructor deploy
│   └── tests/integration.rs
├── scripts/
│   ├── check-snapshots.sh    # orphan snapshot check (CI)
│   ├── check-manifests.sh    # deployment manifest validation (CI)
│   └── verify-deployment.sh  # verify a manifest against the live chain
└── deployments/          # one manifest per deployed instance (append-only)
```

> Note: the crate name (`soroban-impala-integration-test`) and WASM artifact
> name (`soroban_impala_integration_test.wasm`) are deliberately unchanged —
> `testnet-tests` hardcodes the artifact path, CI globs `*.wasm`, and the
> deployment manifests name the artifact.

## Build

Requires Rust 1.91+ (`rust-version`; CI pins 1.96.0) with the `wasm32-unknown-unknown` target:

```bash
# Build the contract WASM. The --target flag is required: the crate is
# crate-type = ["cdylib"] with no .cargo/config.toml, so a bare
# `cargo build --release` produces a native .so, not the WASM.
cd integration-test
cargo build --release --locked --target wasm32-unknown-unknown
# Output: target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm
sha256sum target/wasm32-unknown-unknown/release/*.wasm   # == on-chain ContractCode hash

# Run unit tests (in-process, no network; includes a 64-case property test)
cargo test
PROPTEST_CASES=512 cargo test invariants                 # CI depth for the state machine

# Artifact gate: the release WASM must load in the pinned host
IMPALA_WASM=$PWD/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm \
  cargo test test_wasm_artifact_loads_in_pinned_host -- --ignored

../scripts/check-snapshots.sh      # test_snapshots/ must have no orphans (--delete removes them)
cargo deny check advisories bans sources licenses        # after cargo install --locked cargo-deny
```

## Deploy

State is created only by `__constructor`, which the host runs inside the deploy transaction. Upload first so the WASM hash is literally the deploy parameter, then deploy with the constructor arguments after `--`:

```bash
stellar contract upload --wasm target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm \
  --source <deployer> --network <net>              # prints the wasm hash == sha256sum
stellar contract deploy --wasm-hash <hash> --source <deployer> --network <net> -- \
  --signers '["G_SIGNER_1","G_SIGNER_2","G_SIGNER_3"]' --threshold 2 --min_threshold 2 \
  --usdc_token "$SAC" --usdc_issuer <G_CIRCLE_ISSUER> --min_lock_duration 86400
```

This moves no money but is irreversible: the instance's issuer, signer set and `min_threshold` are fixed for life (signers rotate; `min_threshold` never changes). The full procedure — signer ceremony, manifest, verification, retirement — is `docs/runbooks/deploy-soroban.md`; every instance is recorded in `deployments/` (see `deployments/README.md`).

## Testnet Tests

Requires the [Stellar CLI](https://github.com/stellar/stellar-cli) (the version pinned in `.github/workflows/impala-soroban.yml`, `STELLAR_CLI_VERSION`) and the contract WASM pre-built:

```bash
# First, build the WASM (see above)
cd integration-test && cargo build --release --locked --target wasm32-unknown-unknown

# Then run testnet tests
cd ../testnet-tests
cargo test
```

Tests are slow (ledger latency + timelock waits). Each test deploys a fresh contract instance through the constructor with fresh identities on Stellar testnet.

The fixture **self-issues a test USDC asset** rather than using Circle's faucet: it generates and friendbot-funds a throwaway issuer account, deploys the SAC for `USDC:<issuer>`, establishes trustlines from the signer accounts, and pays test USDC from the issuer. The constructor's issuer pin passes because the fixture passes its own issuer as `--usdc_issuer`; the pin itself is exercised by `test_deploy_rejects_issuer_mismatch`, which deploys against a second issuer's genuine `USDC` SAC. The setup also asserts the funded SAC balance in stroops, so a stellar-cli amount-unit change fails loudly instead of corrupting test expectations.

Panic strings never reach the chain (`panic = "abort"`, symbols stripped), so failure tests assert a host error (`Error(`) **and** explicit state (balance / reserved / total unchanged). Constructor failures surface as `Error(Context, InvalidAction)`; the observed lines are recorded on the first run.

### Test Cases

| Test | Description |
|------|-------------|
| `test_deploy_with_constructor` | Deploys through `__constructor`; `usdc_token`, `usdc_issuer`, `min_lock_duration`, `min_threshold` and `multisig_config` read back as configured |
| `test_wrap_tokens` | Immediate USDC wrapping, balance and supply validation |
| `test_schedule_and_execute_unwrap` | Reservation-backed unwrap: schedule, wait, execute with the current quorum |
| `test_schedule_and_execute_transfer` | Time-locked transfer between addresses |
| `test_cancel_timelock` | Cancel releases the reservation; execution afterwards fails on the pruned entry |
| `test_insufficient_signers_rejected` | Multisig threshold enforcement |
| `test_deploy_rejects_non_usdc_token` | Deploy with the native XLM SAC (`symbol() == "native"`) fails in the constructor |
| `test_deploy_rejects_issuer_mismatch` | Deploy against a genuine `USDC` SAC from another issuer fails the `name()` pin |
| `test_constructor_not_callable_after_deploy` | Invoking `__constructor` on a live instance fails; configuration unchanged |
| `test_over_schedule_rejected` | A second schedule beyond `available` is refused; `reserved`/`available` as expected |
| `test_execute_after_rotation` | After `rotate_signers` the old set cannot execute, the new set can |

## Contract: MultisigUsdcWrapper

Wraps Circle's USDC Stellar asset with multisig authorization and time-locked operations. Withdrawals and transfers require a schedule/execute pattern with a configurable minimum delay, and scheduling reserves the amount.

### Construction

`__constructor(signers, threshold, min_threshold, usdc_token, usdc_issuer, min_lock_duration)` runs only inside the deploy transaction. The host refuses direct calls to `__`-prefixed functions and a contract id cannot be created twice, so there is no post-deploy initialization entry point and nobody can seize a fresh instance (pinned by `test_constructor_cannot_be_invoked_directly`, `test_initialize_entry_point_removed` and the testnet `test_constructor_not_callable_after_deploy`). Validation, in order, before any state is written: signers non-empty, at most 20, no duplicates; `1 <= min_threshold <= len`; `min_threshold <= threshold <= len`; `min_lock_duration <= MAX_LOCK_DURATION`; the network's `max_entry_ttl` is at least the persistent extend-to target; then the issuer pin.

### USDC per network

The USDC SAC address differs per network, so it and Circle's issuer are constructor arguments checked against the SAC's `name()`. Resolve the SAC for Circle's verified issuers:

```bash
# Testnet (Circle testnet issuer)
stellar contract id asset --asset USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5 --network testnet
# Pubnet (Circle issuer)
stellar contract id asset --asset USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN --network public
# Local/hermetic e2e: self-issued USDC
stellar contract asset deploy --asset USDC:<your_test_issuer_G...> --network <network>
```

### Issuer pin

What the contract verifies at construction: `symbol() == "USDC"`, `decimals() == 7`, and `name() == "USDC:<usdc_issuer>"`. A SAC's `name()` is derived by the host from the asset code and issuer at SAC creation and cannot be forged by a deployer: a look-alike `USDC` from another issuer fails on the strkey, a contract-address issuer can never match (SAC names carry a G strkey), the native SAC fails on the symbol, and non-SAC tokens still fail on decimals. Unit tests exercise this against a host-built real `USDC:<issuer>` SAC (`test_constructor_accepts_real_usdc_sac`, `test_constructor_rejects_issuer_mismatch_real_sac`).

What the contract *cannot* decide is which issuer is Circle. That binding is a deployment record: `deployments/<network>/<contract_id>.json` names the issuer, `scripts/check-manifests.sh` refuses any pubnet issuer but Circle's, and `scripts/verify-deployment.sh` re-reads `usdc_token()` / `usdc_issuer()` and the SAC's `name()` from chain.

### Reservation

Per holder: `balance`, `reserved`, `available = balance − reserved`. Scheduling atomically moves `amount` from available to reserved, so an accepted schedule is fully funded until it executes, is cancelled, or expires. Invariants (checked after every operation by the property test): `0 <= reserved <= balance`; `reserved(a)` equals the sum of pending operations debiting `a`; the sum of balances equals `total_wrapped`. The contract trips `"Reserved invariant violated"` on any money path that observes a violation.

On-chain the SAC balance of the contract is `>=` `total_wrapped`: anyone can pay USDC straight to the contract address and there is no sweep. The unit tests assert equality only because the mock token has no such path; `sweep_surplus` is a designed-separately follow-up.

### Execution model

A time-locked operation is created by one multisig ceremony (`schedule_unwrap` / `schedule_transfer`: at least `threshold` of the signers current at that moment) and consumed by a second (`execute_unwrap` / `execute_transfer`: at least `threshold` of the signers current at *execution* time). The delay is a veto window: while it runs, any quorum of the current set may `cancel_timelock`, and the reserved amount cannot be spent by any other operation. The execution window `[unlock_time, expires_at)` (`expires_at = unlock_time + 30 days`) bounds how long an approved-but-unexecuted operation may linger; at or after `expires_at` anyone may call `expire_timelock` to release the reservation, and the operation must be scheduled again. `rotate_signers` replaces the signer set immediately and increments `epoch`; pending operations survive rotation and are executable or cancellable only by the *new* set — a rotated-out set (retired or compromised) can neither execute nor cancel, and nothing is stranded. The `signers` and `config_epoch` recorded on a timelock are audit metadata (who approved, under which configuration); they are never consulted for authorization. Rotation can never set a threshold below the `min_threshold` fixed at construction, and `min_threshold` has no setter. `pause` blocks `wrap`, `schedule_*` and `execute_*`; `cancel_timelock`, `expire_timelock`, `bump_ttl`, `bump_entry_ttl`, `rotate_signers`, `unpause` and all reads work while paused, so an operation that matures during a pause either executes within its window after `unpause` or expires — it never becomes executable forever.

`wrap` is immediate and needs the multisig plus the depositor's authorization; a depositor who is one of the provided signers authorizes once, as a signer (the host rejects a second `require_auth` for the same address within one frame, so the previous contract could never wrap for a signer-depositor).

#### Design notes — rejected alternatives

(a) *Permissionless execute after maturity* — one ceremony moves value; a compromised quorum's scheduled withdrawal executes unless a cancel quorum is mustered in time; rotation cannot revoke it. (b) *Re-auth by every stored signer (the previous model)* — strands operations on any rotation removing a stored signer, requires all stored signers rather than a quorum, and former signers keep authority. (c) *Threshold subset of stored signers* — still lets a rotated-out set execute; still strands. (d) *Epoch gate (execute requires `config_epoch == current`)* — the current-quorum rule already revokes rotated-out sets; the gate would kill every legitimate pending op on routine rotation; kept as audit metadata only. (e) *Timelocked rotation* — a compromised quorum can already drain via schedule+execute within the same delay, so it adds a ceremony without changing the attacker's bound; deferred follow-up. (f) *Majority floor `2·threshold ≥ n`* — admits 1-of-1 and 1-of-2 from any configuration while forbidding legitimate 1-of-3; replaced by the immutable `min_threshold`. (g) *Configurable execution window* — more knobs, no security gain; constant 30 days. (h) *`#[contracterror]` typed errors* — better on-chain diagnosability (release WASM strips panic strings) but touches every panic site; separate PR.

### Storage & TTL

| `DataKey` variant (encoded by name; append-only) | Class | Value | Absent means |
|---|---|---|---|
| `MultisigConfig` | instance | `{ signers, threshold, epoch }` | never |
| `WrappedUsdc` | instance | `{ usdc_token, decimals, total_wrapped, usdc_issuer }` | never |
| `MinLockDuration` | instance | `u64` | never |
| `NextTimeLockId` | instance | `u64` (monotone, starts 0) | never |
| `Paused` | instance | `bool` | `false` |
| `MinThreshold` | instance | `u32`, immutable | never |
| `Balance(Address)` | persistent | `i128` (kept at 0 after a full unwrap) | 0 |
| `Reserved(Address)` | persistent | `i128`; removed when it returns to 0 | 0 |
| `TimeLock(u64)` | persistent | `TimeLock` | `"Timelock not found"` |

Constants: `MAX_LOCK_DURATION` 90 days, `EXECUTION_WINDOW` 30 days; instance TTL policy extend to ~30 days of ledgers (518,400) when fewer than ~7 (120,960) remain; persistent policy extend to ~160 days (2,764,800) when fewer than ~30 (518,400) remain — below the public network `max_entry_ttl` (3,110,400) so on-chain extensions are never clamped, and 2,764,800 × 4 s = 128 d ≥ `MAX_LOCK_DURATION + EXECUTION_WINDOW` = 120 d, so a pending operation never needs a bump even at 4 s ledgers (compile-time asserted). The constructor refuses a network whose `max_entry_ttl` is below the extend-to target.

Every entry point that touches a holder or timelock extends its entries (`Balance(a)` and `Reserved(a)` always together); reads never extend. `bump_ttl()` extends the instance only; the permissionless `bump_entry_ttl(addresses, timelock_ids)` (at most 32 keys per call, missing keys skipped) extends per-holder and per-timelock entries.

**Archived ≠ lost.** A persistent entry untouched for ~160 days is archived, not deleted: every entry point that reads it fails with a host storage error until it is restored with a `RestoreFootprint` operation (`stellar contract restore`), and it never reads as zero. A `balance()` call that fails with a storage error for a known holder means the entry is archived — restore it; funds are intact. Temporary storage is deliberately unused (a temporary entry is deleted at expiry, which would strand a reservation).

### Operations

| Function | Auth | Paused? | Description |
|---|---|---|---|
| `__constructor(signers, threshold, min_threshold, usdc_token, usdc_issuer, min_lock_duration)` | deploy tx | — | Atomic construction; validates config, network TTL and the issuer pin before writing state |
| `wrap(signers, depositor, amount)` | multisig + depositor | blocked | Immediate: USDC moves from the depositor to the contract; the depositor's wrapped balance is credited |
| `schedule_unwrap(signers, recipient, amount, delay_seconds) -> u64` | multisig | blocked | Reserves `amount` from the recipient's available balance; `unlock_time = now + delay`, `expires_at = unlock_time + 30 d` |
| `schedule_transfer(signers, from, to, amount, delay_seconds) -> u64` | multisig | blocked | Reserves `amount` from `from`'s available balance |
| `execute_unwrap(signers, timelock_id)` | multisig (current) | blocked | Within the window: consumes the reservation, burns wrapped balance, transfers USDC to the recipient |
| `execute_transfer(signers, timelock_id)` | multisig (current) | blocked | Within the window: consumes the reservation, moves wrapped balance to the recipient |
| `cancel_timelock(signers, timelock_id)` | multisig (current) | allowed | Releases the reservation and removes the entry |
| `expire_timelock(timelock_id)` | none | allowed | At or after `expires_at`: releases the reservation and removes the entry |
| `pause(signers)` / `unpause(signers)` | multisig | — | Incident switch |
| `rotate_signers(current_signers, new_signers, new_threshold)` | multisig | allowed | New threshold must be `>= min_threshold`; increments `epoch` |
| `bump_ttl()` | none | allowed | Extend the instance TTL |
| `bump_entry_ttl(addresses, timelock_ids)` | none | allowed | Extend per-holder and per-timelock entries (≤ 32 keys) |
| `get_timelock`, `balance`, `reserved`, `available`, `total_supply`, `usdc_token`, `usdc_decimals`, `usdc_issuer`, `multisig_config`, `min_lock_duration`, `min_threshold`, `is_paused`, `next_timelock_id`, `max_entry_ttl` | — | — | Reads (never extend TTL) |

Panic vocabulary is complete and pinned by the tests: constructor (`Signers must not be empty`, `Too many signers`, `Duplicate signer detected`, `Invalid min threshold`, `Invalid threshold`, `Min lock duration exceeds maximum`, `Network max entry TTL below policy`, `Underlying token is not USDC`, `USDC token must have 7 decimals`, `Underlying token issuer mismatch`); money paths (`Contract is paused`, `Amount must be positive`, `Self-transfer not allowed`, `Insufficient signers`, `Signer not authorized`, `Delay too short`, `Delay exceeds maximum lock duration`, `Reserved invariant violated`, `Insufficient available balance`); execute/cancel/expire (`Timelock not found`, `Already executed`, `Wrong operation type`, `Timelock not matured`, `Timelock expired`, `Timelock not yet expired`); governance (`New signers must not be empty`, `Invalid new threshold`, `Bump batch too large`). All arithmetic is `checked_*`; `overflow-checks = true` stays in the release profile.

### Multisig

All mutating operations require `threshold` authorized signers from the configured signer list; each signer must `require_auth()`. Configuration-time hardening in the constructor and `rotate_signers`: the signer set is capped at 20, duplicate signers are rejected (a duplicated configured signer could make the threshold unsatisfiable, bricking the contract), the threshold can never go below `min_threshold`, and the constructor rejects a `min_lock_duration` above the 90-day maximum delay (which would make every schedule call panic).

### Events

Frozen ABI, pinned byte-for-byte by `test_event_abi_pins` (the `0` data values are `i32`):

| Call | Topics | Data |
|---|---|---|
| `wrap` | `("wrap", depositor)` | `amount: i128` |
| `schedule_unwrap` | `("sched_unw", recipient, timelock_id: u64)` | `unlock_time: u64` |
| `execute_unwrap` | `("exec_unw", recipient, timelock_id)` | `amount: i128` |
| `schedule_transfer` | `("sched_tx", from, to, timelock_id)` | `unlock_time: u64` |
| `execute_transfer` | `("exec_tx", sender, recipient, timelock_id)` | `amount: i128` |
| `cancel_timelock` | `("cancel", timelock_id)` | `0: i32` |
| `pause` / `unpause` | `("pause",)` / `("unpause",)` | `0: i32` |
| `rotate_signers` | `("rotate",)` | `new_threshold: u32` |
| `expire_timelock` | `("expire", timelock_id)` | `0: i32` (additive) |

### Tests

`cargo test` runs the unit suite in-process: constructor and adversarial re-initialization tests, reservation and execution-model tests, `mock_auths(&[])` authorization tests (every privileged entry point must panic without auth; every permissionless one must succeed), storage-class and TTL tests (including the network-max clamp), the event ABI pin, and `invariants::state_machine` — a proptest state machine (`src/invariants.rs`) that drives random operation sequences through the `try_*` client against a reference model and checks the reservation, conservation, id, storage-class and configuration invariants after every op (64 cases locally, `PROPTEST_CASES=512` in CI; failing seeds persist to `proptest-regressions/invariants.txt`, commit them). Fixtures seed balances only through real `mint + wrap` with a full quorum; the only direct storage write in the suite is the tripwire test that corrupts a reservation on purpose.

In unit tests, soroban-sdk 23.5.3's `register_stellar_asset_contract_v2` hardcodes the test SAC's asset code to `aaa`, so the issuer-pin tests build a real `USDC:<issuer>` SAC through the host directly (`make_usdc_sac`); everything else uses the `#[cfg(test)]` mock token `MockUsdc`, whose `name()` is the SAC-shaped `USDC:<issuer strkey>`.

## Releases & deployments

- CI (`.github/workflows/impala-soroban.yml`) prints the WASM sha256 (== on-chain `ContractCode` hash) and a `build-info.json` for every build, runs the artifact gate, the deep property run, the snapshot orphan check and `scripts/check-manifests.sh`; a tag `impala-soroban-vX.Y.Z` (matching `Cargo.toml`) publishes a GitHub Release with the artifact, `.sha256`, `build-info.json` and `SHA256SUMS`, plus a non-gating Docker double-build reproducibility check.
- `deployments/<network>/<contract_id>.json` records every instance (issuer, signers, thresholds, WASM hash, deploy txs); append-only, exactly one `active` per network. `scripts/check-manifests.sh` validates offline (and compares terraform's `testnet_soroban_contract_id` when the CI secret is set); `scripts/verify-deployment.sh <manifest>` verifies against the chain.
- `docs/runbooks/deploy-soroban.md` — deploy, verify, day-2 (`bump_entry_ttl` cadence, restore, rotation, pause, expiring dead timelocks) and retirement.
- The keep-alive/verify CI job is `workflow_dispatch`-only until a funded keeper identity (`STELLAR_TESTNET_KEEPER_SECRET`, fees only, never a signer) exists.

## Known limitations

- The live networks' `max_entry_ttl` and the stellar-cli constructor-argument syntax are confirmed on the first manual run; the constructor fails closed if the network max is below policy (which would block deployment — the correct outcome).
- On-chain conservation is `SAC.balance(contract) >= total_wrapped` until `sweep_surplus` exists.
- The keep-alive job is manual until a keeper secret exists; the reproducibility check is advisory until it has passed on a tag.
- The pre-constructor testnet instance is recorded as retired with a placeholder id (`deployments/testnet/retired-pre-constructor-instance.json`); the first `active` manifest is written from the first constructor deploy.

## Dependencies

- `soroban-sdk 23.5.3` — the only runtime dependency; `proptest` is dev-only (`std` feature only, so `rusty-fork`/`tempfile`/`wait-timeout` stay out of the audited tree).
- Contract is `#![no_std]` for WASM compatibility.
- Configuration lives in `env.storage().instance()`; balances, reservations and timelocks in `env.storage().persistent()` (see Storage & TTL).

The contract is pinned to soroban-sdk 23.5.3 (env-host 23.0.1) and builds for `wasm32-unknown-unknown` on rustc 1.96.0. soroban-sdk 26's `build.rs` rejects `wasm32-unknown-unknown` on rustc ≥ 1.82 and requires `wasm32v1-none` (`integration-test/Cargo.toml` pin comment, 2026-06-09). The reason is not cosmetic: on rustc ≥ 1.82 the `wasm32-unknown-unknown` target enables post-MVP WebAssembly features by default, which the Soroban VM rejects if they appear in the binary; `wasm32v1-none` is the MVP-only target. Our toolchain is in that range, so the release artifact must be proven loadable in the pinned host — the CI artifact gate (`test_wasm_artifact_loads_in_pinned_host`) does exactly that and is the acceptance check for the current pin. Staying on 23.x for this hardening is a maintenance decision, not a correctness one: a WASM built against SDK 23 declares protocol 23 in its meta and is accepted by any network at protocol ≥ 23, the code paths used here (storage, token client, auth, events via the deprecated `publish`, constructors, SAC `name()`) are stable, and `cargo audit`/`cargo-deny` run on every push. What the pin costs: unit tests simulate protocol-23 host semantics; newer host functions and `#[contractevent]` are unavailable; transitive dependencies age (cargo-deny's unmaintained check is scoped to direct dependencies for the host's `ark-*` stack — see `deny.toml`). Migration is a bounded, mechanical, separate PR after this hardening lands and **before any mainnet (T3) deployment**: `rustup target add wasm32v1-none`; `targets: wasm32v1-none` in `impala-soroban.yml` (both jobs; the `security.yml` cargo-deny job installs no target and needs no change); `soroban-sdk = "26.x"`; the artifact path in `testnet-tests/src/lib.rs`, README and DEVELOPMENT build lines; keep `#![allow(deprecated)]` so the event ABI stays byte-identical (`test_event_abi_pins` is the gate); regenerate `test_snapshots/`; run the property suite, the artifact gate and the testnet e2e; the WASM hash changes, so a new manifest entry and tag are mandatory — never re-point an existing manifest. Until then the manifest's `source.soroban_sdk` field is the compatibility statement of record.

See the [rs-soroban-sdk](https://github.com/stellar/rs-soroban-sdk) repository for Soroban SDK documentation.
