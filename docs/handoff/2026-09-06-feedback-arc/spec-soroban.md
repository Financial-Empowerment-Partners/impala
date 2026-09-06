# MultisigUsdcWrapper hardening — implementation spec

All paths are absolute under `/Users/user/sonoranpub/impala/`. The contract is `impala-soroban/integration-test/src/lib.rs` (contract lines 1–745, inline tests 747–1968, HEAD == working tree for `impala-soroban/`). Nothing in this spec has been applied to the repo; it is the build order for two PRs (PR-A contract+tests+docs, PR-B release discipline). An implementer with no other context builds exactly this.

---

## 0. Ground truth this spec rests on (all re-verified in-session)

| # | Fact | Where verified |
|---|---|---|
| G1 | `__constructor` runs only from `CreateContract` (`call_constructor`, `internal_host_call: true`); a direct call to any `__`-prefixed function fails with `"can't invoke a reserved function directly"` (env-host `host/frame.rs:38, 826-838`); a contract id cannot be created twice (`host/lifecycle.rs:28-38`); a recoverable constructor error is wrapped as `Error(Context, InvalidAction) "constructor invocation has failed with error"` (`lifecycle.rs:87-100`); a deploy with args against a contract lacking `__constructor` fails (`treat_missing_function_as_noop: constructor_args.is_empty()`, `lifecycle.rs:80-84`). | source |
| G2 | Calling a function a native test contract does not define fails `"calling unknown contract function"` (`frame.rs:928`, external calls use `treat_missing_function_as_noop: false`, `frame.rs:107-113`). | source |
| G3 | In native tests a string `panic!` inside a contract is logged as `caught panic '<msg>' from contract function …` (`frame.rs:963-987`); the test env runs at `DiagnosticLevel::Debug` (sdk `env.rs:589`); `HostError`'s `Debug` prints the event log (`host/error.rs:108-118`); `env.register` unwraps (`env.rs:898`) and host errors escalate with `panic!("{:?}", escalation)` (`host.rs:851-862`), so `#[should_panic(expected = "<msg>")]` matches through both `env.register` and `env.invoke_contract`. Experiment `exp_sac_name_and_issuer_pin` (scratchpad `exp/src/lib.rs:2076`) confirmed the constructor case. | source + experiment |
| G4 | SAC metadata is fixed at SAC creation: `symbol = SEP-0011 code`, `name = symbol + ":" + issuer G-strkey` (61 bytes for `USDC:G…`), native → `"native"`, `decimals` constant 7 (env-host `stellar_asset_contract/metadata.rs:130-198`). `Address::to_string()` (sdk `address.rs:343`), `String::to_bytes()` (`string.rs:293`), `Bytes::from_slice/append` (`bytes.rs:497,698`) exist in `no_std`. Experiment printed `SAC name = USDC:G…` and a mismatched issuer panicked `Underlying token issuer mismatch`. | source + experiment |
| G5 | `persistent().extend_ttl(key, threshold, extend_to)`: requires `threshold <= extend_to`; extends **only when** `old_live_until.saturating_sub(seq) <= threshold` and `new_live_until > old_live_until` (`storage.rs:490`); clamps persistent entries silently to `max_live_until_ledger` (`storage.rs:463-466`), errors for temporary; errors on a missing key (`"trying to extend invalid entry"`, `storage.rs:428-436`). `max_live_until_ledger = sequence + max_entry_ttl − 1` (`ledger_info.rs:25-30`). In the SDK test env an expired persistent entry is auto-restored to min TTL on access (`storage.rs:579-622`); on-chain an archived entry makes the read fail (never reads as 0). | source + experiment (`exp_ttl_clamp_and_try_panic`: TTL 999,999 with max 1,000,000) |
| G6 | `testutils::storage::Persistent::get_ttl` excludes the current ledger (`testutils/storage.rs:8-14`): a fresh `set` entry reads **4095** (min_persistent_entry_ttl 4096); after `extend_ttl(.., X)` it reads exactly `X`. `Ledger::set_max_entry_ttl(N)` stores `N+1` so that `get_ttl` after a clamp reads `N` (`ledger.rs:162-169`). Test env defaults: seq 0, ts 0, min_persistent 4096, max_entry_ttl 6,312,000 (`testutils.rs:281-283`). | source |
| G7 | `EnvTestConfig { capture_snapshot_at_drop: bool }` + `Env::new_with_config` (`env.rs:268-279, 516`); `env.cost_estimate().budget().reset_unlimited()` (`cost_estimate.rs:89`, `testutils.rs:384`); `Env::invoke_contract::<T>(&Address, &Symbol, Vec<Val>)` (`env.rs:384`); `Symbol::new(&env, &str)` (`symbol.rs:212`); `impl Register for &[u8]` (`testutils.rs:63`) so `env.register(wasm_bytes.as_slice(), args)` works; generated `try_*` methods return `Err` for a string panic (experiment `try_boom -> Err`); `Instance::all()`/`Persistent::all()` return `Map<Val, Val>` (`testutils/storage.rs:6,34`); `Events::all()` returns `(Address, Vec<Val>, Val)` triples excluding failed calls (`events.rs:125-137`). | source + experiment |
| G8 | `proptest = "1.10"` resolves to the locally cached 1.10.0 (rust-version 1.84); features `default = ["std","fork","timeout","bit-set"]`, `std` exists standalone; compiles and runs inside this `#![no_std]` crate with `#[cfg(test)] extern crate std;` (experiment `exp_proptest_smoke`, `exp/Cargo.toml`). | cache + experiment |
| G9 | Host reentry mode is `Prohibited`; a panic anywhere rolls back every storage write (`frame.rs:109-118`). | source |
| G10 | Repo: bridge never invokes the contract (`impala-bridge/src/config.rs:655`, `handlers/network.rs:17`); zero git tags; no manifest; `terraform/variables.tf:238` is the only deployment record (fed from CI secret `TF_VAR_testnet_soroban_contract_id`, `ci.yml:386,401`); both `impala-soroban/*/Cargo.lock` are tracked (the CI comment at `impala-soroban.yml:74-75` is stale); `impala-card.yml:43,348-424` is the tag-release pattern (`impala-card-v*`, `softprops/action-gh-release`); only `impala-bridge/deny.toml` exists while `security.yml:110-134` runs cargo-deny on both soroban crates; no `stellar` CLI, `cargo-deny` or `cargo-audit` is installed locally; local rustc/cargo are 1.96.0 (== CI pin). | repo |
| G11 | `lib.rs:1462-1463` hardcodes `31_536_001` with the comment `MAX_LOCK_DURATION is 31_536_000`; `"Timelock not expired"` is at `:1653`; `"Insufficient wrapped balance"` at `:973, :1335`; `"Insufficient balance"` at `:1127`; the 22 direct-seeding sites and 5 `instance().has(TimeLock)` sites are at the lines listed in §5.4. | repo |

Unverifiable offline (must be confirmed on the first manual run and recorded in the manifest, §10): the `stellar contract deploy … -- --arg value` constructor-argument syntax, the CLI's stderr formatting for failed simulations, and the live networks' `max_entry_ttl` (phase-1 map says 3,110,400 for pubnet/testnet).

---

## 1. Decisions (what resolves the judges' flaws and grafts)

1. **`initialize` is deleted; `__constructor(signers, threshold, min_threshold, usdc_token, usdc_issuer, min_lock_duration)` (six caller args) replaces it. `DataKey::Initialized` is removed** — the host makes re-initialization impossible (G1); dead security code is not kept.
2. **Adversarial evidence instead of a self-referential tripwire**: `test_constructor_cannot_be_invoked_directly` (invoke `__constructor` → `"can't invoke a reserved function directly"`), `test_initialize_entry_point_removed` (invoke `initialize` → `"calling unknown contract function"`), testnet `test_constructor_not_callable_after_deploy` (config unchanged after the failed invoke).
3. **Issuer pin**: `name().to_bytes() == b"USDC:" ++ usdc_issuer.to_string().to_bytes()`; persisted as trailing `WrappedUsdc.usdc_issuer`; read fn `usdc_issuer()`; tested against a host-built real `USDC:<issuer>` SAC, a look-alike from another issuer, a C-address issuer, the `aaa` SAC, and a renamed `MockUsdc`.
4. **Storage**: `Balance(Address)`, `Reserved(Address)` (new), `TimeLock(u64)` → persistent; config/supply/ids/flags stay in instance. **Instance TTL constants unchanged** (7 d / 30 d; existing pinned tests untouched). **One persistent policy**: threshold 30 d (518,400), extend-to 160 d (2,764,800 ledgers): below pubnet's max (3,110,400) by 345,600 so no on-chain clamp, and `2,764,800 × 4 s = 128 d ≥ MAX_LOCK_DURATION + EXECUTION_WINDOW = 120 d`, so no bump is ever needed for a pending operation even at 4 s ledgers. The constructor refuses networks whose `max_entry_ttl < 2,764,800` (fail closed, with margin — fixes the zero-margin gate).
5. **`touch_account(a)`** extends both `Balance(a)` and `Reserved(a)` (guarded by `has`) on every path that touches a holder, including `wrap` and `execute_transfer`'s recipient; `Reserved` is removed when it returns to 0.
6. **Reserved accounting** with the explicit tripwire `if reserved < 0 || reserved > balance { panic!("Reserved invariant violated") }` (a `checked_sub` cannot detect it); `available = balance − reserved`; schedule reserves, cancel/expire release, execute consumes.
7. **Execution model B** (§4.9): `execute_*` take `signers` verified against the **current** config; delay = veto window; `expires_at = unlock_time + 30 d`; permissionless `expire_timelock`; `min_threshold` fixed at construction with no setter and enforced on rotation (replaces the majority floor, which admitted 1-of-2); `config_epoch` recorded for audit only; stored `TimeLock.signers` audit only. New explicit `"Wrong operation type"` check so an unwrap timelock can never be executed through `execute_transfer` or vice-versa (the current code has no such check; under reservation accounting it is load-bearing).
8. **Panic vocabulary**: `"expired"` means only "past `expires_at`": before unlock → `"Timelock not matured"`; past window → `"Timelock expired"`; `expire_timelock` too early → `"Timelock not yet expired"`. `"Insufficient available balance"` replaces both advisory strings.
9. **Tests**: fixtures seed through real `mint + wrap` signed by a **full quorum of the fixture's threshold** (fixes the threshold-2 seed flaw); the 22 direct-seeding sites go away; proptest state machine drives `try_*` (no `catch_unwind`), `mock_all_auths`, `capture_snapshot_at_drop: false`, budget reset unlimited, `PROPTEST_CASES` env override, regressions committed; the deterministic `mock_auths(&[])` tests are mandatory and extended to execute/cancel/rotate/expire/bump; event ABI pinned; artifact gate on the release WASM; `test_instance_holds_only_config_keys`; `test_timelock_ttl_clamped_to_network_max`; window-boundary tests; stored-signers-audit-only test.
10. **Conservation is stated honestly everywhere**: on-chain `SAC.balance(contract) >= total_wrapped` (anyone can pay USDC to the contract address; there is no sweep); the proptest asserts `==` only because `MockUsdc` has no such path; `sweep_surplus` is a designed-separately follow-up.
11. **Release discipline**: CI emits `*.wasm.sha256` + `build-info.json`; tag `impala-soroban-v*` mirrors `impala-card.yml`'s softprops release job; Docker double-build reproducibility check non-gating first; manifests in `impala-soroban/deployments/<network>/<contract_id>.json` with `upload_tx_hash`, `deploy_tx_hash`, `ci_run`, `evaluator_accounts`, `stellar_cli_version`, `self_issued`; `deployments/README.md`; `scripts/check-manifests.sh` and `scripts/verify-deployment.sh` compare the issuer to Circle's canonical issuer per network (public refuses anything else), resolve `stellar contract id asset` == `usdc_token()`, and read `multisig_config()/min_threshold()/min_lock_duration()` on-chain; keep-alive job is `workflow_dispatch` only until a funded keeper identity exists in CI secrets (documented new secret surface); terraform CI equality check; stellar-cli pinned.
12. **Docs**: root `README.md:104-107` rewritten (the "anyone calls `execute_unwrap(timelock_id)`" claim was never true); `ARCHITECTURE.md:34-43` Use Case 2 steps 3-5 rewritten (bridge detection is unimplemented); `ARCHITECTURE.md:413-460`, `impala-soroban/README.md`, `DEVELOPMENT.md`, `CHANGELOG.md`, `CLAUDE.md`, new runbook `docs/runbooks/deploy-soroban.md`; snapshot orphan tripwire strips any `.N.json`.
13. **Delivery**: PR-A (contract + tests + docs) then PR-B (CI hash/manifest/verifier/runbook/tag/first testnet deploy). Crate version bumps to `0.2.0`; tag `impala-soroban-v0.2.0`.

---

## 2. Files touched (index)

PR-A
- `impala-soroban/integration-test/src/lib.rs` — contract rewrite (§4), `mod tests` rewrite (§5), `#[cfg(test)] mod invariants;`
- `impala-soroban/integration-test/src/invariants.rs` — **new** proptest state machine (§5.6)
- `impala-soroban/integration-test/Cargo.toml` — version `0.2.0`, dev-dep `proptest` (§6)
- `impala-soroban/integration-test/Cargo.lock` — regenerated, committed
- `impala-soroban/integration-test/deny.toml` — **new** (§6)
- `impala-soroban/integration-test/test_snapshots/tests/*.json` — regenerated; orphans deleted (§5.8)
- `impala-soroban/testnet-tests/src/lib.rs`, `tests/integration.rs` — constructor deploy, new tests (§7)
- `impala-soroban/README.md`, `ARCHITECTURE.md`, `README.md`, `DEVELOPMENT.md`, `CHANGELOG.md`, `CLAUDE.md` (§11)

PR-B
- `.github/workflows/impala-soroban.yml` (§8), `.github/workflows/ci.yml` (terraform equality step, §8.4)
- `impala-soroban/scripts/check-snapshots.sh`, `check-manifests.sh`, `verify-deployment.sh` — **new** (§9)
- `impala-soroban/deployments/README.md`, `deployments/testnet/<C…>.json` — **new** (§10)
- `docs/runbooks/deploy-soroban.md` — **new**; `docs/runbooks/README.md` row (§11.7)
- `terraform/terraform.tfvars.example:113` comment (§11.8)

---

## 3. Storage layout (final)

| `DataKey` variant (encoded by variant **name**; removal/append does not renumber) | Class | Value | Absent means |
|---|---|---|---|
| `MultisigConfig` | instance | `MultisigConfig { signers, threshold, epoch }` (`epoch` **appended**) | never |
| `WrappedUsdc` | instance | `WrappedUsdc { usdc_token, decimals, total_wrapped, usdc_issuer }` (`usdc_issuer` **appended**) | never |
| `MinLockDuration` | instance | `u64` | never |
| `NextTimeLockId` | instance | `u64` (monotone, starts 0) | never |
| `Paused` | instance | `bool` | `false` |
| `Reserved(Address)` | **persistent** (**new**, appended) | `i128` | 0; removed when it returns to 0 |
| `MinThreshold` | instance (**new**, appended) | `u32`, immutable | never |
| `Balance(Address)` | **persistent** (moved) | `i128` (kept at 0 after a full unwrap; absent = 0) | 0 |
| `TimeLock(u64)` | **persistent** (moved) | `TimeLock` | `"Timelock not found"` |
| `Initialized` | **removed** | — | — |

Final enum order: `MultisigConfig, WrappedUsdc, Balance(Address), TimeLock(u64), NextTimeLockId, MinLockDuration, Paused, Reserved(Address), MinThreshold`.

Temporary storage is deliberately unused (a temporary entry is deleted at expiry, which would strand a reservation; persistent entries archive and are restorable, and every read of an archived entry fails closed).

---

## 4. Contract (`impala-soroban/integration-test/src/lib.rs`, lines 1-745 replaced)

### 4.1 Module doc (verbatim; replaces lines 1-39)

```rust
//! MultisigUsdcWrapper — a Soroban smart contract that wraps Circle's USDC
//! Stellar asset with multisig authorization and time-locked operations.
//!
//! # Design
//!
//! The contract holds USDC (via its Stellar Asset Contract) on behalf of
//! users. Deposits (`wrap`) are immediate; withdrawals (`unwrap`) and
//! inter-account transfers require a two-ceremony schedule/execute pattern
//! with a configurable minimum delay.
//!
//! # Construction
//!
//! State is created only by `__constructor`, which the host runs inside the
//! deploy transaction. There is no post-deploy initialization entry point:
//! the host refuses direct calls to `__`-prefixed functions and a contract id
//! cannot be created twice, so no third party can seize a fresh instance.
//!
//! # Issuer pin
//!
//! The USDC SAC differs per network, so its address and Circle's issuer are
//! constructor arguments. Before any state is written the constructor checks
//! `symbol() == "USDC"`, `decimals() == 7` and `name() == "USDC:<issuer>"` —
//! a SAC's `name()` is derived by the host from the asset's code and issuer
//! at SAC creation and cannot be forged by a deployer. What the contract
//! cannot decide is *which* issuer is Circle: that binding is published in
//! `impala-soroban/deployments/` and re-verified from chain by
//! `scripts/verify-deployment.sh`.
//!
//! # Reservation
//!
//! Per holder: `balance`, `reserved`, `available = balance - reserved`.
//! Scheduling atomically moves `amount` from available to reserved, so an
//! accepted schedule is fully funded until it executes, is cancelled, or
//! expires. Invariants: `0 <= reserved <= balance`; `reserved(a)` equals the
//! sum of pending operations debiting `a`; the sum of balances equals
//! `total_wrapped`. On-chain the SAC balance of the contract is `>=`
//! `total_wrapped` (anyone can pay USDC straight to the contract address and
//! there is no sweep); the unit tests assert equality only because the mock
//! token has no such path.
//!
//! # Execution model
//!
//! A time-locked operation is created by one multisig ceremony
//! (`schedule_unwrap` / `schedule_transfer`: at least `threshold` of the
//! signers current at that moment) and consumed by a second
//! (`execute_unwrap` / `execute_transfer`: at least `threshold` of the
//! signers current at *execution* time). The delay is a veto window: while it
//! runs, any quorum of the current set may `cancel_timelock`, and the reserved
//! amount cannot be spent by any other operation. The execution window
//! `[unlock_time, expires_at)` (`expires_at = unlock_time + 30 days`) bounds
//! how long an approved-but-unexecuted operation may linger; at or after
//! `expires_at` anyone may call `expire_timelock` to release the reservation,
//! and the operation must be scheduled again. `rotate_signers` replaces the
//! signer set immediately and increments `epoch`; pending operations survive
//! rotation and are executable or cancellable only by the *new* set — a
//! rotated-out set (retired or compromised) can neither execute nor cancel,
//! and nothing is stranded. The `signers` and `config_epoch` recorded on a
//! timelock are audit metadata (who approved, under which configuration);
//! they are never consulted for authorization. Rotation can never set a
//! threshold below the `min_threshold` fixed at construction, and
//! `min_threshold` has no setter. `pause` blocks `wrap`, `schedule_*` and
//! `execute_*`; `cancel_timelock`, `expire_timelock`, `bump_ttl`,
//! `bump_entry_ttl`, `rotate_signers`, `unpause` and all reads work while
//! paused, so an operation that matures during a pause either executes within
//! its window after `unpause` or expires — it never becomes executable
//! forever.
//!
//! # Storage and TTL
//!
//! Configuration, total supply, the id counter, the pause flag and the
//! threshold floor live in instance storage (extended to ~30 days of ledgers
//! whenever fewer than ~7 remain). Per-holder balances, reservations and
//! timelocks are separate persistent entries, extended to ~160 days of
//! ledgers whenever fewer than ~30 remain, by every entry point that touches
//! them and by the permissionless `bump_entry_ttl`. A persistent entry that is
//! not touched for that long is *archived, not deleted*: every entry point that
//! reads it fails (host storage error) until it is restored with a
//! `RestoreFootprint` operation; it never reads as zero. `Balance(a)` and
//! `Reserved(a)` are always extended together. The constructor refuses a
//! network whose `max_entry_ttl` is below the extend-to target, so that a
//! pending operation can never archive before `expires_at` without any bump.
```

### 4.2 Crate attributes and imports

```rust
#![no_std]
// soroban-sdk 23.x deprecates `env.events().publish(...)`; the topics below are a
// frozen ABI for off-chain consumers (pinned by `test_event_abi_pins`), so the
// #[contractevent] migration is a separately coordinated change.
#![allow(deprecated)]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Bytes, Env, String, Vec,
};

#[cfg(test)]
extern crate std;
```

(`Bytes` is the only new import.) At the bottom of the file, after `mod tests`, add `#[cfg(test)] mod invariants;`.

### 4.3 Types (append-only; `Initialized` removed)

```rust
#[contracttype]
pub struct MultisigConfig {
    pub signers: Vec<Address>,
    pub threshold: u32,
    /// Incremented by every `rotate_signers`; 0 at construction. Audit only.
    pub epoch: u32,
}

#[contracttype]
pub struct WrappedUsdc {
    pub usdc_token: Address,
    pub decimals: u32,
    pub total_wrapped: i128,
    /// Issuer pinned at construction via the SAC's `name()`.
    pub usdc_issuer: Address,
}

#[contracttype]
pub struct TimeLock {
    pub operation_type: u32,      // 1 = unwrap, 2 = transfer
    pub signers: Vec<Address>,    // AUDIT ONLY: quorum that approved scheduling
    pub sender: Address,          // holder debited (unwrap: == recipient)
    pub recipient: Address,
    pub amount: i128,
    pub unlock_time: u64,
    pub executed: bool,           // in-flight marker (host also prohibits reentry)
    pub expires_at: u64,          // unlock_time + EXECUTION_WINDOW; execute requires now < expires_at
    pub scheduled_at: u64,        // ledger timestamp at schedule (audit)
    pub config_epoch: u32,        // MultisigConfig.epoch at schedule (audit; NOT an auth gate)
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    MultisigConfig,
    WrappedUsdc,
    Balance(Address),
    TimeLock(u64),
    NextTimeLockId,
    MinLockDuration,
    Paused,
    Reserved(Address),
    MinThreshold,
}
```

This is the last free struct change: after the first manifest entry (PR-B) all three structs are frozen except for trailing appends.

### 4.4 Constants (replace lines 112-127)

```rust
const SECONDS_PER_DAY: u64 = 86_400;
/// Ledgers per day at the 5 s nominal close time.
const LEDGERS_PER_DAY: u32 = 17_280;

/// Maximum schedule delay: 90 days (was 365). Bounded so that a pending
/// operation's whole life (MAX_LOCK_DURATION + EXECUTION_WINDOW = 120 d) fits
/// inside PERSISTENT_TTL_EXTEND_TO even at a 4 s ledger close.
const MAX_LOCK_DURATION: u64 = 90 * SECONDS_PER_DAY; // 7_776_000
/// Execution window after unlock_time; after it the op can only be expired.
const EXECUTION_WINDOW: u64 = 30 * SECONDS_PER_DAY; // 2_592_000
/// USDC always has 7 decimals on Stellar (constant for every SAC).
const USDC_DECIMALS: u32 = 7;
/// SAC name() prefix for the pinned asset code.
const USDC_NAME_PREFIX: &[u8] = b"USDC:";
const MAX_SIGNERS: u32 = 20;
/// Upper bound on keys per bump_entry_ttl call (bounded, permissionless work).
const MAX_BUMP_BATCH: u32 = 32;

/// Instance policy (unchanged): extend to ~30 d when fewer than ~7 d remain.
const INSTANCE_TTL_THRESHOLD: u32 = 7 * LEDGERS_PER_DAY; // 120_960
const INSTANCE_TTL_EXTEND_TO: u32 = 30 * LEDGERS_PER_DAY; // 518_400
/// Persistent policy: extend to ~160 d when fewer than ~30 d remain. Below the
/// public network max_entry_ttl (3,110,400) so on-chain extensions are never
/// clamped; 2,764,800 ledgers × 4 s = 128 d ≥ 120 d.
const PERSISTENT_TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY; // 518_400
const PERSISTENT_TTL_EXTEND_TO: u32 = 160 * LEDGERS_PER_DAY; // 2_764_800

const _: () = assert!(INSTANCE_TTL_THRESHOLD <= INSTANCE_TTL_EXTEND_TO);
const _: () = assert!(PERSISTENT_TTL_THRESHOLD <= PERSISTENT_TTL_EXTEND_TO);
// A pending operation never needs a bump, even at 4 s ledgers.
const _: () = assert!(MAX_LOCK_DURATION + EXECUTION_WINDOW <= (PERSISTENT_TTL_EXTEND_TO as u64) * 4);
```

### 4.5 Private helpers (inside `impl MultisigUsdcWrapper`, alongside the unchanged `extend_instance_ttl`, `require_not_paused`, `verify_multisig`, `require_no_duplicates`)

```rust
fn ledger_max_entry_ttl(env: &Env) -> u32 {
    env.ledger()
        .max_live_until_ledger()               // #[doc(hidden)] pub, sdk ledger.rs:73
        .checked_sub(env.ledger().sequence())
        .expect("Ledger TTL underflow")
        .checked_add(1)
        .expect("Ledger TTL overflow")
}

fn read_balance(env: &Env, a: &Address) -> i128 {
    env.storage().persistent().get(&DataKey::Balance(a.clone())).unwrap_or(0)
}
fn read_reserved(env: &Env, a: &Address) -> i128 {
    env.storage().persistent().get(&DataKey::Reserved(a.clone())).unwrap_or(0)
}
/// (balance, reserved) with the reservation invariant as a tripwire on every money path.
fn read_holder(env: &Env, a: &Address) -> (i128, i128) {
    let balance = Self::read_balance(env, a);
    let reserved = Self::read_reserved(env, a);
    if reserved < 0 || reserved > balance {
        panic!("Reserved invariant violated");
    }
    (balance, reserved)
}
fn extend_entry_ttl_if_present(env: &Env, key: &DataKey) {
    if env.storage().persistent().has(key) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND_TO);
    }
}
/// Balance(a) and Reserved(a) must age together.
fn touch_account(env: &Env, a: &Address) {
    Self::extend_entry_ttl_if_present(env, &DataKey::Balance(a.clone()));
    Self::extend_entry_ttl_if_present(env, &DataKey::Reserved(a.clone()));
}
fn write_balance(env: &Env, a: &Address, v: i128) {
    env.storage().persistent().set(&DataKey::Balance(a.clone()), &v);
    Self::touch_account(env, a);
}
fn write_reserved(env: &Env, a: &Address, v: i128) {
    if v == 0 {
        env.storage().persistent().remove(&DataKey::Reserved(a.clone()));
    } else {
        env.storage().persistent().set(&DataKey::Reserved(a.clone()), &v);
    }
    Self::touch_account(env, a);
}
fn read_timelock(env: &Env, id: u64) -> TimeLock {
    env.storage().persistent().get(&DataKey::TimeLock(id)).expect("Timelock not found")
}
fn write_timelock(env: &Env, id: u64, tl: &TimeLock) {
    let key = DataKey::TimeLock(id);
    env.storage().persistent().set(&key, tl);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND_TO);
}
fn remove_timelock(env: &Env, id: u64) {
    env.storage().persistent().remove(&DataKey::TimeLock(id));
}
/// Releases a pending operation's reservation (cancel / expire).
fn release_reservation(env: &Env, timelock: &TimeLock) {
    let (_balance, reserved) = Self::read_holder(env, &timelock.sender);
    let new_reserved = reserved.checked_sub(timelock.amount).expect("Reserved underflow");
    Self::write_reserved(env, &timelock.sender, new_reserved);
}
```

Rules: a `write_*` always extends the key it wrote (an entry just written exists, so no `has()` is needed for it); read-only entry points never extend (unchanged policy). Because `extend_ttl` is a no-op above the threshold (G5), calling it on every write is cheap.

### 4.6 `__constructor` (replaces `initialize`, lines 139-207)

```rust
/// Atomic with deployment. There is no post-deploy initialization entry point.
/// No `require_auth`: the deploy transaction is the authorization.
pub fn __constructor(
    env: Env,
    signers: Vec<Address>,
    threshold: u32,
    min_threshold: u32,
    usdc_token: Address,
    usdc_issuer: Address,
    min_lock_duration: u64,
) {
    if signers.is_empty() {
        panic!("Signers must not be empty");
    }
    if signers.len() > MAX_SIGNERS {
        panic!("Too many signers");
    }
    Self::require_no_duplicates(&signers);
    if min_threshold == 0 || min_threshold > signers.len() {
        panic!("Invalid min threshold");
    }
    if threshold < min_threshold || threshold > signers.len() {
        panic!("Invalid threshold");
    }
    if min_lock_duration > MAX_LOCK_DURATION {
        panic!("Min lock duration exceeds maximum");
    }
    if Self::ledger_max_entry_ttl(&env) < PERSISTENT_TTL_EXTEND_TO {
        panic!("Network max entry TTL below policy");
    }

    let token_client = token::Client::new(&env, &usdc_token);
    if token_client.symbol() != String::from_str(&env, "USDC") {
        panic!("Underlying token is not USDC");
    }
    let decimals = token_client.decimals();
    if decimals != USDC_DECIMALS {
        panic!("USDC token must have 7 decimals");
    }
    let mut expected_name = Bytes::from_slice(&env, USDC_NAME_PREFIX);
    expected_name.append(&usdc_issuer.to_string().to_bytes());
    if token_client.name().to_bytes() != expected_name {
        panic!("Underlying token issuer mismatch");
    }

    env.storage().instance().set(
        &DataKey::MultisigConfig,
        &MultisigConfig { signers, threshold, epoch: 0 },
    );
    env.storage().instance().set(
        &DataKey::WrappedUsdc,
        &WrappedUsdc { usdc_token, decimals, total_wrapped: 0, usdc_issuer },
    );
    env.storage().instance().set(&DataKey::MinLockDuration, &min_lock_duration);
    env.storage().instance().set(&DataKey::MinThreshold, &min_threshold);
    env.storage().instance().set(&DataKey::NextTimeLockId, &0u64);
    Self::extend_instance_ttl(&env);
}
```

Validation order is exactly the code order (cheapest first, no write before every check passes; a panic aborts the deploy so no instance exists). `threshold == 0` is caught by step 5 because `min_threshold >= 1`, so the existing literal `"Invalid threshold"` in `test_zero_threshold_panics` / `test_threshold_exceeding_signers_panics` still holds. Properties of the pin: a C-address issuer can never match (SAC names carry a G strkey); the native SAC fails on symbol; a look-alike `USDC` from another issuer fails on the strkey; `decimals` still rejects non-SAC tokens. No event (the deploy tx is the record; the manifest carries it).

### 4.7 Entry points — exact check order, effects, panics, events

Unchanged bodies: `bump_ttl`, `pause`, `unpause`, `verify_multisig`, `require_no_duplicates`, `require_not_paused`, `extend_instance_ttl`, `total_supply`, `usdc_token`, `usdc_decimals`.

**`wrap(env, signers, depositor, amount)`** — `require_not_paused` → `amount <= 0` → `"Amount must be positive"` → `verify_multisig(&signers)` → `depositor.require_auth()` → `extend_instance_ttl` → `token.transfer(depositor → contract, amount)` → `let (balance, _) = read_holder(depositor)` → `balance.checked_add(amount).expect("Balance overflow")` → `write_balance` → `total_wrapped.checked_add(amount).expect("Total supply overflow")` → set `WrappedUsdc` → event `(wrap, depositor) = amount` (unchanged).

**`schedule_unwrap(env, signers, recipient, amount, delay_seconds) -> u64`** — `require_not_paused` → `"Amount must be positive"` → `verify_multisig` → `extend_instance_ttl` → `let (id, unlock_time) = Self::schedule(&env, 1, signers, recipient.clone(), recipient.clone(), amount, delay_seconds)` → event `(sched_unw, recipient, id) = unlock_time` (unchanged) → return `id`.

**`schedule_transfer(env, signers, from, to, amount, delay_seconds) -> u64`** — `require_not_paused` → `"Amount must be positive"` → `from == to` → `"Self-transfer not allowed"` → `verify_multisig` → `extend_instance_ttl` → `schedule(&env, 2, signers, from.clone(), to.clone(), …)` → event `(sched_tx, from, to, id) = unlock_time` (unchanged).

Shared private `schedule`:

```rust
fn schedule(
    env: &Env,
    operation_type: u32,
    signers: Vec<Address>,
    sender: Address,
    recipient: Address,
    amount: i128,
    delay_seconds: u64,
) -> (u64, u64) {
    let min_duration: u64 = env.storage().instance().get(&DataKey::MinLockDuration).unwrap();
    if delay_seconds < min_duration {
        panic!("Delay too short");
    }
    if delay_seconds > MAX_LOCK_DURATION {
        panic!("Delay exceeds maximum lock duration");
    }
    let (balance, reserved) = Self::read_holder(env, &sender);
    let available = balance.checked_sub(reserved).expect("Reserved invariant violated");
    if available < amount {
        panic!("Insufficient available balance");
    }
    let timelock_id: u64 = env.storage().instance().get(&DataKey::NextTimeLockId).unwrap();
    let now = env.ledger().timestamp();
    let unlock_time = now.checked_add(delay_seconds).expect("Unlock time overflow");
    let expires_at = unlock_time.checked_add(EXECUTION_WINDOW).expect("Expiry overflow");
    let config: MultisigConfig = env.storage().instance().get(&DataKey::MultisigConfig).unwrap();
    let new_reserved = reserved.checked_add(amount).expect("Reserved overflow");
    Self::write_reserved(env, &sender, new_reserved);
    let timelock = TimeLock {
        operation_type, signers, sender, recipient, amount, unlock_time,
        executed: false, expires_at, scheduled_at: now, config_epoch: config.epoch,
    };
    Self::write_timelock(env, timelock_id, &timelock);
    let next_id = timelock_id.checked_add(1).expect("Timelock id overflow");
    env.storage().instance().set(&DataKey::NextTimeLockId, &next_id);
    (timelock_id, unlock_time)
}
```

**`execute_unwrap(env, signers, timelock_id)`** (signature changed):

```rust
pub fn execute_unwrap(env: Env, signers: Vec<Address>, timelock_id: u64) {
    Self::require_not_paused(&env);
    let mut timelock = Self::read_timelock(&env, timelock_id);     // "Timelock not found"
    if timelock.executed { panic!("Already executed"); }
    if timelock.operation_type != 1 { panic!("Wrong operation type"); }
    let now = env.ledger().timestamp();
    if now < timelock.unlock_time { panic!("Timelock not matured"); }
    if now >= timelock.expires_at { panic!("Timelock expired"); }
    Self::verify_multisig(&env, &signers);                           // CURRENT config
    Self::extend_instance_ttl(&env);
    let holder = timelock.sender.clone();                             // == recipient for unwraps
    let (balance, reserved) = Self::read_holder(&env, &holder);
    if balance < timelock.amount { panic!("Insufficient balance"); } // unreachable guard
    timelock.executed = true;
    Self::write_timelock(&env, timelock_id, &timelock);              // defense in depth
    let new_reserved = reserved.checked_sub(timelock.amount).expect("Reserved underflow");
    let new_balance = balance.checked_sub(timelock.amount).expect("Balance underflow");
    Self::write_reserved(&env, &holder, new_reserved);
    Self::write_balance(&env, &holder, new_balance);
    let mut wrapped_usdc: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
    let token_client = token::Client::new(&env, &wrapped_usdc.usdc_token);
    token_client.transfer(&env.current_contract_address(), &timelock.recipient, &timelock.amount);
    wrapped_usdc.total_wrapped = wrapped_usdc.total_wrapped.checked_sub(timelock.amount).expect("Total supply underflow");
    env.storage().instance().set(&DataKey::WrappedUsdc, &wrapped_usdc);
    Self::remove_timelock(&env, timelock_id);
    env.events().publish((symbol_short!("exec_unw"), timelock.recipient, timelock_id), timelock.amount);
}
```

**`execute_transfer(env, signers, timelock_id)`** — identical gates with `operation_type != 2` → `"Wrong operation type"`; then `let (from_balance, from_reserved) = read_holder(sender)`; `let (to_balance, _) = read_holder(recipient)`; guard `"Insufficient balance"`; `executed = true` + write; `from_reserved − amount` (`"Reserved underflow"`), `from_balance − amount` (`"Balance underflow"`), `to_balance + amount` (`"Balance overflow"`); `write_reserved(sender)`, `write_balance(sender)`, `write_balance(recipient)` (each touches the account); `remove_timelock`; event `(exec_tx, sender, recipient, id) = amount` (unchanged). No token call, no `total_wrapped` change.

**`cancel_timelock(env, signers, timelock_id)`** (signature unchanged) — `verify_multisig(&signers)` (current) → `extend_instance_ttl` → `read_timelock` → `executed` → `"Already executed"` → `release_reservation` → `remove_timelock` → event `(cancel, id) = 0` (unchanged). Not pause-gated.

**`expire_timelock(env, timelock_id)`** (**new**, permissionless):

```rust
pub fn expire_timelock(env: Env, timelock_id: u64) {
    let timelock = Self::read_timelock(&env, timelock_id);
    if timelock.executed { panic!("Already executed"); }
    if env.ledger().timestamp() < timelock.expires_at { panic!("Timelock not yet expired"); }
    Self::extend_instance_ttl(&env);
    Self::release_reservation(&env, &timelock);
    Self::remove_timelock(&env, timelock_id);
    env.events().publish((symbol_short!("expire"), timelock_id), 0);
}
```
`now >= expires_at` is the exact complement of execute's `now < expires_at` (no gap, no overlap). Not pause-gated. No auth: after the window the only lawful outcome is release, and it must not depend on quorum liveness.

**`rotate_signers(env, current_signers, new_signers, new_threshold)`** (signature unchanged) — `new_signers.is_empty()` → `"New signers must not be empty"` → `let min_threshold: u32 = instance.get(MinThreshold)` → `new_threshold < min_threshold || new_threshold > new_signers.len()` → `"Invalid new threshold"` → `len > MAX_SIGNERS` → `"Too many signers"` → `require_no_duplicates(&new_signers)` → `verify_multisig(&current_signers)` → `extend_instance_ttl` → `epoch = current.epoch.checked_add(1).expect("Epoch overflow")` → set `MultisigConfig { signers: new_signers, threshold: new_threshold, epoch }` → event `(rotate,) = new_threshold` (unchanged).

**`bump_entry_ttl(env, addresses: Vec<Address>, timelock_ids: Vec<u64>)`** (**new**, permissionless):

```rust
pub fn bump_entry_ttl(env: Env, addresses: Vec<Address>, timelock_ids: Vec<u64>) {
    let total = addresses.len().checked_add(timelock_ids.len()).expect("Bump batch overflow");
    if total > MAX_BUMP_BATCH { panic!("Bump batch too large"); }
    Self::extend_instance_ttl(&env);
    for a in addresses.iter() { Self::touch_account(&env, &a); }
    for id in timelock_ids.iter() { Self::extend_entry_ttl_if_present(&env, &DataKey::TimeLock(id)); }
}
```
Missing keys are skipped; archived keys cannot be touched from inside a contract (the operator restores first). No events. `bump_ttl()` keeps its name and behaviour (instance only); its doc changes to "instance only — per-holder and per-timelock entries are bumped with `bump_entry_ttl`".

**Reads** (never extend TTL):
```rust
pub fn get_timelock(env: Env, timelock_id: u64) -> TimeLock { Self::read_timelock(&env, timelock_id) }
pub fn balance(env: Env, address: Address) -> i128 { Self::read_balance(&env, &address) }
pub fn reserved(env: Env, address: Address) -> i128 { Self::read_reserved(&env, &address) }          // new
pub fn available(env: Env, address: Address) -> i128 {                                              // new
    let (b, r) = Self::read_holder(&env, &address);
    b.checked_sub(r).expect("Reserved invariant violated")
}
pub fn total_supply(env: Env) -> i128            // unchanged
pub fn usdc_token(env: Env) -> Address           // unchanged
pub fn usdc_decimals(env: Env) -> u32            // unchanged
pub fn usdc_issuer(env: Env) -> Address          // new: WrappedUsdc.usdc_issuer
pub fn multisig_config(env: Env) -> MultisigConfig   // new
pub fn min_lock_duration(env: Env) -> u64        // new
pub fn min_threshold(env: Env) -> u32            // new
pub fn is_paused(env: Env) -> bool               // new: Paused.unwrap_or(false)
pub fn next_timelock_id(env: Env) -> u64         // new
pub fn max_entry_ttl(env: Env) -> u32            // new: Self::ledger_max_entry_ttl(&env) (what the TTL policy is clamped to)
```

### 4.8 Final public ABI (append-only from PR-B's first manifest onward)

| Function | Auth | Paused? | Status |
|---|---|---|---|
| `__constructor(signers, threshold, min_threshold, usdc_token, usdc_issuer, min_lock_duration)` | deploy tx | — | replaces `initialize` |
| `wrap(signers, depositor, amount)` | multisig + depositor | blocked | unchanged |
| `schedule_unwrap(signers, recipient, amount, delay_seconds) -> u64` | multisig | blocked | now reserves |
| `schedule_transfer(signers, from, to, amount, delay_seconds) -> u64` | multisig | blocked | now reserves |
| `execute_unwrap(signers, timelock_id)` | multisig (current) | blocked | **signature changed** |
| `execute_transfer(signers, timelock_id)` | multisig (current) | blocked | **signature changed** |
| `cancel_timelock(signers, timelock_id)` | multisig (current) | allowed | releases |
| `expire_timelock(timelock_id)` | none | allowed | **new** |
| `pause(signers)` / `unpause(signers)` | multisig | — | unchanged |
| `rotate_signers(current_signers, new_signers, new_threshold)` | multisig | allowed | floor + epoch |
| `bump_ttl()` | none | allowed | unchanged (instance only) |
| `bump_entry_ttl(addresses, timelock_ids)` | none | allowed | **new** |
| reads: `get_timelock`, `balance`, `total_supply`, `usdc_token`, `usdc_decimals` | — | — | unchanged |
| reads new: `reserved`, `available`, `usdc_issuer`, `multisig_config`, `min_lock_duration`, `min_threshold`, `is_paused`, `next_timelock_id`, `max_entry_ttl` | — | — | **new** |

Crate name `soroban-impala-integration-test` and artifact `soroban_impala_integration_test.wasm` unchanged.

### 4.9 Events (frozen; pinned by `test_event_abi_pins`)

| Call | Topics | Data |
|---|---|---|
| `wrap` | `(symbol_short!("wrap"), depositor: Address)` | `amount: i128` |
| `schedule_unwrap` | `("sched_unw", recipient, timelock_id: u64)` | `unlock_time: u64` |
| `execute_unwrap` | `("exec_unw", recipient, timelock_id)` | `amount: i128` |
| `schedule_transfer` | `("sched_tx", from, to, timelock_id)` | `unlock_time: u64` |
| `execute_transfer` | `("exec_tx", sender, recipient, timelock_id)` | `amount: i128` |
| `cancel_timelock` | `("cancel", timelock_id)` | `0i32` |
| `pause` / `unpause` | `("pause",)` / `("unpause",)` | `0i32` |
| `rotate_signers` | `("rotate",)` | `new_threshold: u32` |
| `expire_timelock` | `("expire", timelock_id)` | `0i32` — **new, additive** |

The nine existing topic/data shapes are byte-identical to today (the `0` literals are `i32`, as today).

### 4.10 Panic vocabulary (complete; tests pin every string they exercise)

Constructor: `Signers must not be empty`, `Too many signers`, `Duplicate signer detected`, `Invalid min threshold`, `Invalid threshold`, `Min lock duration exceeds maximum`, `Network max entry TTL below policy`, `Underlying token is not USDC`, `USDC token must have 7 decimals`, `Underlying token issuer mismatch`.
Money paths: `Contract is paused`, `Amount must be positive`, `Self-transfer not allowed`, `Insufficient signers`, `Signer not authorized`, `Delay too short`, `Delay exceeds maximum lock duration`, `Reserved invariant violated`, `Insufficient available balance`, `Unlock time overflow`, `Expiry overflow`, `Reserved overflow`, `Timelock id overflow`, `Balance overflow`, `Total supply overflow`.
Execute/cancel/expire: `Timelock not found`, `Already executed`, `Wrong operation type`, `Timelock not matured`, `Timelock expired`, `Timelock not yet expired`, `Insufficient balance` (guard), `Reserved underflow`, `Balance underflow`, `Total supply underflow`.
Governance: `New signers must not be empty`, `Invalid new threshold`, `Epoch overflow`, `Bump batch too large`, `Ledger TTL underflow`, `Ledger TTL overflow`.
Removed: `Already initialized`, `Insufficient wrapped balance`, `Timelock not expired`.

All arithmetic is `checked_*`; `overflow-checks = true` stays in the release profile.

---

## 5. Unit tests (`mod tests` in `lib.rs`, plus `src/invariants.rs`)

### 5.1 Fixture (replaces `setup_env` / `init_contract`, lines 821-846)

```rust
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, vec, Env, Symbol, Val, IntoVal};

struct Fx {
    env: Env,
    contract: Address,
    token: Address,   // MockUsdc
    issuer: Address,
    s1: Address,
    s2: Address,
    signers: Vec<Address>,
    threshold: u32,
}
impl Fx {
    fn client(&self) -> MultisigUsdcWrapperClient<'_> { MultisigUsdcWrapperClient::new(&self.env, &self.contract) }
    fn usdc(&self) -> MockUsdcClient<'_> { MockUsdcClient::new(&self.env, &self.token) }
    /// First `threshold` configured signers — always a valid quorum for this fixture.
    fn quorum(&self) -> Vec<Address> {
        let mut q = Vec::new(&self.env);
        for i in 0..self.threshold { q.push_back(self.signers.get(i).unwrap()); }
        q
    }
    /// Conservation-preserving seed: mint on the mock, then wrap through the contract
    /// with a full quorum. Never writes storage directly.
    fn seed(&self, holder: &Address, amount: i128) {
        self.usdc().mint(holder, &amount);
        self.client().wrap(&self.quorum(), holder, &amount);
    }
    fn advance(&self, secs: u64) { self.env.ledger().with_mut(|li| li.timestamp += secs); }
    /// Σ balance(holders) == total_supply == MockUsdc.balance(contract); 0 <= reserved <= balance.
    fn assert_conserved(&self, holders: &[&Address]) { /* as stated */ }
    fn has_timelock(&self, id: u64) -> bool {
        self.env.as_contract(&self.contract, || self.env.storage().persistent().has(&DataKey::TimeLock(id)))
    }
}
fn register_wrapper(env: &Env, signers: &Vec<Address>, threshold: u32, min_threshold: u32,
                    token: &Address, issuer: &Address, min_lock: u64) -> Address {
    // tuple form of ConstructorArgs (verified); MultisigUsdcWrapperArgs::__constructor(..) is equivalent
    env.register(MultisigUsdcWrapper, (signers.clone(), threshold, min_threshold, token.clone(), issuer.clone(), min_lock))
}
fn deploy_n(n: u32, threshold: u32, min_threshold: u32, min_lock: u64) -> Fx {
    let env = Env::default();
    env.mock_all_auths();
    let issuer = Address::generate(&env);
    let token = create_usdc_token(&env, &issuer);
    let mut signers = Vec::new(&env);
    for _ in 0..n { signers.push_back(Address::generate(&env)); }
    let contract = register_wrapper(&env, &signers, threshold, min_threshold, &token, &issuer, min_lock);
    let s1 = signers.get(0).unwrap();
    let s2 = signers.get(1).unwrap_or_else(|| s1.clone());
    Fx { env, contract, token, issuer, s1, s2, signers, threshold }
}
fn deploy(threshold: u32, min_threshold: u32, min_lock: u64) -> Fx { deploy_n(2, threshold, min_threshold, min_lock) }
fn deploy_default() -> Fx { deploy(1, 1, 10) }   // == today's init_contract
```

### 5.2 `MockUsdc` changes (test-only, lines 760-819)

- `__constructor(env, name: String, symbol: String, decimals: u32)` (`name` prepended); new `MockUsdcKey::Name`; new `pub fn name(env) -> String`.
- `fn strkey(a: &Address) -> std::string::String { let s = a.to_string(); let mut b = std::vec![0u8; s.len() as usize]; s.copy_into_slice(&mut b); std::string::String::from_utf8(b).unwrap() }`
- `fn create_usdc_token(env: &Env, issuer: &Address) -> Address { let name = std::format!("USDC:{}", strkey(issuer)); env.register(MockUsdc, (String::from_str(env, &name), String::from_str(env, "USDC"), 7u32)) }`
- `fn create_token(env, name: &str, symbol: &str, decimals: u32) -> Address` for negatives.
- Make `MockUsdc`, `MockUsdcClient`, `create_usdc_token` `pub(crate)` so `invariants.rs` can use them.

### 5.3 Real-SAC helper (honesty gate for the pin; copy verbatim from `scratchpad/exp/src/lib.rs:2016-2058`, verified)

`fn issuer_address(env, seed: u8) -> (Address, xdr::AccountId)` and `fn make_usdc_sac(env, seed: u8) -> (sac: Address, issuer: Address)` replicating `register_stellar_asset_contract_v2` (sdk `env.rs:984-1050`) with `AssetCode4(*b"USDC")`: add the issuer `LedgerEntryData::Account` via `env.host().add_ledger_entry`, then `env.host().invoke_function(HostFunction::CreateContract(CreateContractArgs { contract_id_preimage: ContractIdPreimage::Asset(Asset::CreditAlphanum4 {..}), executable: ContractExecutable::StellarAsset }))`, convert with `Address::try_from_val`. Imports: `soroban_sdk::{xdr, TryFromVal}`, `std::rc::Rc`. Minting on a real SAC: `token::StellarAssetClient::new(&env, &sac).mint(&holder, &amount)` under `mock_all_auths`.

### 5.4 Mechanical edits to existing tests (line-cited)

- Delete `test_double_initialize_panics` (860-868).
- The 13 `client.initialize(...)` sites (877, 887, 932, 951, 965, 1258, 1704, 1726, 1857, 1869, 1883, 1897, 1911) become `register_wrapper(...)` (or `deploy(...)`) inside the **same** `#[should_panic(expected = …)]` (G3). Rename `test_initialize_*` → `test_constructor_*`, `test_init_*` → `test_constructor_*`.
- The 22 direct-seeding sites (993, 1015, 1042, 1079, 1105, 1207, 1232, 1260, 1281, 1317, 1341, 1377, 1399, 1429, 1451, 1493, 1519, 1565, 1599, 1619, 1659, 1740) become `fx.seed(&holder, N)`. The threshold-2 fixture at 1249-1272 becomes `let fx = deploy(2, 1, 10); fx.seed(&fx.s1, 500);` then `schedule_transfer(&vec![&env, s1], …)` → `"Insufficient signers"` for the right reason. Line 1565 (seed after rotation) seeds with the **new** quorum (`fx.signers`/`threshold` are not updated by rotation, so this test builds its own quorum vector of the new signers).
- The 5 `instance().has(&DataKey::TimeLock(..))` asserts (1055, 1063, 1541, 1643, 1963) → `fx.has_timelock(id)` (persistent).
- Execute call sites (1419, 1637, 1673, 1759, 1762, 1954) gain `&signers` as first argument.
- Literals: 973/1335 `"Insufficient wrapped balance"` → `"Insufficient available balance"`; 1127 `"Insufficient balance"` → `"Insufficient available balance"`; 1653 `"Timelock not expired"` → `"Timelock not matured"`; 1462-1463 replace the literal `31_536_001` and its comment with `&(MAX_LOCK_DURATION + 1)`; 1897 stays symbolic.
- `test_constructor_rejects_wrong_decimals` (1862): `create_token(&env, &format!("USDC:{}", strkey(&issuer)), "USDC", 6)`.
- `test_constructor_rejects_non_usdc_token` (1850): keep the `aaa` SAC, pass `sac.issuer().address()` as `usdc_issuer` so the failure is provably the symbol.
- No-mock tests (1691, 1716): `Env::default(); env.mock_auths(&[]);` `create_usdc_token`, `register_wrapper` (no `require_auth` in the constructor), then the call; keep bare `#[should_panic]`.
- TTL tests 1790-1833: **unchanged** (instance constants unchanged).
- Add `fx.assert_conserved(..)` at the end of every test that moves value (wrap/execute/cancel/expire paths).

### 5.5 New targeted tests (name → assertion)

Constructor / adversarial
- `test_constructor_sets_state`: `multisig_config()` == (signers, threshold, epoch 0), `min_threshold()`, `min_lock_duration()`, `usdc_token()`, `usdc_issuer()`, `usdc_decimals()==7`, `total_supply()==0`, `next_timelock_id()==0`, `is_paused()==false`.
- `test_constructor_cannot_be_invoked_directly`: `#[should_panic(expected = "can't invoke a reserved function directly")]`; `fx.env.invoke_contract::<Val>(&fx.contract, &Symbol::new(&fx.env, "__constructor"), vec![&fx.env])` (the reserved check precedes argument handling, G1).
- `test_initialize_entry_point_removed`: `#[should_panic(expected = "calling unknown contract function")]`; invoke `Symbol::new(&env, "initialize")` with `vec![&env]`.
- `test_constructor_rejects_empty_signers` (`"Signers must not be empty"`), `test_constructor_rejects_threshold_below_min_threshold` (3 signers, min 2, threshold 1 → `"Invalid threshold"`), `test_constructor_rejects_min_threshold_above_len` (`"Invalid min threshold"`), `test_constructor_rejects_zero_min_threshold` (`"Invalid min threshold"`).
- `test_constructor_rejects_low_network_max_ttl`: `env.ledger().set_max_entry_ttl(1_000_000)` before `register_wrapper` → `"Network max entry TTL below policy"`.
- `test_constructor_accepts_real_usdc_sac`: `make_usdc_sac(&env, 7)`; construct; `usdc_issuer()==issuer`, `usdc_token()==sac`; mint via `StellarAssetClient`, `wrap`, schedule/execute one unwrap; `token::Client::balance(contract)` == `total_supply()` at both points.
- `test_constructor_rejects_issuer_mismatch_real_sac`: two real SACs (seeds 7 and 9); `(sac_b, issuer_a)` → `"Underlying token issuer mismatch"`.
- `test_constructor_rejects_issuer_mismatch_mock`: MockUsdc named for issuer A, constructor given B → mismatch.
- `test_constructor_rejects_contract_address_issuer`: `usdc_issuer = usdc_token` (C-address) → mismatch.
- `test_constructor_rejects_native_symbol`: `create_token(&env, "native", "native", 7)` → `"Underlying token is not USDC"`.
- Kept/renamed: `test_zero_threshold_panics`, `test_threshold_exceeding_signers_panics`, `test_constructor_rejects_duplicate_signers`, `_too_many_signers`, `_min_lock_above_max`, `_non_usdc_token`, `_wrong_decimals`, `test_constructor_records_usdc_token_and_decimals`.

Reservation
- `test_schedule_reserves`: seed 500; schedule 300 → `reserved==300`, `available==200`, `balance==500`.
- `test_over_schedule_rejected`: then schedule 300 → `"Insufficient available balance"`; (second test fn) schedule 200 succeeds.
- `test_schedule_transfer_over_available_rejected`: balance 500, unwrap 300 pending, `schedule_transfer 201` → panic; `200` succeeds.
- `test_cancel_releases_reservation`: reserved back to 0; `Reserved` key absent (`persistent().has(Reserved(a)) == false`); then schedule 500 succeeds.
- `test_execute_unwrap_consumes_reservation`: seed 1_000, schedule 400, advance, execute → balance 600, reserved 0, total 600, `usdc.balance(contract)==600`, `usdc.balance(holder)==400`, entry gone.
- `test_execute_transfer_consumes_reservation`: sender reserved 0, balances moved, recipient's `reserved` untouched.
- `test_transfer_recipient_reservation_untouched`: recipient has its own pending reservation before the transfer; unchanged after.
- `test_reserved_entry_removed_at_zero`.
- `test_reserved_invariant_tripwire`: `env.as_contract` sets `Reserved(s1) = 600` with `Balance(s1)=500` → `schedule_unwrap` → `"Reserved invariant violated"` (the only remaining direct storage write in the suite). Also `available()` panics with the same string.
- `test_execute_unwrap_rejects_transfer_timelock` and `test_execute_transfer_rejects_unwrap_timelock`: `"Wrong operation type"`; state unchanged.
- `test_reserved_never_exceeds_balance_after_sequence`: schedule 3, execute 1, cancel 1, expire 1 → invariants hold.

Execution model
- `test_execute_after_rotation_by_new_signers_succeeds`: schedule with `[s1]`; rotate to `[n1,n2]` threshold 1; advance; `execute_unwrap(&vec![n1], id)` succeeds; `get_timelock` before execute still reports `signers == [s1]` (stored signers unchanged by rotation).
- `test_execute_after_rotation_by_old_signers_panics`: `"Signer not authorized"`.
- `test_cancel_by_old_signers_after_rotation_panics`: `"Signer not authorized"`.
- `test_execute_requires_current_threshold`: rotate 1-of-2 → 2-of-3; execute with one signer → `"Insufficient signers"`.
- `test_stored_signers_are_audit_only`: after rotation the entry's `signers`/`config_epoch` are the schedule-time values; `multisig_config().epoch == 1`.
- `test_execute_under_pause_panics` (`"Contract is paused"`); `test_execute_after_unpause_within_window_succeeds`.
- `test_execute_at_window_boundaries`: `now == unlock_time` succeeds; a second timelock with `now == expires_at` → `"Timelock expired"`; `now == expires_at − 1` succeeds.
- `test_execute_past_expiry_panics` (`"Timelock expired"`), `test_execute_before_maturity_panics` (`"Timelock not matured"`).
- `test_expire_before_expiry_panics` (`"Timelock not yet expired"`), `test_expire_releases_reservation_and_removes_entry`, `test_expire_twice_panics` (`"Timelock not found"`), `test_expire_works_while_paused`.
- `test_timelock_records_expiry_epoch_and_scheduled_at`: `expires_at == unlock_time + EXECUTION_WINDOW`, `scheduled_at == ts at schedule`, `config_epoch == 0`.
- `test_rotate_bumps_epoch`, `test_rotate_below_min_threshold_panics` (`deploy_n(3,2,2,10)`, rotate to threshold 1 → `"Invalid new threshold"`), `test_rotate_to_min_threshold_allowed`.
- `test_delay_too_long_panics` now uses `MAX_LOCK_DURATION + 1`.

Authorization (all with `env.mock_auths(&[])` at the point of the asserted call; schedule under `mock_all_auths` first where needed, then `env.mock_auths(&[])`)
- Kept: `test_wrap_requires_signer_auth`, `test_schedule_unwrap_requires_signer_auth`.
- New `#[should_panic]`: `test_execute_unwrap_requires_signer_auth`, `test_execute_transfer_requires_signer_auth`, `test_cancel_requires_signer_auth`, `test_rotate_requires_signer_auth`, `test_pause_requires_signer_auth`.
- New permissionless (must **succeed** with no mocks): `test_expire_is_permissionless`, `test_bump_entry_ttl_is_permissionless`, `test_bump_ttl_is_permissionless`.
- `test_execute_by_non_signer_rejected` (`"Signer not authorized"`), `test_cancel_by_non_signer_rejected`.

Storage / TTL (`use soroban_sdk::testutils::storage::{Persistent as _, Instance as _}`)
- `test_balance_is_persistent_not_instance`: after wrap, `persistent().has(Balance(d))` and `!instance().has(Balance(d))`.
- `test_instance_holds_only_config_keys`: after wrap/schedule/execute/cancel/pause/unpause/rotate, every key of `env.as_contract(.., || instance().all())` decodes via `DataKey::try_from_val(&env, &key)` to one of `MultisigConfig | WrappedUsdc | MinLockDuration | MinThreshold | NextTimeLockId | Paused`; any other or undecodable key fails.
- `test_fresh_persistent_entry_reads_min_ttl_minus_one`: direct-set (in a throwaway contract frame) reads 4095 — documents G6 so nobody asserts 4096.
- `test_wrap_extends_balance_ttl`: `get_ttl(Balance(d)) == PERSISTENT_TTL_EXTEND_TO`.
- `test_schedule_extends_timelock_and_reserved_ttl`: both `== PERSISTENT_TTL_EXTEND_TO`.
- `test_wrap_touches_reserved`: with a pending reservation, decay `sequence_number += 2_300_000`, `wrap` again → `get_ttl(Reserved(d)) == PERSISTENT_TTL_EXTEND_TO` (closes the archive-independently risk).
- `test_bump_entry_ttl_extends_listed_keys`: decay by `2_300_000` (remaining 464,800 < threshold 518,400), call `bump_entry_ttl([d], [id])` → Balance/Reserved/TimeLock all `== PERSISTENT_TTL_EXTEND_TO`; instance `== INSTANCE_TTL_EXTEND_TO`.
- `test_bump_entry_ttl_skips_missing_keys` (unknown address + unknown id → no panic), `test_bump_entry_ttl_batch_too_large` (`"Bump batch too large"` at 33 entries).
- `test_timelock_ttl_clamped_to_network_max`: deploy at default max; `env.ledger().set_max_entry_ttl(2_000_000)`; decay `2_300_000`; `bump_entry_ttl` → `get_ttl(TimeLock(id)) == 2_000_000` (clamp, G5/G6).
- `test_bump_ttl_extends_instance`, `test_mutating_op_extends_instance_ttl`: unchanged.

Events
- `test_event_abi_pins`: one of each operation; after each call take `env.events().all().last()` and `assert_eq!` against `(contract.clone(), <topics>.into_val(&env), <data>.into_val(&env))` per §4.9 (data types exactly `i128`, `u64`, `i32`, `u32` as listed).

Artifact gate (`#[ignore]`, run by CI after the WASM build)
- `test_wasm_artifact_loads_in_pinned_host`: `let path = std::env::var("IMPALA_WASM").expect("IMPALA_WASM")`; `let wasm = std::fs::read(path).unwrap()`; `env.register(wasm.as_slice(), (signers, 1u32, 1u32, token, issuer, 10u64))` with a `MockUsdc`; mint, `wrap`, schedule + advance + `execute_unwrap`; assert conservation. Proves the release artifact parses in the pinned host and the constructor-arg encoding end-to-end (and guards the rustc ≥ 1.82 `wasm32-unknown-unknown` feature hazard, §11.9).

### 5.6 Property test — `impala-soroban/integration-test/src/invariants.rs` (`#[cfg(test)] mod invariants;` in `lib.rs`)

```rust
use super::tests::{create_usdc_token, MockUsdcClient};
use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Ledger as _};
use soroban_sdk::Vec as SVec;
use std::vec::Vec;

const HOLDERS: usize = 4;
const POOL: usize = 5;          // signer pool S0..S4; initial config [S0,S1,S2]
const INIT_THRESHOLD: u32 = 2;
const MIN_THRESHOLD: u32 = 2;   // so Rotate exercises the floor
const MIN_LOCK: u64 = 10;
const MINT: i128 = 20_000;      // per holder on MockUsdc

#[derive(Clone, Debug)] enum Amt { Fixed(i128), ExactAvailable, AvailablePlusOne }
#[derive(Clone, Debug)] enum Op {
    Wrap { h: usize, amt: i128 },
    SchedUnwrap { h: usize, amt: Amt, delay: u64 },
    SchedTransfer { from: usize, to: usize, amt: Amt, delay: u64 },
    Execute { slot: usize }, Cancel { slot: usize }, Expire { slot: usize },
    Advance { secs: u64 }, Pause, Unpause,
    Rotate { mask: u8, threshold: u32 },
    BumpEntries,
}
#[derive(Clone, Debug)] struct Pend { id: u64, kind: u32, from: usize, to: usize, amt: i128, unlock: u64, expires: u64 }
struct Model {
    bal: [i128; HOLDERS], res: [i128; HOLDERS], sac: [i128; HOLDERS], total: i128,
    paused: bool, signers: Vec<usize>, threshold: u32, epoch: u32,
    next_id: u64, now: u64, issued: Vec<u64>, pending: Vec<Pend>,
}
```

Strategies (`fn op_strategy() -> impl Strategy<Value = Op>`), `prop_oneof!` weights: Wrap 3 (`amt in 1..=6_000i128`), SchedUnwrap 3, SchedTransfer 3 (`amt: prop_oneof![ (1..=6_000i128).prop_map(Amt::Fixed) => 6, Just(Amt::ExactAvailable) => 1, Just(Amt::AvailablePlusOne) => 1 ]`, `delay: prop_oneof![ (MIN_LOCK..=2_000u64) => 8, Just(MIN_LOCK - 1) => 1, Just(MAX_LOCK_DURATION + 1) => 1 ]`), Execute 3, Cancel 2, Expire 1, Advance 3 (`secs: prop_oneof![ (0..=3_000u64) => 6, Just(EXECUTION_WINDOW - 1) => 1, Just(EXECUTION_WINDOW + 1) => 1, Just(MAX_LOCK_DURATION + EXECUTION_WINDOW + 10) => 1 ]`), Pause 1, Unpause 1, Rotate 1 (`mask in 0u8..32, threshold in 1u32..=5`), BumpEntries 1. `slot` is `0..64usize` and indexes `model.issued` modulo its length (no-op when empty), so consumed ids are retried and must fail `"Timelock not found"`.

Driver:
```rust
fn cases() -> u32 { std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64) }
proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), max_shrink_iters: 256, .. ProptestConfig::default() })]
    #[test]
    fn state_machine(ops in prop::collection::vec(op_strategy(), 1..=40)) {
        let env = Env::new_with_config(EnvTestConfig { capture_snapshot_at_drop: false });
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();
        // holders H[0..4], pool S[0..5], issuer, MockUsdc, mint MINT to each holder,
        // register wrapper with ([S0,S1,S2], INIT_THRESHOLD, MIN_THRESHOLD, token, issuer, MIN_LOCK)
        // model initialised to match; run ops; check() after every op
    }
}
```
Per op: compute `expected_ok` from the model using the contract's own predicates —
- Wrap: `!paused && sac[h] >= amt`.
- SchedUnwrap: `!paused && MIN_LOCK <= delay <= MAX_LOCK_DURATION && amt >= 1 && bal[h]-res[h] >= amt` (resolve `Amt` first: `ExactAvailable` → `bal-res` (if 0 → expect `"Amount must be positive"` failure), `AvailablePlusOne` → `bal-res+1`).
- SchedTransfer: additionally `from != to`.
- Execute: `!paused && pending && unlock <= now < expires`; call `try_execute_unwrap` or `try_execute_transfer` by kind.
- Cancel: `pending`. Expire: `pending && now >= expires`.
- Rotate: `mask != 0 && MIN_THRESHOLD <= threshold <= popcount(mask)`; `current = quorum(model)`.
- Advance/Pause/Unpause/BumpEntries: always ok (BumpEntries passes all holders and all pending ids, ≤ 4 + pending ≤ 32).
The harness signs every multisig call with the first `threshold` members of `model.signers`. Issue the call through the generated `try_*` method and `prop_assert_eq!(res.is_ok(), expected_ok, "op {:?}", op)`; on success apply the transition to the model (wrap: `bal+=`, `sac-=`, `total+=`; schedule: `res+=`, push `Pend`, `issued.push`, `next_id+=1`; execute unwrap: `res-=`, `bal-=`, `total-=`, `sac+=`; execute transfer: `res[from]-=`, `bal[from]-=`, `bal[to]+=`; cancel/expire: `res-=`, drop pending; rotate: signers/threshold/`epoch+=1`; advance: `now+=`, `env.ledger().with_mut(|li| li.timestamp = now)`).

`check(&env, &client, &usdc, &model)` after **every** op:
1. `∀h: client.balance(h)==bal[h]`, `client.reserved(h)==res[h]`, `client.available(h)==bal[h]-res[h]`, `0 <= res[h] <= bal[h]`.
2. `Σ bal == client.total_supply() == usdc.balance(contract)`; `usdc.balance(contract) + Σ usdc.balance(h) == HOLDERS*MINT`. *(Comment in the file: equality holds only against MockUsdc; on-chain `SAC.balance(contract) >= total_wrapped`.)*
3. `∀h: res[h] == Σ pending.amt where pending.from == h`.
4. `client.next_timelock_id() == model.next_id`, non-decreasing across ops; every issued id `< next_id`.
5. `∀ pending: get_timelock(id)` has `executed == false`, matching `amount/sender/unlock_time/expires_at`; `∀ issued ∉ pending: client.try_get_timelock(id).is_err()` and `!persistent().has(TimeLock(id))`.
6. `client.is_paused() == model.paused`; `client.multisig_config().threshold == model.threshold`, `.epoch == model.epoch`, signers set-equal.
7. `instance().all()` keys ⊆ the six instance keys (as in `test_instance_holds_only_config_keys`).

Authorization is intentionally outside the property (`mock_all_auths`); the deterministic `mock_auths(&[])` tests in §5.5 are mandatory and not redundant with it. Failing seeds persist to `impala-soroban/integration-test/proptest-regressions/invariants.txt` (proptest's default `SourceParallel` persistence); commit that file whenever a regression is found.

### 5.7 Snapshots

`Env::default()` tests rewrite `test_snapshots/tests/<test>.N.json` on every run. Delete the 7 existing orphans (`test_cancel_timelock_marks_executed`, `test_cancel_timelock_prevents_execution`, `test_schedule_unwrap_delay_too_short`, `test_schedule_unwrap_insufficient_balance`, `test_schedule_unwrap_returns_timelock_id`, `test_wrap_increases_balance_and_supply`, `test_wrap_multiple_times_accumulates`), plus those of deleted/renamed tests; commit the regenerated set in the last PR-A commit; §9.1's script enforces no orphans from then on. The proptest and the artifact gate use `capture_snapshot_at_drop: false` and write none.

---

## 6. `Cargo.toml`, lockfile, `deny.toml`

`impala-soroban/integration-test/Cargo.toml`:
```toml
version = "0.2.0"          # was 0.0.1; the release tag impala-soroban-v0.2.0 matches
[dev-dependencies]
soroban-sdk = { version = "23.5.3", features = ["testutils"] }
# std only: drops rusty-fork/tempfile/wait-timeout from the audited tree.
proptest = { version = "1.10", default-features = false, features = ["std"] }
```
Commit the regenerated `Cargo.lock` (CI cache key and `cargo audit`/`cargo-deny` read it; `--locked` builds require it).

New `impala-soroban/integration-test/deny.toml`: copy `impala-bridge/deny.toml` minus the `[[licenses.clarify]]` `ring` block (not in this tree). Run `cargo install --locked cargo-deny && cargo deny check advisories bans sources licenses` locally; if a permissive license in the soroban/proptest tree is missing from `allow` (candidates: `BSL-1.0`, `0BSD`, `Unlicense`), add it to `allow` — never add advisory ignores. `testnet-tests` is unchanged and keeps running without a config as today.

---

## 7. testnet-tests (`impala-soroban/testnet-tests/`)

`src/lib.rs`:
```rust
/// Deploy the WASM with constructor args (`ctor_args` are appended after `--`).
pub fn deploy_contract(source_identity: &str, ctor_args: &[&str]) -> TestResult<String> {
    // existing wasm-path check, then:
    let mut cmd_args = vec!["contract", "deploy", "--wasm", wasm, "--source", source_identity, "--network", "testnet"];
    if !ctor_args.is_empty() { cmd_args.push("--"); cmd_args.extend_from_slice(ctor_args); }
    let output = stellar_cmd(&cmd_args)?;
    assert_cmd_success(&output, "contract deploy");
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}
/// Deploy expecting the constructor to fail; returns stderr, Err if it succeeded.
pub fn deploy_contract_expect_fail(source_identity: &str, ctor_args: &[&str]) -> TestResult<String> { /* mirror of invoke_expect_fail */ }
```
Update the `deploy_usdc_sac` doc comment (lines 154-160): the self-issued SAC passes the constructor because the fixture passes its own issuer as `--usdc_issuer`; the pin is exercised by `test_deploy_rejects_issuer_mismatch`.

`tests/integration.rs`:
- `TestFixture::setup(test_name: &str, threshold: u32, min_lock_duration: u64) -> Self`: builds `signers_json`, then `deploy_contract(&deployer.name, &["--signers", &signers_json, "--threshold", &threshold.to_string(), "--min_threshold", "1", "--usdc_token", &usdc_sac_id, "--usdc_issuer", &issuer.public_key, "--min_lock_duration", &min_lock_duration.to_string()])`. Delete `TestFixture::initialize` (104-126); every `f.initialize(t, d)` call (174, 187, 205, 265, 321, 386) folds into `setup(name, t, d)`. Add `fn ctor_args(&self, threshold, min_lock) -> Vec<String>` helper reused by the negative tests, and `fn query_config(&self) -> String` (invoke `multisig_config`).
- Execute invocations (239-245, 299-305, 359-365) add `"--signers", &signers_json`.
- `test_deploy_and_initialize` → `test_deploy_with_constructor`: also asserts `usdc_token` == SAC id, `usdc_issuer` == issuer pk, `min_lock_duration`, `min_threshold`, and `multisig_config` output contains both signer keys.
- `test_initialize_rejects_non_usdc_token` → `test_deploy_rejects_non_usdc_token`: `deploy_contract_expect_fail` with the native SAC and the fixture issuer.
- New `test_deploy_rejects_issuer_mismatch`: generate + fund a second throwaway issuer, `deploy_usdc_sac(&issuer2)`, deploy with `--usdc_token <sac2> --usdc_issuer <issuer1.public_key>` → must fail.
- New `test_constructor_not_callable_after_deploy`: `invoke_expect_fail(id, deployer, "__constructor", &ctor_args)` must fail; then `multisig_config`, `usdc_token`, `usdc_issuer` equal their pre-invoke values.
- New `test_over_schedule_rejected`: wrap 2_000_000; schedule 1_500_000 (ok); schedule 1_500_000 again → `invoke_expect_fail`; `balance` unchanged, `reserved` == 1_500_000, `available` == 500_000.
- New `test_execute_after_rotation`: schedule with signer1; `rotate_signers --current_signers ["s1"] --new_signers ["s2"] --new_threshold 1`; wait; `execute_unwrap --signers ["s1"]` fails; `execute_unwrap --signers ["s2"]` (source signer2) succeeds; balances assert.
- Every failure assertion (370, 407, 439 and the new ones): `println!("stderr: {err}"); assert!(err.contains("Error("), "expected a host error, got: {err}");` **plus explicit state assertions** (balance/reserved/total unchanged). Panic strings never reach the chain (`panic = "abort"`, symbols stripped), so string matches would be dishonest; constructor failures surface as `Error(Context, InvalidAction)` per `lifecycle.rs:87-100` — record the observed line on the first run and tighten to that literal if stable.
- Keep the amount-unit self-check.

---

## 8. CI (`.github/workflows/impala-soroban.yml`) — PR-B

8.1 Triggers: add under `on.push`: `tags: ['impala-soroban-v*']` (path filters do not apply to tag pushes). Workflow-level `env: STELLAR_CLI_VERSION: '<pin>'` — pin the newest 23.x `stellar-cli` release on crates.io at implementation time; the first successful manual constructor deploy confirms or bumps it and the same value is recorded in the manifest.

8.2 `contract` job — replace the build/upload tail with:
```yaml
      - name: Build contract WASM
        run: cargo build --release --locked --target wasm32-unknown-unknown
      - name: WASM sha256 (== on-chain ContractCode hash) + build info
        env: { W: target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm }
        run: |
          set -euo pipefail
          sha256sum "$W" | tee "$W.sha256"
          SDK=$(cargo metadata --format-version 1 --locked | jq -r '.packages[]|select(.name=="soroban-sdk")|.version' | sort -u | paste -sd,)
          HOST=$(cargo metadata --format-version 1 --locked | jq -r '.packages[]|select(.name=="soroban-env-host")|.version' | sort -u | paste -sd,)
          jq -n --arg sha "$(cut -d' ' -f1 "$W.sha256")" --arg size "$(stat -c%s "$W")" \
                --arg git "$GITHUB_SHA" --arg ref "$GITHUB_REF_NAME" --arg rustc "$(rustc -V)" \
                --arg sdk "$SDK" --arg host "$HOST" --arg lock "$(sha256sum Cargo.lock | cut -d' ' -f1)" \
                --arg run "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
                '{schema_version:1, artifact:"soroban_impala_integration_test.wasm", wasm_sha256:$sha,
                  wasm_size_bytes:($size|tonumber), git_sha:$git, git_ref:$ref, rustc:$rustc,
                  soroban_sdk:$sdk, soroban_env_host:$host, target:"wasm32-unknown-unknown",
                  cargo_lock_sha256:$lock, ci_run:$run}' | tee build-info.json
          { echo '### soroban_impala_integration_test.wasm'; echo '```'; cat "$W.sha256"; cat build-info.json; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
      - name: Artifact gate (release WASM in the pinned host)
        run: IMPALA_WASM=$PWD/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm cargo test test_wasm_artifact_loads_in_pinned_host -- --ignored
      - name: Property tests (deep)
        run: PROPTEST_CASES=512 cargo test invariants
      - name: Snapshot orphan check
        run: ../scripts/check-snapshots.sh
      - name: Validate deployment manifests
        run: ../scripts/check-manifests.sh
      - name: Upload WASM artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: soroban-impala-integration-test-wasm-${{ github.sha }}
          path: |
            impala-soroban/integration-test/target/wasm32-unknown-unknown/release/*.wasm
            impala-soroban/integration-test/target/wasm32-unknown-unknown/release/*.wasm.sha256
            impala-soroban/integration-test/build-info.json
          if-no-files-found: error
          retention-days: ${{ startsWith(github.ref, 'refs/tags/') && 90 || 30 }}
```
Also: fix the stale comment at lines 74-75 and add `cargo audit` for `testnet-tests` (`working-directory: impala-soroban/testnet-tests`); add a `cargo deny`-equivalent is already in `security.yml`.

8.3 `testnet-tests` job: `cargo install --locked stellar-cli --version "$STELLAR_CLI_VERSION"` then `stellar --version | tee /dev/stderr | grep -F "$STELLAR_CLI_VERSION"`; build with `--locked`; stays `workflow_dispatch`-only.

8.4 New `release` job (mirrors `impala-card.yml:348-424`): `needs: contract`, `if: startsWith(github.ref, 'refs/tags/impala-soroban-v')`, `permissions: contents: write`; checkout; toolchain 1.96.0 + target; `cargo build --release --locked --target wasm32-unknown-unknown`; `sha256sum` → `dist/SHA256SUMS`; **non-gating reproducibility check** (`continue-on-error: true` until it has passed on a tag, then remove the flag):
```yaml
      - name: Reproducibility (Docker double build, non-gating)
        continue-on-error: true
        run: |
          docker run --rm --platform linux/amd64 -e CARGO_TARGET_DIR=/tmp/target \
            -v "$PWD":/src -w /src/impala-soroban/integration-test rust:1.96.0-bookworm \
            sh -c 'rustup target add wasm32-unknown-unknown && cargo build --release --locked --target wasm32-unknown-unknown && sha256sum /tmp/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm' \
            | tee docker.sha256
          diff <(cut -d" " -f1 docker.sha256) <(cut -d" " -f1 target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm.sha256)
```
then `softprops/action-gh-release@b4309332981a82ec1c5618f44dd2e27cc8bfbfda # v3.0.0` with `files: impala-soroban/integration-test/dist/{soroban_impala_integration_test-<VERSION>.wasm, *.sha256, build-info.json, SHA256SUMS}`, `fail_on_unmatched_files: true`, `generate_release_notes: true`. Soroban's on-chain wasm hash is `sha256(wasm)`, so the release hash is directly comparable with `stellar contract fetch`.

8.5 New `keepalive-verify` job — `workflow_dispatch` only (a `schedule:` block is added **commented out** with the note below): needs `stellar-cli` (pinned) and a new repository secret `STELLAR_TESTNET_KEEPER_SECRET` — a throwaway testnet key that only holds XLM for fees; it is **never** a contract signer, never the deployer, and the only calls it makes are the permissionless `bump_ttl` / `bump_entry_ttl` plus read-only verification, so it cannot move wrapper funds. This is a new secret surface (the `impala-card.yml` header keeps signing keys out of CI for the same reason) and stays manual until the owner creates it. Steps: read the single `active` testnet manifest; `stellar keys add keeper --secret-key …` from the secret (env var, never argv-echoed); `stellar contract invoke --id $CID --source keeper --network testnet -- bump_ttl`; `… -- bump_entry_ttl --addresses '<evaluator_accounts json>' --timelock_ids '[]'`; `scripts/verify-deployment.sh deployments/testnet/$CID.json --source keeper`.

8.6 `.github/workflows/ci.yml` (terraform job, before `Terraform Plan`): when `TF_VAR_testnet_soroban_contract_id` is non-empty, assert it equals `jq -r '.contract_id' impala-soroban/deployments/testnet/*.json | (exactly the one whose status == active)`; fail on mismatch; skip with a notice when the secret is empty.

---

## 9. Scripts — `impala-soroban/scripts/` (new directory; all `#!/usr/bin/env bash`, `set -euo pipefail`)

9.1 `check-snapshots.sh [--delete]` — for every `integration-test/test_snapshots/tests/*.json`, strip any `.N.json` suffix (`sed -E 's/\.[0-9]+\.json$//'`) and require `grep -qE "fn ${name}\(" integration-test/src/*.rs`; list orphans; exit 1 if any (with `--delete`, remove them and exit 0).

9.2 `check-manifests.sh` — `jq`-based, over `deployments/{testnet,public}/*.json`: required keys (§10 schema); `network` ∈ {testnet, public} and equals the directory; `contract_id` matches `^C[A-Z2-7]{55}$`; `wasm_sha256`, `deploy.tx_hash`, `deploy.upload_tx_hash` are 64 hex; `usdc.issuer`, `deploy.deployer`, every `governance.signers[]`, every `evaluator_accounts[]` match `^G[A-Z2-7]{55}$`; `usdc.expected_name == "USDC:" + usdc.issuer`; `status` ∈ {active, retired} and **exactly one** `active` per network directory; `governance.threshold >= governance.min_threshold >= 1`; `policy.*` are positive integers with `ttl_threshold_ledgers <= ttl_extend_to_ledgers`; **issuer policy**: `public` ⇒ `usdc.issuer == GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`, `usdc.self_issued == false`, `min_threshold >= 2`, `threshold >= 2`; `testnet` ⇒ `usdc.issuer == GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` unless `usdc.self_issued == true`. Exit 1 on any violation, printing file + rule.

9.3 `verify-deployment.sh <manifest.json> [--source <identity>]` — needs `stellar`, `jq`, `sha256sum`; exit 0 verified / 1 mismatch or RPC error / 2 usage. Fail closed on any step:
1. Load the manifest; `NET=$(jq -r .network)`, `CID=$(jq -r .contract_id)`.
2. Issuer policy exactly as 9.2 (public refuses non-Circle issuers outright).
3. `stellar contract fetch --id "$CID" --network "$NET" --out-file "$TMP/onchain.wasm"`; `sha256sum` must equal `wasm_sha256`.
4. `stellar contract id asset --asset "USDC:$ISSUER" --network "$NET"` must equal `usdc.sac_contract_id`.
5. Read fns via `stellar contract invoke --id "$CID" --network "$NET" --source "$SRC" -- <fn>` (simulation only): `usdc_token` == `usdc.sac_contract_id`; `usdc_issuer` == `usdc.issuer`; `min_threshold`, `min_lock_duration` equal the manifest; `multisig_config` → signers set-equal and threshold equal (print `epoch` so rotations are visible); `max_entry_ttl` printed and compared with `policy.network_max_entry_ttl_at_deploy` (warn, not fail, on drift).
6. Invoke the SAC's `name` (`stellar contract invoke --id <sac> … -- name`) == `usdc.expected_name`.
7. `stellar tx fetch --hash <deploy.tx_hash> --network $NET` (or Horizon `/transactions/<hash>`) exists and succeeded (warn-only if the CLI subcommand is unavailable in the pinned version).
8. Print an expected/actual table per field.
CLI output formats (quotes around strings, JSON for structs) are confirmed on the first manual run; the script strips surrounding quotes and parses `multisig_config` with `jq`.

---

## 10. Deployment manifests — `impala-soroban/deployments/`

`deployments/README.md` documents: one file per instance at `<network>/<contract_id>.json`; append-only — **retire, never delete**; exactly one `active` per network; public entries require `threshold >= 2`, `min_threshold >= 2`, Circle's pubnet issuer, `self_issued: false`; the schema below; how `scripts/check-manifests.sh` and `scripts/verify-deployment.sh` use it; that `terraform/variables.tf:238` (`testnet_soroban_contract_id`) must equal the active testnet entry (CI-checked); that no secret ever belongs here (public identifiers only).

Schema (`schema_version: 1`):
```json
{
  "schema_version": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "contract_id": "C…",
  "wasm_sha256": "<64 hex == on-chain ContractCode hash == stellar contract upload output == deploy --wasm-hash>",
  "wasm_artifact": "soroban_impala_integration_test.wasm",
  "source": { "git_sha": "<40 hex>", "git_tag": "impala-soroban-v0.2.0", "rust_toolchain": "1.96.0",
              "target": "wasm32-unknown-unknown", "soroban_sdk": "23.5.3", "soroban_env_host": "23.0.1",
              "cargo_lock_sha256": "<64 hex>", "ci_run": "https://github.com/…/actions/runs/…" },
  "usdc": { "sac_contract_id": "C…", "issuer": "G…", "expected_name": "USDC:G…", "self_issued": false },
  "governance": { "signers": ["G…"], "threshold": 2, "min_threshold": 2, "min_lock_duration_seconds": 86400 },
  "policy": { "max_lock_duration_seconds": 7776000, "execution_window_seconds": 2592000,
              "ttl_threshold_ledgers": 518400, "ttl_extend_to_ledgers": 2764800,
              "instance_ttl_threshold_ledgers": 120960, "instance_ttl_extend_to_ledgers": 518400,
              "network_max_entry_ttl_at_deploy": 3110400 },
  "deploy": { "upload_tx_hash": "<64 hex>", "tx_hash": "<64 hex>", "ledger": 0, "deployer": "G…",
              "stellar_cli_version": "<stellar --version>", "deployed_at": "2026-09-05T00:00:00Z" },
  "evaluator_accounts": ["G…"],
  "status": "active",
  "retired": null
}
```
`retired` (when `status == "retired"`): `{ "reason": "…", "superseded_by": "C…|null", "retired_at": "…" }`. PR-B adds a `retired` manifest for the terraform-only testnet id (reason: `pre-constructor ABI; instance storage; no issuer pin`) — its id comes from the CI secret (open question) — and the first `active` testnet manifest from the fresh deploy.

---

## 11. Docs (verbatim where load-bearing)

11.1 **Root `README.md:102-107`** → replace with:
```
### Token Wrapping via Smart Contract

1. Authorized signers call `wrap(signers, depositor, amount)` → USDC moves from the depositor to the contract and the depositor's wrapped balance is credited
2. Signers call `schedule_unwrap(signers, recipient, amount, delay)` → the amount is reserved from the recipient's available balance and a timelock is created with `unlock_time = now + delay` and `expires_at = unlock_time + 30 days`
3. After the delay, the *current* signer quorum calls `execute_unwrap(signers, timelock_id)` within the 30-day window → USDC transfers to the recipient
4. During the delay any current quorum may call `cancel_timelock(signers, timelock_id)`; after the window anyone may call `expire_timelock(timelock_id)` — both release the reservation and leave the tokens wrapped
```

11.2 **`ARCHITECTURE.md:34-43` Use Case 2** → replace steps 1-6 with:
```
1. Two of three authorized signers call `schedule_unwrap(signers, recipient, amount, 86400)`
2. The contract verifies the 2-of-3 quorum, reserves `amount` from the recipient's available balance, and records `unlock_time = now + 24h` and `expires_at = unlock_time + 30 days`
3. During the 24-hour veto window any current quorum may call `cancel_timelock`, which releases the reservation
4. After 24 hours (and before `expires_at`) a current quorum calls `execute_unwrap(signers, timelock_id)` — USDC transfers to the recipient
5. If nobody executes within the window, anyone may call `expire_timelock(timelock_id)` to release the reservation
The bridge does not observe or drive this contract (`SOROBAN_CONTRACT_ID` is only echoed by `GET /network`); event monitoring is a separate, unimplemented integration.
```

11.3 **`ARCHITECTURE.md:413-460`**: intro sentence now says the SAC address *and Circle's issuer* are constructor arguments and the issuer is pinned on-chain via `name()`; state diagram:
```mermaid
stateDiagram-v2
    [*] --> Initialized : deploy(__constructor(signers, threshold, min_threshold, usdc_token, usdc_issuer, min_lock_duration))
    state Initialized { [*] --> Active
        Active --> Paused : pause(signers)
        Paused --> Active : unpause(signers) }
    Active --> Wrapped : wrap(signers, depositor, amount) [immediate]
    Wrapped --> UnwrapScheduled : schedule_unwrap(signers, recipient, amount, delay) [reserves]
    UnwrapScheduled --> Unwrapped : execute_unwrap(signers, timelock_id) [unlock_time <= now < expires_at, current quorum]
    UnwrapScheduled --> Wrapped : cancel_timelock(signers, timelock_id) [releases]
    UnwrapScheduled --> Wrapped : expire_timelock(timelock_id) [now >= expires_at, anyone]
    Wrapped --> TransferScheduled : schedule_transfer(signers, from, to, amount, delay) [reserves]
    TransferScheduled --> Wrapped : execute_transfer(signers, timelock_id) [window, current quorum]
    TransferScheduled --> Wrapped : cancel_timelock(signers, timelock_id)
    TransferScheduled --> Wrapped : expire_timelock(timelock_id)
```
Rewrite "Initialization", "Token operations", "Governance", "Read-only", "Constraints", "Events" from §4.7-4.9; replace "All storage is instance-level for ledger efficiency" with the §3 table and the archival sentence; insert the §4.1 "Execution model" paragraph verbatim; add the honest conservation sentence.

11.4 **`impala-soroban/README.md`**: line 3 → "Soroban smart contract holding USDC under multisig control with time-locked, reservation-backed withdrawals and transfers" (drop "bulk payments, offline escrow"); line 28 → "Rust 1.91+" (matches `rust-version`); build commands gain `--locked`; new "Deploy" section with the constructor command (§11.7 step 4); line 57 rewritten (issuer IS verified on-chain; the fixture passes its own issuer; `test_deploy_rejects_issuer_mismatch`); test table updated (renamed + new testnet tests); "USDC per network" keeps the `stellar contract id asset` lines and says the issuer is a constructor argument checked against the SAC's `name()`; delete "Deferred hardening" and "Over-scheduling"; new sections **Construction**, **Issuer pin** (what the contract verifies vs what the manifest/verify script verifies), **Reservation** (incl. the `>=` on-chain honesty sentence and the `sweep_surplus` follow-up), **Execution model** (§4.1 paragraph verbatim), **Storage & TTL** (§3 table, constants, archived ≠ lost: "a `balance()` call that fails with a storage error for a known holder means the entry is archived — restore it with `RestoreFootprint`, funds are intact", `bump_entry_ttl`), Operations table rewritten from §4.8, Events (+`expire`, pinned by `test_event_abi_pins`), **Releases & deployments** (manifest dir, `check-manifests.sh`, `verify-deployment.sh`, runbook, tag scheme, CI sha256), Dependencies (`proptest` dev-only; "All storage uses instance()" sentence replaced; the §11.9 SDK paragraph verbatim).

11.5 **`DEVELOPMENT.md:52-57`**:
```bash
cd impala-soroban/integration-test
cargo build --release --locked --target wasm32-unknown-unknown   # WASM artifact (target flag required)
cargo test                                                       # in-process, incl. a 64-case property test
PROPTEST_CASES=512 cargo test invariants                         # CI depth for the state-machine test
IMPALA_WASM=$PWD/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm \
  cargo test test_wasm_artifact_loads_in_pinned_host -- --ignored   # release artifact in the pinned host
../scripts/check-snapshots.sh                                    # test_snapshots/ must have no orphans
cd ../testnet-tests && cargo test                                # end-to-end; needs the pinned stellar-cli + network
```
and the prerequisites row: `stellar-cli` "pinned in `.github/workflows/impala-soroban.yml` (`STELLAR_CLI_VERSION`)".

11.6 **`CHANGELOG.md` [Unreleased]** — Added: `__constructor` (atomic construction; `initialize` removed), on-chain issuer pin via SAC `name()`, reserved-balance accounting (`reserved`/`available`), execution window + `expire_timelock`, `min_threshold` floor + `epoch`, `bump_entry_ttl`, read fns, `"Wrong operation type"` guard, proptest state machine, adversarial re-initialization tests, event-ABI pin, artifact gate, CI wasm sha256 + build-info, deployment manifests + verifier + runbook, tag release `impala-soroban-v*`. Changed: `execute_*` take `signers` and verify the current quorum; `Balance/Reserved/TimeLock` persistent with a 30 d/160 d policy; `MAX_LOCK_DURATION` 365 d → 90 d; panic strings (`Insufficient available balance`, `Timelock not matured`, `Timelock expired`); `TimeLock`/`WrappedUsdc`/`MultisigConfig` gain trailing fields; crate version 0.2.0. Removed: `initialize`, `DataKey::Initialized`. Note: "fresh deployment required; no recorded instance existed".

11.7 **`docs/runbooks/deploy-soroban.md`** (new; row in `docs/runbooks/README.md`: "Deploy, verify or retire the Soroban USDC wrapper"): Audience/Prerequisites (pinned toolchain 1.96.0, `wasm32-unknown-unknown`, pinned `stellar-cli`, `jq`); 1. checkout the tag, `cargo build --release --locked --target wasm32-unknown-unknown`, `sha256sum` == CI summary / release `SHA256SUMS`; 2. resolve `SAC=$(stellar contract id asset --asset USDC:<issuer> --network <net>)` (Circle issuers listed; testnet self-issued only for e2e); 3. dual-control signer ceremony (public: `threshold >= 2`, `min_threshold >= 2`); 4. deploy in two steps so the hash is literally the deploy parameter:
```bash
stellar contract upload --wasm target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm --source <deployer> --network <net>   # prints the wasm hash == sha256sum
stellar contract deploy --wasm-hash <hash> --source <deployer> --network <net> -- \
  --signers '["G_SIGNER_1","G_SIGNER_2","G_SIGNER_3"]' --threshold 2 --min_threshold 2 \
  --usdc_token "$SAC" --usdc_issuer <G_CIRCLE_ISSUER> --min_lock_duration 86400
```
(**moves no money but is irreversible**: the instance's config is fixed for life); 5. `stellar contract invoke … -- max_entry_ttl` → record; 6. write the manifest, `scripts/check-manifests.sh`, `scripts/verify-deployment.sh <manifest>`; 7. PR + tag `impala-soroban-vX.Y.Z`; 8. update `TF_VAR_testnet_soroban_contract_id` / `SOROBAN_CONTRACT_ID`; Day-2: `bump_ttl`/`bump_entry_ttl` cadence (any holder or timelock untouched for ~5 months), `stellar contract restore` for an archived entry, rotation (floor), incident pause, expiring dead timelocks; **Retirement** of an instance holding value: `pause` → cancel/execute/expire every pending op → unwrap every holder (**moves real money**) → mark `retired` with `superseded_by`. Record the stellar-cli version and the observed CLI argument syntax on the first execution.

11.8 `terraform/terraform.tfvars.example:113`: comment "must equal the `active` entry in `impala-soroban/deployments/testnet/` (CI-checked)".

11.9 **SDK-26 / `wasm32v1-none` migration assessment** (verbatim for README "Dependencies" and the runbook):
> The contract is pinned to soroban-sdk 23.5.3 (env-host 23.0.1) and builds for `wasm32-unknown-unknown` on rustc 1.96.0. soroban-sdk 26's `build.rs` rejects `wasm32-unknown-unknown` on rustc ≥ 1.82 and requires `wasm32v1-none` (`integration-test/Cargo.toml` pin comment, 2026-06-09). The reason is not cosmetic: on rustc ≥ 1.82 the `wasm32-unknown-unknown` target enables post-MVP WebAssembly features by default, which the Soroban VM rejects if they appear in the binary; `wasm32v1-none` is the MVP-only target. Our toolchain is in that range, so the release artifact must be proven loadable in the pinned host — the CI artifact gate (`test_wasm_artifact_loads_in_pinned_host`) does exactly that and is the acceptance check for the current pin. Staying on 23.x for this hardening is a maintenance decision, not a correctness one: a WASM built against SDK 23 declares protocol 23 in its meta and is accepted by any network at protocol ≥ 23, the code paths used here (storage, token client, auth, events via the deprecated `publish`, constructors, SAC `name()`) are stable, and `cargo audit`/`cargo-deny` run on every push. What the pin costs: unit tests simulate protocol-23 host semantics; newer host functions and `#[contractevent]` are unavailable; transitive dependencies age. Migration is a bounded, mechanical, separate PR after this hardening lands and **before any mainnet (T3) deployment**: `rustup target add wasm32v1-none`; `targets: wasm32v1-none` in `impala-soroban.yml` (both jobs; the `security.yml` cargo-deny job installs no target and needs no change); `soroban-sdk = "26.x"`; the artifact path in `testnet-tests/src/lib.rs:65-69`, README and DEVELOPMENT build lines; keep `#![allow(deprecated)]` so the event ABI stays byte-identical (`test_event_abi_pins` is the gate); regenerate `test_snapshots/`; run the property suite, the artifact gate and the testnet e2e; the WASM hash changes, so a new manifest entry and tag are mandatory — never re-point an existing manifest. Until then the manifest's `source.soroban_sdk` field is the compatibility statement of record.

11.10 **`CLAUDE.md`** — under "Architecture", add: "**impala-soroban:** state is created only by `__constructor` (no `initialize`; the host refuses `__` calls); the USDC SAC is pinned by `(symbol, decimals, name() == "USDC:<issuer>")` with the issuer a constructor argument; scheduling reserves (`available = balance − reserved`); execution needs the *current* quorum within `[unlock_time, expires_at)`; `min_threshold` is immutable; event topics, crate and artifact names are frozen (pinned by `test_event_abi_pins`); on-chain `SAC.balance(contract) >= total_wrapped`; deployments are recorded in `impala-soroban/deployments/` and verified by `scripts/verify-deployment.sh`. Tests: `cargo test` (incl. proptest), `PROPTEST_CASES=512 cargo test invariants`, `scripts/check-snapshots.sh`." Update the Others block line 48 accordingly.

---

## 12. Execution model — rejected alternatives (for README/ARCHITECTURE "Design notes")

(a) *Permissionless execute after maturity* — one ceremony moves value; a compromised quorum's scheduled withdrawal executes unless a cancel quorum is mustered in time; rotation cannot revoke it; the no-mock execute tests would be meaningless. (b) *Status quo: re-auth by every stored signer* — strands ops on any rotation removing a stored signer, requires all stored signers not a quorum, former signers keep authority. (c) *Threshold subset of stored signers* — still lets a rotated-out set execute; still strands. (d) *Epoch gate (execute requires `config_epoch == current`)* — B already revokes rotated-out sets; the gate would kill every legitimate pending op on routine rotation; kept as audit metadata only. (e) *Timelocked rotation* — a compromised quorum can already drain via schedule+execute within the same delay, so it adds a ceremony without changing the attacker's bound; deferred follow-up. (f) *Majority floor `2·threshold ≥ n`* — admits 1-of-1 and 1-of-2 from any configuration while forbidding legitimate 1-of-3; replaced by the immutable `min_threshold`. (g) *Configurable execution window* — more knobs, no security gain; constant 30 d. (h) *`#[contracterror]` typed errors* — better on-chain diagnosability (release WASM strips panic strings) but touches every panic site; separate PR.

---

## 13. Delivery and acceptance

**PR-A** (one reviewable commit per step; each green on `cargo fmt -- --check && cargo clippy --all-targets -- -D warnings && cargo test`):
1. Fixture rewrite (`Fx`, `seed` via quorum wrap, `assert_conserved`), `MockUsdc.name`, `create_usdc_token(env, issuer)`; existing tests still pass against the old contract except the storage-class asserts (do them in step 3).
2. `__constructor` + issuer pin + `MinThreshold` + `Initialized` removal + real-SAC helper + constructor/adversarial tests + `Cargo.toml` version + `deny.toml`.
3. Persistent storage + TTL policy + `touch_account` + `bump_entry_ttl` + constructor TTL gate + storage/TTL tests.
4. Reserved accounting + `expire_timelock` + window fields + `execute_*(signers, …)` + `"Wrong operation type"` + epoch + rotation floor + read fns + reservation/execution/auth tests + event pin.
5. `invariants.rs` + `proptest` dev-dep + `Cargo.lock` + artifact gate test; regenerate snapshots, delete orphans.
6. testnet-tests + docs (README/ARCHITECTURE/root README/DEVELOPMENT/CHANGELOG/CLAUDE.md).

**PR-B**: CI (§8), scripts (§9), `deployments/` + README (§10), runbook (§11.7), terraform comment + CI equality step; fresh testnet deploy through the runbook; first `active` manifest + `retired` manifest for the old id; tag `impala-soroban-v0.2.0`.

**Acceptance checks**
```bash
cd impala-soroban/integration-test
cargo fmt -- --check && cargo clippy --all-targets -- -D warnings
cargo test                                   # ≈ 55 − 1 + ~60 new + invariants::state_machine (64 cases)
PROPTEST_CASES=512 cargo test invariants
cargo build --release --locked --target wasm32-unknown-unknown
IMPALA_WASM=$PWD/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm cargo test test_wasm_artifact_loads_in_pinned_host -- --ignored
sha256sum target/wasm32-unknown-unknown/release/*.wasm
cargo deny check advisories bans sources licenses        # after cargo install --locked cargo-deny
../scripts/check-snapshots.sh && ../scripts/check-manifests.sh
grep -c "pub fn initialize(" src/lib.rs                  # must print 0
cd ../testnet-tests && cargo test                        # manual; pinned stellar-cli; deploys via constructor
../scripts/verify-deployment.sh ../deployments/testnet/<C…>.json
```
Mechanical invariants a reviewer checks: no `env.storage().instance()` access to `Balance/Reserved/TimeLock` remains (`grep -n "instance()" src/lib.rs` shows only config/supply/id/flags); every `write_*` extends; every entry point that reads a holder calls `read_holder`; the nine existing event tuples are unchanged in the diff; `DataKey::Initialized` and `"Already initialized"` do not appear; the three structs only gained trailing fields.

**Risks / follow-ups recorded in README "Known limitations"**: live-network `max_entry_ttl` and stellar-cli syntax are confirmed on the first manual run (fail closed if lower than policy — would block deployment, which is the correct outcome); on-chain conservation is `>=` until `sweep_surplus` exists; the keep-alive job is manual until a keeper secret exists; reproducibility check is advisory until it passes on a tag.