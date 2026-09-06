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

/// Configuration for the multisig signer set.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigConfig {
    /// Authorized signer addresses.
    pub signers: Vec<Address>,
    /// Minimum number of signers required to authorize an operation.
    pub threshold: u32,
    /// Incremented by every `rotate_signers`; 0 at construction. Audit only.
    pub epoch: u32,
}

/// Tracks the underlying USDC token and total amount wrapped by the contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedUsdc {
    /// Address of the USDC Stellar Asset Contract on this network.
    pub usdc_token: Address,
    /// Decimals of the USDC token (validated to be 7 at construction).
    pub decimals: u32,
    /// Total amount of wrapped USDC across all balances (in stroops).
    pub total_wrapped: i128,
    /// Issuer pinned at construction via the SAC's `name()`.
    pub usdc_issuer: Address,
}

/// A pending time-locked operation, executable within
/// `[unlock_time, expires_at)` by the *current* signer quorum.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeLock {
    /// Operation type: 1 = unwrap, 2 = transfer.
    pub operation_type: u32,
    /// AUDIT ONLY: the quorum that approved scheduling. Never consulted for
    /// authorization — execution and cancellation verify the current config.
    pub signers: Vec<Address>,
    /// Holder debited by the operation (for unwraps this equals `recipient`).
    pub sender: Address,
    /// Recipient of the operation's output.
    pub recipient: Address,
    /// Token amount involved in the operation (stroops).
    pub amount: i128,
    /// Ledger timestamp (seconds) at or after which the operation can execute.
    pub unlock_time: u64,
    /// In-flight marker set just before the execute path performs balance
    /// updates / external calls (the host also prohibits reentry). Entries
    /// are removed once executed, cancelled or expired, so stored pending
    /// timelocks are always `false` outside that window.
    pub executed: bool,
    /// `unlock_time + EXECUTION_WINDOW`; execution requires `now < expires_at`.
    pub expires_at: u64,
    /// Ledger timestamp at schedule time (audit).
    pub scheduled_at: u64,
    /// `MultisigConfig.epoch` at schedule time (audit; NOT an auth gate).
    pub config_epoch: u32,
}

/// Storage keys for contract state. Variants are encoded by *name*, so
/// removing or appending a variant never renumbers the others.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Instance: `MultisigConfig`.
    MultisigConfig,
    /// Instance: `WrappedUsdc`.
    WrappedUsdc,
    /// Persistent: per-holder wrapped balance (`i128`; absent = 0).
    Balance(Address),
    /// Persistent: time-locked operation, keyed by sequential id.
    TimeLock(u64),
    /// Instance: next timelock id (monotone, starts at 0).
    NextTimeLockId,
    /// Instance: minimum schedule delay in seconds.
    MinLockDuration,
    /// Instance: whether the contract is paused (absent = false).
    Paused,
    /// Persistent: per-holder reserved amount (`i128`; absent = 0; removed
    /// when it returns to 0).
    Reserved(Address),
    /// Instance: immutable lower bound for `threshold` (`u32`).
    MinThreshold,
}

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
/// Maximum size of the authorized signer set (multisig verification is
/// O(provided x configured), so keep the set small and bounded).
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
const _: () =
    assert!(MAX_LOCK_DURATION + EXECUTION_WINDOW <= (PERSISTENT_TTL_EXTEND_TO as u64) * 4);

#[contract]
pub struct MultisigUsdcWrapper;

// soroban-sdk 23 deprecates Events::publish in favor of #[contractevent]
// structs. Migrating changes the emitted event encoding, and the current
// topics (wrap, sched_unw, exec_tx, ...) are load-bearing for downstream
// consumers, so the migration is deliberately deferred.
#[allow(deprecated)]
#[contractimpl]
impl MultisigUsdcWrapper {
    /// Atomic with deployment. There is no post-deploy initialization entry point.
    /// No `require_auth`: the deploy transaction is the authorization.
    ///
    /// Validation order is cheapest-first and no state is written before every
    /// check passes; a panic aborts the deploy, so no instance exists.
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
        // A duplicated signer in the config could make the threshold
        // unsatisfiable (verify_multisig rejects duplicate provided signers),
        // bricking the contract. Reject at configuration time.
        Self::require_no_duplicates(&signers);
        if min_threshold == 0 || min_threshold > signers.len() {
            panic!("Invalid min threshold");
        }
        if threshold < min_threshold || threshold > signers.len() {
            panic!("Invalid threshold");
        }
        // A minimum above the maximum would make every schedule call panic.
        if min_lock_duration > MAX_LOCK_DURATION {
            panic!("Min lock duration exceeds maximum");
        }
        // Fail closed on a network whose max entry TTL is below the persistent
        // extend-to target: a pending operation could otherwise archive before
        // its execution window closes.
        if Self::ledger_max_entry_ttl(&env) < PERSISTENT_TTL_EXTEND_TO {
            panic!("Network max entry TTL below policy");
        }

        // Validate the token is the pinned USDC SAC before writing any state.
        let token_client = token::Client::new(&env, &usdc_token);
        if token_client.symbol() != String::from_str(&env, "USDC") {
            panic!("Underlying token is not USDC");
        }
        let decimals = token_client.decimals();
        if decimals != USDC_DECIMALS {
            panic!("USDC token must have 7 decimals");
        }
        // A SAC's name() is "<code>:<issuer G-strkey>", fixed by the host at SAC
        // creation. A contract-address issuer can never match (SAC names carry
        // a G strkey) and a look-alike USDC from another issuer fails here.
        let mut expected_name = Bytes::from_slice(&env, USDC_NAME_PREFIX);
        expected_name.append(&usdc_issuer.to_string().to_bytes());
        if token_client.name().to_bytes() != expected_name {
            panic!("Underlying token issuer mismatch");
        }

        env.storage().instance().set(
            &DataKey::MultisigConfig,
            &MultisigConfig {
                signers,
                threshold,
                epoch: 0,
            },
        );
        env.storage().instance().set(
            &DataKey::WrappedUsdc,
            &WrappedUsdc {
                usdc_token,
                decimals,
                total_wrapped: 0,
                usdc_issuer,
            },
        );
        env.storage()
            .instance()
            .set(&DataKey::MinLockDuration, &min_lock_duration);
        env.storage()
            .instance()
            .set(&DataKey::MinThreshold, &min_threshold);
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &0u64);
        Self::extend_instance_ttl(&env);
    }

    /// Extend the instance storage TTL — instance only. Permissionless: anyone
    /// may pay the rent to keep the configuration alive. Per-holder and
    /// per-timelock entries are bumped with `bump_entry_ttl`.
    pub fn bump_ttl(env: Env) {
        Self::extend_instance_ttl(&env);
    }

    /// Extend the TTL of the listed holders' `Balance`/`Reserved` entries and
    /// the listed timelocks (plus the instance). Permissionless and bounded
    /// (`MAX_BUMP_BATCH` keys per call). Missing keys are skipped; an archived
    /// key cannot be touched from inside a contract (the operator restores it
    /// first with `RestoreFootprint`). No events.
    pub fn bump_entry_ttl(env: Env, addresses: Vec<Address>, timelock_ids: Vec<u64>) {
        let total = addresses
            .len()
            .checked_add(timelock_ids.len())
            .expect("Bump batch overflow");
        if total > MAX_BUMP_BATCH {
            panic!("Bump batch too large");
        }
        Self::extend_instance_ttl(&env);
        for a in addresses.iter() {
            Self::touch_account(&env, &a);
        }
        for id in timelock_ids.iter() {
            Self::extend_entry_ttl_if_present(&env, &DataKey::TimeLock(id));
        }
    }

    /// Pause the contract (requires multisig). Blocks `wrap`, `schedule_*` and
    /// `execute_*`; cancel/expire/bump/rotate/unpause and reads keep working.
    pub fn pause(env: Env, signers: Vec<Address>) {
        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("pause"),), 0);
    }

    /// Unpause the contract (requires multisig).
    pub fn unpause(env: Env, signers: Vec<Address>) {
        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpause"),), 0);
    }

    /// Rotate the authorized signer set (requires the current multisig).
    ///
    /// Takes effect immediately and increments `epoch`. Pending operations
    /// survive and become executable/cancellable only by the new set. The new
    /// threshold can never go below the `min_threshold` fixed at construction.
    pub fn rotate_signers(
        env: Env,
        current_signers: Vec<Address>,
        new_signers: Vec<Address>,
        new_threshold: u32,
    ) {
        if new_signers.is_empty() {
            panic!("New signers must not be empty");
        }
        let min_threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::MinThreshold)
            .unwrap();
        if new_threshold < min_threshold || new_threshold > new_signers.len() {
            panic!("Invalid new threshold");
        }
        if new_signers.len() > MAX_SIGNERS {
            panic!("Too many signers");
        }
        // Same bricking hazard as in the constructor: a duplicated signer in
        // the new config could make the new threshold unsatisfiable.
        Self::require_no_duplicates(&new_signers);

        Self::verify_multisig(&env, &current_signers);
        Self::extend_instance_ttl(&env);

        let current: MultisigConfig = env
            .storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap();
        let epoch = current.epoch.checked_add(1).expect("Epoch overflow");
        env.storage().instance().set(
            &DataKey::MultisigConfig,
            &MultisigConfig {
                signers: new_signers,
                threshold: new_threshold,
                epoch,
            },
        );

        env.events()
            .publish((symbol_short!("rotate"),), new_threshold);
    }

    /// Wrap tokens (immediate execution, no timelock).
    ///
    /// `depositor` supplies the underlying tokens and is credited with the
    /// wrapped balance. It must authorize the call (for the token transfer)
    /// in addition to the multisig signer set, but does not need to be an
    /// authorized signer itself; a depositor who is one of the provided
    /// signers authorizes once, as a signer.
    pub fn wrap(env: Env, signers: Vec<Address>, depositor: Address, amount: i128) {
        Self::require_not_paused(&env);

        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);
        // Every provided signer already authorized this invocation inside
        // verify_multisig, and the host rejects a second require_auth for the
        // same address within one frame ("frame is already authorized"), so a
        // depositor who is also a provided signer is not asked twice. A
        // depositor outside the signer list must authorize here.
        if !signers.contains(&depositor) {
            depositor.require_auth();
        }
        Self::extend_instance_ttl(&env);

        let mut wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();

        let token_client = token::Client::new(&env, &wrapped_usdc.usdc_token);
        let contract_address = env.current_contract_address();
        token_client.transfer(&depositor, &contract_address, &amount);

        let (balance, _reserved) = Self::read_holder(&env, &depositor);
        let new_balance = balance.checked_add(amount).expect("Balance overflow");
        Self::write_balance(&env, &depositor, new_balance);

        wrapped_usdc.total_wrapped = wrapped_usdc
            .total_wrapped
            .checked_add(amount)
            .expect("Total supply overflow");
        env.storage()
            .instance()
            .set(&DataKey::WrappedUsdc, &wrapped_usdc);

        env.events()
            .publish((symbol_short!("wrap"), depositor), amount);
    }

    /// Schedule a time-locked unwrap. Reserves `amount` from the recipient's
    /// available balance; returns the timelock id.
    pub fn schedule_unwrap(
        env: Env,
        signers: Vec<Address>,
        recipient: Address,
        amount: i128,
        delay_seconds: u64,
    ) -> u64 {
        Self::require_not_paused(&env);

        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let (timelock_id, unlock_time) = Self::schedule(
            &env,
            1,
            signers,
            recipient.clone(),
            recipient.clone(),
            amount,
            delay_seconds,
        );

        env.events().publish(
            (symbol_short!("sched_unw"), recipient, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Schedule a time-locked transfer of wrapped balance from `from` to `to`.
    /// Reserves `amount` from `from`'s available balance; returns the id.
    pub fn schedule_transfer(
        env: Env,
        signers: Vec<Address>,
        from: Address,
        to: Address,
        amount: i128,
        delay_seconds: u64,
    ) -> u64 {
        Self::require_not_paused(&env);

        if amount <= 0 {
            panic!("Amount must be positive");
        }

        if from == to {
            panic!("Self-transfer not allowed");
        }

        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let (timelock_id, unlock_time) = Self::schedule(
            &env,
            2,
            signers,
            from.clone(),
            to.clone(),
            amount,
            delay_seconds,
        );

        env.events().publish(
            (symbol_short!("sched_tx"), from, to, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Execute a matured unwrap: consumes the reservation, burns the wrapped
    /// balance and transfers USDC to the recipient. Requires a quorum of the
    /// *current* signer set and `unlock_time <= now < expires_at`.
    pub fn execute_unwrap(env: Env, signers: Vec<Address>, timelock_id: u64) {
        Self::require_not_paused(&env);

        let mut timelock = Self::read_timelock(&env, timelock_id);
        if timelock.executed {
            panic!("Already executed");
        }
        if timelock.operation_type != 1 {
            panic!("Wrong operation type");
        }
        let now = env.ledger().timestamp();
        if now < timelock.unlock_time {
            panic!("Timelock not matured");
        }
        if now >= timelock.expires_at {
            panic!("Timelock expired");
        }

        // The CURRENT configuration authorizes execution, never the stored set.
        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let holder = timelock.sender.clone(); // == recipient for unwraps
        let (balance, reserved) = Self::read_holder(&env, &holder);
        if balance < timelock.amount {
            // Unreachable under the reservation invariant; kept as a guard.
            panic!("Insufficient balance");
        }

        // Mark in-flight BEFORE external calls (defense in depth; the host
        // also prohibits reentry).
        timelock.executed = true;
        Self::write_timelock(&env, timelock_id, &timelock);

        let new_reserved = reserved
            .checked_sub(timelock.amount)
            .expect("Reserved underflow");
        let new_balance = balance
            .checked_sub(timelock.amount)
            .expect("Balance underflow");
        Self::write_reserved(&env, &holder, new_reserved);
        Self::write_balance(&env, &holder, new_balance);

        let mut wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
        let token_client = token::Client::new(&env, &wrapped_usdc.usdc_token);
        token_client.transfer(
            &env.current_contract_address(),
            &timelock.recipient,
            &timelock.amount,
        );
        wrapped_usdc.total_wrapped = wrapped_usdc
            .total_wrapped
            .checked_sub(timelock.amount)
            .expect("Total supply underflow");
        env.storage()
            .instance()
            .set(&DataKey::WrappedUsdc, &wrapped_usdc);

        // Operation complete: prune the entry so replay attempts fail with
        // "Timelock not found" and the rent is reclaimed.
        Self::remove_timelock(&env, timelock_id);

        env.events().publish(
            (symbol_short!("exec_unw"), timelock.recipient, timelock_id),
            timelock.amount,
        );
    }

    /// Execute a matured transfer: consumes the sender's reservation and moves
    /// wrapped balance to the recipient. No token call; `total_wrapped` is
    /// unchanged. Requires a quorum of the *current* signer set and
    /// `unlock_time <= now < expires_at`.
    pub fn execute_transfer(env: Env, signers: Vec<Address>, timelock_id: u64) {
        Self::require_not_paused(&env);

        let mut timelock = Self::read_timelock(&env, timelock_id);
        if timelock.executed {
            panic!("Already executed");
        }
        if timelock.operation_type != 2 {
            panic!("Wrong operation type");
        }
        let now = env.ledger().timestamp();
        if now < timelock.unlock_time {
            panic!("Timelock not matured");
        }
        if now >= timelock.expires_at {
            panic!("Timelock expired");
        }

        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let (from_balance, from_reserved) = Self::read_holder(&env, &timelock.sender);
        let (to_balance, _to_reserved) = Self::read_holder(&env, &timelock.recipient);
        if from_balance < timelock.amount {
            // Unreachable under the reservation invariant; kept as a guard.
            panic!("Insufficient balance");
        }

        timelock.executed = true;
        Self::write_timelock(&env, timelock_id, &timelock);

        let new_from_reserved = from_reserved
            .checked_sub(timelock.amount)
            .expect("Reserved underflow");
        let new_from = from_balance
            .checked_sub(timelock.amount)
            .expect("Balance underflow");
        let new_to = to_balance
            .checked_add(timelock.amount)
            .expect("Balance overflow");
        Self::write_reserved(&env, &timelock.sender, new_from_reserved);
        Self::write_balance(&env, &timelock.sender, new_from);
        Self::write_balance(&env, &timelock.recipient, new_to);

        Self::remove_timelock(&env, timelock_id);

        env.events().publish(
            (
                symbol_short!("exec_tx"),
                timelock.sender,
                timelock.recipient,
                timelock_id,
            ),
            timelock.amount,
        );
    }

    /// Cancel a pending timelock (requires a quorum of the *current* signer
    /// set). Releases the reservation. Works while paused.
    pub fn cancel_timelock(env: Env, signers: Vec<Address>, timelock_id: u64) {
        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let timelock = Self::read_timelock(&env, timelock_id);

        // Defense in depth for the execute in-flight window.
        if timelock.executed {
            panic!("Already executed");
        }

        Self::release_reservation(&env, &timelock);
        Self::remove_timelock(&env, timelock_id);

        env.events()
            .publish((symbol_short!("cancel"), timelock_id), 0);
    }

    /// Release the reservation of a timelock whose execution window has
    /// closed (`now >= expires_at`). Permissionless: after the window the
    /// only lawful outcome is release, and it must not depend on quorum
    /// liveness. Works while paused.
    pub fn expire_timelock(env: Env, timelock_id: u64) {
        let timelock = Self::read_timelock(&env, timelock_id);
        if timelock.executed {
            panic!("Already executed");
        }
        if env.ledger().timestamp() < timelock.expires_at {
            panic!("Timelock not yet expired");
        }
        Self::extend_instance_ttl(&env);
        Self::release_reservation(&env, &timelock);
        Self::remove_timelock(&env, timelock_id);
        env.events()
            .publish((symbol_short!("expire"), timelock_id), 0);
    }

    // ------------------------------------------------------------------
    // Reads (never extend any TTL)
    // ------------------------------------------------------------------

    /// Get timelock details.
    pub fn get_timelock(env: Env, timelock_id: u64) -> TimeLock {
        Self::read_timelock(&env, timelock_id)
    }

    /// Wrapped balance of `address` (including any reserved part).
    pub fn balance(env: Env, address: Address) -> i128 {
        Self::read_balance(&env, &address)
    }

    /// Amount of `address`'s balance reserved by pending operations.
    pub fn reserved(env: Env, address: Address) -> i128 {
        Self::read_reserved(&env, &address)
    }

    /// `balance - reserved` for `address`.
    pub fn available(env: Env, address: Address) -> i128 {
        let (balance, reserved) = Self::read_holder(&env, &address);
        balance
            .checked_sub(reserved)
            .expect("Reserved invariant violated")
    }

    /// Total wrapped token supply across all addresses.
    pub fn total_supply(env: Env) -> i128 {
        let wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
        wrapped_usdc.total_wrapped
    }

    /// Address of the underlying USDC Stellar Asset Contract.
    pub fn usdc_token(env: Env) -> Address {
        let wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
        wrapped_usdc.usdc_token
    }

    /// Decimals of the underlying USDC token (always 7).
    pub fn usdc_decimals(env: Env) -> u32 {
        let wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
        wrapped_usdc.decimals
    }

    /// Issuer pinned at construction (the `G…` account in the SAC's `name()`).
    pub fn usdc_issuer(env: Env) -> Address {
        let wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
        wrapped_usdc.usdc_issuer
    }

    /// Current signer set, threshold and rotation epoch.
    pub fn multisig_config(env: Env) -> MultisigConfig {
        env.storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap()
    }

    /// Minimum schedule delay in seconds.
    pub fn min_lock_duration(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::MinLockDuration)
            .unwrap()
    }

    /// Immutable lower bound for the threshold (fixed at construction).
    pub fn min_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::MinThreshold)
            .unwrap()
    }

    /// Whether the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// The id the next scheduled operation will receive.
    pub fn next_timelock_id(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::NextTimeLockId)
            .unwrap()
    }

    /// The network's maximum entry TTL in ledgers (what the persistent TTL
    /// policy is clamped to on this network).
    pub fn max_entry_ttl(env: Env) -> u32 {
        Self::ledger_max_entry_ttl(&env)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Shared schedule path: delay bounds, reservation, timelock creation.
    /// Returns `(timelock_id, unlock_time)`.
    fn schedule(
        env: &Env,
        operation_type: u32,
        signers: Vec<Address>,
        sender: Address,
        recipient: Address,
        amount: i128,
        delay_seconds: u64,
    ) -> (u64, u64) {
        let min_duration: u64 = env
            .storage()
            .instance()
            .get(&DataKey::MinLockDuration)
            .unwrap();
        if delay_seconds < min_duration {
            panic!("Delay too short");
        }
        if delay_seconds > MAX_LOCK_DURATION {
            panic!("Delay exceeds maximum lock duration");
        }

        let (balance, reserved) = Self::read_holder(env, &sender);
        let available = balance
            .checked_sub(reserved)
            .expect("Reserved invariant violated");
        if available < amount {
            panic!("Insufficient available balance");
        }

        let timelock_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextTimeLockId)
            .unwrap();
        let now = env.ledger().timestamp();
        let unlock_time = now
            .checked_add(delay_seconds)
            .expect("Unlock time overflow");
        let expires_at = unlock_time
            .checked_add(EXECUTION_WINDOW)
            .expect("Expiry overflow");
        let config: MultisigConfig = env
            .storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap();

        let new_reserved = reserved.checked_add(amount).expect("Reserved overflow");
        Self::write_reserved(env, &sender, new_reserved);

        let timelock = TimeLock {
            operation_type,
            signers,
            sender,
            recipient,
            amount,
            unlock_time,
            executed: false,
            expires_at,
            scheduled_at: now,
            config_epoch: config.epoch,
        };
        Self::write_timelock(env, timelock_id, &timelock);

        let next_id = timelock_id.checked_add(1).expect("Timelock id overflow");
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &next_id);

        (timelock_id, unlock_time)
    }

    /// The network's maximum entry TTL in ledgers, derived from the ledger
    /// info (`max_live_until_ledger - sequence + 1`).
    fn ledger_max_entry_ttl(env: &Env) -> u32 {
        env.ledger()
            .max_live_until_ledger()
            .checked_sub(env.ledger().sequence())
            .expect("Ledger TTL underflow")
            .checked_add(1)
            .expect("Ledger TTL overflow")
    }

    fn read_balance(env: &Env, a: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(a.clone()))
            .unwrap_or(0)
    }

    fn read_reserved(env: &Env, a: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Reserved(a.clone()))
            .unwrap_or(0)
    }

    /// `(balance, reserved)` with the reservation invariant as a tripwire on
    /// every money path (a `checked_sub` alone cannot detect a violation).
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
            env.storage().persistent().extend_ttl(
                key,
                PERSISTENT_TTL_THRESHOLD,
                PERSISTENT_TTL_EXTEND_TO,
            );
        }
    }

    /// `Balance(a)` and `Reserved(a)` must age together.
    fn touch_account(env: &Env, a: &Address) {
        Self::extend_entry_ttl_if_present(env, &DataKey::Balance(a.clone()));
        Self::extend_entry_ttl_if_present(env, &DataKey::Reserved(a.clone()));
    }

    fn write_balance(env: &Env, a: &Address, v: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::Balance(a.clone()), &v);
        Self::touch_account(env, a);
    }

    fn write_reserved(env: &Env, a: &Address, v: i128) {
        if v == 0 {
            env.storage()
                .persistent()
                .remove(&DataKey::Reserved(a.clone()));
        } else {
            env.storage()
                .persistent()
                .set(&DataKey::Reserved(a.clone()), &v);
        }
        Self::touch_account(env, a);
    }

    fn read_timelock(env: &Env, id: u64) -> TimeLock {
        env.storage()
            .persistent()
            .get(&DataKey::TimeLock(id))
            .expect("Timelock not found")
    }

    fn write_timelock(env: &Env, id: u64, tl: &TimeLock) {
        let key = DataKey::TimeLock(id);
        env.storage().persistent().set(&key, tl);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
    }

    fn remove_timelock(env: &Env, id: u64) {
        env.storage().persistent().remove(&DataKey::TimeLock(id));
    }

    /// Releases a pending operation's reservation (cancel / expire).
    fn release_reservation(env: &Env, timelock: &TimeLock) {
        let (_balance, reserved) = Self::read_holder(env, &timelock.sender);
        let new_reserved = reserved
            .checked_sub(timelock.amount)
            .expect("Reserved underflow");
        Self::write_reserved(env, &timelock.sender, new_reserved);
    }

    /// Extend the instance TTL so the configuration does not expire while in
    /// active use.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Panics if the contract is currently paused.
    fn require_not_paused(env: &Env) {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            panic!("Contract is paused");
        }
    }

    /// Verify that at least `threshold` of the provided signers are in the
    /// authorized signer list and that each has called `require_auth()`.
    /// Panics if any provided signer is not authorized, the threshold is not met,
    /// or duplicate signers are provided.
    fn verify_multisig(env: &Env, provided_signers: &Vec<Address>) {
        let config: MultisigConfig = env
            .storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap();

        if provided_signers.len() < config.threshold {
            panic!("Insufficient signers");
        }

        Self::require_no_duplicates(provided_signers);

        for provided_signer in provided_signers.iter() {
            let mut is_authorized = false;
            for authorized_signer in config.signers.iter() {
                if provided_signer == authorized_signer {
                    is_authorized = true;
                    break;
                }
            }
            if !is_authorized {
                panic!("Signer not authorized");
            }
            provided_signer.require_auth();
        }
    }

    /// Panics if the given address list contains any duplicates.
    ///
    /// Used both on provided signer lists (so one signer cannot be counted
    /// twice towards the threshold) and on configured signer sets in
    /// `__constructor`/`rotate_signers` (where a duplicate could make the
    /// threshold unsatisfiable).
    fn require_no_duplicates(addresses: &Vec<Address>) {
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                if addresses.get(i).unwrap() == addresses.get(j).unwrap() {
                    panic!("Duplicate signer detected");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
    use soroban_sdk::testutils::{Address as _, EnvTestConfig, Events as _, Ledger as _};
    use soroban_sdk::{vec, xdr, IntoVal, Symbol, TryFromVal, Val};
    use std::rc::Rc;

    // ------------------------------------------------------------------
    // Mock USDC token
    // ------------------------------------------------------------------

    /// Minimal mock USDC token for unit tests.
    ///
    /// soroban-sdk 23.5.3's `register_stellar_asset_contract_v2` hardcodes
    /// the test SAC's asset code to `aaa`; a real `USDC:<issuer>` SAC is built
    /// by `make_usdc_sac` for the issuer-pin tests. Everything else uses this
    /// mock: Soroban token calls dispatch dynamically by function name, so
    /// `token::Client` works against it. Only the functions the contract and
    /// the tests actually call are implemented. Its `name()` is whatever the
    /// constructor was given, so `create_usdc_token` builds the SAC-shaped
    /// `USDC:<issuer strkey>` name.
    #[contract]
    pub struct MockUsdc;

    #[contracttype]
    #[derive(Clone)]
    pub enum MockUsdcKey {
        Name,
        Symbol,
        Decimals,
        Balance(Address),
    }

    #[contractimpl]
    impl MockUsdc {
        pub fn __constructor(env: Env, name: String, symbol: String, decimals: u32) {
            env.storage().instance().set(&MockUsdcKey::Name, &name);
            env.storage().instance().set(&MockUsdcKey::Symbol, &symbol);
            env.storage()
                .instance()
                .set(&MockUsdcKey::Decimals, &decimals);
        }

        pub fn name(env: Env) -> String {
            env.storage().instance().get(&MockUsdcKey::Name).unwrap()
        }

        pub fn symbol(env: Env) -> String {
            env.storage().instance().get(&MockUsdcKey::Symbol).unwrap()
        }

        pub fn decimals(env: Env) -> u32 {
            env.storage()
                .instance()
                .get(&MockUsdcKey::Decimals)
                .unwrap()
        }

        pub fn balance(env: Env, id: Address) -> i128 {
            env.storage()
                .instance()
                .get(&MockUsdcKey::Balance(id))
                .unwrap_or(0)
        }

        /// Test-only faucet (the real USDC SAC mints via the issuer).
        pub fn mint(env: Env, to: Address, amount: i128) {
            let key = MockUsdcKey::Balance(to);
            let bal: i128 = env.storage().instance().get(&key).unwrap_or(0);
            env.storage().instance().set(&key, &(bal + amount));
        }

        pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
            from.require_auth();
            let from_key = MockUsdcKey::Balance(from);
            let to_key = MockUsdcKey::Balance(to);
            let from_bal: i128 = env.storage().instance().get(&from_key).unwrap_or(0);
            if from_bal < amount {
                panic!("MockUsdc: insufficient balance");
            }
            let to_bal: i128 = env.storage().instance().get(&to_key).unwrap_or(0);
            env.storage()
                .instance()
                .set(&from_key, &(from_bal - amount));
            env.storage().instance().set(&to_key, &(to_bal + amount));
        }
    }

    /// The `G…`/`C…` strkey of an address as a std string.
    pub(crate) fn strkey(a: &Address) -> std::string::String {
        let s = a.to_string();
        let mut b = std::vec![0u8; s.len() as usize];
        s.copy_into_slice(&mut b);
        std::string::String::from_utf8(b).unwrap()
    }

    /// Register a mock USDC token whose `name()` is the SAC-shaped
    /// `USDC:<issuer strkey>` (`symbol() == "USDC"`, 7 decimals).
    pub(crate) fn create_usdc_token(env: &Env, issuer: &Address) -> Address {
        let name = std::format!("USDC:{}", strkey(issuer));
        env.register(
            MockUsdc,
            (
                String::from_str(env, &name),
                String::from_str(env, "USDC"),
                7u32,
            ),
        )
    }

    /// Register an arbitrary mock token (negative constructor tests).
    fn create_token(env: &Env, name: &str, symbol: &str, decimals: u32) -> Address {
        env.register(
            MockUsdc,
            (
                String::from_str(env, name),
                String::from_str(env, symbol),
                decimals,
            ),
        )
    }

    // ------------------------------------------------------------------
    // Real SAC helper (honesty gate for the issuer pin)
    // ------------------------------------------------------------------

    fn issuer_address(env: &Env, seed: u8) -> (Address, xdr::AccountId) {
        let pk = xdr::Uint256([seed; 32]);
        let account_id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(pk));
        let sc = xdr::ScVal::Address(xdr::ScAddress::Account(account_id.clone()));
        (Address::try_from_val(env, &sc).unwrap(), account_id)
    }

    /// Replicates `register_stellar_asset_contract_v2` with asset code `USDC`
    /// for a deterministic issuer account. Returns `(sac, issuer)`.
    fn make_usdc_sac(env: &Env, seed: u8) -> (Address, Address) {
        let (issuer_addr, issuer_id) = issuer_address(env, seed);
        let k = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
            account_id: issuer_id.clone(),
        }));
        if env.host().get_ledger_entry(&k).unwrap().is_none() {
            let v = Rc::new(xdr::LedgerEntry {
                data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
                    account_id: issuer_id.clone(),
                    balance: 0,
                    flags: 0,
                    home_domain: Default::default(),
                    inflation_dest: None,
                    num_sub_entries: 0,
                    seq_num: xdr::SequenceNumber(0),
                    thresholds: xdr::Thresholds([1; 4]),
                    signers: xdr::VecM::default(),
                    ext: xdr::AccountEntryExt::V0,
                }),
                last_modified_ledger_seq: 0,
                ext: xdr::LedgerEntryExt::V0,
            });
            env.host().add_ledger_entry(&k, &v, None).unwrap();
        }
        let asset = xdr::Asset::CreditAlphanum4(xdr::AlphaNum4 {
            asset_code: xdr::AssetCode4(*b"USDC"),
            issuer: issuer_id,
        });
        let create = xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(asset),
            executable: xdr::ContractExecutable::StellarAsset,
        });
        let sc = env.host().invoke_function(create).unwrap();
        let sac: Address = Address::try_from_val(env, &sc).unwrap();
        (sac, issuer_addr)
    }

    // ------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------

    struct Fx {
        env: Env,
        contract: Address,
        token: Address,
        issuer: Address,
        s1: Address,
        s2: Address,
        signers: Vec<Address>,
        threshold: u32,
    }

    impl Fx {
        fn client(&self) -> MultisigUsdcWrapperClient<'_> {
            MultisigUsdcWrapperClient::new(&self.env, &self.contract)
        }

        fn usdc(&self) -> MockUsdcClient<'_> {
            MockUsdcClient::new(&self.env, &self.token)
        }

        /// First `threshold` configured signers — always a valid quorum.
        fn quorum(&self) -> Vec<Address> {
            let mut q = Vec::new(&self.env);
            for i in 0..self.threshold {
                q.push_back(self.signers.get(i).unwrap());
            }
            q
        }

        /// Conservation-preserving seed: mint on the mock, then wrap through
        /// the contract with a full quorum. Never writes storage directly.
        fn seed(&self, holder: &Address, amount: i128) {
            self.usdc().mint(holder, &amount);
            self.client().wrap(&self.quorum(), holder, &amount);
        }

        fn advance(&self, secs: u64) {
            self.env.ledger().with_mut(|li| li.timestamp += secs);
        }

        /// Σ balance(holders) == total_supply == token.balance(contract);
        /// 0 <= reserved <= balance for every holder.
        fn assert_conserved(&self, holders: &[&Address]) {
            let client = self.client();
            let token = token::Client::new(&self.env, &self.token);
            let mut sum: i128 = 0;
            for h in holders {
                let b = client.balance(h);
                let r = client.reserved(h);
                assert!(
                    r >= 0 && r <= b,
                    "reserved invariant violated: balance {b}, reserved {r}"
                );
                assert_eq!(client.available(h), b - r);
                sum = sum.checked_add(b).unwrap();
            }
            assert_eq!(sum, client.total_supply(), "sum of balances != total");
            assert_eq!(
                client.total_supply(),
                token.balance(&self.contract),
                "total_supply != token balance held by the contract"
            );
        }

        fn has_timelock(&self, id: u64) -> bool {
            self.env.as_contract(&self.contract, || {
                self.env.storage().persistent().has(&DataKey::TimeLock(id))
            })
        }

        fn has_reserved(&self, a: &Address) -> bool {
            self.env.as_contract(&self.contract, || {
                self.env
                    .storage()
                    .persistent()
                    .has(&DataKey::Reserved(a.clone()))
            })
        }

        fn persistent_ttl(&self, key: &DataKey) -> u32 {
            self.env.as_contract(&self.contract, || {
                self.env.storage().persistent().get_ttl(key)
            })
        }

        fn instance_ttl(&self) -> u32 {
            self.env
                .as_contract(&self.contract, || self.env.storage().instance().get_ttl())
        }

        fn decay(&self, ledgers: u32) {
            self.env
                .ledger()
                .with_mut(|li| li.sequence_number += ledgers);
        }
    }

    fn register_wrapper(
        env: &Env,
        signers: &Vec<Address>,
        threshold: u32,
        min_threshold: u32,
        token: &Address,
        issuer: &Address,
        min_lock: u64,
    ) -> Address {
        env.register(
            MultisigUsdcWrapper,
            (
                signers.clone(),
                threshold,
                min_threshold,
                token.clone(),
                issuer.clone(),
                min_lock,
            ),
        )
    }

    fn deploy_n(n: u32, threshold: u32, min_threshold: u32, min_lock: u64) -> Fx {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let mut signers = Vec::new(&env);
        for _ in 0..n {
            signers.push_back(Address::generate(&env));
        }
        let contract = register_wrapper(
            &env,
            &signers,
            threshold,
            min_threshold,
            &token,
            &issuer,
            min_lock,
        );
        let s1 = signers.get(0).unwrap();
        let s2 = signers.get(1).unwrap_or_else(|| s1.clone());
        Fx {
            env,
            contract,
            token,
            issuer,
            s1,
            s2,
            signers,
            threshold,
        }
    }

    fn deploy(threshold: u32, min_threshold: u32, min_lock: u64) -> Fx {
        deploy_n(2, threshold, min_threshold, min_lock)
    }

    /// Two signers, 1-of-2, min_threshold 1, min lock 10 s.
    fn deploy_default() -> Fx {
        deploy(1, 1, 10)
    }

    /// A fresh unmocked env with a constructed wrapper (the constructor has no
    /// `require_auth`, so it works without mocks). Returns `(env, contract, s1, s2, token)`.
    fn deploy_no_mocks() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_auths(&[]); // explicitly: no mocked auths
        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let s1 = Address::generate(&env);
        let s2 = Address::generate(&env);
        let signers = vec![&env, s1.clone(), s2.clone()];
        let contract = register_wrapper(&env, &signers, 1, 1, &token, &issuer, 10);
        (env, contract, s1, s2, token)
    }

    // ==================================================================
    // Constructor
    // ==================================================================

    #[test]
    fn test_constructor_sets_state() {
        let fx = deploy_default();
        let client = fx.client();
        let config = client.multisig_config();
        assert_eq!(config.signers, fx.signers);
        assert_eq!(config.threshold, 1);
        assert_eq!(config.epoch, 0);
        assert_eq!(client.min_threshold(), 1);
        assert_eq!(client.min_lock_duration(), 10);
        assert_eq!(client.usdc_token(), fx.token);
        assert_eq!(client.usdc_issuer(), fx.issuer);
        assert_eq!(client.usdc_decimals(), 7);
        assert_eq!(client.total_supply(), 0);
        assert_eq!(client.next_timelock_id(), 0);
        assert!(!client.is_paused());
        assert_eq!(client.balance(&fx.s1), 0);
        assert_eq!(client.balance(&fx.s2), 0);
    }

    #[test]
    #[should_panic(expected = "can't invoke a reserved function directly")]
    fn test_constructor_cannot_be_invoked_directly() {
        let fx = deploy_default();
        // The reserved-function check precedes argument handling, so an empty
        // argument list is enough to prove the host refuses the call.
        fx.env.invoke_contract::<Val>(
            &fx.contract,
            &Symbol::new(&fx.env, "__constructor"),
            vec![&fx.env],
        );
    }

    #[test]
    #[should_panic(expected = "calling unknown contract function")]
    fn test_initialize_entry_point_removed() {
        let fx = deploy_default();
        fx.env.invoke_contract::<Val>(
            &fx.contract,
            &Symbol::new(&fx.env, "initialize"),
            vec![&fx.env],
        );
    }

    #[test]
    #[should_panic(expected = "Signers must not be empty")]
    fn test_constructor_rejects_empty_signers() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let signers: Vec<Address> = Vec::new(&env);
        register_wrapper(&env, &signers, 1, 1, &token, &issuer, 10);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_zero_threshold_panics() {
        deploy(0, 1, 10);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_threshold_exceeding_signers_panics() {
        deploy(3, 1, 10);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_constructor_rejects_threshold_below_min_threshold() {
        deploy_n(3, 1, 2, 10);
    }

    #[test]
    #[should_panic(expected = "Invalid min threshold")]
    fn test_constructor_rejects_min_threshold_above_len() {
        deploy_n(2, 2, 3, 10);
    }

    #[test]
    #[should_panic(expected = "Invalid min threshold")]
    fn test_constructor_rejects_zero_min_threshold() {
        deploy_n(2, 1, 0, 10);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_constructor_rejects_duplicate_signers() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let s1 = Address::generate(&env);
        // [s1, s1] with threshold 2 would brick the contract: verify_multisig
        // rejects duplicate provided signers, so the threshold could never be
        // met by any call.
        let signers = vec![&env, s1.clone(), s1.clone()];
        register_wrapper(&env, &signers, 2, 1, &token, &issuer, 10);
    }

    #[test]
    #[should_panic(expected = "Too many signers")]
    fn test_constructor_rejects_too_many_signers() {
        deploy_n(MAX_SIGNERS + 1, 1, 1, 10);
    }

    #[test]
    #[should_panic(expected = "Min lock duration exceeds maximum")]
    fn test_constructor_rejects_min_lock_above_max() {
        // A minimum above MAX_LOCK_DURATION would make every schedule call
        // panic ("Delay too short" vs "Delay exceeds maximum" can never both
        // pass), bricking scheduling entirely.
        deploy(1, 1, MAX_LOCK_DURATION + 1);
    }

    #[test]
    #[should_panic(expected = "Network max entry TTL below policy")]
    fn test_constructor_rejects_low_network_max_ttl() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_max_entry_ttl(1_000_000);
        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let signers = vec![&env, Address::generate(&env)];
        register_wrapper(&env, &signers, 1, 1, &token, &issuer, 10);
    }

    #[test]
    fn test_constructor_with_single_signer_threshold_one() {
        let fx = deploy_n(1, 1, 1, 60);
        let client = fx.client();
        assert_eq!(client.balance(&fx.s1), 0);
        assert_eq!(client.total_supply(), 0);
        assert_eq!(client.min_lock_duration(), 60);
    }

    #[test]
    fn test_constructor_with_max_threshold() {
        // threshold == signers.len() is valid
        let fx = deploy_n(3, 3, 1, 10);
        assert_eq!(fx.client().total_supply(), 0);
        assert_eq!(fx.client().multisig_config().threshold, 3);
    }

    #[test]
    fn test_total_supply_zero_after_construction() {
        let fx = deploy_default();
        assert_eq!(fx.client().total_supply(), 0);
    }

    #[test]
    fn test_balance_defaults_to_zero() {
        let fx = deploy_default();
        let unknown = Address::generate(&fx.env);
        assert_eq!(fx.client().balance(&unknown), 0);
        assert_eq!(fx.client().reserved(&unknown), 0);
        assert_eq!(fx.client().available(&unknown), 0);
    }

    #[test]
    fn test_balance_zero_for_all_signers_after_construction() {
        let fx = deploy_default();
        assert_eq!(fx.client().balance(&fx.s1), 0);
        assert_eq!(fx.client().balance(&fx.s2), 0);
    }

    // ---- USDC pin ----

    #[test]
    fn test_constructor_records_usdc_token_and_decimals() {
        let fx = deploy_default();
        assert_eq!(fx.client().usdc_token(), fx.token);
        assert_eq!(fx.client().usdc_decimals(), USDC_DECIMALS);
        assert_eq!(fx.client().usdc_issuer(), fx.issuer);
    }

    #[test]
    fn test_constructor_accepts_real_usdc_sac() {
        let env = Env::default();
        env.mock_all_auths();
        let (sac, issuer) = make_usdc_sac(&env, 7);
        let s1 = Address::generate(&env);
        let signers = vec![&env, s1.clone()];
        let contract = register_wrapper(&env, &signers, 1, 1, &sac, &issuer, 10);
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        assert_eq!(client.usdc_issuer(), issuer);
        assert_eq!(client.usdc_token(), sac);
        assert_eq!(client.usdc_decimals(), 7);

        let holder = Address::generate(&env);
        token::StellarAssetClient::new(&env, &sac).mint(&holder, &1_000);
        let sac_client = token::Client::new(&env, &sac);

        client.wrap(&signers, &holder, &600);
        assert_eq!(client.balance(&holder), 600);
        assert_eq!(client.total_supply(), 600);
        assert_eq!(sac_client.balance(&contract), client.total_supply());

        let id = client.schedule_unwrap(&signers, &holder, &250, &10);
        env.ledger().with_mut(|li| li.timestamp += 100);
        client.execute_unwrap(&signers, &id);
        assert_eq!(client.balance(&holder), 350);
        assert_eq!(client.total_supply(), 350);
        assert_eq!(sac_client.balance(&contract), client.total_supply());
        assert_eq!(sac_client.balance(&holder), 650);
    }

    #[test]
    #[should_panic(expected = "Underlying token issuer mismatch")]
    fn test_constructor_rejects_issuer_mismatch_real_sac() {
        let env = Env::default();
        env.mock_all_auths();
        let (_sac_a, issuer_a) = make_usdc_sac(&env, 7);
        let (sac_b, _issuer_b) = make_usdc_sac(&env, 9);
        let signers = vec![&env, Address::generate(&env)];
        // A genuine USDC SAC from another issuer: symbol and decimals pass,
        // the name()'s strkey does not.
        register_wrapper(&env, &signers, 1, 1, &sac_b, &issuer_a, 10);
    }

    #[test]
    #[should_panic(expected = "Underlying token issuer mismatch")]
    fn test_constructor_rejects_issuer_mismatch_mock() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer_a = Address::generate(&env);
        let issuer_b = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer_a);
        let signers = vec![&env, Address::generate(&env)];
        register_wrapper(&env, &signers, 1, 1, &token, &issuer_b, 10);
    }

    #[test]
    #[should_panic(expected = "Underlying token issuer mismatch")]
    fn test_constructor_rejects_contract_address_issuer() {
        let env = Env::default();
        env.mock_all_auths();
        let (sac, _issuer) = make_usdc_sac(&env, 7);
        let signers = vec![&env, Address::generate(&env)];
        // A C-address can never appear in a SAC name (they carry G strkeys).
        register_wrapper(&env, &signers, 1, 1, &sac, &sac, 10);
    }

    #[test]
    #[should_panic(expected = "Underlying token is not USDC")]
    fn test_constructor_rejects_non_usdc_token() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        // The SDK's test SAC hardcodes the asset code "aaa" — not USDC. Its
        // own issuer is passed so the failure is provably the symbol.
        let sac = env.register_stellar_asset_contract_v2(admin);
        let signers = vec![&env, Address::generate(&env)];
        register_wrapper(
            &env,
            &signers,
            1,
            1,
            &sac.address(),
            &sac.issuer().address(),
            10,
        );
    }

    #[test]
    #[should_panic(expected = "Underlying token is not USDC")]
    fn test_constructor_rejects_native_symbol() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let token = create_token(&env, "native", "native", 7);
        let signers = vec![&env, Address::generate(&env)];
        register_wrapper(&env, &signers, 1, 1, &token, &issuer, 10);
    }

    #[test]
    #[should_panic(expected = "USDC token must have 7 decimals")]
    fn test_constructor_rejects_wrong_decimals() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        // Right symbol and name, wrong decimals (e.g. Ethereum-style 6-decimal USDC).
        let name = std::format!("USDC:{}", strkey(&issuer));
        let token = create_token(&env, &name, "USDC", 6);
        let signers = vec![&env, Address::generate(&env)];
        register_wrapper(&env, &signers, 1, 1, &token, &issuer, 10);
    }

    // ==================================================================
    // Scheduling
    // ==================================================================

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_unwrap_insufficient_signers() {
        let fx = deploy(2, 1, 10);
        // Provide only 1 signer when 2 are required
        let insufficient = vec![&fx.env, fx.s1.clone()];
        fx.client()
            .schedule_unwrap(&insufficient, &fx.s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Insufficient available balance")]
    fn test_schedule_unwrap_zero_balance() {
        let fx = deploy_default();
        // No tokens wrapped — balance is 0
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Delay too short")]
    fn test_schedule_unwrap_delay_below_minimum() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        // min_lock_duration is 10, providing 5
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &100, &5);
    }

    #[test]
    fn test_schedule_unwrap_creates_timelock() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1000);
        let client = fx.client();
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        assert_eq!(tl_id, 0);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 1);
        assert_eq!(tl.amount, 200);
        assert_eq!(tl.sender, fx.s1);
        assert_eq!(tl.recipient, fx.s1);
        assert!(!tl.executed);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_cancel_timelock_removes_entry() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        assert!(
            fx.has_timelock(tl_id),
            "Scheduled timelock entry should be stored"
        );

        client.cancel_timelock(&fx.quorum(), &tl_id);

        assert!(
            !fx.has_timelock(tl_id),
            "Cancelled timelock entry should be removed from storage"
        );
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_schedule_transfer_creates_timelock() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 2);
        assert_eq!(tl.amount, 100);
        assert!(!tl.executed);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    fn test_timelock_ids_are_sequential() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 5000);
        let client = fx.client();
        let q = fx.quorum();

        let id0 = client.schedule_unwrap(&q, &fx.s1, &100, &10);
        let id1 = client.schedule_unwrap(&q, &fx.s1, &100, &10);
        let id2 = client.schedule_transfer(&q, &fx.s1, &fx.s2, &100, &10);

        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(client.next_timelock_id(), 3);
    }

    #[test]
    #[should_panic(expected = "Insufficient available balance")]
    fn test_schedule_transfer_insufficient_balance() {
        let fx = deploy_default();
        // s1 has no balance — should panic
        fx.client()
            .schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_get_timelock_nonexistent() {
        let fx = deploy_default();
        fx.client().get_timelock(&99);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_zero_amount_panics() {
        let fx = deploy_default();
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_zero_amount_panics() {
        let fx = deploy_default();
        fx.client()
            .schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_negative_amount_panics() {
        let fx = deploy_default();
        fx.client()
            .schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &-100, &10);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_verify_multisig_rejects_unauthorized_signer() {
        let fx = deploy_default();
        let unauthorized = Address::generate(&fx.env);
        let signers = vec![&fx.env, unauthorized];
        fx.client().schedule_unwrap(&signers, &fx.s1, &100, &10);
    }

    #[test]
    fn test_schedule_transfer_stores_sender() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.sender, fx.s1);
        assert_eq!(tl.recipient, fx.s2);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_cancel_already_cancelled_timelock_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        client.cancel_timelock(&fx.quorum(), &tl_id);
        // Second cancel should panic: the entry was pruned on the first one
        client.cancel_timelock(&fx.quorum(), &tl_id);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_transfer_insufficient_signers() {
        // 2-of-2: the seed wraps with the full quorum, the schedule offers one.
        let fx = deploy(2, 1, 10);
        fx.seed(&fx.s1, 500);
        let insufficient = vec![&fx.env, fx.s1.clone()];
        fx.client()
            .schedule_transfer(&insufficient, &fx.s1, &fx.s2, &100, &10);
    }

    #[test]
    fn test_multiple_balances_independent() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1000);
        fx.seed(&fx.s2, 500);
        let client = fx.client();
        assert_eq!(client.balance(&fx.s1), 1000);
        assert_eq!(client.balance(&fx.s2), 500);
        assert_eq!(client.total_supply(), 1500);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_negative_amount_panics() {
        let fx = deploy_default();
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &-50, &10);
    }

    #[test]
    fn test_schedule_unwrap_exact_balance() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 300);
        let client = fx.client();
        // Unwrap exactly the full balance — should succeed
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        assert_eq!(client.get_timelock(&tl_id).amount, 300);
        assert_eq!(client.available(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Insufficient available balance")]
    fn test_schedule_unwrap_exceeds_balance() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 300);
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &301, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_wrap_zero_amount_panics() {
        let fx = deploy_default();
        fx.client().wrap(&fx.quorum(), &fx.s1, &0);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_duplicate_signers_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        // Pass duplicate addresses
        let signers = vec![&fx.env, fx.s1.clone(), fx.s1.clone()];
        fx.client().schedule_unwrap(&signers, &fx.s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_cancel_prevents_execution() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        client.cancel_timelock(&fx.quorum(), &tl_id);
        fx.advance(1000);
        // Try to execute the cancelled timelock — should panic (entry pruned)
        client.execute_unwrap(&fx.quorum(), &tl_id);
    }

    #[test]
    #[should_panic(expected = "Self-transfer not allowed")]
    fn test_self_transfer_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        fx.client()
            .schedule_transfer(&fx.quorum(), &fx.s1, &fx.s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Delay exceeds maximum lock duration")]
    fn test_delay_too_long_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        fx.client()
            .schedule_unwrap(&fx.quorum(), &fx.s1, &100, &(MAX_LOCK_DURATION + 1));
    }

    // ==================================================================
    // Reservation
    // ==================================================================

    #[test]
    fn test_schedule_reserves() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        assert_eq!(client.reserved(&fx.s1), 300);
        assert_eq!(client.available(&fx.s1), 200);
        assert_eq!(client.balance(&fx.s1), 500);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Insufficient available balance")]
    fn test_over_schedule_rejected() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        // 300 + 300 > 500: the reservation makes the second schedule fail.
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
    }

    #[test]
    fn test_schedule_within_available_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        assert_eq!(id, 1);
        assert_eq!(client.reserved(&fx.s1), 500);
        assert_eq!(client.available(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Insufficient available balance")]
    fn test_schedule_transfer_over_available_rejected() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &201, &10);
    }

    #[test]
    fn test_schedule_transfer_exact_available_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        assert_eq!(client.reserved(&fx.s1), 500);
        assert_eq!(client.available(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    fn test_cancel_releases_reservation() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &300, &10);
        assert!(fx.has_reserved(&fx.s1));
        client.cancel_timelock(&fx.quorum(), &id);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert!(
            !fx.has_reserved(&fx.s1),
            "Reserved entry must be removed at 0"
        );
        // The whole balance is available again.
        client.schedule_unwrap(&fx.quorum(), &fx.s1, &500, &10);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_execute_unwrap_consumes_reservation() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1_000);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &400, &10);
        fx.advance(100);
        client.execute_unwrap(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s1), 600);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert_eq!(client.total_supply(), 600);
        assert_eq!(fx.usdc().balance(&fx.contract), 600);
        assert_eq!(fx.usdc().balance(&fx.s1), 400);
        assert!(!fx.has_timelock(id));
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_execute_transfer_consumes_reservation() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1_000);
        let client = fx.client();
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &400, &10);
        assert_eq!(client.reserved(&fx.s1), 400);
        fx.advance(100);
        client.execute_transfer(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s1), 600);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert_eq!(client.balance(&fx.s2), 400);
        assert_eq!(client.reserved(&fx.s2), 0);
        assert_eq!(client.total_supply(), 1_000);
        assert!(!fx.has_timelock(id));
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    fn test_transfer_recipient_reservation_untouched() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1_000);
        fx.seed(&fx.s2, 300);
        let client = fx.client();
        // The recipient has its own pending reservation.
        client.schedule_unwrap(&fx.quorum(), &fx.s2, &100, &10);
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &400, &10);
        fx.advance(100);
        client.execute_transfer(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s2), 700);
        assert_eq!(client.reserved(&fx.s2), 100);
        assert_eq!(client.available(&fx.s2), 600);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    fn test_reserved_entry_removed_at_zero() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &500, &10);
        assert!(fx.has_reserved(&fx.s1));
        fx.advance(100);
        client.execute_unwrap(&fx.quorum(), &id);
        assert!(!fx.has_reserved(&fx.s1));
        // Balance entry stays (at 0) after a full unwrap.
        assert_eq!(client.balance(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Reserved invariant violated")]
    fn test_reserved_invariant_tripwire() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        // The only direct storage write in the suite: corrupt the reservation
        // so that reserved > balance and prove every money path trips.
        fx.env.as_contract(&fx.contract, || {
            fx.env
                .storage()
                .persistent()
                .set(&DataKey::Reserved(fx.s1.clone()), &600_i128);
        });
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &1, &10);
    }

    #[test]
    #[should_panic(expected = "Reserved invariant violated")]
    fn test_available_panics_on_invariant_violation() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        fx.env.as_contract(&fx.contract, || {
            fx.env
                .storage()
                .persistent()
                .set(&DataKey::Reserved(fx.s1.clone()), &600_i128);
        });
        fx.client().available(&fx.s1);
    }

    #[test]
    #[should_panic(expected = "Wrong operation type")]
    fn test_execute_unwrap_rejects_transfer_timelock() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(100);
        client.execute_unwrap(&fx.quorum(), &id);
    }

    #[test]
    fn test_execute_unwrap_rejects_transfer_timelock_state_unchanged() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(100);
        assert!(client.try_execute_unwrap(&fx.quorum(), &id).is_err());
        assert_eq!(client.balance(&fx.s1), 500);
        assert_eq!(client.reserved(&fx.s1), 200);
        assert_eq!(client.total_supply(), 500);
        assert!(fx.has_timelock(id));
        assert!(!client.get_timelock(&id).executed);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    #[should_panic(expected = "Wrong operation type")]
    fn test_execute_transfer_rejects_unwrap_timelock() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(100);
        client.execute_transfer(&fx.quorum(), &id);
    }

    #[test]
    fn test_execute_transfer_rejects_unwrap_timelock_state_unchanged() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(100);
        assert!(client.try_execute_transfer(&fx.quorum(), &id).is_err());
        assert_eq!(client.balance(&fx.s1), 500);
        assert_eq!(client.reserved(&fx.s1), 200);
        assert_eq!(fx.usdc().balance(&fx.contract), 500);
        assert!(fx.has_timelock(id));
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_reserved_never_exceeds_balance_after_sequence() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 1_000);
        let client = fx.client();
        let q = fx.quorum();
        let a = client.schedule_unwrap(&q, &fx.s1, &300, &10);
        let b = client.schedule_transfer(&q, &fx.s1, &fx.s2, &300, &10);
        let c = client.schedule_unwrap(&q, &fx.s1, &300, &10);
        assert_eq!(client.reserved(&fx.s1), 900);
        assert_eq!(client.available(&fx.s1), 100);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);

        fx.advance(100);
        client.execute_unwrap(&q, &a);
        assert_eq!(client.balance(&fx.s1), 700);
        assert_eq!(client.reserved(&fx.s1), 600);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);

        client.cancel_timelock(&q, &b);
        assert_eq!(client.reserved(&fx.s1), 300);
        fx.assert_conserved(&[&fx.s1, &fx.s2]);

        fx.advance(EXECUTION_WINDOW);
        client.expire_timelock(&c);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert_eq!(client.available(&fx.s1), 700);
        assert!(!fx.has_reserved(&fx.s1));
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    // ==================================================================
    // Execution model
    // ==================================================================

    #[test]
    fn test_execute_transfer_with_time_advancement() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(1000);
        client.execute_transfer(&fx.quorum(), &tl_id);

        assert_eq!(client.balance(&fx.s1), 300);
        assert_eq!(client.balance(&fx.s2), 200);
        assert!(
            !fx.has_timelock(tl_id),
            "Executed timelock entry should be removed from storage"
        );
        fx.assert_conserved(&[&fx.s1, &fx.s2]);
    }

    #[test]
    #[should_panic(expected = "Timelock not matured")]
    fn test_execute_transfer_before_unlock_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        // Do NOT advance time — try to execute immediately
        client.execute_transfer(&fx.quorum(), &tl_id);
    }

    #[test]
    #[should_panic(expected = "Timelock not matured")]
    fn test_execute_before_maturity_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &100);
        fx.advance(99);
        client.execute_unwrap(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_double_execute_transfer_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(1000);
        client.execute_transfer(&fx.quorum(), &tl_id);
        // Execute again — should panic (entry pruned on first execution)
        client.execute_transfer(&fx.quorum(), &tl_id);
    }

    #[test]
    fn test_execute_after_rotation_by_new_signers_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let old = vec![&fx.env, fx.s1.clone()];
        let id = client.schedule_unwrap(&old, &fx.s1, &200, &10);

        let n1 = Address::generate(&fx.env);
        let n2 = Address::generate(&fx.env);
        client.rotate_signers(&old, &vec![&fx.env, n1.clone(), n2.clone()], &1);

        // Stored signers are unchanged by rotation (audit metadata).
        assert_eq!(client.get_timelock(&id).signers, old);

        fx.advance(100);
        client.execute_unwrap(&vec![&fx.env, n1.clone()], &id);
        assert_eq!(client.balance(&fx.s1), 300);
        assert_eq!(fx.usdc().balance(&fx.s1), 200);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_execute_after_rotation_by_old_signers_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let old = vec![&fx.env, fx.s1.clone()];
        let id = client.schedule_unwrap(&old, &fx.s1, &200, &10);
        let n1 = Address::generate(&fx.env);
        client.rotate_signers(&old, &vec![&fx.env, n1], &1);
        fx.advance(100);
        client.execute_unwrap(&old, &id);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_cancel_by_old_signers_after_rotation_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let old = vec![&fx.env, fx.s1.clone()];
        let id = client.schedule_unwrap(&old, &fx.s1, &200, &10);
        let n1 = Address::generate(&fx.env);
        client.rotate_signers(&old, &vec![&fx.env, n1], &1);
        client.cancel_timelock(&old, &id);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_execute_requires_current_threshold() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let old = vec![&fx.env, fx.s1.clone()];
        let id = client.schedule_unwrap(&old, &fx.s1, &200, &10);
        // 1-of-2 → 2-of-3
        let n1 = Address::generate(&fx.env);
        let n2 = Address::generate(&fx.env);
        let n3 = Address::generate(&fx.env);
        client.rotate_signers(&old, &vec![&fx.env, n1.clone(), n2, n3], &2);
        fx.advance(100);
        client.execute_unwrap(&vec![&fx.env, n1], &id);
    }

    #[test]
    fn test_stored_signers_are_audit_only() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let old = vec![&fx.env, fx.s1.clone()];
        let id = client.schedule_unwrap(&old, &fx.s1, &200, &10);
        let n1 = Address::generate(&fx.env);
        client.rotate_signers(&old, &vec![&fx.env, n1.clone()], &1);

        let tl = client.get_timelock(&id);
        assert_eq!(tl.signers, old);
        assert_eq!(tl.config_epoch, 0);
        assert_eq!(client.multisig_config().epoch, 1);
        assert_eq!(client.multisig_config().signers, vec![&fx.env, n1.clone()]);

        // ...and the new set can still cancel it.
        client.cancel_timelock(&vec![&fx.env, n1], &id);
        assert_eq!(client.reserved(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Contract is paused")]
    fn test_execute_under_pause_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(100);
        client.pause(&fx.quorum());
        client.execute_unwrap(&fx.quorum(), &id);
    }

    #[test]
    fn test_execute_after_unpause_within_window_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        client.pause(&fx.quorum());
        fx.advance(100);
        assert!(client.try_execute_unwrap(&fx.quorum(), &id).is_err());
        client.unpause(&fx.quorum());
        client.execute_unwrap(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s1), 300);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_execute_at_unlock_time_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &100);
        fx.advance(100); // now == unlock_time
        client.execute_unwrap(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s1), 300);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_execute_at_expires_at_minus_one_succeeds() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &100);
        let tl = client.get_timelock(&id);
        fx.advance(100 + EXECUTION_WINDOW - 1);
        assert_eq!(fx.env.ledger().timestamp(), tl.expires_at - 1);
        client.execute_unwrap(&fx.quorum(), &id);
        assert_eq!(client.balance(&fx.s1), 300);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Timelock expired")]
    fn test_execute_at_expires_at_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &100);
        let tl = client.get_timelock(&id);
        fx.advance(100 + EXECUTION_WINDOW);
        assert_eq!(fx.env.ledger().timestamp(), tl.expires_at);
        client.execute_unwrap(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic(expected = "Timelock expired")]
    fn test_execute_past_expiry_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(10 + EXECUTION_WINDOW + 1_000);
        client.execute_transfer(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic(expected = "Timelock not yet expired")]
    fn test_expire_before_expiry_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(10 + EXECUTION_WINDOW - 1);
        client.expire_timelock(&id);
    }

    #[test]
    fn test_expire_releases_reservation_and_removes_entry() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(10 + EXECUTION_WINDOW);
        client.expire_timelock(&id);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert_eq!(client.balance(&fx.s1), 500);
        assert!(!fx.has_timelock(id));
        assert!(!fx.has_reserved(&fx.s1));
        // Tokens stay wrapped.
        assert_eq!(fx.usdc().balance(&fx.contract), 500);
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_expire_twice_panics() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(10 + EXECUTION_WINDOW);
        client.expire_timelock(&id);
        client.expire_timelock(&id);
    }

    #[test]
    fn test_expire_works_while_paused() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        client.pause(&fx.quorum());
        fx.advance(10 + EXECUTION_WINDOW);
        client.expire_timelock(&id);
        assert!(client.is_paused());
        assert_eq!(client.reserved(&fx.s1), 0);
        assert!(!fx.has_timelock(id));
        fx.assert_conserved(&[&fx.s1]);
    }

    #[test]
    fn test_timelock_records_expiry_epoch_and_scheduled_at() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        fx.advance(12_345);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &100);
        let tl = client.get_timelock(&id);
        assert_eq!(tl.scheduled_at, 12_345);
        assert_eq!(tl.unlock_time, 12_345 + 100);
        assert_eq!(tl.expires_at, tl.unlock_time + EXECUTION_WINDOW);
        assert_eq!(tl.config_epoch, 0);
    }

    // ---- Pause ----

    #[test]
    #[should_panic(expected = "Contract is paused")]
    fn test_pause_blocks_wrap() {
        let fx = deploy_default();
        let client = fx.client();
        client.pause(&fx.quorum());
        client.wrap(&fx.quorum(), &fx.s1, &100);
    }

    #[test]
    fn test_unpause_allows_operations() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        client.pause(&fx.quorum());
        assert!(client.is_paused());
        client.unpause(&fx.quorum());
        assert!(!client.is_paused());

        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &100, &10);
        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.amount, 100);
        assert!(!tl.executed);
    }

    #[test]
    fn test_cancel_still_works_while_paused() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let tl_id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        client.pause(&fx.quorum());
        client.cancel_timelock(&fx.quorum(), &tl_id);
        assert!(!fx.has_timelock(tl_id));
        assert_eq!(client.reserved(&fx.s1), 0);
        fx.assert_conserved(&[&fx.s1]);
    }

    // ---- Rotation ----

    #[test]
    fn test_rotate_signers() {
        let fx = deploy_default();
        let client = fx.client();
        let current = vec![&fx.env, fx.s1.clone()];

        let new_s1 = Address::generate(&fx.env);
        let new_s2 = Address::generate(&fx.env);
        let new_signers = vec![&fx.env, new_s1.clone(), new_s2.clone()];
        client.rotate_signers(&current, &new_signers, &1);

        // Seed with the NEW quorum (the fixture's quorum is now rotated out).
        let new_quorum = vec![&fx.env, new_s1.clone()];
        fx.usdc().mint(&new_s1, &500);
        client.wrap(&new_quorum, &new_s1, &500);

        let tl_id = client.schedule_unwrap(&new_quorum, &new_s1, &100, &10);
        assert_eq!(client.get_timelock(&tl_id).amount, 100);
        fx.assert_conserved(&[&new_s1]);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_rotate_signers_old_signers_rejected() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let current = vec![&fx.env, fx.s1.clone()];
        let new_s1 = Address::generate(&fx.env);
        client.rotate_signers(&current, &vec![&fx.env, new_s1], &1);
        // Old signer should be rejected
        client.schedule_unwrap(&current, &fx.s1, &100, &10);
    }

    #[test]
    fn test_rotate_bumps_epoch() {
        let fx = deploy_default();
        let client = fx.client();
        assert_eq!(client.multisig_config().epoch, 0);
        let n1 = Address::generate(&fx.env);
        client.rotate_signers(&fx.quorum(), &vec![&fx.env, n1.clone()], &1);
        assert_eq!(client.multisig_config().epoch, 1);
        let n2 = Address::generate(&fx.env);
        client.rotate_signers(&vec![&fx.env, n1], &vec![&fx.env, n2], &1);
        assert_eq!(client.multisig_config().epoch, 2);
    }

    #[test]
    #[should_panic(expected = "Invalid new threshold")]
    fn test_rotate_below_min_threshold_panics() {
        let fx = deploy_n(3, 2, 2, 10);
        let n1 = Address::generate(&fx.env);
        let n2 = Address::generate(&fx.env);
        fx.client()
            .rotate_signers(&fx.quorum(), &vec![&fx.env, n1, n2], &1);
    }

    #[test]
    fn test_rotate_to_min_threshold_allowed() {
        let fx = deploy_n(3, 3, 2, 10);
        let n1 = Address::generate(&fx.env);
        let n2 = Address::generate(&fx.env);
        fx.client()
            .rotate_signers(&fx.quorum(), &vec![&fx.env, n1, n2], &2);
        assert_eq!(fx.client().multisig_config().threshold, 2);
        assert_eq!(fx.client().min_threshold(), 2);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_rotate_signers_rejects_duplicates() {
        let fx = deploy_default();
        let dup = Address::generate(&fx.env);
        fx.client()
            .rotate_signers(&fx.quorum(), &vec![&fx.env, dup.clone(), dup], &2);
    }

    // ==================================================================
    // Authorization enforcement
    // ==================================================================
    //
    // Most tests use `env.mock_all_auths()`, which bypasses the host's
    // authorization machinery entirely. Those prove the contract behaves
    // correctly *when auths are present* — they do NOT prove that it
    // *demands* authorization from the configured signers. The tests below
    // call `env.mock_auths(&[])` (no mocks) at the asserted call: reaching a
    // `require_auth()` without a matching mock panics. Permissionless entry
    // points must, conversely, succeed with no mocks at all.

    #[test]
    #[should_panic]
    fn test_wrap_requires_signer_auth() {
        let (env, contract, s1, _s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        // wrap -> verify_multisig -> require_auth on each signer (before the
        // depositor auth and the token transfer). With no mocks registered,
        // this must panic.
        let depositor = Address::generate(&env);
        client.wrap(&vec![&env, s1], &depositor, &100);
    }

    #[test]
    #[should_panic]
    fn test_schedule_unwrap_requires_signer_auth() {
        let (env, contract, s1, s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        client.schedule_unwrap(&vec![&env, s1], &s2, &100, &10);
    }

    #[test]
    #[should_panic]
    fn test_execute_unwrap_requires_signer_auth() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(100);
        fx.env.mock_auths(&[]);
        client.execute_unwrap(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic]
    fn test_execute_transfer_requires_signer_auth() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_transfer(&fx.quorum(), &fx.s1, &fx.s2, &200, &10);
        fx.advance(100);
        fx.env.mock_auths(&[]);
        client.execute_transfer(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic]
    fn test_cancel_requires_signer_auth() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.env.mock_auths(&[]);
        client.cancel_timelock(&fx.quorum(), &id);
    }

    #[test]
    #[should_panic]
    fn test_rotate_requires_signer_auth() {
        let (env, contract, s1, _s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        let n1 = Address::generate(&env);
        client.rotate_signers(&vec![&env, s1], &vec![&env, n1], &1);
    }

    #[test]
    #[should_panic]
    fn test_pause_requires_signer_auth() {
        let (env, contract, s1, _s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        client.pause(&vec![&env, s1]);
    }

    #[test]
    fn test_expire_is_permissionless() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(10 + EXECUTION_WINDOW);
        fx.env.mock_auths(&[]);
        client.expire_timelock(&id);
        assert_eq!(client.reserved(&fx.s1), 0);
        assert!(!fx.has_timelock(id));
    }

    #[test]
    fn test_bump_entry_ttl_is_permissionless() {
        let (env, contract, s1, _s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        client.bump_entry_ttl(&vec![&env, s1], &vec![&env, 0u64, 7u64]);
    }

    #[test]
    fn test_bump_ttl_is_permissionless() {
        let (env, contract, _s1, _s2, _token) = deploy_no_mocks();
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        client.bump_ttl();
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_execute_by_non_signer_rejected() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.advance(100);
        let stranger = Address::generate(&fx.env);
        client.execute_unwrap(&vec![&fx.env, stranger], &id);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_cancel_by_non_signer_rejected() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let client = fx.client();
        let id = client.schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        let stranger = Address::generate(&fx.env);
        client.cancel_timelock(&vec![&fx.env, stranger], &id);
    }

    // ==================================================================
    // Wrap
    // ==================================================================

    #[test]
    fn test_wrap_credits_depositor() {
        let fx = deploy_default();
        // Depositor is not an authorized signer
        let depositor = Address::generate(&fx.env);
        fx.usdc().mint(&depositor, &1_000);

        let client = fx.client();
        client.wrap(&fx.quorum(), &depositor, &400);

        assert_eq!(client.balance(&depositor), 400);
        assert_eq!(client.balance(&fx.s1), 0);
        assert_eq!(client.total_supply(), 400);

        let token_client = token::Client::new(&fx.env, &fx.token);
        assert_eq!(token_client.balance(&depositor), 600);
        assert_eq!(token_client.balance(&fx.contract), 400);
        fx.assert_conserved(&[&depositor, &fx.s1]);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_usdc() {
        let fx = deploy_default();
        let depositor = Address::generate(&fx.env);
        let usdc = fx.usdc();
        // 1 USDC = 10_000_000 stroops (7 decimals)
        usdc.mint(&depositor, &10_000_000);

        let client = fx.client();
        let q = fx.quorum();

        // Wrap 0.5 USDC
        client.wrap(&q, &depositor, &5_000_000);
        assert_eq!(usdc.balance(&depositor), 5_000_000);
        assert_eq!(usdc.balance(&fx.contract), 5_000_000);
        assert_eq!(client.balance(&depositor), 5_000_000);
        assert_eq!(client.total_supply(), 5_000_000);
        fx.assert_conserved(&[&depositor]);

        // Schedule and (after the delay) execute an unwrap of the full amount
        let tl_id = client.schedule_unwrap(&q, &depositor, &5_000_000, &10);
        fx.advance(1000);
        client.execute_unwrap(&q, &tl_id);

        // USDC flowed back out to the depositor in full
        assert_eq!(usdc.balance(&depositor), 10_000_000);
        assert_eq!(usdc.balance(&fx.contract), 0);
        assert_eq!(client.balance(&depositor), 0);
        assert_eq!(client.total_supply(), 0);
        assert!(!fx.has_timelock(tl_id));
        fx.assert_conserved(&[&depositor]);
    }

    // ==================================================================
    // Storage / TTL
    // ==================================================================

    #[test]
    fn test_balance_is_persistent_not_instance() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 100);
        let key = DataKey::Balance(fx.s1.clone());
        let (persistent, instance) = fx.env.as_contract(&fx.contract, || {
            (
                fx.env.storage().persistent().has(&key),
                fx.env.storage().instance().has(&key),
            )
        });
        assert!(persistent);
        assert!(!instance);
    }

    /// Every key of instance storage decodes to one of the six config keys.
    fn assert_instance_keys_are_config_only(fx: &Fx) {
        let all = fx
            .env
            .as_contract(&fx.contract, || fx.env.storage().instance().all());
        for (k, _v) in all.iter() {
            let key = DataKey::try_from_val(&fx.env, &k).expect("undecodable instance key");
            match key {
                DataKey::MultisigConfig
                | DataKey::WrappedUsdc
                | DataKey::MinLockDuration
                | DataKey::MinThreshold
                | DataKey::NextTimeLockId
                | DataKey::Paused => {}
                other => panic!("unexpected instance key {other:?}"),
            }
        }
    }

    #[test]
    fn test_instance_holds_only_config_keys() {
        let fx = deploy_default();
        let client = fx.client();
        assert_instance_keys_are_config_only(&fx);
        fx.seed(&fx.s1, 1_000);
        let q = fx.quorum();
        let a = client.schedule_unwrap(&q, &fx.s1, &200, &10);
        let b = client.schedule_transfer(&q, &fx.s1, &fx.s2, &200, &10);
        fx.advance(100);
        client.execute_unwrap(&q, &a);
        client.cancel_timelock(&q, &b);
        client.pause(&q);
        client.unpause(&q);
        let n1 = Address::generate(&fx.env);
        client.rotate_signers(&q, &vec![&fx.env, n1], &1);
        assert_instance_keys_are_config_only(&fx);
    }

    #[test]
    fn test_fresh_persistent_entry_reads_min_ttl_minus_one() {
        // Documents the testutils convention so nobody asserts 4096: a freshly
        // set persistent entry gets min_persistent_entry_ttl (4096) but
        // `get_ttl` excludes the current ledger. Uses a throwaway instance so
        // the fixture's conservation is untouched.
        let fx = deploy_default();
        let throwaway = register_wrapper(&fx.env, &fx.signers, 1, 1, &fx.token, &fx.issuer, 10);
        let probe = Address::generate(&fx.env);
        let ttl = fx.env.as_contract(&throwaway, || {
            fx.env
                .storage()
                .persistent()
                .set(&DataKey::Balance(probe.clone()), &1_i128);
            fx.env
                .storage()
                .persistent()
                .get_ttl(&DataKey::Balance(probe.clone()))
        });
        assert_eq!(ttl, 4095);
    }

    #[test]
    fn test_wrap_extends_balance_ttl() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 100);
        assert_eq!(
            fx.persistent_ttl(&DataKey::Balance(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
    }

    #[test]
    fn test_schedule_extends_timelock_and_reserved_ttl() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let id = fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        assert_eq!(
            fx.persistent_ttl(&DataKey::TimeLock(id)),
            PERSISTENT_TTL_EXTEND_TO
        );
        assert_eq!(
            fx.persistent_ttl(&DataKey::Reserved(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
    }

    #[test]
    fn test_wrap_touches_reserved() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        // Decay below the persistent threshold (464,800 remaining < 518,400).
        fx.decay(2_300_000);
        assert!(fx.persistent_ttl(&DataKey::Reserved(fx.s1.clone())) < PERSISTENT_TTL_THRESHOLD);
        fx.seed(&fx.s1, 100);
        assert_eq!(
            fx.persistent_ttl(&DataKey::Reserved(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
        assert_eq!(
            fx.persistent_ttl(&DataKey::Balance(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
    }

    #[test]
    fn test_bump_entry_ttl_extends_listed_keys() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let id = fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        fx.decay(2_300_000);
        assert!(fx.persistent_ttl(&DataKey::TimeLock(id)) < PERSISTENT_TTL_THRESHOLD);

        fx.client()
            .bump_entry_ttl(&vec![&fx.env, fx.s1.clone()], &vec![&fx.env, id]);

        assert_eq!(
            fx.persistent_ttl(&DataKey::Balance(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
        assert_eq!(
            fx.persistent_ttl(&DataKey::Reserved(fx.s1.clone())),
            PERSISTENT_TTL_EXTEND_TO
        );
        assert_eq!(
            fx.persistent_ttl(&DataKey::TimeLock(id)),
            PERSISTENT_TTL_EXTEND_TO
        );
        assert_eq!(fx.instance_ttl(), INSTANCE_TTL_EXTEND_TO);
    }

    #[test]
    fn test_bump_entry_ttl_skips_missing_keys() {
        let fx = deploy_default();
        let unknown = Address::generate(&fx.env);
        fx.client()
            .bump_entry_ttl(&vec![&fx.env, unknown], &vec![&fx.env, 42u64]);
    }

    #[test]
    #[should_panic(expected = "Bump batch too large")]
    fn test_bump_entry_ttl_batch_too_large() {
        let fx = deploy_default();
        let mut addresses = Vec::new(&fx.env);
        for _ in 0..16 {
            addresses.push_back(Address::generate(&fx.env));
        }
        let mut ids = Vec::new(&fx.env);
        for i in 0..17u64 {
            ids.push_back(i);
        }
        // 16 + 17 = 33 > MAX_BUMP_BATCH
        fx.client().bump_entry_ttl(&addresses, &ids);
    }

    #[test]
    fn test_timelock_ttl_clamped_to_network_max() {
        let fx = deploy_default();
        fx.seed(&fx.s1, 500);
        let id = fx.client().schedule_unwrap(&fx.quorum(), &fx.s1, &200, &10);
        // The network lowers its max entry TTL below the policy after deploy:
        // extensions are silently clamped to the network max.
        fx.env.ledger().set_max_entry_ttl(2_000_000);
        fx.decay(2_300_000);
        fx.client()
            .bump_entry_ttl(&vec![&fx.env, fx.s1.clone()], &vec![&fx.env, id]);
        assert_eq!(fx.persistent_ttl(&DataKey::TimeLock(id)), 2_000_000);
        assert_eq!(fx.client().max_entry_ttl(), 2_000_001);
    }

    #[test]
    fn test_bump_ttl_extends_instance() {
        let fx = deploy_default();
        // The constructor extends to the full target
        assert_eq!(fx.instance_ttl(), INSTANCE_TTL_EXTEND_TO);

        // Let the TTL decay below the threshold
        fx.decay(450_000);
        assert!(fx.instance_ttl() < INSTANCE_TTL_THRESHOLD);

        fx.client().bump_ttl();
        assert_eq!(fx.instance_ttl(), INSTANCE_TTL_EXTEND_TO);
    }

    #[test]
    fn test_mutating_op_extends_instance_ttl() {
        let fx = deploy_default();
        fx.decay(450_000);
        fx.client().pause(&fx.quorum());
        assert_eq!(fx.instance_ttl(), INSTANCE_TTL_EXTEND_TO);
    }

    // ==================================================================
    // Events (frozen ABI)
    // ==================================================================

    /// The last published event as `(contract, topics, data payload bits)`.
    /// Comparing raw payload bits pins the data's exact type tag (i128 vs
    /// i32 vs u64 vs u32) together with its value for the small immediates
    /// the contract emits; the topics compare deeply as host objects.
    fn last_event(env: &Env) -> (Address, Vec<Val>, u64) {
        let (contract, topics, data) = env.events().all().last().unwrap();
        (contract, topics, data.get_payload())
    }

    fn expected_event<T: IntoVal<Env, Vec<Val>>, D: IntoVal<Env, Val>>(
        env: &Env,
        contract: &Address,
        topics: T,
        data: D,
    ) -> (Address, Vec<Val>, u64) {
        let data: Val = data.into_val(env);
        (contract.clone(), topics.into_val(env), data.get_payload())
    }

    #[test]
    fn test_event_abi_pins() {
        let fx = deploy_default();
        let env = &fx.env;
        let c = &fx.contract;
        let client = fx.client();
        let q = fx.quorum();
        let d = Address::generate(env);
        fx.usdc().mint(&d, &1_000);

        client.wrap(&q, &d, &400);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("wrap"), d.clone()), 400i128)
        );

        // The host resets the event buffer on every top-level invocation, so
        // each event is captured before any further (read) call.
        let unw = client.schedule_unwrap(&q, &d, &100, &10);
        let ev_sched_unw = last_event(env);
        let unlock_unw = client.get_timelock(&unw).unlock_time;
        assert_eq!(
            ev_sched_unw,
            expected_event(
                env,
                c,
                (symbol_short!("sched_unw"), d.clone(), unw),
                unlock_unw
            )
        );

        let tx = client.schedule_transfer(&q, &d, &fx.s2, &50, &10);
        let ev_sched_tx = last_event(env);
        let unlock_tx = client.get_timelock(&tx).unlock_time;
        assert_eq!(
            ev_sched_tx,
            expected_event(
                env,
                c,
                (symbol_short!("sched_tx"), d.clone(), fx.s2.clone(), tx),
                unlock_tx
            )
        );

        let cancelled = client.schedule_unwrap(&q, &d, &10, &10);
        client.cancel_timelock(&q, &cancelled);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("cancel"), cancelled), 0i32)
        );

        fx.advance(100);
        client.execute_unwrap(&q, &unw);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("exec_unw"), d.clone(), unw), 100i128)
        );

        client.execute_transfer(&q, &tx);
        assert_eq!(
            last_event(env),
            expected_event(
                env,
                c,
                (symbol_short!("exec_tx"), d.clone(), fx.s2.clone(), tx),
                50i128
            )
        );

        client.pause(&q);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("pause"),), 0i32)
        );

        client.unpause(&q);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("unpause"),), 0i32)
        );

        let expired = client.schedule_unwrap(&q, &d, &10, &10);
        fx.advance(10 + EXECUTION_WINDOW);
        client.expire_timelock(&expired);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("expire"), expired), 0i32)
        );

        let n1 = Address::generate(env);
        client.rotate_signers(&q, &vec![env, n1], &1);
        assert_eq!(
            last_event(env),
            expected_event(env, c, (symbol_short!("rotate"),), 1u32)
        );

        fx.assert_conserved(&[&d, &fx.s2]);
    }

    // ==================================================================
    // Artifact gate (run by CI after the WASM build)
    // ==================================================================

    /// Proves the release artifact parses in the pinned host and that the
    /// constructor-argument encoding works end-to-end. Guards the
    /// rustc >= 1.82 `wasm32-unknown-unknown` post-MVP feature hazard.
    #[test]
    #[ignore]
    fn test_wasm_artifact_loads_in_pinned_host() {
        let path = std::env::var("IMPALA_WASM").expect("IMPALA_WASM");
        let wasm = std::fs::read(&path).expect("read IMPALA_WASM");
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let s1 = Address::generate(&env);
        let signers = vec![&env, s1.clone()];
        let contract = env.register(
            wasm.as_slice(),
            (
                signers.clone(),
                1u32,
                1u32,
                token.clone(),
                issuer.clone(),
                10u64,
            ),
        );
        let client = MultisigUsdcWrapperClient::new(&env, &contract);
        let usdc = MockUsdcClient::new(&env, &token);

        assert_eq!(client.usdc_issuer(), issuer);
        assert_eq!(client.usdc_token(), token);
        assert_eq!(client.min_threshold(), 1);

        let holder = Address::generate(&env);
        usdc.mint(&holder, &1_000);
        client.wrap(&signers, &holder, &600);
        let id = client.schedule_unwrap(&signers, &holder, &250, &10);
        env.ledger().with_mut(|li| li.timestamp += 100);
        client.execute_unwrap(&signers, &id);

        assert_eq!(client.balance(&holder), 350);
        assert_eq!(client.reserved(&holder), 0);
        assert_eq!(client.total_supply(), 350);
        assert_eq!(usdc.balance(&contract), 350);
        assert_eq!(usdc.balance(&holder), 650);
    }
}

#[cfg(test)]
mod invariants;
