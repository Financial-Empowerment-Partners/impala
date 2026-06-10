//! MultisigUsdcWrapper — a Soroban smart contract that wraps Circle's USDC
//! Stellar asset with multisig authorization and time-locked operations.
//!
//! # Design
//!
//! The contract holds USDC (via its Stellar Asset Contract) on behalf of
//! users. Deposits (`wrap`) are immediate, but withdrawals (`unwrap`) and
//! inter-account transfers require a two-phase schedule/execute pattern with
//! a configurable minimum delay, giving signers time to detect and cancel
//! unauthorized operations.
//!
//! The USDC SAC address differs per network, so it is an `initialize`
//! argument rather than a hardcoded constant. `initialize` validates that the
//! token looks like USDC (`symbol() == "USDC"` and `decimals() == 7`) before
//! writing any state. Honest limitation: the asset *issuer* is not verifiable
//! on-chain from inside the contract, so these checks guard against
//! misconfiguration, not against a malicious deployer pointing the contract
//! at a look-alike token.
//!
//! All mutating operations require multisig: at least `threshold` signers
//! from the authorized list must call `require_auth()`.
//!
//! # Over-scheduling
//!
//! Scheduling does **not** reserve balance. The balance check at schedule
//! time is advisory only: multiple pending timelocks may be scheduled
//! against the same balance, and the authoritative check happens at
//! execution time. Over-scheduled operations simply fail when executed —
//! funds can never be over-withdrawn, but a scheduled operation is not a
//! guarantee that the balance will still be available at execution.
//!
//! # Storage
//!
//! All state is stored at the instance level via `env.storage().instance()`.
//! Every mutating entry point extends the instance TTL; `bump_ttl` allows
//! anyone to extend it without mutating state. Executed and cancelled
//! timelock entries are removed from instance storage (replay attempts fail
//! with "Timelock not found"), so the instance does not accumulate rent for
//! finished operations.

#![no_std]
// soroban-sdk 23.x deprecates `env.events().publish(...)` in favour of the
// #[contractevent] macro. Migrating changes the emitted event ABI (topics/data
// shape) that off-chain consumers depend on, so it is a deliberate, separately
// coordinated change — not a lint fix. Keep the current event ABI and silence the
// deprecation here. Tracked as a follow-up.
#![allow(deprecated)]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Vec,
};

/// Configuration for the multisig signer set.
#[contracttype]
pub struct MultisigConfig {
    /// Authorized signer addresses.
    pub signers: Vec<Address>,
    /// Minimum number of signers required to authorize an operation.
    pub threshold: u32,
}

/// Tracks the underlying USDC token and total amount wrapped by the contract.
#[contracttype]
pub struct WrappedUsdc {
    /// Address of the USDC Stellar Asset Contract on this network.
    pub usdc_token: Address,
    /// Decimals of the USDC token (validated to be 7 at initialization).
    pub decimals: u32,
    /// Total amount of wrapped USDC across all balances (in stroops).
    pub total_wrapped: i128,
}

/// Represents a pending time-locked operation that becomes executable
/// after `unlock_time` has passed.
#[contracttype]
pub struct TimeLock {
    /// Operation type: 1=unwrap, 2=transfer.
    pub operation_type: u32,
    /// Signers who authorized the scheduling of this operation.
    pub signers: Vec<Address>,
    /// Source address whose balance is debited (sender for transfers, balance holder for unwraps).
    pub sender: Address,
    /// Recipient address for the operation's output.
    pub recipient: Address,
    /// Token amount involved in the operation.
    pub amount: i128,
    /// Ledger timestamp (seconds) after which the operation can be executed.
    pub unlock_time: u64,
    /// Reentrancy guard: set to true just before the execute path performs
    /// balance updates / external calls. Entries are removed from storage
    /// once executed or cancelled, so stored pending timelocks are always
    /// `false` outside that in-flight window.
    pub executed: bool,
}

/// Storage keys for contract state.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    MultisigConfig,
    WrappedUsdc,
    /// Per-address wrapped token balance.
    Balance(Address),
    Initialized,
    /// Time-locked operation, keyed by sequential ID.
    TimeLock(u64),
    NextTimeLockId,
    MinLockDuration,
    /// Whether the contract is paused.
    Paused,
}

/// Maximum allowed delay for timelocked operations (365 days in seconds).
const MAX_LOCK_DURATION: u64 = 31_536_000;

/// USDC always has 7 decimals on Stellar; enforced at initialization.
const USDC_DECIMALS: u32 = 7;

/// Maximum size of the authorized signer set (multisig verification is
/// O(provided x configured), so keep the set small and bounded).
const MAX_SIGNERS: u32 = 20;

/// Extend the instance TTL when fewer than ~7 days of ledgers remain
/// (17,280 ledgers/day at 5s per ledger).
const INSTANCE_TTL_THRESHOLD: u32 = 7 * 17_280;

/// Extend the instance TTL to ~30 days of ledgers.
const INSTANCE_TTL_EXTEND_TO: u32 = 30 * 17_280;

#[contract]
pub struct MultisigUsdcWrapper;

#[contractimpl]
impl MultisigUsdcWrapper {
    /// One-time setup: signer set, threshold, the network's USDC SAC address,
    /// and the minimum lock duration (in seconds) for scheduled operations.
    ///
    /// Validates that `usdc_token` looks like USDC (`symbol() == "USDC"`,
    /// `decimals() == 7`) before writing any state. The issuer cannot be
    /// verified on-chain; this guards misconfiguration, not a malicious
    /// deployer.
    pub fn initialize(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
        usdc_token: Address,
        min_lock_duration: u64,
    ) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic!("Already initialized");
        }

        if threshold == 0 || threshold > signers.len() {
            panic!("Invalid threshold");
        }

        if signers.len() > MAX_SIGNERS {
            panic!("Too many signers");
        }

        // A duplicated signer in the config could make the threshold
        // unsatisfiable (verify_multisig rejects duplicate provided signers),
        // bricking the contract. Reject at configuration time.
        Self::require_no_duplicates(&signers);

        // A minimum above the maximum would make every schedule call panic.
        if min_lock_duration > MAX_LOCK_DURATION {
            panic!("Min lock duration exceeds maximum");
        }

        // Validate the token is USDC before writing any state.
        let token_client = token::Client::new(&env, &usdc_token);
        if token_client.symbol() != String::from_str(&env, "USDC") {
            panic!("Underlying token is not USDC");
        }
        let decimals = token_client.decimals();
        if decimals != USDC_DECIMALS {
            panic!("USDC token must have 7 decimals");
        }

        let config = MultisigConfig { signers, threshold };
        env.storage()
            .instance()
            .set(&DataKey::MultisigConfig, &config);

        let wrapped_usdc = WrappedUsdc {
            usdc_token,
            decimals,
            total_wrapped: 0,
        };
        env.storage()
            .instance()
            .set(&DataKey::WrappedUsdc, &wrapped_usdc);
        env.storage()
            .instance()
            .set(&DataKey::MinLockDuration, &min_lock_duration);
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &0u64);
        env.storage().instance().set(&DataKey::Initialized, &true);

        Self::extend_instance_ttl(&env);
    }

    /// Extend the instance storage TTL. Permissionless: anyone may pay the
    /// rent to keep the contract instance (and all balances/timelocks stored
    /// in it) alive.
    pub fn bump_ttl(env: Env) {
        Self::extend_instance_ttl(&env);
    }

    /// Pause the contract (requires multisig). Blocks all operations except cancel_timelock.
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

    /// Rotate the authorized signer set (requires current multisig).
    pub fn rotate_signers(
        env: Env,
        current_signers: Vec<Address>,
        new_signers: Vec<Address>,
        new_threshold: u32,
    ) {
        if new_signers.is_empty() {
            panic!("New signers must not be empty");
        }
        if new_threshold == 0 || new_threshold > new_signers.len() {
            panic!("Invalid new threshold");
        }
        if new_signers.len() > MAX_SIGNERS {
            panic!("Too many signers");
        }
        // Same bricking hazard as in initialize: a duplicated signer in the
        // new config could make the new threshold unsatisfiable.
        Self::require_no_duplicates(&new_signers);

        Self::verify_multisig(&env, &current_signers);
        Self::extend_instance_ttl(&env);

        let config = MultisigConfig {
            signers: new_signers,
            threshold: new_threshold,
        };
        env.storage()
            .instance()
            .set(&DataKey::MultisigConfig, &config);

        env.events()
            .publish((symbol_short!("rotate"),), new_threshold);
    }

    /// Wrap tokens (immediate execution, no timelock).
    ///
    /// `depositor` supplies the underlying tokens and is credited with the
    /// wrapped balance. It must authorize the call (for the token transfer)
    /// in addition to the multisig signer set, but does not need to be an
    /// authorized signer itself.
    pub fn wrap(env: Env, signers: Vec<Address>, depositor: Address, amount: i128) {
        Self::require_not_paused(&env);

        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);
        depositor.require_auth();
        Self::extend_instance_ttl(&env);

        let mut wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();

        let token_client = token::Client::new(&env, &wrapped_usdc.usdc_token);
        let contract_address = env.current_contract_address();

        token_client.transfer(&depositor, &contract_address, &amount);

        let balance_key = DataKey::Balance(depositor.clone());
        let current_balance: i128 = env.storage().instance().get(&balance_key).unwrap_or(0);

        let new_balance = current_balance
            .checked_add(amount)
            .expect("Balance overflow");
        env.storage().instance().set(&balance_key, &new_balance);

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

    /// Schedule a time-locked unwrap operation.
    ///
    /// The balance check here is advisory: the scheduled amount is not
    /// reserved, so the same balance can back multiple pending timelocks.
    /// The authoritative balance check happens in `execute_unwrap`.
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

        let balance_key = DataKey::Balance(recipient.clone());
        let current_balance: i128 = env.storage().instance().get(&balance_key).unwrap_or(0);

        if current_balance < amount {
            panic!("Insufficient wrapped balance");
        }

        let timelock_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextTimeLockId)
            .unwrap();

        let unlock_time = env
            .ledger()
            .timestamp()
            .checked_add(delay_seconds)
            .expect("Unlock time overflow");

        let timelock = TimeLock {
            operation_type: 1, // unwrap
            signers: signers.clone(),
            sender: recipient.clone(),
            recipient: recipient.clone(),
            amount,
            unlock_time,
            executed: false,
        };

        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        let next_id = timelock_id.checked_add(1).expect("Timelock id overflow");
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &next_id);

        env.events().publish(
            (symbol_short!("sched_unw"), recipient, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Execute a time-locked unwrap operation
    pub fn execute_unwrap(env: Env, timelock_id: u64) {
        Self::require_not_paused(&env);

        let mut timelock: TimeLock = env
            .storage()
            .instance()
            .get(&DataKey::TimeLock(timelock_id))
            .expect("Timelock not found");

        if timelock.executed {
            panic!("Already executed");
        }

        if env.ledger().timestamp() < timelock.unlock_time {
            panic!("Timelock not expired");
        }

        // Verify original signers still authorize this
        Self::verify_multisig(&env, &timelock.signers);
        Self::extend_instance_ttl(&env);

        let balance_key = DataKey::Balance(timelock.recipient.clone());
        let current_balance: i128 = env.storage().instance().get(&balance_key).unwrap_or(0);

        if current_balance < timelock.amount {
            panic!("Insufficient balance");
        }

        // Mark as executed BEFORE external calls (reentrancy prevention)
        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        let mut wrapped_usdc: WrappedUsdc =
            env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();

        // Burn wrapped tokens
        let new_balance = current_balance
            .checked_sub(timelock.amount)
            .expect("Balance underflow");
        env.storage().instance().set(&balance_key, &new_balance);

        // Transfer underlying tokens
        let token_client = token::Client::new(&env, &wrapped_usdc.usdc_token);
        let contract_address = env.current_contract_address();

        token_client.transfer(&contract_address, &timelock.recipient, &timelock.amount);

        wrapped_usdc.total_wrapped = wrapped_usdc
            .total_wrapped
            .checked_sub(timelock.amount)
            .expect("Total supply underflow");
        env.storage()
            .instance()
            .set(&DataKey::WrappedUsdc, &wrapped_usdc);

        // The entry was marked executed before the external transfer
        // (reentrancy prevention). The operation is now complete, so prune
        // the entry from instance storage: replay attempts fail with
        // "Timelock not found" and the storage rent is reclaimed.
        env.storage()
            .instance()
            .remove(&DataKey::TimeLock(timelock_id));

        env.events().publish(
            (symbol_short!("exec_unw"), timelock.recipient, timelock_id),
            timelock.amount,
        );
    }

    /// Schedule a time-locked transfer.
    ///
    /// The balance check here is advisory: the scheduled amount is not
    /// reserved, so the same balance can back multiple pending timelocks.
    /// The authoritative balance check happens in `execute_transfer`.
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

        let from_key = DataKey::Balance(from.clone());
        let from_balance: i128 = env.storage().instance().get(&from_key).unwrap_or(0);

        if from_balance < amount {
            panic!("Insufficient balance");
        }

        let timelock_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextTimeLockId)
            .unwrap();

        let unlock_time = env
            .ledger()
            .timestamp()
            .checked_add(delay_seconds)
            .expect("Unlock time overflow");

        let timelock = TimeLock {
            operation_type: 2, // transfer
            signers: signers.clone(),
            sender: from.clone(),
            recipient: to.clone(),
            amount,
            unlock_time,
            executed: false,
        };

        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        let next_id = timelock_id.checked_add(1).expect("Timelock id overflow");
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &next_id);

        env.events().publish(
            (symbol_short!("sched_tx"), from, to, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Execute a time-locked transfer using the sender stored at schedule time.
    pub fn execute_transfer(env: Env, timelock_id: u64) {
        Self::require_not_paused(&env);

        let mut timelock: TimeLock = env
            .storage()
            .instance()
            .get(&DataKey::TimeLock(timelock_id))
            .expect("Timelock not found");

        if timelock.executed {
            panic!("Already executed");
        }

        if env.ledger().timestamp() < timelock.unlock_time {
            panic!("Timelock not expired");
        }

        Self::verify_multisig(&env, &timelock.signers);
        Self::extend_instance_ttl(&env);

        let from_key = DataKey::Balance(timelock.sender.clone());
        let to_key = DataKey::Balance(timelock.recipient.clone());

        let from_balance: i128 = env.storage().instance().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().instance().get(&to_key).unwrap_or(0);

        if from_balance < timelock.amount {
            panic!("Insufficient balance");
        }

        // Mark as executed BEFORE state changes (reentrancy prevention)
        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        let new_from = from_balance
            .checked_sub(timelock.amount)
            .expect("Balance underflow");
        let new_to = to_balance
            .checked_add(timelock.amount)
            .expect("Balance overflow");
        env.storage().instance().set(&from_key, &new_from);
        env.storage().instance().set(&to_key, &new_to);

        // Operation complete — prune the entry from instance storage so
        // replay attempts fail with "Timelock not found" and rent is
        // reclaimed.
        env.storage()
            .instance()
            .remove(&DataKey::TimeLock(timelock_id));

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

    /// Cancel a pending timelock (requires multisig)
    pub fn cancel_timelock(env: Env, signers: Vec<Address>, timelock_id: u64) {
        Self::verify_multisig(&env, &signers);
        Self::extend_instance_ttl(&env);

        let timelock: TimeLock = env
            .storage()
            .instance()
            .get(&DataKey::TimeLock(timelock_id))
            .expect("Timelock not found");

        // Defense in depth for the execute in-flight window (the entry is
        // marked executed for the duration of the external transfer).
        if timelock.executed {
            panic!("Already executed");
        }

        // Remove the entry instead of flagging it: re-cancellation and
        // execution both fail with "Timelock not found", and the storage
        // rent is reclaimed.
        env.storage()
            .instance()
            .remove(&DataKey::TimeLock(timelock_id));

        env.events()
            .publish((symbol_short!("cancel"), timelock_id), 0);
    }

    /// Get timelock details
    pub fn get_timelock(env: Env, timelock_id: u64) -> TimeLock {
        env.storage()
            .instance()
            .get(&DataKey::TimeLock(timelock_id))
            .expect("Timelock not found")
    }

    /// Query the wrapped token balance for a given address.
    pub fn balance(env: Env, address: Address) -> i128 {
        let balance_key = DataKey::Balance(address);
        env.storage().instance().get(&balance_key).unwrap_or(0)
    }

    /// Query the total wrapped token supply across all addresses.
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

    /// Extend the instance TTL so the contract (and all instance-stored
    /// balances/timelocks) does not expire while in active use.
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
    /// `initialize`/`rotate_signers` (where a duplicate could make the
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
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, vec, Env};

    /// Minimal mock USDC token for unit tests.
    ///
    /// soroban-sdk 23.5.3's `register_stellar_asset_contract_v2` hardcodes
    /// the test SAC's asset code to `aaa`, so a USDC-labelled SAC cannot be
    /// created via testutils (that SAC is used as the negative test instead).
    /// Soroban token calls dispatch dynamically by function name, so
    /// `token::Client` works against this mock. Only the functions the
    /// contract and the tests actually call are implemented.
    #[contract]
    pub struct MockUsdc;

    #[contracttype]
    #[derive(Clone)]
    pub enum MockUsdcKey {
        Symbol,
        Decimals,
        Balance(Address),
    }

    #[contractimpl]
    impl MockUsdc {
        pub fn __constructor(env: Env, symbol: String, decimals: u32) {
            env.storage().instance().set(&MockUsdcKey::Symbol, &symbol);
            env.storage()
                .instance()
                .set(&MockUsdcKey::Decimals, &decimals);
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

    fn setup_env() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigUsdcWrapper, ());
        let token_admin = Address::generate(&env);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        (env, contract_id, token_admin, signer1, signer2)
    }

    /// Register a mock USDC token (`symbol() == "USDC"`, 7 decimals).
    fn create_usdc_token(env: &Env) -> Address {
        env.register(MockUsdc, (String::from_str(env, "USDC"), 7u32))
    }

    fn init_contract(
        env: &Env,
        contract_id: &Address,
        token_addr: &Address,
        signer1: &Address,
        signer2: &Address,
    ) {
        let client = MultisigUsdcWrapperClient::new(env, contract_id);
        let signers = vec![env, signer1.clone(), signer2.clone()];
        client.initialize(&signers, &1, token_addr, &10);
    }

    #[test]
    fn test_initialize_sets_state() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 0);
        assert_eq!(client.balance(&s2), 0);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_double_initialize_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);
        // Second init should panic
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_zero_threshold_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &0, &token_addr, &10);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_threshold_exceeding_signers_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &3, &token_addr, &10);
    }

    #[test]
    fn test_total_supply_zero_after_init() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_balance_defaults_to_zero() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let unknown = Address::generate(&env);
        assert_eq!(client.balance(&unknown), 0);
    }

    #[test]
    fn test_balance_zero_for_all_signers_after_init() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 0);
        assert_eq!(client.balance(&s2), 0);
    }

    #[test]
    fn test_init_with_single_signer_threshold_one() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigUsdcWrapper, ());
        let signer = Address::generate(&env);
        let token_addr = create_usdc_token(&env);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, signer.clone()];
        client.initialize(&signers, &1, &token_addr, &60);

        assert_eq!(client.balance(&signer), 0);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_init_with_max_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigUsdcWrapper, ());
        let s1 = Address::generate(&env);
        let s2 = Address::generate(&env);
        let s3 = Address::generate(&env);
        let token_addr = create_usdc_token(&env);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone(), s3.clone()];
        // threshold == signers.len() is valid
        client.initialize(&signers, &3, &token_addr, &10);

        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_unwrap_insufficient_signers() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);

        // Initialize with threshold=2
        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &2, &token_addr, &10);

        // Provide only 1 signer when 2 are required
        let insufficient = vec![&env, s1.clone()];
        client.schedule_unwrap(&insufficient, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Insufficient wrapped balance")]
    fn test_schedule_unwrap_zero_balance() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // No tokens wrapped — balance is 0
        client.schedule_unwrap(&signers, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Delay too short")]
    fn test_schedule_unwrap_delay_below_minimum() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance directly via storage to bypass wrap's auth issue
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // min_lock_duration is 10, providing 5
        client.schedule_unwrap(&signers, &s1, &100, &5);
    }

    #[test]
    fn test_schedule_unwrap_creates_timelock() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance via direct storage access
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &1000_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 1000;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        assert_eq!(tl_id, 0);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 1);
        assert_eq!(tl.amount, 200);
        assert!(!tl.executed);
    }

    #[test]
    fn test_cancel_timelock_removes_entry() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);

        let exists_before = env.as_contract(&contract_id, || {
            env.storage().instance().has(&DataKey::TimeLock(tl_id))
        });
        assert!(exists_before, "Scheduled timelock entry should be stored");

        client.cancel_timelock(&signers, &tl_id);

        // Cancelled timelocks are pruned from instance storage entirely.
        let exists_after = env.as_contract(&contract_id, || {
            env.storage().instance().has(&DataKey::TimeLock(tl_id))
        });
        assert!(
            !exists_after,
            "Cancelled timelock entry should be removed from storage"
        );
    }

    #[test]
    fn test_schedule_transfer_creates_timelock() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 2);
        assert_eq!(tl.amount, 100);
        assert!(!tl.executed);
    }

    #[test]
    fn test_timelock_ids_are_sequential() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a large balance
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &5000_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 5000;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];

        let id0 = client.schedule_unwrap(&signers, &s1, &100, &10);
        let id1 = client.schedule_unwrap(&signers, &s1, &100, &10);
        let id2 = client.schedule_transfer(&signers, &s1, &s2, &100, &10);

        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    #[should_panic(expected = "Insufficient balance")]
    fn test_schedule_transfer_insufficient_balance() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // s1 has no balance — should panic
        client.schedule_transfer(&signers, &s1, &s2, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_get_timelock_nonexistent() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        client.get_timelock(&99);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_zero_amount_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_unwrap(&signers, &s1, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_zero_amount_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_transfer(&signers, &s1, &s2, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_negative_amount_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_transfer(&signers, &s1, &s2, &-100, &10);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_verify_multisig_rejects_unauthorized_signer() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let unauthorized = Address::generate(&env);
        // Include an unauthorized address in the signer list
        let signers = vec![&env, unauthorized.clone()];
        client.schedule_unwrap(&signers, &s1, &100, &10);
    }

    #[test]
    fn test_schedule_transfer_stores_sender() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.sender, s1);
        assert_eq!(tl.recipient, s2);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_cancel_already_cancelled_timelock_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        client.cancel_timelock(&signers, &tl_id);
        // Second cancel should panic: the entry was pruned on the first one
        client.cancel_timelock(&signers, &tl_id);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_transfer_insufficient_signers() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);

        // Initialize with threshold=2
        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &2, &token_addr, &10);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        // Only 1 signer provided when 2 are required
        let insufficient = vec![&env, s1.clone()];
        client.schedule_transfer(&insufficient, &s1, &s2, &100, &10);
    }

    #[test]
    fn test_multiple_balances_independent() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed different balances for s1 and s2
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &1000_i128);
            env.storage()
                .instance()
                .set(&DataKey::Balance(s2.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 1500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 1000);
        assert_eq!(client.balance(&s2), 500);
        assert_eq!(client.total_supply(), 1500);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_negative_amount_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_unwrap(&signers, &s1, &-50, &10);
    }

    #[test]
    fn test_schedule_unwrap_exact_balance() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &300_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 300;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // Unwrap exactly the full balance — should succeed
        let tl_id = client.schedule_unwrap(&signers, &s1, &300, &10);
        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.amount, 300);
    }

    #[test]
    #[should_panic(expected = "Insufficient wrapped balance")]
    fn test_schedule_unwrap_exceeds_balance() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &300_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 300;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // Attempt to unwrap more than balance
        client.schedule_unwrap(&signers, &s1, &301, &10);
    }

    // ---- New tests ----

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_wrap_zero_amount_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.wrap(&signers, &s1, &0);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_duplicate_signers_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        // Pass duplicate addresses
        let signers = vec![&env, s1.clone(), s1.clone()];
        client.schedule_unwrap(&signers, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_cancel_prevents_execution() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        client.cancel_timelock(&signers, &tl_id);

        // Advance time past the unlock
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        // Try to execute cancelled timelock — should panic (entry pruned)
        client.execute_unwrap(&tl_id);
    }

    #[test]
    #[should_panic(expected = "Self-transfer not allowed")]
    fn test_self_transfer_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // from == to should panic
        client.schedule_transfer(&signers, &s1, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Delay exceeds maximum lock duration")]
    fn test_delay_too_long_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // MAX_LOCK_DURATION is 31_536_000; exceed it
        client.schedule_unwrap(&signers, &s1, &100, &31_536_001);
    }

    #[test]
    #[should_panic(expected = "Contract is paused")]
    fn test_pause_blocks_wrap() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];

        // Pause the contract
        client.pause(&signers);

        // Try to wrap — should panic
        client.wrap(&signers, &s1, &100);
    }

    #[test]
    fn test_unpause_allows_operations() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        // Pause then unpause
        client.pause(&signers);
        client.unpause(&signers);

        // schedule_unwrap should succeed after unpause
        let tl_id = client.schedule_unwrap(&signers, &s1, &100, &10);
        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.amount, 100);
        assert!(!tl.executed);
    }

    #[test]
    fn test_cancel_still_works_while_paused() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];

        // Schedule a timelock before pausing
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);

        // Pause the contract
        client.pause(&signers);

        // Cancel should still work while paused
        client.cancel_timelock(&signers, &tl_id);

        // The cancelled entry is pruned from storage even while paused.
        let exists = env.as_contract(&contract_id, || {
            env.storage().instance().has(&DataKey::TimeLock(tl_id))
        });
        assert!(!exists);
    }

    #[test]
    fn test_rotate_signers() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let current_signers = vec![&env, s1.clone()];

        // Generate new signers
        let new_s1 = Address::generate(&env);
        let new_s2 = Address::generate(&env);
        let new_signers = vec![&env, new_s1.clone(), new_s2.clone()];

        // Rotate
        client.rotate_signers(&current_signers, &new_signers, &1);

        // Seed a balance for new_s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(new_s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        // New signers should be able to operate
        let new_signer_vec = vec![&env, new_s1.clone()];
        let tl_id = client.schedule_unwrap(&new_signer_vec, &new_s1, &100, &10);
        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.amount, 100);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_rotate_signers_old_signers_rejected() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let current_signers = vec![&env, s1.clone()];

        // Generate new signers
        let new_s1 = Address::generate(&env);
        let new_signers = vec![&env, new_s1.clone()];

        // Rotate
        client.rotate_signers(&current_signers, &new_signers, &1);

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        // Old signer should be rejected
        let old_signer_vec = vec![&env, s1.clone()];
        client.schedule_unwrap(&old_signer_vec, &s1, &100, &10);
    }

    #[test]
    fn test_execute_transfer_with_time_advancement() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &200, &10);

        // Advance ledger time past the unlock
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        client.execute_transfer(&tl_id);

        assert_eq!(client.balance(&s1), 300);
        assert_eq!(client.balance(&s2), 200);

        // Executed timelocks are pruned from instance storage.
        let exists = env.as_contract(&contract_id, || {
            env.storage().instance().has(&DataKey::TimeLock(tl_id))
        });
        assert!(
            !exists,
            "Executed timelock entry should be removed from storage"
        );
    }

    #[test]
    #[should_panic(expected = "Timelock not expired")]
    fn test_execute_transfer_before_unlock_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &200, &10);

        // Do NOT advance time — try to execute immediately
        client.execute_transfer(&tl_id);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_double_execute_transfer_panics() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedUsdc = env.storage().instance().get(&DataKey::WrappedUsdc).unwrap();
            wa.total_wrapped = 500;
            env.storage().instance().set(&DataKey::WrappedUsdc, &wa);
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &200, &10);

        // Advance time past the unlock
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        // Execute once — should succeed
        client.execute_transfer(&tl_id);

        // Execute again — should panic (entry pruned on first execution)
        client.execute_transfer(&tl_id);
    }

    #[test]
    fn test_wrap_credits_depositor() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Depositor is not an authorized signer
        let depositor = Address::generate(&env);
        let usdc = MockUsdcClient::new(&env, &token_addr);
        usdc.mint(&depositor, &1_000);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.wrap(&signers, &depositor, &400);

        assert_eq!(client.balance(&depositor), 400);
        assert_eq!(client.balance(&s1), 0);
        assert_eq!(client.total_supply(), 400);

        let token_client = token::Client::new(&env, &token_addr);
        assert_eq!(token_client.balance(&depositor), 600);
        assert_eq!(token_client.balance(&contract_id), 400);
    }

    #[test]
    fn test_bump_ttl_extends_instance() {
        use soroban_sdk::testutils::storage::Instance as _;

        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // initialize() extends to the full target
        let after_init = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert_eq!(after_init, INSTANCE_TTL_EXTEND_TO);

        // Let the TTL decay below the threshold
        env.ledger().with_mut(|li| {
            li.sequence_number += 450_000;
        });
        let decayed = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert!(decayed < INSTANCE_TTL_THRESHOLD);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        client.bump_ttl();

        let bumped = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert_eq!(bumped, INSTANCE_TTL_EXTEND_TO);
    }

    #[test]
    fn test_mutating_op_extends_instance_ttl() {
        use soroban_sdk::testutils::storage::Instance as _;

        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.ledger().with_mut(|li| {
            li.sequence_number += 450_000;
        });

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.pause(&signers);

        let bumped = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert_eq!(bumped, INSTANCE_TTL_EXTEND_TO);
    }

    // ---- USDC-specific tests ----

    #[test]
    fn test_initialize_records_usdc_token_and_decimals() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        assert_eq!(client.usdc_token(), token_addr);
        assert_eq!(client.usdc_decimals(), USDC_DECIMALS);
    }

    #[test]
    #[should_panic(expected = "Underlying token is not USDC")]
    fn test_initialize_rejects_non_usdc_token() {
        let (env, contract_id, token_admin, s1, s2) = setup_env();
        // The SDK's test SAC hardcodes the asset code "aaa" — not USDC.
        let sac = env.register_stellar_asset_contract_v2(token_admin);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &1, &sac.address(), &10);
    }

    #[test]
    #[should_panic(expected = "USDC token must have 7 decimals")]
    fn test_initialize_rejects_wrong_decimals() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        // Right symbol, wrong decimals (e.g. Ethereum-style 6-decimal USDC).
        let token_addr = env.register(MockUsdc, (String::from_str(&env, "USDC"), 6u32));

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &1, &token_addr, &10);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_initialize_rejects_duplicate_signers() {
        let (env, contract_id, _admin, s1, _s2) = setup_env();
        let token_addr = create_usdc_token(&env);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        // [s1, s1] with threshold 2 would brick the contract: verify_multisig
        // rejects duplicate provided signers, so the threshold could never be
        // met by any call.
        let signers = vec![&env, s1.clone(), s1.clone()];
        client.initialize(&signers, &2, &token_addr, &10);
    }

    #[test]
    #[should_panic(expected = "Min lock duration exceeds maximum")]
    fn test_initialize_rejects_min_lock_above_max() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        // A minimum above MAX_LOCK_DURATION would make every schedule call
        // panic ("Delay too short" vs "Delay exceeds maximum" can never both
        // pass), bricking scheduling entirely.
        client.initialize(&signers, &1, &token_addr, &(MAX_LOCK_DURATION + 1));
    }

    #[test]
    #[should_panic(expected = "Too many signers")]
    fn test_initialize_rejects_too_many_signers() {
        let (env, contract_id, _admin, _s1, _s2) = setup_env();
        let token_addr = create_usdc_token(&env);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let mut signers = Vec::new(&env);
        for _ in 0..(MAX_SIGNERS + 1) {
            signers.push_back(Address::generate(&env));
        }
        client.initialize(&signers, &1, &token_addr, &10);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer detected")]
    fn test_rotate_signers_rejects_duplicates() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let current = vec![&env, s1.clone()];
        let dup = Address::generate(&env);
        let new_signers = vec![&env, dup.clone(), dup.clone()];
        client.rotate_signers(&current, &new_signers, &2);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_usdc() {
        let (env, contract_id, _admin, s1, s2) = setup_env();
        let token_addr = create_usdc_token(&env);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let depositor = Address::generate(&env);
        let usdc = MockUsdcClient::new(&env, &token_addr);
        // 1 USDC = 10_000_000 stroops (7 decimals)
        usdc.mint(&depositor, &10_000_000);

        let client = MultisigUsdcWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];

        // Wrap 0.5 USDC
        client.wrap(&signers, &depositor, &5_000_000);
        assert_eq!(usdc.balance(&depositor), 5_000_000);
        assert_eq!(usdc.balance(&contract_id), 5_000_000);
        assert_eq!(client.balance(&depositor), 5_000_000);
        assert_eq!(client.total_supply(), 5_000_000);

        // Schedule and (after the delay) execute an unwrap of the full amount
        let tl_id = client.schedule_unwrap(&signers, &depositor, &5_000_000, &10);
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });
        client.execute_unwrap(&tl_id);

        // USDC flowed back out to the depositor in full
        assert_eq!(usdc.balance(&depositor), 10_000_000);
        assert_eq!(usdc.balance(&contract_id), 0);
        assert_eq!(client.balance(&depositor), 0);
        assert_eq!(client.total_supply(), 0);

        // Executed timelock entry is pruned from instance storage
        let exists = env.as_contract(&contract_id, || {
            env.storage().instance().has(&DataKey::TimeLock(tl_id))
        });
        assert!(!exists);
    }
}
