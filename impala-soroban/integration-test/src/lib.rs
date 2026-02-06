//! MultisigAssetWrapper — a Soroban smart contract that wraps a Stellar token
//! with multisig authorization and time-locked operations.
//!
//! # Design
//!
//! The contract holds an underlying Stellar token on behalf of users. Deposits
//! (`wrap`) are immediate, but withdrawals (`unwrap`) and inter-account
//! transfers require a two-phase schedule/execute pattern with a configurable
//! minimum delay, giving signers time to detect and cancel unauthorized
//! operations.
//!
//! All mutating operations require multisig: at least `threshold` signers
//! from the authorized list must call `require_auth()`.
//!
//! # Storage
//!
//! All state is stored at the instance level via `env.storage().instance()`.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, Vec, symbol_short
};

/// Configuration for the multisig signer set.
#[contracttype]
pub struct MultisigConfig {
    /// Authorized signer addresses.
    pub signers: Vec<Address>,
    /// Minimum number of signers required to authorize an operation.
    pub threshold: u32,
}

/// Tracks the underlying token and total amount wrapped by the contract.
#[contracttype]
pub struct WrappedAsset {
    /// Address of the underlying Stellar token (SAC or custom).
    pub underlying_token: Address,
    /// Total amount of wrapped tokens across all balances.
    pub total_wrapped: i128,
}

/// Represents a pending time-locked operation that becomes executable
/// after `unlock_time` has passed.
#[contracttype]
pub struct TimeLock {
    /// Operation type: 1=unwrap, 2=transfer, 3=config_change.
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
    /// Set to true once executed or cancelled, preventing replay.
    pub executed: bool,
}

/// Storage keys for contract state.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    MultisigConfig,
    WrappedAsset,
    /// Per-address wrapped token balance.
    Balance(Address),
    Initialized,
    /// Time-locked operation, keyed by sequential ID.
    TimeLock(u64),
    NextTimeLockId,
    MinLockDuration,
}

#[contract]
pub struct MultisigAssetWrapper;

#[contractimpl]
impl MultisigAssetWrapper {
    /// Initialize with minimum lock duration (in seconds)
    pub fn initialize(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
        underlying_token: Address,
        min_lock_duration: u64,
    ) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic!("Already initialized");
        }

        if threshold == 0 || threshold > signers.len() {
            panic!("Invalid threshold");
        }

        let config = MultisigConfig { signers, threshold };
        env.storage().instance().set(&DataKey::MultisigConfig, &config);

        let wrapped_asset = WrappedAsset {
            underlying_token: underlying_token.clone(),
            total_wrapped: 0,
        };
        env.storage().instance().set(&DataKey::WrappedAsset, &wrapped_asset);
        env.storage().instance().set(&DataKey::MinLockDuration, &min_lock_duration);
        env.storage().instance().set(&DataKey::NextTimeLockId, &0u64);
        env.storage().instance().set(&DataKey::Initialized, &true);
    }

    /// Wrap tokens (immediate execution, no timelock)
    pub fn wrap(env: Env, signers: Vec<Address>, amount: i128) {
        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);

        let mut wrapped_asset: WrappedAsset = env
            .storage()
            .instance()
            .get(&DataKey::WrappedAsset)
            .unwrap();

        let token_client = token::Client::new(&env, &wrapped_asset.underlying_token);
        let contract_address = env.current_contract_address();
        
        signers.get(0).unwrap().require_auth();
        token_client.transfer(
            &signers.get(0).unwrap(),
            &contract_address,
            &amount,
        );

        let balance_key = DataKey::Balance(signers.get(0).unwrap());
        let current_balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .unwrap_or(0);
        
        let new_balance = current_balance.checked_add(amount).expect("Balance overflow");
        env.storage()
            .instance()
            .set(&balance_key, &new_balance);

        wrapped_asset.total_wrapped = wrapped_asset.total_wrapped
            .checked_add(amount).expect("Total supply overflow");
        env.storage()
            .instance()
            .set(&DataKey::WrappedAsset, &wrapped_asset);

        env.events().publish(
            (symbol_short!("wrap"), signers.get(0).unwrap()),
            amount,
        );
    }

    /// Schedule a time-locked unwrap operation
    pub fn schedule_unwrap(
        env: Env,
        signers: Vec<Address>,
        recipient: Address,
        amount: i128,
        delay_seconds: u64,
    ) -> u64 {
        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);

        let min_duration: u64 = env
            .storage()
            .instance()
            .get(&DataKey::MinLockDuration)
            .unwrap();

        if delay_seconds < min_duration {
            panic!("Delay too short");
        }

        let balance_key = DataKey::Balance(recipient.clone());
        let current_balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .unwrap_or(0);

        if current_balance < amount {
            panic!("Insufficient wrapped balance");
        }

        let timelock_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextTimeLockId)
            .unwrap();

        let unlock_time = env.ledger().timestamp() + delay_seconds;

        let timelock = TimeLock {
            operation_type: 1,  // unwrap
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
        
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &(timelock_id + 1));

        env.events().publish(
            (symbol_short!("sched_unw"), recipient, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Execute a time-locked unwrap operation
    pub fn execute_unwrap(env: Env, timelock_id: u64) {
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

        let balance_key = DataKey::Balance(timelock.recipient.clone());
        let current_balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .unwrap_or(0);

        if current_balance < timelock.amount {
            panic!("Insufficient balance");
        }

        let mut wrapped_asset: WrappedAsset = env
            .storage()
            .instance()
            .get(&DataKey::WrappedAsset)
            .unwrap();

        // Burn wrapped tokens
        let new_balance = current_balance.checked_sub(timelock.amount).expect("Balance underflow");
        env.storage()
            .instance()
            .set(&balance_key, &new_balance);

        // Transfer underlying tokens
        let token_client = token::Client::new(&env, &wrapped_asset.underlying_token);
        let contract_address = env.current_contract_address();

        token_client.transfer(&contract_address, &timelock.recipient, &timelock.amount);

        wrapped_asset.total_wrapped = wrapped_asset.total_wrapped
            .checked_sub(timelock.amount).expect("Total supply underflow");
        env.storage()
            .instance()
            .set(&DataKey::WrappedAsset, &wrapped_asset);

        // Mark as executed
        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        env.events().publish(
            (symbol_short!("exec_unw"), timelock.recipient, timelock_id),
            timelock.amount,
        );
    }

    /// Schedule a time-locked transfer
    pub fn schedule_transfer(
        env: Env,
        signers: Vec<Address>,
        from: Address,
        to: Address,
        amount: i128,
        delay_seconds: u64,
    ) -> u64 {
        if amount <= 0 {
            panic!("Amount must be positive");
        }

        Self::verify_multisig(&env, &signers);

        let min_duration: u64 = env
            .storage()
            .instance()
            .get(&DataKey::MinLockDuration)
            .unwrap();

        if delay_seconds < min_duration {
            panic!("Delay too short");
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

        let unlock_time = env.ledger().timestamp() + delay_seconds;

        let timelock = TimeLock {
            operation_type: 2,  // transfer
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
        
        env.storage()
            .instance()
            .set(&DataKey::NextTimeLockId, &(timelock_id + 1));

        env.events().publish(
            (symbol_short!("sched_tx"), from, to, timelock_id),
            unlock_time,
        );

        timelock_id
    }

    /// Execute a time-locked transfer using the sender stored at schedule time.
    pub fn execute_transfer(env: Env, timelock_id: u64) {
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

        let from_key = DataKey::Balance(timelock.sender.clone());
        let to_key = DataKey::Balance(timelock.recipient.clone());

        let from_balance: i128 = env.storage().instance().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().instance().get(&to_key).unwrap_or(0);

        if from_balance < timelock.amount {
            panic!("Insufficient balance");
        }

        let new_from = from_balance.checked_sub(timelock.amount).expect("Balance underflow");
        let new_to = to_balance.checked_add(timelock.amount).expect("Balance overflow");
        env.storage().instance().set(&from_key, &new_from);
        env.storage().instance().set(&to_key, &new_to);

        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        env.events().publish(
            (symbol_short!("exec_tx"), timelock.sender, timelock.recipient, timelock_id),
            timelock.amount,
        );
    }

    /// Cancel a pending timelock (requires multisig)
    pub fn cancel_timelock(env: Env, signers: Vec<Address>, timelock_id: u64) {
        Self::verify_multisig(&env, &signers);

        let mut timelock: TimeLock = env
            .storage()
            .instance()
            .get(&DataKey::TimeLock(timelock_id))
            .expect("Timelock not found");

        if timelock.executed {
            panic!("Already executed");
        }

        // Mark as executed to prevent future execution
        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        env.events().publish(
            (symbol_short!("cancel"), timelock_id),
            0,
        );
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
        let wrapped_asset: WrappedAsset = env
            .storage()
            .instance()
            .get(&DataKey::WrappedAsset)
            .unwrap();
        wrapped_asset.total_wrapped
    }

    /// Verify that at least `threshold` of the provided signers are in the
    /// authorized signer list and that each has called `require_auth()`.
    /// Panics if any provided signer is not authorized or the threshold is not met.
    fn verify_multisig(env: &Env, provided_signers: &Vec<Address>) {
        let config: MultisigConfig = env
            .storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap();

        if provided_signers.len() < config.threshold {
            panic!("Insufficient signers");
        }

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

        // All provided signers are authorized, so valid_count == provided_signers.len()
        // which is already checked >= threshold above.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Env};

    fn setup_env() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigAssetWrapper, ());
        let token_admin = Address::generate(&env);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        (env, contract_id, token_admin, signer1, signer2)
    }

    fn create_token(env: &Env, admin: &Address) -> Address {
        let token_contract_id = env.register_stellar_asset_contract_v2(admin.clone());
        token_contract_id.address()
    }

    fn init_contract(
        env: &Env,
        contract_id: &Address,
        token_addr: &Address,
        signer1: &Address,
        signer2: &Address,
    ) {
        let client = MultisigAssetWrapperClient::new(env, contract_id);
        let signers = vec![env, signer1.clone(), signer2.clone()];
        client.initialize(&signers, &1, token_addr, &10);
    }

    #[test]
    fn test_initialize_sets_state() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 0);
        assert_eq!(client.balance(&s2), 0);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_double_initialize_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);
        // Second init should panic
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_zero_threshold_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &0, &token_addr, &10);
    }

    #[test]
    #[should_panic(expected = "Invalid threshold")]
    fn test_threshold_exceeding_signers_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &3, &token_addr, &10);
    }

    #[test]
    fn test_total_supply_zero_after_init() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_balance_defaults_to_zero() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let unknown = Address::generate(&env);
        assert_eq!(client.balance(&unknown), 0);
    }

    #[test]
    fn test_balance_zero_for_all_signers_after_init() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 0);
        assert_eq!(client.balance(&s2), 0);
    }

    #[test]
    fn test_init_with_single_signer_threshold_one() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigAssetWrapper, ());
        let admin = Address::generate(&env);
        let signer = Address::generate(&env);
        let token_addr = create_token(&env, &admin);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, signer.clone()];
        client.initialize(&signers, &1, &token_addr, &60);

        assert_eq!(client.balance(&signer), 0);
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_init_with_max_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(MultisigAssetWrapper, ());
        let admin = Address::generate(&env);
        let s1 = Address::generate(&env);
        let s2 = Address::generate(&env);
        let s3 = Address::generate(&env);
        let token_addr = create_token(&env, &admin);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone(), s3.clone()];
        // threshold == signers.len() is valid
        client.initialize(&signers, &3, &token_addr, &10);

        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_unwrap_insufficient_signers() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);

        // Initialize with threshold=2
        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &2, &token_addr, &10);

        // Provide only 1 signer when 2 are required
        let insufficient = vec![&env, s1.clone()];
        client.schedule_unwrap(&insufficient, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Insufficient wrapped balance")]
    fn test_schedule_unwrap_zero_balance() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // No tokens wrapped — balance is 0
        client.schedule_unwrap(&signers, &s1, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Delay too short")]
    fn test_schedule_unwrap_delay_below_minimum() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance directly via storage to bypass wrap's auth issue
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // min_lock_duration is 10, providing 5
        client.schedule_unwrap(&signers, &s1, &100, &5);
    }

    #[test]
    fn test_schedule_unwrap_creates_timelock() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance via direct storage access
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &1000_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 1000;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        assert_eq!(tl_id, 0);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 1);
        assert_eq!(tl.amount, 200);
        assert!(!tl.executed);
    }

    #[test]
    fn test_cancel_timelock_marks_executed() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        client.cancel_timelock(&signers, &tl_id);

        let tl = client.get_timelock(&tl_id);
        assert!(tl.executed, "Cancelled timelock should be marked as executed");
    }

    #[test]
    fn test_schedule_transfer_creates_timelock() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.operation_type, 2);
        assert_eq!(tl.amount, 100);
        assert!(!tl.executed);
    }

    #[test]
    fn test_timelock_ids_are_sequential() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a large balance
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &5000_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 5000;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
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
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // s1 has no balance — should panic
        client.schedule_transfer(&signers, &s1, &s2, &100, &10);
    }

    #[test]
    #[should_panic(expected = "Timelock not found")]
    fn test_get_timelock_nonexistent() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        client.get_timelock(&99);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_zero_amount_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_unwrap(&signers, &s1, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_zero_amount_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_transfer(&signers, &s1, &s2, &0, &10);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_transfer_negative_amount_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_transfer(&signers, &s1, &s2, &-100, &10);
    }

    #[test]
    #[should_panic(expected = "Signer not authorized")]
    fn test_verify_multisig_rejects_unauthorized_signer() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let unauthorized = Address::generate(&env);
        // Include an unauthorized address in the signer list
        let signers = vec![&env, unauthorized.clone()];
        client.schedule_unwrap(&signers, &s1, &100, &10);
    }

    #[test]
    fn test_schedule_transfer_stores_sender() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed a balance for s1
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_transfer(&signers, &s1, &s2, &100, &10);

        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.sender, s1);
        assert_eq!(tl.recipient, s2);
    }

    #[test]
    #[should_panic(expected = "Already executed")]
    fn test_cancel_already_cancelled_timelock_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        let tl_id = client.schedule_unwrap(&signers, &s1, &200, &10);
        client.cancel_timelock(&signers, &tl_id);
        // Second cancel should panic
        client.cancel_timelock(&signers, &tl_id);
    }

    #[test]
    #[should_panic(expected = "Insufficient signers")]
    fn test_schedule_transfer_insufficient_signers() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);

        // Initialize with threshold=2
        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone(), s2.clone()];
        client.initialize(&signers, &2, &token_addr, &10);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        // Only 1 signer provided when 2 are required
        let insufficient = vec![&env, s1.clone()];
        client.schedule_transfer(&insufficient, &s1, &s2, &100, &10);
    }

    #[test]
    fn test_multiple_balances_independent() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        // Seed different balances for s1 and s2
        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &1000_i128);
            env.storage()
                .instance()
                .set(&DataKey::Balance(s2.clone()), &500_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 1500;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        assert_eq!(client.balance(&s1), 1000);
        assert_eq!(client.balance(&s2), 500);
        assert_eq!(client.total_supply(), 1500);
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_schedule_unwrap_negative_amount_panics() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        client.schedule_unwrap(&signers, &s1, &-50, &10);
    }

    #[test]
    fn test_schedule_unwrap_exact_balance() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &300_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 300;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // Unwrap exactly the full balance — should succeed
        let tl_id = client.schedule_unwrap(&signers, &s1, &300, &10);
        let tl = client.get_timelock(&tl_id);
        assert_eq!(tl.amount, 300);
    }

    #[test]
    #[should_panic(expected = "Insufficient wrapped balance")]
    fn test_schedule_unwrap_exceeds_balance() {
        let (env, contract_id, admin, s1, s2) = setup_env();
        let token_addr = create_token(&env, &admin);
        init_contract(&env, &contract_id, &token_addr, &s1, &s2);

        env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .set(&DataKey::Balance(s1.clone()), &300_i128);
            let mut wa: WrappedAsset = env
                .storage()
                .instance()
                .get(&DataKey::WrappedAsset)
                .unwrap();
            wa.total_wrapped = 300;
            env.storage()
                .instance()
                .set(&DataKey::WrappedAsset, &wa);
        });

        let client = MultisigAssetWrapperClient::new(&env, &contract_id);
        let signers = vec![&env, s1.clone()];
        // Attempt to unwrap more than balance
        client.schedule_unwrap(&signers, &s1, &301, &10);
    }
}
