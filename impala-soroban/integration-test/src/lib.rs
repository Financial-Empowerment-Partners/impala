#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, Vec, symbol_short
};

#[contracttype]
pub struct MultisigConfig {
    pub signers: Vec<Address>,
    pub threshold: u32,
}

#[contracttype]
pub struct WrappedAsset {
    pub underlying_token: Address,
    pub total_wrapped: i128,
}

#[contracttype]
pub struct TimeLock {
    pub operation_type: u32,  // 1=unwrap, 2=transfer, 3=config_change
    pub signers: Vec<Address>,
    pub recipient: Address,
    pub amount: i128,
    pub unlock_time: u64,
    pub executed: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    MultisigConfig,
    WrappedAsset,
    Balance(Address),
    Initialized,
    TimeLock(u64),  // keyed by timelock ID
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
        
        env.storage()
            .instance()
            .set(&balance_key, &(current_balance + amount));

        wrapped_asset.total_wrapped += amount;
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
        env.storage()
            .instance()
            .set(&balance_key, &(current_balance - timelock.amount));

        // Transfer underlying tokens
        let token_client = token::Client::new(&env, &wrapped_asset.underlying_token);
        let contract_address = env.current_contract_address();
        
        token_client.transfer(&contract_address, &timelock.recipient, &timelock.amount);

        wrapped_asset.total_wrapped -= timelock.amount;
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

    /// Execute a time-locked transfer
    pub fn execute_transfer(env: Env, timelock_id: u64, from: Address) {
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

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(timelock.recipient.clone());

        let from_balance: i128 = env.storage().instance().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().instance().get(&to_key).unwrap_or(0);

        if from_balance < timelock.amount {
            panic!("Insufficient balance");
        }

        env.storage().instance().set(&from_key, &(from_balance - timelock.amount));
        env.storage().instance().set(&to_key, &(to_balance + timelock.amount));

        timelock.executed = true;
        env.storage()
            .instance()
            .set(&DataKey::TimeLock(timelock_id), &timelock);

        env.events().publish(
            (symbol_short!("exec_tx"), from, timelock.recipient, timelock_id),
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

    pub fn balance(env: Env, address: Address) -> i128 {
        let balance_key = DataKey::Balance(address);
        env.storage().instance().get(&balance_key).unwrap_or(0)
    }

    pub fn total_supply(env: Env) -> i128 {
        let wrapped_asset: WrappedAsset = env
            .storage()
            .instance()
            .get(&DataKey::WrappedAsset)
            .unwrap();
        wrapped_asset.total_wrapped
    }

    fn verify_multisig(env: &Env, provided_signers: &Vec<Address>) {
        let config: MultisigConfig = env
            .storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap();

        if provided_signers.len() < config.threshold {
            panic!("Insufficient signers");
        }

        let mut valid_count = 0;
        for provided_signer in provided_signers.iter() {
            provided_signer.require_auth();
            
            for authorized_signer in config.signers.iter() {
                if provided_signer == authorized_signer {
                    valid_count += 1;
                    break;
                }
            }
        }

        if valid_count < config.threshold {
            panic!("Threshold not met with valid signers");
        }
    }
}
