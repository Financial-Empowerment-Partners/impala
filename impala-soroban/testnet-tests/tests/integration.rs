use impala_testnet_tests::*;
use std::thread;
use std::time::Duration;

/// Amount passed to `stellar tx new payment --amount` when funding signer1
/// with self-issued USDC: 100 USDC in stroops (7 decimals).
///
/// CAUTION: the CLI's amount-unit semantics (stroops vs whole units) vary by
/// stellar-cli version, so `setup` asserts the resulting SAC balance equals
/// [`USDC_FUNDING_STROOPS`] — if the CLI treats `--amount` as whole units,
/// that self-check fails loudly and this constant must be adjusted.
const USDC_FUNDING_AMOUNT: &str = "1000000000";

/// The SAC balance (in stroops) expected after the funding payment.
const USDC_FUNDING_STROOPS: i128 = 1_000_000_000;

/// Shared setup: check CLI, create identities, fund them, self-issue a test
/// USDC asset (deploy its SAC, establish trustlines, pay signer1), and deploy
/// the wrapper contract **through its constructor** (there is no post-deploy
/// initialization entry point).
struct TestFixture {
    deployer: TestIdentity,
    issuer: TestIdentity,
    contract_id: String,
    usdc_sac_id: String,
    usdc_asset: String,
    signer1: TestIdentity,
    signer2: TestIdentity,
}

/// Assert that a failed CLI invocation surfaced a host error. Panic strings
/// never reach the chain (`panic = "abort"`, symbols stripped), so matching
/// the contract's message would be dishonest; callers pair this with explicit
/// state assertions. Constructor failures surface as
/// `Error(Context, InvalidAction)`; record the observed line on the first run
/// and tighten to that literal if it proves stable.
fn assert_host_error(err: &str, context: &str) {
    println!("stderr ({context}): {err}");
    assert!(
        err.contains("Error("),
        "{context}: expected a host error, got: {err}"
    );
}

impl TestFixture {
    fn setup(test_name: &str, threshold: u32, min_lock_duration: u64) -> Self {
        require_stellar_cli();

        let deployer_name = format!("{test_name}-deployer");
        let issuer_name = format!("{test_name}-issuer");
        let s1_name = format!("{test_name}-signer1");
        let s2_name = format!("{test_name}-signer2");

        let deployer = generate_identity(&deployer_name).expect("generate deployer");
        let issuer = generate_identity(&issuer_name).expect("generate issuer");
        let signer1 = generate_identity(&s1_name).expect("generate signer1");
        let signer2 = generate_identity(&s2_name).expect("generate signer2");

        fund_account(&deployer.public_key).expect("fund deployer");
        fund_account(&issuer.public_key).expect("fund issuer");
        fund_account(&signer1.public_key).expect("fund signer1");
        fund_account(&signer2.public_key).expect("fund signer2");

        // Small delay for ledger finality
        thread::sleep(Duration::from_secs(5));

        // Self-issued test USDC: the SAC's symbol() is the asset code and its
        // name() is `USDC:<issuer>`, so the constructor's pin passes because
        // the fixture passes its own issuer. (No Circle faucet involved — the
        // issuer is a throwaway testnet account.)
        let usdc_asset = format!("USDC:{}", issuer.public_key);
        let usdc_sac_id = deploy_usdc_sac(&issuer).expect("deploy USDC SAC");

        // Accounts (G-addresses) need trustlines to hold USDC; the wrapper
        // contract itself does not.
        establish_trustline(&signer1, &usdc_asset).expect("signer1 trustline");
        establish_trustline(&signer2, &usdc_asset).expect("signer2 trustline");

        let mut fixture = TestFixture {
            deployer,
            issuer,
            contract_id: String::new(),
            usdc_sac_id,
            usdc_asset,
            signer1,
            signer2,
        };
        let ctor = fixture.ctor_args(threshold, min_lock_duration);
        let ctor_refs: Vec<&str> = ctor.iter().map(String::as_str).collect();
        fixture.contract_id =
            deploy_contract(&fixture.deployer.name, &ctor_refs).expect("deploy contract");
        fixture.fund_signer1_with_usdc();
        fixture
    }

    fn signers_json(&self) -> String {
        format!(
            r#"["{}","{}"]"#,
            self.signer1.public_key, self.signer2.public_key
        )
    }

    /// Constructor arguments for the fixture's signers and self-issued USDC
    /// SAC; `min_threshold` is 1 so rotation tests can go down to 1-of-1.
    fn ctor_args(&self, threshold: u32, min_lock_duration: u64) -> Vec<String> {
        self.ctor_args_for(
            &self.usdc_sac_id,
            &self.issuer.public_key,
            threshold,
            min_lock_duration,
        )
    }

    fn ctor_args_for(
        &self,
        usdc_token: &str,
        usdc_issuer: &str,
        threshold: u32,
        min_lock_duration: u64,
    ) -> Vec<String> {
        vec![
            "--signers".into(),
            self.signers_json(),
            "--threshold".into(),
            threshold.to_string(),
            "--min_threshold".into(),
            "1".into(),
            "--usdc_token".into(),
            usdc_token.into(),
            "--usdc_issuer".into(),
            usdc_issuer.into(),
            "--min_lock_duration".into(),
            min_lock_duration.to_string(),
        ]
    }

    /// Pay 100 self-issued USDC to signer1 and assert the SAC balance matches
    /// the expected stroops, so a CLI amount-unit mismatch fails loudly here
    /// rather than corrupting downstream test expectations.
    fn fund_signer1_with_usdc(&self) {
        pay_usdc(
            &self.issuer,
            &self.signer1.public_key,
            USDC_FUNDING_AMOUNT,
            &self.usdc_asset,
        )
        .expect("pay USDC to signer1");

        let bal = sac_balance(
            &self.usdc_sac_id,
            &self.deployer.name,
            &self.signer1.public_key,
        )
        .expect("query signer1 USDC SAC balance");
        assert_eq!(
            bal, USDC_FUNDING_STROOPS,
            "USDC funding self-check failed: expected {USDC_FUNDING_STROOPS} stroops, got {bal}. \
             stellar-cli payment amount-unit semantics may differ for this CLI version — \
             adjust USDC_FUNDING_AMOUNT accordingly."
        );
    }

    fn wrap_tokens(&self, signer: &TestIdentity, amount: i128) {
        let signers_json = format!(r#"["{}"]"#, signer.public_key);

        invoke(
            &self.contract_id,
            &signer.name,
            "wrap",
            &[
                "--signers",
                &signers_json,
                "--depositor",
                &signer.public_key,
                "--amount",
                &amount.to_string(),
            ],
        )
        .expect("wrap tokens");
    }

    fn schedule_unwrap(&self, signer: &TestIdentity, amount: i128, delay: u64) -> String {
        let signers_json = format!(r#"["{}"]"#, signer.public_key);
        let id = invoke(
            &self.contract_id,
            &signer.name,
            "schedule_unwrap",
            &[
                "--signers",
                &signers_json,
                "--recipient",
                &signer.public_key,
                "--amount",
                &amount.to_string(),
                "--delay_seconds",
                &delay.to_string(),
            ],
        )
        .expect("schedule_unwrap");
        id.trim().trim_matches('"').to_string()
    }

    fn query_i128(&self, function: &str, args: &[&str]) -> i128 {
        let result =
            invoke(&self.contract_id, &self.deployer.name, function, args).expect(function);
        parse_i128(&result).expect(function)
    }

    fn query_string(&self, function: &str, args: &[&str]) -> String {
        let result =
            invoke(&self.contract_id, &self.deployer.name, function, args).expect(function);
        result.trim().trim_matches('"').to_string()
    }

    fn query_balance(&self, address: &str) -> i128 {
        self.query_i128("balance", &["--address", address])
    }

    fn query_reserved(&self, address: &str) -> i128 {
        self.query_i128("reserved", &["--address", address])
    }

    fn query_available(&self, address: &str) -> i128 {
        self.query_i128("available", &["--address", address])
    }

    fn query_total_supply(&self) -> i128 {
        self.query_i128("total_supply", &[])
    }

    /// `multisig_config` as printed by the CLI (JSON-ish struct).
    fn query_config(&self) -> String {
        invoke(
            &self.contract_id,
            &self.deployer.name,
            "multisig_config",
            &[],
        )
        .expect("multisig_config")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_with_constructor() {
    let f = TestFixture::setup("deploy-ctor", 1, 60);

    // Verify contract is functional by querying balance (should be 0)
    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(bal, 0, "Initial balance should be 0");

    let supply = f.query_total_supply();
    assert_eq!(supply, 0, "Initial total supply should be 0");

    assert_eq!(f.query_string("usdc_token", &[]), f.usdc_sac_id);
    assert_eq!(f.query_string("usdc_issuer", &[]), f.issuer.public_key);
    assert_eq!(f.query_string("min_lock_duration", &[]), "60");
    assert_eq!(f.query_string("min_threshold", &[]), "1");

    let config = f.query_config();
    println!("multisig_config: {config}");
    assert!(config.contains(&f.signer1.public_key));
    assert!(config.contains(&f.signer2.public_key));
}

#[test]
fn test_wrap_tokens() {
    let f = TestFixture::setup("wrap", 1, 60);

    let wrap_amount: i128 = 1_000_000; // 0.1 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(bal, wrap_amount, "Balance should equal wrapped amount");

    let supply = f.query_total_supply();
    assert_eq!(
        supply, wrap_amount,
        "Total supply should equal wrapped amount"
    );
}

#[test]
fn test_schedule_and_execute_unwrap() {
    let f = TestFixture::setup("unwrap", 1, 5); // 5-second minimum lock for faster test

    let wrap_amount: i128 = 2_000_000; // 0.2 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);
    let unwrap_amount: i128 = 1_000_000;

    // Schedule unwrap with 6-second delay (> min_lock_duration of 5)
    let timelock_id = f.schedule_unwrap(&f.signer1, unwrap_amount, 6);
    println!("Scheduled unwrap timelock ID: {timelock_id}");
    assert_eq!(f.query_reserved(&f.signer1.public_key), unwrap_amount);

    // Wait for the timelock to mature
    println!("Waiting for timelock to mature...");
    thread::sleep(Duration::from_secs(10));

    // Execute the unwrap with the current quorum
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "execute_unwrap",
        &["--signers", &signers_json, "--timelock_id", &timelock_id],
    )
    .expect("execute_unwrap");

    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(
        bal,
        wrap_amount - unwrap_amount,
        "Balance should decrease after unwrap"
    );
    assert_eq!(f.query_reserved(&f.signer1.public_key), 0);

    let supply = f.query_total_supply();
    assert_eq!(
        supply,
        wrap_amount - unwrap_amount,
        "Total supply should decrease after unwrap"
    );
}

#[test]
fn test_schedule_and_execute_transfer() {
    let f = TestFixture::setup("transfer", 1, 5);

    let wrap_amount: i128 = 3_000_000; // 0.3 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);
    let transfer_amount: i128 = 1_500_000;

    let timelock_id = invoke(
        &f.contract_id,
        &f.signer1.name,
        "schedule_transfer",
        &[
            "--signers",
            &signers_json,
            "--from",
            &f.signer1.public_key,
            "--to",
            &f.signer2.public_key,
            "--amount",
            &transfer_amount.to_string(),
            "--delay_seconds",
            "6",
        ],
    )
    .expect("schedule_transfer");

    let timelock_id = timelock_id.trim().trim_matches('"');

    println!("Waiting for transfer timelock to mature...");
    thread::sleep(Duration::from_secs(10));

    // execute_transfer takes the current quorum and the timelock ID — sender
    // and recipient were recorded at schedule time.
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "execute_transfer",
        &["--signers", &signers_json, "--timelock_id", timelock_id],
    )
    .expect("execute_transfer");

    let bal1 = f.query_balance(&f.signer1.public_key);
    let bal2 = f.query_balance(&f.signer2.public_key);

    assert_eq!(
        bal1,
        wrap_amount - transfer_amount,
        "Sender balance should decrease"
    );
    assert_eq!(bal2, transfer_amount, "Recipient balance should increase");
    assert_eq!(f.query_reserved(&f.signer1.public_key), 0);
    assert_eq!(f.query_total_supply(), wrap_amount);
}

#[test]
fn test_cancel_timelock() {
    let f = TestFixture::setup("cancel", 1, 5);

    let wrap_amount: i128 = 2_000_000; // 0.2 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);
    let timelock_id = f.schedule_unwrap(&f.signer1, 1_000_000, 6);
    assert_eq!(f.query_reserved(&f.signer1.public_key), 1_000_000);

    // Cancel the timelock
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "cancel_timelock",
        &["--signers", &signers_json, "--timelock_id", &timelock_id],
    )
    .expect("cancel_timelock");

    // Wait and try to execute — should fail
    thread::sleep(Duration::from_secs(10));

    let err = invoke_expect_fail(
        &f.contract_id,
        &f.signer1.name,
        "execute_unwrap",
        &["--signers", &signers_json, "--timelock_id", &timelock_id],
    )
    .expect("execute_unwrap should return error");
    // Cancelled timelocks are pruned from storage, so execution fails on the
    // missing entry.
    assert_host_error(&err, "execute cancelled timelock");

    // Balance unchanged, reservation released, supply unchanged.
    assert_eq!(f.query_balance(&f.signer1.public_key), wrap_amount);
    assert_eq!(f.query_reserved(&f.signer1.public_key), 0);
    assert_eq!(f.query_total_supply(), wrap_amount);
}

#[test]
fn test_insufficient_signers_rejected() {
    let f = TestFixture::setup("insuf-sig", 2, 60);

    // Try to wrap with only 1 signer — should fail
    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);

    let err = invoke_expect_fail(
        &f.contract_id,
        &f.signer1.name,
        "wrap",
        &[
            "--signers",
            &signers_json,
            "--depositor",
            &f.signer1.public_key,
            "--amount",
            "1000000",
        ],
    )
    .expect("wrap with insufficient signers should fail");
    assert_host_error(&err, "wrap with insufficient signers");

    assert_eq!(f.query_balance(&f.signer1.public_key), 0);
    assert_eq!(f.query_total_supply(), 0);
}

#[test]
fn test_deploy_rejects_non_usdc_token() {
    let f = TestFixture::setup("non-usdc", 1, 60);

    // The native XLM SAC's symbol() is "native", not "USDC".
    let native_sac_id = deploy_sac_native(&f.deployer.name).expect("deploy native SAC");

    let ctor = f.ctor_args_for(&native_sac_id, &f.issuer.public_key, 1, 60);
    let ctor_refs: Vec<&str> = ctor.iter().map(String::as_str).collect();
    let err = deploy_contract_expect_fail(&f.deployer.name, &ctor_refs)
        .expect("deploy with a non-USDC token should fail");
    assert_host_error(&err, "deploy with native SAC");
}

#[test]
fn test_deploy_rejects_issuer_mismatch() {
    let f = TestFixture::setup("issuer-mismatch", 1, 60);

    // A second throwaway issuer with its own genuine `USDC:<issuer2>` SAC:
    // symbol and decimals match, the name()'s strkey does not.
    let issuer2 = generate_identity("issuer-mismatch-issuer2").expect("generate issuer2");
    fund_account(&issuer2.public_key).expect("fund issuer2");
    thread::sleep(Duration::from_secs(5));
    let sac2 = deploy_usdc_sac(&issuer2).expect("deploy USDC SAC for issuer2");
    assert_ne!(sac2, f.usdc_sac_id);

    let ctor = f.ctor_args_for(&sac2, &f.issuer.public_key, 1, 60);
    let ctor_refs: Vec<&str> = ctor.iter().map(String::as_str).collect();
    let err = deploy_contract_expect_fail(&f.deployer.name, &ctor_refs)
        .expect("deploy with a look-alike USDC from another issuer should fail");
    assert_host_error(&err, "deploy with mismatched issuer");
}

#[test]
fn test_constructor_not_callable_after_deploy() {
    let f = TestFixture::setup("ctor-locked", 1, 60);

    let config_before = f.query_config();
    let token_before = f.query_string("usdc_token", &[]);
    let issuer_before = f.query_string("usdc_issuer", &[]);

    // The host refuses direct calls to `__`-prefixed functions; re-running the
    // constructor with a hostile signer set must fail and change nothing.
    let hostile_signers = format!(r#"["{}"]"#, f.deployer.public_key);
    let err = invoke_expect_fail(
        &f.contract_id,
        &f.deployer.name,
        "__constructor",
        &[
            "--signers",
            &hostile_signers,
            "--threshold",
            "1",
            "--min_threshold",
            "1",
            "--usdc_token",
            &f.usdc_sac_id,
            "--usdc_issuer",
            &f.issuer.public_key,
            "--min_lock_duration",
            "1",
        ],
    )
    .expect("__constructor must not be invocable after deploy");
    println!("stderr (__constructor): {err}");
    assert!(!err.is_empty(), "expected an error from the CLI/host");

    assert_eq!(f.query_config(), config_before);
    assert_eq!(f.query_string("usdc_token", &[]), token_before);
    assert_eq!(f.query_string("usdc_issuer", &[]), issuer_before);
    assert!(!f.query_config().contains(&f.deployer.public_key));
}

#[test]
fn test_over_schedule_rejected() {
    let f = TestFixture::setup("over-sched", 1, 5);

    let wrap_amount: i128 = 2_000_000;
    f.wrap_tokens(&f.signer1, wrap_amount);

    let first = f.schedule_unwrap(&f.signer1, 1_500_000, 6);
    println!("first timelock: {first}");

    // 1_500_000 + 1_500_000 > 2_000_000: the reservation makes this fail.
    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);
    let err = invoke_expect_fail(
        &f.contract_id,
        &f.signer1.name,
        "schedule_unwrap",
        &[
            "--signers",
            &signers_json,
            "--recipient",
            &f.signer1.public_key,
            "--amount",
            "1500000",
            "--delay_seconds",
            "6",
        ],
    )
    .expect("over-schedule should fail");
    assert_host_error(&err, "over-schedule");

    assert_eq!(f.query_balance(&f.signer1.public_key), wrap_amount);
    assert_eq!(f.query_reserved(&f.signer1.public_key), 1_500_000);
    assert_eq!(f.query_available(&f.signer1.public_key), 500_000);
    assert_eq!(f.query_total_supply(), wrap_amount);
}

#[test]
fn test_execute_after_rotation() {
    let f = TestFixture::setup("rotate-exec", 1, 5);

    let wrap_amount: i128 = 2_000_000;
    f.wrap_tokens(&f.signer1, wrap_amount);

    let unwrap_amount: i128 = 1_000_000;
    let timelock_id = f.schedule_unwrap(&f.signer1, unwrap_amount, 6);

    // Rotate [s1, s2] 1-of-2 → [s2] 1-of-1 with the current quorum (s1).
    let current = format!(r#"["{}"]"#, f.signer1.public_key);
    let new_signers = format!(r#"["{}"]"#, f.signer2.public_key);
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "rotate_signers",
        &[
            "--current_signers",
            &current,
            "--new_signers",
            &new_signers,
            "--new_threshold",
            "1",
        ],
    )
    .expect("rotate_signers");

    println!("Waiting for timelock to mature...");
    thread::sleep(Duration::from_secs(10));

    // The rotated-out signer can no longer execute.
    let err = invoke_expect_fail(
        &f.contract_id,
        &f.signer1.name,
        "execute_unwrap",
        &["--signers", &current, "--timelock_id", &timelock_id],
    )
    .expect("execute by rotated-out signer should fail");
    assert_host_error(&err, "execute by rotated-out signer");
    assert_eq!(f.query_balance(&f.signer1.public_key), wrap_amount);
    assert_eq!(f.query_reserved(&f.signer1.public_key), unwrap_amount);

    // The new set executes the pending operation.
    invoke(
        &f.contract_id,
        &f.signer2.name,
        "execute_unwrap",
        &["--signers", &new_signers, "--timelock_id", &timelock_id],
    )
    .expect("execute_unwrap by the new signer set");

    assert_eq!(
        f.query_balance(&f.signer1.public_key),
        wrap_amount - unwrap_amount
    );
    assert_eq!(f.query_reserved(&f.signer1.public_key), 0);
    assert_eq!(f.query_total_supply(), wrap_amount - unwrap_amount);
    let sac_bal = sac_balance(&f.usdc_sac_id, &f.deployer.name, &f.signer1.public_key)
        .expect("signer1 SAC balance");
    assert_eq!(sac_bal, USDC_FUNDING_STROOPS - wrap_amount + unwrap_amount);
}
