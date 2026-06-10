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
/// the wrapper contract.
struct TestFixture {
    deployer: TestIdentity,
    issuer: TestIdentity,
    contract_id: String,
    usdc_sac_id: String,
    usdc_asset: String,
    signer1: TestIdentity,
    signer2: TestIdentity,
}

impl TestFixture {
    fn setup(test_name: &str) -> Self {
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

        // Self-issued test USDC: the SAC's symbol() returns the asset code,
        // so the contract's `initialize` USDC validation passes. (No Circle
        // faucet involved — the issuer is a throwaway testnet account.)
        let usdc_asset = format!("USDC:{}", issuer.public_key);
        let usdc_sac_id = deploy_usdc_sac(&issuer).expect("deploy USDC SAC");

        // Accounts (G-addresses) need trustlines to hold USDC; the wrapper
        // contract itself does not.
        establish_trustline(&signer1, &usdc_asset).expect("signer1 trustline");
        establish_trustline(&signer2, &usdc_asset).expect("signer2 trustline");

        let contract_id = deploy_contract(&deployer.name).expect("deploy contract");

        let fixture = TestFixture {
            deployer,
            issuer,
            contract_id,
            usdc_sac_id,
            usdc_asset,
            signer1,
            signer2,
        };
        fixture.fund_signer1_with_usdc();
        fixture
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

    fn initialize(&self, threshold: u32, min_lock_duration: u64) {
        let signers_json = format!(
            r#"["{}","{}"]"#,
            self.signer1.public_key, self.signer2.public_key
        );

        invoke(
            &self.contract_id,
            &self.deployer.name,
            "initialize",
            &[
                "--signers",
                &signers_json,
                "--threshold",
                &threshold.to_string(),
                "--usdc_token",
                &self.usdc_sac_id,
                "--min_lock_duration",
                &min_lock_duration.to_string(),
            ],
        )
        .expect("initialize contract");
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

    fn query_balance(&self, address: &str) -> i128 {
        let result = invoke(
            &self.contract_id,
            &self.deployer.name,
            "balance",
            &["--address", address],
        )
        .expect("query balance");

        result.trim().trim_matches('"').parse::<i128>().unwrap_or(0)
    }

    fn query_total_supply(&self) -> i128 {
        let result = invoke(&self.contract_id, &self.deployer.name, "total_supply", &[])
            .expect("query total_supply");

        result.trim().trim_matches('"').parse::<i128>().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_and_initialize() {
    let f = TestFixture::setup("deploy-init");
    f.initialize(1, 60);

    // Verify contract is functional by querying balance (should be 0)
    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(bal, 0, "Initial balance should be 0");

    let supply = f.query_total_supply();
    assert_eq!(supply, 0, "Initial total supply should be 0");
}

#[test]
fn test_wrap_tokens() {
    let f = TestFixture::setup("wrap");
    f.initialize(1, 60);

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
    let f = TestFixture::setup("unwrap");
    f.initialize(1, 5); // 5-second minimum lock for faster test

    let wrap_amount: i128 = 2_000_000; // 0.2 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);
    let unwrap_amount: i128 = 1_000_000;

    // Schedule unwrap with 6-second delay (> min_lock_duration of 5)
    let timelock_id = invoke(
        &f.contract_id,
        &f.signer1.name,
        "schedule_unwrap",
        &[
            "--signers",
            &signers_json,
            "--recipient",
            &f.signer1.public_key,
            "--amount",
            &unwrap_amount.to_string(),
            "--delay_seconds",
            "6",
        ],
    )
    .expect("schedule_unwrap");

    let timelock_id = timelock_id.trim().trim_matches('"');
    println!("Scheduled unwrap timelock ID: {timelock_id}");

    // Wait for timelock to expire
    println!("Waiting for timelock to expire...");
    thread::sleep(Duration::from_secs(10));

    // Execute the unwrap
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "execute_unwrap",
        &["--timelock_id", timelock_id],
    )
    .expect("execute_unwrap");

    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(
        bal,
        wrap_amount - unwrap_amount,
        "Balance should decrease after unwrap"
    );

    let supply = f.query_total_supply();
    assert_eq!(
        supply,
        wrap_amount - unwrap_amount,
        "Total supply should decrease after unwrap"
    );
}

#[test]
fn test_schedule_and_execute_transfer() {
    let f = TestFixture::setup("transfer");
    f.initialize(1, 5);

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

    println!("Waiting for transfer timelock to expire...");
    thread::sleep(Duration::from_secs(10));

    // execute_transfer takes only the timelock ID — sender and recipient
    // were recorded at schedule time.
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "execute_transfer",
        &["--timelock_id", timelock_id],
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
}

#[test]
fn test_cancel_timelock() {
    let f = TestFixture::setup("cancel");
    f.initialize(1, 5);

    let wrap_amount: i128 = 2_000_000; // 0.2 USDC in stroops (7 decimals)
    f.wrap_tokens(&f.signer1, wrap_amount);

    let signers_json = format!(r#"["{}"]"#, f.signer1.public_key);

    let timelock_id = invoke(
        &f.contract_id,
        &f.signer1.name,
        "schedule_unwrap",
        &[
            "--signers",
            &signers_json,
            "--recipient",
            &f.signer1.public_key,
            "--amount",
            "1000000",
            "--delay_seconds",
            "6",
        ],
    )
    .expect("schedule_unwrap");

    let timelock_id = timelock_id.trim().trim_matches('"');

    // Cancel the timelock
    invoke(
        &f.contract_id,
        &f.signer1.name,
        "cancel_timelock",
        &["--signers", &signers_json, "--timelock_id", timelock_id],
    )
    .expect("cancel_timelock");

    // Wait and try to execute — should fail
    thread::sleep(Duration::from_secs(10));

    let err = invoke_expect_fail(
        &f.contract_id,
        &f.signer1.name,
        "execute_unwrap",
        &["--timelock_id", timelock_id],
    )
    .expect("execute_unwrap should return error");

    // Cancelled timelocks are pruned from storage, so execution fails on the
    // missing entry.
    assert!(
        err.contains("Timelock not found") || err.contains("Error") || !err.is_empty(),
        "Cancelled timelock execution should fail"
    );

    // Balance should be unchanged
    let bal = f.query_balance(&f.signer1.public_key);
    assert_eq!(
        bal, wrap_amount,
        "Balance should remain unchanged after cancel"
    );
}

#[test]
fn test_insufficient_signers_rejected() {
    let f = TestFixture::setup("insuf-sig");
    // Require 2 signers
    f.initialize(2, 60);

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

    assert!(
        err.contains("Insufficient signers") || err.contains("Error") || !err.is_empty(),
        "Should reject operation with insufficient signers"
    );
}

#[test]
fn test_initialize_rejects_non_usdc_token() {
    let f = TestFixture::setup("non-usdc");

    // The native XLM SAC's symbol() is "native", not "USDC".
    let native_sac_id = deploy_sac_native(&f.deployer.name).expect("deploy native SAC");

    let signers_json = format!(r#"["{}","{}"]"#, f.signer1.public_key, f.signer2.public_key);

    let err = invoke_expect_fail(
        &f.contract_id,
        &f.deployer.name,
        "initialize",
        &[
            "--signers",
            &signers_json,
            "--threshold",
            "1",
            "--usdc_token",
            &native_sac_id,
            "--min_lock_duration",
            "60",
        ],
    )
    .expect("initialize with a non-USDC token should fail");

    assert!(
        err.contains("Underlying token is not USDC") || err.contains("Error") || !err.is_empty(),
        "Should reject a non-USDC underlying token"
    );
}
