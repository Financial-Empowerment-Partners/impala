use std::path::PathBuf;
use std::process::{Command, Output};

const TESTNET_RPC: &str = "https://soroban-testnet.stellar.org";
const TESTNET_NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Result type for testnet operations.
pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A test identity with a name usable by the stellar CLI.
pub struct TestIdentity {
    pub name: String,
    pub public_key: String,
}

/// Check that the `stellar` CLI is available.
pub fn require_stellar_cli() {
    let output = Command::new("stellar").arg("--version").output();
    match output {
        Ok(o) if o.status.success() => {}
        _ => panic!(
            "stellar CLI not found. Install it from https://github.com/stellar/stellar-cli"
        ),
    }
}

/// Generate a new test identity via the stellar CLI.
pub fn generate_identity(name: &str) -> TestResult<TestIdentity> {
    let output = stellar_cmd(&["keys", "generate", name, "--network", "testnet"])?;
    assert_cmd_success(&output, "keys generate");

    let addr_output = stellar_cmd(&["keys", "address", name])?;
    assert_cmd_success(&addr_output, "keys address");

    let public_key = String::from_utf8(addr_output.stdout)?.trim().to_string();

    Ok(TestIdentity {
        name: name.to_string(),
        public_key,
    })
}

/// Fund an account via the Stellar Testnet friendbot.
pub fn fund_account(public_key: &str) -> TestResult<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(FRIENDBOT_URL)
        .query(&[("addr", public_key)])
        .send()?;

    if !resp.status().is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!("Friendbot funding failed: {body}").into());
    }
    Ok(())
}

/// Path to the compiled contract WASM (release build).
pub fn contract_wasm_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../integration-test/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm");
    path
}

/// Deploy the contract WASM to testnet using a source identity. Returns the contract ID.
pub fn deploy_contract(source_identity: &str) -> TestResult<String> {
    let wasm_path = contract_wasm_path();
    if !wasm_path.exists() {
        return Err(format!(
            "Contract WASM not found at {}. Run `cargo build --release` in integration-test/ first.",
            wasm_path.display()
        )
        .into());
    }

    let output = stellar_cmd(&[
        "contract",
        "deploy",
        "--wasm",
        wasm_path.to_str().unwrap(),
        "--source",
        source_identity,
        "--network",
        "testnet",
    ])?;
    assert_cmd_success(&output, "contract deploy");

    let contract_id = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(contract_id)
}

/// Invoke a contract function on testnet. Returns stdout as a string.
pub fn invoke(
    contract_id: &str,
    source_identity: &str,
    function: &str,
    args: &[&str],
) -> TestResult<String> {
    let mut cmd_args = vec![
        "contract",
        "invoke",
        "--id",
        contract_id,
        "--source",
        source_identity,
        "--network",
        "testnet",
        "--",
        function,
    ];
    cmd_args.extend_from_slice(args);

    let output = stellar_cmd(&cmd_args)?;
    assert_cmd_success(&output, &format!("invoke {function}"));

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Invoke a contract function expecting failure. Returns stderr.
pub fn invoke_expect_fail(
    contract_id: &str,
    source_identity: &str,
    function: &str,
    args: &[&str],
) -> TestResult<String> {
    let mut cmd_args = vec![
        "contract",
        "invoke",
        "--id",
        contract_id,
        "--source",
        source_identity,
        "--network",
        "testnet",
        "--",
        function,
    ];
    cmd_args.extend_from_slice(args);

    let output = stellar_cmd(&cmd_args)?;
    if output.status.success() {
        return Err("Expected invocation to fail, but it succeeded".into());
    }

    Ok(String::from_utf8(output.stderr)?.trim().to_string())
}

/// Deploy the native XLM Stellar Asset Contract and return its contract ID.
pub fn deploy_sac_native(source_identity: &str) -> TestResult<String> {
    let output = stellar_cmd(&[
        "contract",
        "asset",
        "deploy",
        "--asset",
        "native",
        "--source",
        source_identity,
        "--network",
        "testnet",
    ])?;

    // SAC deploy may "fail" if already deployed, but still returns the ID
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Extract contract ID — it's the 56-char hex string on its own line
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.len() == 56 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(trimmed.to_string());
        }
        // Also accept C-prefixed contract addresses
        if trimmed.starts_with('C') && trimmed.len() == 56 {
            return Ok(trimmed.to_string());
        }
    }

    // If the command succeeded, stdout likely IS the contract id
    if output.status.success() {
        let id = String::from_utf8(output.stdout)?.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }

    Err(format!("Could not extract SAC contract ID from: {combined}").into())
}

fn stellar_cmd(args: &[&str]) -> TestResult<Output> {
    let output = Command::new("stellar").args(args).output()?;
    Ok(output)
}

fn assert_cmd_success(output: &Output, context: &str) {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "stellar {context} failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}
