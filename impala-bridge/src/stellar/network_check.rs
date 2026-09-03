//! Startup assertion that the configured network passphrase is the one the
//! configured Horizon actually serves.
//!
//! `STELLAR_NETWORK` (default testnet) derives the passphrase while
//! `STELLAR_HORIZON_URL` is set independently, so a production deploy that
//! forgets the network variable signs every transaction with the testnet
//! passphrase and gets `tx_bad_auth` on every submit. Horizon publishes the
//! passphrase it serves in its root document; comparing the two at boot turns
//! that silent money-path failure into a refused start.
//!
//! Policy: a mismatch exits immediately; an unreachable Horizon is retried a
//! bounded number of times and then ALSO exits. The check is never skipped —
//! a bridge that cannot prove which network it is on must not sign for one.

use log::{error, info, warn};
use serde_json::Value;
use std::time::Duration;

use crate::constants::{
    HORIZON_NETWORK_CHECK_ATTEMPTS, HORIZON_NETWORK_CHECK_RETRY_SECS,
    HORIZON_NETWORK_CHECK_TIMEOUT_SECS,
};

/// Outcome of one attempt against Horizon's root document.
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkCheckError {
    /// Horizon answered and serves a different network than configured.
    /// Never retried: the configuration is wrong, not the network.
    Mismatch { expected: String, actual: String },
    /// Horizon could not be reached or its answer was unusable.
    Unreachable(String),
}

impl std::fmt::Display for NetworkCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkCheckError::Mismatch { expected, actual } => write!(
                f,
                "network passphrase mismatch: configured '{}' but Horizon serves '{}'",
                expected, actual
            ),
            NetworkCheckError::Unreachable(msg) => write!(f, "Horizon unreachable: {}", msg),
        }
    }
}

/// Pull `network_passphrase` out of a Horizon root document.
///
/// Absence is an error rather than a pass: a JSON body without the field is
/// not a Horizon root (a proxy error page, a wrong URL), and "could not tell"
/// must never read as "matched".
pub fn parse_root_passphrase(root: &Value) -> Result<String, NetworkCheckError> {
    match root.get("network_passphrase").and_then(Value::as_str) {
        Some(p) if !p.is_empty() => Ok(p.to_string()),
        _ => Err(NetworkCheckError::Unreachable(
            "root document has no network_passphrase field".to_string(),
        )),
    }
}

/// Compare the configured passphrase against the one Horizon reports.
///
/// Exact, byte-for-byte: the passphrase is hashed into every signature, so
/// any difference — including whitespace — produces `tx_bad_auth`.
pub fn compare_passphrase(expected: &str, root: &Value) -> Result<String, NetworkCheckError> {
    let actual = parse_root_passphrase(root)?;
    if actual == expected {
        Ok(actual)
    } else {
        Err(NetworkCheckError::Mismatch {
            expected: expected.to_string(),
            actual,
        })
    }
}

/// One `GET {horizon}/` and comparison.
async fn check_once(
    http: &reqwest::Client,
    horizon_url: &str,
    expected: &str,
) -> Result<String, NetworkCheckError> {
    let url = format!("{}/", horizon_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| NetworkCheckError::Unreachable(format!("request error: {}", e)))?;
    if !resp.status().is_success() {
        return Err(NetworkCheckError::Unreachable(format!(
            "HTTP {}",
            resp.status()
        )));
    }
    let root: Value = resp
        .json()
        .await
        .map_err(|e| NetworkCheckError::Unreachable(format!("response parse error: {}", e)))?;
    compare_passphrase(expected, &root)
}

/// Assert that `horizon_url` serves `expected_passphrase`, retrying only
/// while Horizon is unreachable. `Err` means the process must not proceed.
pub async fn assert_horizon_network(
    horizon_url: &str,
    expected_passphrase: &str,
) -> Result<(), NetworkCheckError> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(HORIZON_NETWORK_CHECK_TIMEOUT_SECS))
        .build()
        .map_err(|e| NetworkCheckError::Unreachable(format!("http client: {}", e)))?;

    let mut last_err = None;
    for attempt in 1..=HORIZON_NETWORK_CHECK_ATTEMPTS {
        match check_once(&http, horizon_url, expected_passphrase).await {
            Ok(actual) => {
                info!(
                    "Horizon network check: {} serves passphrase '{}' — matches configuration",
                    horizon_url, actual
                );
                return Ok(());
            }
            Err(e @ NetworkCheckError::Mismatch { .. }) => return Err(e),
            Err(e) => {
                warn!(
                    "Horizon network check: attempt {}/{} against {} failed: {}",
                    attempt, HORIZON_NETWORK_CHECK_ATTEMPTS, horizon_url, e
                );
                last_err = Some(e);
                if attempt < HORIZON_NETWORK_CHECK_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(HORIZON_NETWORK_CHECK_RETRY_SECS)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| NetworkCheckError::Unreachable("no attempts made".into())))
}

/// Run the assertion and exit the process on failure. Called from both the
/// server and worker startup paths before anything can sign or submit.
pub async fn assert_horizon_network_or_exit(horizon_url: &str, expected_passphrase: &str) {
    if let Err(e) = assert_horizon_network(horizon_url, expected_passphrase).await {
        match e {
            NetworkCheckError::Mismatch { .. } => error!(
                "Horizon network check FAILED: {}. STELLAR_NETWORK / STELLAR_NETWORK_PASSPHRASE \
                 and STELLAR_HORIZON_URL disagree — every signed transaction would be rejected \
                 with tx_bad_auth. Refusing to start.",
                e
            ),
            NetworkCheckError::Unreachable(_) => error!(
                "Horizon network check FAILED after {} attempts: {}. The bridge cannot prove \
                 which network {} serves and will not sign for one blind. Refusing to start.",
                HORIZON_NETWORK_CHECK_ATTEMPTS, e, horizon_url
            ),
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{STELLAR_PUBNET_PASSPHRASE, STELLAR_TESTNET_PASSPHRASE};
    use serde_json::json;

    /// Captured from `GET https://horizon-testnet.stellar.org/` (2026-09-03),
    /// `_links` trimmed. Every field Horizon reports beside the passphrase is
    /// kept so the parser is exercised against the real shape.
    const TESTNET_ROOT: &str = r#"{
      "horizon_version": "28.0.1-a70eb47f76985d372de3e59f4d75c7f8542752f7",
      "core_version": "stellar-core 28.0.1 (947aad8413c189d85504acf72207e85eeda9b021)",
      "ingest_latest_ledger": 4486262,
      "history_latest_ledger": 4486262,
      "history_latest_ledger_closed_at": "2026-09-03T17:01:37Z",
      "history_elder_ledger": 128,
      "core_latest_ledger": 4486262,
      "network_passphrase": "Test SDF Network ; September 2015",
      "current_protocol_version": 28,
      "supported_protocol_version": 28,
      "core_supported_protocol_version": 28
    }"#;

    #[test]
    fn parses_passphrase_from_captured_horizon_root() {
        let root: Value = serde_json::from_str(TESTNET_ROOT).unwrap();
        assert_eq!(
            parse_root_passphrase(&root).unwrap(),
            STELLAR_TESTNET_PASSPHRASE
        );
    }

    #[test]
    fn testnet_config_matches_testnet_horizon() {
        let root: Value = serde_json::from_str(TESTNET_ROOT).unwrap();
        assert_eq!(
            compare_passphrase(STELLAR_TESTNET_PASSPHRASE, &root).unwrap(),
            STELLAR_TESTNET_PASSPHRASE
        );
    }

    /// The deploy mistake this check exists for: pubnet Horizon URL with the
    /// testnet default passphrase (or the reverse).
    #[test]
    fn pubnet_config_against_testnet_horizon_is_a_mismatch() {
        let root: Value = serde_json::from_str(TESTNET_ROOT).unwrap();
        assert_eq!(
            compare_passphrase(STELLAR_PUBNET_PASSPHRASE, &root),
            Err(NetworkCheckError::Mismatch {
                expected: STELLAR_PUBNET_PASSPHRASE.to_string(),
                actual: STELLAR_TESTNET_PASSPHRASE.to_string(),
            })
        );
    }

    #[test]
    fn comparison_is_exact_including_whitespace() {
        let root = json!({ "network_passphrase": "Test SDF Network ; September 2015 " });
        assert!(matches!(
            compare_passphrase(STELLAR_TESTNET_PASSPHRASE, &root),
            Err(NetworkCheckError::Mismatch { .. })
        ));
    }

    /// A body without the field is not a Horizon root; it must read as
    /// "could not verify", never as a match.
    #[test]
    fn missing_or_empty_passphrase_is_unreachable_not_match() {
        for root in [
            json!({ "horizon_version": "28.0.1" }),
            json!({ "network_passphrase": "" }),
            json!({ "network_passphrase": 42 }),
            json!([]),
        ] {
            assert!(matches!(
                compare_passphrase(STELLAR_TESTNET_PASSPHRASE, &root),
                Err(NetworkCheckError::Unreachable(_))
            ));
        }
    }

    #[test]
    fn errors_display_both_passphrases_on_mismatch() {
        let e = NetworkCheckError::Mismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        let s = e.to_string();
        assert!(s.contains("'a'") && s.contains("'b'"));
    }
}
