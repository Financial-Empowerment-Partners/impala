//! Read-only on-chain account details from Horizon.
//!
//! Generalizes the signer's private `fetch_sequence` into a reusable fetch that
//! returns balances, sequence, and signers for an account on *this* bridge's
//! configured network (testnet vs mainnet is a per-deployment choice; the UI
//! selects a network by routing to the matching bridge). The parser is split
//! from the I/O so it can be unit-tested without a network.

use log::error;
use serde::Serialize;
use serde_json::Value;

use crate::error::AppError;

#[derive(Debug, Serialize, PartialEq)]
pub struct OnchainBalance {
    pub asset_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_issuer: Option<String>,
    pub balance: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct OnchainSigner {
    pub key: String,
    pub weight: i64,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
pub struct OnchainAccount {
    pub stellar_account_id: String,
    pub exists: bool,
    pub sequence: Option<String>,
    pub native_balance: Option<String>,
    pub balances: Vec<OnchainBalance>,
    pub signers: Vec<OnchainSigner>,
    pub subentry_count: Option<i64>,
}

impl OnchainAccount {
    fn not_found(stellar_account_id: &str) -> Self {
        OnchainAccount {
            stellar_account_id: stellar_account_id.to_string(),
            exists: false,
            sequence: None,
            native_balance: None,
            balances: Vec::new(),
            signers: Vec::new(),
            subentry_count: None,
        }
    }
}

/// Pure parser over a Horizon `GET /accounts/{id}` JSON body.
pub fn parse_account_details(stellar_account_id: &str, body: &Value) -> OnchainAccount {
    let balances: Vec<OnchainBalance> = body["balances"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|b| OnchainBalance {
                    asset_type: b["asset_type"].as_str().unwrap_or("").to_string(),
                    asset_code: b["asset_code"].as_str().map(|s| s.to_string()),
                    asset_issuer: b["asset_issuer"].as_str().map(|s| s.to_string()),
                    balance: b["balance"].as_str().unwrap_or("0").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    let native_balance = balances
        .iter()
        .find(|b| b.asset_type == "native")
        .map(|b| b.balance.clone());

    let signers: Vec<OnchainSigner> = body["signers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|s| OnchainSigner {
                    key: s["key"].as_str().unwrap_or("").to_string(),
                    weight: s["weight"].as_i64().unwrap_or(0),
                    r#type: s["type"].as_str().unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    OnchainAccount {
        stellar_account_id: stellar_account_id.to_string(),
        exists: true,
        sequence: body["sequence"].as_str().map(|s| s.to_string()),
        native_balance,
        balances,
        signers,
        subentry_count: body["subentry_count"].as_i64(),
    }
}

/// Fetch on-chain details for an account from Horizon. A 404 maps to
/// `exists: false` (account not funded yet); other non-2xx responses and
/// transport/parse failures map to `InternalError`.
pub async fn fetch_account_details(
    http: &reqwest::Client,
    horizon_url: &str,
    stellar_account_id: &str,
) -> Result<OnchainAccount, AppError> {
    let url = format!(
        "{}/accounts/{}",
        horizon_url.trim_end_matches('/'),
        stellar_account_id
    );
    let resp = http.get(&url).send().await.map_err(|e| {
        error!("fetch_account_details: horizon request error: {}", e);
        AppError::InternalError("Horizon request failed".to_string())
    })?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(OnchainAccount::not_found(stellar_account_id));
    }
    if !resp.status().is_success() {
        error!("fetch_account_details: horizon HTTP {}", resp.status());
        return Err(AppError::InternalError("Horizon error".to_string()));
    }

    let body: Value = resp.json().await.map_err(|e| {
        error!("fetch_account_details: horizon response parse error: {}", e);
        AppError::InternalError("Horizon response error".to_string())
    })?;

    Ok(parse_account_details(stellar_account_id, &body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_account_details_extracts_fields() {
        let body = json!({
            "sequence": "123456789",
            "subentry_count": 2,
            "balances": [
                { "asset_type": "credit_alphanum4", "asset_code": "USDC",
                  "asset_issuer": "GAISSUER", "balance": "10.5000000" },
                { "asset_type": "native", "balance": "99.9999900" }
            ],
            "signers": [
                { "key": "GABC", "weight": 1, "type": "ed25519_public_key" }
            ]
        });
        let acct = parse_account_details("GTEST", &body);
        assert!(acct.exists);
        assert_eq!(acct.stellar_account_id, "GTEST");
        assert_eq!(acct.sequence.as_deref(), Some("123456789"));
        assert_eq!(acct.subentry_count, Some(2));
        assert_eq!(acct.native_balance.as_deref(), Some("99.9999900"));
        assert_eq!(acct.balances.len(), 2);
        assert_eq!(acct.signers.len(), 1);
        assert_eq!(acct.signers[0].weight, 1);
    }

    #[test]
    fn test_parse_account_details_no_native_balance() {
        let body = json!({ "sequence": "1", "balances": [], "signers": [] });
        let acct = parse_account_details("GTEST", &body);
        assert!(acct.exists);
        assert!(acct.native_balance.is_none());
        assert!(acct.balances.is_empty());
    }

    #[test]
    fn test_not_found_struct() {
        let acct = OnchainAccount::not_found("GTEST");
        assert!(!acct.exists);
        assert!(acct.sequence.is_none());
        assert!(acct.native_balance.is_none());
        assert!(acct.balances.is_empty());
        assert!(acct.signers.is_empty());
    }
}
