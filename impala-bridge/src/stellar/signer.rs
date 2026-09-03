//! `StellarSigner` trait + a `stellar-base`-backed implementation.
//!
//! "Seed bytes" throughout are the UTF-8 bytes of a Stellar `S...` strkey, which
//! `stellar-base` round-trips via `DalekKeyPair::from_secret_seed` / `secret_seed`.
//! The plaintext seed is only ever materialised inside a [`SecretBytes`] and is
//! never logged.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::error;
use stellar_base::amount::{Amount, Stroops};
use stellar_base::asset::Asset as SbAsset;
use stellar_base::crypto::{DalekKeyPair, PublicKey};
use stellar_base::memo::Memo;
use stellar_base::network::Network;
use stellar_base::operations::Operation;
use stellar_base::time_bounds::TimeBounds;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;

use crate::config::StellarConfig;
use crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS;
use crate::error::AppError;
use crate::seed_protect::SecretBytes;

/// Transaction validity window (seconds) — bounds replay/stuck submissions.
const TX_TIMEOUT_SECS: i64 = 300;

/// Asset to transfer: native XLM, or an issued asset (e.g. the conversion
/// reserve's USDC payouts). `code` is 1-12 alphanumeric chars; `issuer` is
/// the issuing account's `G...` address — both validated at build time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    Native,
    Credit { code: String, issuer: String },
}

/// Parameters for a single-operation payment.
#[derive(Debug, Clone)]
pub struct PaymentParams {
    pub destination: String,
    pub amount: String,
    pub asset: Asset,
    pub memo: Option<String>,
    /// Per-operation base fee in stroops; defaults to the network minimum (100).
    pub fee: Option<u32>,
}

/// A signed, encoded transaction that has NOT been submitted yet. Its hash is
/// final (it is the hash of the signed payload, which is exactly what Horizon
/// reports back), so a caller can persist it as a write-ahead marker BEFORE
/// submission — the only way to later resolve an ambiguous submit exactly,
/// by hash, instead of by matching memos and amounts against the feed.
#[derive(Debug, Clone)]
pub struct PreparedTx {
    xdr: String,
    pub stellar_hash: String,
    pub source_account: String,
}

/// Result of a successful sign + submit.
#[derive(Debug, Clone)]
pub struct SubmittedTx {
    pub stellar_hash: String,
    pub stellar_tx_id: Option<String>,
    pub source_account: String,
}

#[async_trait]
pub trait StellarSigner: Send + Sync {
    /// Generate a fresh keypair. Returns `(G-address, S-strkey seed bytes)`.
    fn generate_keypair(&self) -> Result<(String, SecretBytes), AppError>;
    /// Derive the public `G...` address from `S...` seed bytes.
    fn public_address(&self, seed: &[u8]) -> Result<String, AppError>;
    /// Validate an `S...` strkey (incl. checksum) and return its seed bytes.
    fn seed_from_strkey(&self, s_strkey: &str) -> Result<SecretBytes, AppError>;
    /// Build and sign a payment WITHOUT submitting it. Every failure here is
    /// pre-submit (`Retryable`/`BadRequest`), never ambiguous.
    async fn prepare_payment(
        &self,
        seed: &[u8],
        params: &PaymentParams,
    ) -> Result<PreparedTx, AppError>;
    /// Submit a prepared transaction. The only step that can be ambiguous.
    async fn submit_prepared(&self, prepared: &PreparedTx) -> Result<SubmittedTx, AppError>;
    /// Build, sign, and submit a payment to Horizon using the seed
    /// (`prepare_payment` + `submit_prepared`).
    async fn sign_and_submit_payment(
        &self,
        seed: &[u8],
        params: &PaymentParams,
    ) -> Result<SubmittedTx, AppError>;
    /// Build, sign, and submit a `ChangeTrust` for an issued asset with the
    /// maximum limit, from the seed's account. Moves no money: it lets the
    /// account hold `asset`. Re-asserting an existing trustline is a no-op on
    /// the network (same limit), so this is safe to repeat. Native XLM needs
    /// no trustline and is refused.
    async fn sign_and_submit_change_trust(
        &self,
        seed: &[u8],
        asset: &Asset,
    ) -> Result<SubmittedTx, AppError>;
}

fn signer_error(context: &str, cause: impl std::fmt::Display) -> AppError {
    error!("stellar signer: {}: {}", context, cause);
    AppError::InternalError("transaction signing failed".to_string())
}

/// Error for a failure that provably occurred BEFORE the transaction was
/// submitted (reading the source sequence, building or signing) — nothing
/// reached Horizon, so the caller may safely retry without any double-spend
/// risk. Distinct from `signer_error` (ambiguous) so the reserve payout
/// driver does not freeze a payout on a transient pre-submit Horizon blip.
fn presubmit_error(context: &str, cause: impl std::fmt::Display) -> AppError {
    error!("stellar signer (pre-submit): {}: {}", context, cause);
    AppError::Retryable("transaction preparation failed before submission".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Reconstruct a keypair from `S...` seed bytes without logging the seed.
fn keypair_from_seed(seed: &[u8]) -> Result<DalekKeyPair, AppError> {
    let strkey = std::str::from_utf8(seed)
        .map_err(|_| AppError::BadRequest("invalid secret seed encoding".to_string()))?;
    DalekKeyPair::from_secret_seed(strkey)
        .map_err(|_| AppError::BadRequest("invalid Stellar secret seed".to_string()))
}

pub struct StellarBaseSigner {
    http: reqwest::Client,
    horizon_url: String,
    network_passphrase: String,
    /// Per-operation fee bid (stroops). A Stellar fee is a maximum bid: the
    /// ledger charges its effective fee, so a generous bid costs the minimum
    /// in quiet ledgers and buys inclusion through surge pricing — where a
    /// fixed 100-stroop bid failed every reserve submission with
    /// tx_insufficient_fee for hours, freezing payouts and failing refunds.
    max_fee_stroops: u32,
}

impl StellarBaseSigner {
    fn network(&self) -> Network {
        Network::new(self.network_passphrase.clone())
    }

    /// Fetch the source account's current sequence number from Horizon.
    async fn fetch_sequence(&self, account_id: &str) -> Result<i64, AppError> {
        let url = format!(
            "{}/accounts/{}",
            self.horizon_url.trim_end_matches('/'),
            account_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| presubmit_error("horizon accounts request", e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::BadRequest(
                "source account does not exist on the network (not funded yet)".to_string(),
            ));
        }
        if !resp.status().is_success() {
            return Err(presubmit_error(
                "horizon accounts",
                format!("HTTP {}", resp.status()),
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| presubmit_error("horizon accounts response", e))?;
        // Horizon returns the sequence as a string.
        let seq_str = body["sequence"]
            .as_str()
            .ok_or_else(|| presubmit_error("horizon accounts", "missing sequence"))?;
        seq_str
            .parse::<i64>()
            .map_err(|e| presubmit_error("horizon accounts sequence parse", e))
    }

    /// Submit a base64 XDR transaction envelope to Horizon (`POST /transactions`,
    /// form-encoded). Returns the transaction hash on success.
    async fn submit(&self, xdr_base64: &str) -> Result<String, AppError> {
        let url = format!("{}/transactions", self.horizon_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .form(&[("tx", xdr_base64)])
            .send()
            .await
            .map_err(|e| signer_error("horizon submit request", e))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| signer_error("horizon submit response", e))?;
        if !status.is_success() {
            let codes = &body["extras"]["result_codes"];
            // Outcome classification is load-bearing for callers (the
            // conversion-reserve payout driver retries only DEFINITIVE
            // rejections): exactly HTTP 400 with parsed result codes proves
            // the transaction did not and cannot land -> BadRequest. Every
            // other non-2xx — Horizon 504 submission timeouts, 503, 429 —
            // means the transaction may still be queued and can land within
            // its validity window, so it must read as ambiguous
            // (InternalError), never as a safe-to-retry rejection.
            if status == reqwest::StatusCode::BAD_REQUEST && !codes.is_null() {
                let codes = codes.to_string();
                error!("stellar submit rejected: HTTP 400 codes={}", codes);
                return Err(AppError::BadRequest(format!(
                    "Stellar transaction rejected: {}",
                    codes
                )));
            }
            return Err(signer_error(
                "horizon submit",
                format!("HTTP {} codes={}", status, codes),
            ));
        }
        body["hash"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| signer_error("horizon submit", "missing tx hash"))
    }
}

#[async_trait]
impl StellarSigner for StellarBaseSigner {
    fn generate_keypair(&self) -> Result<(String, SecretBytes), AppError> {
        let kp = DalekKeyPair::random().map_err(|e| signer_error("keypair generation", e))?;
        let address = kp.public_key().account_id();
        let seed = kp.secret_key().secret_seed();
        Ok((address, SecretBytes::new(seed.into_bytes())))
    }

    fn public_address(&self, seed: &[u8]) -> Result<String, AppError> {
        let kp = keypair_from_seed(seed)?;
        Ok(kp.public_key().account_id())
    }

    fn seed_from_strkey(&self, s_strkey: &str) -> Result<SecretBytes, AppError> {
        // Constructing the keypair validates the strkey checksum.
        keypair_from_seed(s_strkey.as_bytes())?;
        Ok(SecretBytes::new(s_strkey.as_bytes().to_vec()))
    }

    async fn sign_and_submit_payment(
        &self,
        seed: &[u8],
        params: &PaymentParams,
    ) -> Result<SubmittedTx, AppError> {
        let prepared = self.prepare_payment(seed, params).await?;
        self.submit_prepared(&prepared).await
    }

    async fn submit_prepared(&self, prepared: &PreparedTx) -> Result<SubmittedTx, AppError> {
        // The hash is known before submission. On failure it is the ONLY
        // handle an operator has to learn whether an ambiguous submit
        // (timeout, 5xx) landed anyway, so it is logged with the error rather
        // than discarded along with the Err.
        let submitted_hash = self.submit(&prepared.xdr).await.map_err(|e| {
            error!(
                "stellar signer: submit failed for source={} hash={}: {} — an ambiguous \
                 failure may still be applied within the {}s validity window",
                prepared.source_account, prepared.stellar_hash, e, TX_TIMEOUT_SECS
            );
            e
        })?;
        Ok(SubmittedTx {
            stellar_hash: prepared.stellar_hash.clone(),
            stellar_tx_id: Some(submitted_hash),
            source_account: prepared.source_account.clone(),
        })
    }

    async fn prepare_payment(
        &self,
        seed: &[u8],
        params: &PaymentParams,
    ) -> Result<PreparedTx, AppError> {
        // Pure validation/build first, so a malformed request fails before
        // any network round trip (and never as an ambiguous outcome).
        let destination = PublicKey::from_account_id(&params.destination)
            .map_err(|_| AppError::BadRequest("invalid destination address".to_string()))?;
        let amount = Amount::from_str(&params.amount)
            .map_err(|_| AppError::BadRequest("invalid amount".to_string()))?;
        let asset = sb_asset(&params.asset)?;

        let payment = Operation::new_payment()
            .with_destination(destination)
            .with_amount(amount)
            .map_err(|_| AppError::BadRequest("invalid amount".to_string()))?
            .with_asset(asset)
            .build()
            .map_err(|e| presubmit_error("build payment", e))?;

        let memo = match &params.memo {
            Some(text) => Memo::new_text(text.clone())
                .map_err(|_| AppError::BadRequest("memo must be at most 28 bytes".to_string()))?,
            None => Memo::new_none(),
        };

        self.prepare_op(seed, payment, memo, params.fee).await
    }

    async fn sign_and_submit_change_trust(
        &self,
        seed: &[u8],
        asset: &Asset,
    ) -> Result<SubmittedTx, AppError> {
        if matches!(asset, Asset::Native) {
            return Err(AppError::BadRequest(
                "native XLM needs no trustline".to_string(),
            ));
        }
        let line = sb_asset(asset)?;
        // Maximum limit: the reserve's capacity is governed by its ledger
        // buckets, not by a trustline ceiling that would make a large
        // legitimate deposit fail on-chain.
        let op = Operation::new_change_trust()
            .with_asset(line.into())
            .with_limit(Some(Stroops::max()))
            .map_err(|e| presubmit_error("change_trust limit", e))?
            .build()
            .map_err(|e| presubmit_error("build change_trust", e))?;
        let prepared = self.prepare_op(seed, op, Memo::new_none(), None).await?;
        self.submit_prepared(&prepared).await
    }
}

/// Translate the bridge's asset into stellar-base's, validating code/issuer.
fn sb_asset(asset: &Asset) -> Result<SbAsset, AppError> {
    Ok(match asset {
        Asset::Native => SbAsset::new_native(),
        Asset::Credit { code, issuer } => {
            let issuer_pk = PublicKey::from_account_id(issuer)
                .map_err(|_| AppError::BadRequest("invalid asset issuer".to_string()))?;
            SbAsset::new_credit(code.clone(), issuer_pk)
                .map_err(|_| AppError::BadRequest("invalid asset code".to_string()))?
        }
    })
}

impl StellarBaseSigner {
    /// The shared pre-submit tail every signed transaction goes through:
    /// sequence fetch, fee, validity window, sign, hash, encode. Every failure
    /// here is provably pre-submit (retryable); only `submit_prepared` can be
    /// ambiguous.
    async fn prepare_op(
        &self,
        seed: &[u8],
        op: Operation,
        memo: Memo,
        fee: Option<u32>,
    ) -> Result<PreparedTx, AppError> {
        let kp = keypair_from_seed(seed)?;
        let source = kp.public_key().account_id();

        // The tx sequence must be the account's current sequence + 1.
        let current_seq = self.fetch_sequence(&source).await?;
        let next_seq = current_seq
            .checked_add(1)
            .ok_or_else(|| presubmit_error("sequence", "overflow"))?;

        let base_fee = Stroops::new(fee.unwrap_or(self.max_fee_stroops) as i64);
        let base_fee = if base_fee < MIN_BASE_FEE {
            MIN_BASE_FEE
        } else {
            base_fee
        };

        let network = self.network();
        let mut tx = Transaction::builder(kp.public_key(), next_seq, base_fee)
            .with_memo(memo)
            .with_time_bounds(TimeBounds::valid_for(chrono::Duration::seconds(
                TX_TIMEOUT_SECS,
            )))
            .add_operation(op)
            .into_transaction()
            .map_err(|e| presubmit_error("build transaction", e))?;

        tx.sign(kp.as_ref(), &network)
            .map_err(|e| presubmit_error("sign", e))?;

        let hash = tx.hash(&network).map_err(|e| presubmit_error("hash", e))?;
        let stellar_hash = hex_encode(&hash);

        let xdr = tx
            .into_envelope()
            .xdr_base64()
            .map_err(|e| presubmit_error("xdr encode", e))?;

        Ok(PreparedTx {
            xdr,
            stellar_hash,
            source_account: source,
        })
    }
}

/// Build the signer once at startup from the resolved Stellar network config.
pub fn build_signer(stellar_config: &StellarConfig) -> Arc<dyn StellarSigner> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
        .build()
        .expect("failed to build Stellar HTTP client");
    Arc::new(StellarBaseSigner {
        http,
        horizon_url: stellar_config.horizon_url.clone(),
        network_passphrase: stellar_config.network_passphrase.clone(),
        max_fee_stroops: stellar_config.max_fee_stroops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff, 0xab]), "000fffab");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_keypair_round_trip_via_generate() {
        // Generate -> seed bytes -> public address must be stable.
        let signer = StellarBaseSigner {
            http: reqwest::Client::new(),
            horizon_url: "https://horizon-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            max_fee_stroops: 10_000,
        };
        let (address, seed) = signer.generate_keypair().unwrap();
        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
        let derived = signer.public_address(seed.as_slice()).unwrap();
        assert_eq!(address, derived);
        // The seed bytes are an S-strkey.
        let s = std::str::from_utf8(seed.as_slice()).unwrap();
        assert!(s.starts_with('S'));
        assert_eq!(s.len(), 56);
        assert!(signer.seed_from_strkey(s).is_ok());
    }

    #[test]
    fn test_seed_from_strkey_rejects_garbage() {
        let signer = StellarBaseSigner {
            http: reqwest::Client::new(),
            horizon_url: "https://horizon-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            max_fee_stroops: 10_000,
        };
        assert!(signer.seed_from_strkey("not-a-seed").is_err());
        // A valid-looking G-address is not a seed.
        assert!(signer
            .seed_from_strkey("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF5")
            .is_err());
    }

    /// Live Stellar TESTNET probe of the ChangeTrust path — the only new
    /// signer code that talks to a real network, so it is exercised against
    /// one. Opt-in (`IMPALA_TESTNET_PROBE=1 cargo test -- --ignored
    /// testnet_change_trust`): funds a throwaway keypair via friendbot, adds a
    /// trustline to Circle's testnet USDC, verifies it on Horizon, re-asserts
    /// it (must be an on-chain no-op that still succeeds), and checks native
    /// XLM is refused. Never touches pubnet or any real funds.
    #[tokio::test]
    #[ignore = "live testnet probe; set IMPALA_TESTNET_PROBE=1 and run with --ignored"]
    async fn testnet_change_trust_roundtrip() {
        if std::env::var("IMPALA_TESTNET_PROBE").is_err() {
            return;
        }
        const HORIZON: &str = "https://horizon-testnet.stellar.org";
        const USDC_TESTNET_ISSUER: &str =
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        let signer = StellarBaseSigner {
            http: http.clone(),
            horizon_url: HORIZON.to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            max_fee_stroops: 10_000,
        };
        let (address, seed) = signer.generate_keypair().unwrap();

        // Fund via friendbot (reqwest first; curl fallback for the TLS quirk
        // some clients hit on that host).
        let fb = format!("https://friendbot.stellar.org/?addr={}", address);
        let funded = match http.get(&fb).send().await {
            Ok(r) if r.status().is_success() => true,
            _ => std::process::Command::new("curl")
                .args(["-sf", "-m", "60", &fb])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
        };
        assert!(funded, "friendbot funding failed for {}", address);

        let asset = Asset::Credit {
            code: "USDC".to_string(),
            issuer: USDC_TESTNET_ISSUER.to_string(),
        };
        let first = signer
            .sign_and_submit_change_trust(seed.as_slice(), &asset)
            .await
            .expect("ChangeTrust submits");
        assert_eq!(first.source_account, address);
        assert_eq!(first.stellar_hash.len(), 64);
        // Horizon's POST /transactions returns after inclusion, so the hash
        // it echoes must be the hash we computed locally.
        assert_eq!(
            first.stellar_tx_id.as_deref(),
            Some(first.stellar_hash.as_str())
        );

        let acct = crate::stellar::fetch_account_details(&http, HORIZON, &address)
            .await
            .unwrap();
        assert!(acct.exists);
        assert!(
            acct.balances
                .iter()
                .any(|b| b.asset_code.as_deref() == Some("USDC")
                    && b.asset_issuer.as_deref() == Some(USDC_TESTNET_ISSUER)),
            "trustline missing on-chain: {:?}",
            acct.balances
        );

        // Re-asserting an existing trustline is a no-op that still succeeds.
        signer
            .sign_and_submit_change_trust(seed.as_slice(), &asset)
            .await
            .expect("re-assert succeeds");

        // Native XLM needs no trustline and is refused before any I/O.
        assert!(matches!(
            signer
                .sign_and_submit_change_trust(seed.as_slice(), &Asset::Native)
                .await,
            Err(AppError::BadRequest(_))
        ));
        eprintln!("testnet probe OK: {} tx {}", address, first.stellar_hash);
    }
}
