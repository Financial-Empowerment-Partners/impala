//! Building a SEP-10 login challenge (`docs/sep10-card-keys.md` §6,
//! `docs/sep10-authentication.md` §9).
//!
//! ```text
//! source   the active server key          seqNum 0      fee 100 × 2
//! cond     PRECOND_TIME [now, now + TTL]  memo none     ext v0
//! op[0]    manage_data "<home_domain> auth" = nonce     source = client G
//! op[1]    manage_data "web_auth_domain"   = <domain>   source = server key
//! signatures: exactly one, the server's
//! ```
//!
//! The nonce is 64 base64 characters encoding 48 bytes,
//! `r16 ‖ HMAC-SHA256(k_mac[version], "impala-sep10-chal-v1" ‖ "login" ‖ G32 ‖
//! minTime_be64 ‖ maxTime_be64 ‖ version_be32 ‖ networkId32 ‖ r16)`, so a
//! login challenge needs no server-side state: the verifier recomputes the
//! MAC. A leaked signing key alone cannot mint acceptable challenges without
//! the MAC key sealed beside it.

use base64::Engine;
use stellar_base::xdr::{
    DataValue, DecoratedSignature, Limits, ManageDataOp, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, SequenceNumber, Signature, SignatureHint, String64, TimeBounds,
    TimePoint, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
    WriteXdr,
};

use crate::constants::{
    SEP10_FEE_PER_OP, SEP10_NONCE_DOMAIN, SEP10_NONCE_RANDOM_BYTES, SEP10_PURPOSE_LOGIN,
    SEP10_WEB_AUTH_DOMAIN_KEY,
};
use crate::error::AppError;
use crate::sep10::key::Sep10Key;

/// The exact bytes the nonce MAC covers.
pub fn nonce_mac_input(
    purpose: &[u8],
    client: &[u8; 32],
    min_time: u64,
    max_time: u64,
    version: i32,
    network_id: &[u8; 32],
    r16: &[u8; SEP10_NONCE_RANDOM_BYTES],
) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(SEP10_NONCE_DOMAIN.len() + purpose.len() + 32 + 8 + 8 + 4 + 32 + 16);
    m.extend_from_slice(SEP10_NONCE_DOMAIN);
    m.extend_from_slice(purpose);
    m.extend_from_slice(client);
    m.extend_from_slice(&min_time.to_be_bytes());
    m.extend_from_slice(&max_time.to_be_bytes());
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(network_id);
    m.extend_from_slice(r16);
    m
}

/// The 64-character nonce for a login challenge.
pub fn login_nonce(
    key: &Sep10Key,
    version: i32,
    client: &[u8; 32],
    min_time: u64,
    max_time: u64,
    network_id: &[u8; 32],
    r16: &[u8; SEP10_NONCE_RANDOM_BYTES],
) -> String {
    let mac = key.mac(&nonce_mac_input(
        SEP10_PURPOSE_LOGIN,
        client,
        min_time,
        max_time,
        version,
        network_id,
        r16,
    ));
    let mut raw = Vec::with_capacity(48);
    raw.extend_from_slice(r16);
    raw.extend_from_slice(&mac);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// What a challenge is issued for.
pub struct ChallengeParams<'a> {
    pub client: [u8; 32],
    pub home_domain: &'a str,
    pub web_auth_domain: &'a str,
    pub network_id: [u8; 32],
    pub min_time: u64,
    pub ttl_secs: u64,
}

fn xdr_err(_: impl std::fmt::Debug) -> AppError {
    AppError::InternalError("failed to build the challenge".to_string())
}

fn manage_data(source: [u8; 32], name: &str, value: &[u8]) -> Result<Operation, AppError> {
    Ok(Operation {
        source_account: Some(MuxedAccount::Ed25519(Uint256(source))),
        body: OperationBody::ManageData(ManageDataOp {
            data_name: String64(name.try_into().map_err(xdr_err)?),
            data_value: Some(DataValue(value.to_vec().try_into().map_err(xdr_err)?)),
        }),
    })
}

/// The unsigned login challenge transaction.
pub fn challenge_transaction(
    key: &Sep10Key,
    version: i32,
    p: &ChallengeParams<'_>,
    r16: &[u8; SEP10_NONCE_RANDOM_BYTES],
) -> Result<Transaction, AppError> {
    let server = key.public();
    let max_time = p.min_time + p.ttl_secs;
    let nonce = login_nonce(
        key,
        version,
        &p.client,
        p.min_time,
        max_time,
        &p.network_id,
        r16,
    );
    let ops = vec![
        manage_data(
            p.client,
            &format!("{} auth", p.home_domain),
            nonce.as_bytes(),
        )?,
        manage_data(
            server,
            SEP10_WEB_AUTH_DOMAIN_KEY,
            p.web_auth_domain.as_bytes(),
        )?,
    ];
    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(server)),
        fee: SEP10_FEE_PER_OP * ops.len() as u32,
        seq_num: SequenceNumber(0),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(p.min_time),
            max_time: TimePoint(max_time),
        }),
        memo: Memo::None,
        operations: ops.try_into().map_err(xdr_err)?,
        ext: TransactionExt::V0,
    })
}

/// Sign `tx` with the server key and wrap it in a v1 envelope, base64.
pub fn sign_envelope(
    key: &Sep10Key,
    tx: Transaction,
    network_id: &[u8; 32],
) -> Result<String, AppError> {
    let tx_bytes = tx.to_xdr(Limits::none()).map_err(xdr_err)?;
    let hash = super::transaction_hash(network_id, &tx_bytes);
    let signature = key.sign_challenge_hash(&hash);
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![DecoratedSignature {
            hint: SignatureHint(super::signature_hint(&key.public())),
            signature: Signature(signature.to_vec().try_into().map_err(xdr_err)?),
        }]
        .try_into()
        .map_err(xdr_err)?,
    });
    let bytes = envelope.to_xdr(Limits::none()).map_err(xdr_err)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Build and sign a login challenge with fresh randomness.
pub fn build_login_challenge(
    key: &Sep10Key,
    version: i32,
    p: &ChallengeParams<'_>,
) -> Result<String, AppError> {
    let mut r16 = [0u8; SEP10_NONCE_RANDOM_BYTES];
    aws_lc_rs::rand::fill(&mut r16)
        .map_err(|_| AppError::InternalError("Failed to generate challenge".to_string()))?;
    let tx = challenge_transaction(key, version, p, &r16)?;
    sign_envelope(key, tx, &p.network_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sep10::key::tests::test_key;

    #[test]
    fn nonce_is_64_base64_characters_of_48_bytes() {
        let (key, _) = test_key();
        let n = login_nonce(&key, 3, &[1u8; 32], 100, 400, &[2u8; 32], &[3u8; 16]);
        assert_eq!(n.len(), 64);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&n)
            .unwrap();
        assert_eq!(raw.len(), 48);
        assert_eq!(&raw[..16], &[3u8; 16]);
        // Every bound input changes the MAC.
        let base = login_nonce(&key, 3, &[1u8; 32], 100, 400, &[2u8; 32], &[3u8; 16]);
        assert_eq!(base, n, "deterministic for fixed randomness");
        for other in [
            login_nonce(&key, 4, &[1u8; 32], 100, 400, &[2u8; 32], &[3u8; 16]),
            login_nonce(&key, 3, &[9u8; 32], 100, 400, &[2u8; 32], &[3u8; 16]),
            login_nonce(&key, 3, &[1u8; 32], 101, 400, &[2u8; 32], &[3u8; 16]),
            login_nonce(&key, 3, &[1u8; 32], 100, 401, &[2u8; 32], &[3u8; 16]),
            login_nonce(&key, 3, &[1u8; 32], 100, 400, &[8u8; 32], &[3u8; 16]),
        ] {
            assert_ne!(other[22..], base[22..], "the MAC half must change");
        }
        let (other_key, _) = test_key();
        assert_ne!(
            login_nonce(&other_key, 3, &[1u8; 32], 100, 400, &[2u8; 32], &[3u8; 16]),
            base
        );
    }

    /// The card refuses a transaction over `SEP10_MAX_TX_LENGTH` (640 bytes)
    /// or with more than 5 operations (contract §2): the largest challenge
    /// this bridge can issue (a 59-byte home domain) must fit.
    #[test]
    fn the_largest_challenge_fits_the_card_limits() {
        let (key, _) = test_key();
        let home = format!("{}.example.com", "a".repeat(59 - ".example.com".len()));
        assert_eq!(home.len(), crate::constants::SEP10_HOME_DOMAIN_MAX_LEN);
        let tx = challenge_transaction(
            &key,
            i32::MAX,
            &ChallengeParams {
                client: [7u8; 32],
                home_domain: &home,
                web_auth_domain: &home,
                network_id: [1u8; 32],
                min_time: u64::MAX / 4,
                ttl_secs: 900,
            },
            &[0u8; 16],
        )
        .unwrap();
        let bytes = tx.to_xdr(Limits::none()).unwrap();
        assert!(bytes.len() <= 640, "{} bytes", bytes.len());
        assert!(tx.operations.len() <= 5);
    }

    /// The MAC input layout is pinned byte for byte.
    #[test]
    fn nonce_mac_input_layout_is_pinned() {
        let m = nonce_mac_input(
            b"login",
            &[0x11; 32],
            0x0102,
            0x0304,
            7,
            &[0x22; 32],
            &[0x33; 16],
        );
        let expected = format!(
            "{}{}{}{}{}{}{}{}",
            hex::encode(b"impala-sep10-chal-v1"),
            hex::encode(b"login"),
            "11".repeat(32),
            "0000000000000102",
            "0000000000000304",
            "00000007",
            "22".repeat(32),
            "33".repeat(16)
        );
        assert_eq!(hex::encode(m), expected);
    }
}
