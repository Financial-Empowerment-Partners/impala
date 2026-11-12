//! SEP-10 (Stellar Web Authentication) for card-held Stellar keys.
//!
//! The binding contract is `docs/sep10-card-keys.md`; the earlier,
//! adversarially reviewed bridge design is `docs/sep10-authentication.md`
//! (this module implements its §7 layers 1-3, §8 custody and §9 lifecycle for
//! the card key kind only). Where the two disagree, the card document wins.
//!
//! - [`binding`]: the two card cross-signatures checked by `POST /card`.
//! - [`challenge`]: building a login challenge and its MAC-bound nonce.
//! - [`verify`]: the pure verifier (strict decode, issued-challenge check,
//!   master signature). No I/O, injected clock.
//! - [`key`]: the generate-only signing key, its sealed form, and the
//!   background ring the public handlers read.
//! - [`backend`]: the Redis/Postgres operations the POST handler performs, behind
//!   a trait so the handler order can be tested in-process.
//!
//! Nothing here touches a custodial seed: the ring holds only SEP-10 signing
//! keys, and no source in this module references the managed-seed loaders or
//! the custodial transaction signer (pinned by `key.rs` tests).

pub mod backend;
pub mod binding;
pub mod challenge;
pub mod key;
pub mod verify;

#[cfg(test)]
mod card_vectors;

use sha2::{Digest, Sha256};

/// `SHA-256(passphrase)`: the network id inside every signed hash.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// `SHA-256(networkId ‖ ENVELOPE_TYPE_TX ‖ tx)`: the hash a Stellar
/// signature over a v1 transaction covers (the `TransactionSignaturePayload`
/// encoding, computed over the exact transaction bytes).
pub fn transaction_hash(network_id: &[u8; 32], tx_xdr: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(network_id);
    h.update(ENVELOPE_TYPE_TX);
    h.update(tx_xdr);
    h.finalize().into()
}

/// XDR `ENVELOPE_TYPE_TX` (2), big-endian.
pub const ENVELOPE_TYPE_TX: [u8; 4] = [0, 0, 0, 2];

/// The last four bytes of an Ed25519 public key: a decorated signature's hint.
pub fn signature_hint(public: &[u8; 32]) -> [u8; 4] {
    [public[28], public[29], public[30], public[31]]
}

/// Verify an Ed25519 signature (`aws-lc-rs`, the `card_auth.rs` pattern).
pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, public)
        .verify(message, signature)
        .is_ok()
}

/// The `preauth_src` / lockout bucket for a client source: IPv6 sources are
/// aggregated to their /64 (one subscriber's allocation), so rotating the low
/// 64 bits does not buy a fresh budget. IPv4 and `unknown` pass through.
pub fn source_bucket(source: &str) -> String {
    match source.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => {
            let s = v6.segments();
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{net}/64")
        }
        Err(_) => source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_is_sha256_of_the_passphrase() {
        // Well-known testnet network id.
        assert_eq!(
            hex::encode(network_id(crate::constants::STELLAR_TESTNET_PASSPHRASE)),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    /// The hash equals stellar-base's own `TransactionSignaturePayload` hash
    /// for the same transaction (the probe the design asks for).
    #[test]
    fn transaction_hash_matches_the_signature_payload_encoding() {
        use stellar_base::xdr::{
            Hash, Limits, Transaction, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };
        let tx = Transaction::default();
        let nid = network_id("Test SDF Network ; September 2015");
        let payload = TransactionSignaturePayload {
            network_id: Hash(nid),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        let expected: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
        let tx_bytes = tx.to_xdr(Limits::none()).unwrap();
        assert_eq!(transaction_hash(&nid, &tx_bytes), expected);
    }

    #[test]
    fn ipv6_sources_aggregate_to_their_slash_64() {
        assert_eq!(
            source_bucket("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            "2001:db8:1:2::/64"
        );
        assert_eq!(source_bucket("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(source_bucket("203.0.113.9"), "203.0.113.9");
        assert_eq!(source_bucket("unknown"), "unknown");
    }
}
