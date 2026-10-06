//! Pure byte formats of the card transfer protocol v1 — no I/O, no secrets.
//!
//! The card's formats are the truth (contract-addendum.md §A). Every literal
//! here is reproduced byte-for-byte by the SDK's `TransferProtocol` and pinned
//! on both sides by the shared golden vectors.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::constants::{
    CARD_CERT_DOMAIN_PREFIX, CARD_CERT_MESSAGE_LEN, CARD_CERT_VERSION, CARD_CURRENCY_TAGS,
    CARD_PROGRAM_ID_LEN, CARD_SIGNABLE_LEN, CARD_TRANSFER_PROTOCOL_VERSION,
    CARD_XFER_DOMAIN_PREFIX, CARD_XFER_MESSAGE_LEN,
};

/// Uncompressed SEC1 P-256 point length (`04 ‖ X ‖ Y`).
pub(crate) const POINT_LEN: usize = 65;
/// Fixed DER signature slot on the card wire.
pub(crate) const SLOT_LEN: usize = 72;
/// Shortest DER ECDSA signature the protocol accepts.
pub(crate) const MIN_DER_LEN: usize = 8;

/// The 4-byte card tag for a bucket currency (`XLM`, `USDC`, `USDT0`).
pub(crate) fn currency_tag(bucket: &str) -> Option<[u8; 4]> {
    CARD_CURRENCY_TAGS
        .iter()
        .find(|(code, _)| *code == bucket)
        .map(|(_, tag)| *tag)
}

/// `"IMPALA-CERT:" ‖ 0x01 ‖ programId(16) ‖ account(16) ‖ tag(4) ‖ cardPubKey(65)` — 114 bytes.
pub(crate) fn card_cert_message(
    program_id: &[u8; CARD_PROGRAM_ID_LEN],
    account: &Uuid,
    tag: [u8; 4],
    card_pubkey: &[u8; POINT_LEN],
) -> [u8; CARD_CERT_MESSAGE_LEN] {
    let mut out = [0u8; CARD_CERT_MESSAGE_LEN];
    out[..12].copy_from_slice(CARD_CERT_DOMAIN_PREFIX);
    out[12] = CARD_CERT_VERSION;
    out[13..29].copy_from_slice(program_id);
    out[29..45].copy_from_slice(account.as_bytes());
    out[45..49].copy_from_slice(&tag);
    out[49..].copy_from_slice(card_pubkey);
    out
}

/// `"IMPALA-XFER:" ‖ 0x01 ‖ programId(16) ‖ signable(60)` — 89 bytes.
#[allow(dead_code)] // used by issuance credits / redemption verification (lane C2)
pub(crate) fn xfer_message(
    program_id: &[u8; CARD_PROGRAM_ID_LEN],
    signable: &[u8; CARD_SIGNABLE_LEN],
) -> [u8; CARD_XFER_MESSAGE_LEN] {
    let mut out = [0u8; CARD_XFER_MESSAGE_LEN];
    out[..12].copy_from_slice(CARD_XFER_DOMAIN_PREFIX);
    out[12] = CARD_TRANSFER_PROTOCOL_VERSION;
    out[13..29].copy_from_slice(program_id);
    out[29..].copy_from_slice(signable);
    out
}

/// SHA-256 hex of the XFER message: THE canonical id of a card transfer.
#[allow(dead_code)] // used by issuance credits / redemption verification (lane C2)
pub(crate) fn transfer_id_hex(
    program_id: &[u8; CARD_PROGRAM_ID_LEN],
    signable: &[u8; CARD_SIGNABLE_LEN],
) -> String {
    hex::encode(Sha256::digest(xfer_message(program_id, signable)))
}

/// SHA-256 hex of the CERT message: the certificate registry / revocation key.
pub(crate) fn cert_id_hex(cert_message: &[u8; CARD_CERT_MESSAGE_LEN]) -> String {
    hex::encode(Sha256::digest(cert_message))
}

/// Zero-pads a DER signature (8..=72 bytes) into the 72-byte wire slot.
#[allow(dead_code)] // used by issuance credits / redemption verification (lane C2)
pub(crate) fn pad72(der: &[u8]) -> Option<[u8; SLOT_LEN]> {
    if der.len() < MIN_DER_LEN || der.len() > SLOT_LEN {
        return None;
    }
    let mut out = [0u8; SLOT_LEN];
    out[..der.len()].copy_from_slice(der);
    Some(out)
}

/// ECDSA-P256/SHA-256 (ASN.1 DER) over `msg` under a 65-byte uncompressed point.
pub(crate) fn verify_p256(pubkey: &[u8], msg: &[u8], der: &[u8]) -> bool {
    if pubkey.len() != POINT_LEN || pubkey[0] != 0x04 {
        return false;
    }
    if der.len() < MIN_DER_LEN || der.len() > SLOT_LEN {
        return false;
    }
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        pubkey,
    )
    .verify(msg, der)
    .is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Shared golden vectors (impala-card/docs/transfer-protocol.md §4). The
    // same four literals live in card_auth.rs tests and the SDK's
    // TransferProtocolGoldenTest; scripts/check-shared-vectors.sh pins that.
    pub(crate) const PROGRAM: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    pub(crate) const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";
    /// The generator point G of P-256, uncompressed: a valid public key no one holds.
    pub(crate) const G_POINT_HEX: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    pub(crate) fn golden_signable() -> [u8; 60] {
        let mut s = [0u8; 60];
        s[7] = 1; // dateTime = 1
        s[8..24].copy_from_slice(Uuid::parse_str(ACCOUNT).unwrap().as_bytes());
        s[24..40].copy_from_slice(&hex::decode("ffeeddccbbaa99887766554433221100").unwrap());
        s[40..44].copy_from_slice(b"USDC");
        s[44..48].copy_from_slice(&1000u32.to_be_bytes());
        s[56..60].copy_from_slice(&1u32.to_be_bytes());
        s
    }

    #[test]
    fn cert_message_golden() {
        let point: [u8; 65] = hex::decode(G_POINT_HEX).unwrap().try_into().unwrap();
        let msg = card_cert_message(
            &PROGRAM,
            &Uuid::parse_str(ACCOUNT).unwrap(),
            currency_tag("USDC").unwrap(),
            &point,
        );
        assert_eq!(hex::encode(msg), "494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        assert_eq!(
            cert_id_hex(&msg),
            "82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b"
        );
    }

    #[test]
    fn xfer_message_golden() {
        let s = golden_signable();
        assert_eq!(hex::encode(xfer_message(&PROGRAM, &s)), "494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001");
        assert_eq!(
            transfer_id_hex(&PROGRAM, &s),
            "6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9"
        );
    }

    #[test]
    fn currency_tags_resolve_only_known_buckets() {
        assert_eq!(currency_tag("XLM"), Some(*b"XLM\0"));
        assert_eq!(currency_tag("USDT0"), Some(*b"UST0"));
        assert_eq!(currency_tag("USD"), None);
        assert_eq!(currency_tag("xlm"), None);
    }

    #[test]
    fn pad72_bounds() {
        assert!(pad72(&[0x30; 7]).is_none());
        assert!(pad72(&[0x30; 73]).is_none());
        let p = pad72(&[0x30, 0x06, 1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(&p[..8], &[0x30, 0x06, 1, 2, 3, 4, 5, 6]);
        assert!(p[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn verify_p256_refuses_malformed_inputs() {
        let point = hex::decode(G_POINT_HEX).unwrap();
        assert!(!verify_p256(&point[1..], b"m", &[0x30; 70]));
        assert!(!verify_p256(&point, b"m", &[0x30; 4]));
        assert!(!verify_p256(&point, b"m", &[0x30; 70]));
    }
}
