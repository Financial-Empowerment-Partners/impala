//! The card's Stellar key cross-signatures (`docs/sep10-card-keys.md` §3.2,
//! §6 `POST /card`).
//!
//! ```text
//! SKEY_A = "IMPALA-SKEY:" ‖ 0x01 ‖ accountId(16) ‖ cardId(16) ‖ ed25519Pub(32)   77 bytes
//! SKEY_B = "IMPALA-SKEY:" ‖ 0x02 ‖ accountId(16) ‖ cardId(16) ‖ ecPub(65)        110 bytes
//! bindingSig = ECDSA-P256-SHA256(card EC key, SKEY_A)   ASN.1 DER
//! proofSig   = Ed25519(card Stellar key, SKEY_B)         64 bytes
//! ```
//!
//! `bindingSig` says the card's EC key vouches for the Stellar key; `proofSig`
//! proves possession of the Stellar key, bound to this account and this card,
//! so an address cannot be registered under another account or card.
//! The bridge rebuilds both messages from the request (never from client
//! bytes) and verifies both before the card row is written.

use axum::http::StatusCode;
use uuid::Uuid;

use crate::constants::{
    STELLAR_BINDING_SIG_HEX_MAX, STELLAR_BINDING_SIG_HEX_MIN, STELLAR_PROOF_SIG_HEX_LEN,
    STELLAR_SKEY_A_LEN, STELLAR_SKEY_B_LEN, STELLAR_SKEY_DOMAIN_PREFIX, STELLAR_SKEY_KIND_BINDING,
    STELLAR_SKEY_KIND_PROOF,
};
use crate::error::AppError;

/// The machine-readable refusal for every binding failure.
pub const INVALID_STELLAR_BINDING: &str = "invalid_stellar_binding";

/// `SKEY_A`: what the card's EC key signs.
pub fn skey_a(
    account: &Uuid,
    card_id: &[u8; 16],
    stellar_pub: &[u8; 32],
) -> [u8; STELLAR_SKEY_A_LEN] {
    let mut m = [0u8; STELLAR_SKEY_A_LEN];
    m[..12].copy_from_slice(STELLAR_SKEY_DOMAIN_PREFIX);
    m[12] = STELLAR_SKEY_KIND_BINDING;
    m[13..29].copy_from_slice(account.as_bytes());
    m[29..45].copy_from_slice(card_id);
    m[45..77].copy_from_slice(stellar_pub);
    m
}

/// `SKEY_B`: what the card's Stellar key signs.
pub fn skey_b(account: &Uuid, card_id: &[u8; 16], ec_pub: &[u8; 65]) -> [u8; STELLAR_SKEY_B_LEN] {
    let mut m = [0u8; STELLAR_SKEY_B_LEN];
    m[..12].copy_from_slice(STELLAR_SKEY_DOMAIN_PREFIX);
    m[12] = STELLAR_SKEY_KIND_PROOF;
    m[13..29].copy_from_slice(account.as_bytes());
    m[29..45].copy_from_slice(card_id);
    m[45..110].copy_from_slice(ec_pub);
    m
}

/// Both cross-signatures verify over the messages rebuilt from these inputs.
/// Pure; the parsing and error mapping live in [`check_stellar_fields`].
pub fn verify_binding(
    account: &Uuid,
    card_id: &[u8; 16],
    ec_pub: &[u8; 65],
    stellar_pub: &[u8; 32],
    binding_sig_der: &[u8],
    proof_sig: &[u8],
) -> bool {
    if ec_pub[0] != 0x04 || proof_sig.len() != 64 {
        return false;
    }
    let a = skey_a(account, card_id, stellar_pub);
    let b = skey_b(account, card_id, ec_pub);
    let binding_ok = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        ec_pub,
    )
    .verify(&a, binding_sig_der)
    .is_ok();
    // Evaluate both so the time taken does not say which one failed.
    let proof_ok = super::ed25519_verify(stellar_pub, &b, proof_sig);
    binding_ok & proof_ok
}

/// The verified Stellar fields of a `POST /card`, normalized for storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StellarCardBinding {
    pub stellar_address: String,
    pub binding_sig_hex: String,
    pub proof_sig_hex: String,
}

fn refuse(message: &str) -> AppError {
    AppError::coded(StatusCode::BAD_REQUEST, INVALID_STELLAR_BINDING, message)
}

fn absent(v: Option<&str>) -> bool {
    v.is_none_or(str::is_empty)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse and verify the optional Stellar fields of `POST /card`.
///
/// `Ok(None)` when all three are absent (`null`, missing or `""`): the request
/// takes the pre-040 path byte for byte. All three present: the address must
/// be a checksum-valid `G…`, the account id a UUID, the card id 16 bytes and
/// the EC key the 65-byte uncompressed point, and both signatures must
/// verify. Anything else is 400 `invalid_stellar_binding`.
pub fn check_stellar_fields(
    account_id: &str,
    card_id: &str,
    ec_pubkey_hex: &str,
    stellar_address: Option<&str>,
    binding_sig_hex: Option<&str>,
    proof_sig_hex: Option<&str>,
) -> Result<Option<StellarCardBinding>, AppError> {
    let fields = [stellar_address, binding_sig_hex, proof_sig_hex];
    if fields.iter().all(|f| absent(*f)) {
        return Ok(None);
    }
    let (Some(address), Some(binding_hex), Some(proof_hex)) =
        (stellar_address, binding_sig_hex, proof_sig_hex)
    else {
        return Err(refuse(
            "stellar_address, stellar_binding_sig and stellar_proof_sig must be sent together",
        ));
    };
    if fields.iter().any(|f| absent(*f)) {
        return Err(refuse(
            "stellar_address, stellar_binding_sig and stellar_proof_sig must be sent together",
        ));
    }

    let stellar_pub = crate::validate::decode_stellar_account_id(address)
        .map_err(|_| refuse("stellar_address must be a checksum-valid G… account id"))?;
    if binding_hex.len() % 2 != 0
        || !(STELLAR_BINDING_SIG_HEX_MIN..=STELLAR_BINDING_SIG_HEX_MAX).contains(&binding_hex.len())
        || !is_lower_hex(binding_hex)
    {
        return Err(refuse(
            "stellar_binding_sig must be 16-144 lowercase hex characters (trimmed DER)",
        ));
    }
    if proof_hex.len() != STELLAR_PROOF_SIG_HEX_LEN || !is_lower_hex(proof_hex) {
        return Err(refuse(
            "stellar_proof_sig must be 128 lowercase hex characters",
        ));
    }
    // The messages bind the 16 RFC-4122 account bytes and the 16-byte card
    // id the applet holds, and SKEY_B the uncompressed point.
    let account = Uuid::parse_str(account_id)
        .map_err(|_| refuse("a card with a Stellar key requires a UUID account id"))?;
    let card: [u8; 16] = hex::decode(card_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| refuse("a card with a Stellar key requires a 32-hex (16-byte) card_id"))?;
    let ec_pub: [u8; 65] = hex::decode(ec_pubkey_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .filter(|p: &[u8; 65]| p[0] == 0x04)
        .ok_or_else(|| {
            refuse("a card with a Stellar key requires the 130-hex uncompressed ec_pubkey")
        })?;
    let binding_der = hex::decode(binding_hex).map_err(|_| refuse("bad stellar_binding_sig"))?;
    let proof = hex::decode(proof_hex).map_err(|_| refuse("bad stellar_proof_sig"))?;

    if !verify_binding(&account, &card, &ec_pub, &stellar_pub, &binding_der, &proof) {
        return Err(refuse(
            "the Stellar key cross-signatures do not verify for this account, card and EC key",
        ));
    }
    Ok(Some(StellarCardBinding {
        stellar_address: address.to_string(),
        binding_sig_hex: binding_hex.to_string(),
        proof_sig_hex: proof_hex.to_string(),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    };

    pub const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";
    pub const CARD_ID: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    /// RFC 8032 §7.1 TEST 1 key pair: a fixed, published Ed25519 key, so the
    /// (deterministic) proof signature is a cross-stream vector.
    pub const RFC8032_SEED: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    pub const RFC8032_PUB: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// The secp256r1 generator point (the shared `G_POINT_HEX` vector).
    pub const EC_POINT: &str = crate::offline::signable::tests::G_POINT_HEX;

    fn account() -> Uuid {
        Uuid::parse_str(ACCOUNT).unwrap()
    }
    fn card() -> [u8; 16] {
        hex::decode(CARD_ID).unwrap().try_into().unwrap()
    }
    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    /// Fixed vectors. The SDK and applet tests pin the same bytes.
    #[test]
    fn skey_messages_have_the_pinned_layout() {
        let a = skey_a(&account(), &card(), &arr(RFC8032_PUB));
        assert_eq!(
            hex::encode(a),
            concat!(
                "494d50414c412d534b45593a", // "IMPALA-SKEY:"
                "01",
                "00112233445566778899aabbccddeeff",
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            )
        );
        let b = skey_b(&account(), &card(), &arr(EC_POINT));
        assert_eq!(
            hex::encode(b),
            format!(
                "494d50414c412d534b45593a02{}{}{}",
                "00112233445566778899aabbccddeeff", CARD_ID, EC_POINT
            )
        );
        assert_eq!(&a[..12], b"IMPALA-SKEY:");
        // Never collides with the AUTH/CERT/XFER domains at equal length.
        assert_ne!(&a[..12], crate::constants::CARD_AUTH_DOMAIN_PREFIX);
    }

    /// `proofSig` for the RFC 8032 key over the fixed `SKEY_B` above.
    /// Ed25519 is deterministic, so this is a byte-exact vector (computed
    /// independently with OpenSSL `pkeyutl -rawin` over the same message).
    pub const GOLDEN_PROOF_SIG: &str = "d3f6a3c541f6eaf7477d452f91c3595555136f8ec7aec2e9d9940ed65d884b8b2485dfcbb955829e549a78028e1cb920ef52a0c2b4dacb0705dd542b20c61d02";

    #[test]
    fn rfc8032_proof_signature_is_pinned() {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&hex::decode(RFC8032_SEED).unwrap()).unwrap();
        assert_eq!(hex::encode(pair.public_key().as_ref()), RFC8032_PUB);
        let msg = skey_b(&account(), &card(), &arr(EC_POINT));
        assert_eq!(hex::encode(pair.sign(&msg).as_ref()), GOLDEN_PROOF_SIG);
    }

    /// A freshly personalized card: EC key, Stellar key, both signatures.
    pub struct TestCard {
        pub ec: EcdsaKeyPair,
        pub ec_pub: [u8; 65],
        pub stellar: Ed25519KeyPair,
        pub stellar_pub: [u8; 32],
    }

    pub fn test_card() -> TestCard {
        let ec = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let ec_pub: [u8; 65] = ec.public_key().as_ref().try_into().unwrap();
        let stellar = Ed25519KeyPair::generate().unwrap();
        let stellar_pub: [u8; 32] = stellar.public_key().as_ref().try_into().unwrap();
        TestCard {
            ec,
            ec_pub,
            stellar,
            stellar_pub,
        }
    }

    impl TestCard {
        pub fn binding_sig(&self, account: &Uuid, card: &[u8; 16]) -> Vec<u8> {
            self.ec
                .sign(
                    &SystemRandom::new(),
                    &skey_a(account, card, &self.stellar_pub),
                )
                .unwrap()
                .as_ref()
                .to_vec()
        }
        pub fn proof_sig(&self, account: &Uuid, card: &[u8; 16]) -> Vec<u8> {
            self.stellar
                .sign(&skey_b(account, card, &self.ec_pub))
                .as_ref()
                .to_vec()
        }
        pub fn address(&self) -> String {
            crate::validate::encode_stellar_account_id(&self.stellar_pub)
        }
        /// `(stellar_address, stellar_binding_sig, stellar_proof_sig)` as sent.
        pub fn fields(&self, account: &Uuid, card: &[u8; 16]) -> (String, String, String) {
            (
                self.address(),
                hex::encode(self.binding_sig(account, card)),
                hex::encode(self.proof_sig(account, card)),
            )
        }
    }

    fn check(
        account_id: &str,
        card_id: &str,
        ec_hex: &str,
        f: &(String, String, String),
    ) -> Result<Option<StellarCardBinding>, AppError> {
        check_stellar_fields(
            account_id,
            card_id,
            ec_hex,
            Some(&f.0),
            Some(&f.1),
            Some(&f.2),
        )
    }

    fn code(e: AppError) -> &'static str {
        match e {
            AppError::Coded { code, status, .. } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                code
            }
            other => panic!("expected a coded refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_genuine_binding_verifies() {
        let c = test_card();
        let f = c.fields(&account(), &card());
        let got = check(ACCOUNT, CARD_ID, &hex::encode(c.ec_pub), &f)
            .unwrap()
            .unwrap();
        assert_eq!(got.stellar_address, f.0);
        assert_eq!(got.binding_sig_hex, f.1);
        assert_eq!(got.proof_sig_hex, f.2);
    }

    #[test]
    fn absent_fields_take_the_legacy_path() {
        let ec = hex::encode(test_card().ec_pub);
        assert_eq!(
            check_stellar_fields(ACCOUNT, CARD_ID, &ec, None, None, None).unwrap(),
            None
        );
        assert_eq!(
            check_stellar_fields(ACCOUNT, CARD_ID, &ec, Some(""), Some(""), None).unwrap(),
            None
        );
        // Even a non-UUID account and a short card id stay on the old path.
        assert_eq!(
            check_stellar_fields("alice", "00112233", "02ab", None, None, None).unwrap(),
            None
        );
    }

    #[test]
    fn partial_fields_are_refused() {
        let c = test_card();
        let (a, b, p) = c.fields(&account(), &card());
        let ec = hex::encode(c.ec_pub);
        for (x, y, z) in [
            (Some(a.as_str()), None, None),
            (None, Some(b.as_str()), Some(p.as_str())),
            (Some(a.as_str()), Some(b.as_str()), Some("")),
        ] {
            let e = check_stellar_fields(ACCOUNT, CARD_ID, &ec, x, y, z).unwrap_err();
            assert_eq!(code(e), INVALID_STELLAR_BINDING);
        }
    }

    #[test]
    fn wrong_account_card_key_or_swapped_signatures_are_refused() {
        let c = test_card();
        let f = c.fields(&account(), &card());
        let ec = hex::encode(c.ec_pub);
        // Wrong account: the same signatures presented for another account.
        let other_account = "ffeeddcc-bbaa-9988-7766-554433221100";
        assert_eq!(
            code(check(other_account, CARD_ID, &ec, &f).unwrap_err()),
            INVALID_STELLAR_BINDING
        );
        // Wrong card id.
        let other_card = "b0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        assert_eq!(
            code(check(ACCOUNT, other_card, &ec, &f).unwrap_err()),
            INVALID_STELLAR_BINDING
        );
        // Wrong EC key (another card's).
        let other_ec = hex::encode(test_card().ec_pub);
        assert_eq!(
            code(check(ACCOUNT, CARD_ID, &other_ec, &f).unwrap_err()),
            INVALID_STELLAR_BINDING
        );
        // Wrong Stellar key: another card's address with these signatures.
        let other_addr = (test_card().address(), f.1.clone(), f.2.clone());
        assert_eq!(
            code(check(ACCOUNT, CARD_ID, &ec, &other_addr).unwrap_err()),
            INVALID_STELLAR_BINDING
        );
        // Swapped: the Ed25519 signature in the binding slot and vice versa.
        let swapped = (f.0.clone(), f.2.clone(), f.1.clone());
        assert!(check(ACCOUNT, CARD_ID, &ec, &swapped).is_err());
        // Each signature over the other message (signed by the right key).
        let tag_swap_binding = hex::encode(
            c.ec.sign(
                &SystemRandom::new(),
                &skey_b(&account(), &card(), &c.ec_pub),
            )
            .unwrap()
            .as_ref(),
        );
        let tag_swap_proof = hex::encode(
            c.stellar
                .sign(&skey_a(&account(), &card(), &c.stellar_pub))
                .as_ref(),
        );
        let tag_swapped = (f.0.clone(), tag_swap_binding, tag_swap_proof);
        assert_eq!(
            code(check(ACCOUNT, CARD_ID, &ec, &tag_swapped).unwrap_err()),
            INVALID_STELLAR_BINDING
        );
        // Exactly one bad signature is enough to refuse.
        let mut bad_proof = f.clone();
        bad_proof.2 = format!(
            "{}{}",
            &f.2[..126],
            if f.2.ends_with('0') { "1" } else { "0" }
        );
        assert!(check(ACCOUNT, CARD_ID, &ec, &bad_proof).is_err());
    }

    #[test]
    fn malformed_fields_are_refused_before_any_crypto() {
        let c = test_card();
        let f = c.fields(&account(), &card());
        let ec = hex::encode(c.ec_pub);
        let mut typo = f.clone();
        typo.0 = format!(
            "{}{}",
            &f.0[..55],
            if f.0.ends_with('A') { "B" } else { "A" }
        );
        assert!(check(ACCOUNT, CARD_ID, &ec, &typo).is_err());
        let mut upper = f.clone();
        upper.2 = f.2.to_uppercase();
        assert!(check(ACCOUNT, CARD_ID, &ec, &upper).is_err());
        let mut long = f.clone();
        long.1 = "ab".repeat(73);
        assert!(check(ACCOUNT, CARD_ID, &ec, &long).is_err());
        // Compressed EC key, short card id, non-UUID account: no message can be built.
        let compressed = format!("02{}", &ec[2..66]);
        assert!(check(ACCOUNT, CARD_ID, &compressed, &f).is_err());
        assert!(check(ACCOUNT, "a0a1a2a3", &ec, &f).is_err());
        assert!(check("alice", CARD_ID, &ec, &f).is_err());
    }

    /// Trailing bytes after the DER (the applet's zero-padded 72-byte slot,
    /// untrimmed) are refused: the contract sends the trimmed DER.
    #[test]
    fn untrimmed_der_is_refused() {
        for _ in 0..8 {
            let c = test_card();
            let mut f = c.fields(&account(), &card());
            let ec = hex::encode(c.ec_pub);
            assert!(check(ACCOUNT, CARD_ID, &ec, &f).is_ok());
            let trimmed = f.1.clone();
            // The full 72-byte slot, zero padded, as GET_STELLAR_KEY returns it
            // (refused by the DER parser, or by the length bound when the DER
            // is already 72 bytes and padding pushes it past 144 hex).
            while f.1.len() < 144 {
                f.1.push('0');
            }
            if f.1 == trimmed {
                f.1.push_str("00");
            }
            assert!(check(ACCOUNT, CARD_ID, &ec, &f).is_err());
        }
    }
}
