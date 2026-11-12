//! Cross-stream vectors: bytes produced by the real ImpalaApplet (under
//! jcardsim, `impala-card`) checked by this crate, and a challenge built here
//! that the card-side tests sign (`impala-card/sdk/src/jvmTest/.../
//! BridgeVectorTest.kt` holds the same constants).
//!
//! The card is the deterministic simulator card (`SimulatorBibo(distinctKeys =
//! false)`, JavaCard 3.0.5 Ed25519 engine), so its keys repeat across runs.
//! A change to any of these bytes on either side is a contract change.

use std::sync::Arc;

use super::binding::check_stellar_fields;
use super::challenge::{challenge_transaction, sign_envelope, ChallengeParams};
use super::key::Sep10Key;
use super::verify::tests::Fixed;
use super::verify::{check_issued, decode, verify_master, Expectation, Reject};

const HOME: &str = "api-testnet.example.com";
const NOW: i64 = 1_800_000_000;
const TTL: u64 = 300;
const VERSION: i32 = 7;

/// The server key of the vector: RFC 8032 §7.1 TEST 1 seed, then a MAC key of
/// 32 × 0x4d. A published test key; never a real one.
fn server_key() -> Sep10Key {
    let mut material = [0x4du8; 64];
    material[..32].copy_from_slice(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
    );
    Sep10Key::from_material(&material).unwrap()
}

/// The deterministic simulator card.
const CARD_STELLAR_ADDRESS: &str = "GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF";
const CARD_STELLAR_PUB: &str = "d72f8b652505e0ce4eeca6c15eba8b62f84bb11abc090baba21255b75553fd99";

fn nid() -> [u8; 32] {
    super::network_id(crate::constants::STELLAR_TESTNET_PASSPHRASE)
}

fn exp(now: i64) -> Expectation<'static> {
    Expectation {
        home_domain: HOME,
        web_auth_domain: HOME,
        network_id: nid(),
        ttl_secs: TTL,
        now,
    }
}

fn ring() -> Fixed {
    Fixed {
        key: Arc::new(server_key()),
        version: VERSION,
        others: Vec::new(),
    }
}

/// The login challenge this bridge issues to the card, with the vector's key,
/// clock and randomness.
fn issued() -> String {
    let key = server_key();
    let client: [u8; 32] = hex::decode(CARD_STELLAR_PUB).unwrap().try_into().unwrap();
    let params = ChallengeParams {
        client,
        home_domain: HOME,
        web_auth_domain: HOME,
        network_id: nid(),
        min_time: NOW as u64,
        ttl_secs: TTL,
    };
    let tx = challenge_transaction(&key, VERSION, &params, &[0x5a; 16]).unwrap();
    sign_envelope(&key, tx, &nid()).unwrap()
}

/// The bytes the card-side tests hold as `ISSUED`.
const ISSUED: &str = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAH3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwA=";

/// `ISSUED` signed by the applet (SIGN_SEP10) and framed by the card SDK:
/// what the Android client posts to `POST /auth/sep10`.
const CARD_SIGNED: &str = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAL3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwBVU/2ZAAAAQD5j/mz4dfCycHkSai6dC23Xdio+GWlmCMT7i2qFmqUVrF0IsVp8Gq7w6REyFvr8gDG9VzN+TPEC+bBFAT7CIQk=";

/// A `POST /card` registration of the same card: produced by the applet at
/// PERSONALIZE (the account is `binding::tests::ACCOUNT`).
const REG_CARD_ID: &str = "ea94fa5b0f6b2abc1626bc50c0bd5e17";
const REG_EC_PUB: &str = "042b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb49dee377c97fbb17b61480e857f5ce72408488e2763619159d032d3be091266dd6";
const REG_BINDING_SIG: &str = "304502202b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb49022100fde245243f8e85f3c60a013d3423d514499cd65fa46d9b26622712ea13b90603";
const REG_PROOF_SIG: &str = "6da881be63f5dc8c56e103625c67d5c89fc5c88a53629b7884775d522a763beffba92b3107031f2e0ead000068049e4bc3633b4de6428073eb429100f2e7e705";
const REG_ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[test]
fn the_challenge_the_card_tests_hold_is_the_one_this_bridge_issues() {
    assert_eq!(
        hex::encode(server_key().public()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        crate::validate::decode_stellar_account_id(CARD_STELLAR_ADDRESS)
            .ok()
            .map(hex::encode)
            .as_deref(),
        Some(CARD_STELLAR_PUB)
    );
    assert_eq!(issued(), ISSUED);
}

/// The envelope the real applet signed passes all three verifier layers.
#[test]
fn an_envelope_signed_by_the_applet_verifies() {
    let d = decode(CARD_SIGNED, &nid()).unwrap();
    let issued = check_issued(&d, &ring(), &exp(NOW)).unwrap();
    assert_eq!(hex::encode(issued.client), CARD_STELLAR_PUB);
    assert_eq!(issued.version, VERSION);
    verify_master(&d, &issued).unwrap();
    // The server's own envelope alone has no client signature to accept.
    let bare = decode(ISSUED, &nid()).unwrap();
    assert_eq!(
        check_issued(&bare, &ring(), &exp(NOW)).unwrap_err(),
        Reject::ServerSignature
    );
    // A flipped bit in the card's signature is the counted failure.
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, CARD_SIGNED).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    let d = decode(&tampered, &nid()).unwrap();
    let issued = check_issued(&d, &ring(), &exp(NOW)).unwrap();
    assert_eq!(
        verify_master(&d, &issued).unwrap_err(),
        Reject::BadMasterSignature
    );
    // And it is one challenge: past its lifetime it is expired, whoever signed it.
    let d = decode(CARD_SIGNED, &nid()).unwrap();
    assert_eq!(
        check_issued(&d, &ring(), &exp(NOW + TTL as i64 + 1)).unwrap_err(),
        Reject::Expired
    );
}

/// The cross-signatures the real applet made at PERSONALIZE register.
#[test]
fn a_registration_made_by_the_applet_passes_the_binding_check() {
    let ok = check_stellar_fields(
        REG_ACCOUNT,
        REG_CARD_ID,
        REG_EC_PUB,
        Some(CARD_STELLAR_ADDRESS),
        Some(REG_BINDING_SIG),
        Some(REG_PROOF_SIG),
    )
    .unwrap()
    .unwrap();
    assert_eq!(ok.stellar_address, CARD_STELLAR_ADDRESS);
    // The same key and signatures under another account or card are refused:
    // an address cannot be claimed for an identity the card did not sign for.
    for (account, card) in [
        ("00112233-4455-6677-8899-aabbccddeef0", REG_CARD_ID),
        (REG_ACCOUNT, "ea94fa5b0f6b2abc1626bc50c0bd5e18"),
    ] {
        assert!(check_stellar_fields(
            account,
            card,
            REG_EC_PUB,
            Some(CARD_STELLAR_ADDRESS),
            Some(REG_BINDING_SIG),
            Some(REG_PROOF_SIG),
        )
        .is_err());
    }
}
