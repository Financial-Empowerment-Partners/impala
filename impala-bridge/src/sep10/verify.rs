//! The pure SEP-10 verifier (`docs/sep10-authentication.md` §7 layers 1-3,
//! card key kind: no link purpose, no pinned-signer step, no ledger rule).
//!
//! 1. [`decode`] — strict base64, raw envelope tag `ENVELOPE_TYPE_TX`
//!    checked before any typed access (v0 and fee-bump are refused here),
//!    strict XDR with exact end of data, canonical re-encoding. The only
//!    layer whose failure is a 400.
//! 2. [`check_issued`] — the envelope is a challenge THIS bridge issued and
//!    that is still live: source = an acceptable ring key, seq 0,
//!    fee = 100 × ops, `PRECOND_TIME` with `max − min == TTL` and
//!    `min − 30 ≤ now ≤ max`, memo none, ext v0, exactly the two login
//!    operations, the MAC-bound nonce (constant time), exactly one server
//!    signature. Failure is a generic 401 and is NOT counted.
//! 3. [`verify_master`] — the client signature by `G` itself. A missing or
//!    bad one over a live issued challenge is the only counted failure; an
//!    extra signature after a valid master signature is a 401, not counted.
//!
//! No I/O; the ring and the clock are injected.

use base64::Engine;
use stellar_base::xdr::{
    DecoratedSignature, Limits, Memo, MuxedAccount, OperationBody, Preconditions, ReadXdr,
    Transaction, TransactionEnvelope, TransactionExt, WriteXdr,
};
use subtle::ConstantTimeEq;

use crate::constants::{
    SEP10_FEE_PER_OP, SEP10_MAX_SIGNATURES, SEP10_MIN_TIME_GRACE_SECS, SEP10_NONCE_B64_LEN,
    SEP10_NONCE_DECODED_LEN, SEP10_NONCE_RANDOM_BYTES, SEP10_PURPOSE_LOGIN,
    SEP10_TRANSACTION_MAX_CHARS, SEP10_WEB_AUTH_DOMAIN_KEY,
};
use crate::sep10::challenge::nonce_mac_input;
use crate::sep10::key::{RingSnapshot, Sep10Key};
use crate::sep10::{ed25519_verify, signature_hint, transaction_hash, ENVELOPE_TYPE_TX};

/// Why a POSTed challenge was refused. `label()` is the
/// `sep10_rejections_total{reason}` value (never an address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Layer 1: not a strict, canonical v1 envelope (400).
    Malformed,
    /// Layer 2: not a challenge this bridge issued (401, not counted).
    NotIssued,
    /// Layer 2: outside its time bounds (401, not counted).
    Expired,
    /// Layer 2: the nonce MAC does not verify (401, not counted).
    Mac,
    /// Layer 2: not exactly one valid server signature (401, not counted).
    ServerSignature,
    /// Layer 3: no valid signature by `G` (401, COUNTED).
    BadMasterSignature,
    /// Layer 3: a signature beyond the server's and the master's (401, not counted).
    UnknownSigner,
}

impl Reject {
    pub fn label(&self) -> &'static str {
        match self {
            Reject::Malformed => "malformed",
            Reject::NotIssued => "not_issued",
            Reject::Expired => "expired",
            Reject::Mac => "mac",
            Reject::ServerSignature => "server_signature",
            Reject::BadMasterSignature => "bad_master_signature",
            Reject::UnknownSigner => "unknown_signer",
        }
    }
}

/// A strictly decoded v1 envelope and the hash its signatures cover.
pub struct Decoded {
    pub tx: Transaction,
    pub signatures: Vec<DecoratedSignature>,
    pub hash: [u8; 32],
}

/// Layer 1.
pub fn decode(transaction_b64: &str, network_id: &[u8; 32]) -> Result<Decoded, Reject> {
    if transaction_b64.is_empty() || transaction_b64.len() > SEP10_TRANSACTION_MAX_CHARS {
        return Err(Reject::Malformed);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(transaction_b64)
        .map_err(|_| Reject::Malformed)?;
    // The raw discriminant, before any typed accessor: v0 (0) and fee-bump
    // (5) are refused here rather than converted.
    if bytes.len() < 4 || bytes[..4] != ENVELOPE_TYPE_TX {
        return Err(Reject::Malformed);
    }
    let envelope = TransactionEnvelope::from_xdr(
        &bytes,
        Limits {
            depth: 32,
            len: bytes.len(),
        },
    )
    .map_err(|_| Reject::Malformed)?;
    let TransactionEnvelope::Tx(v1) = envelope else {
        return Err(Reject::Malformed);
    };
    // Hash the exact transaction bytes, and insist they are canonical: the
    // re-encoding must be the slice that was sent.
    let tx_bytes = v1
        .tx
        .to_xdr(Limits::none())
        .map_err(|_| Reject::Malformed)?;
    if bytes.len() < 4 + tx_bytes.len() || bytes[4..4 + tx_bytes.len()] != tx_bytes[..] {
        return Err(Reject::Malformed);
    }
    Ok(Decoded {
        hash: transaction_hash(network_id, &tx_bytes),
        signatures: v1.signatures.to_vec(),
        tx: v1.tx,
    })
}

/// What the issued challenge must look like (configuration + clock).
pub struct Expectation<'a> {
    pub home_domain: &'a str,
    pub web_auth_domain: &'a str,
    pub network_id: [u8; 32],
    pub ttl_secs: u64,
    pub now: i64,
}

/// The server keys the verifier may accept. The ring snapshot implements it;
/// tests inject fixed keys.
pub trait KeyLookup {
    fn acceptable(&self, server: &[u8; 32]) -> Option<(i32, std::sync::Arc<Sep10Key>)>;
    fn is_ring_key(&self, key: &[u8; 32]) -> bool;
}

/// The ring at one instant.
pub struct RingAt<'a> {
    pub snapshot: &'a RingSnapshot,
    pub now: i64,
}

impl KeyLookup for RingAt<'_> {
    fn acceptable(&self, server: &[u8; 32]) -> Option<(i32, std::sync::Arc<Sep10Key>)> {
        self.snapshot.acceptable(server, self.now)
    }
    fn is_ring_key(&self, key: &[u8; 32]) -> bool {
        self.snapshot.is_ring_key(key)
    }
}

/// A live challenge this bridge issued, for client `G`.
#[derive(Debug)]
pub struct Issued {
    pub client: [u8; 32],
    pub version: i32,
    pub max_time: u64,
    pub hash: [u8; 32],
    server_sig_index: usize,
}

/// A manage-data operation as `(source, name, value)`.
type ManageData<'a> = ([u8; 32], &'a [u8], Option<&'a [u8]>);

fn ed25519_source(m: &MuxedAccount) -> Option<[u8; 32]> {
    match m {
        MuxedAccount::Ed25519(k) => Some(k.0),
        MuxedAccount::MuxedEd25519(_) => None,
    }
}

/// Layer 2.
pub fn check_issued(
    d: &Decoded,
    keys: &impl KeyLookup,
    exp: &Expectation<'_>,
) -> Result<Issued, Reject> {
    let tx = &d.tx;
    let server = ed25519_source(&tx.source_account).ok_or(Reject::NotIssued)?;
    let (version, key) = keys.acceptable(&server).ok_or(Reject::NotIssued)?;
    if tx.seq_num.0 != 0 {
        return Err(Reject::NotIssued);
    }
    if !matches!(tx.memo, Memo::None) || !matches!(tx.ext, TransactionExt::V0) {
        return Err(Reject::NotIssued);
    }
    let ops = tx.operations.as_slice();
    if ops.len() != 2 || tx.fee as u64 != SEP10_FEE_PER_OP as u64 * ops.len() as u64 {
        return Err(Reject::NotIssued);
    }

    // PRECOND_TIME only, both bounds set, exactly one TTL wide.
    let Preconditions::Time(tb) = &tx.cond else {
        return Err(Reject::NotIssued);
    };
    let (min_time, max_time) = (tb.min_time.0, tb.max_time.0);
    if min_time == 0
        || max_time == 0
        || max_time < min_time
        || max_time - min_time != exp.ttl_secs
        || max_time > i64::MAX as u64
    {
        return Err(Reject::NotIssued);
    }
    if exp.now < min_time as i64 - SEP10_MIN_TIME_GRACE_SECS || exp.now > max_time as i64 {
        return Err(Reject::Expired);
    }

    // op[0]: "<home> auth" by the client; op[1]: web_auth_domain by the server.
    let manage = |i: usize| -> Option<ManageData<'_>> {
        let op = &ops[i];
        let source = ed25519_source(op.source_account.as_ref()?)?;
        let OperationBody::ManageData(md) = &op.body else {
            return None;
        };
        Some((
            source,
            md.data_name.0.as_slice(),
            md.data_value.as_ref().map(|v| v.0.as_slice()),
        ))
    };
    let (client, name0, value0) = manage(0).ok_or(Reject::NotIssued)?;
    let (src1, name1, value1) = manage(1).ok_or(Reject::NotIssued)?;
    let expected_name0 = format!("{} auth", exp.home_domain);
    if name0 != expected_name0.as_bytes()
        || src1 != server
        || name1 != SEP10_WEB_AUTH_DOMAIN_KEY.as_bytes()
        || value1 != Some(exp.web_auth_domain.as_bytes())
    {
        return Err(Reject::NotIssued);
    }
    if client == server || keys.is_ring_key(&client) {
        return Err(Reject::NotIssued);
    }

    // The MAC-bound nonce, compared in constant time.
    let nonce = value0.ok_or(Reject::NotIssued)?;
    if nonce.len() != SEP10_NONCE_B64_LEN {
        return Err(Reject::NotIssued);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(nonce)
        .map_err(|_| Reject::Mac)?;
    if raw.len() != SEP10_NONCE_DECODED_LEN {
        return Err(Reject::Mac);
    }
    let mut r16 = [0u8; SEP10_NONCE_RANDOM_BYTES];
    r16.copy_from_slice(&raw[..SEP10_NONCE_RANDOM_BYTES]);
    let expected_mac = key.mac(&nonce_mac_input(
        SEP10_PURPOSE_LOGIN,
        &client,
        min_time,
        max_time,
        version,
        &exp.network_id,
        &r16,
    ));
    if !bool::from(expected_mac.ct_eq(&raw[SEP10_NONCE_RANDOM_BYTES..])) {
        return Err(Reject::Mac);
    }

    // 2..=20 signatures, exactly one of which verifies as the server key.
    if d.signatures.len() < 2 || d.signatures.len() > SEP10_MAX_SIGNATURES {
        return Err(Reject::ServerSignature);
    }
    let server_hint = signature_hint(&server);
    let verified: Vec<usize> = d
        .signatures
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.hint.0 == server_hint && ed25519_verify(&server, &d.hash, s.signature.0.as_slice())
        })
        .map(|(i, _)| i)
        .collect();
    let [server_sig_index] = verified[..] else {
        return Err(Reject::ServerSignature);
    };

    Ok(Issued {
        client,
        version,
        max_time,
        hash: d.hash,
        server_sig_index,
    })
}

/// Layer 3: exactly the server's signature plus one valid signature by `G`.
/// `BadMasterSignature` is the only failure a caller may count.
pub fn verify_master(d: &Decoded, issued: &Issued) -> Result<(), Reject> {
    let client_hint = signature_hint(&issued.client);
    let master = d.signatures.iter().enumerate().find(|(i, s)| {
        *i != issued.server_sig_index
            && s.hint.0 == client_hint
            && ed25519_verify(&issued.client, &issued.hash, s.signature.0.as_slice())
    });
    if master.is_none() {
        return Err(Reject::BadMasterSignature);
    }
    if d.signatures.len() != 2 {
        return Err(Reject::UnknownSigner);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sep10::challenge::{challenge_transaction, sign_envelope, ChallengeParams};
    use crate::sep10::key::tests::test_key;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::Arc;
    use stellar_base::xdr::{
        Asset, DataValue, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, ManageDataOp, MuxedAccountMed25519, Operation, PaymentOp,
        SequenceNumber, Signature, SignatureHint, String64, TimeBounds, TimePoint, TransactionV0,
        TransactionV0Envelope, TransactionV0Ext, TransactionV1Envelope, Uint256, VecM,
    };

    pub const HOME: &str = "api-testnet.example.com";
    pub const NOW: i64 = 1_800_000_000;
    pub const TTL: u64 = 300;

    pub struct Fixed {
        pub key: Arc<Sep10Key>,
        pub version: i32,
        pub others: Vec<[u8; 32]>,
    }

    impl KeyLookup for Fixed {
        fn acceptable(&self, server: &[u8; 32]) -> Option<(i32, Arc<Sep10Key>)> {
            (self.key.public() == *server).then(|| (self.version, self.key.clone()))
        }
        fn is_ring_key(&self, key: &[u8; 32]) -> bool {
            self.key.public() == *key || self.others.contains(key)
        }
    }

    pub fn nid() -> [u8; 32] {
        crate::sep10::network_id(crate::constants::STELLAR_TESTNET_PASSPHRASE)
    }

    pub fn exp(now: i64) -> Expectation<'static> {
        Expectation {
            home_domain: HOME,
            web_auth_domain: HOME,
            network_id: nid(),
            ttl_secs: TTL,
            now,
        }
    }

    pub struct World {
        pub ring: Fixed,
        pub client: Ed25519KeyPair,
        pub client_pub: [u8; 32],
    }

    pub fn world() -> World {
        let (key, _) = test_key();
        let client = Ed25519KeyPair::generate().unwrap();
        let client_pub = client.public_key().as_ref().try_into().unwrap();
        World {
            ring: Fixed {
                key: Arc::new(key),
                version: 7,
                others: Vec::new(),
            },
            client,
            client_pub,
        }
    }

    impl World {
        pub fn params(&self) -> ChallengeParams<'static> {
            ChallengeParams {
                client: self.client_pub,
                home_domain: HOME,
                web_auth_domain: HOME,
                network_id: nid(),
                min_time: NOW as u64,
                ttl_secs: TTL,
            }
        }
        pub fn tx(&self) -> Transaction {
            challenge_transaction(
                &self.ring.key,
                self.ring.version,
                &self.params(),
                &[0x5a; 16],
            )
            .unwrap()
        }
        /// The server-signed challenge as issued.
        pub fn issued_b64(&self) -> String {
            sign_envelope(&self.ring.key, self.tx(), &nid()).unwrap()
        }
        pub fn client_sig(&self, envelope_b64: &str) -> DecoratedSignature {
            let d = decode(envelope_b64, &nid()).unwrap();
            DecoratedSignature {
                hint: SignatureHint(signature_hint(&self.client_pub)),
                signature: Signature(
                    self.client
                        .sign(&d.hash)
                        .as_ref()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                ),
            }
        }
    }

    pub fn envelope_parts(b64: &str) -> TransactionV1Envelope {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        match TransactionEnvelope::from_xdr(bytes, Limits::none()).unwrap() {
            TransactionEnvelope::Tx(v1) => v1,
            _ => unreachable!(),
        }
    }

    pub fn encode(env: TransactionEnvelope) -> String {
        base64::engine::general_purpose::STANDARD.encode(env.to_xdr(Limits::none()).unwrap())
    }

    /// The issued envelope with the client's signature appended.
    pub fn signed_by_client(w: &World) -> String {
        let issued = w.issued_b64();
        let sig = w.client_sig(&issued);
        let mut v1 = envelope_parts(&issued);
        let mut sigs = v1.signatures.to_vec();
        sigs.push(sig);
        v1.signatures = sigs.try_into().unwrap();
        encode(TransactionEnvelope::Tx(v1))
    }

    /// Re-sign a mutated transaction with the server key (so only the
    /// mutation is under test) and the client key.
    fn resigned(w: &World, tx: Transaction) -> String {
        let issued = sign_envelope(&w.ring.key, tx, &nid()).unwrap();
        let sig = w.client_sig(&issued);
        let mut v1 = envelope_parts(&issued);
        let mut sigs = v1.signatures.to_vec();
        sigs.push(sig);
        v1.signatures = sigs.try_into().unwrap();
        encode(TransactionEnvelope::Tx(v1))
    }

    fn run(w: &World, b64: &str, now: i64) -> Result<Issued, Reject> {
        let d = decode(b64, &nid())?;
        let issued = check_issued(&d, &w.ring, &exp(now))?;
        verify_master(&d, &issued)?;
        Ok(issued)
    }

    #[test]
    fn build_then_verify_round_trips() {
        let w = world();
        let b64 = signed_by_client(&w);
        let issued = run(&w, &b64, NOW).unwrap();
        assert_eq!(issued.client, w.client_pub);
        assert_eq!(issued.version, 7);
        assert_eq!(issued.max_time, NOW as u64 + TTL);
        // The challenge as issued has exactly the documented shape.
        let tx = w.tx();
        assert_eq!(tx.fee, 200);
        assert_eq!(tx.seq_num.0, 0);
        assert_eq!(tx.operations.len(), 2);
        let OperationBody::ManageData(op0) = &tx.operations[0].body else {
            panic!()
        };
        assert_eq!(op0.data_name.0.as_slice(), b"api-testnet.example.com auth");
        assert_eq!(op0.data_value.as_ref().unwrap().0.len(), 64);
        let OperationBody::ManageData(op1) = &tx.operations[1].body else {
            panic!()
        };
        assert_eq!(op1.data_name.0.as_slice(), b"web_auth_domain");
        assert_eq!(
            op1.data_value.as_ref().unwrap().0.as_slice(),
            HOME.as_bytes()
        );
        // The unsigned-by-client challenge carries exactly one signature.
        assert_eq!(envelope_parts(&w.issued_b64()).signatures.len(), 1);
    }

    /// The challenge hash the card signs is `SHA-256(networkId ‖ 00000002 ‖ tx)`
    /// over the exact `tx` slice of the envelope (contract §3.3).
    #[test]
    fn the_hash_covers_the_exact_transaction_slice() {
        let w = world();
        let b64 = w.issued_b64();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        let tx_bytes = w.tx().to_xdr(Limits::none()).unwrap();
        assert_eq!(&bytes[4..4 + tx_bytes.len()], &tx_bytes[..]);
        assert_eq!(
            decode(&b64, &nid()).unwrap().hash,
            transaction_hash(&nid(), &tx_bytes)
        );
        // The server signature verifies under that hash.
        let v1 = envelope_parts(&b64);
        assert!(ed25519_verify(
            &w.ring.key.public(),
            &transaction_hash(&nid(), &tx_bytes),
            v1.signatures[0].signature.0.as_slice()
        ));
    }

    // ── Mutation matrix ───────────────────────────────────────────────

    fn mutate(w: &World, f: impl FnOnce(&mut Transaction)) -> String {
        let mut tx = w.tx();
        f(&mut tx);
        resigned(w, tx)
    }

    fn assert_rejected(w: &World, b64: &str, want: Reject, what: &str) {
        assert_eq!(run(w, b64, NOW).unwrap_err(), want, "{what}");
    }

    #[test]
    fn sequence_fee_memo_ext_and_source_mutations_are_not_issued() {
        let w = world();
        let cases: Vec<(&str, String)> = vec![
            ("sequence 1", mutate(&w, |t| t.seq_num = SequenceNumber(1))),
            ("fee 100", mutate(&w, |t| t.fee = 100)),
            ("fee 300", mutate(&w, |t| t.fee = 300)),
            (
                "memo text",
                mutate(&w, |t| t.memo = Memo::Text("hi".try_into().unwrap())),
            ),
            ("memo id", mutate(&w, |t| t.memo = Memo::Id(1))),
        ];
        for (what, b64) in cases {
            assert_rejected(&w, &b64, Reject::NotIssued, what);
        }
        // A source that is not a ring key: signed by a stranger's key.
        let (stranger, _) = test_key();
        let mut p = w.params();
        p.client = w.client_pub;
        let tx = challenge_transaction(&stranger, 7, &p, &[1; 16]).unwrap();
        let issued = sign_envelope(&stranger, tx, &nid()).unwrap();
        assert_eq!(
            check_issued(&decode(&issued, &nid()).unwrap(), &w.ring, &exp(NOW)).unwrap_err(),
            Reject::NotIssued
        );
        // A muxed source account.
        let b64 = mutate(&w, |t| {
            t.source_account = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id: 1,
                ed25519: Uint256(w.ring.key.public()),
            })
        });
        assert_rejected(&w, &b64, Reject::NotIssued, "muxed source");
    }

    #[test]
    fn time_bound_mutations_are_refused() {
        let w = world();
        let set = |min: u64, max: u64| {
            mutate(&w, move |t| {
                t.cond = Preconditions::Time(TimeBounds {
                    min_time: TimePoint(min),
                    max_time: TimePoint(max),
                })
            })
        };
        let n = NOW as u64;
        assert_rejected(&w, &set(n, n + TTL + 1), Reject::NotIssued, "span TTL+1");
        assert_rejected(&w, &set(n, n + TTL - 1), Reject::NotIssued, "span TTL-1");
        assert_rejected(&w, &set(0, TTL), Reject::NotIssued, "min 0");
        assert_rejected(
            &w,
            &mutate(&w, |t| t.cond = Preconditions::None),
            Reject::NotIssued,
            "no bounds",
        );
        // The issued bounds outside their window: expired / not yet valid.
        let b64 = signed_by_client(&w);
        assert!(
            run(&w, &b64, NOW + TTL as i64).is_ok(),
            "maxTime itself is valid"
        );
        assert_eq!(
            run(&w, &b64, NOW + TTL as i64 + 1).unwrap_err(),
            Reject::Expired
        );
        assert!(run(&w, &b64, NOW - 30).is_ok(), "30 s of minTime grace");
        assert_eq!(run(&w, &b64, NOW - 31).unwrap_err(), Reject::Expired);
    }

    #[test]
    fn operation_mutations_are_not_issued() {
        let w = world();
        let md = |source: [u8; 32], name: &str, value: Option<&[u8]>| Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256(source))),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: String64(name.try_into().unwrap()),
                data_value: value.map(|v| DataValue(v.to_vec().try_into().unwrap())),
            }),
        };
        let server = w.ring.key.public();
        let client = w.client_pub;
        let base = w.tx();
        let op0 = base.operations[0].clone();
        let op1 = base.operations[1].clone();
        let with_ops = |ops: Vec<Operation>| {
            let n = ops.len() as u32;
            mutate(&w, move |t| {
                t.operations = ops.try_into().unwrap();
                t.fee = 100 * n;
            })
        };
        let cases: Vec<(&str, String)> = vec![
            (
                "extra op",
                with_ops(vec![
                    op0.clone(),
                    op1.clone(),
                    md(server, "client_domain", Some(b"x.example")),
                ]),
            ),
            ("one op", with_ops(vec![op0.clone()])),
            ("swapped ops", with_ops(vec![op1.clone(), op0.clone()])),
            (
                "wrong op0 name",
                with_ops(vec![
                    {
                        let OperationBody::ManageData(m) = &op0.body else {
                            unreachable!()
                        };
                        md(
                            client,
                            "evil.example auth",
                            m.data_value.as_ref().map(|v| v.0.as_slice()),
                        )
                    },
                    op1.clone(),
                ]),
            ),
            (
                "link purpose",
                with_ops(vec![
                    {
                        let OperationBody::ManageData(m) = &op0.body else {
                            unreachable!()
                        };
                        md(
                            client,
                            "api-testnet.example.com link",
                            m.data_value.as_ref().map(|v| v.0.as_slice()),
                        )
                    },
                    op1.clone(),
                ]),
            ),
            (
                "wrong web_auth_domain",
                with_ops(vec![
                    op0.clone(),
                    md(server, "web_auth_domain", Some(b"evil.example")),
                ]),
            ),
            (
                "web_auth_domain by client",
                with_ops(vec![
                    op0.clone(),
                    md(client, "web_auth_domain", Some(HOME.as_bytes())),
                ]),
            ),
            (
                "op0 without source",
                with_ops(vec![
                    Operation {
                        source_account: None,
                        body: op0.body.clone(),
                    },
                    op1.clone(),
                ]),
            ),
            (
                "not manage data",
                with_ops(vec![
                    Operation {
                        source_account: op0.source_account.clone(),
                        body: OperationBody::Payment(PaymentOp {
                            destination: MuxedAccount::Ed25519(Uint256(server)),
                            asset: Asset::Native,
                            amount: 1,
                        }),
                    },
                    op1.clone(),
                ]),
            ),
        ];
        for (what, b64) in cases {
            let got = run(&w, &b64, NOW).unwrap_err();
            assert!(matches!(got, Reject::NotIssued), "{what}: {got:?}");
        }
    }

    #[test]
    fn tampered_nonce_and_wrong_client_are_mac_failures() {
        let w = world();
        let base = w.tx();
        let OperationBody::ManageData(m) = &base.operations[0].body else {
            unreachable!()
        };
        let nonce = m.data_value.as_ref().unwrap().0.to_vec();
        // Flip one MAC character (keeping valid base64).
        let mut tampered = nonce.clone();
        tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
        let b64 = mutate(&w, |t| {
            let mut ops = t.operations.to_vec();
            if let OperationBody::ManageData(m) = &mut ops[0].body {
                m.data_value = Some(DataValue(tampered.clone().try_into().unwrap()));
            }
            t.operations = ops.try_into().unwrap();
        });
        assert_rejected(&w, &b64, Reject::Mac, "tampered nonce");
        // The same nonce re-addressed to another client G: the MAC binds G.
        let other = Ed25519KeyPair::generate().unwrap();
        let other_pub: [u8; 32] = other.public_key().as_ref().try_into().unwrap();
        let b64 = mutate(&w, |t| {
            let mut ops = t.operations.to_vec();
            ops[0].source_account = Some(MuxedAccount::Ed25519(Uint256(other_pub)));
            t.operations = ops.try_into().unwrap();
        });
        let d = decode(&b64, &nid()).unwrap();
        assert_eq!(
            check_issued(&d, &w.ring, &exp(NOW)).unwrap_err(),
            Reject::Mac
        );
        // Wrong passphrase: the MAC binds the network id (and the hash does too).
        let pub_nid = crate::sep10::network_id(crate::constants::STELLAR_PUBNET_PASSPHRASE);
        let d = decode(&signed_by_client(&w), &pub_nid).unwrap();
        let mut e = exp(NOW);
        e.network_id = pub_nid;
        assert_eq!(check_issued(&d, &w.ring, &e).unwrap_err(), Reject::Mac);
        // The same key under another version number: the MAC binds the version.
        let mut ring = Fixed {
            key: w.ring.key.clone(),
            version: 8,
            others: vec![],
        };
        let d = decode(&signed_by_client(&w), &nid()).unwrap();
        assert_eq!(check_issued(&d, &ring, &exp(NOW)).unwrap_err(), Reject::Mac);
        ring.version = 7;
        assert!(check_issued(&d, &ring, &exp(NOW)).is_ok());
    }

    #[test]
    fn a_client_that_is_a_ring_key_is_refused() {
        let mut w = world();
        w.ring.others.push(w.client_pub);
        assert_eq!(
            run(&w, &signed_by_client(&w), NOW).unwrap_err(),
            Reject::NotIssued
        );
    }

    #[test]
    fn trailing_bytes_v0_and_fee_bump_envelopes_are_malformed() {
        let w = world();
        let b64 = signed_by_client(&w);
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let trailing = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(decode(&trailing, &nid()).err(), Some(Reject::Malformed));
        assert_eq!(decode("not base64!", &nid()).err(), Some(Reject::Malformed));
        assert_eq!(decode("", &nid()).err(), Some(Reject::Malformed));
        assert_eq!(
            decode(&"A".repeat(8196), &nid()).err(),
            Some(Reject::Malformed)
        );
        // v0: the same transaction as a TransactionV0Envelope.
        let tx = w.tx();
        let v0 = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256(w.ring.key.public()),
                fee: tx.fee,
                seq_num: tx.seq_num.clone(),
                time_bounds: match &tx.cond {
                    Preconditions::Time(tb) => Some(tb.clone()),
                    _ => None,
                },
                memo: Memo::None,
                operations: tx.operations.clone(),
                ext: TransactionV0Ext::V0,
            },
            signatures: VecM::default(),
        });
        assert_eq!(decode(&encode(v0), &nid()).err(), Some(Reject::Malformed));
        // Fee-bump wrapping the issued challenge.
        let inner = envelope_parts(&b64);
        let fb = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256(w.client_pub)),
                fee: 400,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: VecM::default(),
        });
        assert_eq!(decode(&encode(fb), &nid()).err(), Some(Reject::Malformed));
        // Non-zero XDR padding (a 1-byte change in a padded string).
        let issued = w.issued_b64();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&issued)
            .unwrap();
        // "api-testnet.example.com auth" is 28 bytes: no padding; find the
        // 15-byte "web_auth_domain" and poison its single pad byte.
        let pos = raw
            .windows(15)
            .position(|w| w == b"web_auth_domain")
            .unwrap();
        raw[pos + 15] = 1;
        let poisoned = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(decode(&poisoned, &nid()).err(), Some(Reject::Malformed));
    }

    #[test]
    fn zero_two_or_forged_server_signatures_are_refused() {
        let w = world();
        let issued = w.issued_b64();
        let client_sig = w.client_sig(&issued);
        let v1 = envelope_parts(&issued);
        let server_sig = v1.signatures[0].clone();
        let with = |sigs: Vec<DecoratedSignature>| {
            let mut v = v1.clone();
            v.signatures = sigs.try_into().unwrap();
            encode(TransactionEnvelope::Tx(v))
        };
        // Zero server signatures (client only): fewer than two.
        assert_rejected(
            &w,
            &with(vec![client_sig.clone()]),
            Reject::ServerSignature,
            "client only",
        );
        // Zero signatures.
        assert_rejected(&w, &with(vec![]), Reject::ServerSignature, "none");
        // The server signature twice (plus the client's).
        assert_rejected(
            &w,
            &with(vec![
                server_sig.clone(),
                server_sig.clone(),
                client_sig.clone(),
            ]),
            Reject::ServerSignature,
            "two server signatures",
        );
        // A forged server signature (right hint, wrong bytes) and the client's.
        let mut forged = server_sig.clone();
        let mut bytes = forged.signature.0.to_vec();
        bytes[0] ^= 1;
        forged.signature = Signature(bytes.try_into().unwrap());
        assert_rejected(
            &w,
            &with(vec![forged, client_sig.clone()]),
            Reject::ServerSignature,
            "forged",
        );
        // The challenge alone (server only): one signature.
        assert_rejected(&w, &issued, Reject::ServerSignature, "unsigned by client");
        // Order does not matter: client first, then server.
        assert!(run(&w, &with(vec![client_sig, server_sig]), NOW).is_ok());
    }

    #[test]
    fn master_signature_failures_are_distinguished() {
        let w = world();
        let issued = w.issued_b64();
        let v1 = envelope_parts(&issued);
        let server_sig = v1.signatures[0].clone();
        let good = w.client_sig(&issued);
        let with = |sigs: Vec<DecoratedSignature>| {
            let mut v = v1.clone();
            v.signatures = sigs.try_into().unwrap();
            encode(TransactionEnvelope::Tx(v))
        };
        // A signature by another key: the counted failure.
        let other = Ed25519KeyPair::generate().unwrap();
        let d = decode(&issued, &nid()).unwrap();
        let wrong = DecoratedSignature {
            hint: SignatureHint(signature_hint(&w.client_pub)),
            signature: Signature(other.sign(&d.hash).as_ref().to_vec().try_into().unwrap()),
        };
        assert_rejected(
            &w,
            &with(vec![server_sig.clone(), wrong.clone()]),
            Reject::BadMasterSignature,
            "wrong key",
        );
        // The right signature with the wrong hint.
        let mut bad_hint = good.clone();
        bad_hint.hint = SignatureHint([0, 0, 0, 0]);
        assert_rejected(
            &w,
            &with(vec![server_sig.clone(), bad_hint]),
            Reject::BadMasterSignature,
            "wrong hint",
        );
        // A valid master plus an extra signature: not counted.
        assert_rejected(
            &w,
            &with(vec![server_sig.clone(), good.clone(), wrong]),
            Reject::UnknownSigner,
            "extra",
        );
        assert_rejected(
            &w,
            &with(vec![server_sig.clone(), good.clone(), good.clone()]),
            Reject::UnknownSigner,
            "duplicate master",
        );
        // The server signature can never count as the master's.
        assert_rejected(
            &w,
            &with(vec![server_sig.clone(), server_sig.clone()]),
            Reject::ServerSignature,
            "server twice",
        );
        assert!(run(&w, &with(vec![server_sig, good]), NOW).is_ok());
    }

    /// A signature is over the hash, which excludes signatures: re-ordering
    /// or re-encoding the signatures cannot change what is claimed.
    #[test]
    fn the_hash_ignores_signatures() {
        let w = world();
        let a = decode(&w.issued_b64(), &nid()).unwrap().hash;
        let b = decode(&signed_by_client(&w), &nid()).unwrap().hash;
        assert_eq!(a, b);
    }
}
