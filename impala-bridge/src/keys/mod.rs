//! Admin-imported bridge credentials: modelling, validation, fingerprinting,
//! and the bound header that ties a ciphertext to the row it belongs to.
//!
//! # What this module is for
//!
//! Provider secrets (Changelly's API key + RSA signing key, OwlPay's API key +
//! webhook secret) have always been read straight from the environment at
//! startup. That is still the default. When `KEY_IMPORT_ENABLED=true`, an
//! admin may instead import them through the API; they are sealed with the
//! configured [`SeedProtector`](crate::seed_protect::SeedProtector) — the same
//! KMS/Vault machinery that protects custodial seeds — and stored in
//! `bridge_credential`.
//!
//! # DANGER
//!
//! A provider credential is **spend authority**. The replenishment driver
//! sends real reserve XLM to the pay-in address the *active Changelly account*
//! names ([`crate::exchange::replenish::create_provider_leg`]), so whoever
//! controls these credentials chooses a counterparty the bridge pays. Every
//! gate in this module yields to a single admin bearer token: the confirmation
//! flow is **anti-accident, not anti-attacker**. See
//! `docs/runbooks/import-keys.md`.
//!
//! # Invariants (do not weaken)
//!
//! - Secret material lives only inside [`Zeroizing`] and is never logged,
//!   returned, or rendered by a `Debug` impl.
//! - Fingerprints are computed over **canonical parsed** material, never over
//!   submitted bytes: the same RSA key handed in as PKCS#1 PEM and as PKCS#8
//!   hex must fingerprint identically, or the compare-and-swap in
//!   `handlers::admin_keys` fabricates a rotation that never happened.
//! - RSA keys are fingerprinted through their **public** half, so no digest of
//!   private material is ever stored or displayed.
//! - A credential set is sealed as one blob under a header naming its kind and
//!   version, and that header is verified on decrypt. Neither protector
//!   backend binds an encryption context, so without this a blob would be
//!   portable between rows.

use std::collections::BTreeMap;

use aws_lc_rs::signature::KeyPair;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::constants::{
    CREDENTIAL_FP_DOMAIN, CREDENTIAL_FP_HEX_LEN, CREDENTIAL_HEADER_MAGIC, CREDENTIAL_PART_MAX_LEN,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, EXCHANGE_PROVIDER_CHANGELLY_FIAT, EXCHANGE_PROVIDER_OWLPAY,
    SEED_HEADER_MAGIC,
};
use crate::error::AppError;
use crate::exchange::changelly::{
    parse_private_key_hex_pkcs8, parse_private_key_pem, parse_public_key,
};

pub mod store;

/// How a part's bytes are parsed and canonicalized before fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartForm {
    /// Provider-issued opaque token (API key, webhook secret). Canonical form
    /// is the trimmed bytes; there is no public counterpart to hash instead.
    Opaque,
    /// RSA private key, PKCS#8 DER, hex-encoded (Changelly Exchange API v2).
    RsaPrivateHex,
    /// RSA private key, PEM (PKCS#1 or PKCS#8) (Changelly Fiat API).
    RsaPrivatePem,
    /// RSA public key used to verify provider callbacks. Not secret, but
    /// validated and versioned alongside the set it belongs to.
    RsaPublic,
}

/// One named component of a credential set.
#[derive(Debug, Clone, Copy)]
pub struct PartSpec {
    pub name: &'static str,
    pub required: bool,
    pub form: PartForm,
    /// Environment variable this part is read from when the set is not
    /// imported. Kept here so `GET /admin/keys` can name the variable an
    /// operator still has to remove to finish a rotation.
    pub env_var: &'static str,
    /// Optional companion variable naming a FILE holding the value (the
    /// mounted-secret pattern the Changelly keys already support). Read only
    /// when `env_var` is unset.
    pub env_file_var: Option<&'static str>,
}

const OWLPAY_PARTS: &[PartSpec] = &[
    PartSpec {
        name: "api_key",
        required: true,
        form: PartForm::Opaque,
        env_var: "OWLPAY_API_KEY",
        env_file_var: None,
    },
    PartSpec {
        name: "webhook_secret",
        required: false,
        form: PartForm::Opaque,
        env_var: "OWLPAY_WEBHOOK_SECRET",
        env_file_var: None,
    },
];

const CHANGELLY_CRYPTO_PARTS: &[PartSpec] = &[
    PartSpec {
        name: "api_key",
        required: true,
        form: PartForm::Opaque,
        env_var: "CHANGELLY_API_KEY",
        env_file_var: None,
    },
    PartSpec {
        name: "private_key",
        required: true,
        form: PartForm::RsaPrivateHex,
        env_var: "CHANGELLY_PRIVATE_KEY",
        env_file_var: Some("CHANGELLY_PRIVATE_KEY_FILE"),
    },
];

const CHANGELLY_FIAT_PARTS: &[PartSpec] = &[
    PartSpec {
        name: "api_key",
        required: true,
        form: PartForm::Opaque,
        env_var: "CHANGELLY_FIAT_API_KEY",
        env_file_var: None,
    },
    PartSpec {
        name: "private_key",
        required: true,
        form: PartForm::RsaPrivatePem,
        env_var: "CHANGELLY_FIAT_PRIVATE_KEY",
        env_file_var: Some("CHANGELLY_FIAT_PRIVATE_KEY_FILE"),
    },
    PartSpec {
        name: "callback_public_key",
        required: false,
        form: PartForm::RsaPublic,
        env_var: "CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY",
        env_file_var: None,
    },
];

/// The parts that make up each credential kind. Returns `None` for an unknown
/// kind, which callers turn into a 400 rather than a panic.
pub fn parts_for(kind: &str) -> Option<&'static [PartSpec]> {
    match kind {
        EXCHANGE_PROVIDER_OWLPAY => Some(OWLPAY_PARTS),
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => Some(CHANGELLY_CRYPTO_PARTS),
        EXCHANGE_PROVIDER_CHANGELLY_FIAT => Some(CHANGELLY_FIAT_PARTS),
        _ => None,
    }
}

/// The part whose presence means "this provider is configured at all".
///
/// The first required part of every kind is its API key, and the provider init
/// functions this replaced keyed their `Ok(None)` ("unconfigured") answer on
/// exactly that variable. Anything else missing while it IS present stays a
/// hard startup error, as it was before: a half-supplied provider on a money
/// path must fail closed rather than silently disappear.
pub fn primary_part(kind: &str) -> Option<&'static PartSpec> {
    parts_for(kind)?.iter().find(|s| s.required)
}

/// A complete or partial set of secret parts, keyed by part name.
///
/// Deliberately no `#[derive(Debug)]` — see the redacted impl below — and no
/// `Serialize`, so a set cannot be accidentally rendered into a response body.
#[derive(Clone, Default)]
pub struct CredentialParts {
    parts: BTreeMap<String, Zeroizing<String>>,
}

impl std::fmt::Debug for CredentialParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialParts({} parts: {:?}, values [REDACTED])",
            self.parts.len(),
            self.parts.keys().collect::<Vec<_>>()
        )
    }
}

impl CredentialParts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a part, trimming surrounding whitespace. Trimming happens once,
    /// here, so the stored value and the fingerprinted value cannot diverge on
    /// a trailing newline from a copy-paste or a mounted secret file.
    pub fn insert(&mut self, name: &str, value: &str) {
        self.parts
            .insert(name.to_string(), Zeroizing::new(value.trim().to_string()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.parts.get(name).map(|v| v.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.parts.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Validate every part against its kind's spec: no unknown names, no
    /// missing required parts, no oversized values, and every key actually
    /// parses. Error messages name the part but never echo its value.
    pub fn validate_for(&self, kind: &str) -> Result<(), AppError> {
        let specs = parts_for(kind)
            .ok_or_else(|| AppError::BadRequest(format!("Unknown credential kind '{}'", kind)))?;

        for name in self.parts.keys() {
            if !specs.iter().any(|s| s.name == name) {
                return Err(AppError::BadRequest(format!(
                    "Unknown part '{}' for credential kind '{}'. Expected: {}",
                    name,
                    kind,
                    specs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
                )));
            }
        }
        for spec in specs {
            match self.parts.get(spec.name) {
                None if spec.required => {
                    return Err(AppError::BadRequest(format!(
                        "Missing required part '{}' for credential kind '{}'",
                        spec.name, kind
                    )));
                }
                None => {}
                Some(value) => {
                    if value.is_empty() {
                        return Err(AppError::BadRequest(format!(
                            "Part '{}' must not be empty",
                            spec.name
                        )));
                    }
                    if value.len() > CREDENTIAL_PART_MAX_LEN {
                        return Err(AppError::BadRequest(format!(
                            "Part '{}' exceeds {} bytes",
                            spec.name, CREDENTIAL_PART_MAX_LEN
                        )));
                    }
                    canonical_bytes(spec.form, value).map_err(|e| {
                        AppError::BadRequest(format!("Part '{}': {}", spec.name, e))
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Per-part fingerprints over canonical material. Assumes
    /// [`Self::validate_for`] already passed; a part that fails to parse here
    /// is reported as `"unparsed"` rather than panicking, so a listing of a
    /// legacy row can never take the process down.
    pub fn fingerprints(&self, kind: &str) -> BTreeMap<String, String> {
        let specs = parts_for(kind).unwrap_or(&[]);
        let mut out = BTreeMap::new();
        for spec in specs {
            if let Some(value) = self.parts.get(spec.name) {
                let fp = match canonical_bytes(spec.form, value) {
                    Ok(bytes) => fingerprint(kind, spec.name, &bytes),
                    Err(_) => "unparsed".to_string(),
                };
                out.insert(spec.name.to_string(), fp);
            }
        }
        out
    }

    /// Fingerprint of the whole set — the compare-and-swap token an admin
    /// echoes back to replace it. Derived from the per-part fingerprints, so
    /// it changes if any part changes, is added, or is removed.
    pub fn set_fingerprint(&self, kind: &str) -> String {
        set_fingerprint_from_parts(kind, &self.fingerprints(kind))
    }

    /// Serialize + seal under the bound header, ready to hand to the
    /// protector. The header names the kind and version this blob belongs to;
    /// [`Self::open_sealed`] refuses a blob whose header does not match the
    /// row it was read from.
    pub fn seal(&self, kind: &str, version: i32) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let header = credential_header(kind, version);
        // Pre-size so serde_json never reallocates and strands a copy of the
        // secrets in a freed buffer we cannot zeroize.
        let estimate = header.len()
            + self
                .parts
                .iter()
                .map(|(k, v)| k.len() + v.len() * 2 + 8)
                .sum::<usize>()
            + 64;
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(estimate));
        buf.extend_from_slice(header.as_bytes());
        let plain: BTreeMap<&str, &str> = self
            .parts
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        serde_json::to_writer(&mut *buf, &plain).map_err(|e| {
            // The error may quote the offending input; never surface it.
            log::error!("keys: credential serialization failed: {}", e);
            AppError::InternalError("credential serialization failed".to_string())
        })?;
        Ok(buf)
    }

    /// Verify the bound header and parse the sealed body.
    ///
    /// On any failure this returns a FIXED string. `AppError` messages reach
    /// the client verbatim, and the interesting failure — a blob from another
    /// row, or a seed transplanted into a credential row — has secret material
    /// sitting in the first bytes of `plaintext`. Nothing derived from those
    /// bytes may appear in the error or the log.
    pub fn open_sealed(kind: &str, version: i32, plaintext: &[u8]) -> Result<Self, AppError> {
        let header = credential_header(kind, version);
        if !plaintext.starts_with(header.as_bytes()) {
            log::error!(
                "keys: credential blob failed the binding check (kind={} version={})",
                kind,
                version
            );
            return Err(AppError::InternalError(
                "credential blob failed the binding check".to_string(),
            ));
        }
        let body = &plaintext[header.len()..];
        let raw: BTreeMap<String, String> = serde_json::from_slice(body).map_err(|_| {
            log::error!(
                "keys: credential blob did not parse (kind={} version={})",
                kind,
                version
            );
            AppError::InternalError("credential blob did not parse".to_string())
        })?;
        let mut parts = CredentialParts::new();
        for (name, value) in raw {
            // `value` is a plaintext secret in a String serde allocated; move
            // it into the zeroizing map and scrub the original in place.
            let mut owned = value;
            parts
                .parts
                .insert(name, Zeroizing::new(std::mem::take(&mut owned)));
            zeroize::Zeroize::zeroize(&mut owned);
        }
        Ok(parts)
    }

    /// Overlay `other`'s parts onto a copy of this set, then remove `drop`.
    /// Used by the merge endpoint so an admin can rotate one part without
    /// re-entering the parts they cannot read back.
    pub fn merged_with(&self, other: &CredentialParts, drop: &[String]) -> CredentialParts {
        let mut out = self.clone();
        for (name, value) in &other.parts {
            out.parts.insert(name.clone(), value.clone());
        }
        for name in drop {
            out.parts.remove(name);
        }
        out
    }
}

/// Canonical, encoding-independent bytes for one part.
///
/// RSA private keys canonicalize to their **public** half: the same key
/// submitted as PKCS#1 PEM, PKCS#8 PEM, or PKCS#8 hex yields identical bytes,
/// and no private material is ever hashed.
fn canonical_bytes(form: PartForm, value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    match form {
        PartForm::Opaque => Ok(Zeroizing::new(value.trim().as_bytes().to_vec())),
        PartForm::RsaPrivateHex => {
            let kp = parse_private_key_hex_pkcs8(value)?;
            Ok(Zeroizing::new(kp.public_key().as_ref().to_vec()))
        }
        PartForm::RsaPrivatePem => {
            let kp = parse_private_key_pem(value)?;
            Ok(Zeroizing::new(kp.public_key().as_ref().to_vec()))
        }
        PartForm::RsaPublic => Ok(Zeroizing::new(parse_public_key(value)?)),
    }
}

/// `SHA-256(domain ‖ kind ‖ part ‖ len ‖ canonical)`, truncated.
///
/// Length-prefixed and NUL-separated so no two distinct inputs share a
/// preimage. Unsalted on purpose: an env-sourced credential and a stored one
/// must fingerprint identically or the compare-and-swap cannot compare them.
/// The accepted cost is that someone who can read a fingerprint can confirm a
/// *guess* of the underlying value — acceptable because every opaque part is
/// high-entropy provider-issued material, and because RSA parts hash only
/// their public half.
pub fn fingerprint(kind: &str, part: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_FP_DOMAIN.as_bytes());
    hasher.update([0u8]);
    hasher.update(kind.as_bytes());
    hasher.update([0u8]);
    hasher.update(part.as_bytes());
    hasher.update([0u8]);
    hasher.update((canonical.len() as u32).to_be_bytes());
    hasher.update(canonical);
    hex::encode(hasher.finalize())[..CREDENTIAL_FP_HEX_LEN].to_string()
}

/// Digest over a set's per-part fingerprints (already sorted by `BTreeMap`).
pub fn set_fingerprint_from_parts(kind: &str, parts: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_FP_DOMAIN.as_bytes());
    hasher.update([0u8]);
    hasher.update(b"set");
    hasher.update([0u8]);
    hasher.update(kind.as_bytes());
    for (name, fp) in parts {
        hasher.update([0u8]);
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(fp.as_bytes());
    }
    hex::encode(hasher.finalize())[..CREDENTIAL_FP_HEX_LEN].to_string()
}

/// The header sealed inside a credential ciphertext.
pub fn credential_header(kind: &str, version: i32) -> String {
    format!("{}\n{}\n{}\n", CREDENTIAL_HEADER_MAGIC, kind, version)
}

/// The header sealed inside a bound custodial-seed ciphertext
/// (`managed_seed.format_version = 1`). Binds the blob to one account, so a
/// ciphertext copied into another account's row fails to open.
pub fn seed_header(payala_account_id: &str) -> String {
    format!("{}\n{}\n", SEED_HEADER_MAGIC, payala_account_id)
}

/// The phrase an admin must type to confirm a replacement.
///
/// Deliberately NOT the fingerprint shown alongside it: typing a value that is
/// on screen and copyable proves transcription, not comprehension. Naming the
/// network is what catches the commonest operator error — the right key in the
/// wrong environment.
pub fn confirm_phrase(kind: &str, network: &str) -> String {
    format!("replace {} {}", kind, network)
}

/// Constant-time-ish equality for confirmation tokens. These are not secrets,
/// but comparing them with `subtle` keeps the handler free of early-exit
/// comparisons on operator-supplied input.
pub fn tokens_match(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// True when a free-text field looks like it contains key material.
///
/// The `note` column is stored in plaintext and re-served in listings, so an
/// operator who pastes a key into it would defeat every protection in this
/// module. Fail closed on anything shaped like a secret.
pub fn looks_like_secret(text: &str) -> bool {
    let t = text.trim();
    if t.contains("-----BEGIN") || t.starts_with("whs_") {
        return true;
    }
    // A Stellar secret seed: 56 chars of upper-case base32 starting with S.
    if t.len() == 56 && t.starts_with('S') && t.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
    {
        return true;
    }
    // A long unbroken run of hex or base64url — an API key or a DER blob.
    t.split_whitespace().any(|word| {
        word.len() >= 32
            && word
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 2048-bit RSA key in both PKCS#8 hex and PEM, generated once for tests.
    // Never used anywhere but here.
    fn test_rsa_pkcs8_der() -> Vec<u8> {
        // Generated at test time so no key material is checked into the repo.
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        let key = KeyPair::generate(KeySize::Rsa2048).expect("rsa keygen");
        AsDer::<Pkcs8V1Der>::as_der(&key)
            .expect("pkcs8 der")
            .as_ref()
            .to_vec()
    }

    fn pem_from_pkcs8(der: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    }

    use crate::constants::VALID_CREDENTIAL_KINDS;

    #[test]
    fn credential_kinds_match_the_exchange_providers() {
        // A credential set exists to build exactly one provider client. If
        // these drift, an admin can import a set no resolver will ever read.
        assert_eq!(
            VALID_CREDENTIAL_KINDS,
            crate::constants::VALID_EXCHANGE_PROVIDERS
        );
        for kind in VALID_CREDENTIAL_KINDS {
            assert!(parts_for(kind).is_some(), "no part spec for kind {}", kind);
        }
    }

    #[test]
    fn every_part_spec_names_a_distinct_env_var() {
        let mut seen = std::collections::HashSet::new();
        for kind in VALID_CREDENTIAL_KINDS {
            for spec in parts_for(kind).unwrap() {
                assert!(
                    seen.insert(spec.env_var),
                    "env var {} claimed by two parts",
                    spec.env_var
                );
            }
        }
    }

    #[test]
    fn missing_required_part_is_rejected() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "sk-live-abc");
        let err = p
            .validate_for(EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)
            .unwrap_err();
        match err {
            AppError::BadRequest(m) => assert!(m.contains("private_key"), "{}", m),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn unknown_part_is_rejected_rather_than_silently_dropped() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "abc");
        p.insert("webhook_secret", "whs_x");
        p.insert("privat_key", "typo");
        let err = p.validate_for(EXCHANGE_PROVIDER_OWLPAY).unwrap_err();
        match err {
            AppError::BadRequest(m) => assert!(m.contains("privat_key"), "{}", m),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn optional_parts_may_be_absent() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "abc");
        assert!(p.validate_for(EXCHANGE_PROVIDER_OWLPAY).is_ok());
    }

    // The compare-and-swap in admin_keys compares an env-sourced fingerprint
    // against a stored one. If encoding leaked into the digest, rotating a key
    // from a PEM-mounted file to a hex env var would look like a key change
    // that never happened — and a genuine replacement would 409 forever.
    #[test]
    fn the_same_rsa_key_fingerprints_identically_in_every_encoding() {
        let der = test_rsa_pkcs8_der();
        let hex_form = hex::encode(&der);
        let pem_form = pem_from_pkcs8(&der);

        let from_hex = canonical_bytes(PartForm::RsaPrivateHex, &hex_form).unwrap();
        let from_pem = canonical_bytes(PartForm::RsaPrivatePem, &pem_form).unwrap();
        assert_eq!(from_hex.as_slice(), from_pem.as_slice());

        // Trailing whitespace from a mounted secret file must not matter.
        let padded = format!("  {}\n\n", hex_form);
        let from_padded = canonical_bytes(PartForm::RsaPrivateHex, padded.trim()).unwrap();
        assert_eq!(from_hex.as_slice(), from_padded.as_slice());
    }

    // No digest of private key material is ever stored or displayed: the
    // canonical form of an RSA private key is its PUBLIC half, which a
    // separately-supplied public key must canonicalize to identically.
    #[test]
    fn rsa_fingerprints_hash_only_public_material() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let der = test_rsa_pkcs8_der();
        let canonical = canonical_bytes(PartForm::RsaPrivateHex, &hex::encode(&der)).unwrap();

        // A PKCS#1 RSAPublicKey is far shorter than the PKCS#8 private key it
        // came from — it carries no private exponent or primes.
        assert!(canonical.len() < der.len() / 2);

        // Handing the matching public key in through the public slot yields
        // the identical canonical bytes, which is what makes the private and
        // public halves comparable at all.
        let public_der = STANDARD.encode(canonical.as_slice());
        let from_public = canonical_bytes(PartForm::RsaPublic, &public_der).unwrap();
        assert_eq!(from_public.as_slice(), canonical.as_slice());
    }

    #[test]
    fn fingerprints_are_domain_separated_by_kind_and_part() {
        let a = fingerprint("owlpay", "api_key", b"same-bytes");
        let b = fingerprint("changelly_crypto", "api_key", b"same-bytes");
        let c = fingerprint("owlpay", "webhook_secret", b"same-bytes");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), CREDENTIAL_FP_HEX_LEN);
    }

    #[test]
    fn set_fingerprint_changes_when_any_part_changes() {
        let mut a = CredentialParts::new();
        a.insert("api_key", "k1");
        a.insert("webhook_secret", "s1");
        let mut b = CredentialParts::new();
        b.insert("api_key", "k1");
        b.insert("webhook_secret", "s2");
        let mut c = CredentialParts::new();
        c.insert("api_key", "k1");

        let fa = a.set_fingerprint(EXCHANGE_PROVIDER_OWLPAY);
        assert_ne!(fa, b.set_fingerprint(EXCHANGE_PROVIDER_OWLPAY));
        // Dropping an optional part must also move the set fingerprint, or a
        // merge that removes a webhook secret would look like a no-op.
        assert_ne!(fa, c.set_fingerprint(EXCHANGE_PROVIDER_OWLPAY));
    }

    #[test]
    fn seal_then_open_round_trips() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "live-key");
        p.insert("webhook_secret", "whs_secret");
        let sealed = p.seal(EXCHANGE_PROVIDER_OWLPAY, 3).unwrap();
        let opened = CredentialParts::open_sealed(EXCHANGE_PROVIDER_OWLPAY, 3, &sealed).unwrap();
        assert_eq!(opened.get("api_key"), Some("live-key"));
        assert_eq!(opened.get("webhook_secret"), Some("whs_secret"));
    }

    // The whole point of the bound header: a blob lifted into another row must
    // not open. Neither protector backend binds an encryption context, so this
    // check is the only thing standing between a database writer and a
    // credential transplanted across kinds or versions.
    #[test]
    fn a_sealed_blob_does_not_open_under_a_different_row() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "live-key");
        let sealed = p.seal(EXCHANGE_PROVIDER_OWLPAY, 1).unwrap();

        assert!(
            CredentialParts::open_sealed(EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, 1, &sealed).is_err(),
            "blob opened under a different kind"
        );
        assert!(
            CredentialParts::open_sealed(EXCHANGE_PROVIDER_OWLPAY, 2, &sealed).is_err(),
            "blob opened under a different version"
        );
    }

    // `AppError` messages are serialized into the response body verbatim, and
    // the failure that matters here is a seed or foreign blob landing in a
    // credential row — where the plaintext IS the secret.
    #[test]
    fn binding_failure_never_echoes_the_plaintext() {
        let secret = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = CredentialParts::open_sealed(EXCHANGE_PROVIDER_OWLPAY, 1, secret.as_bytes())
            .unwrap_err();
        let rendered = format!("{:?}", err);
        assert!(!rendered.contains(secret), "error leaked plaintext");
        assert!(!rendered.contains("SAAAA"), "error leaked plaintext prefix");
    }

    #[test]
    fn parts_debug_never_renders_a_value() {
        let mut p = CredentialParts::new();
        p.insert("api_key", "super-secret-value");
        let rendered = format!("{:?}", p);
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("REDACTED"));
        // Part NAMES are safe and useful in a log line.
        assert!(rendered.contains("api_key"));
    }

    #[test]
    fn merge_overlays_and_drops() {
        let mut base = CredentialParts::new();
        base.insert("api_key", "k1");
        base.insert("webhook_secret", "s1");
        let mut overlay = CredentialParts::new();
        overlay.insert("api_key", "k2");

        let merged = base.merged_with(&overlay, &[]);
        assert_eq!(merged.get("api_key"), Some("k2"));
        assert_eq!(merged.get("webhook_secret"), Some("s1"));

        let dropped = base.merged_with(&CredentialParts::new(), &["webhook_secret".to_string()]);
        assert_eq!(dropped.get("api_key"), Some("k1"));
        assert!(!dropped.contains("webhook_secret"));
    }

    #[test]
    fn confirm_phrase_names_the_network() {
        // The commonest operator error is the right key in the wrong
        // environment; the phrase is the only place that is caught.
        assert_eq!(
            confirm_phrase("changelly_crypto", "pubnet"),
            "replace changelly_crypto pubnet"
        );
        assert_ne!(
            confirm_phrase("changelly_crypto", "pubnet"),
            confirm_phrase("changelly_crypto", "testnet")
        );
    }

    #[test]
    fn tokens_match_is_exact() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("abc", "abcd"));
        assert!(!tokens_match("", "a"));
    }

    #[test]
    fn note_rejects_pasted_key_material() {
        assert!(looks_like_secret(
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(looks_like_secret("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(looks_like_secret("whs_abcdef"));
        assert!(looks_like_secret(&"a1b2c3d4".repeat(8)));
        assert!(!looks_like_secret(
            "rotated after the 2026-08 provider notice"
        ));
        assert!(!looks_like_secret("see ticket OPS-1421"));
    }

    #[test]
    fn oversized_parts_are_rejected() {
        let mut p = CredentialParts::new();
        p.insert("api_key", &"x".repeat(CREDENTIAL_PART_MAX_LEN + 1));
        assert!(p.validate_for(EXCHANGE_PROVIDER_OWLPAY).is_err());
    }

    #[test]
    fn a_public_key_pasted_into_the_private_slot_is_rejected() {
        // A realistic operator error: copying the wrong half of a key pair.
        let mut p = CredentialParts::new();
        p.insert("api_key", "abc");
        p.insert(
            "private_key",
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
        );
        assert!(p.validate_for(EXCHANGE_PROVIDER_CHANGELLY_FIAT).is_err());
    }
}
