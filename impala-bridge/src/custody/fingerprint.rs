//! Request fingerprint for custodial payment intents (pure).
//!
//! An idempotency key identifies an INTENT, not a payload: the same key must
//! replay the recorded outcome for the same request and refuse a different
//! one (`409 idempotency_conflict`). The fingerprint is what "same request"
//! means. It is computed over the PARSED amount (integer minor units), so
//! `"1.5"` and `"1.50"` are the same request, and it is length-prefixed and
//! presence-tagged so an absent field can never collide with an empty one.

use sha2::{Digest, Sha256};

use crate::constants::CUSTODIAL_INTENT_FP_DOMAIN;

/// SHA-256 over `DOMAIN || 0x00`, then for each field in order
/// `[destination, asset_code, asset_issuer|"", amount_minor, memo|"", fee|""]`
/// as `u32 BE length || bytes`, then three presence bytes
/// `[issuer.is_some(), memo.is_some(), fee.is_some()]`. 64 lowercase hex.
pub(crate) fn intent_fingerprint(
    destination: &str,
    asset_code: &str,
    asset_issuer: Option<&str>,
    amount_minor: i64,
    memo: Option<&str>,
    fee_stroops: Option<u32>,
) -> String {
    let mut h = Sha256::new();
    h.update(CUSTODIAL_INTENT_FP_DOMAIN.as_bytes());
    h.update([0u8]);
    let amount = amount_minor.to_string();
    let fee = fee_stroops.map(|f| f.to_string());
    for field in [
        destination,
        asset_code,
        asset_issuer.unwrap_or(""),
        amount.as_str(),
        memo.unwrap_or(""),
        fee.as_deref().unwrap_or(""),
    ] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.update([
        u8::from(asset_issuer.is_some()),
        u8::from(memo.is_some()),
        u8::from(fee_stroops.is_some()),
    ]);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: &str = "GDESTINATIONAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Pinned literal: a change to the domain, field order, or framing
    /// silently turns every stored fingerprint into a conflict on replay.
    #[test]
    fn fingerprint_golden_vector() {
        let fp = intent_fingerprint(DEST, "XLM", None, 125_000_000, Some("invoice 7"), Some(100));
        assert_eq!(fp.len(), 64);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(
            fp,
            "5b8a5167aecd179f12f8c23f7352b91b94ad604e7a1858096fe8c4da403bbcbb"
        );
    }

    #[test]
    fn fingerprint_distinguishes_absent_from_empty() {
        let absent = intent_fingerprint(DEST, "XLM", None, 1, None, None);
        let empty = intent_fingerprint(DEST, "XLM", None, 1, Some(""), None);
        assert_ne!(absent, empty, "an absent memo is not an empty memo");
        let no_issuer = intent_fingerprint(DEST, "USDC", None, 1, None, None);
        let empty_issuer = intent_fingerprint(DEST, "USDC", Some(""), 1, None, None);
        assert_ne!(no_issuer, empty_issuer);
    }

    #[test]
    fn fingerprint_is_amount_canonical() {
        // The caller parses "1.5" and "1.50" to the same minor units; the
        // fingerprint sees only the integer, so both replay each other.
        let a = intent_fingerprint(DEST, "XLM", None, 15_000_000, None, None);
        let b = intent_fingerprint(DEST, "XLM", None, 15_000_000, None, None);
        assert_eq!(a, b);
        assert_ne!(
            a,
            intent_fingerprint(DEST, "XLM", None, 15_000_001, None, None)
        );
    }

    #[test]
    fn fingerprint_changes_with_each_field() {
        let base = intent_fingerprint(DEST, "XLM", None, 100, Some("m"), Some(100));
        let other_dest = format!("G{}", "B".repeat(55));
        assert_ne!(
            base,
            intent_fingerprint(&other_dest, "XLM", None, 100, Some("m"), Some(100))
        );
        assert_ne!(
            base,
            intent_fingerprint(DEST, "USDC", Some("GISS"), 100, Some("m"), Some(100))
        );
        assert_ne!(
            base,
            intent_fingerprint(DEST, "XLM", None, 101, Some("m"), Some(100))
        );
        assert_ne!(
            base,
            intent_fingerprint(DEST, "XLM", None, 100, Some("n"), Some(100))
        );
        assert_ne!(
            base,
            intent_fingerprint(DEST, "XLM", None, 100, Some("m"), Some(101))
        );
        assert_ne!(
            base,
            intent_fingerprint(DEST, "XLM", None, 100, Some("m"), None)
        );
    }

    /// Length framing: moving a byte across a field boundary must change
    /// the digest (no `"ab" || "c"` == `"a" || "bc"` collisions).
    #[test]
    fn fingerprint_frames_fields_by_length() {
        let a = intent_fingerprint("ab", "c", None, 1, None, None);
        let b = intent_fingerprint("a", "bc", None, 1, None, None);
        assert_ne!(a, b);
    }
}
