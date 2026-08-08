use crate::constants::{CARD_SIGNATURE_MAX_BYTES, MAX_EMAIL_LENGTH, STELLAR_ACCOUNT_ID_LENGTH};
use crate::error::AppError;
use std::net::IpAddr;

/// Validate a Stellar account ID format: must start with 'G', be 56 chars, alphanumeric.
pub fn validate_stellar_account_id(id: &str) -> Result<(), AppError> {
    if id.len() != STELLAR_ACCOUNT_ID_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Stellar account ID must be {} characters",
            STELLAR_ACCOUNT_ID_LENGTH
        )));
    }
    if !id.starts_with('G') {
        return Err(AppError::BadRequest(
            "Stellar account ID must start with 'G'".to_string(),
        ));
    }
    if !id.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(AppError::BadRequest(
            "Stellar account ID must contain only Base32 characters (A-Z, 2-7)".to_string(),
        ));
    }
    Ok(())
}

/// Validate a Stellar secret seed format: must start with 'S', be 56 chars, Base32.
///
/// This is the cheap structural gate; strkey checksum validation happens when the
/// seed is decoded into a keypair (`StellarSigner::seed_from_strkey`).
pub fn validate_stellar_secret_seed(seed: &str) -> Result<(), AppError> {
    if seed.len() != STELLAR_ACCOUNT_ID_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Stellar secret seed must be {} characters",
            STELLAR_ACCOUNT_ID_LENGTH
        )));
    }
    if !seed.starts_with('S') {
        return Err(AppError::BadRequest(
            "Stellar secret seed must start with 'S'".to_string(),
        ));
    }
    if !seed.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(AppError::BadRequest(
            "Stellar secret seed must contain only Base32 characters (A-Z, 2-7)".to_string(),
        ));
    }
    Ok(())
}

/// Validate an email address with a basic check.
pub fn validate_email(email: &str) -> Result<(), AppError> {
    if email.len() > MAX_EMAIL_LENGTH {
        return Err(AppError::BadRequest("Email address too long".to_string()));
    }
    if !email.contains('@') {
        return Err(AppError::BadRequest("Invalid email address".to_string()));
    }
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(AppError::BadRequest(
            "Invalid email address format".to_string(),
        ));
    }
    Ok(())
}

/// Validate a phone number in E.164 format (e.g., +14155551234).
pub fn validate_phone_number(phone: &str) -> Result<(), AppError> {
    if !phone.starts_with('+') {
        return Err(AppError::BadRequest(
            "Phone number must start with '+'".to_string(),
        ));
    }
    if phone.len() < 8 || phone.len() > 16 {
        return Err(AppError::BadRequest(
            "Phone number must be between 8 and 16 characters".to_string(),
        ));
    }
    if !phone[1..].chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::BadRequest(
            "Phone number must contain only digits after '+'".to_string(),
        ));
    }
    Ok(())
}

/// Validate a card ID format: hex string, 8-32 characters.
pub fn validate_card_id(id: &str) -> Result<(), AppError> {
    if id.len() < 8 || id.len() > 32 {
        return Err(AppError::BadRequest(
            "Card ID must be between 8 and 32 characters".to_string(),
        ));
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "Card ID must be a hexadecimal string".to_string(),
        ));
    }
    Ok(())
}

/// Validate an EC public key: hex string, 66 chars (compressed) or 130 chars (uncompressed P-256).
pub fn validate_ec_pubkey(key: &str) -> Result<(), AppError> {
    if key.len() != 66 && key.len() != 130 {
        return Err(AppError::BadRequest(
            "EC public key must be 66 (compressed) or 130 (uncompressed) hex characters"
                .to_string(),
        ));
    }
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "EC public key must be a hexadecimal string".to_string(),
        ));
    }
    Ok(())
}

/// Validate a hex-encoded ECDSA signature: even-length hex string decoding to
/// 8..=72 bytes (an ASN.1 DER P-256 signature is at most 72 bytes).
pub fn validate_hex_signature(sig: &str) -> Result<(), AppError> {
    if !sig.len().is_multiple_of(2) || sig.len() < 16 || sig.len() > CARD_SIGNATURE_MAX_BYTES * 2 {
        return Err(AppError::BadRequest(format!(
            "Signature must be an even-length hex string of at most {} characters",
            CARD_SIGNATURE_MAX_BYTES * 2
        )));
    }
    if !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "Signature must be a hexadecimal string".to_string(),
        ));
    }
    Ok(())
}

/// Validate an RSA public key: Base64-encoded, 100-2048 characters.
pub fn validate_rsa_pubkey(key: &str) -> Result<(), AppError> {
    if key.len() < 100 || key.len() > 2048 {
        return Err(AppError::BadRequest(
            "RSA public key must be between 100 and 2048 characters".to_string(),
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(AppError::BadRequest(
            "RSA public key must be Base64-encoded".to_string(),
        ));
    }
    Ok(())
}

/// Validate a callback URL for SSRF prevention.
/// Blocks localhost, private IPs, link-local, and cloud metadata endpoints.
pub fn validate_callback_url(url: &str) -> Result<(), AppError> {
    let parsed =
        url::Url::parse(url).map_err(|_| AppError::BadRequest("Invalid URL format".to_string()))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(AppError::BadRequest(
            "URL scheme must be http or https".to_string(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("URL must have a host".to_string()))?;

    // Block localhost
    if host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
        || host == "0.0.0.0"
    {
        return Err(AppError::BadRequest(
            "Callback URL must not target localhost".to_string(),
        ));
    }

    // Block private/reserved IPs. `host_str()` returns IPv6 literals in
    // bracketed form (e.g. "[fc00::1]"), which `IpAddr::from_str` rejects, so
    // strip the brackets first — otherwise the IPv6 arm of the predicate below
    // is unreachable and link-local/ULA/IPv6-metadata hosts slip through.
    //
    // This only sees IP *literals*: a hostname that resolves to an internal
    // address passes here by design. Enforcement against resolved addresses
    // (and against DNS rebinding) is `crate::ssrf::EgressGuard`, installed as
    // the DNS resolver on every client that fetches one of these URLs. This
    // check stays because it turns the common mistake into an immediate 400
    // instead of a delivery failure discovered later.
    let host_ip = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host_ip.parse::<IpAddr>() {
        if crate::ssrf::is_blocked_ip(&ip) {
            return Err(AppError::BadRequest(
                "Callback URL must not target private IP addresses".to_string(),
            ));
        }
    }

    // Block metadata endpoints (e.g., AWS, GCP, Azure)
    if host == "169.254.169.254" || host == "metadata.google.internal" {
        return Err(AppError::BadRequest(
            "Callback URL must not target cloud metadata endpoints".to_string(),
        ));
    }

    Ok(())
}

// The address predicate lives in `crate::ssrf` so the registration-time gate
// here and the connection-time resolver enforce exactly the same policy. The
// former local copy missed CGNAT, reserved and IPv4-in-IPv6 ranges, and only
// matched fe80::/16 rather than the full fe80::/10 link-local block.

/// Validate a transaction ID: non-empty, max 128 chars, alphanumeric/hex.
pub fn validate_transaction_id(id: &str) -> Result<(), AppError> {
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest(
            "Transaction ID must be between 1 and 128 characters".to_string(),
        ));
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(AppError::BadRequest(
            "Transaction ID must be alphanumeric".to_string(),
        ));
    }
    Ok(())
}

/// Validate a hex hash string (e.g. Stellar transaction hash).
pub fn validate_hex_hash(hash: &str, field_name: &str) -> Result<(), AppError> {
    if hash.is_empty() || hash.len() > 128 {
        return Err(AppError::BadRequest(format!(
            "{} must be between 1 and 128 characters",
            field_name
        )));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(format!(
            "{} must be a hex string",
            field_name
        )));
    }
    Ok(())
}

/// Validate a listen endpoint: must be a valid socket address on localhost
/// with a non-privileged port. Prevents binding on external interfaces.
pub fn validate_listen_endpoint(endpoint: &str) -> Result<(), AppError> {
    let addr: std::net::SocketAddr = endpoint.parse().map_err(|_| {
        AppError::BadRequest(
            "listen_endpoint must be a valid socket address (e.g. 127.0.0.1:8080)".to_string(),
        )
    })?;

    if !addr.ip().is_loopback() {
        return Err(AppError::BadRequest(
            "listen_endpoint must bind to localhost (127.0.0.1 or ::1)".to_string(),
        ));
    }

    if addr.port() == 0 {
        return Err(AppError::BadRequest(
            "listen_endpoint must specify a non-zero port".to_string(),
        ));
    }

    if addr.port() < 1024 {
        return Err(AppError::BadRequest(
            "listen_endpoint port must be >= 1024".to_string(),
        ));
    }

    Ok(())
}

/// Validate an account role against the allowed set (`ALL_ROLES`).
pub fn validate_role(role: &str) -> Result<(), AppError> {
    if crate::constants::ALL_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Invalid role '{}'. Must be one of: {}",
            role,
            crate::constants::ALL_ROLES.join(", ")
        )))
    }
}

/// Validate a Payala currency code: 1–16 chars, uppercase alphanumeric.
/// Lowercase is rejected rather than normalized so per-currency reserve keys
/// stay canonical ("USD" vs "Usd" must not fork into separate balances).
pub fn validate_payala_currency(currency: &str) -> Result<(), AppError> {
    if currency.is_empty() || currency.len() > crate::constants::MAX_PAYALA_CURRENCY_LENGTH {
        return Err(AppError::BadRequest(format!(
            "currency must be between 1 and {} characters",
            crate::constants::MAX_PAYALA_CURRENCY_LENGTH
        )));
    }
    if !currency
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Err(AppError::BadRequest(
            "currency must be uppercase alphanumeric (A-Z, 0-9)".to_string(),
        ));
    }
    Ok(())
}

/// Validate a Payala sync mode against the allowed set (`VALID_SYNC_MODES`).
pub fn validate_sync_mode(mode: &str) -> Result<(), AppError> {
    if crate::constants::VALID_SYNC_MODES.contains(&mode) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Invalid sync_mode '{}'. Must be one of: {}",
            mode,
            crate::constants::VALID_SYNC_MODES.join(", ")
        )))
    }
}

/// Validate that `value` is a well-formed RFC 3339 timestamp (e.g. used for
/// transaction date-range filters). Returns `BadRequest` naming the field.
pub fn validate_rfc3339_timestamp(value: &str, field: &str) -> Result<(), AppError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| AppError::BadRequest(format!("{} must be an RFC 3339 timestamp", field)))
}

/// Validate an exchange currency/ticker code (e.g. "USD", "xlm", "usdcxlm"):
/// 1–24 chars of `[A-Za-z0-9_-]`. Case is preserved rather than normalized —
/// Changelly tickers are lowercase while fiat codes are uppercase, so unlike
/// Payala currencies no canonical case exists.
pub fn validate_exchange_currency(currency: &str) -> Result<(), AppError> {
    if currency.is_empty() || currency.len() > crate::constants::MAX_EXCHANGE_CURRENCY_LEN {
        return Err(AppError::BadRequest(format!(
            "currency must be between 1 and {} characters",
            crate::constants::MAX_EXCHANGE_CURRENCY_LEN
        )));
    }
    if !currency
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "currency must contain only letters, digits, '_' or '-'".to_string(),
        ));
    }
    Ok(())
}

/// Validate a decimal amount string: up to 20 integer digits, optionally a
/// '.' plus up to 18 fraction digits, strictly positive. Exchange amounts are
/// provider-quoted decimal STRINGS end-to-end (heterogeneous precisions) —
/// this gate never parses them into numbers.
pub fn validate_decimal_amount(amount: &str) -> Result<(), AppError> {
    if amount.is_empty() || amount.len() > crate::constants::MAX_EXCHANGE_AMOUNT_LEN {
        return Err(AppError::BadRequest(format!(
            "amount must be between 1 and {} characters",
            crate::constants::MAX_EXCHANGE_AMOUNT_LEN
        )));
    }
    let (int_part, frac_part) = match amount.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (amount, None),
    };
    if int_part.is_empty() || int_part.len() > 20 || !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::BadRequest(
            "amount must be an unsigned decimal number (e.g. 12.5) with at most 20 integer digits"
                .to_string(),
        ));
    }
    if let Some(frac) = frac_part {
        if frac.is_empty() || frac.len() > 18 || !frac.chars().all(|c| c.is_ascii_digit()) {
            return Err(AppError::BadRequest(
                "amount must have between 1 and 18 fraction digits".to_string(),
            ));
        }
    }
    // Strictly positive: at least one nonzero digit somewhere.
    if !amount.chars().any(|c| matches!(c, '1'..='9')) {
        return Err(AppError::BadRequest(
            "amount must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

/// Validate a crypto payout/refund address: 1–128 chars of printable ASCII
/// with no whitespace or control characters. Per-chain format correctness is
/// delegated to the provider's validate-address endpoint; this gate only
/// blocks junk and header/log injection.
pub fn validate_exchange_address(address: &str) -> Result<(), AppError> {
    if address.is_empty() || address.len() > crate::constants::MAX_EXCHANGE_ADDRESS_LEN {
        return Err(AppError::BadRequest(format!(
            "address must be between 1 and {} characters",
            crate::constants::MAX_EXCHANGE_ADDRESS_LEN
        )));
    }
    if !address.chars().all(|c| c.is_ascii_graphic()) {
        return Err(AppError::BadRequest(
            "address must be printable ASCII without whitespace".to_string(),
        ));
    }
    Ok(())
}

/// Validate a payout/refund extra id (destination tag / memo): 1–64 chars of
/// printable ASCII. Interior spaces are allowed (Stellar text memos may
/// contain them); control characters are not.
pub fn validate_exchange_extra_id(extra_id: &str) -> Result<(), AppError> {
    if extra_id.is_empty() || extra_id.len() > crate::constants::MAX_EXCHANGE_EXTRA_ID_LEN {
        return Err(AppError::BadRequest(format!(
            "extra_id must be between 1 and {} characters",
            crate::constants::MAX_EXCHANGE_EXTRA_ID_LEN
        )));
    }
    if !extra_id.chars().all(|c| c == ' ' || c.is_ascii_graphic()) {
        return Err(AppError::BadRequest(
            "extra_id must be printable ASCII".to_string(),
        ));
    }
    Ok(())
}

/// Escape special characters in LDAP filter values per RFC 4515.
pub fn ldap_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => escaped.push_str("\\5c"),
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stellar account ID ─────────────────────────────────────────────

    #[test]
    fn test_valid_stellar_id() {
        let id = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        assert!(validate_stellar_account_id(id).is_ok());
    }

    #[test]
    fn test_stellar_id_wrong_prefix() {
        let id = "SABC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    #[test]
    fn test_stellar_id_too_short() {
        assert!(validate_stellar_account_id("GABC").is_err());
    }

    #[test]
    fn test_stellar_id_non_alphanumeric() {
        let id = "GABC234567890123456789012345678901234567890123456789012!";
        assert!(validate_stellar_account_id(id).is_err());
    }

    // ── Stellar secret seed ────────────────────────────────────────────

    #[test]
    fn test_valid_stellar_secret_seed() {
        let seed = "SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        assert!(validate_stellar_secret_seed(seed).is_ok());
    }

    #[test]
    fn test_secret_seed_wrong_prefix() {
        // A G-address must not pass as a secret seed.
        let id = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        assert!(validate_stellar_secret_seed(id).is_err());
    }

    #[test]
    fn test_secret_seed_too_short() {
        assert!(validate_stellar_secret_seed("SABC").is_err());
    }

    #[test]
    fn test_secret_seed_rejects_lowercase() {
        let seed = "Sabc2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_secret_seed(seed).is_err());
    }

    #[test]
    fn test_secret_seed_rejects_invalid_base32_digit() {
        let seed = "S0BC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_secret_seed(seed).is_err());
    }

    // ── Email ──────────────────────────────────────────────────────────

    #[test]
    fn test_valid_email() {
        assert!(validate_email("user@example.com").is_ok());
    }

    #[test]
    fn test_email_no_at() {
        assert!(validate_email("userexample.com").is_err());
    }

    #[test]
    fn test_email_no_domain_dot() {
        assert!(validate_email("user@example").is_err());
    }

    #[test]
    fn test_email_empty_local() {
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_email_too_long() {
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert!(validate_email(&long_email).is_err());
    }

    // ── Phone number ───────────────────────────────────────────────────

    #[test]
    fn test_valid_phone() {
        assert!(validate_phone_number("+14155551234").is_ok());
    }

    #[test]
    fn test_phone_no_plus() {
        assert!(validate_phone_number("14155551234").is_err());
    }

    #[test]
    fn test_phone_too_short() {
        assert!(validate_phone_number("+12345").is_err());
    }

    #[test]
    fn test_phone_non_digit() {
        assert!(validate_phone_number("+1415555abc4").is_err());
    }

    // ── Callback URL ───────────────────────────────────────────────────

    #[test]
    fn test_valid_callback_url() {
        assert!(validate_callback_url("https://example.com/webhook").is_ok());
    }

    #[test]
    fn test_callback_localhost() {
        assert!(validate_callback_url("http://localhost/callback").is_err());
    }

    #[test]
    fn test_callback_loopback() {
        assert!(validate_callback_url("http://127.0.0.1/callback").is_err());
    }

    #[test]
    fn test_callback_private_10() {
        assert!(validate_callback_url("http://10.0.0.1/callback").is_err());
    }

    #[test]
    fn test_callback_private_172() {
        assert!(validate_callback_url("http://172.16.0.1/callback").is_err());
    }

    #[test]
    fn test_callback_private_192() {
        assert!(validate_callback_url("http://192.168.1.1/callback").is_err());
    }

    #[test]
    fn test_callback_link_local() {
        assert!(validate_callback_url("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn test_callback_metadata() {
        assert!(validate_callback_url("http://169.254.169.254/").is_err());
    }

    #[test]
    fn test_callback_ftp_scheme() {
        assert!(validate_callback_url("ftp://example.com/file").is_err());
    }

    #[test]
    fn test_callback_ipv6_loopback() {
        assert!(validate_callback_url("http://[::1]/callback").is_err());
    }

    #[test]
    fn test_callback_ipv6_link_local() {
        assert!(validate_callback_url("http://[fe80::1]/callback").is_err());
    }

    #[test]
    fn test_callback_ipv6_unique_local() {
        assert!(validate_callback_url("http://[fc00::1]/callback").is_err());
    }

    #[test]
    fn test_callback_ipv6_aws_metadata() {
        // AWS IPv6 instance metadata endpoint (ULA fd00:ec2::254).
        assert!(validate_callback_url("http://[fd00:ec2::254]/latest/meta-data").is_err());
    }

    #[test]
    fn test_callback_ipv6_public_ok() {
        // A public IPv6 literal must still be allowed.
        assert!(validate_callback_url("https://[2606:4700:4700::1111]/webhook").is_ok());
    }

    // ── LDAP escape ────────────────────────────────────────────────────

    #[test]
    fn test_ldap_escape_clean() {
        assert_eq!(ldap_escape("hello"), "hello");
    }

    #[test]
    fn test_ldap_escape_special_chars() {
        assert_eq!(ldap_escape("user*(admin)"), "user\\2a\\28admin\\29");
    }

    #[test]
    fn test_ldap_escape_backslash() {
        assert_eq!(ldap_escape("a\\b"), "a\\5cb");
    }

    #[test]
    fn test_ldap_escape_null() {
        assert_eq!(ldap_escape("a\0b"), "a\\00b");
    }

    // ── Stellar Base32 enforcement ──────────────────────────────────────

    #[test]
    fn test_stellar_id_rejects_lowercase() {
        let id = "Gabc2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    #[test]
    fn test_stellar_id_rejects_digit_0() {
        let id = "G0BC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    #[test]
    fn test_stellar_id_rejects_digit_1() {
        let id = "G1BC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    #[test]
    fn test_stellar_id_rejects_digit_8() {
        let id = "G8BC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    #[test]
    fn test_stellar_id_rejects_digit_9() {
        let id = "G9BC2345678901234567890123456789012345678901234567890123";
        assert!(validate_stellar_account_id(id).is_err());
    }

    // ── Card ID ─────────────────────────────────────────────────────────

    #[test]
    fn test_valid_card_id() {
        assert!(validate_card_id("A1B2C3D4E5F6").is_ok());
    }

    #[test]
    fn test_card_id_too_short() {
        assert!(validate_card_id("ABC").is_err());
    }

    #[test]
    fn test_card_id_non_hex() {
        assert!(validate_card_id("GGHHIIJJ").is_err());
    }

    // ── EC Public Key ───────────────────────────────────────────────────

    #[test]
    fn test_valid_ec_pubkey_compressed() {
        let key = "02".to_string() + &"ab".repeat(32);
        assert!(validate_ec_pubkey(&key).is_ok());
    }

    #[test]
    fn test_valid_ec_pubkey_uncompressed() {
        let key = "04".to_string() + &"ab".repeat(64);
        assert!(validate_ec_pubkey(&key).is_ok());
    }

    #[test]
    fn test_ec_pubkey_wrong_length() {
        assert!(validate_ec_pubkey("abcdef").is_err());
    }

    // ── Hex signature ───────────────────────────────────────────────────

    #[test]
    fn test_valid_hex_signature() {
        // Typical DER ECDSA P-256 signature: ~70-72 bytes
        let sig = "30".to_string() + &"44".repeat(70);
        assert!(validate_hex_signature(&sig).is_ok());
    }

    #[test]
    fn test_hex_signature_odd_length() {
        assert!(validate_hex_signature(&"a".repeat(17)).is_err());
    }

    #[test]
    fn test_hex_signature_too_short() {
        assert!(validate_hex_signature("3044").is_err());
    }

    #[test]
    fn test_hex_signature_too_long() {
        assert!(validate_hex_signature(&"ab".repeat(73)).is_err());
    }

    #[test]
    fn test_hex_signature_non_hex() {
        assert!(validate_hex_signature(&"zz".repeat(35)).is_err());
    }

    // ── RSA Public Key ──────────────────────────────────────────────────

    #[test]
    fn test_valid_rsa_pubkey() {
        let key = "A".repeat(200);
        assert!(validate_rsa_pubkey(&key).is_ok());
    }

    #[test]
    fn test_rsa_pubkey_too_short() {
        let key = "A".repeat(50);
        assert!(validate_rsa_pubkey(&key).is_err());
    }

    #[test]
    fn test_rsa_pubkey_invalid_chars() {
        let key = "!".repeat(200);
        assert!(validate_rsa_pubkey(&key).is_err());
    }

    // ── Transaction ID ────────────────────────────────────────────────

    #[test]
    fn test_valid_transaction_id() {
        assert!(validate_transaction_id("abc123def456").is_ok());
    }

    #[test]
    fn test_transaction_id_empty() {
        assert!(validate_transaction_id("").is_err());
    }

    #[test]
    fn test_transaction_id_too_long() {
        let id = "a".repeat(129);
        assert!(validate_transaction_id(&id).is_err());
    }

    #[test]
    fn test_transaction_id_max_length() {
        let id = "a".repeat(128);
        assert!(validate_transaction_id(&id).is_ok());
    }

    #[test]
    fn test_transaction_id_special_chars() {
        assert!(validate_transaction_id("abc-123").is_err());
    }

    // ── Hex Hash ──────────────────────────────────────────────────────

    #[test]
    fn test_valid_hex_hash() {
        assert!(validate_hex_hash("abcdef0123456789", "stellar_hash").is_ok());
    }

    #[test]
    fn test_hex_hash_empty() {
        assert!(validate_hex_hash("", "stellar_hash").is_err());
    }

    #[test]
    fn test_hex_hash_non_hex() {
        assert!(validate_hex_hash("xyz123", "stellar_hash").is_err());
    }

    #[test]
    fn test_hex_hash_too_long() {
        let hash = "a".repeat(129);
        assert!(validate_hex_hash(&hash, "stellar_hash").is_err());
    }

    // ── Listen Endpoint ───────────────────────────────────────────────

    #[test]
    fn test_valid_listen_endpoint() {
        assert!(validate_listen_endpoint("127.0.0.1:8080").is_ok());
    }

    #[test]
    fn test_listen_endpoint_ipv6_localhost() {
        assert!(validate_listen_endpoint("[::1]:8080").is_ok());
    }

    #[test]
    fn test_listen_endpoint_external_ip() {
        assert!(validate_listen_endpoint("0.0.0.0:8080").is_err());
    }

    #[test]
    fn test_listen_endpoint_port_zero() {
        assert!(validate_listen_endpoint("127.0.0.1:0").is_err());
    }

    #[test]
    fn test_listen_endpoint_privileged_port() {
        assert!(validate_listen_endpoint("127.0.0.1:80").is_err());
    }

    #[test]
    fn test_listen_endpoint_invalid_format() {
        assert!(validate_listen_endpoint("not-an-address").is_err());
    }

    #[test]
    fn test_listen_endpoint_private_ip() {
        assert!(validate_listen_endpoint("192.168.1.1:8080").is_err());
    }

    // ── Role ──────────────────────────────────────────────────────────

    #[test]
    fn test_validate_role_accepts_all_roles() {
        for role in ["view-only", "device", "token", "admin"] {
            assert!(validate_role(role).is_ok(), "role {} should be valid", role);
        }
    }

    #[test]
    fn test_validate_role_rejects_unknown() {
        assert!(validate_role("superuser").is_err());
        assert!(validate_role("").is_err());
        assert!(validate_role("Admin").is_err());
    }

    // ── Payala currency / sync mode ────────────────────────────────────

    #[test]
    fn test_validate_payala_currency_valid() {
        for c in ["USD", "XLM", "PAYALA1", "A", "0123456789ABCDEF"] {
            assert!(
                validate_payala_currency(c).is_ok(),
                "currency {} should be valid",
                c
            );
        }
    }

    #[test]
    fn test_validate_payala_currency_rejects_lowercase() {
        assert!(validate_payala_currency("usd").is_err());
        assert!(validate_payala_currency("Usd").is_err());
    }

    #[test]
    fn test_validate_payala_currency_rejects_empty_and_too_long() {
        assert!(validate_payala_currency("").is_err());
        assert!(validate_payala_currency("ABCDEFGHIJKLMNOPQ").is_err()); // 17 chars
    }

    #[test]
    fn test_validate_payala_currency_rejects_symbols_and_whitespace() {
        assert!(validate_payala_currency("US D").is_err());
        assert!(validate_payala_currency(" USD").is_err());
        assert!(validate_payala_currency("US-D").is_err());
    }

    #[test]
    fn test_validate_sync_mode_accepts_all_modes() {
        for mode in crate::constants::VALID_SYNC_MODES {
            assert!(
                validate_sync_mode(mode).is_ok(),
                "mode {} should be valid",
                mode
            );
        }
    }

    #[test]
    fn test_validate_sync_mode_rejects_unknown() {
        assert!(validate_sync_mode("Reserve").is_err());
        assert!(validate_sync_mode("MIRROR").is_err());
        assert!(validate_sync_mode("").is_err());
        assert!(validate_sync_mode("both").is_err());
    }

    // ── RFC 3339 timestamp ─────────────────────────────────────────────

    #[test]
    fn test_validate_rfc3339_accepts_valid() {
        assert!(validate_rfc3339_timestamp("2026-06-30T00:00:00Z", "from").is_ok());
        assert!(validate_rfc3339_timestamp("2026-06-30T12:34:56+02:00", "to").is_ok());
    }

    #[test]
    fn test_validate_rfc3339_rejects_invalid() {
        assert!(validate_rfc3339_timestamp("not-a-date", "from").is_err());
        assert!(validate_rfc3339_timestamp("2026-13-01T00:00:00Z", "from").is_err());
        assert!(validate_rfc3339_timestamp("2026-06-30", "from").is_err());
    }

    // ── Exchange currency ──────────────────────────────────────────────

    #[test]
    fn test_validate_exchange_currency_valid() {
        for c in [
            "USD",
            "xlm",
            "usdcxlm",
            "USDT-TRC20",
            "usdc_polygon",
            "A",
            "0",
        ] {
            assert!(
                validate_exchange_currency(c).is_ok(),
                "currency {} should be valid",
                c
            );
        }
    }

    #[test]
    fn test_validate_exchange_currency_length_bounds() {
        assert!(validate_exchange_currency(&"a".repeat(24)).is_ok());
        assert!(validate_exchange_currency(&"a".repeat(25)).is_err());
        assert!(validate_exchange_currency("").is_err());
    }

    #[test]
    fn test_validate_exchange_currency_rejects_bad_chars() {
        assert!(validate_exchange_currency("US D").is_err()); // space
        assert!(validate_exchange_currency("usd.e").is_err()); // dot
        assert!(validate_exchange_currency("usd!").is_err());
        assert!(validate_exchange_currency("usd\n").is_err()); // control
        assert!(validate_exchange_currency("usd\t").is_err());
        assert!(validate_exchange_currency("usdé").is_err()); // non-ASCII
    }

    // ── Decimal amount ─────────────────────────────────────────────────

    #[test]
    fn test_validate_decimal_amount_valid() {
        for a in [
            "1",
            "0.1",
            "125.5",
            "01", // leading zeros allowed; value is nonzero
            "0001.0500",
            "99999999999999999999",                    // 20 integer digits
            "0.000000000000000001",                    // 18 fraction digits
            "99999999999999999999.999999999999999999", // both at max
        ] {
            assert!(
                validate_decimal_amount(a).is_ok(),
                "amount {} should be valid",
                a
            );
        }
    }

    #[test]
    fn test_validate_decimal_amount_rejects_zero() {
        for a in ["0", "0.0", "00", "0.000", "000.000000"] {
            assert!(
                validate_decimal_amount(a).is_err(),
                "amount {} must be rejected as zero",
                a
            );
        }
    }

    #[test]
    fn test_validate_decimal_amount_rejects_malformed() {
        assert!(validate_decimal_amount("").is_err());
        assert!(validate_decimal_amount(".5").is_err()); // leading dot
        assert!(validate_decimal_amount("5.").is_err()); // trailing dot
        assert!(validate_decimal_amount("1.2.3").is_err()); // two dots
        assert!(validate_decimal_amount("-1").is_err()); // signed
        assert!(validate_decimal_amount("+1").is_err());
        assert!(validate_decimal_amount("1e5").is_err()); // exponent
        assert!(validate_decimal_amount("1,5").is_err()); // comma decimal
        assert!(validate_decimal_amount(" 1").is_err()); // whitespace
        assert!(validate_decimal_amount("1 ").is_err());
        assert!(validate_decimal_amount("١٢").is_err()); // non-ASCII digits
    }

    #[test]
    fn test_validate_decimal_amount_rejects_oversized() {
        // 21 integer digits.
        assert!(validate_decimal_amount(&"9".repeat(21)).is_err());
        // 19 fraction digits.
        assert!(validate_decimal_amount(&format!("1.{}", "9".repeat(19))).is_err());
        // Over MAX_EXCHANGE_AMOUNT_LEN outright.
        assert!(validate_decimal_amount(&"9".repeat(41)).is_err());
    }

    // ── Exchange address ───────────────────────────────────────────────

    #[test]
    fn test_validate_exchange_address_valid() {
        let stellar = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        assert!(validate_exchange_address(stellar).is_ok());
        assert!(validate_exchange_address("0x52908400098527886E0F7030069857D2E4169EE7").is_ok());
        assert!(validate_exchange_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").is_ok());
        assert!(validate_exchange_address(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn test_validate_exchange_address_rejects_bad_input() {
        assert!(validate_exchange_address("").is_err());
        assert!(validate_exchange_address(&"a".repeat(129)).is_err());
        assert!(validate_exchange_address("addr with space").is_err());
        assert!(validate_exchange_address("addr\ttab").is_err());
        assert!(validate_exchange_address("addr\nnewline").is_err());
        assert!(validate_exchange_address("addr\r").is_err());
        assert!(validate_exchange_address("addr\u{7f}").is_err()); // DEL
        assert!(validate_exchange_address("addrß").is_err()); // non-ASCII
    }

    // ── Exchange extra id ──────────────────────────────────────────────

    #[test]
    fn test_validate_exchange_extra_id_valid() {
        assert!(validate_exchange_extra_id("123456").is_ok()); // XRP-style tag
        assert!(validate_exchange_extra_id("invoice 42").is_ok()); // memo with space
        assert!(validate_exchange_extra_id(&"m".repeat(64)).is_ok());
    }

    #[test]
    fn test_validate_exchange_extra_id_rejects_bad_input() {
        assert!(validate_exchange_extra_id("").is_err());
        assert!(validate_exchange_extra_id(&"m".repeat(65)).is_err());
        assert!(validate_exchange_extra_id("memo\n").is_err());
        assert!(validate_exchange_extra_id("memo\t").is_err());
        assert!(validate_exchange_extra_id("memo\u{0}").is_err());
        assert!(validate_exchange_extra_id("mémo").is_err()); // non-ASCII
    }
}
