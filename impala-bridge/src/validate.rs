use crate::constants::{MAX_EMAIL_LENGTH, STELLAR_ACCOUNT_ID_LENGTH};
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
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(AppError::BadRequest(
            "Stellar account ID must be alphanumeric".to_string(),
        ));
    }
    Ok(())
}

/// Validate an email address with a basic check.
pub fn validate_email(email: &str) -> Result<(), AppError> {
    if email.len() > MAX_EMAIL_LENGTH {
        return Err(AppError::BadRequest(
            "Email address too long".to_string(),
        ));
    }
    if !email.contains('@') {
        return Err(AppError::BadRequest(
            "Invalid email address".to_string(),
        ));
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

/// Validate a callback URL for SSRF prevention.
/// Blocks localhost, private IPs, link-local, and cloud metadata endpoints.
pub fn validate_callback_url(url: &str) -> Result<(), AppError> {
    let parsed = url::Url::parse(url).map_err(|_| {
        AppError::BadRequest("Invalid URL format".to_string())
    })?;

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
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || host == "0.0.0.0" {
        return Err(AppError::BadRequest(
            "Callback URL must not target localhost".to_string(),
        ));
    }

    // Block private/reserved IPs
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
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

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
            // 0.0.0.0
            || (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
            || v6.segments()[0] == 0xfe80 // link-local
            || v6.segments()[0] & 0xfe00 == 0xfc00 // unique local
        }
    }
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
        let id = "GABC2345678901234567890123456789012345678901234567890123";
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
}
