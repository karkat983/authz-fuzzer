//! Header redaction.
//!
//! Credentials must never reach stored evidence. [`is_sensitive_header`] names the headers
//! that carry them, and [`redact_headers`] returns a copy with those header *values*
//! replaced by a placeholder (the names are kept, so evidence still shows that auth was
//! present without revealing the secret).

/// The placeholder substituted for a redacted header value.
pub const REDACTED: &str = "<redacted>";

/// Whether a header name carries a credential or session secret (case-insensitive).
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-amz-security-token"
    ) || lower.ends_with("-token")
        || lower.ends_with("-secret")
        || lower.ends_with("apikey")
}

/// Return a copy of the headers with sensitive values replaced by [`REDACTED`].
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if is_sensitive_header(k) {
                (k.clone(), REDACTED.to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sensitive_headers() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("Set-Cookie"));
        assert!(is_sensitive_header("X-Api-Key"));
        assert!(is_sensitive_header("X-Session-Token"));
        assert!(is_sensitive_header("client-secret"));
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("Accept"));
    }

    #[test]
    fn redaction_keeps_names_hides_values() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer abc.def.ghi".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let red = redact_headers(&headers);
        assert_eq!(red[0], ("Authorization".to_string(), REDACTED.to_string()));
        assert_eq!(red[1].1, "application/json");
        // the real secret must not appear anywhere
        assert!(!red.iter().any(|(_, v)| v.contains("abc.def.ghi")));
    }
}
