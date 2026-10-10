//! The HTTP request and response model used throughout the scanner.

use serde::{Deserialize, Serialize};

use authz_core::{Fingerprint, HttpMethod, StatusClass};

/// A request the scanner intends to send.
///
/// The request records the id of the test identity it is made *as* (not the credential
/// itself) so that evidence and events can attribute it without storing a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The HTTP method.
    pub method: HttpMethod,
    /// The absolute URL.
    pub url: String,
    /// Request headers as ordered name/value pairs (credentials are attached by the
    /// executor at send time and redacted before capture).
    pub headers: Vec<(String, String)>,
    /// The optional request body.
    pub body: Option<Vec<u8>>,
    /// The test identity this request is made as, if any.
    pub identity_id: Option<String>,
}

impl HttpRequest {
    /// A request with no headers or body.
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        HttpRequest {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            identity_id: None,
        }
    }

    /// Builder: add a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Builder: set a JSON body and the matching content type.
    pub fn json_body(mut self, value: &serde_json::Value) -> Self {
        self.body = Some(value.to_string().into_bytes());
        self.headers
            .push(("Content-Type".into(), "application/json".into()));
        self
    }

    /// Builder: set the identity this request is made as.
    pub fn as_identity(mut self, id: impl Into<String>) -> Self {
        self.identity_id = Some(id.into());
        self
    }

    /// The host portion of the URL, if it parses.
    pub fn host(&self) -> Option<String> {
        self.url
            .parse::<reqwest::Url>()
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
    }
}

/// A response the scanner received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The numeric status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
    /// Wall-clock time the request took, in milliseconds.
    pub elapsed_ms: u64,
}

impl HttpResponse {
    /// Construct a response (elapsed defaults to zero).
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.into(),
            elapsed_ms: 0,
        }
    }

    /// Builder: add a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The coarse status class.
    pub fn status_class(&self) -> StatusClass {
        StatusClass::of(self.status)
    }

    /// The body as UTF-8 text, lossily.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// The body parsed as JSON, if it is valid JSON.
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Whether the body is empty (after trimming ASCII whitespace).
    pub fn is_body_empty(&self) -> bool {
        self.body.iter().all(|b| b.is_ascii_whitespace())
    }

    /// A canonical byte form of the body for stable comparison and fingerprinting.
    ///
    /// If the body is JSON it is re-serialized with object keys sorted, so two responses
    /// that differ only in key order compare equal. Otherwise the raw bytes are returned.
    pub fn canonical_body(&self) -> Vec<u8> {
        match self.json() {
            Some(v) => canonicalize_json(&v).into_bytes(),
            None => self.body.clone(),
        }
    }

    /// A content fingerprint over status and canonical body — the oracle uses this to tell
    /// whether two identities received the *same* object.
    pub fn content_fingerprint(&self) -> Fingerprint {
        Fingerprint::builder()
            .field(&self.status.to_string())
            .field_bytes(&self.canonical_body())
            .finish()
    }
}

/// Serialize a JSON value with object keys sorted recursively.
fn canonicalize_json(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonicalize_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_host_parsing() {
        let r = HttpRequest::new(HttpMethod::Get, "https://api.example.test:8443/orders/1");
        assert_eq!(r.host().as_deref(), Some("api.example.test"));
    }

    #[test]
    fn json_body_sets_content_type() {
        let r = HttpRequest::new(HttpMethod::Post, "https://x/orders")
            .json_body(&json!({"item": "a"}));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert!(r.body.is_some());
    }

    #[test]
    fn canonical_body_is_key_order_independent() {
        let a = HttpResponse::new(200, r#"{"b":2,"a":1}"#);
        let b = HttpResponse::new(200, r#"{"a":1,"b":2}"#);
        assert_eq!(a.canonical_body(), b.canonical_body());
        assert_eq!(a.content_fingerprint(), b.content_fingerprint());
    }

    #[test]
    fn different_content_fingerprints_differ() {
        let a = HttpResponse::new(200, r#"{"id":1}"#);
        let b = HttpResponse::new(200, r#"{"id":2}"#);
        assert_ne!(a.content_fingerprint(), b.content_fingerprint());
    }

    #[test]
    fn status_matched_but_body_differs_is_detected() {
        // Two 200s with different bodies must fingerprint differently — the whole point of
        // comparing content, not status.
        let owner = HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#);
        let attacker = HttpResponse::new(200, r#"{"error":"forbidden"}"#);
        assert_ne!(owner.content_fingerprint(), attacker.content_fingerprint());
    }

    #[test]
    fn empty_body_detection() {
        assert!(HttpResponse::new(204, "").is_body_empty());
        assert!(HttpResponse::new(200, "   \n").is_body_empty());
        assert!(!HttpResponse::new(200, "{}").is_body_empty());
    }

    #[test]
    fn non_json_body_canonicalizes_to_itself() {
        let r = HttpResponse::new(200, "plain text");
        assert_eq!(r.canonical_body(), b"plain text");
    }

    #[test]
    fn nested_json_is_canonicalized() {
        let a = HttpResponse::new(200, r#"{"x":{"c":3,"a":1},"arr":[{"z":1,"y":2}]}"#);
        let b = HttpResponse::new(200, r#"{"arr":[{"y":2,"z":1}],"x":{"a":1,"c":3}}"#);
        assert_eq!(a.canonical_body(), b.canonical_body());
    }
}
