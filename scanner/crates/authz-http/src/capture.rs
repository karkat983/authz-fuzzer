//! Evidence captures.
//!
//! A [`Capture`] is a request/response pair recorded for a finding's replay bundle. It
//! stores *redacted* headers only, and exposes a content-addressed evidence reference so
//! the finding can point at it without embedding the bytes or any secret.

use serde::{Deserialize, Serialize};

use authz_core::Fingerprint;

use crate::redact::redact_headers;
use crate::request::{HttpRequest, HttpResponse};

/// A recorded request/response exchange, safe to persist as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capture {
    /// The request, with sensitive headers redacted and body preserved.
    pub request: HttpRequest,
    /// The response, with sensitive headers redacted.
    pub response: HttpResponse,
}

impl Capture {
    /// Build a capture from a raw request/response, redacting sensitive headers on both.
    pub fn record(request: &HttpRequest, response: &HttpResponse) -> Self {
        let mut req = request.clone();
        req.headers = redact_headers(&req.headers);
        let mut resp = response.clone();
        resp.headers = redact_headers(&resp.headers);
        Capture {
            request: req,
            response: resp,
        }
    }

    /// A content fingerprint over the whole exchange, used as its evidence id.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::builder()
            .field("authz-capture-v1")
            .field(self.request.method.as_str())
            .field(&self.request.url)
            .field_opt(self.request.identity_id.as_deref())
            .field_bytes(self.request.body.as_deref().unwrap_or(&[]))
            .field(&self.response.status.to_string())
            .field_bytes(&self.response.canonical_body())
            .finish()
    }

    /// The content-addressed evidence URI for this capture.
    pub fn evidence_uri(&self) -> String {
        self.fingerprint().evidence_uri()
    }

    /// Serialize the capture to pretty JSON for storage in the evidence blob store.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("capture serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::HttpMethod;

    #[test]
    fn capture_redacts_request_and_response_headers() {
        let req = HttpRequest::new(HttpMethod::Get, "https://x/orders/1")
            .header("Authorization", "Bearer secret-token")
            .as_identity("alpha-admin");
        let resp = HttpResponse::new(200, r#"{"id":1}"#).header("Set-Cookie", "session=abc");
        let cap = Capture::record(&req, &resp);
        let json = cap.to_json();
        assert!(!json.contains("secret-token"));
        assert!(!json.contains("session=abc"));
        assert!(json.contains("alpha-admin")); // identity id is not a secret
    }

    #[test]
    fn evidence_uri_is_content_addressed_and_stable() {
        let req = HttpRequest::new(HttpMethod::Get, "https://x/orders/1");
        let resp = HttpResponse::new(200, r#"{"a":1,"b":2}"#);
        let resp2 = HttpResponse::new(200, r#"{"b":2,"a":1}"#);
        let a = Capture::record(&req, &resp);
        let b = Capture::record(&req, &resp2);
        assert_eq!(a.evidence_uri(), b.evidence_uri());
        assert!(a.evidence_uri().starts_with("evidence://sha256/"));
    }

    #[test]
    fn different_identities_capture_differently() {
        let resp = HttpResponse::new(200, "{}");
        let a = Capture::record(
            &HttpRequest::new(HttpMethod::Get, "https://x/1").as_identity("a"),
            &resp,
        );
        let b = Capture::record(
            &HttpRequest::new(HttpMethod::Get, "https://x/1").as_identity("b"),
            &resp,
        );
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
