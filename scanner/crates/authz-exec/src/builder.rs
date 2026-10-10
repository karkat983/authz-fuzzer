//! Building a concrete [`HttpRequest`] from an operation and bindings.
//!
//! Given a discovered [`authz_core::Operation`], a set of [`Bindings`] (path values, query
//! parameters, optional body), the target base URL, the acting [`authz_core::Identity`]
//! and a [`SecretStore`], this produces the request to send — including attaching the
//! identity's credential according to the operation's declared security scheme.

use std::collections::HashMap;

use thiserror::Error;

use authz_core::{Identity, Operation, ParamLocation, SecurityScheme};
use authz_http::HttpRequest;

use crate::base64;
use crate::secret::SecretStore;

/// Values to substitute into an operation's request.
#[derive(Debug, Default, Clone)]
pub struct Bindings {
    /// Path parameter name -> value.
    pub path: HashMap<String, String>,
    /// Query parameters as ordered pairs.
    pub query: Vec<(String, String)>,
    /// Optional JSON request body.
    pub body: Option<serde_json::Value>,
}

impl Bindings {
    /// An empty binding set.
    pub fn new() -> Self {
        Bindings::default()
    }

    /// Bind one path parameter.
    pub fn path(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.path.insert(name.into(), value.into());
        self
    }

    /// Add a query parameter.
    pub fn query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.push((name.into(), value.into()));
        self
    }

    /// Set the JSON body.
    pub fn body(mut self, value: serde_json::Value) -> Self {
        self.body = Some(value);
        self
    }
}

/// Errors building a request.
#[derive(Debug, Error, PartialEq)]
pub enum BuildError {
    /// A required path parameter had no binding.
    #[error("missing binding for path parameter {0:?}")]
    MissingPathBinding(String),
    /// The acting identity has no resolvable credential.
    #[error("no credential resolved for identity {identity:?} (ref {reference:?})")]
    MissingCredential {
        /// The identity id.
        identity: String,
        /// The credential reference that failed to resolve.
        reference: String,
    },
}

/// Build the request for `op` as `identity`, substituting `bindings`.
pub fn build_request(
    op: &Operation,
    bindings: &Bindings,
    base_url: &str,
    identity: &Identity,
    secrets: &dyn SecretStore,
) -> Result<HttpRequest, BuildError> {
    let path = substitute_path(&op.raw_path, bindings)?;
    let mut url = format!("{}{}", base_url.trim_end_matches('/'), path);
    if !bindings.query.is_empty() {
        let qs: Vec<String> = bindings
            .query
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }

    let mut req = HttpRequest::new(op.key.method, url).as_identity(identity.id.as_str());

    if !identity.is_public {
        req = attach_credential(req, op, identity, secrets)?;
    }

    if let Some(body) = &bindings.body {
        req = req.json_body(body);
    }

    Ok(req)
}

/// Substitute `{name}` segments in a raw path from the bindings, percent-encoding values.
fn substitute_path(raw_path: &str, bindings: &Bindings) -> Result<String, BuildError> {
    let mut out = String::with_capacity(raw_path.len());
    let mut chars = raw_path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for nc in chars.by_ref() {
                if nc == '}' {
                    break;
                }
                name.push(nc);
            }
            let value = bindings
                .path
                .get(&name)
                .ok_or_else(|| BuildError::MissingPathBinding(name.clone()))?;
            out.push_str(&percent_encode(value));
        } else {
            out.push(c);
        }
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    Ok(out)
}

/// Attach the identity's credential per the operation's first usable security scheme.
fn attach_credential(
    req: HttpRequest,
    op: &Operation,
    identity: &Identity,
    secrets: &dyn SecretStore,
) -> Result<HttpRequest, BuildError> {
    let secret = secrets
        .get(&identity.credential_ref)
        .ok_or_else(|| BuildError::MissingCredential {
            identity: identity.id.to_string(),
            reference: identity.credential_ref.clone(),
        })?;

    let scheme = op
        .security
        .iter()
        .find(|s| !matches!(s, SecurityScheme::None))
        .cloned()
        // Default: if the operation declares no concrete scheme but the identity is
        // authenticated, send a bearer token.
        .unwrap_or(SecurityScheme::HttpBearer);

    Ok(match scheme {
        SecurityScheme::HttpBearer | SecurityScheme::OAuth2 => {
            req.header("Authorization", format!("Bearer {secret}"))
        }
        SecurityScheme::HttpBasic => {
            req.header("Authorization", format!("Basic {}", base64::encode(secret.as_bytes())))
        }
        SecurityScheme::ApiKey { name, location } => match location {
            ParamLocation::Header => req.header(name, secret),
            ParamLocation::Cookie => req.header("Cookie", format!("{name}={secret}")),
            // A query API key is appended to the existing query string.
            ParamLocation::Query => {
                let mut r = req;
                let sep = if r.url.contains('?') { '&' } else { '?' };
                r.url = format!("{}{}{}={}", r.url, sep, percent_encode(&name), percent_encode(&secret));
                r
            }
            ParamLocation::Path | ParamLocation::Body => req.header(name, secret),
        },
        SecurityScheme::None => req,
    })
}

/// Percent-encode a string for use in a URL path segment or query value.
///
/// Encodes everything outside the RFC 3986 unreserved set plus a few safe chars, which is
/// conservative but always correct.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{HttpMethod, OperationKey, Operation, ParamLocation, Parameter, ResourceClass, Role};
    use serde_json::json;

    use crate::secret::MapSecretStore;

    fn op(method: HttpMethod, raw_path: &str, security: Vec<SecurityScheme>) -> Operation {
        let key = OperationKey::new(method, raw_path, "1.0").unwrap();
        Operation {
            resource_class: ResourceClass::from_path(&key.normalized_path),
            key,
            raw_path: raw_path.into(),
            operation_id: None,
            parameters: vec![Parameter::new("id", ParamLocation::Path)],
            security,
            ownership: vec![],
            creates_resource: false,
        }
    }

    fn identity() -> Identity {
        Identity::new("alpha-admin", "alpha", Role::Admin, "env:ALPHA")
    }

    fn secrets() -> MapSecretStore {
        MapSecretStore::new().with("env:ALPHA", "tok-123")
    }

    #[test]
    fn builds_url_with_path_binding_and_bearer() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![SecurityScheme::HttpBearer]);
        let b = Bindings::new().path("id", "order-42");
        let req = build_request(&op, &b, "https://api.test/", &identity(), &secrets()).unwrap();
        assert_eq!(req.url, "https://api.test/orders/order-42");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer tok-123"));
        assert_eq!(req.identity_id.as_deref(), Some("alpha-admin"));
    }

    #[test]
    fn missing_path_binding_errors() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![]);
        let err = build_request(&op, &Bindings::new(), "https://api.test", &identity(), &secrets())
            .unwrap_err();
        assert_eq!(err, BuildError::MissingPathBinding("id".into()));
    }

    #[test]
    fn missing_credential_errors() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![SecurityScheme::HttpBearer]);
        let b = Bindings::new().path("id", "1");
        let empty = MapSecretStore::new();
        let err = build_request(&op, &b, "https://api.test", &identity(), &empty).unwrap_err();
        assert!(matches!(err, BuildError::MissingCredential { .. }));
    }

    #[test]
    fn public_identity_gets_no_auth_header() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![SecurityScheme::HttpBearer]);
        let b = Bindings::new().path("id", "1");
        let req = build_request(&op, &b, "https://api.test", &Identity::public(), &secrets()).unwrap();
        assert!(!req.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn basic_auth_is_base64() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![SecurityScheme::HttpBasic]);
        let b = Bindings::new().path("id", "1");
        let secrets = MapSecretStore::new().with("env:ALPHA", "alpha-admin:password");
        let req = build_request(&op, &b, "https://api.test", &identity(), &secrets).unwrap();
        let auth = req.headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Basic YWxwaGEtYWRtaW46cGFzc3dvcmQ=");
    }

    #[test]
    fn api_key_header_and_query() {
        let header_op = op(
            HttpMethod::Get,
            "/orders/{id}",
            vec![SecurityScheme::ApiKey {
                name: "X-Api-Key".into(),
                location: ParamLocation::Header,
            }],
        );
        let b = Bindings::new().path("id", "1");
        let req = build_request(&header_op, &b, "https://api.test", &identity(), &secrets()).unwrap();
        assert!(req.headers.iter().any(|(k, v)| k == "X-Api-Key" && v == "tok-123"));

        let query_op = op(
            HttpMethod::Get,
            "/orders/{id}",
            vec![SecurityScheme::ApiKey {
                name: "api_key".into(),
                location: ParamLocation::Query,
            }],
        );
        let req = build_request(&query_op, &b, "https://api.test", &identity(), &secrets()).unwrap();
        assert!(req.url.contains("api_key=tok-123"));
    }

    #[test]
    fn query_bindings_and_body() {
        let op = op(HttpMethod::Post, "/orders", vec![SecurityScheme::HttpBearer]);
        let b = Bindings::new()
            .query("expand", "items")
            .body(json!({"item": "widget"}));
        let req = build_request(&op, &b, "https://api.test", &identity(), &secrets()).unwrap();
        assert!(req.url.ends_with("/orders?expand=items"));
        assert!(req.body.is_some());
    }

    #[test]
    fn path_values_are_percent_encoded() {
        let op = op(HttpMethod::Get, "/orders/{id}", vec![]);
        let b = Bindings::new().path("id", "a/b 42");
        let req = build_request(&op, &b, "https://api.test", &Identity::public(), &secrets()).unwrap();
        assert_eq!(req.url, "https://api.test/orders/a%2Fb%2042");
    }
}
