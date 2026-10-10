//! The operation model populated by discovery.
//!
//! An [`Operation`] is one callable API endpoint: a method, a path template, its
//! parameters, its declared security, and — crucially for authorization testing — which
//! of its inputs identify an *object* (an id a caller might tamper with) and which
//! identify the *owner* of that object.
//!
//! Operations are keyed by [`OperationKey`] = method + normalized path template + spec
//! version. Normalizing the path (replacing each `{param}` with a positional `{}`) means
//! two specs that describe the same route with differently named path parameters collapse
//! to the same key, which keeps finding fingerprints stable across spec revisions.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::http::HttpMethod;

/// Where a parameter is carried in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamLocation {
    /// A `{placeholder}` segment of the path. These are the primary BOLA tampering targets.
    Path,
    /// A `?name=value` query parameter.
    Query,
    /// An HTTP header.
    Header,
    /// A cookie.
    Cookie,
    /// A field inside the request body.
    Body,
}

/// A single declared parameter of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// The parameter name as written in the spec.
    pub name: String,
    /// Where it travels.
    pub location: ParamLocation,
    /// Whether the spec marks it required.
    pub required: bool,
    /// A coarse type hint ("string", "integer", ...) when the spec gives one.
    pub type_hint: Option<String>,
    /// True when the classifier believes this parameter names an object instance
    /// (e.g. `id`, `orderId`, a UUID-typed path segment) — i.e. a tampering target.
    pub is_object_reference: bool,
}

impl Parameter {
    /// Construct a minimal parameter.
    pub fn new(name: impl Into<String>, location: ParamLocation) -> Self {
        Parameter {
            name: name.into(),
            location,
            required: location == ParamLocation::Path,
            type_hint: None,
            is_object_reference: false,
        }
    }

    /// Builder-style setter for the type hint.
    pub fn with_type(mut self, t: impl Into<String>) -> Self {
        self.type_hint = Some(t.into());
        self
    }

    /// Builder-style setter marking this an object reference.
    pub fn object_reference(mut self) -> Self {
        self.is_object_reference = true;
        self
    }
}

/// How an operation authenticates, as declared by the spec's security schemes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SecurityScheme {
    /// HTTP bearer token (`Authorization: Bearer ...`).
    HttpBearer,
    /// HTTP basic auth.
    HttpBasic,
    /// An API key carried in a named header, query or cookie.
    ApiKey {
        /// The parameter name carrying the key.
        name: String,
        /// Where it travels.
        location: ParamLocation,
    },
    /// OAuth2 / OpenID Connect flows (treated opaquely; the executor supplies tokens).
    OAuth2,
    /// No authentication declared.
    None,
}

/// A coarse class of the resource an operation acts on, derived from the collection
/// segment of its path (e.g. `/orders/{id}` -> `order`).
///
/// Resource class is part of a finding's fingerprint, so a cross-tenant read of any order
/// dedupes to one finding rather than one per order id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceClass(pub String);

impl ResourceClass {
    /// Best-effort resource class from a normalized path, using the last collection
    /// segment before a trailing id placeholder, singularized naively.
    ///
    /// `/api/v1/orders/{}` -> `order`; `/users/{}/addresses/{}` -> `address`.
    pub fn from_path(path: &str) -> ResourceClass {
        let segments: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty() && *s != "{}")
            .collect();
        let name = segments
            .iter()
            .rev()
            .find(|s| !is_version_segment(s))
            .map(|s| singularize(s))
            .unwrap_or_else(|| "resource".to_string());
        ResourceClass(name)
    }
}

/// Which parameter carries the identity of the object's owner, if the spec or a fixture
/// tells us. Discovery marks these so the oracle can tell a cross-owner access from a
/// same-owner one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipField {
    /// The parameter or body field naming the owner (e.g. `tenantId`, `userId`).
    pub field: String,
    /// Where it is found.
    pub location: ParamLocation,
}

/// The stable identity of an operation: method, normalized path, spec version.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationKey {
    /// The HTTP method.
    pub method: HttpMethod,
    /// The path with every `{param}` replaced by `{}`.
    pub normalized_path: String,
    /// The version of the spec the operation was discovered from.
    pub spec_version: String,
}

impl OperationKey {
    /// Build a key, normalizing the supplied path template.
    pub fn new(
        method: HttpMethod,
        path_template: &str,
        spec_version: impl Into<String>,
    ) -> Result<Self, CoreError> {
        Ok(OperationKey {
            method,
            normalized_path: normalize_path(path_template)?,
            spec_version: spec_version.into(),
        })
    }

    /// A compact string form, e.g. `GET /orders/{}@1.0`.
    pub fn display(&self) -> String {
        format!(
            "{} {}@{}",
            self.method, self.normalized_path, self.spec_version
        )
    }
}

/// A discovered, callable operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Its stable key.
    pub key: OperationKey,
    /// The original path template as written in the spec (param names preserved).
    pub raw_path: String,
    /// The spec's operationId, if any.
    pub operation_id: Option<String>,
    /// Declared parameters.
    pub parameters: Vec<Parameter>,
    /// The security schemes that apply.
    pub security: Vec<SecurityScheme>,
    /// The resource class this operation acts on.
    pub resource_class: ResourceClass,
    /// Ownership fields, if known.
    pub ownership: Vec<OwnershipField>,
    /// True if this operation creates a resource (useful to seed owned fixtures).
    pub creates_resource: bool,
}

impl Operation {
    /// The object-reference parameters — the tampering targets for authorization testing.
    pub fn object_references(&self) -> impl Iterator<Item = &Parameter> {
        self.parameters.iter().filter(|p| p.is_object_reference)
    }

    /// Whether this operation reads only (safe method and not a resource creator).
    pub fn is_read_only(&self) -> bool {
        self.key.method.is_safe() && !self.creates_resource
    }

    /// Path parameter names, in path order.
    pub fn path_param_names(&self) -> Vec<&str> {
        self.parameters
            .iter()
            .filter(|p| p.location == ParamLocation::Path)
            .map(|p| p.name.as_str())
            .collect()
    }
}

/// Replace each `{param}` in a path template with a positional `{}`, validating braces.
///
/// A leading slash is enforced; a trailing slash (other than the root) is stripped so
/// `/orders/` and `/orders` are the same operation.
pub fn normalize_path(template: &str) -> Result<String, CoreError> {
    let invalid = |reason: &str| CoreError::InvalidPathTemplate {
        template: template.to_string(),
        reason: reason.to_string(),
    };

    let mut out = String::with_capacity(template.len());
    let mut depth = 0u32;
    for ch in template.chars() {
        match ch {
            '{' => {
                if depth > 0 {
                    return Err(invalid("nested '{'"));
                }
                depth += 1;
                out.push_str("{}");
            }
            '}' => {
                if depth == 0 {
                    return Err(invalid("unmatched '}'"));
                }
                depth -= 1;
            }
            _ if depth > 0 => { /* drop the parameter name */ }
            c => out.push(c),
        }
    }
    if depth != 0 {
        return Err(invalid("unterminated '{'"));
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    // Collapse any accidental double slashes.
    while out.contains("//") {
        out = out.replace("//", "/");
    }
    Ok(out)
}

fn is_version_segment(s: &str) -> bool {
    let s = s.trim_start_matches('v');
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Naive English singularization sufficient for resource-class labels.
fn singularize(word: &str) -> String {
    let w = word.to_ascii_lowercase();
    if let Some(stem) = w.strip_suffix("ies") {
        format!("{stem}y")
    } else if w.ends_with("ses") || w.ends_with("xes") || w.ends_with("ches") || w.ends_with("shes")
    {
        w[..w.len() - 2].to_string()
    } else if w.ends_with('s') && !w.ends_with("ss") {
        w[..w.len() - 1].to_string()
    } else {
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_replaces_params_positionally() {
        assert_eq!(normalize_path("/orders/{id}").unwrap(), "/orders/{}");
        assert_eq!(
            normalize_path("/users/{userId}/addresses/{addressId}").unwrap(),
            "/users/{}/addresses/{}"
        );
    }

    #[test]
    fn differently_named_params_normalize_equal() {
        assert_eq!(
            normalize_path("/orders/{id}").unwrap(),
            normalize_path("/orders/{orderId}").unwrap()
        );
    }

    #[test]
    fn normalize_enforces_leading_and_strips_trailing_slash() {
        assert_eq!(normalize_path("orders").unwrap(), "/orders");
        assert_eq!(normalize_path("/orders/").unwrap(), "/orders");
        assert_eq!(normalize_path("/").unwrap(), "/");
    }

    #[test]
    fn normalize_rejects_unbalanced_braces() {
        assert!(normalize_path("/a/{b").is_err());
        assert!(normalize_path("/a/b}").is_err());
        assert!(normalize_path("/a/{{b}}").is_err());
    }

    #[test]
    fn operation_key_display() {
        let k = OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap();
        assert_eq!(k.display(), "GET /orders/{}@1.0");
    }

    #[test]
    fn resource_class_from_path() {
        assert_eq!(ResourceClass::from_path("/orders/{}").0, "order");
        assert_eq!(ResourceClass::from_path("/api/v1/orders/{}").0, "order");
        assert_eq!(
            ResourceClass::from_path("/users/{}/addresses/{}").0,
            "address"
        );
        assert_eq!(ResourceClass::from_path("/companies/{}").0, "company");
    }

    #[test]
    fn singularize_handles_common_plurals() {
        assert_eq!(singularize("orders"), "order");
        assert_eq!(singularize("companies"), "company");
        assert_eq!(singularize("addresses"), "address");
        assert_eq!(singularize("boxes"), "box");
        // A word that is not a plural is left unchanged (ignoring the naive "ss" guard).
        assert_eq!(singularize("class"), "class");
    }

    #[test]
    fn object_reference_filter() {
        let op = Operation {
            key: OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            raw_path: "/orders/{id}".into(),
            operation_id: Some("getOrder".into()),
            parameters: vec![
                Parameter::new("id", ParamLocation::Path).object_reference(),
                Parameter::new("verbose", ParamLocation::Query),
            ],
            security: vec![SecurityScheme::HttpBearer],
            resource_class: ResourceClass("order".into()),
            ownership: vec![],
            creates_resource: false,
        };
        let refs: Vec<_> = op.object_references().map(|p| p.name.as_str()).collect();
        assert_eq!(refs, vec!["id"]);
        assert!(op.is_read_only());
        assert_eq!(op.path_param_names(), vec!["id"]);
    }
}
