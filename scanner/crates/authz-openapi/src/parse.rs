//! The OpenAPI discovery walk.
//!
//! [`discover`] reads an OpenAPI 3.x document (as parsed JSON) and produces an
//! [`OperationRegistry`] together with a [`DiscoveryReport`] of everything it could not
//! fully handle. It never panics on malformed input: unsupported features become warnings.

use serde_json::Value;
use thiserror::Error;

use authz_core::{
    HttpMethod, Operation, OperationKey, OwnershipField, ParamLocation, Parameter,
    ResourceClass, SecurityScheme,
};

use crate::classify;
use crate::refs::{resolve_deep, RefResolution};
use crate::registry::OperationRegistry;

/// A fatal error that prevents discovery from producing any operations.
#[derive(Debug, Error, PartialEq)]
pub enum OpenApiError {
    /// The document root was not a JSON object.
    #[error("OpenAPI document must be a JSON object")]
    NotAnObject,
    /// The document had no `paths` object.
    #[error("OpenAPI document has no 'paths' object")]
    NoPaths,
    /// The JSON could not be parsed.
    #[error("invalid JSON: {0}")]
    Json(String),
}

/// Warnings gathered during discovery — spec features that were skipped or approximated.
#[derive(Debug, Default, PartialEq)]
pub struct DiscoveryReport {
    /// Number of operations discovered.
    pub operations: usize,
    /// Human-readable warnings, each tied to a location in the spec.
    pub warnings: Vec<String>,
}

impl DiscoveryReport {
    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Whether discovery hit any unsupported features.
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

const METHODS: [(&str, HttpMethod); 7] = [
    ("get", HttpMethod::Get),
    ("put", HttpMethod::Put),
    ("post", HttpMethod::Post),
    ("delete", HttpMethod::Delete),
    ("options", HttpMethod::Options),
    ("head", HttpMethod::Head),
    ("patch", HttpMethod::Patch),
];

/// Discover operations from an OpenAPI document.
pub fn discover(spec: &Value) -> Result<(OperationRegistry, DiscoveryReport), OpenApiError> {
    let root = spec.as_object().ok_or(OpenApiError::NotAnObject)?;
    let paths = root
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(OpenApiError::NoPaths)?;

    let spec_version = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(Value::as_str)
        .unwrap_or("0")
        .to_string();

    let global_security = root.get("security");
    let scheme_defs = root
        .get("components")
        .and_then(|c| c.get("securitySchemes"));

    let mut registry = OperationRegistry::new();
    let mut report = DiscoveryReport::default();

    for (raw_path, path_item_value) in paths {
        let path_item = match deref(spec, path_item_value, &mut report, raw_path) {
            Some(v) => v,
            None => continue,
        };
        let Some(path_item) = path_item.as_object() else {
            report.warn(format!("path {raw_path:?}: item is not an object"));
            continue;
        };

        // Parameters declared on the path item are shared by all its operations.
        let shared_params = extract_parameters(
            spec,
            path_item.get("parameters"),
            &mut report,
            raw_path,
        );

        for (method_name, method) in METHODS {
            let Some(op_value) = path_item.get(method_name) else {
                continue;
            };
            let Some(op_obj) = op_value.as_object() else {
                report.warn(format!("{} {raw_path}: operation is not an object", method));
                continue;
            };

            let key = match OperationKey::new(method, raw_path, spec_version.clone()) {
                Ok(k) => k,
                Err(e) => {
                    report.warn(format!("{method} {raw_path}: {e}"));
                    continue;
                }
            };

            // Merge path-item params with operation params (op overrides by name+location).
            let mut params = shared_params.clone();
            let op_params =
                extract_parameters(spec, op_obj.get("parameters"), &mut report, raw_path);
            merge_parameters(&mut params, op_params);

            // Body fields become Body-location parameters and feed ownership detection.
            let body_params =
                extract_body_fields(spec, op_obj.get("requestBody"), &mut report, raw_path);
            params.extend(body_params);

            // Synthesize a Path parameter for any `{placeholder}` in the path that the spec
            // did not declare explicitly. Real specs often omit these, but the scanner must
            // still know the path takes an id to bind and tamper with it.
            for name in path_placeholders(raw_path) {
                let declared = params
                    .iter()
                    .any(|p| p.name == name && p.location == ParamLocation::Path);
                if !declared {
                    params.push(Parameter {
                        name,
                        location: ParamLocation::Path,
                        required: true,
                        type_hint: None,
                        is_object_reference: false,
                    });
                }
            }

            // Classify object references on every parameter.
            for p in &mut params {
                p.is_object_reference =
                    classify::looks_like_object_reference(&p.name, p.type_hint.as_deref());
            }

            let ownership = params
                .iter()
                .filter(|p| classify::looks_like_ownership_field(&p.name))
                .map(|p| OwnershipField {
                    field: p.name.clone(),
                    location: p.location,
                })
                .collect();

            let security = resolve_security(
                spec,
                op_obj.get("security").or(global_security),
                scheme_defs,
                &mut report,
                raw_path,
            );

            let resource_class = ResourceClass::from_path(&key.normalized_path);
            let creates_resource = classify::creates_resource(method, &key.normalized_path);

            let operation = Operation {
                key,
                raw_path: raw_path.clone(),
                operation_id: op_obj
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(String::from),
                parameters: params,
                security,
                resource_class,
                ownership,
                creates_resource,
            };
            if operation.operation_id.is_none() {
                report.warn(format!("{} {raw_path}: missing operationId", method));
            }
            registry.insert(operation);
        }
    }

    report.operations = registry.len();
    Ok((registry, report))
}

/// Convenience: parse a JSON string and discover.
pub fn discover_str(json: &str) -> Result<(OperationRegistry, DiscoveryReport), OpenApiError> {
    let spec: Value = serde_json::from_str(json).map_err(|e| OpenApiError::Json(e.to_string()))?;
    discover(&spec)
}

/// Extract the `{placeholder}` names from a raw path template, in order.
fn path_placeholders(raw_path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut chars = raw_path.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for nc in chars.by_ref() {
                if nc == '}' {
                    break;
                }
                name.push(nc);
            }
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    names
}

/// Resolve a possibly-`$ref` value, recording a warning on failure and returning `None`.
fn deref<'a>(
    root: &'a Value,
    value: &'a Value,
    report: &mut DiscoveryReport,
    loc: &str,
) -> Option<&'a Value> {
    match resolve_deep(root, value) {
        RefResolution::NotARef(v) | RefResolution::Resolved(v) => Some(v),
        RefResolution::Dangling(r) => {
            report.warn(format!("{loc}: dangling $ref {r}"));
            None
        }
        RefResolution::Unsupported(r) => {
            report.warn(format!("{loc}: unsupported $ref {r}"));
            None
        }
    }
}

/// Extract an array of parameter objects (resolving refs) into [`Parameter`]s.
fn extract_parameters(
    root: &Value,
    params_value: Option<&Value>,
    report: &mut DiscoveryReport,
    loc: &str,
) -> Vec<Parameter> {
    let Some(arr) = params_value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        let Some(param) = deref(root, item, report, loc) else {
            continue;
        };
        let Some(name) = param.get("name").and_then(Value::as_str) else {
            report.warn(format!("{loc}: parameter without a name"));
            continue;
        };
        let location = match param.get("in").and_then(Value::as_str) {
            Some("path") => ParamLocation::Path,
            Some("query") => ParamLocation::Query,
            Some("header") => ParamLocation::Header,
            Some("cookie") => ParamLocation::Cookie,
            Some(other) => {
                report.warn(format!("{loc}: parameter {name:?} has unsupported location {other:?}"));
                continue;
            }
            None => {
                report.warn(format!("{loc}: parameter {name:?} has no 'in'"));
                continue;
            }
        };
        let required = param
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(location == ParamLocation::Path);
        let type_hint = type_hint_of(root, param.get("schema"), report, loc);
        out.push(Parameter {
            name: name.to_string(),
            location,
            required,
            type_hint,
            is_object_reference: false,
        });
    }
    out
}

/// Merge operation-level parameters over shared ones, replacing by (name, location).
fn merge_parameters(base: &mut Vec<Parameter>, overrides: Vec<Parameter>) {
    for ov in overrides {
        if let Some(existing) = base
            .iter_mut()
            .find(|p| p.name == ov.name && p.location == ov.location)
        {
            *existing = ov;
        } else {
            base.push(ov);
        }
    }
}

/// Pull top-level scalar properties out of a requestBody's JSON schema as Body parameters.
fn extract_body_fields(
    root: &Value,
    request_body: Option<&Value>,
    report: &mut DiscoveryReport,
    loc: &str,
) -> Vec<Parameter> {
    let Some(rb) = request_body else {
        return Vec::new();
    };
    let Some(rb) = deref(root, rb, report, loc) else {
        return Vec::new();
    };
    let Some(content) = rb.get("content").and_then(Value::as_object) else {
        return Vec::new();
    };
    // Prefer application/json; otherwise take the first media type.
    let media = content
        .get("application/json")
        .or_else(|| content.values().next());
    let Some(schema) = media.and_then(|m| m.get("schema")) else {
        return Vec::new();
    };
    let Some(schema) = deref(root, schema, report, loc) else {
        return Vec::new();
    };
    if schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("allOf").is_some()
    {
        report.warn(format!("{loc}: polymorphic request body schema not fully modeled"));
    }
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .map(|(name, prop)| Parameter {
            name: name.clone(),
            location: ParamLocation::Body,
            required: required.contains(&name.as_str()),
            type_hint: type_hint_of(root, Some(prop), report, loc),
            is_object_reference: false,
        })
        .collect()
}

/// A coarse type hint from a schema's `format` (preferred) or `type`.
fn type_hint_of(
    root: &Value,
    schema: Option<&Value>,
    report: &mut DiscoveryReport,
    loc: &str,
) -> Option<String> {
    let schema = deref(root, schema?, report, loc)?;
    schema
        .get("format")
        .and_then(Value::as_str)
        .or_else(|| schema.get("type").and_then(Value::as_str))
        .map(String::from)
}

/// Resolve the security requirement for an operation into concrete [`SecurityScheme`]s.
fn resolve_security(
    root: &Value,
    security: Option<&Value>,
    scheme_defs: Option<&Value>,
    report: &mut DiscoveryReport,
    loc: &str,
) -> Vec<SecurityScheme> {
    let Some(requirements) = security.and_then(Value::as_array) else {
        return vec![SecurityScheme::None];
    };
    if requirements.is_empty() {
        return vec![SecurityScheme::None];
    }
    let mut out = Vec::new();
    for req in requirements {
        let Some(obj) = req.as_object() else { continue };
        if obj.is_empty() {
            out.push(SecurityScheme::None);
            continue;
        }
        for scheme_name in obj.keys() {
            match scheme_defs.and_then(|d| d.get(scheme_name)) {
                Some(def) => out.push(parse_scheme(root, def, report, loc)),
                None => report.warn(format!("{loc}: security scheme {scheme_name:?} not defined")),
            }
        }
    }
    if out.is_empty() {
        out.push(SecurityScheme::None);
    }
    out
}

fn parse_scheme(
    root: &Value,
    def: &Value,
    report: &mut DiscoveryReport,
    loc: &str,
) -> SecurityScheme {
    let def = match deref(root, def, report, loc) {
        Some(d) => d,
        None => return SecurityScheme::None,
    };
    match def.get("type").and_then(Value::as_str) {
        Some("http") => match def.get("scheme").and_then(Value::as_str) {
            Some("bearer") => SecurityScheme::HttpBearer,
            Some("basic") => SecurityScheme::HttpBasic,
            _ => SecurityScheme::HttpBearer,
        },
        Some("apiKey") => {
            let name = def
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Authorization")
                .to_string();
            let location = match def.get("in").and_then(Value::as_str) {
                Some("query") => ParamLocation::Query,
                Some("cookie") => ParamLocation::Cookie,
                _ => ParamLocation::Header,
            };
            SecurityScheme::ApiKey { name, location }
        }
        Some("oauth2") | Some("openIdConnect") => SecurityScheme::OAuth2,
        _ => SecurityScheme::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn petstore_like() -> Value {
        json!({
            "openapi": "3.0.3",
            "info": {"title": "Orders", "version": "2.1.0"},
            "components": {
                "securitySchemes": {
                    "bearer": {"type": "http", "scheme": "bearer"}
                },
                "parameters": {
                    "OrderId": {
                        "name": "orderId", "in": "path", "required": true,
                        "schema": {"type": "string", "format": "uuid"}
                    }
                }
            },
            "security": [{"bearer": []}],
            "paths": {
                "/orders": {
                    "get": {"operationId": "listOrders"},
                    "post": {
                        "operationId": "createOrder",
                        "requestBody": {
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "required": ["item"],
                                "properties": {
                                    "item": {"type": "string"},
                                    "tenantId": {"type": "string"}
                                }
                            }}}
                        }
                    }
                },
                "/orders/{orderId}": {
                    "parameters": [{"$ref": "#/components/parameters/OrderId"}],
                    "get": {"operationId": "getOrder"},
                    "delete": {"operationId": "deleteOrder"}
                }
            }
        })
    }

    #[test]
    fn discovers_all_operations() {
        let (reg, report) = discover(&petstore_like()).unwrap();
        assert_eq!(reg.len(), 4);
        assert_eq!(report.operations, 4);
        let paths = reg.paths();
        assert!(paths.contains(&"/orders".to_string()));
        assert!(paths.contains(&"/orders/{}".to_string()));
    }

    #[test]
    fn path_param_is_classified_as_object_reference() {
        let (reg, _) = discover(&petstore_like()).unwrap();
        let get = reg
            .get(&OperationKey::new(HttpMethod::Get, "/orders/{orderId}", "2.1.0").unwrap())
            .unwrap();
        let id = get.parameters.iter().find(|p| p.name == "orderId").unwrap();
        assert!(id.is_object_reference);
        assert_eq!(id.location, ParamLocation::Path);
        assert_eq!(id.type_hint.as_deref(), Some("uuid"));
    }

    #[test]
    fn body_ownership_field_is_detected() {
        let (reg, _) = discover(&petstore_like()).unwrap();
        let post = reg
            .get(&OperationKey::new(HttpMethod::Post, "/orders", "2.1.0").unwrap())
            .unwrap();
        assert!(post.creates_resource);
        assert!(post.ownership.iter().any(|o| o.field == "tenantId"));
        // the body field is present as a Body-location parameter
        assert!(post
            .parameters
            .iter()
            .any(|p| p.name == "tenantId" && p.location == ParamLocation::Body));
    }

    #[test]
    fn security_is_resolved_from_components() {
        let (reg, _) = discover(&petstore_like()).unwrap();
        let get = reg
            .get(&OperationKey::new(HttpMethod::Get, "/orders", "2.1.0").unwrap())
            .unwrap();
        assert_eq!(get.security, vec![SecurityScheme::HttpBearer]);
    }

    #[test]
    fn shared_path_parameters_apply_to_each_method() {
        let (reg, _) = discover(&petstore_like()).unwrap();
        for method in [HttpMethod::Get, HttpMethod::Delete] {
            let op = reg
                .get(&OperationKey::new(method, "/orders/{orderId}", "2.1.0").unwrap())
                .unwrap();
            assert!(op.parameters.iter().any(|p| p.name == "orderId"));
        }
    }

    #[test]
    fn missing_operation_id_is_warned() {
        let spec = json!({
            "info": {"version": "1.0"},
            "paths": {"/x": {"get": {}}}
        });
        let (_reg, report) = discover(&spec).unwrap();
        assert!(report.warnings.iter().any(|w| w.contains("missing operationId")));
    }

    #[test]
    fn non_object_root_is_an_error() {
        assert_eq!(discover(&json!([])).unwrap_err(), OpenApiError::NotAnObject);
    }

    #[test]
    fn no_paths_is_an_error() {
        assert_eq!(
            discover(&json!({"info": {"version": "1"}})).unwrap_err(),
            OpenApiError::NoPaths
        );
    }

    #[test]
    fn unsupported_param_location_is_reported_not_fatal() {
        let spec = json!({
            "info": {"version": "1.0"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{"name": "weird", "in": "matrix"}]
            }}}
        });
        let (reg, report) = discover(&spec).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(report.warnings.iter().any(|w| w.contains("unsupported location")));
    }

    #[test]
    fn discover_str_parses_json() {
        let (reg, _) = discover_str(r#"{"info":{"version":"1"},"paths":{"/h":{"get":{"operationId":"h"}}}}"#).unwrap();
        assert_eq!(reg.len(), 1);
    }
}
