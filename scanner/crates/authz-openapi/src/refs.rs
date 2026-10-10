//! Local `$ref` resolution for OpenAPI documents.
//!
//! OpenAPI lets parameters, schemas and security schemes be referenced by JSON pointer,
//! e.g. `{"$ref": "#/components/parameters/OrderId"}`. This module resolves such local
//! pointers against the root document. Remote references (anything not starting with `#/`)
//! are not followed and are surfaced to the caller as unsupported.

use serde_json::Value;

/// The outcome of attempting to resolve a `$ref`.
#[derive(Debug, PartialEq)]
pub enum RefResolution<'a> {
    /// Not a `$ref` object; the original value is returned untouched.
    NotARef(&'a Value),
    /// A local ref that resolved to a value.
    Resolved(&'a Value),
    /// A local ref that pointed at a missing location.
    Dangling(String),
    /// A remote or otherwise unsupported ref.
    Unsupported(String),
}

/// If `value` is a `{"$ref": "..."}` object, resolve it against `root`; otherwise return
/// the value unchanged. Only a single level of indirection is resolved; callers that may
/// encounter chained refs should loop until they get a non-ref.
pub fn resolve<'a>(root: &'a Value, value: &'a Value) -> RefResolution<'a> {
    let Some(ref_str) = value.get("$ref").and_then(Value::as_str) else {
        return RefResolution::NotARef(value);
    };
    // A local ref is `#/<json-pointer>`; the pointer after `#` is passed straight to
    // serde_json, which performs `~1`/`~0` unescaping itself.
    if let Some(pointer) = ref_str.strip_prefix('#') {
        match root.pointer(pointer) {
            Some(v) => RefResolution::Resolved(v),
            None => RefResolution::Dangling(ref_str.to_string()),
        }
    } else {
        RefResolution::Unsupported(ref_str.to_string())
    }
}

/// Follow chained local refs until a concrete value (or a terminal error) is reached.
/// Guards against reference cycles with a fixed depth bound.
pub fn resolve_deep<'a>(root: &'a Value, value: &'a Value) -> RefResolution<'a> {
    let mut current = value;
    for _ in 0..32 {
        match resolve(root, current) {
            RefResolution::Resolved(v) => {
                if v.get("$ref").is_some() {
                    current = v;
                    continue;
                }
                return RefResolution::Resolved(v);
            }
            other => return other,
        }
    }
    RefResolution::Unsupported(format!("ref chain too deep starting at {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> Value {
        json!({
            "components": {
                "parameters": {
                    "OrderId": {"name": "id", "in": "path", "required": true},
                    "AliasId": {"$ref": "#/components/parameters/OrderId"}
                }
            }
        })
    }

    #[test]
    fn plain_value_is_not_a_ref() {
        let r = root();
        let v = json!({"name": "x"});
        assert!(matches!(resolve(&r, &v), RefResolution::NotARef(_)));
    }

    #[test]
    fn local_ref_resolves() {
        let r = root();
        let v = json!({"$ref": "#/components/parameters/OrderId"});
        match resolve(&r, &v) {
            RefResolution::Resolved(target) => assert_eq!(target["name"], "id"),
            other => panic!("expected resolved, got {other:?}"),
        }
    }

    #[test]
    fn chained_refs_resolve_deeply() {
        let r = root();
        let v = json!({"$ref": "#/components/parameters/AliasId"});
        match resolve_deep(&r, &v) {
            RefResolution::Resolved(target) => assert_eq!(target["name"], "id"),
            other => panic!("expected resolved, got {other:?}"),
        }
    }

    #[test]
    fn dangling_ref_is_reported() {
        let r = root();
        let v = json!({"$ref": "#/components/parameters/Missing"});
        assert_eq!(
            resolve(&r, &v),
            RefResolution::Dangling("#/components/parameters/Missing".into())
        );
    }

    #[test]
    fn remote_ref_is_unsupported() {
        let r = root();
        let v = json!({"$ref": "https://example.com/common.yaml#/X"});
        assert!(matches!(resolve(&r, &v), RefResolution::Unsupported(_)));
    }

    #[test]
    fn escaped_pointer_segments() {
        let r = json!({"paths": {"/a/b": {"x": 1}}});
        let v = json!({"$ref": "#/paths/~1a~1b"});
        match resolve(&r, &v) {
            RefResolution::Resolved(target) => assert_eq!(target["x"], 1),
            other => panic!("got {other:?}"),
        }
    }
}
