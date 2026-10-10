//! Heuristic classification of parameters and operations.
//!
//! Discovery cannot know for certain which inputs are object ids or owner references —
//! that is ultimately confirmed by fixtures — but good heuristics focus the scan on the
//! parameters most likely to be authorization-relevant. These functions are deliberately
//! conservative and well-tested, because a missed object reference means a missed test.

/// Whether a parameter name looks like it identifies an object instance.
///
/// Matches `id`, `uuid`, names ending in `Id`/`_id`/`-id`, and names containing `ref`/
/// `key` used as identifiers. Case-insensitive.
pub fn looks_like_object_reference(name: &str, type_hint: Option<&str>) -> bool {
    let lower = name.to_ascii_lowercase();
    let by_name = lower == "id"
        || lower == "uuid"
        || lower == "guid"
        || lower.ends_with("id")
        || lower.ends_with("_id")
        || lower.ends_with("-id")
        || lower.ends_with("uuid")
        || lower.ends_with("ref")
        || lower.ends_with("key")
        || lower.ends_with("number")
        || lower.ends_with("code");
    let by_type = matches!(
        type_hint.map(str::to_ascii_lowercase).as_deref(),
        Some("uuid") | Some("guid")
    );
    by_name || by_type
}

/// Whether a field name identifies the *owner* of a resource (tenant, user, account, org).
///
/// These are the fields the oracle uses to decide whether a request is same-owner or
/// cross-owner, and the fields a BOLA attack tries to override in a request body.
pub fn looks_like_ownership_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace(['_', '-'], "");
    const OWNER_WORDS: [&str; 8] = [
        "tenantid", "userid", "ownerid", "accountid", "orgid", "organizationid",
        "customerid", "companyid",
    ];
    if OWNER_WORDS.contains(&lower.as_str()) {
        return true;
    }
    // Also accept the bare owner nouns when used as a scoping field.
    matches!(lower.as_str(), "tenant" | "owner" | "account" | "org")
}

/// Whether an operation on `normalized_path` with the given HTTP method creates a resource.
///
/// Heuristic: a `POST` to a *collection* path (one that does not end in an id placeholder)
/// creates a resource; a `PUT` to an *instance* path (ending in `{}`) may create-or-replace
/// and is treated as a creator too, because the scan can use it to seed owned fixtures.
pub fn creates_resource(method: authz_core::HttpMethod, normalized_path: &str) -> bool {
    use authz_core::HttpMethod::*;
    let ends_in_id = normalized_path.ends_with("/{}");
    match method {
        Post => !ends_in_id,
        Put => ends_in_id,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::HttpMethod;

    #[test]
    fn object_reference_names() {
        assert!(looks_like_object_reference("id", None));
        assert!(looks_like_object_reference("orderId", None));
        assert!(looks_like_object_reference("order_id", None));
        assert!(looks_like_object_reference("accountNumber", None));
        assert!(looks_like_object_reference("x", Some("uuid")));
        assert!(!looks_like_object_reference("verbose", None));
        assert!(!looks_like_object_reference("limit", None));
        assert!(!looks_like_object_reference("name", Some("string")));
    }

    #[test]
    fn ownership_fields() {
        assert!(looks_like_ownership_field("tenantId"));
        assert!(looks_like_ownership_field("tenant_id"));
        assert!(looks_like_ownership_field("ownerId"));
        assert!(looks_like_ownership_field("organization_id"));
        assert!(looks_like_ownership_field("tenant"));
        assert!(!looks_like_ownership_field("id"));
        assert!(!looks_like_ownership_field("name"));
    }

    #[test]
    fn resource_creation_heuristic() {
        assert!(creates_resource(HttpMethod::Post, "/orders"));
        assert!(!creates_resource(HttpMethod::Post, "/orders/{}"));
        assert!(creates_resource(HttpMethod::Put, "/orders/{}"));
        assert!(!creates_resource(HttpMethod::Put, "/orders"));
        assert!(!creates_resource(HttpMethod::Get, "/orders"));
        assert!(!creates_resource(HttpMethod::Delete, "/orders/{}"));
    }
}
