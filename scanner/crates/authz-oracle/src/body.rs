//! Response-body analysis used by the oracles.
//!
//! These helpers exist to avoid the classic false positive: an API that returns HTTP 200
//! with an error envelope (`{"error": "forbidden"}`) has *denied* the request even though
//! the status is 2xx. The oracle must not treat that as disclosure.

use authz_http::HttpResponse;

/// Whether a 2xx JSON body looks like a soft error/denial envelope rather than real data.
///
/// Heuristic: the body is a JSON object whose keys are dominated by error-signalling names
/// (`error`, `message`, `code`, `status`, `detail`, `title`) and that carries no obvious
/// data payload. Bodies that are plain data objects or arrays are not error envelopes.
pub fn is_error_envelope(resp: &HttpResponse) -> bool {
    let Some(value) = resp.json() else {
        // A non-JSON 2xx body: treat a short body containing "forbidden"/"denied"/"error"
        // as a soft denial, otherwise as data.
        let text = resp.text().to_ascii_lowercase();
        return text.len() < 200
            && (text.contains("forbidden")
                || text.contains("unauthorized")
                || text.contains("access denied")
                || text.contains("permission"));
    };
    let serde_json::Value::Object(map) = value else {
        // Arrays and scalars are data, not error envelopes.
        return false;
    };
    if map.is_empty() {
        return false;
    }
    const ERROR_KEYS: [&str; 7] = [
        "error", "errors", "message", "code", "status", "detail", "title",
    ];
    const DATA_HINTS: [&str; 6] = ["id", "data", "items", "result", "results", "name"];
    let has_error_key = map.keys().any(|k| {
        let k = k.to_ascii_lowercase();
        ERROR_KEYS.contains(&k.as_str())
    });
    let has_data_key = map.keys().any(|k| {
        let k = k.to_ascii_lowercase();
        DATA_HINTS.contains(&k.as_str())
    });
    // An error key and no data key, or an explicit error-ish single-field object.
    has_error_key && !has_data_key
}

/// Whether two responses disclose the *same* object content (identical canonical body and
/// a non-empty payload). This is the strong signal for a read disclosure.
pub fn same_object(a: &HttpResponse, b: &HttpResponse) -> bool {
    !a.is_body_empty() && a.canonical_body() == b.canonical_body()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelopes_are_recognized() {
        assert!(is_error_envelope(&HttpResponse::new(200, r#"{"error":"forbidden"}"#)));
        assert!(is_error_envelope(&HttpResponse::new(
            200,
            r#"{"message":"access denied","code":403}"#
        )));
        assert!(is_error_envelope(&HttpResponse::new(403, "Access denied")));
    }

    #[test]
    fn real_data_is_not_an_error_envelope() {
        assert!(!is_error_envelope(&HttpResponse::new(
            200,
            r#"{"id":"order-1","total":42}"#
        )));
        assert!(!is_error_envelope(&HttpResponse::new(200, r#"[1,2,3]"#)));
        // a status field alongside data is still data
        assert!(!is_error_envelope(&HttpResponse::new(
            200,
            r#"{"id":1,"status":"shipped"}"#
        )));
        assert!(!is_error_envelope(&HttpResponse::new(200, "{}")));
    }

    #[test]
    fn same_object_requires_nonempty_identical_body() {
        let a = HttpResponse::new(200, r#"{"id":1}"#);
        let b = HttpResponse::new(200, r#"{"id":1}"#);
        let c = HttpResponse::new(200, r#"{"id":2}"#);
        let empty = HttpResponse::new(200, "");
        assert!(same_object(&a, &b));
        assert!(!same_object(&a, &c));
        assert!(!same_object(&empty, &empty));
    }
}
