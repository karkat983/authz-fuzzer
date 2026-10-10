//! HTTP primitives: methods and a status-code classification used by the oracles.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// The HTTP methods the scanner understands.
///
/// Methods are split into *safe* (read-only) and *unsafe* (state-changing). The executor
/// refuses unsafe methods unless the scan scope explicitly permits mutation, and the
/// oracle verifies state differently for the two classes (see the oracle crate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// Retrieve a resource. Safe.
    Get,
    /// Retrieve headers only. Safe.
    Head,
    /// Describe communication options. Safe.
    Options,
    /// Create or replace a resource. Unsafe.
    Put,
    /// Create a subordinate resource. Unsafe.
    Post,
    /// Partially modify a resource. Unsafe.
    Patch,
    /// Remove a resource. Unsafe.
    Delete,
}

impl HttpMethod {
    /// All methods, in a stable order.
    pub const ALL: [HttpMethod; 7] = [
        HttpMethod::Get,
        HttpMethod::Head,
        HttpMethod::Options,
        HttpMethod::Put,
        HttpMethod::Post,
        HttpMethod::Patch,
        HttpMethod::Delete,
    ];

    /// Whether the method is read-only (cannot change server state when well-behaved).
    pub fn is_safe(self) -> bool {
        matches!(
            self,
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
        )
    }

    /// Whether the method may change server state and therefore needs mutation permission.
    pub fn is_mutating(self) -> bool {
        !self.is_safe()
    }

    /// The canonical uppercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Put => "PUT",
            HttpMethod::Post => "POST",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PUT" => Ok(HttpMethod::Put),
            "POST" => Ok(HttpMethod::Post),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            other => Err(CoreError::UnknownMethod(other.to_string())),
        }
    }
}

/// A coarse classification of an HTTP status code.
///
/// The oracle logic reasons in terms of these classes rather than raw numbers, but the
/// raw code is always preserved on the response for evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusClass {
    /// 1xx informational.
    Informational,
    /// 2xx success. **Never** sufficient on its own to prove unauthorized access.
    Success,
    /// 3xx redirection.
    Redirect,
    /// 401/403: explicit authorization denial.
    Denied,
    /// 404: not found. May be a genuine miss or a deliberate camouflage of a denial.
    NotFound,
    /// Other 4xx client errors (400, 405, 409, 422, 429, ...).
    ClientError,
    /// 5xx server errors.
    ServerError,
    /// A code outside 100..=599.
    Unknown,
}

impl StatusClass {
    /// Classify a raw status code.
    pub fn of(code: u16) -> StatusClass {
        match code {
            100..=199 => StatusClass::Informational,
            200..=299 => StatusClass::Success,
            300..=399 => StatusClass::Redirect,
            401 | 403 => StatusClass::Denied,
            404 => StatusClass::NotFound,
            400 | 402 | 405..=499 => StatusClass::ClientError,
            500..=599 => StatusClass::ServerError,
            _ => StatusClass::Unknown,
        }
    }

    /// Whether this class is a 2xx success.
    pub fn is_success(self) -> bool {
        matches!(self, StatusClass::Success)
    }

    /// Whether this class represents an explicit denial (401/403).
    ///
    /// Note 404 is deliberately *not* a denial here: whether a 404 means "does not exist"
    /// or "exists but hidden from you" is exactly what the oracle must disambiguate, so it
    /// is kept separate.
    pub fn is_explicit_denial(self) -> bool {
        matches!(self, StatusClass::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_parse_is_case_insensitive_and_trims() {
        assert_eq!("  get ".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("DELETE".parse::<HttpMethod>().unwrap(), HttpMethod::Delete);
        assert!("TRACE".parse::<HttpMethod>().is_err());
    }

    #[test]
    fn safe_and_mutating_partition_all_methods() {
        for m in HttpMethod::ALL {
            assert_ne!(m.is_safe(), m.is_mutating());
        }
        assert!(HttpMethod::Get.is_safe());
        assert!(HttpMethod::Patch.is_mutating());
    }

    #[test]
    fn status_classification() {
        assert_eq!(StatusClass::of(200), StatusClass::Success);
        assert_eq!(StatusClass::of(204), StatusClass::Success);
        assert_eq!(StatusClass::of(401), StatusClass::Denied);
        assert_eq!(StatusClass::of(403), StatusClass::Denied);
        assert_eq!(StatusClass::of(404), StatusClass::NotFound);
        assert_eq!(StatusClass::of(400), StatusClass::ClientError);
        assert_eq!(StatusClass::of(429), StatusClass::ClientError);
        assert_eq!(StatusClass::of(500), StatusClass::ServerError);
        assert_eq!(StatusClass::of(999), StatusClass::Unknown);
    }

    #[test]
    fn not_found_is_not_counted_as_an_explicit_denial() {
        assert!(!StatusClass::NotFound.is_explicit_denial());
        assert!(StatusClass::Denied.is_explicit_denial());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for m in HttpMethod::ALL {
            assert_eq!(m.to_string().parse::<HttpMethod>().unwrap(), m);
        }
    }

    #[test]
    fn serde_uses_uppercase() {
        let j = serde_json::to_string(&HttpMethod::Post).unwrap();
        assert_eq!(j, "\"POST\"");
    }
}
