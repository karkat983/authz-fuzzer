//! Error types shared across the core model.

use thiserror::Error;

/// Result alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors that can arise while constructing or validating core domain values.
///
/// These are all *programming* or *input* errors, not I/O failures; the executor layer
/// wraps its own transport errors separately.
#[derive(Debug, Error)]
pub enum CoreError {
    /// An HTTP method string was not one of the recognized verbs.
    #[error("unknown HTTP method: {0:?}")]
    UnknownMethod(String),

    /// A path template could not be normalized (e.g. unbalanced braces).
    #[error("invalid path template {template:?}: {reason}")]
    InvalidPathTemplate {
        /// The offending template as supplied.
        template: String,
        /// Why normalization failed.
        reason: String,
    },

    /// A value expected to be non-empty was empty.
    #[error("{field} must not be empty")]
    Empty {
        /// Name of the field that was empty.
        field: &'static str,
    },

    /// A numeric limit was zero or otherwise out of range.
    #[error("{field} must be greater than zero (was {value})")]
    NonPositive {
        /// Name of the limit.
        field: &'static str,
        /// The invalid value supplied.
        value: i64,
    },

    /// A JSON document could not be parsed.
    #[error("json error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Json(e.to_string())
    }
}
