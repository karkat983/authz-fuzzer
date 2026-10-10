//! OpenAPI 3.x discovery for the AuthZ Fuzzer.
//!
//! Discovery turns an OpenAPI document into an [`registry::OperationRegistry`] of callable
//! [`authz_core::Operation`]s, each with its parameters classified so later phases know
//! which inputs are *object references* (the tampering targets for authorization testing)
//! and which identify an owner.
//!
//! The parser deliberately works over a [`serde_json::Value`] rather than a strict typed
//! model so that it degrades gracefully: unsupported schema features are *reported*
//! (see [`parse::DiscoveryReport`]) rather than causing the whole spec to fail, which
//! matches the discovery spec's requirement that "unsupported schema features are reported
//! explicitly".
//!
//! Only local `$ref`s (`#/components/...`) are resolved; remote refs are reported as
//! unsupported.

pub mod classify;
pub mod parse;
pub mod refs;
pub mod registry;

pub use parse::{discover, discover_str, DiscoveryReport, OpenApiError};
pub use registry::OperationRegistry;
