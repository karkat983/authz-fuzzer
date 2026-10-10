//! Core domain model for the AuthZ Fuzzer.
//!
//! This crate defines the types every other crate shares: HTTP primitives, the
//! [`operation`] registry model that discovery populates, the [`identity`] matrix the
//! oracles compare across, the [`scope`] that bounds what an authorized scan may touch,
//! and the [`finding`] and [`event`] records the scanner emits.
//!
//! The design goal is to make illegal states hard to represent. A finding, for example,
//! cannot be constructed as "verified" without an oracle and an observed effect
//! (see [`finding::Finding`]); a status code alone can never imply a vulnerability.
//!
//! Nothing in this crate performs I/O. It is pure data and logic, so it is cheap to test
//! exhaustively and safe to reuse from the executor, the report generator and the CLI.

pub mod error;
pub mod fingerprint;
pub mod http;
pub mod identity;
pub mod event;
pub mod finding;
pub mod operation;
pub mod scope;

pub use error::{CoreError, Result};
pub use fingerprint::Fingerprint;
pub use http::{HttpMethod, StatusClass};
pub use identity::{Identity, IdentityId, IdentityRelation, Role};
pub use operation::{
    Operation, OperationKey, OwnershipField, Parameter, ParamLocation, ResourceClass, SecurityScheme,
};
pub use scope::{MutationPolicy, Scope, ScopeError, TargetRef};
pub use finding::{Confidence, Finding, FindingId, Severity, ViolationType};
pub use event::{Actor, ActorKind, Event, EventOutcome, Provenance};

/// The schema version this build of the core model speaks.
///
/// Persisted records (events, findings) carry this so a later reader can detect and
/// migrate older data rather than silently misinterpret it.
pub const SCHEMA_VERSION: &str = "1.0";
