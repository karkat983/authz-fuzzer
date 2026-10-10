//! The scoped execution engine.
//!
//! Everything that turns a plan into controlled network traffic lives here. The design
//! centre is [`guard::ScopeGuard`]: before any request is sent it must pass the guard,
//! which checks the [`authz_core::Scope`] (host, method, mutation), the request budget,
//! and the kill switch — all three fail closed. On top of that the engine provides a
//! [`ratelimit::TokenBucket`] and a bounded-concurrency [`pool::WorkerPool`] so an
//! authorized scan stays within its declared operational limits, a [`cleanup::CleanupJournal`]
//! so any test resource the scan creates can be removed afterwards, and a
//! [`builder`] that constructs requests from operations, parameter bindings and resolved
//! credentials.

pub mod base64;
pub mod budget;
pub mod builder;
pub mod cleanup;
pub mod guard;
pub mod killswitch;
pub mod pool;
pub mod ratelimit;
pub mod secret;

pub use budget::RequestBudget;
pub use builder::{build_request, BuildError, Bindings};
pub use cleanup::{CleanupJournal, CreatedResource};
pub use guard::{GuardError, ScopeGuard};
pub use killswitch::KillSwitch;
pub use pool::WorkerPool;
pub use ratelimit::TokenBucket;
pub use secret::{EnvSecretStore, MapSecretStore, SecretStore};
