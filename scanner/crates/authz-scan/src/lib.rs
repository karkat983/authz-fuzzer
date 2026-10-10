//! Scan orchestration.
//!
//! This crate connects the pieces into a working scan. [`fixture::ScanFixtures`] declares
//! the test identities and the resources with known owners; [`plan::plan_probes`] turns
//! fixtures plus a discovered [`authz_openapi::OperationRegistry`] into a deterministic
//! list of [`plan::Probe`]s; and [`runner::ScanRunner`] executes them through a
//! [`authz_http::Transport`] under the [`authz_exec::ScopeGuard`], feeds the observations
//! to the oracle, and collects [`authz_core::Finding`]s.
//!
//! The runner is transport-agnostic, so the whole scan runs against a deterministic mock
//! in tests and against a real service from the CLI with identical logic.

pub mod fixture;
pub mod plan;
pub mod runner;

pub use fixture::{ResourceFixture, ScanFixtures};
pub use plan::{plan_probes, Probe, ProbeKind};
pub use runner::{ScanRunner, ScanSummary};
