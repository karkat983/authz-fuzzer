//! Finding post-processing: deduplication, suppression, gating and export.
//!
//! A scan emits one [`authz_core::Finding`] per confirmed probe, but the same authorization
//! weakness can surface from several probes (different resource ids, repeated runs). This
//! crate collapses them by fingerprint into a [`FindingSet`], applies a [`suppress::SuppressionList`]
//! of accepted findings, decides a CI [`gate::GateOutcome`], and exports the result as JSON
//! or [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for code-scanning tools.

pub mod dedup;
pub mod gate;
pub mod report;
pub mod sarif;
pub mod suppress;

pub use dedup::FindingSet;
pub use gate::{gate, GateOutcome, GatePolicy};
pub use report::FindingsReport;
pub use sarif::to_sarif;
pub use suppress::{Suppression, SuppressionList};
