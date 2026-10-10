//! Library surface of the `authz` CLI, so the manifest, event and run logic can be tested
//! independently of the binary.

pub mod events;
pub mod manifest;
pub mod run;

pub use manifest::{Manifest, ManifestError};
pub use run::{discover_only, plan_only, run_scan, RunError, ScanResults};
