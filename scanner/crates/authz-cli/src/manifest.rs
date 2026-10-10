//! The scan manifest.
//!
//! A manifest is the single declarative input to a scan: the target and its OpenAPI spec,
//! the authorized scope (host allowlist, limits, mutation policy), the test identities and
//! the known resources, and the CI gate policy. It deserializes from JSON and produces the
//! typed [`Scope`], [`ScanFixtures`] and [`GatePolicy`] the engine consumes.

use std::collections::BTreeSet;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use authz_core::{
    Confidence, HttpMethod, Identity, MutationPolicy, Scope, Severity, TargetRef,
};
use authz_findings::GatePolicy;
use authz_scan::{ResourceFixture, ScanFixtures};

/// Operational limits for a scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum total requests.
    pub max_requests: u64,
    /// Time budget in seconds.
    pub time_budget_secs: u64,
    /// Maximum concurrent requests.
    pub max_concurrency: u32,
    /// Requests-per-second ceiling.
    pub rate_limit_rps: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_requests: 5_000,
            time_budget_secs: 600,
            max_concurrency: 4,
            rate_limit_rps: 20,
        }
    }
}

/// How many times read probes repeat and how many must agree to verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reproductions {
    /// How many times each read probe is repeated.
    pub read_repeats: u32,
    /// How many consistent reproductions are required for a verified read finding.
    pub required: u32,
}

impl Default for Reproductions {
    fn default() -> Self {
        Reproductions {
            read_repeats: 3,
            required: 2,
        }
    }
}

/// The CI gate thresholds, as strings in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateSpec {
    /// Minimum confidence: `verified` | `probable` | `speculative`.
    pub min_confidence: String,
    /// Minimum severity: `critical` | `high` | `medium` | `low` | `info`.
    pub min_severity: String,
}

impl Default for GateSpec {
    fn default() -> Self {
        GateSpec {
            min_confidence: "verified".into(),
            min_severity: "high".into(),
        }
    }
}

/// A full scan manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// The target under test.
    pub target: TargetRef,
    /// Path to the OpenAPI document (relative to the manifest or absolute).
    pub spec: String,
    /// Hosts the scanner may contact.
    pub host_allowlist: Vec<String>,
    /// Mutation policy: `read_only` | `test_owned_only` | `unrestricted`.
    #[serde(default = "default_mutation")]
    pub mutation: String,
    /// Mutating methods explicitly permitted (e.g. `["PATCH","DELETE"]`).
    #[serde(default)]
    pub permitted_methods: Vec<String>,
    /// Operational limits.
    #[serde(default)]
    pub limits: Limits,
    /// Reproduction counts.
    #[serde(default)]
    pub reproductions: Reproductions,
    /// Per-request timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub request_timeout_ms: u64,
    /// The test identities.
    pub identities: Vec<Identity>,
    /// The known resources.
    pub resources: Vec<ResourceFixture>,
    /// The CI gate.
    #[serde(default)]
    pub gate: GateSpec,
    /// An authorization signature over this scan, proving it is permitted.
    #[serde(default)]
    pub authorization_signature: Option<String>,
}

fn default_mutation() -> String {
    "read_only".into()
}
fn default_timeout() -> u64 {
    10_000
}

/// Errors building typed values from a manifest.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ManifestError {
    /// A method string was not a known HTTP verb.
    #[error("unknown HTTP method {0:?}")]
    BadMethod(String),
    /// The mutation policy string was not recognized.
    #[error("unknown mutation policy {0:?}")]
    BadMutation(String),
    /// A confidence/severity string in the gate was not recognized.
    #[error("unknown {field} {value:?}")]
    BadEnum {
        /// Which field.
        field: &'static str,
        /// The bad value.
        value: String,
    },
    /// The scope or fixtures were invalid.
    #[error("{0}")]
    Invalid(String),
}

impl Manifest {
    /// Parse a manifest from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The parsed mutation policy.
    pub fn mutation_policy(&self) -> Result<MutationPolicy, ManifestError> {
        match self.mutation.as_str() {
            "read_only" => Ok(MutationPolicy::ReadOnly),
            "test_owned_only" => Ok(MutationPolicy::TestOwnedOnly),
            "unrestricted" => Ok(MutationPolicy::Unrestricted),
            other => Err(ManifestError::BadMutation(other.to_string())),
        }
    }

    /// The permitted mutating methods as a set.
    pub fn methods(&self) -> Result<BTreeSet<HttpMethod>, ManifestError> {
        self.permitted_methods
            .iter()
            .map(|m| HttpMethod::from_str(m).map_err(|_| ManifestError::BadMethod(m.clone())))
            .collect()
    }

    /// Build the typed scope.
    pub fn build_scope(&self) -> Result<Scope, ManifestError> {
        let scope = Scope {
            target: self.target.clone(),
            host_allowlist: self.host_allowlist.iter().cloned().collect(),
            permitted_methods: self.methods()?,
            mutation: self.mutation_policy()?,
            max_requests: self.limits.max_requests,
            time_budget_secs: self.limits.time_budget_secs,
            max_concurrency: self.limits.max_concurrency,
            rate_limit_rps: self.limits.rate_limit_rps,
            identities: self.identities.iter().map(|i| i.id.clone()).collect(),
            authorization_signature: self.authorization_signature.clone(),
        };
        scope.validate().map_err(|e| ManifestError::Invalid(e.to_string()))?;
        Ok(scope)
    }

    /// Build the scan fixtures.
    pub fn build_fixtures(&self) -> Result<ScanFixtures, ManifestError> {
        let fixtures = ScanFixtures {
            identities: self.identities.clone(),
            resources: self.resources.clone(),
        };
        fixtures.validate().map_err(ManifestError::Invalid)?;
        Ok(fixtures)
    }

    /// Build the CI gate policy.
    pub fn gate_policy(&self) -> Result<GatePolicy, ManifestError> {
        Ok(GatePolicy {
            min_confidence: parse_confidence(&self.gate.min_confidence)?,
            min_severity: parse_severity(&self.gate.min_severity)?,
        })
    }
}

fn parse_confidence(s: &str) -> Result<Confidence, ManifestError> {
    match s {
        "verified" => Ok(Confidence::Verified),
        "probable" => Ok(Confidence::Probable),
        "speculative" => Ok(Confidence::Speculative),
        other => Err(ManifestError::BadEnum {
            field: "min_confidence",
            value: other.to_string(),
        }),
    }
}

fn parse_severity(s: &str) -> Result<Severity, ManifestError> {
    match s {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        other => Err(ManifestError::BadEnum {
            field: "min_severity",
            value: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "target": {"name": "orders", "base_url": "https://api.test"},
        "spec": "openapi.json",
        "host_allowlist": ["api.test"],
        "mutation": "test_owned_only",
        "permitted_methods": ["PATCH", "DELETE"],
        "limits": {"max_requests": 100, "time_budget_secs": 60, "max_concurrency": 2, "rate_limit_rps": 10},
        "identities": [
            {"id": "alpha-admin", "tenant": "alpha", "role": "admin", "credential_ref": "env:ALPHA", "is_public": false},
            {"id": "bravo-admin", "tenant": "bravo", "role": "admin", "credential_ref": "env:BRAVO", "is_public": false}
        ],
        "resources": [
            {"instance_id": "order-1", "path_param": "id", "resource_class": "order", "owner": "alpha-admin"}
        ],
        "gate": {"min_confidence": "verified", "min_severity": "high"}
    }"#;

    #[test]
    fn parses_and_builds_scope_and_fixtures() {
        let m = Manifest::from_json(MANIFEST).unwrap();
        let scope = m.build_scope().unwrap();
        assert_eq!(scope.mutation, MutationPolicy::TestOwnedOnly);
        assert!(scope.permitted_methods.contains(&HttpMethod::Patch));
        assert!(scope.permitted_methods.contains(&HttpMethod::Delete));
        assert_eq!(scope.max_requests, 100);
        let fixtures = m.build_fixtures().unwrap();
        assert_eq!(fixtures.identities.len(), 2);
        assert_eq!(fixtures.resources.len(), 1);
    }

    #[test]
    fn gate_policy_parsed() {
        let m = Manifest::from_json(MANIFEST).unwrap();
        let g = m.gate_policy().unwrap();
        assert_eq!(g.min_confidence, Confidence::Verified);
        assert_eq!(g.min_severity, Severity::High);
    }

    #[test]
    fn defaults_apply_when_omitted() {
        let minimal = r#"{
            "target": {"name": "t", "base_url": "https://api.test"},
            "spec": "s.json",
            "host_allowlist": ["api.test"],
            "identities": [{"id": "a", "tenant": "alpha", "role": "viewer", "credential_ref": "env:A", "is_public": false}],
            "resources": []
        }"#;
        let m = Manifest::from_json(minimal).unwrap();
        assert_eq!(m.mutation_policy().unwrap(), MutationPolicy::ReadOnly);
        assert_eq!(m.limits.max_requests, 5000);
        assert_eq!(m.reproductions.read_repeats, 3);
        assert_eq!(m.request_timeout_ms, 10_000);
    }

    #[test]
    fn bad_method_is_rejected() {
        let mut m = Manifest::from_json(MANIFEST).unwrap();
        m.permitted_methods = vec!["FETCH".into()];
        assert_eq!(m.methods().unwrap_err(), ManifestError::BadMethod("FETCH".into()));
    }

    #[test]
    fn unknown_owner_fails_fixture_validation() {
        let mut m = Manifest::from_json(MANIFEST).unwrap();
        m.resources[0].owner = authz_core::IdentityId::new("ghost");
        assert!(m.build_fixtures().is_err());
    }

    #[test]
    fn empty_host_allowlist_fails_scope() {
        let mut m = Manifest::from_json(MANIFEST).unwrap();
        m.host_allowlist.clear();
        assert!(m.build_scope().is_err());
    }
}
