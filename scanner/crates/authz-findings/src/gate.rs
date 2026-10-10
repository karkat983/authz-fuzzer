//! The CI gate.
//!
//! A continuous-integration run wants a single yes/no: should this build fail because the
//! scan found something that matters? [`gate`] answers it against a [`GatePolicy`] (a
//! minimum confidence and severity) and yields a [`GateOutcome`] with the failing findings
//! and a process exit code.

use authz_core::{Confidence, Finding, Severity};

use crate::dedup::FindingSet;

/// The threshold at which a finding should fail a build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatePolicy {
    /// Minimum confidence to count (e.g. only `Verified`).
    pub min_confidence: Confidence,
    /// Minimum severity to count (e.g. `High` and above).
    pub min_severity: Severity,
}

impl Default for GatePolicy {
    /// The conservative default: only verified findings of high severity or above fail a build.
    fn default() -> Self {
        GatePolicy {
            min_confidence: Confidence::Verified,
            min_severity: Severity::High,
        }
    }
}

impl GatePolicy {
    /// Whether a single finding trips this gate.
    pub fn fails(&self, f: &Finding) -> bool {
        f.confidence >= self.min_confidence && f.severity >= self.min_severity
    }
}

/// The result of applying a gate policy to a finding set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateOutcome {
    /// Whether the gate passed (no finding tripped it).
    pub passed: bool,
    /// How many findings tripped the gate.
    pub failing_count: usize,
    /// How many findings were present in total.
    pub total_count: usize,
}

impl GateOutcome {
    /// The process exit code: 0 when passed, 2 when the gate failed.
    pub fn exit_code(&self) -> i32 {
        if self.passed {
            0
        } else {
            2
        }
    }
}

/// Apply a gate policy to a finding set.
pub fn gate(set: &FindingSet, policy: GatePolicy) -> GateOutcome {
    let failing = set.iter().filter(|f| policy.fails(f)).count();
    GateOutcome {
        passed: failing == 0,
        failing_count: failing,
        total_count: set.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{HttpMethod, IdentityRelation, OperationKey, ResourceClass, ViolationType};

    fn finding(confidence: Confidence, severity: Severity) -> Finding {
        let mut f = Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::Bola,
            IdentityRelation::SameTenantNonOwner,
            false,
            confidence,
            "o",
            "s",
        );
        f.severity = severity;
        f
    }

    #[test]
    fn default_gate_fails_only_on_verified_high() {
        let policy = GatePolicy::default();
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Verified, Severity::High));
        set.add(finding(Confidence::Probable, Severity::Critical)); // below confidence
        // (both have the same fingerprint, so they merge to the stronger: Verified+Critical)
        let outcome = gate(&set, policy);
        assert!(!outcome.passed);
        assert_eq!(outcome.exit_code(), 2);
    }

    #[test]
    fn clean_set_passes() {
        let set = FindingSet::new();
        let outcome = gate(&set, GatePolicy::default());
        assert!(outcome.passed);
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(outcome.failing_count, 0);
    }

    #[test]
    fn medium_finding_does_not_trip_default_gate() {
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Verified, Severity::Medium));
        let outcome = gate(&set, GatePolicy::default());
        assert!(outcome.passed);
        assert_eq!(outcome.total_count, 1);
    }

    #[test]
    fn a_stricter_policy_can_fail_on_probable() {
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Probable, Severity::Medium));
        let policy = GatePolicy {
            min_confidence: Confidence::Probable,
            min_severity: Severity::Medium,
        };
        assert!(!gate(&set, policy).passed);
    }
}
