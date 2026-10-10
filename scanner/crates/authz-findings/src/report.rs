//! A JSON summary report of a finding set.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use authz_core::{Confidence, Finding, Severity};

use crate::dedup::FindingSet;

/// Aggregated counts and the finding list, suitable for a JSON report artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsReport {
    /// Total distinct findings.
    pub total: usize,
    /// Counts keyed by severity name (critical/high/medium/low/info).
    pub by_severity: IndexMap<String, usize>,
    /// Counts keyed by confidence tier.
    pub by_confidence: IndexMap<String, usize>,
    /// Counts keyed by violation slug.
    pub by_violation: IndexMap<String, usize>,
    /// The findings, sorted by severity then confidence.
    pub findings: Vec<Finding>,
}

impl FindingsReport {
    /// Build a report from a finding set.
    pub fn from_set(set: &FindingSet) -> Self {
        let mut by_severity = severity_table();
        let mut by_confidence = confidence_table();
        let mut by_violation: IndexMap<String, usize> = IndexMap::new();

        for f in set.iter() {
            *by_severity.get_mut(severity_name(f.severity)).unwrap() += 1;
            *by_confidence.get_mut(confidence_name(f.confidence)).unwrap() += 1;
            *by_violation.entry(f.violation.slug().to_string()).or_insert(0) += 1;
        }

        FindingsReport {
            total: set.len(),
            by_severity,
            by_confidence,
            by_violation,
            findings: set.sorted(),
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }

    /// A one-line human summary, e.g. `3 findings (1 critical, 2 high); 2 verified`.
    pub fn headline(&self) -> String {
        if self.total == 0 {
            return "no findings".to_string();
        }
        let sev: Vec<String> = ["critical", "high", "medium", "low", "info"]
            .iter()
            .filter_map(|k| {
                let n = *self.by_severity.get(*k).unwrap_or(&0);
                (n > 0).then(|| format!("{n} {k}"))
            })
            .collect();
        let verified = *self.by_confidence.get("verified").unwrap_or(&0);
        format!(
            "{} finding{} ({}); {} verified",
            self.total,
            if self.total == 1 { "" } else { "s" },
            sev.join(", "),
            verified
        )
    }
}

fn severity_table() -> IndexMap<String, usize> {
    let mut m = IndexMap::new();
    for k in ["critical", "high", "medium", "low", "info"] {
        m.insert(k.to_string(), 0);
    }
    m
}

fn confidence_table() -> IndexMap<String, usize> {
    let mut m = IndexMap::new();
    for k in ["verified", "probable", "speculative"] {
        m.insert(k.to_string(), 0);
    }
    m
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn confidence_name(c: Confidence) -> &'static str {
    match c {
        Confidence::Verified => "verified",
        Confidence::Probable => "probable",
        Confidence::Speculative => "speculative",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{HttpMethod, IdentityRelation, OperationKey, ResourceClass, ViolationType};

    fn cross_tenant() -> Finding {
        Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
            IdentityRelation::CrossTenant,
            false,
            Confidence::Verified,
            "o",
            "cross tenant read",
        )
    }

    #[test]
    fn report_counts_and_headline() {
        let mut set = FindingSet::new();
        set.add(cross_tenant());
        let report = FindingsReport::from_set(&set);
        assert_eq!(report.total, 1);
        assert_eq!(report.by_severity["high"], 1);
        assert_eq!(report.by_confidence["verified"], 1);
        assert_eq!(report.by_violation["cross_tenant_access"], 1);
        assert_eq!(report.headline(), "1 finding (1 high); 1 verified");
    }

    #[test]
    fn empty_report_headline() {
        let report = FindingsReport::from_set(&FindingSet::new());
        assert_eq!(report.headline(), "no findings");
        assert_eq!(report.total, 0);
    }

    #[test]
    fn report_round_trips_through_json() {
        let mut set = FindingSet::new();
        set.add(cross_tenant());
        let json = FindingsReport::from_set(&set).to_json();
        let back: FindingsReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total, 1);
    }
}
