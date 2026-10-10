//! Deduplicating findings by fingerprint.
//!
//! Two findings with the same id (tenant + operation + resource class + violation) are the
//! same weakness. [`FindingSet`] merges them, keeping the highest confidence and severity
//! seen, summing replay counts, and unioning evidence — so a report shows one row per
//! distinct weakness, however many probes produced it.

use indexmap::IndexMap;

use authz_core::{Confidence, Finding, FindingId, Severity};

/// A set of findings deduplicated by id, preserving first-seen order.
#[derive(Debug, Default, Clone)]
pub struct FindingSet {
    findings: IndexMap<FindingId, Finding>,
}

impl FindingSet {
    /// An empty set.
    pub fn new() -> Self {
        FindingSet::default()
    }

    /// Build a set from an iterator of findings, deduplicating as it goes.
    pub fn from_iter_merged<I: IntoIterator<Item = Finding>>(iter: I) -> Self {
        let mut set = FindingSet::new();
        for f in iter {
            set.add(f);
        }
        set
    }

    /// Add a finding, merging it into any existing finding with the same id.
    pub fn add(&mut self, finding: Finding) {
        match self.findings.get_mut(&finding.id) {
            Some(existing) => merge_into(existing, finding),
            None => {
                self.findings.insert(finding.id.clone(), finding);
            }
        }
    }

    /// Number of distinct findings.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Iterate the distinct findings in first-seen order.
    pub fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.findings.values()
    }

    /// The findings as a vector, sorted by severity (desc) then confidence (desc).
    pub fn sorted(&self) -> Vec<Finding> {
        let mut out: Vec<Finding> = self.findings.values().cloned().collect();
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.cmp(&a.confidence))
                .then(a.id.as_str().cmp(b.id.as_str()))
        });
        out
    }

    /// Count of findings at or above a confidence tier.
    pub fn count_at_least(&self, min: Confidence) -> usize {
        self.iter().filter(|f| f.confidence >= min).count()
    }

    /// The highest severity present, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.iter().map(|f| f.severity).max()
    }
}

/// Merge `incoming` into `existing`: keep the stronger confidence/severity, sum replays,
/// union evidence.
fn merge_into(existing: &mut Finding, incoming: Finding) {
    existing.confidence = existing.confidence.max(incoming.confidence);
    existing.severity = existing.severity.max(incoming.severity);
    existing.replay_count = existing.replay_count.saturating_add(incoming.replay_count);
    for e in incoming.evidence {
        if !existing.evidence.contains(&e) {
            existing.evidence.push(e);
        }
    }
    // A write observation is "stronger" context than a read-only one for the same id.
    existing.is_write |= incoming.is_write;
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{HttpMethod, IdentityRelation, OperationKey, ResourceClass, ViolationType};

    fn finding(confidence: Confidence, evidence: &str) -> Finding {
        Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
            IdentityRelation::CrossTenant,
            false,
            confidence,
            "read_oracle",
            "summary",
        )
        .with_evidence(evidence)
    }

    #[test]
    fn same_fingerprint_merges() {
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Probable, "evidence://sha256/a"));
        set.add(finding(Confidence::Verified, "evidence://sha256/b"));
        assert_eq!(set.len(), 1);
        let merged = set.iter().next().unwrap();
        assert_eq!(merged.confidence, Confidence::Verified); // stronger wins
        assert_eq!(merged.evidence.len(), 2); // evidence unioned
        assert_eq!(merged.replay_count, 2); // replays summed
    }

    #[test]
    fn distinct_violations_do_not_merge() {
        let mut set = FindingSet::new();
        // A different violation on the same operation has a different fingerprint.
        let other = Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::InformationDisclosure,
            IdentityRelation::CrossTenant,
            false,
            Confidence::Verified,
            "o",
            "s",
        );
        set.add(finding(Confidence::Verified, "x"));
        set.add(other);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn sorted_orders_by_severity_then_confidence() {
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Speculative, "a")); // High severity (cross-tenant read)
        let mut low = Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/notes/{id}", "1.0").unwrap(),
            ResourceClass("note".into()),
            ViolationType::Bola,
            IdentityRelation::SameTenantNonOwner,
            false,
            Confidence::Verified,
            "o",
            "s",
        );
        low.severity = Severity::Low;
        set.add(low);
        let sorted = set.sorted();
        assert_eq!(sorted[0].severity, Severity::High);
    }

    #[test]
    fn counts_and_max_severity() {
        let mut set = FindingSet::new();
        set.add(finding(Confidence::Verified, "a"));
        assert_eq!(set.count_at_least(Confidence::Verified), 1);
        assert_eq!(set.count_at_least(Confidence::Probable), 1);
        assert_eq!(set.max_severity(), Some(Severity::High));
    }
}
