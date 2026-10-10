//! Suppressing accepted findings, with mandatory expiry.
//!
//! A team may accept a known finding (a declared exception, a risk accepted for now). A
//! [`Suppression`] records that decision against a finding id, with a reason and an
//! **expiry** — suppressions are deliberately temporary so an accepted risk is revisited
//! rather than forgotten. An expired suppression no longer hides its finding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use authz_core::FindingId;

use crate::dedup::FindingSet;

/// A decision to suppress a finding until a given time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    /// The id of the finding to suppress.
    pub finding_id: String,
    /// Why it is suppressed (required, for the audit trail).
    pub reason: String,
    /// When the suppression expires. After this, the finding reappears.
    pub expires_at: DateTime<Utc>,
}

impl Suppression {
    /// Whether the suppression is still in effect at `now`.
    pub fn active_at(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

/// A list of suppressions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SuppressionList {
    /// The suppressions.
    pub suppressions: Vec<Suppression>,
}

impl SuppressionList {
    /// An empty list.
    pub fn new() -> Self {
        SuppressionList::default()
    }

    /// Add a suppression.
    pub fn with(mut self, s: Suppression) -> Self {
        self.suppressions.push(s);
        self
    }

    /// Whether a finding id is actively suppressed at `now`.
    pub fn is_suppressed(&self, id: &FindingId, now: DateTime<Utc>) -> bool {
        self.suppressions
            .iter()
            .any(|s| s.finding_id == id.as_str() && s.active_at(now))
    }

    /// Split a finding set into (reported, suppressed) at `now`.
    pub fn partition(&self, set: &FindingSet, now: DateTime<Utc>) -> (FindingSet, FindingSet) {
        let mut reported = FindingSet::new();
        let mut suppressed = FindingSet::new();
        for f in set.iter() {
            if self.is_suppressed(&f.id, now) {
                suppressed.add(f.clone());
            } else {
                reported.add(f.clone());
            }
        }
        (reported, suppressed)
    }

    /// Expired suppressions at `now` (so a report can warn that they no longer apply).
    pub fn expired(&self, now: DateTime<Utc>) -> Vec<&Suppression> {
        self.suppressions.iter().filter(|s| !s.active_at(now)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{Finding, HttpMethod, IdentityRelation, OperationKey, ResourceClass, Confidence, ViolationType};
    use chrono::Duration;

    fn a_finding() -> Finding {
        Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
            IdentityRelation::CrossTenant,
            false,
            Confidence::Verified,
            "o",
            "s",
        )
    }

    #[test]
    fn active_suppression_hides_finding() {
        let f = a_finding();
        let now = Utc::now();
        let list = SuppressionList::new().with(Suppression {
            finding_id: f.id.as_str().to_string(),
            reason: "accepted for q3".into(),
            expires_at: now + Duration::days(30),
        });
        let mut set = FindingSet::new();
        set.add(f);
        let (reported, suppressed) = list.partition(&set, now);
        assert!(reported.is_empty());
        assert_eq!(suppressed.len(), 1);
    }

    #[test]
    fn expired_suppression_does_not_hide() {
        let f = a_finding();
        let now = Utc::now();
        let list = SuppressionList::new().with(Suppression {
            finding_id: f.id.as_str().to_string(),
            reason: "was accepted".into(),
            expires_at: now - Duration::days(1),
        });
        let mut set = FindingSet::new();
        set.add(f);
        let (reported, suppressed) = list.partition(&set, now);
        assert_eq!(reported.len(), 1);
        assert!(suppressed.is_empty());
        assert_eq!(list.expired(now).len(), 1);
    }

    #[test]
    fn unrelated_suppression_is_ignored() {
        let now = Utc::now();
        let list = SuppressionList::new().with(Suppression {
            finding_id: "fnd-doesnotexist".into(),
            reason: "x".into(),
            expires_at: now + Duration::days(1),
        });
        let mut set = FindingSet::new();
        set.add(a_finding());
        let (reported, _) = list.partition(&set, now);
        assert_eq!(reported.len(), 1);
    }
}
