//! Findings: the record of a verified (or suspected) authorization weakness.
//!
//! The single most important rule, stated in the oracle spec, is encoded here: a finding
//! cannot be [`Confidence::Verified`] from a status code alone. [`Finding::new`] requires
//! an [`crate::identity::IdentityRelation`], an expected-versus-observed outcome, and an
//! oracle name; and the severity rubric and fingerprint are derived, not free-form.

use serde::{Deserialize, Serialize};

use crate::fingerprint::Fingerprint;
use crate::identity::IdentityRelation;
use crate::operation::{OperationKey, ResourceClass};

/// A stable identifier for a finding, derived from its fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingId(pub String);

impl FindingId {
    /// The underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The confidence tier of a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A candidate requiring human review; evidence is weak or heuristic.
    Speculative,
    /// Suspicious with partial evidence, but the oracle could not fully confirm.
    Probable,
    /// A reproducible unauthorized effect confirmed by a clear oracle. The only tier that
    /// should ever fail a CI gate by default.
    Verified,
}

/// The kind of authorization weakness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// Broken Object Level Authorization: a caller read or wrote an object they do not own.
    Bola,
    /// Cross-tenant access: tenant isolation was breached.
    CrossTenantAccess,
    /// A resource shared read-only was writable by the grantee.
    SharedResourceWrite,
    /// Broken Function Level Authorization: a caller invoked an operation their role forbids.
    Bfla,
    /// An unauthenticated caller reached a protected resource.
    MissingAuthentication,
    /// A denial leaked the resource's existence or content (e.g. 404 that still returned data).
    InformationDisclosure,
}

impl ViolationType {
    /// A short stable slug used in fingerprints and exports.
    pub fn slug(self) -> &'static str {
        match self {
            ViolationType::Bola => "bola",
            ViolationType::CrossTenantAccess => "cross_tenant_access",
            ViolationType::SharedResourceWrite => "shared_resource_write",
            ViolationType::Bfla => "bfla",
            ViolationType::MissingAuthentication => "missing_authentication",
            ViolationType::InformationDisclosure => "information_disclosure",
        }
    }
}

/// The severity of a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Low impact.
    Low,
    /// Moderate impact.
    Medium,
    /// Serious impact.
    High,
    /// Critical impact.
    Critical,
}

impl Severity {
    /// Derive a severity from the violation type, the access relation, and whether the
    /// access was a write.
    ///
    /// The rubric: cross-tenant and unauthenticated writes are critical; cross-tenant
    /// reads and BOLA writes are high; BOLA reads are medium; shared-write is high;
    /// information disclosure is medium.
    pub fn rubric(violation: ViolationType, relation: IdentityRelation, is_write: bool) -> Severity {
        use IdentityRelation as R;
        use ViolationType as V;
        match (violation, relation, is_write) {
            (V::CrossTenantAccess, _, true) => Severity::Critical,
            (V::MissingAuthentication, _, true) => Severity::Critical,
            (V::CrossTenantAccess, _, false) => Severity::High,
            (V::MissingAuthentication, _, false) => Severity::High,
            (V::SharedResourceWrite, _, _) => Severity::High,
            (V::Bola, _, true) => Severity::High,
            (V::Bola, R::CrossTenant, false) => Severity::High,
            (V::Bola, _, false) => Severity::Medium,
            (V::Bfla, _, true) => Severity::High,
            (V::Bfla, _, false) => Severity::Medium,
            (V::InformationDisclosure, _, _) => Severity::Medium,
        }
    }
}

/// A single authorization finding.
///
/// Secrets and raw tokens are never stored on a finding; evidence is referenced by
/// content-addressed [`Fingerprint`] URIs resolved through the evidence store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Derived stable id.
    pub id: FindingId,
    /// The tenant the finding belongs to.
    pub tenant: String,
    /// The operation involved.
    pub operation: OperationKey,
    /// The class of resource affected.
    pub resource_class: ResourceClass,
    /// The kind of weakness.
    pub violation: ViolationType,
    /// The relation of the requesting identity to the resource owner.
    pub relation: IdentityRelation,
    /// Whether the offending access was a state-changing write.
    pub is_write: bool,
    /// The confidence tier.
    pub confidence: Confidence,
    /// Derived severity.
    pub severity: Severity,
    /// The name of the oracle that produced the finding (for traceability).
    pub oracle: String,
    /// A one-line human summary of expected vs. observed.
    pub summary: String,
    /// How many times the effect reproduced during verification.
    pub replay_count: u32,
    /// Content-addressed evidence references (request/response captures), never raw secrets.
    pub evidence: Vec<String>,
}

impl Finding {
    /// Construct a finding. The required arguments make it impossible to record a verified
    /// finding without an oracle, a relation, and an explicit expected/observed summary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: impl Into<String>,
        operation: OperationKey,
        resource_class: ResourceClass,
        violation: ViolationType,
        relation: IdentityRelation,
        is_write: bool,
        confidence: Confidence,
        oracle: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        let tenant = tenant.into();
        let severity = Severity::rubric(violation, relation, is_write);
        let fp = Self::fingerprint(&tenant, &operation, &resource_class, violation);
        Finding {
            id: FindingId(format!("fnd-{}", &fp.to_hex()[..16])),
            tenant,
            operation,
            resource_class,
            violation,
            relation,
            is_write,
            confidence,
            severity,
            oracle: oracle.into(),
            summary: summary.into(),
            replay_count: 1,
            evidence: Vec::new(),
        }
    }

    /// The deduplication fingerprint: tenant + operation + resource class + violation type.
    ///
    /// Deliberately independent of the specific resource id, so the same weakness probed
    /// against many ids collapses to one finding.
    pub fn fingerprint(
        tenant: &str,
        operation: &OperationKey,
        resource_class: &ResourceClass,
        violation: ViolationType,
    ) -> Fingerprint {
        Fingerprint::builder()
            .field("authz-finding-v1")
            .field(tenant)
            .field(operation.method.as_str())
            .field(&operation.normalized_path)
            .field(&operation.spec_version)
            .field(&resource_class.0)
            .field(violation.slug())
            .finish()
    }

    /// Attach a content-addressed evidence reference.
    pub fn with_evidence(mut self, uri: impl Into<String>) -> Self {
        self.evidence.push(uri.into());
        self
    }

    /// Set the number of reproductions observed.
    pub fn with_replays(mut self, n: u32) -> Self {
        self.replay_count = n.max(1);
        self
    }

    /// Whether this finding should fail a CI gate at the given minimum confidence.
    pub fn fails_gate(&self, min_confidence: Confidence) -> bool {
        self.confidence >= min_confidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpMethod;

    fn op() -> OperationKey {
        OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap()
    }

    #[test]
    fn severity_rubric() {
        assert_eq!(
            Severity::rubric(ViolationType::CrossTenantAccess, IdentityRelation::CrossTenant, true),
            Severity::Critical
        );
        assert_eq!(
            Severity::rubric(ViolationType::CrossTenantAccess, IdentityRelation::CrossTenant, false),
            Severity::High
        );
        assert_eq!(
            Severity::rubric(ViolationType::Bola, IdentityRelation::SameTenantNonOwner, false),
            Severity::Medium
        );
        assert_eq!(
            Severity::rubric(ViolationType::SharedResourceWrite, IdentityRelation::Shared, true),
            Severity::High
        );
    }

    #[test]
    fn fingerprint_ignores_resource_id_but_splits_on_violation() {
        let f1 = Finding::fingerprint("alpha", &op(), &ResourceClass("order".into()), ViolationType::Bola);
        let f2 = Finding::fingerprint("alpha", &op(), &ResourceClass("order".into()), ViolationType::Bola);
        let f3 = Finding::fingerprint(
            "alpha",
            &op(),
            &ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
        );
        assert_eq!(f1, f2, "same weakness must fingerprint identically");
        assert_ne!(f1, f3, "different violation must fingerprint differently");
    }

    #[test]
    fn different_tenants_do_not_collide() {
        let a = Finding::fingerprint("alpha", &op(), &ResourceClass("order".into()), ViolationType::Bola);
        let b = Finding::fingerprint("bravo", &op(), &ResourceClass("order".into()), ViolationType::Bola);
        assert_ne!(a, b);
    }

    #[test]
    fn constructing_a_finding_derives_id_and_severity() {
        let f = Finding::new(
            "alpha",
            op(),
            ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
            IdentityRelation::CrossTenant,
            false,
            Confidence::Verified,
            "cross_tenant_read_oracle",
            "bravo-admin read alpha's order",
        );
        assert!(f.id.as_str().starts_with("fnd-"));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Verified);
        assert_eq!(f.replay_count, 1);
    }

    #[test]
    fn ci_gate_respects_min_confidence() {
        let mut f = Finding::new(
            "alpha",
            op(),
            ResourceClass("order".into()),
            ViolationType::Bola,
            IdentityRelation::SameTenantNonOwner,
            false,
            Confidence::Verified,
            "o",
            "s",
        );
        f.confidence = Confidence::Probable;
        assert!(f.fails_gate(Confidence::Probable));
        assert!(!f.fails_gate(Confidence::Verified));
    }

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::Verified > Confidence::Probable);
        assert!(Confidence::Probable > Confidence::Speculative);
    }
}
