//! Emitting findings as common-envelope events.
//!
//! Beyond its own report, the scanner can emit each finding as an `authz.finding` event in
//! the shared Lattivant event envelope, so the platform can ingest and correlate authz
//! findings with agent and network telemetry. These events are *inferred* assertions (an
//! oracle's conclusion), tagged as such in their provenance.

use authz_core::{ActorKind, Event, Finding};

/// Build an `authz.finding` event for a finding.
pub fn finding_event(finding: &Finding, target: &str) -> Result<Event, String> {
    let mut builder = Event::builder("authz.finding", finding.tenant.clone())
        .actor(ActorKind::Scanner, finding.oracle.clone())
        .action("type", "authorization_finding")
        .action("violation", finding.violation.slug())
        .target("type", "api_operation")
        .target("operation", finding.operation.display())
        .target("resource_class", finding.resource_class.0.clone())
        .target("target", target.to_string())
        .outcome(confidence_status(finding), None)
        .event_id(format!("evt-{}", finding.id.as_str().trim_start_matches("fnd-")))
        .inferred();
    for e in &finding.evidence {
        builder = builder.raw_ref(e.clone());
    }
    builder.build()
}

/// Render findings as JSON-lines events.
pub fn findings_as_jsonl(findings: &[Finding], target: &str) -> Result<String, String> {
    let mut out = String::new();
    for f in findings {
        let event = finding_event(f, target)?;
        out.push_str(&serde_json::to_string(&event).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    Ok(out)
}

fn confidence_status(f: &Finding) -> String {
    format!("{:?}", f.confidence).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{Confidence, HttpMethod, IdentityRelation, OperationKey, ResourceClass, ViolationType};

    fn finding() -> Finding {
        Finding::new(
            "alpha",
            OperationKey::new(HttpMethod::Get, "/orders/{id}", "1.0").unwrap(),
            ResourceClass("order".into()),
            ViolationType::CrossTenantAccess,
            IdentityRelation::CrossTenant,
            false,
            Confidence::Verified,
            "read_oracle",
            "cross-tenant read",
        )
        .with_evidence("evidence://sha256/abc")
    }

    #[test]
    fn finding_event_has_envelope_fields() {
        let e = finding_event(&finding(), "orders-staging").unwrap();
        assert_eq!(e.event_type, "authz.finding");
        assert_eq!(e.source_engine, "authz");
        assert_eq!(e.tenant_id, "alpha");
        assert_eq!(e.outcome.status, "verified");
        assert_eq!(e.action["violation"], "cross_tenant_access");
        assert_eq!(e.provenance.raw_ref.as_deref(), Some("evidence://sha256/abc"));
        // a finding is an inferred conclusion, not a directly observed fact
        assert_eq!(e.provenance.assertion, authz_core::event::Assertion::Inferred);
    }

    #[test]
    fn jsonl_has_one_line_per_finding() {
        let findings = vec![finding(), finding()];
        let jsonl = findings_as_jsonl(&findings, "t").unwrap();
        assert_eq!(jsonl.lines().count(), 2);
        // each line is valid JSON
        for line in jsonl.lines() {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }
}
