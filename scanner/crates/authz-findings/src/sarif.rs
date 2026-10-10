//! SARIF 2.1.0 export.
//!
//! Static-analysis and code-scanning tools (GitHub code scanning, IDE viewers) consume
//! SARIF. [`to_sarif`] renders a [`FindingSet`] as a valid SARIF 2.1.0 document: one rule
//! per distinct violation type, one result per finding, with the authz finding id as a
//! partial fingerprint so results stay stable across scans.

use indexmap::IndexMap;
use serde_json::{json, Value};

use authz_core::{Confidence, Finding, Severity, ViolationType};

use crate::dedup::FindingSet;

/// Render a finding set as a SARIF 2.1.0 JSON string.
pub fn to_sarif(set: &FindingSet, tool_version: &str) -> String {
    serde_json::to_string_pretty(&sarif_value(set, tool_version)).expect("sarif serializes")
}

/// Build the SARIF document as a JSON value.
pub fn sarif_value(set: &FindingSet, tool_version: &str) -> Value {
    let findings = set.sorted();

    // Rules: one per distinct violation type, in first-seen order, with a stable index.
    let mut rule_index: IndexMap<ViolationType, usize> = IndexMap::new();
    let mut rules = Vec::new();
    for f in &findings {
        if !rule_index.contains_key(&f.violation) {
            rule_index.insert(f.violation, rules.len());
            rules.push(rule_descriptor(f.violation));
        }
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|f| result_object(f, rule_index[&f.violation]))
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "authz-fuzzer",
                    "informationUri": "https://github.com/karkat983/authz-fuzzer",
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn rule_descriptor(v: ViolationType) -> Value {
    json!({
        "id": v.slug(),
        "name": rule_name(v),
        "shortDescription": {"text": rule_text(v)},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    })
}

fn result_object(f: &Finding, rule_index: usize) -> Value {
    json!({
        "ruleId": f.violation.slug(),
        "ruleIndex": rule_index,
        "level": sarif_level(f.severity),
        "rank": confidence_rank(f.confidence),
        "message": {"text": format!("{} (relation: {:?})", f.summary, f.relation)},
        "locations": [{
            "logicalLocations": [{
                "fullyQualifiedName": format!("{} {}", f.operation.method, f.operation.normalized_path),
                "kind": "function",
            }]
        }],
        "partialFingerprints": {"authzFindingId/v1": f.id.as_str()},
        "properties": {
            "confidence": confidence_str(f.confidence),
            "severity": severity_str(f.severity),
            "tenant": f.tenant,
            "isWrite": f.is_write,
            "oracle": f.oracle,
            "replayCount": f.replay_count,
            "evidence": f.evidence,
        }
    })
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn confidence_rank(c: Confidence) -> u32 {
    match c {
        Confidence::Verified => 100,
        Confidence::Probable => 60,
        Confidence::Speculative => 30,
    }
}

fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::Verified => "verified",
        Confidence::Probable => "probable",
        Confidence::Speculative => "speculative",
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn rule_name(v: ViolationType) -> &'static str {
    match v {
        ViolationType::Bola => "BrokenObjectLevelAuthorization",
        ViolationType::CrossTenantAccess => "CrossTenantAccess",
        ViolationType::SharedResourceWrite => "SharedResourceWrite",
        ViolationType::Bfla => "BrokenFunctionLevelAuthorization",
        ViolationType::MissingAuthentication => "MissingAuthentication",
        ViolationType::InformationDisclosure => "InformationDisclosure",
    }
}

fn rule_text(v: ViolationType) -> &'static str {
    match v {
        ViolationType::Bola => "A caller accessed an object they do not own.",
        ViolationType::CrossTenantAccess => "A caller accessed another tenant's resource.",
        ViolationType::SharedResourceWrite => "A read-only shared resource was writable by the grantee.",
        ViolationType::Bfla => "A caller invoked an operation their role forbids.",
        ViolationType::MissingAuthentication => "A protected resource was reachable without authentication.",
        ViolationType::InformationDisclosure => "A denial response leaked the resource's content.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{HttpMethod, IdentityRelation, OperationKey, ResourceClass};

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
            "non-owner read the owner's object",
        )
        .with_evidence("evidence://sha256/abc")
    }

    #[test]
    fn sarif_has_expected_shape() {
        let mut set = FindingSet::new();
        set.add(finding());
        let doc = sarif_value(&set, "0.1.0");
        assert_eq!(doc["version"], "2.1.0");
        let run = &doc["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "authz-fuzzer");
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "cross_tenant_access");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "cross_tenant_access");
        assert_eq!(result["level"], "error");
        assert_eq!(result["rank"], 100);
        assert_eq!(result["ruleIndex"], 0);
        assert!(result["partialFingerprints"]["authzFindingId/v1"].is_string());
        assert_eq!(result["properties"]["tenant"], "alpha");
        assert_eq!(result["properties"]["evidence"][0], "evidence://sha256/abc");
    }

    #[test]
    fn sarif_is_valid_json_and_parses_back() {
        let mut set = FindingSet::new();
        set.add(finding());
        let s = to_sarif(&set, "0.1.0");
        let _: Value = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn empty_set_still_valid_sarif() {
        let doc = sarif_value(&FindingSet::new(), "0.1.0");
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }
}
