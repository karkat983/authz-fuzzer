//! Wiring a manifest and spec into a running scan.

use std::sync::Arc;

use authz_exec::{KillSwitch, RequestBudget, ScopeGuard, SecretStore, TokenBucket};
use authz_findings::{gate, FindingSet, FindingsReport, GateOutcome};
use authz_http::Transport;
use authz_openapi::{discover_str, DiscoveryReport, OperationRegistry};
use authz_scan::{plan_probes, ScanRunner, ScanSummary};

use crate::manifest::{Manifest, ManifestError};

/// Everything a completed scan yields.
pub struct ScanResults {
    /// The deduplicated findings.
    pub findings: FindingSet,
    /// The aggregated report.
    pub report: FindingsReport,
    /// The CI gate outcome.
    pub gate: GateOutcome,
    /// The raw scan summary (probes run, notes).
    pub summary: ScanSummary,
    /// Discovery warnings.
    pub discovery: DiscoveryReport,
}

/// Errors running a scan.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The manifest could not be turned into typed values.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The OpenAPI spec could not be parsed.
    #[error("spec error: {0}")]
    Spec(String),
}

/// Discover operations from a spec without running any probes.
pub fn discover_only(spec_json: &str) -> Result<(OperationRegistry, DiscoveryReport), RunError> {
    discover_str(spec_json).map_err(|e| RunError::Spec(e.to_string()))
}

/// Plan probes without sending any request (a dry run), returning one line per probe.
pub fn plan_only(manifest: &Manifest, spec_json: &str) -> Result<Vec<String>, RunError> {
    let (registry, _) = discover_only(spec_json)?;
    let fixtures = manifest.build_fixtures()?;
    let allow_mutation = manifest.mutation_policy()?.allows_mutation();
    let probes = plan_probes(&registry, &fixtures, allow_mutation);
    Ok(probes
        .iter()
        .map(|p| {
            format!(
                "{:?} {} {} as {} (relation {:?})",
                p.kind,
                p.operation.key.method,
                p.operation.key.normalized_path,
                p.requester.id,
                p.relation
            )
        })
        .collect())
}

/// Run a full scan with the provided transport and secret store.
pub async fn run_scan(
    manifest: &Manifest,
    spec_json: &str,
    transport: Arc<dyn Transport>,
    secrets: Arc<dyn SecretStore>,
) -> Result<ScanResults, RunError> {
    let (registry, discovery) = discover_only(spec_json)?;
    let scope = Arc::new(manifest.build_scope()?);
    let fixtures = manifest.build_fixtures()?;
    let gate_policy = manifest.gate_policy()?;
    let allow_mutation = scope.mutation.allows_mutation();

    let guard = ScopeGuard::new(
        scope.clone(),
        RequestBudget::new(scope.max_requests),
        KillSwitch::new(),
    );
    let rate = Arc::new(TokenBucket::new(
        scope.rate_limit_rps,
        scope.rate_limit_rps.max(1),
    ));

    let runner = ScanRunner::new(transport, guard, rate, secrets, scope.target.base_url.clone())
        .with_reproductions(manifest.reproductions.read_repeats, manifest.reproductions.required);

    let summary = runner.run(&registry, &fixtures, allow_mutation).await;
    let findings = FindingSet::from_iter_merged(summary.findings.clone());
    let report = FindingsReport::from_set(&findings);
    let gate_outcome = gate(&findings, gate_policy);

    Ok(ScanResults {
        findings,
        report,
        gate: gate_outcome,
        summary,
        discovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_exec::MapSecretStore;
    use authz_http::{HttpRequest, HttpResponse, MockTransport, TransportError};

    const MANIFEST: &str = r#"{
        "target": {"name": "orders", "base_url": "https://api.test"},
        "spec": "openapi.json",
        "host_allowlist": ["api.test"],
        "mutation": "read_only",
        "limits": {"max_requests": 1000, "time_budget_secs": 60, "max_concurrency": 2, "rate_limit_rps": 1000},
        "reproductions": {"read_repeats": 2, "required": 2},
        "identities": [
            {"id": "alpha-admin", "tenant": "alpha", "role": "admin", "credential_ref": "env:ALPHA", "is_public": false},
            {"id": "bravo-admin", "tenant": "bravo", "role": "admin", "credential_ref": "env:BRAVO", "is_public": false}
        ],
        "resources": [
            {"instance_id": "order-1", "path_param": "id", "resource_class": "order", "owner": "alpha-admin"}
        ]
    }"#;

    const SPEC: &str = r#"{"info":{"version":"1.0"},"paths":{"/orders/{id}":{"get":{"operationId":"get"}}}}"#;

    fn secrets() -> Arc<MapSecretStore> {
        Arc::new(
            MapSecretStore::new()
                .with("env:ALPHA", "tok-a")
                .with("env:BRAVO", "tok-b"),
        )
    }

    #[test]
    fn plan_only_lists_probes() {
        let m = Manifest::from_json(MANIFEST).unwrap();
        let lines = plan_only(&m, SPEC).unwrap();
        // bravo + public read probes
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.contains("GET")));
    }

    #[tokio::test]
    async fn vulnerable_api_scan_produces_a_finding_and_fails_gate() {
        let m = Manifest::from_json(MANIFEST).unwrap();
        let mock = Arc::new(MockTransport::new());
        mock.fallback(HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#));
        let results = run_scan(&m, SPEC, mock, secrets()).await.unwrap();
        assert!(!results.findings.is_empty());
        assert!(!results.gate.passed);
        assert_eq!(results.gate.exit_code(), 2);
        assert!(results.report.headline().contains("verified"));
    }

    /// Identity-aware hardened API: only alpha's token reads alpha's order.
    struct Hardened;

    #[async_trait::async_trait]
    impl Transport for Hardened {
        async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError> {
            let owner = req
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.contains("tok-a"));
            Ok(if owner {
                HttpResponse::new(200, r#"{"order":"alpha-1"}"#)
            } else {
                HttpResponse::new(403, r#"{"error":"forbidden"}"#)
            })
        }
    }

    #[tokio::test]
    async fn hardened_api_scan_passes_gate() {
        let m = Manifest::from_json(MANIFEST).unwrap();
        let results = run_scan(&m, SPEC, Arc::new(Hardened), secrets()).await.unwrap();
        assert!(results.findings.is_empty());
        assert!(results.gate.passed);
        assert_eq!(results.gate.exit_code(), 0);
    }
}
