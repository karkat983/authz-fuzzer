//! End-to-end integration: run a real scan, over a real socket, against the reference
//! orders API in each vulnerability mode.
//!
//! This is the integrated-lab self-check: the scanner must find nothing when the API is
//! correctly authorized, and must find exactly the right weakness in each vulnerable mode.
//! Everything runs in-process — the server, the HTTP client and the oracle — so it needs no
//! external services.

use std::net::SocketAddr;
use std::sync::Arc;

use authz_cli::{run_scan, Manifest};
use authz_core::{Confidence, ViolationType};
use authz_exec::MapSecretStore;
use authz_http::ReqwestTransport;
use authz_target::{serve, Vulnerability};

/// A manifest pointing at the live server on `port`, in `mutation` mode.
fn manifest_json(port: u16, mutation: &str) -> String {
    format!(
        r#"{{
        "target": {{"name": "orders", "base_url": "http://127.0.0.1:{port}"}},
        "spec": "unused.json",
        "host_allowlist": ["127.0.0.1"],
        "mutation": "{mutation}",
        "permitted_methods": ["PATCH", "DELETE"],
        "limits": {{"max_requests": 1000, "time_budget_secs": 60, "max_concurrency": 2, "rate_limit_rps": 1000}},
        "reproductions": {{"read_repeats": 2, "required": 2}},
        "request_timeout_ms": 5000,
        "identities": [
            {{"id": "alpha-admin", "tenant": "alpha", "role": "admin", "credential_ref": "env:ALPHA_ADMIN", "is_public": false}},
            {{"id": "bravo-admin", "tenant": "bravo", "role": "admin", "credential_ref": "env:BRAVO_ADMIN", "is_public": false}}
        ],
        "resources": [
            {{"instance_id": "order-1", "path_param": "id", "resource_class": "order",
              "owner": "alpha-admin", "write_body": {{"status": "cancelled"}}}}
        ]
    }}"#
    )
}

fn secrets() -> Arc<MapSecretStore> {
    Arc::new(
        MapSecretStore::new()
            .with("env:ALPHA_ADMIN", "tok-alpha-admin")
            .with("env:BRAVO_ADMIN", "tok-bravo-admin"),
    )
}

/// Start the server, scan it, and return the deduplicated findings.
async fn scan(vuln: Vulnerability, mutation: &str) -> authz_findings::FindingSet {
    let (addr, guard) = serve(SocketAddr::from(([127, 0, 0, 1], 0)), vuln)
        .await
        .expect("server starts");
    let spec = authz_target::openapi_json().to_string();
    let manifest = Manifest::from_json(&manifest_json(addr.port(), mutation)).unwrap();
    let transport = Arc::new(ReqwestTransport::new(5000).unwrap());
    let results = run_scan(&manifest, &spec, transport, secrets())
        .await
        .expect("scan runs");
    guard.stop().await;
    results.findings
}

#[tokio::test]
async fn hardened_target_yields_no_findings() {
    let findings = scan(Vulnerability::None, "test_owned_only").await;
    assert!(
        findings.is_empty(),
        "a correctly authorized API must produce zero findings, got: {:?}",
        findings.sorted()
    );
}

#[tokio::test]
async fn bola_read_is_caught_as_verified_cross_tenant() {
    let findings = scan(Vulnerability::BolaRead, "read_only").await;
    assert!(
        findings.iter().any(|f| f.violation == ViolationType::CrossTenantAccess
            && !f.is_write
            && f.confidence == Confidence::Verified),
        "cross-tenant read leak must be a verified finding, got: {:?}",
        findings.sorted()
    );
}

#[tokio::test]
async fn missing_auth_is_caught() {
    let findings = scan(Vulnerability::MissingAuth, "read_only").await;
    assert!(
        findings
            .iter()
            .any(|f| f.violation == ViolationType::MissingAuthentication),
        "an unauthenticated read must be flagged, got: {:?}",
        findings.sorted()
    );
}

#[tokio::test]
async fn bola_write_is_caught_as_verified_write() {
    let findings = scan(Vulnerability::BolaWrite, "test_owned_only").await;
    assert!(
        findings
            .iter()
            .any(|f| f.is_write && f.confidence == Confidence::Verified),
        "a cross-tenant write that changed state must be a verified finding, got: {:?}",
        findings.sorted()
    );
}

#[tokio::test]
async fn scanner_respects_read_only_scope_and_sends_no_writes() {
    // In read-only mode against a write-vulnerable server, the scope must stop the scanner
    // from ever attempting the write — so no write finding appears even though the server is
    // vulnerable to one.
    let findings = scan(Vulnerability::BolaWrite, "read_only").await;
    assert!(
        findings.iter().all(|f| !f.is_write),
        "read-only scope must never produce a write finding, got: {:?}",
        findings.sorted()
    );
}
