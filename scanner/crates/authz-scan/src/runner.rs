//! The scan runner.
//!
//! [`ScanRunner`] executes planned probes against a [`authz_http::Transport`] under the
//! [`authz_exec::ScopeGuard`] and rate limiter, feeds observations to the oracle, and
//! collects findings. Reads are repeated and combined so a verified finding is
//! reproducible; writes are performed once and judged by whether the owner's state
//! actually changed.

use std::sync::Arc;

use authz_core::{Finding, HttpMethod, Identity, ResourceClass};
use authz_http::{Capture, HttpRequest, HttpResponse, Transport};
use authz_exec::{build_request, Bindings, ScopeGuard, SecretStore, TokenBucket};
use authz_oracle::{
    combine_reproductions, read_oracle, write_oracle, OracleVerdict, ReadObservation,
    WriteObservation,
};

use crate::fixture::ScanFixtures;
use crate::plan::{plan_probes, Probe, ProbeKind};

/// The outcome of a completed scan.
#[derive(Debug, Default)]
pub struct ScanSummary {
    /// Findings produced (not yet deduplicated — that is the findings crate's job).
    pub findings: Vec<Finding>,
    /// How many probes were executed.
    pub probes_run: usize,
    /// How many probes were skipped (e.g. the owner reference was unavailable).
    pub probes_skipped: usize,
    /// Non-fatal issues encountered during the scan.
    pub notes: Vec<String>,
    /// Whether the scan stopped early (budget exhausted or cancelled).
    pub stopped_early: bool,
}

/// Executes probes and collects findings.
pub struct ScanRunner {
    transport: Arc<dyn Transport>,
    guard: ScopeGuard,
    rate: Arc<TokenBucket>,
    secrets: Arc<dyn SecretStore>,
    base_url: String,
    read_reproductions: u32,
    required_reproductions: u32,
}

impl ScanRunner {
    /// Build a runner. `base_url` is the target root; `read_reproductions` is how many
    /// times a read probe is repeated, and `required_reproductions` how many must agree for
    /// a read finding to be verified.
    pub fn new(
        transport: Arc<dyn Transport>,
        guard: ScopeGuard,
        rate: Arc<TokenBucket>,
        secrets: Arc<dyn SecretStore>,
        base_url: impl Into<String>,
    ) -> Self {
        ScanRunner {
            transport,
            guard,
            rate,
            secrets,
            base_url: base_url.into(),
            read_reproductions: 3,
            required_reproductions: 2,
        }
    }

    /// Override the reproduction counts (useful for fast tests).
    pub fn with_reproductions(mut self, repeats: u32, required: u32) -> Self {
        self.read_reproductions = repeats.max(1);
        self.required_reproductions = required.max(1);
        self
    }

    /// Plan and run every probe from the fixtures and registry.
    pub async fn run(
        &self,
        registry: &authz_openapi::OperationRegistry,
        fixtures: &ScanFixtures,
        allow_mutation: bool,
    ) -> ScanSummary {
        let mut summary = ScanSummary::default();
        for probe in plan_probes(registry, fixtures, allow_mutation) {
            match probe.kind {
                ProbeKind::Read => self.run_read(&probe, &mut summary).await,
                ProbeKind::Write => self.run_write(&probe, &mut summary).await,
            }
            if summary.stopped_early {
                summary
                    .notes
                    .push("scan stopped early: budget exhausted or cancelled".into());
                break;
            }
        }
        summary
    }

    /// Send a request under the rate limit and guard. Returns `None` if the guard refused
    /// (budget/cancel), which signals the caller to stop.
    async fn send(&self, req: &HttpRequest, summary: &mut ScanSummary) -> Option<HttpResponse> {
        let host = match req.host() {
            Some(h) => h,
            None => {
                summary.notes.push(format!("unparseable URL {:?}", req.url));
                return None;
            }
        };
        if self.guard.check(req.method, &host).is_err() {
            summary.stopped_early = true;
            return None;
        }
        self.rate.acquire().await;
        match self.transport.send(req).await {
            Ok(resp) => Some(resp),
            Err(e) => {
                summary.notes.push(format!("{} {}: {e}", req.method, req.url));
                None
            }
        }
    }

    /// Build the request for a probe's operation as `identity`.
    fn build(&self, op: &authz_core::Operation, instance_id: &str, identity: &Identity, body: Option<&serde_json::Value>) -> Option<HttpRequest> {
        let param = op.path_param_names().first().copied()?.to_string();
        let mut bindings = Bindings::new().path(param, instance_id);
        if let Some(b) = body {
            bindings = bindings.body(b.clone());
        }
        build_request(op, &bindings, &self.base_url, identity, self.secrets.as_ref()).ok()
    }

    async fn run_read(&self, probe: &Probe, summary: &mut ScanSummary) {
        // The owner-visible reference.
        let Some(owner_req) = self.build(&probe.read_operation, &probe.instance_id, &probe.owner, None)
        else {
            summary.probes_skipped += 1;
            return;
        };
        let Some(owner_ref) = self.send(&owner_req, summary).await else {
            summary.probes_skipped += 1;
            return;
        };
        if !owner_ref.status_class().is_success() {
            summary
                .notes
                .push(format!("owner reference not readable for {}", probe.instance_id));
            summary.probes_skipped += 1;
            return;
        }

        let Some(req) = self.build(&probe.operation, &probe.instance_id, &probe.requester, None) else {
            summary.probes_skipped += 1;
            return;
        };

        let mut verdicts = Vec::new();
        let mut first_capture: Option<Capture> = None;
        for _ in 0..self.read_reproductions {
            let Some(resp) = self.send(&req, summary).await else {
                break;
            };
            if first_capture.is_none() {
                first_capture = Some(Capture::record(&req, &resp));
            }
            verdicts.push(read_oracle(&ReadObservation {
                relation: probe.relation,
                attacker: &resp,
                owner_reference: &owner_ref,
                expectation: probe.expectation,
            }));
        }
        summary.probes_run += 1;

        let verdict = combine_reproductions(&verdicts, self.required_reproductions);
        self.emit(probe, &verdict, "read_oracle", verdicts.len() as u32, first_capture, &owner_req, &owner_ref, summary);
    }

    async fn run_write(&self, probe: &Probe, summary: &mut ScanSummary) {
        // State before.
        let Some(before_req) = self.build(&probe.read_operation, &probe.instance_id, &probe.owner, None)
        else {
            summary.probes_skipped += 1;
            return;
        };
        let Some(before) = self.send(&before_req, summary).await else {
            summary.probes_skipped += 1;
            return;
        };

        // The write attempt by the requester.
        let Some(write_req) =
            self.build(&probe.operation, &probe.instance_id, &probe.requester, probe.body.as_ref())
        else {
            summary.probes_skipped += 1;
            return;
        };
        let Some(write_resp) = self.send(&write_req, summary).await else {
            return;
        };

        // State after.
        let Some(after) = self.send(&before_req, summary).await else {
            summary.probes_skipped += 1;
            return;
        };
        summary.probes_run += 1;

        let verdict = write_oracle(&WriteObservation {
            relation: probe.relation,
            attacker_response: &write_resp,
            owner_state_before: &before,
            owner_state_after: &after,
            expectation: probe.expectation,
        });
        let capture = Some(Capture::record(&write_req, &write_resp));
        // Writes are judged on a single confirmed state change, so their verdict is used as
        // is (not combined across repeated mutations).
        self.emit(probe, &verdict, "write_oracle", 1, capture, &before_req, &before, summary);
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        probe: &Probe,
        verdict: &OracleVerdict,
        oracle: &str,
        replays: u32,
        attacker_capture: Option<Capture>,
        owner_req: &HttpRequest,
        owner_resp: &HttpResponse,
        summary: &mut ScanSummary,
    ) {
        let OracleVerdict::Violation {
            violation,
            confidence,
            is_write,
            rationale,
        } = verdict
        else {
            return;
        };
        let mut finding = Finding::new(
            probe.tenant.clone(),
            probe.operation.key.clone(),
            ResourceClass(probe.operation.resource_class.0.clone()),
            *violation,
            probe.relation,
            *is_write,
            *confidence,
            oracle,
            rationale.clone(),
        )
        .with_replays(replays);
        if let Some(cap) = attacker_capture {
            finding = finding.with_evidence(cap.evidence_uri());
        }
        // The owner reference is evidence too (the comparison baseline).
        finding = finding.with_evidence(Capture::record(owner_req, owner_resp).evidence_uri());
        summary.findings.push(finding);
    }
}

/// A convenience to confirm a method is an instance write (used by callers).
pub fn is_instance_write(method: HttpMethod) -> bool {
    matches!(method, HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{Confidence, IdentityId, MutationPolicy, Role, Scope, TargetRef, ViolationType};
    use authz_exec::{KillSwitch, MapSecretStore, RequestBudget};
    use authz_http::MockTransport;

    use crate::fixture::ResourceFixture;

    const SPEC: &str = r#"{
        "info": {"version": "1.0"},
        "paths": {
            "/orders/{id}": {
                "get": {"operationId": "get"},
                "patch": {"operationId": "patch"}
            }
        }
    }"#;

    fn fixtures() -> ScanFixtures {
        let alpha = Identity::new("alpha-admin", "alpha", Role::Admin, "env:A");
        let bravo = Identity::new("bravo-admin", "bravo", Role::Admin, "env:B");
        ScanFixtures::new()
            .with_identity(alpha.clone())
            .with_identity(bravo)
            .with_resource(ResourceFixture::new("order-1", "id", "order", alpha.id.clone()))
    }

    fn scope(mutation: MutationPolicy) -> Scope {
        let mut s = Scope::read_only(
            TargetRef { name: "t".into(), base_url: "https://api.test".into() },
            "api.test",
            vec![IdentityId::new("alpha-admin"), IdentityId::new("bravo-admin")],
        );
        s.mutation = mutation;
        s.permitted_methods.insert(HttpMethod::Patch);
        s.max_requests = 1000;
        s
    }

    fn runner(transport: Arc<dyn Transport>, mutation: MutationPolicy) -> ScanRunner {
        let guard = ScopeGuard::new(Arc::new(scope(mutation)), RequestBudget::new(1000), KillSwitch::new());
        let secrets = Arc::new(
            MapSecretStore::new().with("env:A", "tok-a").with("env:B", "tok-b"),
        );
        ScanRunner::new(
            transport,
            guard,
            Arc::new(TokenBucket::new(1000, 1000)),
            secrets,
            "https://api.test",
        )
        .with_reproductions(2, 2)
    }

    #[tokio::test]
    async fn detects_verified_cross_tenant_read() {
        let mock = Arc::new(MockTransport::new());
        // Both owner (alpha) and attacker (bravo) and public get the same order body: the
        // API leaks alpha's order to everyone.
        mock.fallback(HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#));
        let (reg, _) = authz_openapi::discover_str(SPEC).unwrap();

        let summary = runner(mock.clone(), MutationPolicy::ReadOnly)
            .run(&reg, &fixtures(), false)
            .await;

        // bravo (cross-tenant) and public (unauthenticated) both see the data.
        assert!(summary
            .findings
            .iter()
            .any(|f| f.violation == ViolationType::CrossTenantAccess
                && f.confidence == Confidence::Verified));
        assert!(summary
            .findings
            .iter()
            .any(|f| f.violation == ViolationType::MissingAuthentication));
    }

    /// An identity-aware target: only alpha's token may read or write alpha's order; every
    /// other caller is denied with 403 and the order never changes. This models a correctly
    /// authorized API, so the scanner must find nothing.
    struct HardenedOrders;

    #[async_trait::async_trait]
    impl Transport for HardenedOrders {
        async fn send(
            &self,
            req: &HttpRequest,
        ) -> Result<HttpResponse, authz_http::TransportError> {
            let is_owner = req
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.contains("tok-a"));
            Ok(if is_owner {
                HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#)
            } else {
                HttpResponse::new(403, r#"{"error":"forbidden"}"#)
            })
        }
    }

    #[tokio::test]
    async fn hardened_api_produces_no_findings() {
        let (reg, _) = authz_openapi::discover_str(SPEC).unwrap();
        let summary = runner(Arc::new(HardenedOrders), MutationPolicy::TestOwnedOnly)
            .run(&reg, &fixtures(), true)
            .await;
        assert!(
            summary.findings.is_empty(),
            "hardened API must yield zero findings, got {:?}",
            summary.findings
        );
        assert!(summary.probes_run > 0, "probes should still have run");
    }

    /// An API that lets a cross-tenant caller actually change the owner's order: a write that
    /// returns 403 but nonetheless mutates state (the oracle must catch the real effect).
    struct LeakyWrite {
        state: std::sync::Mutex<String>,
    }

    #[async_trait::async_trait]
    impl Transport for LeakyWrite {
        async fn send(
            &self,
            req: &HttpRequest,
        ) -> Result<HttpResponse, authz_http::TransportError> {
            match req.method {
                HttpMethod::Patch => {
                    // The write "succeeds" server-side regardless of who sent it, but returns
                    // a misleading 403.
                    *self.state.lock().unwrap() = r#"{"order":"alpha-1","status":"cancelled"}"#.into();
                    Ok(HttpResponse::new(403, r#"{"error":"forbidden"}"#))
                }
                _ => Ok(HttpResponse::new(200, self.state.lock().unwrap().clone())),
            }
        }
    }

    #[tokio::test]
    async fn write_that_mutates_despite_403_is_caught() {
        let (reg, _) = authz_openapi::discover_str(SPEC).unwrap();
        let transport = Arc::new(LeakyWrite {
            state: std::sync::Mutex::new(r#"{"order":"alpha-1","status":"open"}"#.into()),
        });
        let summary = runner(transport, MutationPolicy::TestOwnedOnly)
            .run(&reg, &fixtures(), true)
            .await;
        assert!(
            summary
                .findings
                .iter()
                .any(|f| f.is_write && f.confidence == Confidence::Verified),
            "an unauthorized write that changed state must be a verified finding"
        );
    }

    #[tokio::test]
    async fn budget_exhaustion_stops_the_scan() {
        let mock = Arc::new(MockTransport::new());
        mock.fallback(HttpResponse::new(200, r#"{"a":1}"#));
        let (reg, _) = authz_openapi::discover_str(SPEC).unwrap();
        let guard = ScopeGuard::new(Arc::new(scope(MutationPolicy::ReadOnly)), RequestBudget::new(1), KillSwitch::new());
        let secrets = Arc::new(MapSecretStore::new().with("env:A", "a").with("env:B", "b"));
        let runner = ScanRunner::new(mock, guard, Arc::new(TokenBucket::new(1000, 1000)), secrets, "https://api.test")
            .with_reproductions(2, 2);
        let summary = runner.run(&reg, &fixtures(), false).await;
        assert!(summary.stopped_early);
    }
}
