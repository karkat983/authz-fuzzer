//! Probe planning.
//!
//! A [`Probe`] is one authorization test: exercise an operation against a known resource as
//! a particular identity, and judge the result against that identity's relation to the
//! resource owner. [`plan_probes`] enumerates probes deterministically from the discovered
//! operations and the fixtures.
//!
//! The planner restricts itself to *instance* operations with exactly one path parameter
//! (the common BOLA shape, `GET /orders/{id}`). Multi-path-parameter operations need an
//! ownership model the fixtures do not yet express and are skipped.

use authz_core::{HttpMethod, Identity, IdentityRelation, Operation};
use authz_oracle::Expectation;

use authz_openapi::OperationRegistry;

use crate::fixture::ScanFixtures;

/// Whether a probe reads or writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// A read test (GET), judged against an owner-visible reference.
    Read,
    /// A write test (PUT/PATCH/DELETE), judged against owner-visible state before/after.
    Write,
}

/// One planned authorization test.
#[derive(Clone, Debug)]
pub struct Probe {
    /// Read or write.
    pub kind: ProbeKind,
    /// The operation exercised by the requesting identity.
    pub operation: Operation,
    /// The GET instance operation used to read the owner's reference / state snapshot.
    pub read_operation: Operation,
    /// The resource instance id to bind.
    pub instance_id: String,
    /// The identity making the test request.
    pub requester: Identity,
    /// The owning identity.
    pub owner: Identity,
    /// The relation between requester and owner.
    pub relation: IdentityRelation,
    /// The policy expectation for this probe.
    pub expectation: Expectation,
    /// The JSON body for a write probe, if any.
    pub body: Option<serde_json::Value>,
    /// The victim tenant the finding belongs to (the owner's tenant).
    pub tenant: String,
}

impl Probe {
    /// Whether this is a write probe.
    pub fn is_write(&self) -> bool {
        self.kind == ProbeKind::Write
    }
}

/// Find a single-path-parameter instance operation of `method` acting on `resource_class`.
fn instance_op<'a>(
    registry: &'a OperationRegistry,
    method: HttpMethod,
    resource_class: &str,
) -> Option<&'a Operation> {
    registry.iter().find(|op| {
        op.key.method == method
            && op.resource_class.0 == resource_class
            && op.key.normalized_path.ends_with("/{}")
            && op.path_param_names().len() == 1
    })
}

/// Enumerate probes from the registry and fixtures.
///
/// When `allow_mutation` is false, only read probes are produced. An unauthenticated
/// (public) requester is always added for read probes so missing-authentication is tested.
pub fn plan_probes(
    registry: &OperationRegistry,
    fixtures: &ScanFixtures,
    allow_mutation: bool,
) -> Vec<Probe> {
    let mut probes = Vec::new();
    let public = Identity::public();

    for res in &fixtures.resources {
        let Some(owner) = fixtures.identity(&res.owner) else {
            continue;
        };
        let Some(read_op) = instance_op(registry, HttpMethod::Get, &res.resource_class) else {
            // Without a GET reference we cannot soundly judge reads or verify writes.
            continue;
        };

        let write_ops: Vec<&Operation> = if allow_mutation {
            [HttpMethod::Put, HttpMethod::Patch, HttpMethod::Delete]
                .into_iter()
                .filter_map(|m| instance_op(registry, m, &res.resource_class))
                .collect()
        } else {
            Vec::new()
        };

        // Requesters: every identity that is not the owner, plus the public principal.
        let requesters = fixtures
            .identities
            .iter()
            .filter(|i| i.id != owner.id)
            .chain(std::iter::once(&public));

        for requester in requesters {
            let shared = res.is_shared_with(&requester.id);
            let relation = IdentityRelation::classify(requester, owner, shared, false);
            let read_expectation = if res.public {
                Expectation::Allowed
            } else {
                Expectation::Default
            };

            probes.push(Probe {
                kind: ProbeKind::Read,
                operation: read_op.clone(),
                read_operation: read_op.clone(),
                instance_id: res.instance_id.clone(),
                requester: requester.clone(),
                owner: owner.clone(),
                relation,
                expectation: read_expectation,
                body: None,
                tenant: owner.tenant.clone(),
            });

            // Write probes are not planned for the public principal (unauthenticated writes
            // are covered by the missing-auth read case and are riskier to attempt broadly).
            if requester.is_public {
                continue;
            }
            for wop in &write_ops {
                let body = if wop.key.method == HttpMethod::Delete {
                    None
                } else {
                    Some(
                        res.write_body
                            .clone()
                            .unwrap_or_else(|| serde_json::json!({"_authz_probe": true})),
                    )
                };
                probes.push(Probe {
                    kind: ProbeKind::Write,
                    operation: (*wop).clone(),
                    read_operation: read_op.clone(),
                    instance_id: res.instance_id.clone(),
                    requester: requester.clone(),
                    owner: owner.clone(),
                    relation,
                    expectation: Expectation::Default,
                    body,
                    tenant: owner.tenant.clone(),
                });
            }
        }
    }

    probes
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{IdentityId, Role};
    use authz_openapi::discover_str;

    use crate::fixture::ResourceFixture;

    const SPEC: &str = r#"{
        "info": {"version": "1.0"},
        "paths": {
            "/orders": {"post": {"operationId": "create"}},
            "/orders/{id}": {
                "get": {"operationId": "get"},
                "patch": {"operationId": "patch"},
                "delete": {"operationId": "del"}
            }
        }
    }"#;

    fn fixtures() -> ScanFixtures {
        let alpha = Identity::new("alpha-admin", "alpha", Role::Admin, "env:A");
        let bravo = Identity::new("bravo-admin", "bravo", Role::Admin, "env:B");
        let order = ResourceFixture::new("order-1", "id", "order", alpha.id.clone());
        ScanFixtures::new()
            .with_identity(alpha)
            .with_identity(bravo)
            .with_resource(order)
    }

    #[test]
    fn read_only_plan_has_read_probes_including_public() {
        let (reg, _) = discover_str(SPEC).unwrap();
        let probes = plan_probes(&reg, &fixtures(), false);
        // requesters for the one alpha-owned resource: bravo + public = 2 read probes
        assert_eq!(probes.len(), 2);
        assert!(probes.iter().all(|p| p.kind == ProbeKind::Read));
        assert!(probes.iter().any(|p| p.requester.is_public
            && p.relation == IdentityRelation::Unauthenticated));
        assert!(probes
            .iter()
            .any(|p| p.requester.id == IdentityId::new("bravo-admin")
                && p.relation == IdentityRelation::CrossTenant));
    }

    #[test]
    fn mutation_plan_adds_write_probes_for_non_public() {
        let (reg, _) = discover_str(SPEC).unwrap();
        let probes = plan_probes(&reg, &fixtures(), true);
        // bravo: 1 read + 2 writes (patch, delete); public: 1 read = 4
        assert_eq!(probes.len(), 4);
        let writes: Vec<_> = probes.iter().filter(|p| p.is_write()).collect();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().any(|p| p.operation.key.method == HttpMethod::Patch));
        assert!(writes.iter().any(|p| p.operation.key.method == HttpMethod::Delete));
        // patch carries a body, delete does not
        let patch = writes.iter().find(|p| p.operation.key.method == HttpMethod::Patch).unwrap();
        assert!(patch.body.is_some());
        let del = writes.iter().find(|p| p.operation.key.method == HttpMethod::Delete).unwrap();
        assert!(del.body.is_none());
    }

    #[test]
    fn shared_resource_relation_is_shared() {
        let (reg, _) = discover_str(SPEC).unwrap();
        let mut fx = fixtures();
        fx.resources[0] = fx.resources[0].clone().shared_with(IdentityId::new("bravo-admin"));
        let probes = plan_probes(&reg, &fx, false);
        let bravo = probes
            .iter()
            .find(|p| p.requester.id == IdentityId::new("bravo-admin"))
            .unwrap();
        assert_eq!(bravo.relation, IdentityRelation::Shared);
    }

    #[test]
    fn public_resource_sets_allowed_expectation() {
        let (reg, _) = discover_str(SPEC).unwrap();
        let mut fx = fixtures();
        fx.resources[0] = fx.resources[0].clone().public();
        let probes = plan_probes(&reg, &fx, false);
        assert!(probes.iter().all(|p| p.expectation == Expectation::Allowed));
    }

    #[test]
    fn no_get_reference_means_no_probes() {
        let spec = r#"{"info":{"version":"1"},"paths":{"/orders/{id}":{"delete":{"operationId":"d"}}}}"#;
        let (reg, _) = discover_str(spec).unwrap();
        assert!(plan_probes(&reg, &fixtures(), true).is_empty());
    }
}
