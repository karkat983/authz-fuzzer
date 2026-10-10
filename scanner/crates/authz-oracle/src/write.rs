//! The write oracle.
//!
//! A write test asks: can identity B change an object owned by A, when policy forbids it?
//! The decisive evidence is not B's response code — an API may return 403 and still apply
//! the change, or return 200 and apply nothing — but whether A's view of the object
//! actually changed. So the oracle compares an owner-visible snapshot taken *before* the
//! write with one taken *after*.

use authz_core::{Confidence, IdentityRelation, ViolationType};
use authz_http::HttpResponse;

use crate::policy::Expectation;
use crate::verdict::OracleVerdict;

/// One write observation to judge.
pub struct WriteObservation<'a> {
    /// The relation of the requesting identity to the resource owner.
    pub relation: IdentityRelation,
    /// The response to the write attempt made by the test identity.
    pub attacker_response: &'a HttpResponse,
    /// The owner-visible state of the object *before* the write attempt.
    pub owner_state_before: &'a HttpResponse,
    /// The owner-visible state of the object *after* the write attempt.
    pub owner_state_after: &'a HttpResponse,
    /// Any policy override for this probe.
    pub expectation: Expectation,
}

impl WriteObservation<'_> {
    /// Whether the owner's view of the object changed across the write attempt.
    ///
    /// A change in either the canonical body or the status (e.g. 200 -> 404 after an
    /// unauthorized delete) counts.
    pub fn state_changed(&self) -> bool {
        self.owner_state_before.status != self.owner_state_after.status
            || self.owner_state_before.canonical_body() != self.owner_state_after.canonical_body()
    }
}

/// Judge a write observation.
pub fn write_oracle(obs: &WriteObservation) -> OracleVerdict {
    if obs.expectation.write_allowed(obs.relation) {
        return OracleVerdict::ok("write is allowed by policy for this relation");
    }

    let violation = write_violation_for(obs.relation);

    if obs.state_changed() {
        // Confirmed: an unauthorized write took effect. The attacker's status code is
        // irrelevant to this conclusion.
        return OracleVerdict::violation(
            violation,
            Confidence::Verified,
            true,
            "owner-visible state changed after a write that policy forbids",
        );
    }

    // No observed change. Interpret the attacker's response cautiously.
    let status = obs.attacker_response.status;
    match obs.attacker_response.status_class() {
        authz_core::StatusClass::Denied | authz_core::StatusClass::ClientError => {
            OracleVerdict::ok(format!("write rejected with {status}; no state change"))
        }
        authz_core::StatusClass::Success => OracleVerdict::violation(
            violation,
            Confidence::Probable,
            true,
            "write returned 2xx but no owner-visible state change was observed (possibly \
             asynchronous or a no-op); needs follow-up",
        ),
        authz_core::StatusClass::ServerError | authz_core::StatusClass::Redirect => {
            OracleVerdict::inconclusive(format!("{status}; no state change observed"))
        }
        _ => OracleVerdict::ok("no state change observed"),
    }
}

/// Map a relation to the specific write violation type.
fn write_violation_for(relation: IdentityRelation) -> ViolationType {
    match relation {
        IdentityRelation::Shared => ViolationType::SharedResourceWrite,
        IdentityRelation::CrossTenant => ViolationType::CrossTenantAccess,
        IdentityRelation::Unauthenticated => ViolationType::MissingAuthentication,
        _ => ViolationType::Bola,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs<'a>(
        relation: IdentityRelation,
        attacker: &'a HttpResponse,
        before: &'a HttpResponse,
        after: &'a HttpResponse,
    ) -> WriteObservation<'a> {
        WriteObservation {
            relation,
            attacker_response: attacker,
            owner_state_before: before,
            owner_state_after: after,
            expectation: Expectation::Default,
        }
    }

    #[test]
    fn owner_write_is_no_finding() {
        let r = HttpResponse::new(200, r#"{"v":1}"#);
        assert!(!write_oracle(&obs(IdentityRelation::Owner, &r, &r, &r)).is_violation());
    }

    #[test]
    fn cross_tenant_write_that_changes_state_is_verified_even_on_403() {
        // The attacker's request returned 403, yet the owner's object changed: a real
        // unauthorized write hiding behind a misleading status code.
        let attacker = HttpResponse::new(403, r#"{"error":"forbidden"}"#);
        let before = HttpResponse::new(200, r#"{"status":"open"}"#);
        let after = HttpResponse::new(200, r#"{"status":"cancelled"}"#);
        let v = write_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &before, &after));
        assert_eq!(v.violation_type(), Some(ViolationType::CrossTenantAccess));
        assert_eq!(v.confidence(), Some(Confidence::Verified));
    }

    #[test]
    fn two_hundred_write_with_no_state_change_is_probable() {
        // The attacker got 200, but the owner's object is unchanged: not confirmed.
        let attacker = HttpResponse::new(200, r#"{"ok":true}"#);
        let state = HttpResponse::new(200, r#"{"status":"open"}"#);
        let v = write_oracle(&obs(IdentityRelation::SameTenantNonOwner, &attacker, &state, &state));
        assert_eq!(v.confidence(), Some(Confidence::Probable));
    }

    #[test]
    fn denied_write_with_no_change_is_clean() {
        let attacker = HttpResponse::new(403, "");
        let state = HttpResponse::new(200, r#"{"status":"open"}"#);
        let v = write_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &state, &state));
        assert!(!v.is_violation());
    }

    #[test]
    fn unauthorized_delete_changes_status_and_is_caught() {
        let attacker = HttpResponse::new(204, "");
        let before = HttpResponse::new(200, r#"{"id":1}"#);
        let after = HttpResponse::new(404, r#"{"error":"not found"}"#);
        let v = write_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &before, &after));
        assert_eq!(v.confidence(), Some(Confidence::Verified));
    }

    #[test]
    fn shared_resource_write_has_its_own_violation_type() {
        let attacker = HttpResponse::new(200, "");
        let before = HttpResponse::new(200, r#"{"note":"a"}"#);
        let after = HttpResponse::new(200, r#"{"note":"b"}"#);
        let v = write_oracle(&obs(IdentityRelation::Shared, &attacker, &before, &after));
        assert_eq!(v.violation_type(), Some(ViolationType::SharedResourceWrite));
    }

    #[test]
    fn declared_allowed_write_is_not_a_finding() {
        let attacker = HttpResponse::new(200, "");
        let before = HttpResponse::new(200, r#"{"note":"a"}"#);
        let after = HttpResponse::new(200, r#"{"note":"b"}"#);
        let observation = WriteObservation {
            relation: IdentityRelation::SameTenantNonOwner,
            attacker_response: &attacker,
            owner_state_before: &before,
            owner_state_after: &after,
            expectation: Expectation::Allowed,
        };
        assert!(!write_oracle(&observation).is_violation());
    }

    #[test]
    fn server_error_without_change_is_inconclusive() {
        let attacker = HttpResponse::new(500, "");
        let state = HttpResponse::new(200, r#"{"v":1}"#);
        assert!(matches!(
            write_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &state, &state)),
            OracleVerdict::Inconclusive { .. }
        ));
    }
}
