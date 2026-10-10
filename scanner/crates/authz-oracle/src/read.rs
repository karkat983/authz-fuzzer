//! The read oracle.
//!
//! A read test asks: can identity B retrieve an object that belongs to A, when policy says
//! it should not? The oracle compares B's response against an *owner-visible reference* —
//! the same object fetched as A — because only that comparison can tell a genuine
//! disclosure from a coincidental 2xx.

use authz_core::{Confidence, IdentityRelation, ViolationType};
use authz_http::HttpResponse;

use crate::body::{is_error_envelope, same_object};
use crate::policy::Expectation;
use crate::verdict::OracleVerdict;

/// One read observation to judge.
pub struct ReadObservation<'a> {
    /// The relation of the requesting identity to the resource owner.
    pub relation: IdentityRelation,
    /// The response the test identity received.
    pub attacker: &'a HttpResponse,
    /// The same object fetched as its true owner (the reference).
    pub owner_reference: &'a HttpResponse,
    /// Any policy override for this probe.
    pub expectation: Expectation,
}

/// Judge a read observation.
pub fn read_oracle(obs: &ReadObservation) -> OracleVerdict {
    // We only hunt for *excess* access. If policy allows this read, there is nothing to
    // find here (a wrongful denial is a functionality bug, not a security finding).
    if obs.expectation.read_allowed(obs.relation) {
        return OracleVerdict::ok("read is allowed by policy for this relation");
    }

    let violation = violation_for(obs.relation);
    let status = obs.attacker.status;

    match obs.attacker.status_class() {
        authz_core::StatusClass::Denied => {
            OracleVerdict::ok(format!("properly denied with {status}"))
        }
        authz_core::StatusClass::NotFound => {
            // A 404 is the correct way to hide an object's existence — unless the 404 body
            // itself leaks the owner's content.
            if same_object(obs.attacker, obs.owner_reference) {
                OracleVerdict::violation(
                    ViolationType::InformationDisclosure,
                    Confidence::Verified,
                    false,
                    "404 response still disclosed the owner's object content",
                )
            } else {
                OracleVerdict::ok("denied via 404 (existence hidden)")
            }
        }
        authz_core::StatusClass::Redirect => {
            OracleVerdict::inconclusive(format!("{status} redirect, possibly to a login page"))
        }
        authz_core::StatusClass::ServerError => {
            OracleVerdict::inconclusive(format!("{status} server error"))
        }
        authz_core::StatusClass::ClientError => {
            OracleVerdict::ok(format!("rejected with {status}"))
        }
        authz_core::StatusClass::Success => judge_success(obs, violation),
        authz_core::StatusClass::Informational | authz_core::StatusClass::Unknown => {
            OracleVerdict::inconclusive(format!("unexpected status {status}"))
        }
    }
}

fn judge_success(obs: &ReadObservation, violation: ViolationType) -> OracleVerdict {
    // Rule 1: a 2xx alone proves nothing. Look at the body.
    if obs.attacker.is_body_empty() {
        return OracleVerdict::ok("2xx with empty body; no data disclosed");
    }
    if is_error_envelope(obs.attacker) {
        return OracleVerdict::ok("2xx carrying an error envelope; effectively a denial");
    }
    if same_object(obs.attacker, obs.owner_reference) {
        // The strongest signal: the non-owner received *exactly* the owner's object.
        return OracleVerdict::violation(
            violation,
            Confidence::Verified,
            false,
            "non-owner received a 2xx body identical to the owner's object",
        );
    }
    // The attacker got some non-empty 2xx data that is not the owner's object. This may be
    // a partial view, a different representation, or a generic landing payload — suspicious
    // but not confirmed.
    OracleVerdict::violation(
        violation,
        Confidence::Probable,
        false,
        "non-owner received non-empty 2xx data that does not match the owner reference",
    )
}

/// Map an identity relation to the specific read violation type.
fn violation_for(relation: IdentityRelation) -> ViolationType {
    match relation {
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
        owner: &'a HttpResponse,
    ) -> ReadObservation<'a> {
        ReadObservation {
            relation,
            attacker,
            owner_reference: owner,
            expectation: Expectation::Default,
        }
    }

    #[test]
    fn allowed_read_is_no_finding() {
        let r = HttpResponse::new(200, r#"{"id":1}"#);
        let v = read_oracle(&obs(IdentityRelation::Owner, &r, &r));
        assert!(!v.is_violation());
    }

    #[test]
    fn cross_tenant_identical_body_is_verified_disclosure() {
        let owner = HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#);
        let attacker = HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#);
        let v = read_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &owner));
        assert_eq!(v.violation_type(), Some(ViolationType::CrossTenantAccess));
        assert_eq!(v.confidence(), Some(Confidence::Verified));
    }

    #[test]
    fn proper_403_is_no_finding() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let attacker = HttpResponse::new(403, r#"{"error":"forbidden"}"#);
        let v = read_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &owner));
        assert!(!v.is_violation());
    }

    #[test]
    fn two_hundred_with_empty_body_is_not_a_finding() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let attacker = HttpResponse::new(200, "");
        let v = read_oracle(&obs(IdentityRelation::SameTenantNonOwner, &attacker, &owner));
        assert!(!v.is_violation(), "empty 2xx must never be a disclosure");
    }

    #[test]
    fn two_hundred_error_envelope_is_not_a_finding() {
        let owner = HttpResponse::new(200, r#"{"id":1,"total":5}"#);
        let attacker = HttpResponse::new(200, r#"{"error":"forbidden"}"#);
        let v = read_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &owner));
        assert!(!v.is_violation(), "soft 200 denial must not be a disclosure");
    }

    #[test]
    fn four_oh_four_camouflage_is_correct() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let attacker = HttpResponse::new(404, r#"{"error":"not found"}"#);
        let v = read_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &owner));
        assert!(!v.is_violation());
    }

    #[test]
    fn four_oh_four_that_leaks_owner_content_is_a_finding() {
        let owner = HttpResponse::new(200, r#"{"id":1,"secret":"x"}"#);
        let attacker = HttpResponse::new(404, r#"{"id":1,"secret":"x"}"#);
        let v = read_oracle(&obs(IdentityRelation::CrossTenant, &attacker, &owner));
        assert_eq!(v.violation_type(), Some(ViolationType::InformationDisclosure));
    }

    #[test]
    fn different_2xx_data_is_probable_not_verified() {
        let owner = HttpResponse::new(200, r#"{"order":"alpha-1","total":10}"#);
        let attacker = HttpResponse::new(200, r#"{"order":"other","total":1}"#);
        let v = read_oracle(&obs(IdentityRelation::SameTenantNonOwner, &attacker, &owner));
        assert_eq!(v.confidence(), Some(Confidence::Probable));
        assert_eq!(v.violation_type(), Some(ViolationType::Bola));
    }

    #[test]
    fn redirect_and_server_error_are_inconclusive() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let redirect = HttpResponse::new(302, "");
        let error = HttpResponse::new(500, "");
        assert!(matches!(
            read_oracle(&obs(IdentityRelation::CrossTenant, &redirect, &owner)),
            OracleVerdict::Inconclusive { .. }
        ));
        assert!(matches!(
            read_oracle(&obs(IdentityRelation::CrossTenant, &error, &owner)),
            OracleVerdict::Inconclusive { .. }
        ));
    }

    #[test]
    fn unauthenticated_disclosure_maps_to_missing_auth() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let attacker = HttpResponse::new(200, r#"{"id":1}"#);
        let v = read_oracle(&obs(IdentityRelation::Unauthenticated, &attacker, &owner));
        assert_eq!(v.violation_type(), Some(ViolationType::MissingAuthentication));
    }

    #[test]
    fn declared_public_read_is_allowed_even_cross_tenant() {
        let owner = HttpResponse::new(200, r#"{"id":1}"#);
        let attacker = HttpResponse::new(200, r#"{"id":1}"#);
        let observation = ReadObservation {
            relation: IdentityRelation::CrossTenant,
            attacker: &attacker,
            owner_reference: &owner,
            expectation: Expectation::Allowed,
        };
        assert!(!read_oracle(&observation).is_violation());
    }
}
