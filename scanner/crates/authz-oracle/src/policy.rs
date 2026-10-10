//! Policy expectations.
//!
//! By default the oracle expects access to be allowed or denied according to the identity
//! relation (see [`authz_core::IdentityRelation`]). But real APIs have exceptions: a
//! resource may be deliberately public, or an endpoint may intentionally allow same-tenant
//! reads. A scan can declare these as [`Expectation`] overrides so the oracle does not
//! flag intended behaviour.

use authz_core::IdentityRelation;

/// What authorization outcome a scan expects for a particular probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    /// Use the default policy derived from the identity relation.
    Default,
    /// This access is expected to be allowed (a declared exception).
    Allowed,
    /// This access is expected to be denied.
    Denied,
}

impl Expectation {
    /// Resolve whether a *read* is expected to be allowed, given the relation.
    pub fn read_allowed(self, relation: IdentityRelation) -> bool {
        match self {
            Expectation::Allowed => true,
            Expectation::Denied => false,
            Expectation::Default => relation.read_allowed_by_default(),
        }
    }

    /// Resolve whether a *write* is expected to be allowed, given the relation.
    pub fn write_allowed(self, relation: IdentityRelation) -> bool {
        match self {
            Expectation::Allowed => true,
            Expectation::Denied => false,
            Expectation::Default => relation.write_allowed_by_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_follows_relation() {
        assert!(Expectation::Default.read_allowed(IdentityRelation::Owner));
        assert!(!Expectation::Default.read_allowed(IdentityRelation::CrossTenant));
        assert!(!Expectation::Default.write_allowed(IdentityRelation::Shared));
    }

    #[test]
    fn overrides_win() {
        assert!(Expectation::Allowed.read_allowed(IdentityRelation::CrossTenant));
        assert!(!Expectation::Denied.read_allowed(IdentityRelation::Owner));
        assert!(Expectation::Allowed.write_allowed(IdentityRelation::SameTenantNonOwner));
    }
}
