//! The identity matrix.
//!
//! Authorization testing is fundamentally about *who* makes a request. An [`Identity`] is
//! a test principal with credentials, a tenant, and a role. The oracle reasons about the
//! [`IdentityRelation`] between the identity making a request and the identity that owns
//! the target resource — owner, same-tenant non-owner, cross-tenant, admin, and so on —
//! because the expected outcome depends entirely on that relation.

use serde::{Deserialize, Serialize};

/// A stable identifier for a test identity (not a secret).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdentityId(pub String);

impl IdentityId {
    /// Wrap a string as an identity id.
    pub fn new(s: impl Into<String>) -> Self {
        IdentityId(s.into())
    }

    /// The underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The role a test identity holds within its tenant.
///
/// Roles mirror the platform RBAC model (viewer/analyst/appsec/admin) but the scanner
/// only cares about the privilege ordering, so it can predict that an admin *should* see
/// more than a viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only within the tenant.
    Viewer,
    /// Read and investigate.
    Analyst,
    /// Full resource read/write within the tenant.
    Appsec,
    /// Tenant administrator.
    Admin,
}

impl Role {
    /// A numeric privilege level; higher is more privileged.
    pub fn level(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Analyst => 1,
            Role::Appsec => 2,
            Role::Admin => 3,
        }
    }

    /// Whether this role is at least as privileged as `other`.
    pub fn dominates(self, other: Role) -> bool {
        self.level() >= other.level()
    }
}

/// A test principal the scanner can act as.
///
/// Credentials are held as an opaque *reference*, never as a literal secret, so that
/// identities can be serialized into scan manifests and evidence without leaking tokens.
/// The executor resolves the reference to a real credential at request time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Stable id.
    pub id: IdentityId,
    /// The tenant this identity belongs to.
    pub tenant: String,
    /// The role within that tenant.
    pub role: Role,
    /// A reference (e.g. `env:ALPHA_ADMIN_TOKEN`, `vault:...`) the executor resolves.
    pub credential_ref: String,
    /// Whether this identity is the designated "public"/unauthenticated principal.
    pub is_public: bool,
}

impl Identity {
    /// Construct an authenticated identity.
    pub fn new(
        id: impl Into<String>,
        tenant: impl Into<String>,
        role: Role,
        credential_ref: impl Into<String>,
    ) -> Self {
        Identity {
            id: IdentityId::new(id),
            tenant: tenant.into(),
            role,
            credential_ref: credential_ref.into(),
            is_public: false,
        }
    }

    /// Construct the public (unauthenticated) principal.
    pub fn public() -> Self {
        Identity {
            id: IdentityId::new("public"),
            tenant: String::new(),
            role: Role::Viewer,
            credential_ref: String::new(),
            is_public: true,
        }
    }

    /// Whether two identities are in the same tenant (and neither is public).
    pub fn same_tenant_as(&self, other: &Identity) -> bool {
        !self.is_public && !other.is_public && self.tenant == other.tenant
    }
}

/// The relationship between a *requesting* identity and the identity that *owns* the
/// target resource. This is the single most important input to the oracle: it determines
/// what the correct authorization outcome is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRelation {
    /// The requester owns the resource. Access should normally succeed.
    Owner,
    /// Same tenant, different owner. Access should usually be denied (depends on policy).
    SameTenantNonOwner,
    /// A different tenant entirely. Access must be denied — the core BOLA / tenant-isolation case.
    CrossTenant,
    /// A tenant administrator acting within their own tenant. Often allowed by policy.
    Admin,
    /// The resource has been explicitly shared with the requester. Read should succeed; writes should not.
    Shared,
    /// The resource is public. Reads succeed for anyone.
    Public,
    /// Access was delegated (e.g. a scoped token). Behaviour depends on the delegation grant.
    Delegated,
    /// An unauthenticated requester against a non-public resource. Must be denied.
    Unauthenticated,
}

impl IdentityRelation {
    /// Classify the relation between a requester and the resource owner, given optional
    /// share/delegation facts supplied by the fixture.
    ///
    /// `shared_with_requester` and `delegated` come from test fixtures, because sharing
    /// and delegation are not deducible from identity alone.
    pub fn classify(
        requester: &Identity,
        owner: &Identity,
        shared_with_requester: bool,
        delegated: bool,
    ) -> IdentityRelation {
        if requester.is_public {
            return if owner.is_public {
                IdentityRelation::Public
            } else {
                IdentityRelation::Unauthenticated
            };
        }
        if owner.is_public {
            return IdentityRelation::Public;
        }
        if requester.id == owner.id {
            return IdentityRelation::Owner;
        }
        if delegated {
            return IdentityRelation::Delegated;
        }
        if shared_with_requester {
            return IdentityRelation::Shared;
        }
        if requester.tenant != owner.tenant {
            return IdentityRelation::CrossTenant;
        }
        if requester.role == Role::Admin {
            return IdentityRelation::Admin;
        }
        IdentityRelation::SameTenantNonOwner
    }

    /// Whether a *read* by this relation is, by default policy, expected to be allowed.
    ///
    /// This is the baseline the oracle uses; a scan may override it with an explicit
    /// policy exception (see the scope model).
    pub fn read_allowed_by_default(self) -> bool {
        matches!(
            self,
            IdentityRelation::Owner
                | IdentityRelation::Admin
                | IdentityRelation::Shared
                | IdentityRelation::Public
                | IdentityRelation::Delegated
        )
    }

    /// Whether a *write* by this relation is expected to be allowed by default.
    ///
    /// Note that `Shared` is read-only: a shared resource must not be writable by the
    /// grantee, which is a common real-world authorization bug.
    pub fn write_allowed_by_default(self) -> bool {
        matches!(self, IdentityRelation::Owner | IdentityRelation::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(id: &str, tenant: &str, role: Role) -> Identity {
        Identity::new(id, tenant, role, format!("env:{id}"))
    }

    #[test]
    fn role_ordering() {
        assert!(Role::Admin.dominates(Role::Viewer));
        assert!(Role::Appsec.dominates(Role::Analyst));
        assert!(!Role::Viewer.dominates(Role::Admin));
        assert!(Role::Viewer.dominates(Role::Viewer));
    }

    #[test]
    fn owner_relation() {
        let a = ident("alpha-user", "alpha", Role::Viewer);
        assert_eq!(
            IdentityRelation::classify(&a, &a, false, false),
            IdentityRelation::Owner
        );
    }

    #[test]
    fn cross_tenant_relation() {
        let a = ident("a", "alpha", Role::Admin);
        let b = ident("b", "bravo", Role::Viewer);
        // Even an admin is cross-tenant against another tenant's resource.
        assert_eq!(
            IdentityRelation::classify(&a, &b, false, false),
            IdentityRelation::CrossTenant
        );
    }

    #[test]
    fn same_tenant_non_owner_and_admin() {
        let viewer = ident("v", "alpha", Role::Viewer);
        let other = ident("o", "alpha", Role::Viewer);
        let admin = ident("adm", "alpha", Role::Admin);
        assert_eq!(
            IdentityRelation::classify(&viewer, &other, false, false),
            IdentityRelation::SameTenantNonOwner
        );
        assert_eq!(
            IdentityRelation::classify(&admin, &other, false, false),
            IdentityRelation::Admin
        );
    }

    #[test]
    fn shared_and_delegated_take_precedence_over_tenant() {
        let a = ident("a", "alpha", Role::Viewer);
        let b = ident("b", "bravo", Role::Viewer);
        assert_eq!(
            IdentityRelation::classify(&a, &b, true, false),
            IdentityRelation::Shared
        );
        assert_eq!(
            IdentityRelation::classify(&a, &b, false, true),
            IdentityRelation::Delegated
        );
    }

    #[test]
    fn public_and_unauthenticated() {
        let pub_id = Identity::public();
        let owner = ident("o", "alpha", Role::Viewer);
        let public_resource = {
            let mut i = ident("pub", "", Role::Viewer);
            i.is_public = true;
            i
        };
        assert_eq!(
            IdentityRelation::classify(&pub_id, &owner, false, false),
            IdentityRelation::Unauthenticated
        );
        assert_eq!(
            IdentityRelation::classify(&pub_id, &public_resource, false, false),
            IdentityRelation::Public
        );
        assert_eq!(
            IdentityRelation::classify(&owner, &public_resource, false, false),
            IdentityRelation::Public
        );
    }

    #[test]
    fn shared_is_read_only_by_default() {
        assert!(IdentityRelation::Shared.read_allowed_by_default());
        assert!(!IdentityRelation::Shared.write_allowed_by_default());
    }

    #[test]
    fn cross_tenant_denied_for_read_and_write() {
        assert!(!IdentityRelation::CrossTenant.read_allowed_by_default());
        assert!(!IdentityRelation::CrossTenant.write_allowed_by_default());
        assert!(!IdentityRelation::Unauthenticated.read_allowed_by_default());
    }
}
