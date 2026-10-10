//! Scan fixtures: the ground truth a scan needs to judge authorization.
//!
//! The scanner cannot know which identity *owns* a given resource, or which resources are
//! deliberately shared or public, from the API alone — that is exactly the knowledge an
//! authorization test needs. [`ScanFixtures`] supplies it: the set of test identities and,
//! for each resource, its instance id, resource class, owner, and any sharing.

use serde::{Deserialize, Serialize};

use authz_core::{Identity, IdentityId};

/// A known resource instance with a known owner, used to drive and judge probes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceFixture {
    /// The path-parameter value that identifies the instance (e.g. `order-42`).
    pub instance_id: String,
    /// The name of the path parameter the instance id binds to (e.g. `orderId`).
    pub path_param: String,
    /// The resource class (e.g. `order`), matched against discovered operations.
    pub resource_class: String,
    /// The identity that owns this resource.
    pub owner: IdentityId,
    /// Identities the resource has been explicitly shared with (read-only).
    #[serde(default)]
    pub shared_with: Vec<IdentityId>,
    /// Whether the resource is public (readable by anyone).
    #[serde(default)]
    pub public: bool,
    /// A JSON body to use when exercising write operations against this resource.
    #[serde(default)]
    pub write_body: Option<serde_json::Value>,
}

impl ResourceFixture {
    /// Construct a minimal resource fixture.
    pub fn new(
        instance_id: impl Into<String>,
        path_param: impl Into<String>,
        resource_class: impl Into<String>,
        owner: IdentityId,
    ) -> Self {
        ResourceFixture {
            instance_id: instance_id.into(),
            path_param: path_param.into(),
            resource_class: resource_class.into(),
            owner,
            shared_with: Vec::new(),
            public: false,
            write_body: None,
        }
    }

    /// Builder: mark the resource shared with an identity (read-only).
    pub fn shared_with(mut self, id: IdentityId) -> Self {
        self.shared_with.push(id);
        self
    }

    /// Builder: mark the resource public.
    pub fn public(mut self) -> Self {
        self.public = true;
        self
    }

    /// Builder: set a write body for mutation probes.
    pub fn with_write_body(mut self, body: serde_json::Value) -> Self {
        self.write_body = Some(body);
        self
    }

    /// Whether `identity` has been shared this resource.
    pub fn is_shared_with(&self, identity: &IdentityId) -> bool {
        self.shared_with.contains(identity)
    }
}

/// The identities and resources a scan tests with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanFixtures {
    /// The test identities.
    pub identities: Vec<Identity>,
    /// The known resources.
    pub resources: Vec<ResourceFixture>,
}

impl ScanFixtures {
    /// An empty fixture set.
    pub fn new() -> Self {
        ScanFixtures::default()
    }

    /// Add an identity.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identities.push(identity);
        self
    }

    /// Add a resource.
    pub fn with_resource(mut self, resource: ResourceFixture) -> Self {
        self.resources.push(resource);
        self
    }

    /// Look up an identity by id.
    pub fn identity(&self, id: &IdentityId) -> Option<&Identity> {
        self.identities.iter().find(|i| &i.id == id)
    }

    /// Validate that every resource's owner is a known identity.
    pub fn validate(&self) -> Result<(), String> {
        if self.identities.is_empty() {
            return Err("no identities".into());
        }
        for r in &self.resources {
            if self.identity(&r.owner).is_none() {
                return Err(format!(
                    "resource {:?} owner {:?} is not a known identity",
                    r.instance_id, r.owner
                ));
            }
            for s in &r.shared_with {
                if self.identity(s).is_none() {
                    return Err(format!(
                        "resource {:?} shared with unknown identity {:?}",
                        r.instance_id, s
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::Role;

    #[test]
    fn fixture_lookup_and_sharing() {
        let alpha = Identity::new("alpha-admin", "alpha", Role::Admin, "env:A");
        let bravo = Identity::new("bravo-admin", "bravo", Role::Admin, "env:B");
        let res = ResourceFixture::new("order-1", "orderId", "order", alpha.id.clone())
            .shared_with(bravo.id.clone());
        let fx = ScanFixtures::new()
            .with_identity(alpha.clone())
            .with_identity(bravo.clone())
            .with_resource(res.clone());
        assert_eq!(fx.identity(&alpha.id).unwrap().tenant, "alpha");
        assert!(res.is_shared_with(&bravo.id));
        assert!(fx.validate().is_ok());
    }

    #[test]
    fn validate_rejects_unknown_owner() {
        let res = ResourceFixture::new("o1", "id", "order", IdentityId::new("ghost"));
        let fx = ScanFixtures::new()
            .with_identity(Identity::new("a", "alpha", Role::Viewer, "env:A"))
            .with_resource(res);
        assert!(fx.validate().is_err());
    }
}
