//! Resolving credential references to secret material.
//!
//! Identities hold a *reference* (e.g. `env:ALPHA_ADMIN_TOKEN`), never the secret. A
//! [`SecretStore`] resolves that reference to the actual secret at request time. Keeping
//! secrets out of the identity records and out of evidence is a core safety property, so
//! the store is the single choke point where a secret enters the request path.

use std::collections::HashMap;

/// Resolves a credential reference to its secret value.
pub trait SecretStore: Send + Sync {
    /// Resolve `reference` to a secret, or `None` if it is unknown.
    fn get(&self, reference: &str) -> Option<String>;
}

/// Resolves `env:NAME` references from process environment variables.
///
/// References without the `env:` scheme are not resolved (returns `None`), so a literal
/// secret accidentally placed in an identity record is never used.
#[derive(Debug, Default, Clone)]
pub struct EnvSecretStore;

impl SecretStore for EnvSecretStore {
    fn get(&self, reference: &str) -> Option<String> {
        let name = reference.strip_prefix("env:")?;
        std::env::var(name).ok()
    }
}

/// An in-memory store for tests and manifests that inline (already non-production) secrets.
#[derive(Debug, Default, Clone)]
pub struct MapSecretStore {
    secrets: HashMap<String, String>,
}

impl MapSecretStore {
    /// An empty store.
    pub fn new() -> Self {
        MapSecretStore::default()
    }

    /// Insert a reference -> secret mapping, builder style.
    pub fn with(mut self, reference: impl Into<String>, secret: impl Into<String>) -> Self {
        self.secrets.insert(reference.into(), secret.into());
        self
    }
}

impl SecretStore for MapSecretStore {
    fn get(&self, reference: &str) -> Option<String> {
        self.secrets.get(reference).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_store_only_resolves_env_scheme() {
        std::env::set_var("AUTHZ_TEST_TOKEN_X", "s3cr3t");
        let store = EnvSecretStore;
        assert_eq!(store.get("env:AUTHZ_TEST_TOKEN_X").as_deref(), Some("s3cr3t"));
        assert_eq!(store.get("AUTHZ_TEST_TOKEN_X"), None);
        assert_eq!(store.get("env:AUTHZ_TEST_MISSING"), None);
        std::env::remove_var("AUTHZ_TEST_TOKEN_X");
    }

    #[test]
    fn map_store_round_trips() {
        let store = MapSecretStore::new()
            .with("env:A", "tok-a")
            .with("vault:b", "tok-b");
        assert_eq!(store.get("env:A").as_deref(), Some("tok-a"));
        assert_eq!(store.get("vault:b").as_deref(), Some("tok-b"));
        assert_eq!(store.get("env:missing"), None);
    }
}
