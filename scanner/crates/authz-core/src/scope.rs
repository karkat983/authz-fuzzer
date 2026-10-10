//! The authorized scan scope.
//!
//! Every request the scanner makes must be inside a [`Scope`]: a declared target, a host
//! allowlist, a set of permitted methods, hard request and time budgets, and an explicit
//! mutation policy. The scope is the safety contract — the executor consults
//! [`Scope::admits`] before *every* request and refuses anything outside it. This is what
//! turns a fuzzer into an *authorized* testing tool.
//!
//! Scopes are designed to fail closed: mutation is forbidden unless explicitly allowed,
//! and a host not on the allowlist is rejected even if it is a subdomain of the target.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http::HttpMethod;
use crate::identity::IdentityId;

/// Whether the scan may perform state-changing (unsafe) requests, and against what.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPolicy {
    /// No unsafe methods at all. The safe default.
    ReadOnly,
    /// Unsafe methods permitted, but only against resources the scan itself created
    /// (tracked in the cleanup journal). Production data is never written.
    TestOwnedOnly,
    /// Unsafe methods permitted broadly. Requires an explicit, signed high-risk scope.
    Unrestricted,
}

impl MutationPolicy {
    /// Whether any mutation is permitted under this policy.
    pub fn allows_mutation(self) -> bool {
        !matches!(self, MutationPolicy::ReadOnly)
    }
}

/// A reference to the target under test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRef {
    /// A human label for the target (e.g. "orders-api-staging").
    pub name: String,
    /// The base URL, e.g. `https://staging.example.test/api`.
    pub base_url: String,
}

/// Errors returned when a request is checked against a scope.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    /// The request host is not on the allowlist.
    #[error("host {host:?} is not in the scope allowlist")]
    HostNotAllowed {
        /// The rejected host.
        host: String,
    },
    /// The method is not permitted by this scope.
    #[error("method {0} is not permitted by this scope")]
    MethodNotPermitted(HttpMethod),
    /// A mutating method was attempted but the mutation policy forbids it.
    #[error("mutating method {0} forbidden by the scope's mutation policy")]
    MutationForbidden(HttpMethod),
    /// The request budget has been exhausted.
    #[error("request budget of {budget} exhausted")]
    BudgetExhausted {
        /// The configured budget.
        budget: u64,
    },
    /// The scope itself is malformed.
    #[error("invalid scope: {0}")]
    Invalid(String),
}

/// A signed, bounded authorization to test a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// The target under test.
    pub target: TargetRef,
    /// Hosts the scanner may contact. A request to any other host is refused, which stops
    /// an out-of-scope redirect from quietly escaping the target.
    pub host_allowlist: BTreeSet<String>,
    /// Methods permitted. Empty means "all safe methods".
    pub permitted_methods: BTreeSet<HttpMethod>,
    /// Mutation policy.
    pub mutation: MutationPolicy,
    /// Maximum total requests the scan may make.
    pub max_requests: u64,
    /// Time budget in seconds.
    pub time_budget_secs: u64,
    /// Maximum concurrent in-flight requests.
    pub max_concurrency: u32,
    /// Requests-per-second ceiling (token-bucket rate).
    pub rate_limit_rps: u32,
    /// The test identities this scan is authorized to act as.
    pub identities: Vec<IdentityId>,
    /// An opaque signature over the scope, proving it was authorized. The CLI verifies
    /// this before running; it is checked for presence here, not cryptographically.
    pub authorization_signature: Option<String>,
}

impl Scope {
    /// Validate internal consistency of the scope.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.target.base_url.is_empty() {
            return Err(ScopeError::Invalid("target base_url is empty".into()));
        }
        if self.host_allowlist.is_empty() {
            return Err(ScopeError::Invalid("host allowlist is empty".into()));
        }
        if self.max_requests == 0 {
            return Err(ScopeError::Invalid("max_requests is zero".into()));
        }
        if self.max_concurrency == 0 {
            return Err(ScopeError::Invalid("max_concurrency is zero".into()));
        }
        if self.identities.is_empty() {
            return Err(ScopeError::Invalid("no test identities".into()));
        }
        Ok(())
    }

    /// Whether a method is permitted, taking the allowlist and mutation policy into account.
    pub fn method_permitted(&self, method: HttpMethod) -> Result<(), ScopeError> {
        let listed = self.permitted_methods.is_empty() && method.is_safe()
            || self.permitted_methods.contains(&method);
        if !listed {
            return Err(ScopeError::MethodNotPermitted(method));
        }
        if method.is_mutating() && !self.mutation.allows_mutation() {
            return Err(ScopeError::MutationForbidden(method));
        }
        Ok(())
    }

    /// Whether a host is on the allowlist. Matching is exact (case-insensitive); a
    /// subdomain is *not* implicitly in scope.
    pub fn host_allowed(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.host_allowlist
            .iter()
            .any(|allowed| allowed.to_ascii_lowercase() == h)
    }

    /// Check a prospective request: host, method and mutation policy. Does not consume
    /// budget; the executor tracks budget separately via [`Scope::check_budget`].
    pub fn admits(&self, method: HttpMethod, host: &str) -> Result<(), ScopeError> {
        if !self.host_allowed(host) {
            return Err(ScopeError::HostNotAllowed {
                host: host.to_string(),
            });
        }
        self.method_permitted(method)
    }

    /// Check that making one more request stays within the request budget, given how many
    /// have already been made.
    pub fn check_budget(&self, requests_made: u64) -> Result<(), ScopeError> {
        if requests_made >= self.max_requests {
            return Err(ScopeError::BudgetExhausted {
                budget: self.max_requests,
            });
        }
        Ok(())
    }

    /// A conservative default scope for a target: read-only, modest budgets.
    pub fn read_only(target: TargetRef, host: impl Into<String>, identities: Vec<IdentityId>) -> Self {
        let mut hosts = BTreeSet::new();
        hosts.insert(host.into());
        Scope {
            target,
            host_allowlist: hosts,
            permitted_methods: BTreeSet::new(),
            mutation: MutationPolicy::ReadOnly,
            max_requests: 5_000,
            time_budget_secs: 600,
            max_concurrency: 4,
            rate_limit_rps: 20,
            identities,
            authorization_signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope::read_only(
            TargetRef {
                name: "orders".into(),
                base_url: "https://staging.example.test/api".into(),
            },
            "staging.example.test",
            vec![IdentityId::new("alpha-admin")],
        )
    }

    #[test]
    fn read_only_scope_admits_safe_methods_only() {
        let s = scope();
        assert!(s.admits(HttpMethod::Get, "staging.example.test").is_ok());
        assert_eq!(
            s.admits(HttpMethod::Delete, "staging.example.test"),
            Err(ScopeError::MethodNotPermitted(HttpMethod::Delete))
        );
    }

    #[test]
    fn host_must_be_exactly_allowlisted() {
        let s = scope();
        assert!(s.host_allowed("staging.example.test"));
        assert!(s.host_allowed("STAGING.EXAMPLE.TEST"));
        assert!(!s.host_allowed("evil.example.test"));
        // a subdomain is not implicitly in scope
        assert!(!s.host_allowed("api.staging.example.test"));
        assert_eq!(
            s.admits(HttpMethod::Get, "evil.example.test"),
            Err(ScopeError::HostNotAllowed {
                host: "evil.example.test".into()
            })
        );
    }

    #[test]
    fn mutation_requires_policy_even_when_method_listed() {
        let mut s = scope();
        s.permitted_methods.insert(HttpMethod::Patch);
        // method is listed, but policy is ReadOnly
        assert_eq!(
            s.method_permitted(HttpMethod::Patch),
            Err(ScopeError::MutationForbidden(HttpMethod::Patch))
        );
        s.mutation = MutationPolicy::TestOwnedOnly;
        assert!(s.method_permitted(HttpMethod::Patch).is_ok());
    }

    #[test]
    fn budget_is_enforced() {
        let s = scope();
        assert!(s.check_budget(0).is_ok());
        assert!(s.check_budget(4_999).is_ok());
        assert_eq!(
            s.check_budget(5_000),
            Err(ScopeError::BudgetExhausted { budget: 5_000 })
        );
    }

    #[test]
    fn validate_catches_empty_fields() {
        let mut s = scope();
        assert!(s.validate().is_ok());
        s.host_allowlist.clear();
        assert!(matches!(s.validate(), Err(ScopeError::Invalid(_))));
    }

    #[test]
    fn mutation_policy_default_is_read_only() {
        assert!(!MutationPolicy::ReadOnly.allows_mutation());
        assert!(MutationPolicy::TestOwnedOnly.allows_mutation());
        assert!(MutationPolicy::Unrestricted.allows_mutation());
    }
}
