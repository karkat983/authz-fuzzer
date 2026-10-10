//! The scope guard — the single checkpoint every request passes before it is sent.
//!
//! [`ScopeGuard::check`] enforces, in order: the kill switch (is the scan cancelled?), the
//! [`authz_core::Scope`] (is this host and method in scope, and is mutation permitted?),
//! and the [`RequestBudget`] (is there budget left?). All three fail closed, and the
//! budget is only consumed once the host/method checks pass, so an out-of-scope attempt
//! never spends budget.

use std::sync::Arc;

use thiserror::Error;

use authz_core::{HttpMethod, Scope, ScopeError};

use crate::budget::RequestBudget;
use crate::killswitch::KillSwitch;

/// Why a request was refused by the guard.
#[derive(Debug, Error, PartialEq)]
pub enum GuardError {
    /// The scan has been cancelled.
    #[error("scan cancelled")]
    Cancelled,
    /// The request is outside the authorized scope.
    #[error(transparent)]
    OutOfScope(#[from] ScopeError),
    /// The request budget is exhausted.
    #[error("request budget exhausted")]
    BudgetExhausted,
}

/// Combines the scope, budget and kill switch into one admission check.
#[derive(Clone)]
pub struct ScopeGuard {
    scope: Arc<Scope>,
    budget: RequestBudget,
    kill: KillSwitch,
}

impl ScopeGuard {
    /// Build a guard over a scope, budget and kill switch.
    pub fn new(scope: Arc<Scope>, budget: RequestBudget, kill: KillSwitch) -> Self {
        ScopeGuard {
            scope,
            budget,
            kill,
        }
    }

    /// Admit (or refuse) one request to `host` with `method`. On success, one unit of
    /// budget has been consumed.
    pub fn check(&self, method: HttpMethod, host: &str) -> Result<(), GuardError> {
        if self.kill.is_tripped() {
            return Err(GuardError::Cancelled);
        }
        self.scope.admits(method, host)?;
        if !self.budget.try_reserve() {
            return Err(GuardError::BudgetExhausted);
        }
        Ok(())
    }

    /// The underlying scope.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The remaining request budget.
    pub fn budget_remaining(&self) -> u64 {
        self.budget.remaining()
    }

    /// Trip the kill switch for this scan.
    pub fn cancel(&self) {
        self.kill.trip();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{IdentityId, MutationPolicy, TargetRef};

    fn guard(max_requests: u64) -> ScopeGuard {
        let mut scope = Scope::read_only(
            TargetRef {
                name: "t".into(),
                base_url: "https://api.test".into(),
            },
            "api.test",
            vec![IdentityId::new("alpha")],
        );
        scope.max_requests = max_requests;
        ScopeGuard::new(
            Arc::new(scope),
            RequestBudget::new(max_requests),
            KillSwitch::new(),
        )
    }

    #[test]
    fn admits_in_scope_safe_request() {
        let g = guard(10);
        assert!(g.check(HttpMethod::Get, "api.test").is_ok());
        assert_eq!(g.budget_remaining(), 9);
    }

    #[test]
    fn out_of_scope_host_does_not_consume_budget() {
        let g = guard(10);
        assert!(matches!(
            g.check(HttpMethod::Get, "evil.test"),
            Err(GuardError::OutOfScope(_))
        ));
        assert_eq!(g.budget_remaining(), 10, "refused request must not spend budget");
    }

    #[test]
    fn mutation_refused_under_read_only_policy() {
        let g = guard(10);
        assert!(matches!(
            g.check(HttpMethod::Delete, "api.test"),
            Err(GuardError::OutOfScope(ScopeError::MethodNotPermitted(_)))
        ));
    }

    #[test]
    fn mutation_allowed_when_policy_permits() {
        let mut scope = Scope::read_only(
            TargetRef { name: "t".into(), base_url: "https://api.test".into() },
            "api.test",
            vec![IdentityId::new("a")],
        );
        scope.mutation = MutationPolicy::TestOwnedOnly;
        scope.permitted_methods.insert(HttpMethod::Post);
        let g = ScopeGuard::new(Arc::new(scope), RequestBudget::new(5), KillSwitch::new());
        assert!(g.check(HttpMethod::Post, "api.test").is_ok());
    }

    #[test]
    fn budget_exhaustion_is_reported() {
        let g = guard(1);
        assert!(g.check(HttpMethod::Get, "api.test").is_ok());
        assert_eq!(g.check(HttpMethod::Get, "api.test"), Err(GuardError::BudgetExhausted));
    }

    #[test]
    fn cancellation_blocks_everything() {
        let g = guard(10);
        g.cancel();
        assert_eq!(g.check(HttpMethod::Get, "api.test"), Err(GuardError::Cancelled));
    }
}
