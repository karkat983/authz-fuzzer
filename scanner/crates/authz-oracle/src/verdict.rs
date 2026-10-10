//! The oracle's output.

use authz_core::{Confidence, ViolationType};

/// What an oracle concluded from one set of observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OracleVerdict {
    /// The system behaved as authorization policy expects. No finding.
    NoViolation {
        /// A short reason, for the audit trail (e.g. "properly denied with 403").
        rationale: String,
    },
    /// An unauthorized effect was observed.
    Violation {
        /// The kind of weakness.
        violation: ViolationType,
        /// How strongly the evidence supports it, for a single observation.
        confidence: Confidence,
        /// Whether the offending access was a state-changing write.
        is_write: bool,
        /// A human explanation of expected-versus-observed.
        rationale: String,
    },
    /// The observation was ambiguous (server error, redirect to login, missing
    /// reference). Not a finding, but worth surfacing so a human can decide.
    Inconclusive {
        /// Why the oracle could not decide.
        reason: String,
    },
}

impl OracleVerdict {
    /// Convenience constructor for a clean result.
    pub fn ok(rationale: impl Into<String>) -> Self {
        OracleVerdict::NoViolation {
            rationale: rationale.into(),
        }
    }

    /// Convenience constructor for a violation.
    pub fn violation(
        violation: ViolationType,
        confidence: Confidence,
        is_write: bool,
        rationale: impl Into<String>,
    ) -> Self {
        OracleVerdict::Violation {
            violation,
            confidence,
            is_write,
            rationale: rationale.into(),
        }
    }

    /// Convenience constructor for an ambiguous result.
    pub fn inconclusive(reason: impl Into<String>) -> Self {
        OracleVerdict::Inconclusive {
            reason: reason.into(),
        }
    }

    /// Whether this verdict is a violation.
    pub fn is_violation(&self) -> bool {
        matches!(self, OracleVerdict::Violation { .. })
    }

    /// The violation type, if any.
    pub fn violation_type(&self) -> Option<ViolationType> {
        match self {
            OracleVerdict::Violation { violation, .. } => Some(*violation),
            _ => None,
        }
    }

    /// The confidence, if this is a violation.
    pub fn confidence(&self) -> Option<Confidence> {
        match self {
            OracleVerdict::Violation { confidence, .. } => Some(*confidence),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors() {
        let v = OracleVerdict::violation(
            ViolationType::Bola,
            Confidence::Probable,
            false,
            "x",
        );
        assert!(v.is_violation());
        assert_eq!(v.violation_type(), Some(ViolationType::Bola));
        assert_eq!(v.confidence(), Some(Confidence::Probable));

        let ok = OracleVerdict::ok("denied");
        assert!(!ok.is_violation());
        assert_eq!(ok.violation_type(), None);
        assert_eq!(ok.confidence(), None);
    }
}
