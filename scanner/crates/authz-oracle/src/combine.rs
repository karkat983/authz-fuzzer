//! Combining repeated observations into a single verdict.
//!
//! A verified finding must be *reproducible*. The oracle judges one observation at a time;
//! this function takes the verdicts from several replays of the same probe and decides the
//! final confidence. A violation is only [`Confidence::Verified`] when it reproduced in
//! every replay and at least the required number of replays were run; a flaky effect (seen
//! in some replays but not others) is downgraded to [`Confidence::Probable`] or
//! [`Confidence::Speculative`].

use std::collections::HashMap;

use authz_core::{Confidence, ViolationType};

use crate::verdict::OracleVerdict;

/// Combine the verdicts from repeated probes into one.
///
/// `required` is the minimum number of consistent reproductions needed to reach
/// `Verified`. Typical value is 2 or 3.
pub fn combine_reproductions(verdicts: &[OracleVerdict], required: u32) -> OracleVerdict {
    if verdicts.is_empty() {
        return OracleVerdict::inconclusive("no observations");
    }
    let total = verdicts.len();

    // Collect the (violation type, is_write) key and per-observation confidence.
    let mut violations: Vec<(ViolationType, bool, Confidence)> = Vec::new();
    let mut any_inconclusive = false;
    for v in verdicts {
        match v {
            OracleVerdict::Violation {
                violation,
                confidence,
                is_write,
                ..
            } => violations.push((*violation, *is_write, *confidence)),
            OracleVerdict::Inconclusive { .. } => any_inconclusive = true,
            OracleVerdict::NoViolation { .. } => {}
        }
    }

    if violations.is_empty() {
        return if any_inconclusive {
            OracleVerdict::inconclusive("no violation observed; some observations were inconclusive")
        } else {
            OracleVerdict::ok("consistently no violation across all replays")
        };
    }

    // Find the modal (type, is_write).
    let mut counts: HashMap<(ViolationType, bool), usize> = HashMap::new();
    for (t, w, _) in &violations {
        *counts.entry((*t, *w)).or_default() += 1;
    }
    let (&(modal_type, modal_write), _) = counts
        .iter()
        .max_by_key(|(_, &n)| n)
        .expect("at least one violation");

    let consistent: Vec<&(ViolationType, bool, Confidence)> = violations
        .iter()
        .filter(|(t, w, _)| *t == modal_type && *w == modal_write)
        .collect();
    let consistent_n = consistent.len();
    let max_conf = consistent
        .iter()
        .map(|(_, _, c)| *c)
        .max()
        .unwrap_or(Confidence::Speculative);

    let all_agree = consistent_n == total;
    let reproduced = consistent_n as u32 >= required;

    let final_conf = if all_agree && reproduced && max_conf == Confidence::Verified {
        Confidence::Verified
    } else if all_agree && reproduced {
        // Reproduced consistently, but the strongest single-observation evidence was only
        // Probable (e.g. a 2xx write with no confirmed state change each time).
        Confidence::Probable
    } else if reproduced {
        // Seen in enough replays but not all: flaky. Downgrade a would-be Verified.
        Confidence::Probable
    } else {
        Confidence::Speculative
    };

    let rationale = format!(
        "violation observed in {consistent_n}/{total} replays (required {required} for verified)"
    );
    OracleVerdict::violation(modal_type, final_conf, modal_write, rationale)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified(t: ViolationType, write: bool) -> OracleVerdict {
        OracleVerdict::violation(t, Confidence::Verified, write, "x")
    }
    fn probable(t: ViolationType, write: bool) -> OracleVerdict {
        OracleVerdict::violation(t, Confidence::Probable, write, "x")
    }
    fn clean() -> OracleVerdict {
        OracleVerdict::ok("denied")
    }

    #[test]
    fn single_verified_observation_is_downgraded_without_reproduction() {
        let v = combine_reproductions(&[verified(ViolationType::Bola, false)], 2);
        assert_eq!(v.confidence(), Some(Confidence::Speculative));
    }

    #[test]
    fn consistent_verified_reproductions_stay_verified() {
        let v = combine_reproductions(
            &[
                verified(ViolationType::CrossTenantAccess, false),
                verified(ViolationType::CrossTenantAccess, false),
                verified(ViolationType::CrossTenantAccess, false),
            ],
            2,
        );
        assert_eq!(v.confidence(), Some(Confidence::Verified));
        assert_eq!(v.violation_type(), Some(ViolationType::CrossTenantAccess));
    }

    #[test]
    fn flaky_violation_is_downgraded_to_probable() {
        // verified twice, clean once -> not all agree, but reproduced >= 2
        let v = combine_reproductions(
            &[
                verified(ViolationType::Bola, false),
                clean(),
                verified(ViolationType::Bola, false),
            ],
            2,
        );
        assert_eq!(v.confidence(), Some(Confidence::Probable));
    }

    #[test]
    fn one_off_among_clean_is_speculative() {
        let v = combine_reproductions(
            &[verified(ViolationType::Bola, false), clean(), clean()],
            2,
        );
        assert_eq!(v.confidence(), Some(Confidence::Speculative));
    }

    #[test]
    fn consistently_clean_is_no_violation() {
        let v = combine_reproductions(&[clean(), clean()], 2);
        assert!(!v.is_violation());
    }

    #[test]
    fn all_probable_reproductions_cap_at_probable() {
        let v = combine_reproductions(
            &[
                probable(ViolationType::Bola, true),
                probable(ViolationType::Bola, true),
            ],
            2,
        );
        assert_eq!(v.confidence(), Some(Confidence::Probable));
    }

    #[test]
    fn empty_is_inconclusive() {
        assert!(matches!(
            combine_reproductions(&[], 2),
            OracleVerdict::Inconclusive { .. }
        ));
    }

    #[test]
    fn inconclusive_only_stays_inconclusive() {
        let v = combine_reproductions(
            &[
                OracleVerdict::inconclusive("500"),
                OracleVerdict::inconclusive("timeout"),
            ],
            2,
        );
        assert!(matches!(v, OracleVerdict::Inconclusive { .. }));
    }
}
