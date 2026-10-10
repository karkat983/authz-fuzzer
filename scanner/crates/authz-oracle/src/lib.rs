//! The authorization oracle.
//!
//! An oracle answers one question: *given what we observed, was there an unauthorized
//! effect?* It is the most safety-critical logic in the scanner, and it follows two rules
//! from the oracle spec without exception:
//!
//! 1. **Never infer a vulnerability from a 2xx status alone.** A read is a disclosure only
//!    when the attacker's response actually contains the owner's object (confirmed by
//!    comparing against an owner-visible reference). A write is a violation only when the
//!    owner's state actually changed — regardless of whether the attacker's request
//!    returned 200 or 403.
//! 2. **Distinguish denial from disclosure.** A 401/403, or a 404 that hides an object the
//!    owner can see, is correct behaviour, not a finding.
//!
//! The oracle is pure: it takes observations in and returns a [`verdict::OracleVerdict`].
//! Reproduction (running a probe several times and requiring the effect to recur before
//! calling it [`authz_core::Confidence::Verified`]) is combined separately in
//! [`combine`], so the executor controls how much evidence a "verified" label requires.

pub mod body;
pub mod combine;
pub mod policy;
pub mod read;
pub mod verdict;
pub mod write;

pub use combine::combine_reproductions;
pub use policy::Expectation;
pub use read::{read_oracle, ReadObservation};
pub use verdict::OracleVerdict;
pub use write::{write_oracle, WriteObservation};
