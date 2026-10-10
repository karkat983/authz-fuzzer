//! HTTP transport and evidence capture for the AuthZ Fuzzer.
//!
//! This crate is the only place the scanner touches the network. It defines a small
//! [`HttpRequest`]/[`HttpResponse`] model, a [`Transport`] trait with a real reqwest
//! backend ([`ReqwestTransport`]) and an in-memory [`MockTransport`] for tests, and the
//! [`Capture`] evidence record.
//!
//! Two safety properties live here:
//!
//! * **Redaction.** A [`Capture`] never stores `Authorization`, `Cookie` or `Set-Cookie`
//!   headers, so evidence can be persisted and shown without leaking credentials (a
//!   requirement from the threat model).
//! * **Determinism for the oracle.** [`HttpResponse::canonical_body`] produces a stable
//!   byte form (JSON with sorted keys when the body parses as JSON) so that the oracle's
//!   owner-vs-attacker body comparison does not flap on key ordering.

pub mod capture;
pub mod redact;
pub mod request;
pub mod transport;

pub use capture::Capture;
pub use request::{HttpRequest, HttpResponse};
pub use transport::{MockTransport, ReqwestTransport, Transport, TransportError};
