//! Content fingerprints.
//!
//! A [`Fingerprint`] is a SHA-256 over a caller-supplied sequence of fields. It is used
//! in two places: to give evidence content-addressed references (so an evidence blob can
//! be verified against its id) and to deduplicate findings (so the same authorization
//! weakness reported by two scans collapses to one record).
//!
//! The builder hashes a length prefix before each field so that `["ab", "c"]` and
//! `["a", "bc"]` produce different digests — a subtle but important property when the
//! fields are attacker-influenced strings.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest, rendered as lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Start building a fingerprint over one or more fields.
    pub fn builder() -> FingerprintBuilder {
        FingerprintBuilder {
            hasher: Sha256::new(),
        }
    }

    /// Fingerprint a single byte slice directly.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Fingerprint::builder().field_bytes(bytes).finish()
    }

    /// The raw 32 bytes of the digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// A content-addressed evidence URI of the form `evidence://sha256/<hex>`.
    ///
    /// The platform's evidence store (see the evidence-storage spec) resolves these.
    pub fn evidence_uri(&self) -> String {
        format!("evidence://sha256/{}", self.to_hex())
    }

    /// Parse a fingerprint from a hex string, returning `None` if it is not 64 hex chars.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Fingerprint(arr))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Accumulates fields into a [`Fingerprint`].
///
/// Each field is preceded by its length as an 8-byte big-endian prefix, so distinct field
/// boundaries always produce distinct digests.
pub struct FingerprintBuilder {
    hasher: Sha256,
}

impl FingerprintBuilder {
    /// Add a length-prefixed byte field.
    pub fn field_bytes(mut self, bytes: &[u8]) -> Self {
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
        self
    }

    /// Add a length-prefixed string field.
    pub fn field(self, s: &str) -> Self {
        self.field_bytes(s.as_bytes())
    }

    /// Add an optional string field; `None` is distinct from `Some("")`.
    pub fn field_opt(self, s: Option<&str>) -> Self {
        match s {
            Some(v) => self.field("some").field(v),
            None => self.field("none"),
        }
    }

    /// Finish and produce the digest.
    pub fn finish(self) -> Fingerprint {
        Fingerprint(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let fp = Fingerprint::of_bytes(b"hello");
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Fingerprint::from_hex(&hex), Some(fp));
    }

    #[test]
    fn length_prefix_prevents_field_ambiguity() {
        let a = Fingerprint::builder().field("ab").field("c").finish();
        let b = Fingerprint::builder().field("a").field("bc").finish();
        assert_ne!(a, b, "concatenation collision must not occur");
    }

    #[test]
    fn some_empty_differs_from_none() {
        let some = Fingerprint::builder().field_opt(Some("")).finish();
        let none = Fingerprint::builder().field_opt(None).finish();
        assert_ne!(some, none);
    }

    #[test]
    fn known_vector_is_sha256() {
        // SHA-256 of the length-prefixed field: 8 zero bytes then nothing.
        let empty = Fingerprint::builder().field("").finish();
        // Stable across runs; guards against accidental hasher changes.
        assert_eq!(&empty.to_hex()[..8], "af5570f5");
    }

    #[test]
    fn evidence_uri_format() {
        let fp = Fingerprint::of_bytes(b"x");
        assert!(fp.evidence_uri().starts_with("evidence://sha256/"));
        assert_eq!(fp.evidence_uri().len(), "evidence://sha256/".len() + 64);
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(Fingerprint::from_hex("nothex"), None);
        assert_eq!(Fingerprint::from_hex("ab"), None);
    }
}
