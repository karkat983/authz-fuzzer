//! The cleanup journal.
//!
//! When a scan is permitted to create test resources (to exercise write paths against
//! objects it owns), it must be able to remove them afterwards. Every created resource is
//! recorded here with the request that deletes it; [`CleanupJournal::deletion_requests`]
//! yields those so the executor can replay them at the end of the scan, leaving no
//! orphaned test data.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use authz_core::HttpMethod;
use authz_http::HttpRequest;

/// A resource the scan created and is responsible for deleting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedResource {
    /// The absolute URL of the created resource instance.
    pub url: String,
    /// The identity id that created it (and that should delete it).
    pub owner_identity: String,
    /// Whether cleanup has already been performed.
    pub cleaned: bool,
}

/// A thread-safe record of resources created during a scan.
#[derive(Debug, Default)]
pub struct CleanupJournal {
    created: Mutex<Vec<CreatedResource>>,
}

impl CleanupJournal {
    /// An empty journal.
    pub fn new() -> Self {
        CleanupJournal::default()
    }

    /// Record that a resource was created at `url` by `owner_identity`.
    pub fn record(&self, url: impl Into<String>, owner_identity: impl Into<String>) {
        self.created.lock().unwrap().push(CreatedResource {
            url: url.into(),
            owner_identity: owner_identity.into(),
            cleaned: false,
        });
    }

    /// All recorded resources (a snapshot).
    pub fn all(&self) -> Vec<CreatedResource> {
        self.created.lock().unwrap().clone()
    }

    /// The number of resources still awaiting cleanup.
    pub fn pending_count(&self) -> usize {
        self.created.lock().unwrap().iter().filter(|r| !r.cleaned).count()
    }

    /// DELETE requests for every resource not yet cleaned, made as the creating identity.
    pub fn deletion_requests(&self) -> Vec<HttpRequest> {
        self.created
            .lock()
            .unwrap()
            .iter()
            .filter(|r| !r.cleaned)
            .map(|r| HttpRequest::new(HttpMethod::Delete, &r.url).as_identity(&r.owner_identity))
            .collect()
    }

    /// Mark the resource at `url` as cleaned.
    pub fn mark_cleaned(&self, url: &str) {
        for r in self.created.lock().unwrap().iter_mut() {
            if r.url == url {
                r.cleaned = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_produces_deletion_requests() {
        let j = CleanupJournal::new();
        j.record("https://api.test/orders/t1", "alpha-admin");
        j.record("https://api.test/orders/t2", "alpha-admin");
        assert_eq!(j.pending_count(), 2);
        let dels = j.deletion_requests();
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0].method, HttpMethod::Delete);
        assert_eq!(dels[0].identity_id.as_deref(), Some("alpha-admin"));
    }

    #[test]
    fn marking_cleaned_removes_from_pending() {
        let j = CleanupJournal::new();
        j.record("https://api.test/orders/t1", "a");
        j.mark_cleaned("https://api.test/orders/t1");
        assert_eq!(j.pending_count(), 0);
        assert!(j.deletion_requests().is_empty());
        assert!(j.all()[0].cleaned);
    }
}
