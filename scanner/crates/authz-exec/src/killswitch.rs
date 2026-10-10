//! The kill switch.
//!
//! A scan can be cancelled at any time. [`KillSwitch`] is a shared flag the guard checks
//! before every request; once tripped, no new request is admitted (in-flight requests are
//! allowed to finish). It is cloneable so the CLI's signal handler and the worker pool
//! share one switch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shared cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct KillSwitch {
    tripped: Arc<AtomicBool>,
}

impl KillSwitch {
    /// A new, untripped switch.
    pub fn new() -> Self {
        KillSwitch::default()
    }

    /// Trip the switch: no further requests will be admitted.
    pub fn trip(&self) {
        self.tripped.store(true, Ordering::SeqCst);
    }

    /// Whether the switch has been tripped.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_untripped_and_trips_once() {
        let k = KillSwitch::new();
        assert!(!k.is_tripped());
        k.trip();
        assert!(k.is_tripped());
    }

    #[test]
    fn clones_share_state() {
        let a = KillSwitch::new();
        let b = a.clone();
        a.trip();
        assert!(b.is_tripped());
    }
}
