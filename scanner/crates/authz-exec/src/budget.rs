//! The request budget.
//!
//! A scan declares a maximum number of requests. [`RequestBudget`] is a shared atomic
//! counter the guard consults before each send; once exhausted, no further requests are
//! admitted. It is cloneable and thread-safe so the whole worker pool shares one budget.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A shared, atomic request counter bounded by a maximum.
#[derive(Debug, Clone)]
pub struct RequestBudget {
    used: Arc<AtomicU64>,
    max: u64,
}

impl RequestBudget {
    /// A budget permitting `max` requests.
    pub fn new(max: u64) -> Self {
        RequestBudget {
            used: Arc::new(AtomicU64::new(0)),
            max,
        }
    }

    /// Atomically reserve one request. Returns `true` if within budget (and counts it),
    /// `false` if the budget is already exhausted (and does not count it).
    pub fn try_reserve(&self) -> bool {
        // Compare-and-swap loop so concurrent reservations never exceed the max.
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            if used >= self.max {
                return false;
            }
            match self.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => used = actual,
            }
        }
    }

    /// How many requests have been counted.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// How many requests remain.
    pub fn remaining(&self) -> u64 {
        self.max.saturating_sub(self.used())
    }

    /// The maximum.
    pub fn max(&self) -> u64 {
        self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_up_to_the_max() {
        let b = RequestBudget::new(3);
        assert!(b.try_reserve());
        assert!(b.try_reserve());
        assert!(b.try_reserve());
        assert!(!b.try_reserve());
        assert_eq!(b.used(), 3);
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn concurrent_reservations_do_not_exceed_max() {
        let b = RequestBudget::new(1000);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let b = b.clone();
            handles.push(std::thread::spawn(move || {
                let mut count = 0;
                while b.try_reserve() {
                    count += 1;
                }
                count
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 1000);
        assert_eq!(b.used(), 1000);
    }
}
