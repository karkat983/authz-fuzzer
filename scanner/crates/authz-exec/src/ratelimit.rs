//! A token-bucket rate limiter.
//!
//! An authorized scan declares a requests-per-second ceiling so it never overwhelms the
//! target. [`TokenBucket`] enforces it: [`TokenBucket::acquire`] waits until a token is
//! available. The refill maths is exposed as [`TokenBucket::try_take_at`] taking an
//! explicit instant, so the behaviour can be tested deterministically without real time.

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

struct Bucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }
}

/// A shared token bucket limiting requests per second.
pub struct TokenBucket {
    inner: Mutex<Bucket>,
}

impl TokenBucket {
    /// Build a bucket allowing `rate_per_sec` requests per second with a burst capacity of
    /// `burst` (minimum 1). The bucket starts full.
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        let capacity = burst.max(1) as f64;
        TokenBucket {
            inner: Mutex::new(Bucket {
                tokens: capacity,
                capacity,
                refill_per_sec: rate_per_sec.max(1) as f64,
                last: Instant::now(),
            }),
        }
    }

    /// Try to take a token as of `now`. On success returns `Ok(())`; otherwise returns the
    /// [`Duration`] the caller should wait before a token will be available.
    pub fn try_take_at(&self, now: Instant) -> Result<(), Duration> {
        let mut bucket = self.inner.lock().unwrap();
        bucket.refill(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - bucket.tokens;
            let secs = needed / bucket.refill_per_sec;
            Err(Duration::from_secs_f64(secs))
        }
    }

    /// Await a token, sleeping as needed.
    pub async fn acquire(&self) {
        loop {
            match self.try_take_at(Instant::now()) {
                Ok(()) => return,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }

    /// The number of whole tokens currently available (for diagnostics/tests).
    pub fn available_at(&self, now: Instant) -> u32 {
        let mut bucket = self.inner.lock().unwrap();
        bucket.refill(now);
        bucket.tokens.floor().max(0.0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_is_consumed_then_refills_over_time() {
        let bucket = TokenBucket::new(10, 3); // 10/s, burst 3
        let t0 = Instant::now();
        // three immediate tokens
        assert!(bucket.try_take_at(t0).is_ok());
        assert!(bucket.try_take_at(t0).is_ok());
        assert!(bucket.try_take_at(t0).is_ok());
        // fourth is denied, with a wait of about 1/10 s
        let wait = bucket.try_take_at(t0).unwrap_err();
        assert!(wait.as_secs_f64() > 0.09 && wait.as_secs_f64() < 0.11);
        // after 0.3 s, three tokens have refilled
        let t1 = t0 + Duration::from_millis(300);
        assert_eq!(bucket.available_at(t1), 3);
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let bucket = TokenBucket::new(100, 5);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(bucket.try_take_at(t0).is_ok());
        }
        // a long time later, tokens cap at burst=5, not unbounded
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(bucket.available_at(t1), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_waits_and_then_proceeds() {
        let bucket = TokenBucket::new(5, 1); // 5/s, burst 1
        // first acquire is immediate
        bucket.acquire().await;
        // the second must wait ~0.2 s; with paused time the sleep auto-advances
        let start = Instant::now();
        bucket.acquire().await;
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(190), "waited {waited:?}");
    }
}
