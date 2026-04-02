use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

/// A simple sliding-window rate limiter (token bucket).
///
/// Tracks timestamps of past requests and allows up to `max_per_minute`
/// requests within any 60-second window.
pub struct RateLimiter {
    max_per_minute: u32,
    timestamps: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given per-minute cap.
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    /// Try to acquire a slot.
    ///
    /// Returns `true` if the request is allowed (a new timestamp is recorded).
    /// Returns `false` if the per-minute limit has been reached.
    pub fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        let mut ts = self.timestamps.lock().expect("rate limiter lock poisoned");

        // Evict entries older than 60 seconds.
        while let Some(&front) = ts.front() {
            if now.duration_since(front) > window {
                ts.pop_front();
            } else {
                break;
            }
        }

        if (ts.len() as u32) < self.max_per_minute {
            ts.push_back(now);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_up_to_limit_succeeds() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
    }

    #[test]
    fn acquire_beyond_limit_fails() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire(), "third request should be denied");
    }

    #[test]
    fn old_entries_expire() {
        let limiter = RateLimiter::new(1);

        // Manually insert an entry far in the past.
        {
            let mut ts = limiter.timestamps.lock().unwrap();
            ts.push_back(Instant::now() - std::time::Duration::from_secs(120));
        }

        // The old entry should have been evicted, so this should succeed.
        assert!(
            limiter.try_acquire(),
            "should succeed after old entries expire"
        );
    }

    #[test]
    fn zero_limit_always_rejects() {
        let limiter = RateLimiter::new(0);
        assert!(!limiter.try_acquire());
    }
}
