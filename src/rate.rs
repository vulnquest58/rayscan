use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// A global token bucket shared by every scan worker.
#[derive(Debug)]
pub struct RateLimiter {
    bucket: Option<Mutex<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rate: u64) -> Self {
        if rate == 0 {
            return Self { bucket: None };
        }

        let rate = rate as f64;
        let burst = (rate / 10.0).clamp(1.0, 1_000.0);
        Self {
            bucket: Some(Mutex::new(Bucket {
                rate,
                burst,
                tokens: burst,
                last: Instant::now(),
            })),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.bucket.is_none()
    }

    pub fn set_rate(&self, rate: u64) {
        let Some(bucket) = &self.bucket else {
            return;
        };
        let mut bucket = bucket.lock().expect("rate limiter lock poisoned");
        bucket.refill();
        bucket.rate = rate as f64;
        bucket.burst = (rate as f64 / 10.0).clamp(1.0, 1_000.0);
        bucket.tokens = bucket.tokens.min(bucket.burst);
    }

    pub async fn acquire(&self) {
        let Some(bucket) = &self.bucket else {
            return;
        };

        loop {
            let wait = {
                let mut bucket = bucket.lock().expect("rate limiter lock poisoned");
                bucket.refill();
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - bucket.tokens) / bucket.rate)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
    }
}

/// Adaptive rate controller for connect scans.
///
/// Observes completed probes in fixed-size windows and adjusts the rate:
/// - If > 25% of probes in a window time out (filtered), the rate is halved.
/// - If < 5% time out, the rate is increased by 25% up to the ceiling.
/// - Otherwise the rate is held constant.
///
/// The controller is not thread-safe; it lives in the scan receiver loop.
#[derive(Debug)]
pub struct AdaptiveRate {
    window: u64,
    observed: u64,
    timeouts: u64,
    current: u64,
    floor: u64,
    ceiling: u64,
}

impl AdaptiveRate {
    pub fn new(ceiling: u64, floor: u64) -> Self {
        let ceiling = ceiling.max(floor).max(1);
        Self {
            window: 500,
            observed: 0,
            timeouts: 0,
            current: ceiling,
            floor,
            ceiling,
        }
    }

    pub fn current_rate(&self) -> u64 {
        self.current
    }

    /// Record one probe result. Returns the new rate when it changes.
    pub fn observe(&mut self, timed_out: bool) -> Option<u64> {
        self.observed += 1;
        if timed_out {
            self.timeouts += 1;
        }
        if self.observed < self.window {
            return None;
        }
        let ratio = self.timeouts as f64 / self.observed as f64;
        let new_rate = if ratio > 0.25 {
            (self.current as f64 * 0.5).max(self.floor as f64) as u64
        } else if ratio < 0.05 {
            (self.current as f64 * 1.25).min(self.ceiling as f64) as u64
        } else {
            self.current
        };
        self.observed = 0;
        self.timeouts = 0;
        if new_rate != self.current {
            self.current = new_rate;
            Some(new_rate)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_rate_is_unlimited() {
        assert!(RateLimiter::new(0).is_unlimited());
        assert!(!RateLimiter::new(1).is_unlimited());
    }

    #[tokio::test]
    async fn zero_rate_never_yields() {
        let limiter = RateLimiter::new(0);
        let start = Instant::now();
        for _ in 0..10_000 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn limited_rate_consumes_the_burst_first() {
        let limiter = RateLimiter::new(100);
        let start = Instant::now();
        for _ in 0..10 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn adaptive_rate_halves_on_heavy_timeouts() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..374 {
            assert_eq!(adaptive.observe(false), None);
        }
        for _ in 0..125 {
            assert_eq!(adaptive.observe(true), None);
        }
        assert_eq!(adaptive.observe(true), Some(250));
    }

    #[test]
    fn adaptive_rate_increases_on_low_timeouts() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..499 {
            assert_eq!(adaptive.observe(false), None);
        }
        assert_eq!(adaptive.observe(false), Some(625));
    }
}
