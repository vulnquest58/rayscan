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
}
