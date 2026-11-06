use std::time::Duration;

/// Per-host round-trip estimator based on RFC 6298.
///
/// Timeouts do not produce samples (Karn's rule); they increase a bounded
/// backoff instead. A successful connection resets the backoff.
#[derive(Clone, Debug, Default)]
pub struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    backoff: u32,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, sample: Duration) {
        let sample = sample.max(Duration::from_micros(1));

        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let srtt_seconds = srtt.as_secs_f64();
                let sample_seconds = sample.as_secs_f64();
                let variance_seconds = self.rttvar.as_secs_f64();
                let difference = (srtt_seconds - sample_seconds).abs();

                let new_variance = 0.75 * variance_seconds + 0.25 * difference;
                let new_srtt = 0.875 * srtt_seconds + 0.125 * sample_seconds;

                self.srtt = Some(Duration::from_secs_f64(new_srtt));
                self.rttvar = Duration::from_secs_f64(new_variance);
            }
        }

        self.backoff = 0;
    }

    pub fn on_timeout(&mut self) {
        self.backoff = (self.backoff + 1).min(4);
    }

    /// Return the current timeout clamped to the caller's bounds.
    pub fn timeout(&self, minimum: Duration, maximum: Duration) -> Duration {
        let minimum = minimum.min(maximum);
        let base = match self.srtt {
            Some(srtt) => srtt.saturating_add(self.rttvar.saturating_mul(4)),
            None => Duration::from_secs(1),
        };
        let scaled = base.saturating_mul(1u32 << self.backoff);

        scaled.max(minimum).min(maximum)
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_sets_srtt_and_variance() {
        let mut estimator = RttEstimator::new();
        estimator.observe(Duration::from_millis(20));

        assert_eq!(estimator.srtt(), Some(Duration::from_millis(20)));
        assert_eq!(
            estimator.timeout(Duration::from_millis(100), Duration::from_secs(2)),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn timeout_backs_off_and_success_resets_it() {
        let mut estimator = RttEstimator::new();
        estimator.observe(Duration::from_millis(10));
        let base = estimator.timeout(Duration::from_millis(1), Duration::from_secs(10));

        estimator.on_timeout();
        let backed_off = estimator.timeout(Duration::from_millis(1), Duration::from_secs(10));
        assert!(backed_off > base);

        estimator.observe(Duration::from_millis(10));
        let reset = estimator.timeout(Duration::from_millis(1), Duration::from_secs(10));
        assert!(reset < backed_off);
        assert!(reset >= Duration::from_millis(1));
    }

    #[test]
    fn initial_timeout_is_one_second_clamped_to_bounds() {
        let estimator = RttEstimator::new();
        assert_eq!(
            estimator.timeout(Duration::from_millis(50), Duration::from_secs(5)),
            Duration::from_secs(1)
        );
        assert_eq!(
            estimator.timeout(Duration::from_millis(50), Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }
}
