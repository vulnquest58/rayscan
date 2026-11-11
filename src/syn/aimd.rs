//! Additive-Increase / Multiplicative-Decrease (AIMD) rate controller for the
//! raw SYN engine.
//!
//! # Design
//!
//! The controller tracks the ratio of responses received to probes sent over an
//! exponential moving average (EMA) window.  When the response ratio drops below
//! a configurable threshold (default 80 %) it applies a multiplicative decrease
//! (`rate /= decrease_factor`).  When the ratio stays above the threshold it
//! applies an additive increase (`rate += step_pps`).  Both `min_pps` and
//! `max_pps` clamp the resulting rate.
//!
//! # Thread safety
//!
//! `AimdController` is `!Send`; it must live entirely in the TX thread.  The TX
//! thread calls `update()` after draining each response batch; no locking is
//! required.

/// Configuration for the AIMD rate controller.
#[derive(Clone, Debug)]
pub struct AimdConfig {
    /// Initial transmit rate in packets per second.  Also the additive ceiling.
    pub initial_pps: u64,
    /// Lower bound: AIMD will never go below this rate.
    pub min_pps: u64,
    /// Upper bound: additive increase stops here.
    pub max_pps: u64,
    /// Additive increase step in packets per second applied each update that is
    /// above the response-rate threshold.
    pub step_pps: u64,
    /// Multiplicative decrease factor applied on loss.  The rate is divided by
    /// this value.  Typical value: 2.0.
    pub decrease_factor: f64,
    /// Response ratio below which a multiplicative decrease is triggered.
    /// Expressed as a fraction in [0, 1].  Typical value: 0.80.
    pub loss_threshold: f64,
    /// EMA smoothing coefficient α in [0, 1].  Higher means more weight on
    /// recent observations.  Typical value: 0.25.
    pub ema_alpha: f64,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            initial_pps: 0, // 0 means unlimited; override before use
            min_pps: 100,
            max_pps: u64::MAX,
            step_pps: 100,
            decrease_factor: 2.0,
            loss_threshold: 0.80,
            ema_alpha: 0.25,
        }
    }
}

/// AIMD rate controller state.
#[derive(Debug)]
pub struct AimdController {
    cfg: AimdConfig,
    /// Current rate in packets per second.
    rate: u64,
    /// EMA of the response ratio (responses / probes sent), initialised to 1.0.
    ema_ratio: f64,
    /// Whether AIMD is actually active.  When `initial_pps == 0` (unlimited)
    /// the controller is a no-op.
    enabled: bool,
}

impl AimdController {
    /// Create a new controller from the given configuration.
    pub fn new(cfg: AimdConfig) -> Self {
        let enabled = cfg.initial_pps > 0;
        let rate = cfg
            .initial_pps
            .clamp(cfg.min_pps, cfg.max_pps.max(cfg.min_pps));
        Self {
            cfg,
            rate,
            ema_ratio: 1.0,
            enabled,
        }
    }

    /// Return the current transmit rate in packets per second.
    ///
    /// A return value of `0` means unlimited (AIMD disabled).
    pub fn rate_pps(&self) -> u64 {
        if self.enabled { self.rate } else { 0 }
    }

    /// Update the controller with the number of probes sent and responses
    /// received since the last call.  Returns the new rate.
    ///
    /// `sent` must be > 0; if `sent == 0` the controller is left unchanged.
    pub fn update(&mut self, sent: u64, received: u64) -> u64 {
        if !self.enabled || sent == 0 {
            return self.rate_pps();
        }

        // A silent path answers nothing regardless of the transmit rate: sub
        // 1-percent response samples carry no congestion signal and a decrease
        // would just stall the scan (firewalls and NATs commonly drop RST
        // replies).  Freeze the rate instead; partial responses still feed the
        // regular AIMD logic.
        let ratio = (received as f64) / (sent as f64);
        if ratio < 0.01 {
            return self.rate_pps();
        }

        let ratio = (received as f64) / (sent as f64);
        self.ema_ratio = self.cfg.ema_alpha * ratio + (1.0 - self.cfg.ema_alpha) * self.ema_ratio;

        if self.ema_ratio < self.cfg.loss_threshold {
            // Multiplicative decrease
            let new_rate = ((self.rate as f64) / self.cfg.decrease_factor).round() as u64;
            self.rate = new_rate.clamp(self.cfg.min_pps, self.max_rate());
        } else {
            // Additive increase
            self.rate = self
                .rate
                .saturating_add(self.cfg.step_pps)
                .clamp(self.cfg.min_pps, self.max_rate());
        }

        self.rate
    }

    fn max_rate(&self) -> u64 {
        if self.cfg.max_pps == 0 || self.cfg.max_pps == u64::MAX {
            self.cfg.initial_pps.max(self.rate)
        } else {
            self.cfg.max_pps
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(initial: u64) -> AimdController {
        AimdController::new(AimdConfig {
            initial_pps: initial,
            min_pps: 100,
            max_pps: 10_000,
            step_pps: 100,
            decrease_factor: 2.0,
            loss_threshold: 0.80,
            ema_alpha: 1.0, // instant EMA for deterministic tests
        })
    }

    #[test]
    fn additive_increase_on_full_response_rate() {
        let mut ctrl = controller(1000);
        for i in 1..=5 {
            let new_rate = ctrl.update(100, 100);
            assert_eq!(new_rate, 1000 + i * 100, "step {i}");
        }
    }

    #[test]
    fn multiplicative_decrease_on_loss() {
        let mut ctrl = controller(1000);
        // 50% response ratio → below 80% threshold → halve the rate
        let new_rate = ctrl.update(100, 50);
        assert_eq!(new_rate, 500);
    }

    #[test]
    fn zero_received_freezes_rate() {
        let mut ctrl = controller(1000);
        // A silent path is not congestion evidence; keep the configured rate.
        ctrl.update(1000, 0);
        ctrl.update(4096, 1);
        assert_eq!(ctrl.rate_pps(), 1000);
    }

    #[test]
    fn rate_clamps_to_min() {
        let mut ctrl = controller(200);
        // Force several decreases with heavy partial loss
        for _ in 0..10 {
            ctrl.update(100, 1);
        }
        assert_eq!(ctrl.rate_pps(), 100, "must not go below min_pps");
    }

    #[test]
    fn rate_clamps_to_max() {
        let mut ctrl = controller(1000);
        // Force many increases
        for _ in 0..200 {
            ctrl.update(100, 100);
        }
        assert_eq!(ctrl.rate_pps(), 10_000, "must not exceed max_pps");
    }

    #[test]
    fn zero_initial_rate_is_disabled() {
        let mut ctrl = AimdController::new(AimdConfig {
            initial_pps: 0,
            ..AimdConfig::default()
        });
        ctrl.update(1000, 0); // severe loss
        assert_eq!(ctrl.rate_pps(), 0, "unlimited mode must stay unlimited");
    }

    #[test]
    fn zero_sent_is_a_no_op() {
        let mut ctrl = controller(1000);
        let rate_before = ctrl.rate_pps();
        ctrl.update(0, 0);
        assert_eq!(ctrl.rate_pps(), rate_before);
    }
}
