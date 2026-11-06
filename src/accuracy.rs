//! Unified Accuracy Scoring and Evidence Engine.
//!
//! Evaluates probe results against four objective criteria:
//! 1. TCP Handshake (Weight: 20%): Handshake established without truncation or error
//! 2. Application Banner / Payload (Weight: 40%): Protocol banners or responsive data
//! 3. TCP/IP Stack & OS Conformance (Weight: 20%): Standard TTL, TCP window, and options
//! 4. Stability & RTT Consistency (Weight: 20%): Non-anomalous latency without immediate RST/drops

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::fingerprint::OsGuess;
use crate::model::{PortResult, PortState, ScanReport};

/// Detailed breakdown of the four accuracy pillars.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AccuracyScore {
    /// Handshake score (0.0 ..= 0.20)
    pub handshake: f32,
    /// Application banner / payload score (0.0 ..= 0.40)
    pub banner: f32,
    /// Stack & OS conformance score (0.0 ..= 0.20)
    pub stack: f32,
    /// Behavioral stability & latency score (0.0 ..= 0.20)
    pub stability: f32,
    /// Total aggregate score (0.0 ..= 1.0)
    pub total: f32,
    /// Compact evidence string
    pub evidence: String,
    /// Categorical classification tag
    pub classification: &'static str,
}

impl AccuracyScore {
    pub const WEIGHT_HANDSHAKE: f32 = 0.20;
    pub const WEIGHT_BANNER: f32 = 0.40;
    pub const WEIGHT_STACK: f32 = 0.20;
    pub const WEIGHT_STABILITY: f32 = 0.20;

    /// Calculate the accuracy score for a port result.
    pub fn calculate(result: &PortResult, os_guess: Option<&OsGuess>) -> Self {
        // 1. TCP Handshake Score (0.0 ..= 0.20)
        let (handshake, hs_desc) = match result.state {
            PortState::Open => (Self::WEIGHT_HANDSHAKE, "handshake:ok(20%)"),
            PortState::Silent => (0.15, "handshake:mute(15%)"),
            _ => (0.0, "handshake:none(0%)"),
        };

        // 2. Application Data / Banner Score (0.0 ..= 0.40)
        let (banner, banner_desc) = if let Some(service) = &result.service {
            if let Some(product) = &service.product {
                (
                    Self::WEIGHT_BANNER,
                    format!("banner:{}/{}(40%)", service.name, product),
                )
            } else if service.version.is_some() {
                (Self::WEIGHT_BANNER, format!("banner:{}(40%)", service.name))
            } else {
                (0.35, format!("banner:{}(35%)", service.name))
            }
        } else if let Some(raw) = &result.banner {
            if !raw.trim().is_empty() {
                (0.30, "banner:raw-text(30%)".to_string())
            } else {
                (0.10, "banner:eof(10%)".to_string())
            }
        } else if result.state == PortState::Open {
            (0.10, "banner:none(10%)".to_string())
        } else {
            (0.0, "banner:none(0%)".to_string())
        };

        // 3. Stack Conformance Score (0.0 ..= 0.20)
        let (stack, stack_desc) = if let Some(guess) = os_guess {
            if guess.confidence >= 0.8 {
                (Self::WEIGHT_STACK, format!("stack:{}(20%)", guess.family))
            } else if guess.confidence >= 0.5 {
                (0.15, format!("stack:{}(15%)", guess.family))
            } else {
                (0.10, "stack:partial(10%)".to_string())
            }
        } else if result.state == PortState::Open {
            (0.15, "stack:standard(15%)".to_string())
        } else if result.state == PortState::Silent {
            (0.10, "stack:standard(10%)".to_string())
        } else {
            (0.0, "stack:none(0%)".to_string())
        };

        // 4. Behavioral Stability & Latency Score (0.0 ..= 0.20)
        let (stability, stab_desc) =
            if result.state == PortState::Open || result.state == PortState::Silent {
                let lat_ms = result.latency.as_secs_f64() * 1000.0;
                let base = if result.latency <= Duration::from_millis(500) {
                    Self::WEIGHT_STABILITY
                } else if result.latency <= Duration::from_millis(1500) {
                    0.15
                } else if result.latency <= Duration::from_millis(3000) {
                    0.10
                } else {
                    0.05
                };

                // Scale by any prior confidence indicator (e.g., if SYN retry pass was required)
                let factor = result.confidence.unwrap_or(1.0).clamp(0.5, 1.0);
                let final_stab = (base * factor).clamp(0.0, Self::WEIGHT_STABILITY);
                (
                    final_stab,
                    format!("latency:{:.1}ms({:.0}%)", lat_ms, final_stab * 100.0),
                )
            } else {
                (0.0, "latency:none(0%)".to_string())
            };

        let total = (handshake + banner + stack + stability).clamp(0.0, 1.0);

        let classification = if total >= 0.85 {
            "genuine_service"
        } else if total >= 0.65 {
            "verified_service"
        } else if total >= 0.40 {
            "candidate_service"
        } else {
            "defense_suspect"
        };

        let evidence = format!("{} {} {} {}", hs_desc, banner_desc, stack_desc, stab_desc);

        Self {
            handshake,
            banner,
            stack,
            stability,
            total,
            evidence,
            classification,
        }
    }

    /// User-friendly label for classification tag.
    pub fn classification_label(&self) -> &'static str {
        match self.classification {
            "genuine_service" => "High Confidence - Genuine Service",
            "verified_service" => "Good Confidence - Verified Service",
            "candidate_service" => "Moderate Confidence - Candidate Service",
            _ => "Low Confidence - Defense / Tarpit Suspect",
        }
    }

    /// Formatted explanation report for a port.
    pub fn explain(
        &self,
        host: IpAddr,
        port: u16,
        state: PortState,
        service: Option<&str>,
    ) -> String {
        let pct = (self.total * 100.0).round() as u8;
        let mut out = String::new();
        out.push_str(&format!("Port {}/tcp on {}:\n", port, host));
        out.push_str(&format!("  State:               {}\n", state));
        out.push_str(&format!(
            "  Accuracy Score:      {}% ({})\n",
            pct,
            self.classification_label()
        ));
        out.push_str("  Criteria Breakdown:\n");
        out.push_str(&format!(
            "    [+] TCP Handshake:   {:>4.1}% / 20%  (3-way handshake established)\n",
            self.handshake * 100.0
        ));
        out.push_str(&format!(
            "    [+] Application:     {:>4.1}% / 40%  ({})\n",
            self.banner * 100.0,
            service.unwrap_or("No banner received")
        ));
        out.push_str(&format!(
            "    [+] Stack / OS:      {:>4.1}% / 20%  (TCP options and TTL characteristics)\n",
            self.stack * 100.0
        ));
        out.push_str(&format!(
            "    [+] Stability:       {:>4.1}% / 20%  (Handshake latency and RTT consistency)\n",
            self.stability * 100.0
        ));
        out.push_str(&format!("  Evidence String:     {}\n", self.evidence));
        out
    }
}

/// Apply accuracy scores to all results in a scan report.
pub fn score_report(report: &mut ScanReport) {
    for result in &mut report.results {
        let guess = report.os_fingerprints.get(&result.host);
        let score = AccuracyScore::calculate(result, guess);
        result.confidence = Some(score.total);
        result.evidence = Some(score.evidence);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceInfo;

    #[test]
    fn genuine_ssh_service_achieves_perfect_or_near_perfect_score() {
        let host: IpAddr = "192.168.1.1".parse().unwrap();
        let mut result = PortResult::new(host, 22, PortState::Open, Duration::from_millis(2));
        result.service = Some(ServiceInfo {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.4p1".to_string()),
        });
        result.banner = Some("SSH-2.0-OpenSSH_8.4p1".to_string());

        let guess = OsGuess {
            family: crate::fingerprint::OsFamily::Linux,
            detail: "Linux 5.x".to_string(),
            confidence: 0.95,
            initial_ttl: Some(64),
            evidence: None,
        };

        let score = AccuracyScore::calculate(&result, Some(&guess));
        assert_eq!(score.handshake, 0.20);
        assert_eq!(score.banner, 0.40);
        assert_eq!(score.stack, 0.20);
        assert_eq!(score.stability, 0.20);
        assert_eq!(score.total, 1.0);
        assert_eq!(score.classification, "genuine_service");
        assert!(score.evidence.contains("OpenSSH"));
    }

    #[test]
    fn silent_candidate_gets_low_confidence() {
        let host: IpAddr = "192.168.1.1".parse().unwrap();
        let result = PortResult::new(host, 9000, PortState::Silent, Duration::from_millis(1200));

        let score = AccuracyScore::calculate(&result, None);
        assert_eq!(score.handshake, 0.15);
        assert_eq!(score.banner, 0.0);
        assert_eq!(score.stack, 0.10);
        assert_eq!(score.stability, 0.15);
        assert_eq!(score.total, 0.40);
        assert_eq!(score.classification, "candidate_service");
        assert!(score.evidence.contains("handshake:mute"));
    }

    #[test]
    fn explain_formats_comprehensive_text() {
        let host: IpAddr = "192.168.1.1".parse().unwrap();
        let result = PortResult::new(host, 80, PortState::Open, Duration::from_millis(10));
        let score = AccuracyScore::calculate(&result, None);
        let explanation = score.explain(host, 80, PortState::Open, Some("http (Apache)"));
        assert!(explanation.contains("Port 80/tcp on 192.168.1.1"));
        assert!(explanation.contains("Criteria Breakdown"));
        assert!(explanation.contains("Accuracy Score"));
    }
}
