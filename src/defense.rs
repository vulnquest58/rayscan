//! Defense Awareness & Middlebox Intelligence Classifier (Phase 8).
//!
//! Analyzes discrepancy signatures, latency anomalies, silent listener ratios,
//! and stack characteristics across probed ports to detect and classify
//! defensive perimeters, including:
//! - SYN Proxies (iptables SYNPROXY, hardware appliances, Cloudflare/F5)
//! - TCP Tarpits (xt_TARPIT, LaBrea, honeypots, zero-window holds)
//! - Aggressive Rate Limiters (token-bucket drop rules, iptables -m limit)
//! - Layer-7 WAF / DPI Inspection (payload-triggered resets)
//! - Direct, unproxied hosts

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Serialize;

use crate::model::{PortResult, PortState, ScanReport};

/// Categorical classification of the defensive posture of a target host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseType {
    /// Clean direct endpoint without detectable middlebox intervention
    DirectHost,
    /// SYN Proxy / SYN cookie middlebox responding on behalf of target
    SynProxy,
    /// TCP Tarpit or honeypot holding connections open without answering
    Tarpit,
    /// Aggressive rate-limiting dropping burst probes
    RateLimiting,
    /// Layer-7 WAF or DPI engine inspecting and dropping application payloads
    WafOrDpi,
    /// Multi-layered defense combining proxies, tarpits, and filtering
    MultiLayerDefense,
}

impl DefenseType {
    pub const fn badge(self) -> &'static str {
        match self {
            Self::DirectHost => "[CLEAN] Direct Host",
            Self::RateLimiting => "[NOTICE] Rate-Limiting Active",
            Self::Tarpit => "[WARNING] TCP Tarpit Active",
            Self::SynProxy => "[WARNING] SYN-Proxy Middlebox Detected",
            Self::WafOrDpi => "[WARNING] Layer-7 WAF / DPI Detected",
            Self::MultiLayerDefense => "[CRITICAL] Heavy Middlebox / Deception Detected",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectHost => "Clean Direct Endpoint",
            Self::SynProxy => "SYN-Proxy Middlebox",
            Self::Tarpit => "TCP Tarpit / Honeypot",
            Self::RateLimiting => "Aggressive Rate Limiter",
            Self::WafOrDpi => "Layer-7 WAF / DPI Middlebox",
            Self::MultiLayerDefense => "Multi-Layered Defense Active",
        }
    }
}

impl std::fmt::Display for DefenseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Comprehensive defense assessment for a single target host.
#[derive(Clone, Debug, Serialize)]
pub struct HostDefenseAssessment {
    pub host: IpAddr,
    pub defense_type: DefenseType,
    pub confidence: f32,
    pub summary: String,
    pub indicators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
}

/// Analyze a scan report and evaluate the defensive environment for all scanned hosts.
pub fn analyze_defenses(report: &ScanReport) -> HashMap<IpAddr, HostDefenseAssessment> {
    let mut by_host: HashMap<IpAddr, Vec<&PortResult>> = HashMap::new();
    for result in &report.results {
        by_host.entry(result.host).or_default().push(result);
    }
    for result in &report.defense_observations {
        by_host.entry(result.host).or_default().push(result);
    }

    let mut assessments = HashMap::new();
    for (host, results) in by_host {
        let assessment = assess_host(host, &results, report);
        assessments.insert(host, assessment);
    }
    assessments
}

fn assess_host(
    host: IpAddr,
    results: &[&PortResult],
    report: &ScanReport,
) -> HostDefenseAssessment {
    let mut open_count = 0usize;
    let mut silent_count = 0usize;
    let mut reclassified_closed = 0usize;
    let mut service_identified_count = 0usize;

    for r in results {
        match r.state {
            PortState::Open => {
                open_count += 1;
                if r.service.is_some() {
                    service_identified_count += 1;
                }
            }
            PortState::Silent => {
                silent_count += 1;
            }
            PortState::Closed
                if r.detail.as_deref().is_some_and(|detail| {
                    detail.contains("connection closed during verification")
                        || detail.contains("anomaly:")
                }) =>
            {
                reclassified_closed += 1;
            }
            _ => {}
        }
    }

    let mut indicators = Vec::new();
    let mut is_syn_proxy = false;
    let mut is_tarpit = false;
    let mut is_rate_limited = false;

    // Check 1: SYN Proxy detection
    // In raw SYN scans, ports answer SYN-ACK initially, but verification fails on connect.
    if reclassified_closed > 0 {
        is_syn_proxy = true;
        indicators.push(format!(
            "{reclassified_closed} port(s) returned SYN-ACK during discovery but were rejected or dropped upon connection verification"
        ));
    }

    // Check 2: Tarpit detection
    // High silent ratio or multiple mute listeners with long timeouts
    if silent_count >= 3 || (silent_count > 0 && silent_count >= open_count) {
        is_tarpit = true;
        indicators.push(format!(
            "{silent_count} port(s) completed TCP handshakes but held connections mute without emitting application banners (tarpit behavior)"
        ));
    }

    // Check 3: Anomaly threshold / Honeypot sweep
    if results
        .first()
        .and_then(|first| first.detail.as_deref())
        .is_some_and(|detail| detail.contains("anomaly:"))
    {
        is_tarpit = true;
        indicators.push(
            "Host triggered high-density SYN-open anomaly threshold (tarpit/honeypot farm)"
                .to_string(),
        );
    }

    // Check 4: Rate-limiting detection
    // Probes that required retries or were marked with low retry confidence
    let retried_count = results
        .iter()
        .filter(|r| r.confidence.unwrap_or(1.0) < 0.85)
        .count();
    if retried_count >= 4 {
        is_rate_limited = true;
        indicators.push(format!(
            "{retried_count} port(s) required probe retries or backoff, suggesting packet loss or rate-limiting thresholds"
        ));
    }

    // Determine aggregate classification and confidence
    let (defense_type, confidence, summary, recommended_action) = if is_syn_proxy && is_tarpit {
        (
            DefenseType::MultiLayerDefense,
            0.95,
            "Target is protected by a multi-layered defense (active SYN-proxy and TCP tarpits detected).".to_string(),
            Some("Use `--min-confidence 80` to discard tarpit artifacts, and `--probe-timeout-ms 2000` to probe deep services.".to_string()),
        )
    } else if is_syn_proxy {
        (
            DefenseType::SynProxy,
            0.92,
            "Target is shielded by a SYN Proxy middlebox (e.g. iptables SYNPROXY, F5 BIG-IP, or DDoS protection).".to_string(),
            Some("Raw SYN discovery produces phantom candidates; verified scan mode (`rayscan scan`) confirms true backend listeners.".to_string()),
        )
    } else if is_tarpit {
        (
            DefenseType::Tarpit,
            0.90,
            "Target or perimeter firewall employs TCP Tarpits (`xt_TARPIT` or LaBrea style mute listeners).".to_string(),
            Some("Filter out silent ports by showing only verified open services (`--show open`).".to_string()),
        )
    } else if is_rate_limited {
        (
            DefenseType::RateLimiting,
            0.80,
            "Target network enforces probe rate-limiting or token-bucket traffic policing."
                .to_string(),
            Some(
                "Use `--rate 50` or `--profile careful` to stay below packet drop thresholds."
                    .to_string(),
            ),
        )
    } else {
        let os_evidence = report
            .os_fingerprints
            .get(&host)
            .map(|g| format!(" (conforming to {} stack)", g.detail))
            .unwrap_or_default();
        indicators.push(format!(
            "All {} open port(s) (with {} identified services) responded with standard TCP semantics{}",
            open_count, service_identified_count, os_evidence
        ));
        (
            DefenseType::DirectHost,
            1.0,
            "Target behaves as a clean, direct endpoint with no detectable middlebox or tarpit interference.".to_string(),
            None,
        )
    };

    HostDefenseAssessment {
        host,
        defense_type,
        confidence,
        summary,
        indicators,
        recommended_action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceInfo;
    use std::time::Duration;

    #[test]
    fn direct_clean_host_is_classified_as_direct() {
        let host: IpAddr = "192.168.1.10".parse().unwrap();
        let mut r1 = PortResult::new(host, 80, PortState::Open, Duration::from_millis(1));
        r1.service = Some(ServiceInfo {
            name: "http".to_string(),
            product: Some("nginx".to_string()),
            version: None,
        });
        let mut r2 = PortResult::new(host, 22, PortState::Open, Duration::from_millis(1));
        r2.service = Some(ServiceInfo {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: None,
        });

        let report = ScanReport {
            targets: 1,
            ports: 2,
            jobs: 2,
            workers: 2,
            elapsed: Duration::from_millis(50),
            counts: crate::model::StateCounts {
                open: 2,
                ..Default::default()
            },
            results: vec![r1, r2],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![80, 22],
            partial: false,
            defense_observations: Vec::new(),
        };

        let assessments = analyze_defenses(&report);
        let assess = assessments.get(&host).unwrap();
        assert_eq!(assess.defense_type, DefenseType::DirectHost);
        assert_eq!(assess.confidence, 1.0);
    }

    #[test]
    fn tarpit_host_with_silent_ports_is_identified() {
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        let s1 = PortResult::new(host, 9000, PortState::Silent, Duration::from_millis(500));
        let s2 = PortResult::new(host, 9001, PortState::Silent, Duration::from_millis(500));
        let s3 = PortResult::new(host, 9002, PortState::Silent, Duration::from_millis(500));

        let report = ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(500),
            counts: crate::model::StateCounts {
                silent: 3,
                ..Default::default()
            },
            results: vec![s1, s2, s3],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![9000, 9001, 9002],
            partial: false,
            defense_observations: Vec::new(),
        };

        let assessments = analyze_defenses(&report);
        let assess = assessments.get(&host).unwrap();
        assert_eq!(assess.defense_type, DefenseType::Tarpit);
        assert!(assess.confidence >= 0.90);
    }

    #[test]
    fn syn_proxy_verification_failure_is_identified() {
        let host: IpAddr = "10.77.0.2".parse().unwrap();
        let mut r = PortResult::new(host, 9003, PortState::Closed, Duration::from_millis(5));
        r.detail = Some("connection closed during verification: connection refused".to_string());

        let report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(10),
            counts: crate::model::StateCounts {
                closed: 1,
                ..Default::default()
            },
            results: vec![r],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![9003],
            partial: false,
            defense_observations: Vec::new(),
        };

        let assessments = analyze_defenses(&report);
        let assess = assessments.get(&host).unwrap();
        assert_eq!(assess.defense_type, DefenseType::SynProxy);
        assert!(assess.confidence >= 0.90);
    }
}
