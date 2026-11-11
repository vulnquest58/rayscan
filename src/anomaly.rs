//! Post-SYN anomaly detection.
//!
//! Before the verification pass, the SYN engine may have reported thousands of
//! ports as open on a single host.  This can happen when the host is a tarpit
//! farm, a SYN-proxy appliance, or a honeypot that sends SYN-ACK for every
//! port.  Running a full TCP verification pass against tens of thousands of
//! "open" candidates would be very slow and would skew results.
//!
//! This module detects such hosts and reduces the verification candidate list
//! to a small sample, flagging the host in the scan report with an informative
//! detail string.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::{PortState, ScanReport};

/// Default per-host SYN-open count above which the host is considered anomalous.
pub const DEFAULT_ANOMALY_THRESHOLD: u32 = 1_000;

/// Maximum number of ports sampled from an anomalous host for verification.
const SAMPLE_SIZE: usize = 10;

/// A pair of host-port candidate lists: (normal, all_including_sample).
pub type CandidatePair = (Vec<(IpAddr, u16)>, Vec<(IpAddr, u16)>);

/// Partition `report`'s open results into normal candidates and a sample from
/// anomalous hosts.
///
/// A host is *anomalous* when its SYN-open count exceeds `threshold`.
/// For anomalous hosts:
/// - Only `SAMPLE_SIZE` ports are returned in the candidate list.
/// - Every SYN-open `PortResult` for that host has its `detail` field set to
///   an informative warning string so the warning is visible in the output.
///
/// Returns `(normal_candidates, all_candidates_including_sample)`.  The caller
/// should pass `all_candidates_including_sample` to the verifier; the normal
/// candidates list is returned separately for diagnostics.
pub fn partition_candidates(report: &mut ScanReport, threshold: u32) -> CandidatePair {
    // Count SYN-open ports per host
    let mut counts: HashMap<IpAddr, u32> = HashMap::new();
    for result in report.results.iter().filter(|r| r.state == PortState::Open) {
        *counts.entry(result.host).or_default() += 1;
    }

    let anomalous: std::collections::HashSet<IpAddr> = counts
        .iter()
        .filter(|&(_, &count)| count >= threshold)
        .map(|(&host, _)| host)
        .collect();

    if anomalous.is_empty() {
        // Fast path: no anomalous hosts
        let candidates = report
            .results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .map(|r| (r.host, r.port))
            .collect::<Vec<_>>();
        return (candidates.clone(), candidates);
    }

    // Annotate anomalous results and build candidate lists
    for result in report
        .results
        .iter_mut()
        .filter(|r| r.state == PortState::Open && anomalous.contains(&r.host))
    {
        let count = counts[&result.host];
        result.detail = Some(format!(
            "anomaly: host has {count} SYN-open ports (threshold {}); \
             sampling {SAMPLE_SIZE} ports for verification",
            threshold
        ));
    }

    let mut normal: Vec<(IpAddr, u16)> = Vec::new();
    let mut sample: Vec<(IpAddr, u16)> = Vec::new();
    let mut sampled_per_host: HashMap<IpAddr, usize> = HashMap::new();

    for result in report.results.iter().filter(|r| r.state == PortState::Open) {
        if anomalous.contains(&result.host) {
            let n = sampled_per_host.entry(result.host).or_default();
            if *n < SAMPLE_SIZE {
                sample.push((result.host, result.port));
                *n += 1;
            }
        } else {
            normal.push((result.host, result.port));
        }
    }

    let all_candidates: Vec<(IpAddr, u16)> = normal.iter().chain(sample.iter()).copied().collect();
    (normal, all_candidates)
}

/// Convenience wrapper: returns `true` when any host in `report` has more
/// SYN-open ports than `threshold`.
pub fn has_anomalous_hosts(report: &ScanReport, threshold: u32) -> bool {
    let mut counts: HashMap<IpAddr, u32> = HashMap::new();
    for result in report.results.iter().filter(|r| r.state == PortState::Open) {
        let count = counts.entry(result.host).or_default();
        *count += 1;
        if *count >= threshold {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::{PortResult, StateCounts};

    fn make_report(host: IpAddr, ports: &[u16]) -> ScanReport {
        let results: Vec<PortResult> = ports
            .iter()
            .map(|&port| PortResult::new(host, port, PortState::Open, Duration::from_millis(1)))
            .collect();
        let counts = StateCounts {
            open: results.len() as u64,
            ..StateCounts::default()
        };
        ScanReport {
            targets: 1,
            ports: ports.len(),
            jobs: ports.len() as u64,
            workers: 2,
            elapsed: Duration::from_millis(100),
            counts,
            results,
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: ports.to_vec(),
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        }
    }

    #[test]
    fn host_below_threshold_is_not_flagged() {
        let host: IpAddr = "10.77.0.2".parse().unwrap();
        let ports: Vec<u16> = (80..=90).collect();
        let mut report = make_report(host, &ports);

        let (normal, all) = partition_candidates(&mut report, 1000);

        assert_eq!(normal.len(), ports.len());
        assert_eq!(all.len(), ports.len());
        // No detail annotations on normal hosts
        assert!(report.results.iter().all(|r| r.detail.is_none()));
    }

    #[test]
    fn host_above_threshold_is_flagged_and_sampled() {
        let host: IpAddr = "10.77.0.2".parse().unwrap();
        let ports: Vec<u16> = (1..=2000).collect();
        let mut report = make_report(host, &ports);

        let (normal, all) = partition_candidates(&mut report, 1000);

        assert_eq!(normal.len(), 0, "all ports are on the anomalous host");
        assert_eq!(all.len(), SAMPLE_SIZE, "only a sample is returned");
        assert!(
            report
                .results
                .iter()
                .all(|r| r.detail.as_deref().unwrap_or("").contains("anomaly")),
            "all results on the anomalous host must carry a detail annotation"
        );
    }

    #[test]
    fn has_anomalous_hosts_matches_partition_result() {
        let host: IpAddr = "10.77.0.2".parse().unwrap();
        let ports_small: Vec<u16> = (80..=90).collect();
        let ports_large: Vec<u16> = (1..=2000).collect();

        let report_small = make_report(host, &ports_small);
        let report_large = make_report(host, &ports_large);

        assert!(!has_anomalous_hosts(&report_small, 1000));
        assert!(has_anomalous_hosts(&report_large, 1000));
    }
}
