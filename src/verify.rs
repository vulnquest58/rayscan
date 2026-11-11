use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::classify::{FailureKind, classify_kind};
use crate::discovery::socket_addr;
use crate::error::AppError;
#[cfg(test)]
use crate::model::StateSet;
use crate::model::{PortResult, PortState, ScanReport};
use crate::rate::RateLimiter;
use crate::scanner::{self, ProgressCallback, ScanOptions};

pub async fn verify_syn_open(
    report: &mut ScanReport,
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<(), AppError> {
    let candidates: Vec<(IpAddr, u16)> = report
        .results
        .iter()
        .filter(|result| result.state == PortState::Open)
        .map(|result| (result.host, result.port))
        .collect();

    verify_syn_open_candidates(report, &candidates, options, progress).await
}

/// Verify a specific subset of candidates (used when anomaly detection has
/// already filtered the full open list down to a manageable sample).
pub async fn verify_syn_open_candidates(
    report: &mut ScanReport,
    candidates: &[(IpAddr, u16)],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<(), AppError> {
    if candidates.is_empty() {
        return Ok(());
    }

    let verified = scanner::verify_candidates(candidates, options, progress).await?;
    merge_verification(report, verified, options);
    Ok(())
}

fn merge_verification(report: &mut ScanReport, verified: Vec<PortResult>, options: &ScanOptions) {
    for result in verified {
        let Some(index) = report.results.iter().position(|existing| {
            existing.host == result.host
                && existing.port == result.port
                && existing.state == PortState::Open
        }) else {
            continue;
        };

        report.counts.remove(PortState::Open);
        report.counts.add(result.state);

        if result.state != PortState::Open {
            report.defense_observations.push(result.clone());
        }

        let retain = options.retains(&result);
        if retain {
            report.results[index] = result;
        } else {
            report.results.remove(index);
        }
    }
}

/// Re-verify open results that point at this machine.
///
/// A scan whose target is the local host completes inside the kernel, so two
/// of the scanner's own in-flight connections can pair up (TCP simultaneous
/// open) and be reported as listeners that do not exist.  The recheck walks
/// the open set one connection at a time — a lone connection cannot pair with
/// anything — and reclassifies every open that now refuses to connect.
/// Remote targets are skipped entirely: they cannot produce the artifact and
/// re-probing them would double the traffic the user asked for.
pub async fn recheck_local_opens(report: &mut ScanReport, options: &ScanOptions) {
    if options.shutdown.load(Ordering::Relaxed) {
        return;
    }

    let candidates: Vec<(IpAddr, u16)> = report
        .results
        .iter()
        .filter(|result| result.state == PortState::Open && is_local_target(result.host))
        .map(|result| (result.host, result.port))
        .collect();
    if candidates.is_empty() {
        return;
    }

    let limiter = RateLimiter::new(options.rate);
    let mut rejected = Vec::new();
    for (host, port) in candidates {
        limiter.acquire().await;
        let address = socket_addr(host, port);
        let started = Instant::now();
        let outcome = tokio::time::timeout(options.timeout, TcpStream::connect(address)).await;
        let elapsed = started.elapsed();
        let refused = match &outcome {
            Ok(Err(error)) => classify_kind(error) == FailureKind::Closed,
            _ => false,
        };
        if refused {
            rejected.push(
                PortResult::new(host, port, PortState::Closed, elapsed).with_detail(
                    "connection refused on recheck; the initial open was a loopback \
                     simultaneous open or a listener that has since stopped",
                ),
            );
        }
    }

    if !rejected.is_empty() {
        merge_verification(report, rejected, options);
    }
}

/// True when `ip` addresses this machine, i.e. a scan against it can finish
/// inside the kernel and pair up two of our own connections.
fn is_local_target(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    // A UDP connect() sends no packets; it only resolves the route, so the
    // socket's local address equals the target exactly when the target is
    // one of this machine's own addresses.
    let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let Ok(socket) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    if socket.connect(SocketAddr::new(ip, 53)).is_err() {
        return false;
    }
    socket.local_addr().is_ok_and(|addr| addr.ip() == ip)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use super::*;
    use crate::model::StateCounts;

    fn host() -> IpAddr {
        "10.77.0.2".parse().unwrap()
    }

    fn local_host() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn options(retain: StateSet) -> ScanOptions {
        ScanOptions {
            timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(100),
            rate: 0,
            workers: 4,
            retries: 0,
            randomize: false,
            connect_only: false,
            service_detection: true,
            retain,
            retain_silent_ports: Vec::new(),
            retain_reset_closed: false,
            jitter: Duration::ZERO,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn local_open_report(port: u16) -> ScanReport {
        ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(1),
            counts: StateCounts {
                open: 1,
                ..StateCounts::default()
            },
            results: vec![PortResult::new(
                local_host(),
                port,
                PortState::Open,
                Duration::from_micros(100),
            )],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![port],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        }
    }

    fn dead_port() -> u16 {
        // Bind and drop so nothing listens when the recheck runs.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    fn report() -> ScanReport {
        ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(100),
            counts: StateCounts {
                open: 3,
                ..StateCounts::default()
            },
            results: vec![
                PortResult::new(host(), 80, PortState::Open, Duration::from_millis(1)),
                PortResult::new(host(), 9000, PortState::Open, Duration::from_millis(1)),
                PortResult::new(host(), 9003, PortState::Open, Duration::from_millis(1)),
            ],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![80, 9000, 9003],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        }
    }

    #[test]
    fn reclassifies_false_open_candidates_and_updates_counts() {
        let mut report = report();
        let verified = vec![
            PortResult::new(host(), 80, PortState::Open, Duration::from_millis(2)),
            PortResult::new(host(), 9000, PortState::Silent, Duration::from_millis(300)),
            PortResult::new(host(), 9003, PortState::Closed, Duration::from_millis(1)),
        ];

        merge_verification(&mut report, verified, &options(StateSet::all()));

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.silent, 1);
        assert_eq!(report.counts.closed, 1);
        assert_eq!(report.results.len(), 3);
        assert!(
            report
                .results
                .iter()
                .any(|result| { result.port == 9000 && result.state == PortState::Silent })
        );
    }

    #[test]
    fn drops_reclassified_results_that_are_not_retained() {
        let mut report = report();
        let verified = vec![PortResult::new(
            host(),
            9000,
            PortState::Silent,
            Duration::from_millis(300),
        )];

        merge_verification(&mut report, verified, &options(StateSet::open()));

        assert_eq!(report.counts.open, 2);
        assert_eq!(report.counts.silent, 1);
        assert!(report.results.iter().all(|result| result.port != 9000));
    }

    #[test]
    fn local_target_detection_covers_loopback_and_rejects_remote() {
        assert!(is_local_target("127.0.0.1".parse().unwrap()));
        assert!(is_local_target("127.9.9.9".parse().unwrap()));
        assert!(is_local_target("::1".parse().unwrap()));
        assert!(!is_local_target("192.0.2.1".parse().unwrap()));
        assert!(!is_local_target("198.51.100.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn recheck_reclassifies_local_opens_that_refuse() {
        let port = dead_port();
        let mut report = local_open_report(port);

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 0);
        assert_eq!(report.counts.closed, 1);
        assert!(report.results.is_empty());
        assert_eq!(report.probed_ports, vec![port]);
    }

    #[tokio::test]
    async fn recheck_keeps_local_listeners_that_still_accept() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut report = local_open_report(port);
        report.results[0].banner = Some("hello".to_string());

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Open);
        assert_eq!(report.results[0].banner.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn recheck_leaves_remote_targets_untouched() {
        let mut report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(1),
            counts: StateCounts {
                open: 1,
                ..StateCounts::default()
            },
            results: vec![PortResult::new(
                "192.0.2.1".parse().unwrap(),
                80,
                PortState::Open,
                Duration::from_micros(100),
            )],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![80],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn recheck_retains_reclassified_opens_when_all_states_are_kept() {
        let port = dead_port();
        let mut report = local_open_report(port);

        recheck_local_opens(&mut report, &options(StateSet::all())).await;

        assert_eq!(report.counts.open, 0);
        assert_eq!(report.counts.closed, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Closed);
        assert!(report.results[0].detail.is_some());
    }

    #[tokio::test]
    async fn recheck_skips_probing_after_shutdown() {
        let port = dead_port();
        let mut report = local_open_report(port);
        let scan_options = options(StateSet::open());
        scan_options.shutdown.store(true, Ordering::Relaxed);

        recheck_local_opens(&mut report, &scan_options).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
    }
}
