use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_channel::Sender;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::classify::{Failure, FailureKind, classify_io_error, classify_kind};
use crate::error::AppError;
use crate::limits::worker_count;
use crate::model::{PortResult, PortState, ScanReport, StateCounts, StateSet};
use crate::rate::RateLimiter;
use crate::rtt::RttEstimator;
use crate::service;

const MIN_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const SERVICE_BANNER_LIMIT: usize = 1024;
const SERVICE_BANNER_IDLE: Duration = Duration::from_millis(50);
const SERVICE_BANNER_GRACE: Duration = Duration::from_millis(100);
/// Probes buffered per channel message.  Delivering every result as its own
/// message costs a cross-thread wakeup per probe and capped scan throughput at
/// roughly a third of the raw connect rate; batching trades a little buffering
/// for far fewer wakeups.
const RESULT_BATCH: usize = 64;
/// Upper bound on buffered batches so a stalled receiver cannot pin memory.
const MAX_BATCHED_MESSAGES: usize = 256;
/// Flush a partially filled batch after this long so slow, low-worker scans
/// still deliver progress and counts promptly.
const BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

fn batch_channel_capacity(workers: usize) -> usize {
    workers.clamp(4, MAX_BATCHED_MESSAGES)
}

#[derive(Clone, Debug, Default)]
pub struct ProgressEvent {
    pub state: Option<PortState>,
    pub result: Option<PortResult>,
}

impl ProgressEvent {
    pub const fn state(state: PortState) -> Self {
        Self {
            state: Some(state),
            result: None,
        }
    }

    pub const fn result(state: PortState) -> Self {
        Self {
            state: Some(state),
            result: None,
        }
    }

    pub fn with_result(result: PortResult) -> Self {
        Self {
            state: Some(result.state),
            result: Some(result),
        }
    }
}

pub type ProgressCallback = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub probe_timeout: Duration,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
    pub randomize: bool,
    pub connect_only: bool,
    pub service_detection: bool,
    pub retain: StateSet,
    /// Maximum random delay before each probe. Zero disables jitter.
    pub jitter: Duration,
    /// When set to `true` by an external signal handler, workers stop picking
    /// new jobs and the scan returns a partial report instead of an error.
    pub shutdown: Arc<AtomicBool>,
}

struct Shared {
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    options: ScanOptions,
    limiter: RateLimiter,
    rtt: Vec<Mutex<RttEstimator>>,
    jobs: u64,
}

pub async fn scan(
    targets: &[IpAddr],
    ports: &[u16],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if targets.is_empty() || ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    let started = Instant::now();
    let mut targets = targets.to_vec();
    let mut ports = ports.to_vec();
    if options.randomize {
        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);
        ports.shuffle(&mut rng);
    }

    let jobs = (targets.len() as u64)
        .checked_mul(ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;
    let workers = worker_count(options.workers, jobs);
    let rtt = (0..targets.len())
        .map(|_| Mutex::new(RttEstimator::new()))
        .collect();

    let shared = Arc::new(Shared {
        targets,
        ports,
        options: options.clone(),
        limiter: RateLimiter::new(options.rate),
        rtt,
        jobs,
    });
    let next = Arc::new(AtomicU64::new(0));
    let (sender, receiver) =
        async_channel::bounded::<Vec<PortResult>>(batch_channel_capacity(workers));

    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let shared = Arc::clone(&shared);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        tasks.spawn(async move {
            run_worker(shared, next, sender).await;
        });
    }
    drop(sender);

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut probed_ports = Vec::new();
    while let Ok(batch) = receiver.recv().await {
        for result in batch {
            counts.add(result.state);
            probed_ports.push(result.port);
            let state = result.state;
            let retained = options.retain.contains(result.state);
            let res_clone = if retained { Some(result.clone()) } else { None };
            if retained {
                results.push(result);
            }
            if let Some(progress) = &progress {
                progress(ProgressEvent {
                    state: Some(state),
                    result: res_clone,
                });
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        joined.map_err(|error| AppError::runtime(format!("scan worker failed: {error}")))?;
    }

    if counts.total() != jobs {
        // If the shutdown flag was set (Ctrl-C), return a partial report
        // instead of an error so the caller can still display results.
        let cancelled = shared.options.shutdown.load(Ordering::Relaxed);
        if !cancelled {
            return Err(AppError::runtime(format!(
                "scan incomplete: {} of {jobs} probes completed",
                counts.total()
            )));
        }
        return Ok(ScanReport {
            targets: shared.targets.len(),
            ports: shared.ports.len(),
            jobs,
            workers,
            elapsed: started.elapsed(),
            counts,
            results,
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports,
            partial: true,
            defense_observations: Vec::new(),
        });
    }

    Ok(ScanReport {
        targets: shared.targets.len(),
        ports: shared.ports.len(),
        jobs,
        workers,
        elapsed: started.elapsed(),
        counts,
        results,
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports,
        partial: false,
        defense_observations: Vec::new(),
    })
}

pub async fn verify_candidates(
    candidates: &[(IpAddr, u16)],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<Vec<PortResult>, AppError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let jobs = candidates.len() as u64;
    let workers = worker_count(options.workers, jobs);
    let candidates = Arc::new(candidates.to_vec());
    let options = Arc::new(options.clone());
    let limiter = Arc::new(RateLimiter::new(options.rate));
    let next = Arc::new(AtomicU64::new(0));
    let (sender, receiver) =
        async_channel::bounded::<PortResult>(workers.saturating_mul(2).max(64));

    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let candidates = Arc::clone(&candidates);
        let options = Arc::clone(&options);
        let limiter = Arc::clone(&limiter);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        tasks.spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= jobs {
                    break;
                }
                let (host, port) = candidates[index as usize];
                let result = verify_candidate(&options, &limiter, host, port).await;
                if sender.send(result).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(sender);

    let mut results = Vec::with_capacity(candidates.len());
    while let Ok(result) = receiver.recv().await {
        if let Some(progress) = &progress {
            progress(ProgressEvent::with_result(result.clone()));
        }
        results.push(result);
    }

    while let Some(joined) = tasks.join_next().await {
        joined
            .map_err(|error| AppError::runtime(format!("verification worker failed: {error}")))?;
    }

    Ok(results)
}

async fn verify_candidate(
    options: &ScanOptions,
    limiter: &RateLimiter,
    host: IpAddr,
    port: u16,
) -> PortResult {
    let address = SocketAddr::new(host, port);
    let mut attempt = 0u32;

    loop {
        limiter.acquire().await;
        apply_jitter(options.jitter).await;
        let started = Instant::now();
        let outcome = tokio::time::timeout(options.timeout, TcpStream::connect(address)).await;
        let elapsed = started.elapsed();

        match outcome {
            Err(_) => {
                if attempt < options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                let failure = Failure::timed_out(options.timeout);
                return PortResult::new(host, port, failure.kind.state(), elapsed)
                    .with_detail(failure.detail);
            }
            Ok(Err(error)) => {
                let failure = classify_io_error(&error);
                if failure.kind.retryable() && attempt < options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                return PortResult::new(host, port, failure.kind.state(), elapsed)
                    .with_detail(failure.detail);
            }
            Ok(Ok(stream)) => {
                let result = verify_service(
                    stream,
                    host,
                    port,
                    elapsed,
                    options.probe_timeout,
                    options.service_detection,
                )
                .await;
                if matches!(result.state, PortState::Closed | PortState::Silent)
                    && attempt < options.retries
                {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                return result;
            }
        }
    }
}

async fn run_worker(shared: Arc<Shared>, next: Arc<AtomicU64>, sender: Sender<Vec<PortResult>>) {
    let port_count = shared.ports.len() as u64;
    let mut batch: Vec<PortResult> = Vec::with_capacity(RESULT_BATCH);
    let mut last_flush = Instant::now();

    loop {
        // Honour graceful-shutdown request (Ctrl-C via signal handler).
        if shared.options.shutdown.load(Ordering::Relaxed) {
            break;
        }

        let index = next.fetch_add(1, Ordering::Relaxed);
        if index >= shared.jobs {
            break;
        }

        let target_index = (index / port_count) as usize;
        let port_index = (index % port_count) as usize;
        let target = shared.targets[target_index];
        let port = shared.ports[port_index];
        let result = probe(&shared, target_index, target, port).await;

        batch.push(result);
        let flush = batch.len() >= RESULT_BATCH
            || (!batch.is_empty() && last_flush.elapsed() >= BATCH_FLUSH_INTERVAL);
        if flush {
            last_flush = Instant::now();
            let pending = std::mem::replace(&mut batch, Vec::with_capacity(RESULT_BATCH));
            if sender.send(pending).await.is_err() {
                break;
            }
        }
    }

    if !batch.is_empty() {
        // Deliver results collected before a shutdown or end-of-scan break so
        // the report's counts stay consistent with the probes actually sent.
        let _ = sender.send(batch).await;
    }
}

async fn apply_jitter(jitter: Duration) {
    if jitter.is_zero() {
        return;
    }
    let max_millis = jitter.as_millis().min(u128::from(u64::MAX)) as u64;
    let delay = rand::thread_rng().gen_range(0..=max_millis);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

async fn probe(shared: &Shared, target_index: usize, host: IpAddr, port: u16) -> PortResult {
    let address = SocketAddr::new(host, port);
    let mut attempt = 0u32;

    loop {
        shared.limiter.acquire().await;
        apply_jitter(shared.options.jitter).await;
        let timeout = current_timeout(shared, target_index);
        let attempt_started = Instant::now();
        let outcome = tokio::time::timeout(timeout, TcpStream::connect(address)).await;
        let elapsed = attempt_started.elapsed();

        match outcome {
            Err(_) => {
                record_timeout(shared, target_index);
                return result_with_detail(
                    shared,
                    FailureKind::Filtered.state(),
                    host,
                    port,
                    elapsed,
                    || Failure::timed_out(timeout).detail,
                );
            }
            Ok(Err(error)) => {
                let kind = classify_kind(&error);
                if kind.retryable() && attempt < shared.options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                if kind == FailureKind::Closed {
                    record_sample(shared, target_index, elapsed);
                }
                let state = kind.state();
                return result_with_detail(shared, state, host, port, elapsed, || {
                    classify_io_error(&error).detail
                });
            }
            Ok(Ok(stream)) => {
                record_sample(shared, target_index, elapsed);
                if shared.options.connect_only {
                    return PortResult::new(host, port, PortState::Open, elapsed);
                }
                return verify_service(
                    stream,
                    host,
                    port,
                    elapsed,
                    shared.options.probe_timeout,
                    shared.options.service_detection,
                )
                .await;
            }
        }
    }
}

fn current_timeout(shared: &Shared, target_index: usize) -> Duration {
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .timeout(MIN_CONNECT_TIMEOUT, shared.options.timeout)
}

/// Build a result, allocating its detail string only when the state will be
/// retained.  Closed probes dominate scan volume and are dropped unless they
/// were requested, so the hot path skips one `String` allocation per probe.
fn result_with_detail(
    shared: &Shared,
    state: PortState,
    host: IpAddr,
    port: u16,
    latency: Duration,
    detail: impl FnOnce() -> String,
) -> PortResult {
    let result = PortResult::new(host, port, state, latency);
    if shared.options.retain.contains(state) {
        result.with_detail(detail())
    } else {
        result
    }
}

fn record_sample(shared: &Shared, target_index: usize, sample: Duration) {
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .observe(sample);
}

fn record_timeout(shared: &Shared, target_index: usize) {
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .on_timeout();
}

fn retry_delay(attempt: u32) -> Duration {
    let millis = 10u64.saturating_mul(1u64 << attempt.min(6));
    Duration::from_millis(millis.min(500))
}

async fn verify_service(
    stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
    service_detection: bool,
) -> PortResult {
    if service_detection {
        return verify_and_inspect(stream, host, port, latency, probe_timeout).await;
    }

    verify_first_byte(stream, host, port, latency, probe_timeout).await
}

async fn verify_first_byte(
    mut stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    let mut buffer = [0u8; 1];
    match tokio::time::timeout(probe_timeout, stream.read(&mut buffer)).await {
        Err(_) => PortResult::new(host, port, PortState::Silent, latency).with_detail(format!(
            "handshake succeeded but no banner arrived within {}ms",
            probe_timeout.as_millis()
        )),
        Ok(Ok(0)) => PortResult::new(host, port, PortState::Open, latency),
        Ok(Ok(_)) => PortResult::new(host, port, PortState::Open, latency),
        Ok(Err(error)) => {
            let failure = classify_io_error(&error);
            PortResult::new(host, port, failure.kind.state(), latency).with_detail(format!(
                "connection closed during verification: {}",
                failure.detail
            ))
        }
    }
}

enum ReadOutcome {
    Data,
    Timeout,
    Eof,
    Error(std::io::Error),
}

async fn read_chunk(stream: &mut TcpStream, banner: &mut Vec<u8>, until: Instant) -> ReadOutcome {
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return ReadOutcome::Timeout;
    }
    let capacity = SERVICE_BANNER_LIMIT.saturating_sub(banner.len());
    if capacity == 0 {
        return ReadOutcome::Data;
    }

    let mut chunk = [0u8; 1024];
    match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
        Err(_) => ReadOutcome::Timeout,
        Ok(Ok(0)) => ReadOutcome::Eof,
        Ok(Ok(read)) => {
            banner.extend_from_slice(&chunk[..read.min(capacity)]);
            ReadOutcome::Data
        }
        Ok(Err(error)) => ReadOutcome::Error(error),
    }
}

async fn verify_and_inspect(
    mut stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    let started = Instant::now();
    let deadline = started + probe_timeout;
    let grace_end = started + (probe_timeout / 2).min(SERVICE_BANNER_GRACE);
    let mut banner = Vec::new();
    let mut closed = false;

    match read_chunk(&mut stream, &mut banner, grace_end).await {
        ReadOutcome::Data | ReadOutcome::Timeout => {}
        ReadOutcome::Eof => closed = true,
        ReadOutcome::Error(error) => return verification_failure(host, port, latency, error),
    }

    let now = Instant::now();
    if banner.is_empty() && !closed && now < deadline {
        let probe = service::http_probe(host);
        let remaining = deadline.saturating_duration_since(now);
        let _ = tokio::time::timeout(remaining, stream.write_all(&probe)).await;
    }

    while !closed && Instant::now() < deadline && banner.len() < SERVICE_BANNER_LIMIT {
        let until = if banner.is_empty() {
            deadline
        } else {
            (Instant::now() + SERVICE_BANNER_IDLE).min(deadline)
        };
        match read_chunk(&mut stream, &mut banner, until).await {
            ReadOutcome::Data => {}
            ReadOutcome::Timeout => break,
            ReadOutcome::Eof => {
                closed = true;
                break;
            }
            ReadOutcome::Error(error) => {
                if banner.is_empty() {
                    return verification_failure(host, port, latency, error);
                }
                closed = true;
                break;
            }
        }
    }

    if banner.is_empty() && !closed {
        return silent_result(host, port, latency, probe_timeout);
    }

    let detection = service::inspect(port, &banner);
    PortResult::new(host, port, PortState::Open, latency).with_detection(detection)
}

fn verification_failure(
    host: IpAddr,
    port: u16,
    latency: Duration,
    error: std::io::Error,
) -> PortResult {
    let failure = classify_io_error(&error);
    PortResult::new(host, port, failure.kind.state(), latency).with_detail(format!(
        "connection closed during verification: {}",
        failure.detail
    ))
}

fn silent_result(
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    PortResult::new(host, port, PortState::Silent, latency).with_detail(format!(
        "handshake succeeded but no banner arrived within {}ms",
        probe_timeout.as_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn options(connect_only: bool) -> ScanOptions {
        ScanOptions {
            timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(100),
            rate: 0,
            workers: 4,
            retries: 0,
            randomize: false,
            connect_only,
            service_detection: true,
            retain: StateSet::all(),
            jitter: Duration::ZERO,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn host() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    async fn banner_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"hello\n").await.unwrap();
        });
        (port, task)
    }

    async fn http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nServer: rayscan-lab\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn request_driven_http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: request-lab/2.0\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn split_banner_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            socket
                .write_all(b"Server: split-lab/1.2\r\n\r\n")
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn silent_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(socket);
        });
        (port, task)
    }

    async fn flaky_http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            second
                .write_all(b"HTTP/1.1 200 OK\r\nServer: retry-lab\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let mut drain = [0u8; 128];
            let _ = tokio::time::timeout(Duration::from_millis(500), second.read(&mut drain)).await;
        });
        (port, task)
    }

    async fn unused_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn detects_open_and_closed_ports() {
        let (open_port, server) = banner_server().await;
        let closed_port = unused_port().await;

        let report = scan(&[host()], &[open_port, closed_port], &options(false), None)
            .await
            .unwrap();

        server.await.unwrap();
        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.closed, 1);
        let open = report
            .results
            .iter()
            .find(|result| result.port == open_port)
            .unwrap();
        assert_eq!(open.state, PortState::Open);
        assert!(open.service.is_none());
        assert_eq!(open.banner.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn detects_http_service_and_product() {
        let (port, server) = http_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        let service = open.service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("rayscan-lab"));
        assert_eq!(open.banner.as_deref(), Some("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn probes_a_service_that_waits_for_a_request() {
        let (port, server) = request_driven_http_server().await;
        let mut options = options(false);
        options.probe_timeout = Duration::from_millis(300);

        let report = scan(&[host()], &[port], &options, None).await.unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        let service = open.service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("request-lab"));
        assert_eq!(service.version.as_deref(), Some("2.0"));
    }

    #[tokio::test]
    async fn collects_a_banner_split_across_reads() {
        let (port, server) = split_banner_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.await.unwrap();

        let service = report.results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("split-lab"));
        assert_eq!(service.version.as_deref(), Some("1.2"));
    }

    #[tokio::test]
    async fn service_detection_can_be_disabled() {
        let (port, server) = http_server().await;
        let mut options = options(false);
        options.service_detection = false;

        let report = scan(&[host()], &[port], &options, None).await.unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        assert!(open.service.is_none());
        assert!(open.banner.is_none());
    }

    #[tokio::test]
    async fn silent_handshake_is_not_reported_open() {
        let (port, server) = silent_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.silent, 1);
        assert_eq!(report.counts.open, 0);
        assert_eq!(report.results[0].state, PortState::Silent);
    }

    #[tokio::test]
    async fn connect_only_reports_a_silent_handshake_as_open() {
        let (port, server) = silent_server().await;
        let report = scan(&[host()], &[port], &options(true), None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn verification_retries_an_ambiguous_silent_candidate() {
        let (port, server) = flaky_http_server().await;
        let mut options = options(false);
        options.probe_timeout = Duration::from_millis(200);
        options.retries = 1;

        let results = verify_candidates(&[(host(), port)], &options, None)
            .await
            .unwrap();
        server.await.unwrap();

        let result = &results[0];
        assert_eq!(result.state, PortState::Open);
        assert_eq!(
            result.service.as_ref().unwrap().product.as_deref(),
            Some("retry-lab")
        );
    }

    #[tokio::test]
    async fn verify_candidates_keeps_open_and_reclassifies_silent() {
        let (open_port, server) = banner_server().await;
        let (silent_port, silent) = silent_server().await;
        let candidates = [(host(), open_port), (host(), silent_port)];

        let results = verify_candidates(&candidates, &options(false), None)
            .await
            .unwrap();

        server.await.unwrap();
        silent.abort();

        let open = results.iter().find(|r| r.port == open_port).unwrap();
        let silent = results.iter().find(|r| r.port == silent_port).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(silent.state, PortState::Silent);
    }

    #[tokio::test]
    async fn progress_callback_runs_once_per_probe() {
        let (open_port, server) = banner_server().await;
        let closed_port = unused_port().await;
        let ticks = Arc::new(AtomicU64::new(0));
        let callback = {
            let ticks = Arc::clone(&ticks);
            Arc::new(move |_event: ProgressEvent| {
                ticks.fetch_add(1, Ordering::Relaxed);
            }) as ProgressCallback
        };

        scan(
            &[host()],
            &[open_port, closed_port],
            &options(false),
            Some(callback),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(ticks.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn reports_every_probe_across_batch_boundaries() {
        // One worker over 200 probes forces several mid-scan batch flushes plus
        // the final partial batch, so a dropped tail or miscounted batch shows
        // up immediately.
        let mut ports = Vec::with_capacity(200);
        for _ in 0..200 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            ports.push(listener.local_addr().unwrap().port());
            drop(listener);
        }
        let mut scan_options = options(false);
        scan_options.workers = 1;
        let ticks = Arc::new(AtomicU64::new(0));
        let callback = {
            let ticks = Arc::clone(&ticks);
            Arc::new(move |_event: ProgressEvent| {
                ticks.fetch_add(1, Ordering::Relaxed);
            }) as ProgressCallback
        };

        let report = scan(&[host()], &ports, &scan_options, Some(callback))
            .await
            .unwrap();

        assert_eq!(report.counts.total(), 200);
        assert_eq!(report.probed_ports.len(), 200);
        assert_eq!(report.results.len(), 200);
        assert_eq!(ticks.load(Ordering::Relaxed), 200);
    }
}
