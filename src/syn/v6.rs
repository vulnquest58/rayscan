//! Raw IPv6 SYN scanning over Linux `AF_INET6` raw sockets.
//!
//! IPv6 neighbours and routing are delegated to the kernel (unlike the
//! `AF_PACKET` IPv4 engine). SYN cookies bind the 128-bit target address to
//! the target/source port pair in the same stateless way as IPv4.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::engine::{Pacer, SynScanOptions};
use super::packet;
use super::permute::BlackRock;
use crate::error::AppError;
use crate::model::{PortResult, PortState, ScanReport, StateCounts};
use crate::scanner::{ProgressCallback, ProgressEvent};

struct RawSocket(i32);

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: the descriptor is owned exclusively by this wrapper.
            unsafe { libc::close(self.0) };
        }
    }
}

#[derive(Debug)]
struct RxResponse {
    host: Ipv6Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
}

fn sockaddr_v6(target: Ipv6Addr, port: u16) -> libc::sockaddr_in6 {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as u16;
    addr.sin6_port = port.to_be();
    addr.sin6_addr.s6_addr = target.octets();
    addr
}

/// `IPPROTO_RAW` IPv6 destinations reject a non-zero `sin6_port`.
fn sockaddr_v6_raw(target: Ipv6Addr) -> libc::sockaddr_in6 {
    sockaddr_v6(target, 0)
}

pub(crate) fn source_for(target: Ipv6Addr, port: u16) -> Result<Ipv6Addr, AppError> {
    let socket = UdpSocket::bind("[::]:0").map_err(|error| {
        AppError::runtime(format!("cannot create IPv6 route probe socket: {error}"))
    })?;
    socket
        .connect(SocketAddrV6::new(target, port, 0, 0))
        .map_err(|error| {
            AppError::runtime(format!("cannot route to IPv6 target {target}: {error}"))
        })?;
    match socket.local_addr() {
        Ok(std::net::SocketAddr::V6(addr)) => Ok(*addr.ip()),
        _ => Err(AppError::runtime(format!(
            "cannot determine IPv6 source address for {target}"
        ))),
    }
}

fn rx_loop(
    rx_fd: i32,
    running: Arc<AtomicBool>,
    cookie_key: super::cookie::CookieKey,
    sender: crossbeam_channel::Sender<RxResponse>,
) {
    let mut buf = [0u8; 2048];
    while running.load(Ordering::Acquire) {
        let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        // SAFETY: rx_fd is a valid raw IPv6 socket and both buffers are owned here.
        let n = unsafe {
            libc::recvfrom(
                rx_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            break;
        }

        let peer = Ipv6Addr::from(from.sin6_addr.s6_addr);
        let now = Instant::now();
        match packet::parse_ipv6_tcp(&buf[..n as usize], Some(peer)) {
            packet::ParsedV6Frame::SynAck {
                src_ip,
                src_port,
                dst_port,
                ack,
            } => {
                if cookie_key.validate_v6(&src_ip.octets(), src_port, dst_port, ack) {
                    let _ = sender.send(RxResponse {
                        host: src_ip,
                        port: src_port,
                        state: PortState::Open,
                        timestamp: now,
                    });
                }
            }
            packet::ParsedV6Frame::Rst {
                src_ip, src_port, ..
            } => {
                let _ = sender.send(RxResponse {
                    host: src_ip,
                    port: src_port,
                    state: PortState::Closed,
                    timestamp: now,
                });
            }
            packet::ParsedV6Frame::Other => {}
        }
    }
}

fn record_response(
    response: RxResponse,
    tx_times: &HashMap<(Ipv6Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv6Addr, u16), (PortState, Duration)>,
    fallback: Instant,
) {
    let key = (response.host, response.port);
    if matches!(responses.get(&key), Some((PortState::Open, _))) {
        return;
    }
    let latency = response
        .timestamp
        .saturating_duration_since(tx_times.get(&key).copied().unwrap_or(fallback));
    responses.insert(key, (response.state, latency));
}

fn drain_responses(
    receiver: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv6Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv6Addr, u16), (PortState, Duration)>,
    fallback: Instant,
) {
    while let Ok(response) = receiver.try_recv() {
        record_response(response, tx_times, responses, fallback);
    }
}

fn wait_for_responses(
    receiver: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv6Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv6Addr, u16), (PortState, Duration)>,
    fallback: Instant,
    total_probes: u64,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if responses.len() >= total_probes as usize {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(response) => record_response(response, tx_times, responses, fallback),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Execute a raw IPv6 SYN scan for the supplied targets.
pub(super) fn scan_v6(
    targets: &[Ipv6Addr],
    opts: &SynScanOptions,
    progress: Option<&ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    let total_probes = (targets.len() as u64)
        .checked_mul(opts.ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;

    let mut sources: HashMap<Ipv6Addr, Ipv6Addr> = HashMap::new();
    for &target in targets {
        let source = source_for(target, opts.ports[0])?;
        sources.insert(target, source);
    }

    // SAFETY: probe whether an AF_INET6 raw TCP socket can be created.
    let rx_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if rx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create IPv6 RX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _rx_socket = RawSocket(rx_fd);

    let bind_addr = sockaddr_v6(Ipv6Addr::UNSPECIFIED, 0);
    // SAFETY: rx_fd is a valid socket and bind_addr is fully initialized.
    if unsafe {
        libc::bind(
            rx_fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(AppError::runtime(format!(
            "failed to bind IPv6 RX socket: {}",
            io::Error::last_os_error()
        )));
    }

    let timeout_us = 100_000;
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: timeout_us,
    };
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: rx_fd is a valid socket; option pointers are valid for the call.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // IPPROTO_RAW always expects the IPv6 header on Linux raw sockets.
    // SAFETY: creating a raw IPv6 transmit socket.
    let tx_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if tx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create IPv6 TX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _tx_socket = RawSocket(tx_fd);

    let (result_tx, result_rx) = crossbeam_channel::unbounded::<RxResponse>();
    let running = Arc::new(AtomicBool::new(true));
    let cookie_key = super::cookie::CookieKey::random();

    let rx_running = Arc::clone(&running);
    let rx_cookie = cookie_key;
    let rx_handle = std::thread::Builder::new()
        .name("rayscan-rx6".to_string())
        .spawn(move || rx_loop(rx_fd, rx_running, rx_cookie, result_tx))
        .map_err(|error| AppError::runtime(format!("failed to spawn IPv6 RX thread: {error}")))?;

    let blackrock = BlackRock::new(total_probes);
    let mut pacer = Pacer::new(opts.rate_pps);
    let mut tx_times: HashMap<(Ipv6Addr, u16), Instant> = HashMap::new();
    let mut responses: HashMap<(Ipv6Addr, u16), (PortState, Duration)> = HashMap::new();

    let sport_lo = opts.sport_range.0;
    let sport_hi = opts.sport_range.1;
    let range_len = (sport_hi - sport_lo + 1) as u64;
    let ports_len = opts.ports.len() as u64;
    let start_time = Instant::now();
    let timeout_duration = Duration::from_millis(opts.timeout_ms);
    let attempts = opts.retries.saturating_add(1);
    let retry_rate = if opts.retry_rate_pps > 0 {
        opts.retry_rate_pps
    } else if opts.rate_pps > 0 {
        (opts.rate_pps / 4).max(100)
    } else {
        0
    };

    for attempt in 0..attempts {
        if attempt > 0 {
            pacer = Pacer::new(retry_rate);
        }
        let mut sent_any = false;

        for index in 0..total_probes {
            let perm_index = blackrock.encrypt(index);
            let target = targets[(perm_index / ports_len) as usize];
            let port = opts.ports[(perm_index % ports_len) as usize];
            if attempt > 0 && responses.contains_key(&(target, port)) {
                continue;
            }

            let sport_offset = perm_index.wrapping_add((attempt as u64).wrapping_mul(total_probes));
            let source_port = sport_lo + (sport_offset % range_len) as u16;
            let sequence = cookie_key.encode_v6(&target.octets(), port, source_port);
            let source = sources[&target];
            let packet =
                packet::build_ipv6_syn_packet(&source, &target, source_port, port, sequence);

            pacer.wait_for_batch(1);
            let destination = sockaddr_v6_raw(target);
            // SAFETY: tx_fd is a valid raw IPv6 socket; packet and destination are valid.
            let sent = unsafe {
                libc::sendto(
                    tx_fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &destination as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(AppError::runtime(format!(
                    "IPv6 TX send failed: {}",
                    io::Error::last_os_error()
                )));
            }
            tx_times.insert((target, port), Instant::now());
            sent_any = true;

            drain_responses(&result_rx, &tx_times, &mut responses, start_time);
            if let Some(callback) = progress {
                callback(ProgressEvent::default());
            }
        }

        wait_for_responses(
            &result_rx,
            &tx_times,
            &mut responses,
            start_time,
            total_probes,
            timeout_duration,
        );

        if !sent_any || responses.len() >= total_probes as usize {
            break;
        }
    }

    running.store(false, Ordering::Release);
    let _ = rx_handle.join();
    drain_responses(&result_rx, &tx_times, &mut responses, start_time);

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = responses
                .get(&(target, port))
                .copied()
                .unwrap_or((PortState::Filtered, timeout_duration));
            counts.add(state);
            if opts.retain.contains(state) {
                results.push(PortResult::new(IpAddr::V6(target), port, state, latency));
            }
        }
    }

    Ok(ScanReport {
        targets: targets.len(),
        ports: opts.ports.len(),
        jobs: total_probes,
        workers: 2,
        elapsed: start_time.elapsed(),
        counts,
        results,
        os_fingerprints: HashMap::new(),
        probed_ports: opts.ports.clone(),
        partial: false,
        defense_observations: Vec::new(),
    })
}
