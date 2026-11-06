//! High-performance raw SYN scanner engine.
//!
//! Features:
//! - Hand-crafted Ethernet/IPv4/TCP frames sent over Linux `AF_PACKET` raw sockets
//! - Kernel-level BPF filtering for inbound SYN-ACK, RST, and ICMP Destination Unreachable frames
//! - SipHash-1-3 stateless SYN cookies encoded into TCP ISN
//! - BlackRock format-preserving Feistel permutation for $O(1)$-memory randomized probe traversal
//! - Asynchronous split-architecture with dedicated TX and RX threads pinned via core affinity
//! - Automatic fallback detection for unprivileged execution without `CAP_NET_RAW`

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::aimd::{AimdConfig, AimdController};
use super::cookie::CookieKey;
use super::filter;
use super::packet;
use super::permute::BlackRock;
use super::route;
use crate::error::AppError;
use crate::model::{PortResult, PortState, ScanReport, StateCounts, StateSet};
use crate::scanner::{ProgressCallback, ProgressEvent};

/// Configuration options for a raw SYN scan.
#[derive(Clone, Debug)]
pub struct SynScanOptions {
    /// Target IP addresses to scan.
    pub targets: Vec<IpAddr>,
    /// Target TCP ports to probe on each host.
    pub ports: Vec<u16>,
    /// Initial transmit rate in packets per second (0 means unlimited).
    pub rate_pps: u64,
    /// Rate used for retransmission passes (0 means `rate_pps / 4`).
    pub retry_rate_pps: u64,
    /// Source port range used by the scanner `(min, max)`.
    pub sport_range: (u16, u16),
    /// Milliseconds to wait after the last transmitted probe before declaring quiet ports filtered.
    pub timeout_ms: u64,
    /// Number of frames to batch per `sendmmsg` syscall.
    pub batch_size: usize,
    /// Number of retransmission passes for probes that received no response.
    pub retries: u32,
    /// Set of port states to retain in the resulting report.
    pub retain: StateSet,
    /// Enable AIMD adaptive rate control.  Has no effect when `rate_pps == 0`.
    pub aimd: bool,
    /// AIMD minimum rate floor in packets per second.
    pub aimd_min_pps: u64,
}

impl Default for SynScanOptions {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: Vec::new(),
            rate_pps: 0,
            retry_rate_pps: 0,
            sport_range: (61000, 61999),
            timeout_ms: 1000,
            batch_size: 64,
            retries: 2,
            retain: StateSet::all(),
            aimd: true,
            aimd_min_pps: 100,
        }
    }
}

/// Internal RAII wrapper ensuring file descriptors are always closed on drop.
struct RawSocket(i32);

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: self.0 is an open socket descriptor managed exclusively by this wrapper.
            unsafe { libc::close(self.0) };
        }
    }
}

/// Resolved routing and MAC addressing for a specific target IPv4 address.
#[derive(Clone, Debug)]
struct TargetRoute {
    if_idx: i32,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
}

/// Incoming probe response message sent from the RX thread to the coordinator.
#[derive(Debug)]
struct RxResponse {
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
}

/// Checks if the current process has the necessary permissions (`root` or `CAP_NET_RAW`)
/// to open raw packet sockets.
pub fn check_raw_privilege() -> Result<(), AppError> {
    // SAFETY: Creating an AF_PACKET raw socket to probe kernel capability.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
            return Err(AppError::runtime(
                "raw SYN scanning requires root privileges or CAP_NET_RAW capability",
            ));
        }
        return Err(AppError::runtime(format!(
            "failed to create raw socket: {err}",
        )));
    }
    // SAFETY: fd is a valid open socket descriptor.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Enables loopback raw frame reception in the Linux kernel if running as root.
fn enable_loopback_raw() {
    let _ = fs::write("/proc/sys/net/ipv4/conf/all/accept_local", "1");
    let _ = fs::write("/proc/sys/net/ipv4/conf/lo/accept_local", "1");
    let _ = fs::write("/proc/sys/net/ipv4/conf/lo/route_localnet", "1");
}

/// Resolves the outgoing interface, source IP, and target/gateway MAC address for a target.
fn resolve_target_route(
    target: Ipv4Addr,
    cache: &mut HashMap<Ipv4Addr, TargetRoute>,
) -> Result<TargetRoute, AppError> {
    if let Some(cached) = cache.get(&target) {
        return Ok(cached.clone());
    }

    if target.is_loopback() {
        enable_loopback_raw();
        let lo_idx = route::iface_index("lo").map_err(|e| AppError::runtime(e.to_string()))?;
        let route_info = TargetRoute {
            if_idx: lo_idx,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: u32::from(Ipv4Addr::new(127, 0, 0, 1)),
        };
        cache.insert(target, route_info.clone());
        return Ok(route_info);
    }

    let rt = route::route_for(target).map_err(|e| AppError::runtime(e.to_string()))?;
    let src_mac = route::iface_mac(&rt.iface).map_err(|e| AppError::runtime(e.to_string()))?;
    let if_idx = route::iface_index(&rt.iface).map_err(|e| AppError::runtime(e.to_string()))?;
    // For directly connected routes, ARP the target itself; for gateway routes, ARP the gateway.
    let dst_mac = route::arp_resolve(&rt.iface, &src_mac, rt.src_ip, rt.gateway_ip)
        .map_err(|e| AppError::runtime(e.to_string()))?;

    let route_info = TargetRoute {
        if_idx,
        src_mac,
        dst_mac,
        src_ip: u32::from(rt.src_ip),
    };
    cache.insert(target, route_info.clone());
    Ok(route_info)
}

/// Lightweight token bucket pacer for transmit pacing.
struct Pacer {
    rate_pps: u64,
    tokens: f64,
    last: Instant,
}

impl Pacer {
    fn new(rate_pps: u64) -> Self {
        Self {
            rate_pps,
            tokens: if rate_pps > 0 {
                (rate_pps as f64 / 10.0).clamp(1.0, 1000.0)
            } else {
                0.0
            },
            last: Instant::now(),
        }
    }

    fn wait_for_batch(&mut self, batch_count: usize) {
        if self.rate_pps == 0 || batch_count == 0 {
            return;
        }

        let rate = self.rate_pps as f64;
        let burst = (rate / 10.0).clamp(1.0, 1000.0);
        let mut remaining = batch_count as f64;

        while remaining > 0.0 {
            let cost = remaining.min(burst);
            loop {
                let now = Instant::now();
                let elapsed = now.duration_since(self.last).as_secs_f64();
                self.last = now;
                self.tokens = (self.tokens + elapsed * rate).min(burst);

                if self.tokens >= cost {
                    self.tokens -= cost;
                    break;
                }

                let needed = cost - self.tokens;
                let sleep_secs = needed / rate;
                std::thread::sleep(Duration::from_secs_f64(sleep_secs));
            }
            remaining -= cost;
        }
    }
}

/// Sends a batch of raw Ethernet frames using `sendmmsg(2)`.
fn send_frames_batch(
    fd: i32,
    batch: &[([u8; 54], libc::sockaddr_ll, (Ipv4Addr, u16))],
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len());
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len());

    for (frame, sll, _) in batch {
        let iov = libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        iovs.push(iov);
        let last_iov_idx = iovs.len() - 1;

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = sll as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &mut iovs[last_iov_idx];
        msg.msg_iovlen = 1;

        let mmsg = libc::mmsghdr {
            msg_hdr: msg,
            msg_len: 0,
        };
        msgs.push(mmsg);
    }

    let mut sent = 0;
    while sent < msgs.len() {
        // SAFETY: `fd` is a valid open socket descriptor. `msgs` points to an array of valid
        // `libc::mmsghdr` structs with corresponding valid iovecs and sockaddr_ll addresses.
        let ret = unsafe {
            libc::sendmmsg(
                fd,
                msgs[sent..].as_mut_ptr(),
                (msgs.len() - sent) as libc::c_uint,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        sent += ret as usize;
    }
    Ok(())
}

fn flush_batch(
    fd: i32,
    pacer: &mut Pacer,
    batch: &mut Vec<([u8; 54], libc::sockaddr_ll, (Ipv4Addr, u16))>,
    tx_times: &mut HashMap<(Ipv4Addr, u16), Instant>,
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    pacer.wait_for_batch(batch.len());
    let now = Instant::now();
    for (_, _, key) in batch.iter() {
        tx_times.insert(*key, now);
    }
    send_frames_batch(fd, batch)?;
    batch.clear();
    Ok(())
}

/// The continuous receive loop executed on the dedicated RX worker thread.
fn rx_loop(
    rx_fd: i32,
    running: Arc<AtomicBool>,
    cookie_key: CookieKey,
    sender: crossbeam_channel::Sender<RxResponse>,
) {
    let mut buf = [0u8; 2048];
    while running.load(Ordering::Acquire) {
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        // SAFETY: `rx_fd` is a valid open socket. `buf` is a writable 2048-byte buffer.
        // `from` points to a properly allocated sockaddr_ll structure.
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                continue;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Ignore our own locally transmitted packets
        if from.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }

        let parsed = packet::parse_frame(&buf[..n as usize]);
        let now = Instant::now();

        match parsed {
            packet::ParsedFrame::SynAck {
                src_ip,
                src_port,
                dst_port,
                ack,
                ..
            } => {
                if cookie_key.validate(src_ip, src_port, dst_port, ack) {
                    let _ = sender.send(RxResponse {
                        host: Ipv4Addr::from(src_ip),
                        port: src_port,
                        state: PortState::Open,
                        timestamp: now,
                    });
                }
            }
            packet::ParsedFrame::Rst {
                src_ip, src_port, ..
            } => {
                let _ = sender.send(RxResponse {
                    host: Ipv4Addr::from(src_ip),
                    port: src_port,
                    state: PortState::Closed,
                    timestamp: now,
                });
            }
            packet::ParsedFrame::IcmpUnreachable { dst_ip, dst_port } => {
                let _ = sender.send(RxResponse {
                    host: Ipv4Addr::from(dst_ip),
                    port: dst_port,
                    state: PortState::Filtered,
                    timestamp: now,
                });
            }
            packet::ParsedFrame::Other => {}
        }
    }
}

fn record_response(
    response: RxResponse,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    fallback: Instant,
) {
    let tx_time = tx_times
        .get(&(response.host, response.port))
        .copied()
        .unwrap_or(fallback);
    let latency = response.timestamp.saturating_duration_since(tx_time);

    if let Some(&(PortState::Open, _)) = responses.get(&(response.host, response.port)) {
        return;
    }
    responses.insert((response.host, response.port), (response.state, latency));
}

fn drain_responses(
    result_rx: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    fallback: Instant,
) {
    while let Ok(response) = result_rx.try_recv() {
        record_response(response, tx_times, responses, fallback);
    }
}

fn wait_for_responses(
    result_rx: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
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
        let wait_step = remaining.min(Duration::from_millis(50));
        match result_rx.recv_timeout(wait_step) {
            Ok(response) => record_response(response, tx_times, responses, fallback),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Executes a raw SYN port scan against the specified target hosts and ports.
pub fn syn_scan(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if opts.targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    // 1. Verify raw socket privilege (CAP_NET_RAW or root)
    check_raw_privilege()?;

    // 2. Filter and extract IPv4 targets
    let mut v4_targets = Vec::with_capacity(opts.targets.len());
    for target in &opts.targets {
        match target {
            IpAddr::V4(v4) => v4_targets.push(*v4),
            IpAddr::V6(_) => {
                return Err(AppError::usage(
                    "raw SYN scanning currently supports IPv4 targets only",
                ));
            }
        }
    }

    let total_probes = (v4_targets.len() as u64)
        .checked_mul(opts.ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;

    // 3. Resolve routes and ARP for all targets
    let mut route_cache = HashMap::new();
    for &target in &v4_targets {
        resolve_target_route(target, &mut route_cache)?;
    }

    // 4. Open RX raw packet socket and attach BPF filter
    // SAFETY: Creating raw AF_PACKET socket to capture IPv4 frames.
    let rx_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if rx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create RX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _rx_sock = RawSocket(rx_fd);

    let filter = filter::build_filter(opts.sport_range.0, opts.sport_range.1);
    filter::attach_filter(rx_fd, &filter).map_err(|e| AppError::runtime(e.to_string()))?;

    // Set receive timeout of 100ms on RX socket
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    // SAFETY: rx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Set receive buffer size to 4MB
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: rx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // 5. Open TX raw packet socket
    // SAFETY: Creating raw AF_PACKET socket for probe frame transmission.
    let tx_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if tx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create TX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _tx_sock = RawSocket(tx_fd);

    let sndbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: tx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            tx_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // 6. Spawn RX worker thread
    let (result_tx, result_rx) = crossbeam_channel::unbounded::<RxResponse>();
    let running = Arc::new(AtomicBool::new(true));
    let cookie_key = CookieKey::random();

    let rx_running = Arc::clone(&running);
    let rx_cookie = cookie_key;
    let rx_handle = std::thread::Builder::new()
        .name("rayscan-rx".to_string())
        .spawn(move || {
            if let Some(first_core) =
                core_affinity::get_core_ids().and_then(|ids| ids.into_iter().next())
            {
                core_affinity::set_for_current(first_core);
            }
            rx_loop(rx_fd, rx_running, rx_cookie, result_tx);
        })
        .map_err(|e| AppError::runtime(format!("failed to spawn RX thread: {e}")))?;

    // 7. Pin TX thread (main thread) to second CPU core if available
    if let Some(second_core) = core_affinity::get_core_ids().and_then(|ids| ids.get(1).copied()) {
        core_affinity::set_for_current(second_core);
    }

    // 8. TX Loop with BlackRock permutation
    let blackrock = BlackRock::new(total_probes);
    let mut pacer = Pacer::new(opts.rate_pps);
    let mut tx_times: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut responses: HashMap<(Ipv4Addr, u16), (PortState, Duration)> = HashMap::new();
    let mut batch: Vec<([u8; 54], libc::sockaddr_ll, (Ipv4Addr, u16))> =
        Vec::with_capacity(opts.batch_size.max(1));

    let sport_lo = opts.sport_range.0;
    let sport_hi = opts.sport_range.1;
    let range_len = (sport_hi - sport_lo + 1) as u64;
    let ports_len = opts.ports.len() as u64;
    let start_time = Instant::now();

    let timeout_duration = Duration::from_millis(opts.timeout_ms);
    let attempts = opts.retries.saturating_add(1);

    // Compute effective retry rate (default: quarter of initial rate, min 100 pps)
    let retry_rate_pps = if opts.retry_rate_pps > 0 {
        opts.retry_rate_pps
    } else if opts.rate_pps > 0 {
        (opts.rate_pps / 4).max(100)
    } else {
        0
    };

    // AIMD controller for the initial pass
    let mut aimd = AimdController::new(AimdConfig {
        initial_pps: opts.rate_pps,
        min_pps: opts.aimd_min_pps.max(1),
        max_pps: opts.rate_pps,
        step_pps: (opts.rate_pps / 20).max(10),
        ..AimdConfig::default()
    });

    for attempt in 0..attempts {
        let mut sent_any = false;
        // Use lower rate on retransmission passes; AIMD only applies to pass 0
        if attempt > 0 {
            pacer = Pacer::new(retry_rate_pps);
        }
        let mut pass_sent: u64 = 0;
        let mut pass_received: u64 = responses.len() as u64;

        for i in 0..total_probes {
            let perm_idx = blackrock.encrypt(i);
            let target_idx = (perm_idx / ports_len) as usize;
            let port_idx = (perm_idx % ports_len) as usize;
            let target_ip = v4_targets[target_idx];
            let target_port = opts.ports[port_idx];

            if attempt > 0 && responses.contains_key(&(target_ip, target_port)) {
                continue;
            }

            let sport_offset = perm_idx.wrapping_add((attempt as u64).wrapping_mul(total_probes));
            let src_port = sport_lo + (sport_offset % range_len) as u16;
            let seq = cookie_key.encode(u32::from(target_ip), target_port, src_port);

            let rt = route_cache.get(&target_ip).expect("cached route");
            let frame = packet::build_syn_frame(
                &rt.src_mac,
                &rt.dst_mac,
                rt.src_ip,
                u32::from(target_ip),
                src_port,
                target_port,
                seq,
            );

            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
            sll.sll_ifindex = rt.if_idx;
            sll.sll_halen = 6;
            sll.sll_addr[..6].copy_from_slice(&rt.dst_mac);

            batch.push((frame, sll, (target_ip, target_port)));
            sent_any = true;

            if batch.len() >= opts.batch_size.max(1) {
                flush_batch(tx_fd, &mut pacer, &mut batch, &mut tx_times)
                    .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;
                pass_sent += opts.batch_size as u64;
            }

            let prev_responses = responses.len() as u64;
            drain_responses(&result_rx, &tx_times, &mut responses, start_time);
            let new_responses = responses.len() as u64 - prev_responses;
            pass_received += new_responses;

            // Update AIMD on the initial pass after each batch flush
            if attempt == 0 && opts.aimd && opts.rate_pps > 0 && pass_sent > 0 {
                let new_rate = aimd.update(pass_sent, pass_received);
                pacer = Pacer::new(new_rate);
            }

            if attempt == 0
                && let Some(cb) = &progress
            {
                cb(ProgressEvent::default());
            }
        }

        flush_batch(tx_fd, &mut pacer, &mut batch, &mut tx_times)
            .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;

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

    // 10. Stop RX thread
    running.store(false, Ordering::Release);
    let _ = rx_handle.join();

    drain_responses(&result_rx, &tx_times, &mut responses, start_time);

    // 11. Aggregate scan report
    let mut counts = StateCounts::default();
    let mut results = Vec::new();

    for &target in &v4_targets {
        for &port in &opts.ports {
            let (state, latency) = match responses.get(&(target, port)) {
                Some(&(st, lat)) => (st, lat),
                None => (PortState::Filtered, timeout_duration),
            };
            counts.add(state);
            if opts.retain.contains(state) {
                results.push(PortResult::new(IpAddr::V4(target), port, state, latency));
            }
        }
    }

    Ok(ScanReport {
        targets: v4_targets.len(),
        ports: opts.ports.len(),
        jobs: total_probes,
        workers: 2,
        elapsed: start_time.elapsed(),
        counts,
        results,
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports: opts.ports.clone(),
        partial: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_handles_batches_larger_than_the_burst() {
        let mut pacer = Pacer::new(1000);
        let started = Instant::now();
        pacer.wait_for_batch(101);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
