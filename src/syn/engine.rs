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
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts, StateSet};
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
    /// Maximum random delay inserted before each packet batch, in milliseconds.
    pub jitter_ms: u64,
    /// Spoofed source addresses for decoy probes (IPv4 only).
    pub decoys: Vec<Ipv4Addr>,
    /// Maximum IPv4 payload bytes per fragment (multiple of 8). `None` disables.
    pub fragment_size: Option<usize>,
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
            batch_size: 4096,
            retries: 2,
            retain: StateSet::all(),
            aimd: true,
            aimd_min_pps: 100,
            jitter_ms: 0,
            decoys: Vec::new(),
            fragment_size: None,
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

/// One outbound frame with an optional probe key used for latency tracking.
struct TxFrame {
    frame: Vec<u8>,
    sll: libc::sockaddr_ll,
    key: Option<(Ipv4Addr, u16)>,
}

/// Preallocated, reusable transmit batch.
///
/// Frame buffers are allocated once when the batch is created and reused slot
/// by slot across every probe/retransmission pass, so the steady-state transmit
/// loop never hits the heap allocator.
struct Batch {
    slots: Vec<TxFrame>,
    len: usize,
}

impl Batch {
    fn new(batch_size: usize) -> Self {
        let slots = (0..batch_size.max(1))
            .map(|_| TxFrame {
                frame: Vec::with_capacity(64),
                sll: unsafe { std::mem::zeroed() },
                key: None,
            })
            .collect();
        Self { slots, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a frame built on the stack (no heap allocation in steady state).
    fn push_frame(
        &mut self,
        frame: &[u8],
        if_idx: i32,
        dst_mac: &[u8; 6],
        key: Option<(Ipv4Addr, u16)>,
    ) {
        // Fragmented probes emit several frames for one slot iteration, so the
        // pool occasionally needs to grow past `batch_size`; existing slots are
        // never reallocated.
        if self.len >= self.slots.len() {
            self.slots.push(TxFrame {
                frame: Vec::with_capacity(64),
                sll: unsafe { std::mem::zeroed() },
                key: None,
            });
        }
        let slot = &mut self.slots[self.len];
        slot.frame.clear();
        slot.frame.extend_from_slice(frame);
        slot.sll = make_sll(if_idx, dst_mac);
        slot.key = key;
        self.len += 1;
    }
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
pub(super) struct Pacer {
    rate_pps: u64,
    tokens: f64,
    last: Instant,
}

impl Pacer {
    pub(super) fn new(rate_pps: u64) -> Self {
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

    pub(super) fn wait_for_batch(&mut self, batch_count: usize) {
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
fn send_frames_batch(fd: i32, batch: &[TxFrame]) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len());
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len());

    for TxFrame { frame, sll, .. } in batch {
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
    batch: &mut Batch,
    tx_times: &mut HashMap<(Ipv4Addr, u16), Instant>,
    jitter_ms: u64,
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    pacer.wait_for_batch(batch.len());
    if jitter_ms > 0 {
        use rand::Rng;
        let delay = rand::thread_rng().gen_range(0..=jitter_ms);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
    }
    let now = Instant::now();
    for entry in batch.slots[..batch.len].iter() {
        if let Some(key) = entry.key {
            tx_times.insert(key, now);
        }
    }
    send_frames_batch(fd, &batch.slots[..batch.len])?;
    batch.len = 0;
    Ok(())
}

fn decoy_source_port(index: usize, sport_lo: u16, sport_hi: u16) -> u16 {
    let mut candidate = 1024_u16.wrapping_add(index as u16);
    for _ in 0..128 {
        if candidate != 0 && !(sport_lo..=sport_hi).contains(&candidate) {
            return candidate;
        }
        candidate = candidate.wrapping_add(1001);
    }
    if sport_lo > 1024 { 1023 } else { 65535 }
}

fn make_sll(if_idx: i32, dst_mac: &[u8; 6]) -> libc::sockaddr_ll {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = if_idx;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(dst_mac);
    sll
}

/// Routes a decoded response to the TX worker that owns the target address.
fn dispatch_response(
    senders: &[crossbeam_channel::Sender<RxResponse>],
    owners: &HashMap<Ipv4Addr, usize>,
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
) {
    if let Some(&index) = owners.get(&host)
        && let Some(sender) = senders.get(index)
    {
        let _ = sender.send(RxResponse {
            host,
            port,
            state,
            timestamp,
        });
    }
}

/// Number of frames drained from the RX socket per `recvmmsg(2)` syscall.
const RX_BATCH: usize = 64;
/// Per-datagram receive buffer size (Ethernet frames are well under 2 KiB).
const RX_SLOT_SIZE: usize = 2048;

struct RxBatch {
    data: Vec<[u8; RX_SLOT_SIZE]>,
    addrs: Vec<libc::sockaddr_ll>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl RxBatch {
    fn new(count: usize) -> Self {
        let data = vec![[0u8; RX_SLOT_SIZE]; count];
        let mut batch = Self {
            addrs: vec![unsafe { std::mem::zeroed() }; count],
            iovs: Vec::with_capacity(count.next_power_of_two()),
            msgs: Vec::with_capacity(count),
            data,
        };
        // SAFETY: every pointer group stays allocated and stable for the
        // lifetime of `batch`; the iovec/msg arrays are never reallocated
        // after construction.
        for slot in 0..count {
            let payload = batch.data[slot].as_mut_ptr();
            let name = batch.addrs.as_mut_ptr().wrapping_add(slot);
            // SAFETY: base pointers are initialized before the recv loop runs.
            let iov = libc::iovec {
                iov_base: payload.cast(),
                iov_len: RX_SLOT_SIZE,
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = name.cast();
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            msg.msg_iov = batch.iovs.as_mut_ptr().wrapping_add(slot);
            msg.msg_iovlen = 1;
            batch.iovs.push(iov);
            batch.msgs.push(libc::mmsghdr {
                msg_hdr: msg,
                msg_len: 0,
            });
        }
        batch
    }
}

/// Receives a batch of frames into `batch`; returns the number of frames read.
fn receive_batch(rx_fd: i32, batch: &mut RxBatch) -> io::Result<usize> {
    for msg in batch.msgs.iter_mut() {
        msg.msg_len = 0;
    }
    // SAFETY: `rx_fd` is a valid open socket; `batch.msgs` points to prebuilt
    // `libc::mmsghdr` entries whose iovecs and names reference allocations
    // owned by `batch` and outlive the syscall.
    let n = unsafe {
        libc::recvmmsg(
            rx_fd,
            batch.msgs.as_mut_ptr(),
            batch.msgs.len() as libc::c_uint,
            0,
            std::ptr::null_mut(),
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// The continuous receive loop executed on the dedicated RX worker thread.
fn rx_loop(
    rx_fd: i32,
    running: Arc<AtomicBool>,
    cookie_key: CookieKey,
    senders: Vec<crossbeam_channel::Sender<RxResponse>>,
    owners: HashMap<Ipv4Addr, usize>,
) {
    let mut batch = RxBatch::new(RX_BATCH);
    while running.load(Ordering::Acquire) {
        let count = match receive_batch(rx_fd, &mut batch) {
            Ok(count) => count,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };

        for index in 0..count {
            let len = batch.msgs[index].msg_len as usize;
            if len == 0 || batch.addrs[index].sll_pkttype == libc::PACKET_OUTGOING {
                // Ignore our own locally transmitted packets
                continue;
            }
            let frame = &batch.data[index][..len];
            let parsed = packet::parse_frame(frame);
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
                        dispatch_response(
                            &senders,
                            &owners,
                            Ipv4Addr::from(src_ip),
                            src_port,
                            PortState::Open,
                            now,
                        );
                    }
                }
                packet::ParsedFrame::Rst {
                    src_ip, src_port, ..
                } => {
                    dispatch_response(
                        &senders,
                        &owners,
                        Ipv4Addr::from(src_ip),
                        src_port,
                        PortState::Closed,
                        now,
                    );
                }
                packet::ParsedFrame::IcmpUnreachable { dst_ip, dst_port } => {
                    dispatch_response(
                        &senders,
                        &owners,
                        Ipv4Addr::from(dst_ip),
                        dst_port,
                        PortState::Filtered,
                        now,
                    );
                }
                packet::ParsedFrame::Other => {}
            }
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

/// Executes a raw SYN port scan against IPv4 and IPv6 targets.
pub fn syn_scan(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if opts.targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }
    let v4_targets: Vec<Ipv4Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    let v6_targets: Vec<std::net::Ipv6Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    if v6_targets.is_empty() {
        return syn_scan_v4(opts, progress);
    }
    if v4_targets.is_empty() {
        return super::v6::scan_v6(&v6_targets, &opts, progress.as_ref());
    }

    let started = Instant::now();
    let mut v4_opts = opts.clone();
    v4_opts.targets = v4_targets.iter().copied().map(IpAddr::V4).collect();
    let v4_report = syn_scan_v4(v4_opts, progress.clone())?;
    let mut report = super::v6::scan_v6(&v6_targets, &opts, progress.as_ref())?;

    report.targets += v4_report.targets;
    report.jobs += v4_report.jobs;
    report.elapsed = started.elapsed();
    report.counts.open += v4_report.counts.open;
    report.counts.closed += v4_report.counts.closed;
    report.counts.filtered += v4_report.counts.filtered;
    report.counts.silent += v4_report.counts.silent;
    report.counts.unreachable += v4_report.counts.unreachable;
    report.counts.error += v4_report.counts.error;
    report.results.extend(v4_report.results);
    report.os_fingerprints.extend(v4_report.os_fingerprints);
    report.partial |= v4_report.partial;
    Ok(report)
}

/// Splits targets into contiguous destination shards for parallel TX workers.
fn shard_targets(targets: &[Ipv4Addr], max_workers: usize) -> Vec<Vec<Ipv4Addr>> {
    let max_workers = max_workers.max(1);
    let shard_len = targets.len().div_ceil(max_workers).max(1);
    targets
        .chunks(shard_len)
        .map(<[Ipv4Addr]>::to_vec)
        .collect()
}

/// Builds a lookup table mapping every target address to its owning shard.
fn shard_owners(shards: &[Vec<Ipv4Addr>]) -> HashMap<Ipv4Addr, usize> {
    let mut owners = HashMap::new();
    for (index, shard) in shards.iter().enumerate() {
        for &target in shard {
            owners.insert(target, index);
        }
    }
    owners
}

/// Per-TX-worker shard handed to its dedicated thread.
struct ShardJob {
    worker_id: usize,
    /// Number of CPU cores observed; used for core-affinity pinning.
    core_count: usize,
    targets: Vec<Ipv4Addr>,
    /// Pre-divided per-worker transmit rate (0 means unlimited).
    rate_pps: u64,
    /// Pre-divided per-worker retransmission rate (0 means unlimited).
    retry_rate_pps: u64,
    opts: SynScanOptions,
    routes: std::sync::Arc<HashMap<Ipv4Addr, TargetRoute>>,
    cookie_key: CookieKey,
    result_rx: crossbeam_channel::Receiver<RxResponse>,
    progress: Option<ProgressCallback>,
}

fn run_shard(job: ShardJob) -> Result<ScanReport, AppError> {
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

    // Pin each TX worker to a core after the RX-reserved first core.
    if job.core_count > 1
        && let Some(core) = core_affinity::get_core_ids()
            .and_then(|ids| ids.get((job.worker_id % (ids.len() - 1)) + 1).copied())
    {
        core_affinity::set_for_current(core);
    }

    scan_shard(&job, tx_fd)
}

fn scan_shard(job: &ShardJob, tx_fd: i32) -> Result<ScanReport, AppError> {
    let targets = job.targets.as_slice();
    let opts = &job.opts;
    let ports_len = opts.ports.len() as u64;
    if targets.is_empty() || ports_len == 0 {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }
    let total_probes = (targets.len() as u64)
        .checked_mul(ports_len)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;

    let blackrock = BlackRock::new(total_probes);
    let mut pacer = Pacer::new(job.rate_pps);
    let mut tx_times: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut responses: HashMap<(Ipv4Addr, u16), (PortState, Duration)> = HashMap::new();
    let batch_size = opts.batch_size.max(1);
    let mut batch = Batch::new(batch_size);
    let batch_flush_count = batch_size as u64;

    let sport_lo = opts.sport_range.0;
    let sport_hi = opts.sport_range.1;
    let range_len = (sport_hi - sport_lo + 1) as u64;
    let start_time = Instant::now();

    let timeout_duration = Duration::from_millis(opts.timeout_ms);
    let attempts = opts.retries.saturating_add(1);

    // AIMD controller for the initial pass
    let mut aimd = AimdController::new(AimdConfig {
        initial_pps: job.rate_pps,
        min_pps: opts.aimd_min_pps.max(1),
        max_pps: job.rate_pps,
        step_pps: (job.rate_pps / 4).max(10),
        ..AimdConfig::default()
    });
    let mut aimd_last_tick = Instant::now();

    for attempt in 0..attempts {
        let mut sent_any = false;
        // Use lower rate on retransmission passes; AIMD only applies to pass 0
        if attempt > 0 {
            pacer = Pacer::new(job.retry_rate_pps);
        }
        let mut pass_sent: u64 = 0;
        let mut pass_received: u64 = responses.len() as u64;

        for i in 0..total_probes {
            let perm_idx = blackrock.encrypt(i);
            let target_idx = (perm_idx / ports_len) as usize;
            let port_idx = (perm_idx % ports_len) as usize;
            let target_ip = targets[target_idx];
            let target_port = opts.ports[port_idx];

            if attempt > 0 && responses.contains_key(&(target_ip, target_port)) {
                continue;
            }

            let sport_offset = perm_idx.wrapping_add((attempt as u64).wrapping_mul(total_probes));
            let src_port = sport_lo + (sport_offset % range_len) as u16;
            let seq = job
                .cookie_key
                .encode(u32::from(target_ip), target_port, src_port);

            let rt = job
                .routes
                .get(&target_ip)
                .expect("target route resolved by the coordinator");
            let mut stack_frame = [0u8; 54];
            packet::write_syn_frame(
                &mut stack_frame,
                &rt.src_mac,
                &rt.dst_mac,
                rt.src_ip,
                u32::from(target_ip),
                src_port,
                target_port,
                seq,
            );

            let real_frames = match opts.fragment_size {
                Some(size) => packet::fragment_syn_frame(&stack_frame, size),
                None => vec![stack_frame.to_vec()],
            };
            for frame in real_frames {
                batch.push_frame(
                    &frame,
                    rt.if_idx,
                    &rt.dst_mac,
                    Some((target_ip, target_port)),
                );
            }

            for (decoy_index, decoy) in opts.decoys.iter().enumerate() {
                let decoy_port = decoy_source_port(decoy_index, sport_lo, sport_hi);
                let decoy_frame = packet::build_syn_frame(
                    &rt.src_mac,
                    &rt.dst_mac,
                    u32::from(*decoy),
                    u32::from(target_ip),
                    decoy_port,
                    target_port,
                    seq.wrapping_add(decoy_index as u32 + 1),
                );
                let decoy_frames = match opts.fragment_size {
                    Some(size) => packet::fragment_syn_frame(&decoy_frame, size),
                    None => vec![decoy_frame.to_vec()],
                };
                for frame in decoy_frames {
                    batch.push_frame(&frame, rt.if_idx, &rt.dst_mac, None);
                }
            }
            sent_any = true;

            if batch.len() >= batch_size {
                flush_batch(tx_fd, &mut pacer, &mut batch, &mut tx_times, opts.jitter_ms)
                    .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;
                pass_sent += batch_flush_count;

                let prev_responses = responses.len() as u64;
                drain_responses(&job.result_rx, &tx_times, &mut responses, start_time);
                let new_responses = responses.len() as u64 - prev_responses;
                pass_received += new_responses;

                // Update AIMD on the initial pass using a fixed 1 s window.
                // Updating per flush with cumulative counts measures the ratio
                // before the just-flushed batch's responses arrive, which reads
                // low on every update and collapses the rate toward min_pps.
                if attempt == 0
                    && opts.aimd
                    && job.rate_pps > 0
                    && pass_sent >= 64
                    && aimd_last_tick.elapsed() >= Duration::from_secs(1)
                {
                    let new_rate = aimd.update(pass_sent, pass_received);
                    pacer = Pacer::new(new_rate);
                    aimd_last_tick = Instant::now();
                    pass_sent = 0;
                    pass_received = 0;
                }

                if attempt == 0
                    && let Some(cb) = &job.progress
                {
                    cb(ProgressEvent::default());
                }
            }
        }

        flush_batch(tx_fd, &mut pacer, &mut batch, &mut tx_times, opts.jitter_ms)
            .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;

        wait_for_responses(
            &job.result_rx,
            &tx_times,
            &mut responses,
            start_time,
            total_probes,
            timeout_duration,
        );

        if !sent_any || responses.len() >= total_probes as usize {
            break;
        }

        // A path that answered to under 1 % of the first pass's probes is
        // silent: retransmits cannot recover responses that never arrive on
        // such a path, so skip the retry passes instead of paying their wall
        // clock again.
        if attempt == 0 && responses.len() * 100 < total_probes as usize {
            break;
        }
    }

    drain_responses(&job.result_rx, &tx_times, &mut responses, start_time);

    // Aggregate the shard scan report
    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();

    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = match responses.get(&(target, port)) {
                Some(&(st, lat)) => (st, lat),
                None => (PortState::Filtered, timeout_duration),
            };
            counts.add(state);
            let progress = host_progress.entry(IpAddr::V4(target)).or_default();
            progress.ports_scanned.push(port);
            progress.counts.add(state);
            if opts.retain.contains(state) {
                results.push(PortResult::new(IpAddr::V4(target), port, state, latency));
            }
        }
    }

    Ok(ScanReport {
        targets: targets.len(),
        ports: opts.ports.len(),
        jobs: total_probes,
        workers: 1,
        elapsed: start_time.elapsed(),
        counts,
        results,
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}

fn syn_scan_v4(
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

    // 2. Extract IPv4 targets (IPv6 is handled by the AF_INET6 engine).
    let v4_targets: Vec<Ipv4Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect();

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

    // 5. Thread layout: one RX thread plus one TX thread per target shard.
    let core_ids: Vec<core_affinity::CoreId> = core_affinity::get_core_ids().unwrap_or_default();
    let core_count = core_ids.len().max(1);
    let max_tx_workers = (core_count / 2).clamp(1, 8);
    let shards = shard_targets(&v4_targets, max_tx_workers);
    let worker_count = shards.len();
    let owners = shard_owners(&shards);

    let mut senders: Vec<crossbeam_channel::Sender<RxResponse>> = Vec::with_capacity(worker_count);
    let mut channels: Vec<crossbeam_channel::Receiver<RxResponse>> =
        Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (sender, receiver) = crossbeam_channel::unbounded::<RxResponse>();
        senders.push(sender);
        channels.push(receiver);
    }

    let running = Arc::new(AtomicBool::new(true));
    let cookie_key = CookieKey::random();

    // 6. Spawn RX worker thread with per-shard fan-out
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
            rx_loop(rx_fd, rx_running, rx_cookie, senders, owners);
        })
        .map_err(|e| AppError::runtime(format!("failed to spawn RX thread: {e}")))?;

    // 7. Divide rates evenly across TX workers
    let per_worker_rate = if opts.rate_pps > 0 {
        (opts.rate_pps / worker_count as u64).max(1)
    } else {
        0
    };
    let per_worker_retry_rate = if opts.retry_rate_pps > 0 {
        (opts.retry_rate_pps / worker_count as u64).max(1)
    } else if opts.rate_pps > 0 {
        (per_worker_rate / 4).max(100)
    } else {
        0
    };

    // 8. Spawn one TX worker per shard, each with its own AF_PACKET socket
    let routes = std::sync::Arc::new(route_cache);
    let overall_start = Instant::now();
    let mut handles = Vec::with_capacity(worker_count);
    for (worker_id, shard) in shards.into_iter().enumerate() {
        let shard_routes = std::sync::Arc::clone(&routes);
        let shard_opts = opts.clone();
        let shard_receiver = channels.remove(0);
        let shard_progress = progress.clone();
        let shard_cookie = cookie_key;
        let handle = std::thread::Builder::new()
            .name(format!("rayscan-tx{worker_id}"))
            .spawn(move || {
                run_shard(ShardJob {
                    worker_id,
                    core_count,
                    targets: shard,
                    rate_pps: per_worker_rate,
                    retry_rate_pps: per_worker_retry_rate,
                    opts: shard_opts,
                    routes: shard_routes,
                    cookie_key: shard_cookie,
                    result_rx: shard_receiver,
                    progress: shard_progress,
                })
            })
            .map_err(|e| AppError::runtime(format!("failed to spawn TX worker: {e}")))?;
        handles.push(handle);
    }

    // 9. Collect shard reports
    let mut merged = ScanReport {
        targets: v4_targets.len(),
        ports: opts.ports.len(),
        jobs: 0,
        workers: worker_count + 1,
        elapsed: overall_start.elapsed(),
        counts: StateCounts::default(),
        results: Vec::new(),
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress: HashMap::new(),
        partial: false,
        defense_observations: Vec::new(),
    };
    let mut worker_error: Option<AppError> = None;
    for handle in handles {
        let shard_report = match handle.join() {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                worker_error = Some(error);
                break;
            }
            Err(panic) => {
                worker_error = Some(AppError::runtime(format!("TX worker panicked: {panic:?}")));
                break;
            }
        };
        merged.jobs = merged.jobs.saturating_add(shard_report.jobs);
        merged.counts.open += shard_report.counts.open;
        merged.counts.closed += shard_report.counts.closed;
        merged.counts.filtered += shard_report.counts.filtered;
        merged.counts.silent += shard_report.counts.silent;
        merged.counts.unreachable += shard_report.counts.unreachable;
        merged.counts.error += shard_report.counts.error;
        merged.results.extend(shard_report.results);
        merged.os_fingerprints.extend(shard_report.os_fingerprints);
        merged.host_progress.extend(shard_report.host_progress);
        merged.partial |= shard_report.partial;
    }
    merged.elapsed = overall_start.elapsed();

    // 10. Stop RX thread
    running.store(false, Ordering::Release);
    let _ = rx_handle.join();

    if let Some(error) = worker_error {
        return Err(error);
    }

    Ok(merged)
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

    #[test]
    fn shard_targets_partitions_without_overlap_or_loss() {
        let targets: Vec<Ipv4Addr> = (1..=10)
            .map(|octet| Ipv4Addr::new(10, 0, 0, octet))
            .collect();

        for workers in 1..=12 {
            let shards = shard_targets(&targets, workers);
            assert!(shards.len() <= workers.max(1));
            assert_eq!(shards.iter().map(Vec::len).sum::<usize>(), targets.len());
            let mut seen: Vec<(usize, Ipv4Addr)> = Vec::new();
            for (index, shard) in shards.iter().enumerate() {
                for &target in shard {
                    seen.push((index, target));
                }
            }
            let mut unique: Vec<(usize, Ipv4Addr)> = seen.clone();
            unique.dedup();
            assert_eq!(unique.len(), seen.len(), "duplicate target across shards");

            // Contiguous chunks preserve original order.
            let mut flattened: Vec<Ipv4Addr> = Vec::new();
            for shard in &shards {
                flattened.extend_from_slice(shard);
            }
            assert_eq!(flattened, targets);
        }
    }

    #[test]
    fn single_target_is_never_sharded() {
        let targets = vec![Ipv4Addr::new(10, 0, 0, 1)];
        let shards = shard_targets(&targets, 8);
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0], targets);
    }

    #[test]
    fn owner_lookup_routes_every_target_to_its_shard() {
        let targets: Vec<Ipv4Addr> = (1..=6)
            .map(|octet| Ipv4Addr::new(192, 168, 100, octet))
            .collect();
        let shards = shard_targets(&targets, 3);
        let owners = shard_owners(&shards);
        assert_eq!(owners.len(), targets.len());
        for (index, shard) in shards.iter().enumerate() {
            for &target in shard {
                assert_eq!(owners.get(&target), Some(&index));
            }
        }
    }
}
