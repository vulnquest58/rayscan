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
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts};
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

struct BatchV6 {
    packets: Vec<(Vec<u8>, libc::sockaddr_in6, (Ipv6Addr, u16))>,
    len: usize,
}

impl BatchV6 {
    fn new(batch_size: usize) -> Self {
        let packets = (0..batch_size.max(1))
            .map(|_| {
                (
                    Vec::with_capacity(60),
                    sockaddr_v6_raw(Ipv6Addr::UNSPECIFIED),
                    (Ipv6Addr::UNSPECIFIED, 0),
                )
            })
            .collect();
        Self { packets, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append an IPv6 SYN probe; the packet buffer is reused across probes.
    fn push(&mut self, target: Ipv6Addr, source: Ipv6Addr, src_port: u16, dst_port: u16, seq: u32) {
        if self.len >= self.packets.len() {
            self.packets.push((
                Vec::with_capacity(60),
                sockaddr_v6_raw(target),
                (target, dst_port),
            ));
        }
        let (buffer, dest, key) = &mut self.packets[self.len];
        buffer.clear();
        let mut packet_buf = [0u8; 60];
        packet::write_ipv6_syn_packet_into(
            &mut packet_buf,
            &source,
            &target,
            src_port,
            dst_port,
            seq,
        );
        buffer.extend_from_slice(&packet_buf);
        *dest = sockaddr_v6_raw(target);
        *key = (target, dst_port);
        self.len += 1;
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// Sends a batch of raw IPv6 packets using `sendmmsg(2)`.
fn send_v6_frames_batch(fd: i32, batch: &BatchV6) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len);
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len);

    for (frame, dest, _) in batch.packets[..batch.len].iter() {
        let iov = libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        iovs.push(iov);
        let last_iov_idx = iovs.len() - 1;

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = dest as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        msg.msg_iov = &mut iovs[last_iov_idx];
        msg.msg_iovlen = 1;

        msgs.push(libc::mmsghdr {
            msg_hdr: msg,
            msg_len: 0,
        });
    }

    let mut sent = 0;
    while sent < msgs.len() {
        // SAFETY: `fd` is a valid open socket descriptor. `msgs` points to an array of valid
        // `libc::mmsghdr` structs with corresponding valid iovecs and sockaddr_in6 addresses.
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

fn flush_v6_batch(
    fd: i32,
    pacer: &mut Pacer,
    batch: &mut BatchV6,
    tx_times: &mut HashMap<(Ipv6Addr, u16), Instant>,
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    pacer.wait_for_batch(batch.len);
    let now = Instant::now();
    for &(_, _, key) in batch.packets[..batch.len].iter() {
        tx_times.insert(key, now);
    }
    send_v6_frames_batch(fd, batch)?;
    batch.clear();
    Ok(())
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

/// Number of frames drained from the RX socket per `recvmmsg(2)` syscall.
const RX_BATCH: usize = 64;
/// Per-datagram receive buffer size.
const RX_SLOT_SIZE: usize = 2048;

struct RxBatch {
    data: Vec<[u8; RX_SLOT_SIZE]>,
    addrs: Vec<libc::sockaddr_in6>,
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
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as u32;
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

fn rx_loop(
    rx_fd: i32,
    running: Arc<AtomicBool>,
    cookie_key: super::cookie::CookieKey,
    sender: crossbeam_channel::Sender<RxResponse>,
) {
    let mut batch = RxBatch::new(RX_BATCH);
    while running.load(Ordering::Acquire) {
        let count = match receive_batch(rx_fd, &mut batch) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
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
            if len == 0 {
                continue;
            }
            let peer = Ipv6Addr::from(batch.addrs[index].sin6_addr.s6_addr);
            let now = Instant::now();
            match packet::parse_ipv6_tcp(&batch.data[index][..len], Some(peer)) {
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

    let batch_size = opts.batch_size.max(1);
    let mut v6_batch = BatchV6::new(batch_size);

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

            v6_batch.push(target, source, source_port, port, sequence);
            sent_any = true;

            if v6_batch.len() >= batch_size {
                flush_v6_batch(tx_fd, &mut pacer, &mut v6_batch, &mut tx_times)
                    .map_err(|error| AppError::runtime(format!("IPv6 TX send failed: {error}")))?;
                drain_responses(&result_rx, &tx_times, &mut responses, start_time);
                if attempt == 0
                    && let Some(callback) = progress
                {
                    callback(ProgressEvent::default());
                }
            }
        }

        flush_v6_batch(tx_fd, &mut pacer, &mut v6_batch, &mut tx_times)
            .map_err(|error| AppError::runtime(format!("IPv6 TX send failed: {error}")))?;

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

        // Skip retransmits on a silent path (see the IPv4 shard worker).
        if attempt == 0 && responses.len() * 100 < total_probes as usize {
            break;
        }
    }

    running.store(false, Ordering::Release);
    let _ = rx_handle.join();
    drain_responses(&result_rx, &tx_times, &mut responses, start_time);

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();
    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = responses
                .get(&(target, port))
                .copied()
                .unwrap_or((PortState::Filtered, timeout_duration));
            counts.add(state);
            let progress = host_progress.entry(IpAddr::V6(target)).or_default();
            progress.ports_scanned.push(port);
            progress.counts.add(state);
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
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}
