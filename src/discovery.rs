//! Host discovery (ping sweep) used before port scanning.
//!
//! On Linux, ICMP echo probes are attempted when the process has
//! `CAP_NET_RAW`.  If raw ICMP is unavailable or the host does not answer,
//! a TCP connect probe against a small set of common ports is used.  A
//! connection refusal still proves the host is alive, so firewalled hosts
//! with reachable closed ports are discovered without raw privileges.
//!
//! IPv4 targets additionally get an ARP probe (who-has) as the first and
//! most definitive liveness check on a LAN segment.  On Linux this uses
//! raw `AF_PACKET` frames for directly connected routes only; on Windows
//! it uses the `SendARP` helper API, which previously left no usable
//! discovery path for hosts that drop ICMP and refuse no TCP ports.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::task::JoinSet;

#[cfg(target_os = "linux")]
use crate::syn::route::{arp_resolve, iface_mac, route_for};

pub const TCP_PING_PORTS: [u16; 7] = [80, 443, 22, 445, 3389, 8080, 53];

static IPV6_SCOPE_IDS: OnceLock<RwLock<HashMap<Ipv6Addr, u32>>> = OnceLock::new();

fn scope_ids() -> &'static RwLock<HashMap<Ipv6Addr, u32>> {
    IPV6_SCOPE_IDS.get_or_init(|| RwLock::new(HashMap::new()))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn register_scope_id(address: Ipv6Addr, index: u32) {
    if index == 0 || !is_link_local(address) {
        return;
    }
    if let Ok(mut scopes) = scope_ids().write() {
        scopes.insert(address, index);
    }
}

/// Build a socket address, attaching an interface scope for link-local IPv6
/// targets discovered through NDP.
pub fn socket_addr(host: IpAddr, port: u16) -> SocketAddr {
    if let IpAddr::V6(address) = host
        && is_link_local(address)
        && let Ok(scopes) = scope_ids().read()
        && let Some(index) = scopes.get(&address)
    {
        return SocketAddr::V6(SocketAddrV6::new(address, port, 0, *index));
    }
    SocketAddr::new(host, port)
}

fn is_link_local(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

#[derive(Clone, Copy, Debug)]
pub struct DiscoveryOptions {
    pub count: u8,
    pub timeout: Duration,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            count: 2,
            timeout: Duration::from_millis(500),
        }
    }
}

/// Return the subset of targets that responded to an ICMP echo or TCP probe.
///
/// The original target order is preserved.
pub async fn sweep(targets: &[IpAddr], options: DiscoveryOptions) -> Vec<IpAddr> {
    sweep_ports(targets, options, &TCP_PING_PORTS).await
}

async fn sweep_ports(targets: &[IpAddr], options: DiscoveryOptions, ports: &[u16]) -> Vec<IpAddr> {
    if targets.is_empty() {
        return Vec::new();
    }

    let ports = ports.to_vec();
    let mut alive = HashSet::new();
    for chunk in targets.chunks(64) {
        let mut tasks = JoinSet::new();
        for &host in chunk {
            let ports = ports.clone();
            tasks.spawn(async move {
                let discovered = if host.is_ipv4() && arp_ping_available() {
                    arp_ping(host).await || icmp_or_tcp_discovery(host, options, &ports).await
                } else {
                    icmp_or_tcp_discovery(host, options, &ports).await
                };
                (host, discovered)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Ok((host, true)) = joined {
                alive.insert(host);
            }
        }
    }

    targets
        .iter()
        .copied()
        .filter(|target| alive.contains(target))
        .collect()
}

/// ICMP/TCP discovery fallback shared by all platforms.
async fn icmp_or_tcp_discovery(host: IpAddr, options: DiscoveryOptions, ports: &[u16]) -> bool {
    #[cfg(target_os = "linux")]
    let raw_icmp = raw_icmp_available();
    #[cfg(target_os = "linux")]
    let raw_icmp_v6 = raw_icmpv6_available();
    #[cfg(not(target_os = "linux"))]
    let raw_icmp = false;
    #[cfg(not(target_os = "linux"))]
    let raw_icmp_v6 = false;

    if raw_icmp && host.is_ipv4() {
        let raw = tokio::task::spawn_blocking(move || {
            host_responds_to_icmp(host, options.count, options.timeout)
        })
        .await
        .unwrap_or(false);
        raw || tcp_ping(host, options.count, options.timeout, ports).await
    } else if raw_icmp_v6 && host.is_ipv6() {
        let raw = tokio::task::spawn_blocking(move || {
            host_responds_to_icmpv6(host, options.count, options.timeout)
        })
        .await
        .unwrap_or(false);
        raw || tcp_ping(host, options.count, options.timeout, ports).await
    } else {
        tcp_ping(host, options.count, options.timeout, ports).await
    }
}

/// Whether an ARP liveness probe is possible on this platform.
///
/// Linux needs `CAP_NET_RAW` for an `AF_PACKET` socket; Windows always
/// exposes `SendARP` from iphlpapi.  Other platforms have no implementation.
pub fn arp_ping_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: creating and immediately closing a socket is sound.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ARP as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return false;
        }
        // SAFETY: fd is a valid owned socket.
        unsafe {
            libc::close(fd);
        }
        true
    }
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// ARP who-has liveness probe for an IPv4 target.
///
/// Linux: only directly connected routes are probed — the gateway is never
/// asked for, so an ARP reply can only come from the target itself.  Windows:
/// `SendARP` performs the same constrained lookup internally and fails for
/// off-link destinations without ARPing the gateway.
async fn arp_ping(host: IpAddr) -> bool {
    let address = match host {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => return false,
    };
    if address.is_loopback() {
        return false;
    }
    tokio::task::spawn_blocking(move || blocking_arp_ping(address))
        .await
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn blocking_arp_ping(address: Ipv4Addr) -> bool {
    // Directly connected targets only: the route's next hop must be the
    // target itself so a gateway's reply can never count as liveness.
    let Ok(route) = route_for(address) else {
        return false;
    };
    if route.gateway_ip != address {
        return false;
    }
    let Ok(src_mac) = iface_mac(&route.iface) else {
        return false;
    };
    arp_resolve(&route.iface, &src_mac, route.src_ip, address).is_ok()
}

#[cfg(target_os = "windows")]
fn blocking_arp_ping(address: Ipv4Addr) -> bool {
    const NO_ERROR: u32 = 0;
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn SendARP(dest_ip: u32, src_ip: u32, mac_addr: *mut u8, phy_addr_len: *mut u32) -> u32;
    }

    let mut mac = [0u8; 6];
    let mut mac_len = mac.len() as u32;
    // SAFETY: buffers are correctly sized; SendARP only writes mac_len bytes.
    let status = unsafe {
        SendARP(
            u32::from_ne_bytes(address.octets()),
            0,
            mac.as_mut_ptr(),
            &mut mac_len,
        )
    };
    status == NO_ERROR && mac_len == 6
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn blocking_arp_ping(_address: Ipv4Addr) -> bool {
    false
}

/// Distinct ICMP echo identifier per probe socket so concurrent probes never
/// collide on (id, sequence) even if the kernel multiplexes replies across
/// raw sockets bound for other targets.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn icmp_id_for(host: IpAddr) -> u16 {
    let pid = std::process::id();
    let folded: u32 = match host {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_ne_bytes([o[0] ^ o[8], o[1] ^ o[9], o[2] ^ o[10], o[3] ^ o[11]])
        }
    };
    (pid ^ folded) as u16
}

async fn tcp_ping(host: IpAddr, count: u8, timeout: Duration, ports: &[u16]) -> bool {
    for _ in 0..count.max(1) {
        for &port in ports {
            let address = socket_addr(host, port);
            match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    drop(stream);
                    return true;
                }
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn raw_icmp_available() -> bool {
    // SAFETY: creating and immediately closing a socket is sound.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return false;
    }
    // SAFETY: fd is a valid owned socket.
    unsafe {
        libc::close(fd);
    }
    true
}

#[cfg(target_os = "linux")]
fn raw_icmpv6_available() -> bool {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
    if fd < 0 {
        return false;
    }
    unsafe {
        libc::close(fd);
    }
    true
}

#[cfg(target_os = "linux")]
fn host_responds_to_icmp(host: IpAddr, count: u8, timeout: Duration) -> bool {
    let IpAddr::V4(address) = host else {
        return false;
    };

    // SAFETY: raw socket creation and the following syscalls operate on the
    // owned descriptor and initialized buffers.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd < 0 {
            return false;
        }

        let timeval = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut destination: libc::sockaddr_in = std::mem::zeroed();
        destination.sin_family = libc::AF_INET as libc::sa_family_t;
        destination.sin_port = 0;
        destination.sin_addr.s_addr = u32::from_ne_bytes(address.octets());

        let id = icmp_id_for(host);
        let mut answered = false;

        'probe: for sequence in 0..u32::from(count.max(1)) {
            let mut packet = [0_u8; 8];
            packet[0] = 8; // ICMP echo request
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            packet[6..8].copy_from_slice(&(sequence as u16).to_be_bytes());
            let checksum = checksum(&packet);
            packet[2..4].copy_from_slice(&checksum.to_be_bytes());

            let sent = libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &destination as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if sent < 0 {
                break;
            }

            let mut buffer = [0_u8; 1500];
            loop {
                let mut source: libc::sockaddr_in = std::mem::zeroed();
                let mut source_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                let read = libc::recvfrom(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut source as *mut libc::sockaddr_in as *mut libc::sockaddr,
                    &mut source_len,
                );
                if read <= 0 {
                    break;
                }
                if source.sin_addr.s_addr != destination.sin_addr.s_addr {
                    continue;
                }
                let read = read as usize;
                let header = usize::from(buffer[0] & 0x0f) * 4;
                if read < header + 8 || buffer[header] != 0 {
                    continue;
                }
                let reply_id = u16::from_be_bytes([buffer[header + 4], buffer[header + 5]]);
                let reply_seq = u16::from_be_bytes([buffer[header + 6], buffer[header + 7]]);
                if reply_id == id && reply_seq == sequence as u16 {
                    answered = true;
                    break 'probe;
                }
            }
        }

        libc::close(fd);
        answered
    }
}

#[cfg(target_os = "linux")]
fn host_responds_to_icmpv6(host: IpAddr, count: u8, timeout: Duration) -> bool {
    let IpAddr::V6(address) = host else {
        return false;
    };

    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6);
        if fd < 0 {
            return false;
        }

        let timeval = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut destination: libc::sockaddr_in6 = std::mem::zeroed();
        destination.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        destination.sin6_port = 0;
        destination.sin6_addr.s6_addr = address.octets();

        let id = icmp_id_for(host);
        let mut answered = false;

        'probe: for sequence in 0..u32::from(count.max(1)) {
            let mut packet = [0_u8; 8];
            packet[0] = 128; // ICMPv6 echo request
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            packet[6..8].copy_from_slice(&(sequence as u16).to_be_bytes());

            let sent = libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &destination as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            if sent < 0 {
                break;
            }

            let mut buffer = [0_u8; 1500];
            loop {
                let mut source: libc::sockaddr_in6 = std::mem::zeroed();
                let mut source_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                let read = libc::recvfrom(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut source as *mut libc::sockaddr_in6 as *mut libc::sockaddr,
                    &mut source_len,
                );
                if read <= 0 {
                    break;
                }
                if read < 8 || buffer[0] != 129 {
                    continue;
                }
                let reply_id = u16::from_be_bytes([buffer[4], buffer[5]]);
                let reply_seq = u16::from_be_bytes([buffer[6], buffer[7]]);
                if reply_id == id && reply_seq == sequence as u16 {
                    answered = true;
                    break 'probe;
                }
            }
        }

        libc::close(fd);
        answered
    }
}

#[cfg(not(target_os = "linux"))]
fn host_responds_to_icmp(_host: IpAddr, _count: u8, _timeout: Duration) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn host_responds_to_icmpv6(_host: IpAddr, _count: u8, _timeout: Duration) -> bool {
    false
}

/// Parse Linux `/proc/net/ipv6_route` content to extract verified 128-bit IPv6 host routes.
pub fn parse_ipv6_route_content(content: &str) -> Vec<Ipv6Addr> {
    let mut addrs = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(dst_hex) = parts.next() else {
            continue;
        };
        let Some(prefix_hex) = parts.next() else {
            continue;
        };
        if prefix_hex != "80" || dst_hex.len() != 32 {
            continue;
        }
        let mut bytes = [0u8; 16];
        let mut valid = true;
        for i in 0..16 {
            if let Ok(byte) = u8::from_str_radix(&dst_hex[i * 2..i * 2 + 2], 16) {
                bytes[i] = byte;
            } else {
                valid = false;
                break;
            }
        }
        if !valid {
            continue;
        }
        let addr = Ipv6Addr::from(bytes);
        if !addr.is_loopback() && !addr.is_unspecified() && !addr.is_multicast() {
            addrs.push(addr);
        }
    }
    addrs
}

/// One IPv6 address configured on a local interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Interface {
    pub name: String,
    pub index: u32,
    pub address: Ipv6Addr,
    pub scope: u8,
}

/// Parse Linux `/proc/net/if_inet6` into usable local IPv6 interfaces.
///
/// Each line contains the address, interface index, prefix length, scope,
/// flags, and interface name. Loopback and host-local entries are skipped.
pub fn parse_proc_ipv6_interfaces(content: &str) -> Vec<Ipv6Interface> {
    let mut interfaces = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let Some(address) = parse_ipv6_hex(fields[0]) else {
            continue;
        };
        let Ok(index) = u32::from_str_radix(fields[1], 16) else {
            continue;
        };
        let Ok(scope) = u8::from_str_radix(fields[3], 16) else {
            continue;
        };
        let name = fields[5].to_string();
        if name == "lo"
            || scope == 0x10
            || address.is_multicast()
            || address.is_unspecified()
            || address.is_loopback()
        {
            continue;
        }
        interfaces.push(Ipv6Interface {
            name,
            index,
            address,
            scope,
        });
    }
    interfaces
}

/// Parse `ip -6 neigh show` (or `/proc/net/ndisc_cache`) output.
pub fn parse_ipv6_neighbors(content: &str) -> Vec<Ipv6Addr> {
    let mut neighbors = HashSet::new();
    for (address, _) in parse_ipv6_neighbor_entries(content) {
        neighbors.insert(address);
    }
    neighbors.into_iter().collect()
}

fn parse_ipv6_neighbor_entries(content: &str) -> Vec<(Ipv6Addr, Option<String>)> {
    let mut neighbors = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        if upper.contains("FAILED") || upper.contains("INCOMPLETE") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let first = first.trim_end_matches(',');
        let Ok(address) = first.parse::<Ipv6Addr>() else {
            continue;
        };
        if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
            continue;
        }
        let interface = fields
            .clone()
            .position(|field| field == "dev")
            .and_then(|index| fields.nth(index + 1))
            .map(str::to_string);
        neighbors.push((address, interface));
    }
    neighbors
}

/// Whether NDP discovery is available on this platform.
pub const fn ndp_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Discover active local IPv6 neighbors via an ICMPv6 all-nodes multicast
/// probe (`ff02::1`) plus the kernel neighbor and host-route tables.
#[cfg(target_os = "linux")]
pub fn discover_ipv6_multicast(timeout: Duration) -> Vec<IpAddr> {
    let mut discovered = HashSet::new();
    let mut local = HashSet::new();

    let interfaces = std::fs::read_to_string("/proc/net/if_inet6")
        .map(|content| parse_proc_ipv6_interfaces(&content))
        .unwrap_or_default();
    for interface in &interfaces {
        local.insert(interface.address);
    }
    for address in probe_ipv6_all_nodes(&interfaces, timeout) {
        discovered.insert(address);
    }

    for address in read_ipv6_neighbor_table(&interfaces) {
        discovered.insert(address);
    }

    let mut addresses: Vec<IpAddr> = discovered
        .into_iter()
        .map(IpAddr::V6)
        .filter(|address| match address {
            IpAddr::V6(address) => {
                !local.contains(address)
                    && !address.is_loopback()
                    && !address.is_unspecified()
                    && !address.is_multicast()
            }
            IpAddr::V4(_) => false,
        })
        .collect();
    addresses.sort();
    addresses
}

#[cfg(target_os = "linux")]
fn probe_ipv6_all_nodes(interfaces: &[Ipv6Interface], timeout: Duration) -> Vec<Ipv6Addr> {
    let mut answered = HashSet::new();
    if interfaces.is_empty() || timeout.is_zero() {
        return Vec::new();
    }

    // SAFETY: creation and all following operations use an owned descriptor
    // and fully initialized buffers.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6);
        if fd < 0 {
            return Vec::new();
        }

        // The kernel computes the ICMPv6 checksum at offset 2 of the payload.
        let checksum_offset: libc::c_int = 2;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &checksum_offset as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let timeval = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let hops: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &hops as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let mut destination: libc::sockaddr_in6 = std::mem::zeroed();
        destination.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        destination.sin6_addr.s6_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets();

        let id = std::process::id() as u16;
        let mut sequence = 0u16;
        let mut sent_interfaces = HashSet::new();
        for interface in interfaces {
            if !sent_interfaces.insert(interface.index) {
                continue;
            }
            let index = interface.index as libc::c_int;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                &index as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                continue;
            }
            destination.sin6_scope_id = interface.index;

            sequence = sequence.wrapping_add(1);
            let mut packet = [0_u8; 8];
            packet[0] = 128; // ICMPv6 echo request
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            packet[6..8].copy_from_slice(&sequence.to_be_bytes());
            let _ = libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &destination as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
        }

        let deadline = Instant::now() + timeout;
        let mut buffer = [0_u8; 1500];
        while Instant::now() < deadline {
            let mut source: libc::sockaddr_in6 = std::mem::zeroed();
            let mut source_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let read = libc::recvfrom(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
                &mut source as *mut libc::sockaddr_in6 as *mut libc::sockaddr,
                &mut source_len,
            );
            if read <= 0 {
                break;
            }
            if read >= 8 && buffer[0] == 129 {
                let address = Ipv6Addr::from(source.sin6_addr.s6_addr);
                if !address.is_loopback() && !address.is_unspecified() {
                    if source.sin6_scope_id != 0 {
                        register_scope_id(address, source.sin6_scope_id);
                    }
                    answered.insert(address);
                }
            }
        }

        libc::close(fd);
    }

    answered.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn read_ipv6_neighbor_table(interfaces: &[Ipv6Interface]) -> Vec<Ipv6Addr> {
    let mut neighbors = HashSet::new();
    let indices: HashMap<&str, u32> = interfaces
        .iter()
        .map(|interface| (interface.name.as_str(), interface.index))
        .collect();
    let fallback_index = (interfaces.len() == 1).then_some(interfaces[0].index);

    if let Ok(output) = Command::new("ip").args(["-6", "neigh", "show"]).output()
        && output.status.success()
        && let Ok(content) = String::from_utf8(output.stdout)
    {
        for (address, interface) in parse_ipv6_neighbor_entries(&content) {
            let index = interface
                .as_deref()
                .and_then(|name| indices.get(name).copied())
                .or(fallback_index);
            if let Some(index) = index {
                register_scope_id(address, index);
            }
            neighbors.insert(address);
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/ndisc_cache") {
        for (address, _) in parse_ipv6_neighbor_entries(&content) {
            if let Some(index) = fallback_index {
                register_scope_id(address, index);
            }
            neighbors.insert(address);
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
        neighbors.extend(parse_ipv6_route_content(&content));
    }

    neighbors.into_iter().collect()
}

#[cfg(not(target_os = "linux"))]
pub fn discover_ipv6_multicast(_timeout: Duration) -> Vec<IpAddr> {
    Vec::new()
}

fn parse_ipv6_hex(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_ipv6_interfaces_and_skips_loopback() {
        let sample = "\
            fe8000000000000002155dfffe6fc63d 02 40 20 80     eth0\n\
            20010db8000000000000000000000042 02 40 00 80     eth0\n\
            00000000000000000000000000000001 01 80 10 80       lo\n";
        let interfaces = parse_proc_ipv6_interfaces(sample);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "eth0");
        assert_eq!(interfaces[0].index, 2);
        assert_eq!(
            interfaces[0].address,
            "fe80::215:5dff:fe6f:c63d".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(interfaces[1].scope, 0);
    }

    #[test]
    fn scoped_socket_address_uses_registered_interface() {
        let host: Ipv6Addr = "fe80::abcd".parse().unwrap();
        register_scope_id(host, 42);
        let address = socket_addr(IpAddr::V6(host), 443);
        assert_eq!(address.port(), 443);
        match address {
            SocketAddr::V6(address) => assert_eq!(address.scope_id(), 42),
            SocketAddr::V4(_) => panic!("expected an IPv6 socket address"),
        }
    }

    #[test]
    fn parses_neighbor_table_and_ignores_failed_entries() {
        let sample = "\
            fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE\n\
            fe80::2 dev eth0 lladdr 00:11:22:33:44:66 STALE\n\
            fe80::3 dev eth0 FAILED\n\
            2001:db8::5 dev eth0 lladdr 00:11:22:33:44:77 DELAY\n";
        let mut neighbors = parse_ipv6_neighbors(sample);
        neighbors.sort();
        assert_eq!(neighbors.len(), 3);
        assert_eq!(neighbors[0], "2001:db8::5".parse::<Ipv6Addr>().unwrap());
        assert_eq!(neighbors[1], "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(neighbors[2], "fe80::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn icmp_ids_are_stable_per_host_and_differ_between_hosts() {
        let a: IpAddr = "192.168.1.10".parse().unwrap();
        let a6: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(icmp_id_for(a), icmp_id_for(a));
        assert_eq!(icmp_id_for(a6), icmp_id_for(a6));
        // 255 consecutive LAN addresses should collide at most once with the
        // pid fold (birthday bound), so assert strict separation for a small
        // deterministic sample instead of over the whole range.
        let sample: Vec<IpAddr> = (1..8)
            .map(|i| IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)))
            .collect();
        let mut seen = HashSet::new();
        for host in &sample {
            assert!(seen.insert(icmp_id_for(*host)), "id collision in sample");
        }
    }

    #[test]
    fn arp_ping_skips_loopback_and_ipv6() {
        assert!(!arp_ping_sync(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!arp_ping_sync(IpAddr::V6("::1".parse().unwrap())));
    }

    /// Synchronous wrapper used only by tests.
    fn arp_ping_sync(host: IpAddr) -> bool {
        let address = match host {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => return false,
        };
        if address.is_loopback() {
            return false;
        }
        blocking_arp_ping(address)
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // Header with the checksum field zeroed: 0x0800 + 0x0000 + 0x0001 + 0x0001.
        assert_eq!(
            checksum(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]),
            0xf7fd
        );
        assert_eq!(checksum(&[0x00, 0x00]), 0xffff);
    }

    #[tokio::test]
    async fn tcp_ping_detects_listener_and_refusal() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            tcp_ping(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1,
                Duration::from_millis(500),
                &[port],
            )
            .await
        );

        drop(listener);
        assert!(
            tcp_ping(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1,
                Duration::from_millis(500),
                &[port],
            )
            .await
        );
    }

    #[tokio::test]
    async fn sweep_preserves_order_and_filters_unreachable() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let targets = vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "192.0.2.1".parse().unwrap(),
        ];
        let discovered = sweep_ports(
            &targets,
            DiscoveryOptions {
                count: 1,
                timeout: Duration::from_millis(150),
            },
            &[port],
        )
        .await;
        assert_eq!(discovered, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn parses_ipv6_routes_from_proc_format() {
        let sample = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n\
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n\
fe8000000000000002155dfffe6fcc55 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001 eth0\n\
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001 eth0\n";
        let parsed = parse_ipv6_route_content(sample);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            "fe80::215:5dff:fe6f:cc55".parse::<Ipv6Addr>().unwrap()
        );
    }
}
