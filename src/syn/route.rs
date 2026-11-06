use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::AppError;

/// Routing and resolution errors for raw packet scanning.
#[derive(Debug)]
pub enum SynError {
    PermissionDenied(String),
    InterfaceNotFound(String),
    RouteNotFound(String),
    ArpFailed(String),
    Socket(String),
    Bpf(String),
    Io(io::Error),
}

impl fmt::Display for SynError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::InterfaceNotFound(msg) => write!(f, "interface not found: {msg}"),
            Self::RouteNotFound(msg) => write!(f, "route not found: {msg}"),
            Self::ArpFailed(msg) => write!(f, "ARP resolution failed: {msg}"),
            Self::Socket(msg) => write!(f, "raw socket error: {msg}"),
            Self::Bpf(msg) => write!(f, "BPF filter error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for SynError {}

impl From<io::Error> for SynError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<SynError> for AppError {
    fn from(err: SynError) -> Self {
        match err {
            SynError::PermissionDenied(msg) => AppError::runtime(msg),
            other => AppError::runtime(other.to_string()),
        }
    }
}

/// Outgoing route information containing interface name, local source IP, and default gateway IP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    /// Outgoing network interface name (e.g. "eth0").
    pub iface: String,
    /// Local IPv4 address assigned to the interface.
    pub src_ip: Ipv4Addr,
    /// Next-hop gateway IPv4 address.
    pub gateway_ip: Ipv4Addr,
}

/// Read `/proc/net/route` to find the default gateway and outgoing interface.
pub fn default_route() -> Result<RouteInfo, SynError> {
    let content = fs::read_to_string("/proc/net/route")
        .map_err(|e| SynError::RouteNotFound(format!("cannot read /proc/net/route: {e}")))?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0];
        let dest = fields[1];
        let gateway = fields[2];
        let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);

        // Default route has destination 0.0.0.0 (00000000) and RTF_GATEWAY (0x0002) set
        if dest == "00000000" && (flags & 0x0002) != 0 {
            let gateway_ip = parse_proc_ipv4(gateway)?;
            let src_ip = iface_ip(iface)?;
            return Ok(RouteInfo {
                iface: iface.to_string(),
                src_ip,
                gateway_ip,
            });
        }
    }

    Err(SynError::RouteNotFound(
        "no default IPv4 gateway found in /proc/net/route".to_string(),
    ))
}

/// Look up the best route for a specific target IP using longest-prefix-match against
/// `/proc/net/route`. Handles both gateway routes (RTF_GATEWAY) and directly connected
/// routes (scope link, no gateway). Falls back to `default_route()` if no specific
/// match is found.
pub fn route_for(target: Ipv4Addr) -> Result<RouteInfo, SynError> {
    let content = fs::read_to_string("/proc/net/route")
        .map_err(|e| SynError::RouteNotFound(format!("cannot read /proc/net/route: {e}")))?;

    let target_u32 = u32::from(target);
    let mut best: Option<(u32, RouteInfo)> = None; // (prefix_len, info)

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0];
        let dest_hex = fields[1];
        let gateway_hex = fields[2];
        let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
        let mask_hex = fields[7];

        // RTF_UP (0x0001) must be set
        if (flags & 0x0001) == 0 {
            continue;
        }

        let dest = match parse_proc_ipv4(dest_hex) {
            Ok(ip) => u32::from(ip),
            Err(_) => continue,
        };
        let mask = match parse_proc_ipv4(mask_hex) {
            Ok(ip) => u32::from(ip),
            Err(_) => continue,
        };

        if (target_u32 & mask) == (dest & mask) {
            let prefix_len = mask.count_ones();
            let is_better = best
                .as_ref()
                .is_none_or(|(best_len, _)| prefix_len > *best_len);
            if is_better {
                // For directly connected routes (no RTF_GATEWAY), next-hop is the target itself
                let gateway_ip = if (flags & 0x0002) != 0 {
                    parse_proc_ipv4(gateway_hex).unwrap_or(target)
                } else {
                    target
                };
                let src_ip = match iface_ip(iface) {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                best = Some((
                    prefix_len,
                    RouteInfo {
                        iface: iface.to_string(),
                        src_ip,
                        gateway_ip,
                    },
                ));
            }
        }
    }

    if let Some((_, info)) = best {
        return Ok(info);
    }

    // Fallback to the default gateway route
    default_route()
}

/// Query the IPv4 address assigned to a specific network interface.
pub fn iface_ip(iface: &str) -> Result<Ipv4Addr, SynError> {
    if iface == "lo" {
        return Ok(Ipv4Addr::new(127, 0, 0, 1));
    }

    // SAFETY: Creating a standard UDP socket to issue SIOCGIFADDR ioctl.
    let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket_fd < 0 {
        return Err(SynError::Socket(format!(
            "failed to create socket: {}",
            io::Error::last_os_error()
        )));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let iface_bytes = iface.as_bytes();
    if iface_bytes.len() >= ifr.ifr_name.len() {
        // SAFETY: socket_fd is valid and open.
        unsafe { libc::close(socket_fd) };
        return Err(SynError::InterfaceNotFound(format!(
            "interface name '{iface}' too long"
        )));
    }

    for (i, &b) in iface_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    // SAFETY: ioctl SIOCGIFADDR is called with a valid socket and properly initialized ifreq.
    // musl defines SIOCGIFADDR as u64; glibc defines it as c_ulong. Use `as _` to let
    // the compiler infer the correct target type for the platform.
    #[allow(clippy::useless_conversion)]
    let ret = unsafe { libc::ioctl(socket_fd, libc::SIOCGIFADDR as _, &mut ifr) };
    // SAFETY: socket_fd is valid and must be closed after ioctl.
    unsafe { libc::close(socket_fd) };

    if ret < 0 {
        return Err(SynError::RouteNotFound(format!(
            "SIOCGIFADDR failed for interface '{iface}': {}",
            io::Error::last_os_error()
        )));
    }

    // SAFETY: ifr.ifr_ifru.ifru_addr holds sockaddr_in on successful SIOCGIFADDR.
    let sockaddr_in =
        unsafe { &*(&ifr.ifr_ifru.ifru_addr as *const _ as *const libc::sockaddr_in) };
    let ip_u32 = u32::from_be(sockaddr_in.sin_addr.s_addr);
    Ok(Ipv4Addr::from(ip_u32))
}

/// Look up the hardware MAC address of a network interface from sysfs or ioctl.
pub fn iface_mac(iface: &str) -> Result<[u8; 6], SynError> {
    if iface == "lo" {
        return Ok([0u8; 6]);
    }

    let path = format!("/sys/class/net/{iface}/address");
    if let Ok(content) = fs::read_to_string(&path) {
        let trimmed = content.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            let mut ok = true;
            for (i, part) in parts.iter().enumerate() {
                if let Ok(byte) = u8::from_str_radix(part, 16) {
                    mac[i] = byte;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Ok(mac);
            }
        }
    }

    // Fallback: ioctl SIOCGIFHWADDR
    // SAFETY: Creating standard UDP socket to query hardware address via ioctl.
    let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket_fd >= 0 {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let iface_bytes = iface.as_bytes();
        if iface_bytes.len() < ifr.ifr_name.len() {
            for (i, &b) in iface_bytes.iter().enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
            // SAFETY: socket_fd is valid and ifr has valid interface name.
            // musl and glibc differ in SIOCGIFHWADDR type; use `as _` to infer the correct type.
            #[allow(clippy::useless_conversion)]
            let ret = unsafe { libc::ioctl(socket_fd, libc::SIOCGIFHWADDR as _, &mut ifr) };
            // SAFETY: Closing open socket.
            unsafe { libc::close(socket_fd) };
            if ret == 0 {
                let mut mac = [0u8; 6];
                for (i, slot) in mac.iter_mut().enumerate() {
                    // SAFETY: sa_data contains MAC bytes on SIOCGIFHWADDR success.
                    *slot = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data[i] } as u8;
                }
                return Ok(mac);
            }
        } else {
            // SAFETY: Closing open socket.
            unsafe { libc::close(socket_fd) };
        }
    }

    Err(SynError::InterfaceNotFound(format!(
        "failed to determine MAC address for interface '{iface}'"
    )))
}

/// Retrieve the kernel interface index for a given interface name.
pub fn iface_index(iface: &str) -> Result<i32, SynError> {
    let c_iface = CString::new(iface)
        .map_err(|_| SynError::InterfaceNotFound(format!("invalid interface name: '{iface}'")))?;

    // SAFETY: if_nametoindex is POSIX standard, passed a valid null-terminated string.
    let index = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if index == 0 {
        return Err(SynError::InterfaceNotFound(format!(
            "interface '{iface}' not found: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(index as i32)
}

/// Resolve the MAC address of `target_ip` via ARP on interface `iface`.
///
/// First checks `/proc/net/arp` for an existing cache entry. If not found,
/// sends an Ethernet broadcast ARP request and waits for a reply.
pub fn arp_resolve(
    iface: &str,
    src_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<[u8; 6], SynError> {
    if iface == "lo" || target_ip.is_loopback() {
        return Ok([0u8; 6]);
    }

    // 1. Check existing kernel ARP cache in /proc/net/arp
    if let Ok(cached) = lookup_arp_cache(iface, target_ip) {
        return Ok(cached);
    }

    // 2. Transmit ARP request via AF_PACKET
    let if_idx = iface_index(iface)?;

    // SAFETY: Creating raw AF_PACKET socket to send ARP request. Requires CAP_NET_RAW.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(SynError::Socket(format!(
            "cannot create ARP socket: {}",
            io::Error::last_os_error()
        )));
    }

    // Set receive timeout of 300ms
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 300_000,
    };
    // SAFETY: Setting SO_RCVTIMEO on valid open socket fd.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Build 42-byte Ethernet + ARP frame
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]); // Destination broadcast MAC
    frame[6..12].copy_from_slice(src_mac); // Source MAC
    frame[12..14].copy_from_slice(&[0x08, 0x06]); // ETH_P_ARP

    // ARP Payload
    frame[14..16].copy_from_slice(&1u16.to_be_bytes()); // Hardware type: Ethernet (1)
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // Protocol type: IPv4 (0x0800)
    frame[18] = 6; // Hardware address length
    frame[19] = 4; // Protocol address length
    frame[20..22].copy_from_slice(&1u16.to_be_bytes()); // Operation: ARP Request (1)
    frame[22..28].copy_from_slice(src_mac); // Sender hardware address
    frame[28..32].copy_from_slice(&src_ip.octets()); // Sender protocol address
    frame[32..38].copy_from_slice(&[0u8; 6]); // Target hardware address (zeroed)
    frame[38..42].copy_from_slice(&target_ip.octets()); // Target protocol address

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    sll.sll_ifindex = if_idx;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    let deadline = Instant::now() + Duration::from_millis(1500);

    for _ in 0..3 {
        // Send request
        // SAFETY: fd is valid, frame is 42 bytes, sll is valid sockaddr_ll.
        let send_ret = unsafe {
            libc::sendto(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if send_ret < 0 {
            // SAFETY: Closing open socket before returning error.
            unsafe { libc::close(fd) };
            return Err(SynError::ArpFailed(format!(
                "failed to send ARP request: {}",
                io::Error::last_os_error()
            )));
        }

        // Wait for reply
        while Instant::now() < deadline {
            let mut buf = [0u8; 256];
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            // SAFETY: fd is valid, buf is 256 bytes, from is valid sockaddr_ll pointer.
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut from as *mut _ as *mut libc::sockaddr,
                    &mut from_len,
                )
            };

            if n >= 42 {
                // Verify ARP reply
                let oper = u16::from_be_bytes([buf[20], buf[21]]);
                let spa = &buf[28..32];
                if oper == 2 && spa == target_ip.octets() {
                    let mut resolved_mac = [0u8; 6];
                    resolved_mac.copy_from_slice(&buf[22..28]);
                    // SAFETY: Closing open socket.
                    unsafe { libc::close(fd) };
                    return Ok(resolved_mac);
                }
            } else if n < 0 {
                break; // Timeout, retry send
            }
        }
    }

    // SAFETY: Closing open socket.
    unsafe { libc::close(fd) };

    // Final attempt: check if kernel ARP cache got updated
    if let Ok(cached) = lookup_arp_cache(iface, target_ip) {
        return Ok(cached);
    }

    Err(SynError::ArpFailed(format!(
        "no ARP response received for target {target_ip} on {iface}"
    )))
}

/// Parse IPv4 address encoded in 8 hex digits from `/proc/net/route`.
fn parse_proc_ipv4(hex_str: &str) -> Result<Ipv4Addr, SynError> {
    if hex_str.len() != 8 {
        return Err(SynError::RouteNotFound(format!(
            "invalid route IP hex length: '{hex_str}'"
        )));
    }
    let b0 = u8::from_str_radix(&hex_str[6..8], 16)
        .map_err(|e| SynError::RouteNotFound(e.to_string()))?;
    let b1 = u8::from_str_radix(&hex_str[4..6], 16)
        .map_err(|e| SynError::RouteNotFound(e.to_string()))?;
    let b2 = u8::from_str_radix(&hex_str[2..4], 16)
        .map_err(|e| SynError::RouteNotFound(e.to_string()))?;
    let b3 = u8::from_str_radix(&hex_str[0..2], 16)
        .map_err(|e| SynError::RouteNotFound(e.to_string()))?;
    Ok(Ipv4Addr::new(b0, b1, b2, b3))
}

/// Look up `/proc/net/arp` for an existing completed ARP cache entry.
fn lookup_arp_cache(iface: &str, target_ip: Ipv4Addr) -> Result<[u8; 6], SynError> {
    let content = fs::read_to_string("/proc/net/arp")
        .map_err(|e| SynError::RouteNotFound(format!("cannot read /proc/net/arp: {e}")))?;

    let target_str = target_ip.to_string();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[0] == target_str && fields[5] == iface {
            let flags = u32::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap_or(0);
            // 0x02 indicates completed ARP entry (ATF_COM)
            if (flags & 0x02) != 0 {
                let parts: Vec<&str> = fields[3].split(':').collect();
                if parts.len() == 6 {
                    let mut mac = [0u8; 6];
                    let mut ok = true;
                    for (i, p) in parts.iter().enumerate() {
                        if let Ok(b) = u8::from_str_radix(p, 16) {
                            mac[i] = b;
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if ok && mac != [0u8; 6] {
                        return Ok(mac);
                    }
                }
            }
        }
    }

    Err(SynError::ArpFailed(format!(
        "target {target_ip} not present in /proc/net/arp"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_ipv4_matches_endianness() {
        let ip = parse_proc_ipv4("014016AC").unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 22, 64, 1));

        let loopback = parse_proc_ipv4("0100007F").unwrap();
        assert_eq!(loopback, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn loopback_route_and_mac_are_predictable() {
        let mac = iface_mac("lo").unwrap();
        assert_eq!(mac, [0u8; 6]);

        let ip = iface_ip("lo").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));

        let idx = iface_index("lo").unwrap();
        assert!(idx > 0);
    }
}
