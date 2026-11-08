//! Host discovery (ping sweep) used before port scanning.
//!
//! On Linux, ICMP echo probes are attempted when the process has
//! `CAP_NET_RAW`.  If raw ICMP is unavailable or the host does not answer,
//! a TCP connect probe against a small set of common ports is used.  A
//! connection refusal still proves the host is alive, so firewalled hosts
//! with reachable closed ports are discovered without raw privileges.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;

pub const TCP_PING_PORTS: [u16; 7] = [80, 443, 22, 445, 3389, 8080, 53];

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

    #[cfg(target_os = "linux")]
    let raw_icmp = raw_icmp_available();
    #[cfg(not(target_os = "linux"))]
    let raw_icmp = false;

    let ports = ports.to_vec();
    let mut alive = HashSet::new();
    for chunk in targets.chunks(64) {
        let mut tasks = JoinSet::new();
        for &host in chunk {
            let ports = ports.clone();
            tasks.spawn(async move {
                let discovered = if raw_icmp && host.is_ipv4() {
                    let raw = tokio::task::spawn_blocking(move || {
                        host_responds_to_icmp(host, options.count, options.timeout)
                    })
                    .await
                    .unwrap_or(false);
                    raw || tcp_ping(host, options.count, options.timeout, &ports).await
                } else {
                    tcp_ping(host, options.count, options.timeout, &ports).await
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

async fn tcp_ping(host: IpAddr, count: u8, timeout: Duration, ports: &[u16]) -> bool {
    for _ in 0..count.max(1) {
        for &port in ports {
            let address = SocketAddr::new(host, port);
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

        let id = std::process::id() as u16;
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

#[cfg(not(target_os = "linux"))]
fn host_responds_to_icmp(_host: IpAddr, _count: u8, _timeout: Duration) -> bool {
    false
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
}
