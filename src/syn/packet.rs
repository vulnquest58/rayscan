//! Raw Ethernet, IPv4/IPv6, and TCP frame construction and parsing.
//!
//! Provides zero-copy packet generation for TCP SYN probes and safe parsing
//! for incoming SYN-ACK, RST, and ICMP Destination Unreachable frames.

use std::net::Ipv6Addr;

/// Parsed representation of an incoming network frame relevant to SYN scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedFrame {
    /// A TCP SYN-ACK response indicating an open port.
    SynAck {
        /// Source IPv4 address (the target host).
        src_ip: u32,
        /// Source port (the probed port on target).
        src_port: u16,
        /// Destination port (our scanner's source port).
        dst_port: u16,
        /// TCP sequence number from the target.
        seq: u32,
        /// TCP acknowledgment number from the target (must match our cookie + 1).
        ack: u32,
    },
    /// A TCP RST response indicating a closed port.
    Rst {
        /// Source IPv4 address (the target host).
        src_ip: u32,
        /// Source port (the probed port on target).
        src_port: u16,
        /// Destination port (our scanner's source port).
        dst_port: u16,
    },
    /// An ICMP Destination Unreachable packet indicating a filtered or unreachable port.
    IcmpUnreachable {
        /// Destination IPv4 address of the original probed packet.
        dst_ip: u32,
        /// Destination port of the original probed packet.
        dst_port: u16,
    },
    /// Any other frame that is not relevant to the scanner.
    Other,
}

/// Computes the 16-bit one's complement Internet Checksum over a byte slice.
///
/// Follows RFC 1071. If length is odd, the last byte is padded with zero on the right.
#[inline]
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        let word = u16::from_be_bytes(*chunk);
        sum = sum.wrapping_add(word as u32);
    }
    if let Some(&rem) = remainder.first() {
        let word = (rem as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Computes the TCP checksum over IPv4 pseudo-header and TCP segment.
///
/// Follows RFC 793.
#[inline]
pub fn tcp_checksum(src_ip: u32, dst_ip: u32, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // IPv4 pseudo-header:
    // Source IP (4 bytes)
    sum = sum.wrapping_add(src_ip >> 16);
    sum = sum.wrapping_add(src_ip & 0xffff);
    // Destination IP (4 bytes)
    sum = sum.wrapping_add(dst_ip >> 16);
    sum = sum.wrapping_add(dst_ip & 0xffff);
    // Zero + Protocol (6 for TCP)
    sum = sum.wrapping_add(6);
    // TCP Segment Length (2 bytes)
    sum = sum.wrapping_add(tcp_segment.len() as u32);

    let (chunks, remainder) = tcp_segment.as_chunks::<2>();
    for chunk in chunks {
        let word = u16::from_be_bytes(*chunk);
        sum = sum.wrapping_add(word as u32);
    }
    if let Some(&rem) = remainder.first() {
        let word = (rem as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 { 0xffff } else { res }
}

/// Computes the TCP checksum over an IPv6 pseudo-header and TCP segment.
#[inline]
pub fn tcp6_checksum(src_ip: &Ipv6Addr, dst_ip: &Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src_ip.octets().as_chunks::<2>().0 {
        sum = sum.wrapping_add(u16::from_be_bytes(*chunk) as u32);
    }
    for chunk in dst_ip.octets().as_chunks::<2>().0 {
        sum = sum.wrapping_add(u16::from_be_bytes(*chunk) as u32);
    }
    sum = sum.wrapping_add((tcp_segment.len() as u32) >> 16);
    sum = sum.wrapping_add((tcp_segment.len() as u32) & 0xffff);
    sum = sum.wrapping_add(6);

    let (chunks, remainder) = tcp_segment.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.wrapping_add(u16::from_be_bytes(*chunk) as u32);
    }
    if let Some(&rem) = remainder.first() {
        sum = sum.wrapping_add((rem as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 { 0xffff } else { result }
}

/// Builds a raw IPv6 + TCP packet for `IPPROTO_RAW`/`IPV6_HDRINCL` sockets.
///
/// `tcp_options` must be zero or a multiple of four bytes.
pub fn build_ipv6_tcp_packet(
    src_ip: &Ipv6Addr,
    dst_ip: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    tcp_options: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + tcp_options.len();
    let mut packet = vec![0u8; 40 + tcp_len];

    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src_ip.octets());
    packet[24..40].copy_from_slice(&dst_ip.octets());

    let tcp = &mut packet[40..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = (((20 + tcp_options.len()) / 4) as u8) << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
    tcp[20..].copy_from_slice(tcp_options);

    let checksum = tcp6_checksum(src_ip, dst_ip, tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Builds a plain IPv6 SYN packet without TCP options.
pub fn build_ipv6_syn_packet(
    src_ip: &Ipv6Addr,
    dst_ip: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    build_ipv6_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, &[])
}

/// Parsed IPv6/TCP response relevant to the raw SYN scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedV6Frame {
    SynAck {
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        ack: u32,
    },
    Rst {
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    },
    Other,
}

/// Parses a raw IPv6 socket payload, accepting either a full IPv6 header or a
/// bare TCP segment. `fallback_src` supplies the peer address from `recvfrom`.
pub fn parse_ipv6_tcp(data: &[u8], fallback_src: Option<Ipv6Addr>) -> ParsedV6Frame {
    let (src_ip, tcp) = if data.len() >= 40 && (data[0] >> 4) == 6 {
        if data[6] != 6 {
            return ParsedV6Frame::Other;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[8..24]);
        (Ipv6Addr::from(octets), &data[40..])
    } else if let Some(src) = fallback_src {
        (src, data)
    } else {
        return ParsedV6Frame::Other;
    };

    if tcp.len() < 20 {
        return ParsedV6Frame::Other;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];

    if (flags & 0x12) == 0x12 {
        ParsedV6Frame::SynAck {
            src_ip,
            src_port,
            dst_port,
            ack,
        }
    } else if (flags & 0x04) != 0 {
        ParsedV6Frame::Rst {
            src_ip,
            src_port,
            dst_port,
        }
    } else {
        ParsedV6Frame::Other
    }
}

/// Builds a 54-byte raw Ethernet/IPv4/TCP SYN frame.
///
/// Header structure:
/// - Ethernet II: 14 bytes (destination MAC, source MAC, EtherType 0x0800)
/// - IPv4 Header: 20 bytes (Version 4, IHL 5, Total Length 40, DF set, TTL 64, Protocol 6, Checksum)
/// - TCP Header: 20 bytes (Data Offset 5, SYN flag set, Window Size 1024, Checksum)
pub fn build_syn_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> [u8; 54] {
    let mut frame = [0u8; 54];

    // 1. Ethernet Header (bytes 0..14)
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    // 2. IPv4 Header (bytes 14..34)
    frame[14] = 0x45; // Version 4, IHL 5 (20 bytes)
    frame[15] = 0x00; // DSCP / ECN
    frame[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total Length: 40 bytes (20 IP + 20 TCP)
    frame[18..20].copy_from_slice(&(seq as u16).to_be_bytes()); // Identification
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment (DF), Offset 0
    frame[22] = 64; // TTL
    frame[23] = 6; // Protocol: TCP
    frame[24..26].copy_from_slice(&[0, 0]); // Zero out checksum for calculation
    frame[26..30].copy_from_slice(&src_ip.to_be_bytes());
    frame[30..34].copy_from_slice(&dst_ip.to_be_bytes());

    let ip_ck = ip_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_ck.to_be_bytes());

    // 3. TCP Header (bytes 34..54)
    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&0u32.to_be_bytes()); // Acknowledgment number (0 in initial SYN)
    frame[46] = 0x50; // Data offset: 5 (20 bytes), Reserved: 0
    frame[47] = 0x02; // Flags: SYN
    frame[48..50].copy_from_slice(&1024u16.to_be_bytes()); // Window Size: 1024
    frame[50..52].copy_from_slice(&[0, 0]); // Zero out checksum for calculation
    frame[52..54].copy_from_slice(&[0, 0]); // Urgent Pointer: 0

    let tcp_ck = tcp_checksum(src_ip, dst_ip, &frame[34..54]);
    frame[50..52].copy_from_slice(&tcp_ck.to_be_bytes());

    frame
}

/// Split a raw Ethernet/IPv4/TCP SYN frame into IPv4 fragments.
///
/// `fragment_size` is the maximum IP payload (TCP bytes) per fragment and must
/// be a multiple of 8.  The TCP checksum is calculated once over the complete
/// segment and remains in the first fragment; every fragment gets its own IP
/// header checksum, identification value, and fragment offset.
pub fn fragment_syn_frame(frame: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    const ETHERNET_LEN: usize = 14;
    const IP_LEN: usize = 20;

    if frame.len() < ETHERNET_LEN + IP_LEN || fragment_size == 0 || !fragment_size.is_multiple_of(8)
    {
        return vec![frame.to_vec()];
    }

    let payload = &frame[ETHERNET_LEN + IP_LEN..];
    if payload.len() <= fragment_size {
        return vec![frame.to_vec()];
    }

    let mut fragments = Vec::with_capacity(payload.len().div_ceil(fragment_size));
    let mut offset = 0;
    while offset < payload.len() {
        let chunk_len = (payload.len() - offset).min(fragment_size);
        let mut fragment = Vec::with_capacity(ETHERNET_LEN + IP_LEN + chunk_len);
        fragment.extend_from_slice(&frame[..ETHERNET_LEN + IP_LEN]);
        fragment[16..18].copy_from_slice(&(IP_LEN as u16 + chunk_len as u16).to_be_bytes());

        let mut flags_offset = ((offset / 8) as u16) & 0x1fff;
        if offset + chunk_len < payload.len() {
            flags_offset |= 0x2000; // More Fragments
        }
        fragment[20..22].copy_from_slice(&flags_offset.to_be_bytes());
        fragment[24..26].copy_from_slice(&[0, 0]);
        let checksum = ip_checksum(&fragment[ETHERNET_LEN..ETHERNET_LEN + IP_LEN]);
        fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
        fragment.extend_from_slice(&payload[offset..offset + chunk_len]);
        fragments.push(fragment);
        offset += chunk_len;
    }
    fragments
}

/// Parses an incoming Ethernet frame and extracts TCP/ICMP probe responses.
///
/// Guaranteed not to panic on malformed or truncated input.
pub fn parse_frame(data: &[u8]) -> ParsedFrame {
    // Minimum Ethernet header length is 14 bytes
    if data.len() < 14 {
        return ParsedFrame::Other;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return ParsedFrame::Other;
    }

    let ip_data = &data[14..];
    if ip_data.len() < 20 {
        return ParsedFrame::Other;
    }

    // Check IPv4 version
    if (ip_data[0] >> 4) != 4 {
        return ParsedFrame::Other;
    }

    let ihl = ((ip_data[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip_data.len() < ihl {
        return ParsedFrame::Other;
    }

    let src_ip = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
    let proto = ip_data[9];

    if proto == 6 {
        // TCP
        let tcp_data = &ip_data[ihl..];
        if tcp_data.len() < 20 {
            return ParsedFrame::Other;
        }

        let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
        let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
        let seq = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
        let ack = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
        let flags = tcp_data[13];

        if (flags & 0x12) == 0x12 {
            // SYN + ACK
            ParsedFrame::SynAck {
                src_ip,
                src_port,
                dst_port,
                seq,
                ack,
            }
        } else if (flags & 0x04) != 0 {
            // RST
            ParsedFrame::Rst {
                src_ip,
                src_port,
                dst_port,
            }
        } else {
            ParsedFrame::Other
        }
    } else if proto == 1 {
        // ICMP
        let icmp_data = &ip_data[ihl..];
        // ICMP header is 8 bytes, followed by original IP header (at least 20 bytes) + original payload (at least 8 bytes)
        if icmp_data.len() < 8 {
            return ParsedFrame::Other;
        }

        let icmp_type = icmp_data[0];
        if icmp_type == 3 {
            // Destination Unreachable
            let inner_ip = &icmp_data[8..];
            if inner_ip.len() < 20 {
                return ParsedFrame::Other;
            }
            if (inner_ip[0] >> 4) != 4 {
                return ParsedFrame::Other;
            }
            let inner_ihl = ((inner_ip[0] & 0x0f) as usize) * 4;
            if inner_ihl < 20 || inner_ip.len() < inner_ihl + 4 {
                return ParsedFrame::Other;
            }

            let inner_dst_ip =
                u32::from_be_bytes([inner_ip[16], inner_ip[17], inner_ip[18], inner_ip[19]]);
            let inner_tcp = &inner_ip[inner_ihl..];
            let inner_dst_port = u16::from_be_bytes([inner_tcp[2], inner_tcp[3]]);

            ParsedFrame::IcmpUnreachable {
                dst_ip: inner_dst_ip,
                dst_port: inner_dst_port,
            }
        } else {
            ParsedFrame::Other
        }
    } else {
        ParsedFrame::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_syn_ack() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let src_ip = 0x0a000001; // 10.0.0.1
        let dst_ip = 0x0a000002; // 10.0.0.2
        let src_port = 61234;
        let dst_port = 80;
        let seq = 0x12345678;

        let frame = build_syn_frame(&src_mac, &dst_mac, src_ip, dst_ip, src_port, dst_port, seq);
        assert_eq!(frame.len(), 54);

        // Verify IP checksum validates to 0
        let ip_hdr = &frame[14..34];
        assert_eq!(ip_checksum(ip_hdr), 0);

        // Simulate SYN-ACK reply from target to us
        let mut reply = [0u8; 54];
        reply[0..6].copy_from_slice(&src_mac);
        reply[6..12].copy_from_slice(&dst_mac);
        reply[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        // IP header
        reply[14] = 0x45;
        reply[22] = 64;
        reply[23] = 6; // TCP
        reply[26..30].copy_from_slice(&dst_ip.to_be_bytes()); // src is target
        reply[30..34].copy_from_slice(&src_ip.to_be_bytes()); // dst is scanner

        // TCP header
        reply[34..36].copy_from_slice(&dst_port.to_be_bytes()); // src_port 80
        reply[36..38].copy_from_slice(&src_port.to_be_bytes()); // dst_port 61234
        reply[38..42].copy_from_slice(&0x99887766u32.to_be_bytes()); // remote seq
        reply[42..46].copy_from_slice(&(seq + 1).to_be_bytes()); // ack = seq + 1
        reply[46] = 0x50; // offset 5
        reply[47] = 0x12; // SYN + ACK

        let parsed = parse_frame(&reply);
        match parsed {
            ParsedFrame::SynAck {
                src_ip: sip,
                src_port: sp,
                dst_port: dp,
                seq: s,
                ack: a,
            } => {
                assert_eq!(sip, dst_ip);
                assert_eq!(sp, 80);
                assert_eq!(dp, 61234);
                assert_eq!(s, 0x99887766);
                assert_eq!(a, seq + 1);
            }
            _ => panic!("Expected SynAck, got {:?}", parsed),
        }
    }

    #[test]
    fn test_parse_rst() {
        let mut reply = [0u8; 54];
        reply[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        reply[14] = 0x45;
        reply[23] = 6; // TCP
        reply[26..30].copy_from_slice(&0x0a000002u32.to_be_bytes()); // src_ip
        reply[34..36].copy_from_slice(&443u16.to_be_bytes()); // src_port
        reply[36..38].copy_from_slice(&61005u16.to_be_bytes()); // dst_port
        reply[46] = 0x50;
        reply[47] = 0x04; // RST

        let parsed = parse_frame(&reply);
        match parsed {
            ParsedFrame::Rst {
                src_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, 0x0a000002);
                assert_eq!(src_port, 443);
                assert_eq!(dst_port, 61005);
            }
            _ => panic!("Expected Rst, got {:?}", parsed),
        }
    }

    #[test]
    fn test_parse_icmp_unreachable() {
        let mut frame = vec![0u8; 14 + 20 + 8 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[23] = 1; // ICMP
        let icmp_start = 14 + 20;
        frame[icmp_start] = 3; // Destination Unreachable

        let inner_ip_start = icmp_start + 8;
        frame[inner_ip_start] = 0x45;
        // inner dst_ip at offset 16
        frame[inner_ip_start + 16..inner_ip_start + 20]
            .copy_from_slice(&0x0a000003u32.to_be_bytes());

        let inner_tcp_start = inner_ip_start + 20;
        // inner tcp dst_port at offset 2
        frame[inner_tcp_start + 2..inner_tcp_start + 4].copy_from_slice(&22u16.to_be_bytes());

        let parsed = parse_frame(&frame);
        match parsed {
            ParsedFrame::IcmpUnreachable { dst_ip, dst_port } => {
                assert_eq!(dst_ip, 0x0a000003);
                assert_eq!(dst_port, 22);
            }
            _ => panic!("Expected IcmpUnreachable, got {:?}", parsed),
        }
    }

    #[test]
    fn fragments_preserve_payload_and_offsets() {
        let frame = build_syn_frame(
            &[1, 2, 3, 4, 5, 6],
            &[7, 8, 9, 10, 11, 12],
            0x0a000001,
            0x0a000002,
            61234,
            80,
            0x12345678,
        );
        let fragments = fragment_syn_frame(&frame, 8);
        assert_eq!(fragments.len(), 3); // 20-byte TCP segment -> 8 + 8 + 4
        let mut payload = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.len(), 34 + if index < 2 { 8 } else { 4 });
            assert_eq!(ip_checksum(&fragment[14..34]), 0);
            let flags_offset = u16::from_be_bytes([fragment[20], fragment[21]]);
            assert_eq!(flags_offset & 0x1fff, index as u16);
            assert_eq!(flags_offset & 0x2000 != 0, index < 2);
            assert_eq!(
                u16::from_be_bytes([fragment[16], fragment[17]]) as usize,
                fragment.len() - 14
            );
            payload.extend_from_slice(&fragment[34..]);
        }
        assert_eq!(payload, frame[34..]);
    }

    #[test]
    fn tiny_or_unaligned_fragment_sizes_are_ignored() {
        let frame = build_syn_frame(&[1; 6], &[2; 6], 0x0a000001, 0x0a000002, 61234, 80, 1);
        assert_eq!(fragment_syn_frame(&frame, 0).len(), 1);
        assert_eq!(fragment_syn_frame(&frame, 7).len(), 1);
        assert_eq!(fragment_syn_frame(&frame, 64).len(), 1);
    }

    #[test]
    fn ipv6_packet_has_valid_lengths_and_checksum() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = build_ipv6_syn_packet(&src, &dst, 61000, 443, 0x1234_5678);
        assert_eq!(packet.len(), 60);
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 20);
        assert_eq!(packet[6], 6);
        assert_eq!(&packet[8..24], &src.octets());
        assert_eq!(&packet[24..40], &dst.octets());
        assert_eq!(&packet[40..42], &61000u16.to_be_bytes());
        assert_eq!(&packet[42..44], &443u16.to_be_bytes());
        assert_ne!(u16::from_be_bytes([packet[56], packet[57]]), 0);
    }

    #[test]
    fn parses_ipv6_syn_ack_with_and_without_header() {
        let src: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut packet = build_ipv6_syn_packet(&src, &dst, 443, 61000, 99);
        packet[40 + 13] = 0x12;
        packet[40 + 8..40 + 12].copy_from_slice(&100u32.to_be_bytes());

        match parse_ipv6_tcp(&packet, None) {
            ParsedV6Frame::SynAck {
                src_ip,
                src_port,
                dst_port,
                ack,
            } => {
                assert_eq!(src_ip, src);
                assert_eq!(src_port, 443);
                assert_eq!(dst_port, 61000);
                assert_eq!(ack, 100);
            }
            other => panic!("expected IPv6 SYN-ACK, got {other:?}"),
        }

        match parse_ipv6_tcp(&packet[40..], Some(src)) {
            ParsedV6Frame::SynAck { src_ip, .. } => assert_eq!(src_ip, src),
            other => panic!("expected headerless IPv6 SYN-ACK, got {other:?}"),
        }
    }
}
