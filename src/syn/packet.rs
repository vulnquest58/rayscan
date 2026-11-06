//! Raw Ethernet, IPv4, and TCP frame construction and parsing.
//!
//! Provides zero-copy packet generation for TCP SYN probes and safe parsing
//! for incoming SYN-ACK, RST, and ICMP Destination Unreachable frames.

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
}
