//! Berkeley Packet Filter (BPF) bytecode generator and socket attachment.
//!
//! Generates kernel-level BPF bytecode for an `AF_PACKET` socket so that the
//! kernel discards irrelevant network traffic before waking up the scanner's
//! receive thread. Matches:
//! - IPv4 TCP SYN-ACK frames directed to the scanner's source port range
//! - IPv4 TCP RST frames directed to the scanner's source port range
//! - IPv4 ICMP Destination Unreachable (Type 3) frames

use super::route::SynError;

/// Builds a Berkeley Packet Filter bytecode program tailored to the given
/// scanner source port range `[sport_lo, sport_hi]`.
///
/// Accepts:
/// 1. EtherType 0x0800 (IPv4)
/// 2. TCP packets with flags SYN+ACK or RST where destination port is in `[sport_lo, sport_hi]`
/// 3. ICMP packets of Type 3 (Destination Unreachable)
pub fn build_filter(sport_lo: u16, sport_hi: u16) -> Vec<libc::sock_filter> {
    vec![
        // (000) Load halfword at offset 12 (EtherType)
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x0000000c,
        },
        // (001) Check if EtherType == 0x0800 (IPv4)
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 20, // Jump to reject (022)
            k: 0x00000800,
        },
        // (002) Load byte at offset 23 (IP Protocol: 14 Ethernet + 9)
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000017,
        },
        // (003) Check if Protocol == 6 (TCP)
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 11, // Jump to ICMP check (015)
            k: 0x00000006,
        },
        // (004) Load halfword at offset 20 (IP Flags & Frag Offset)
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x00000014,
        },
        // (005) Check if fragmented (offset & 0x1fff != 0) -> reject if fragmented
        libc::sock_filter {
            code: 0x45,
            jt: 16, // Jump to reject (022)
            jf: 0,
            k: 0x00001fff,
        },
        // (006) Load IP header length into index register X: 4 * (ip[14] & 0x0f)
        libc::sock_filter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 0x0000000e,
        },
        // (007) Load byte at offset X + 27 (14 Ethernet + TCP Flags offset 13)
        libc::sock_filter {
            code: 0x50,
            jt: 0,
            jf: 0,
            k: 0x0000001b,
        },
        // (008) Mask with 0x12 (SYN | ACK)
        libc::sock_filter {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: 0x00000012,
        },
        // (009) Check if (flags & 0x12) == 0x12 (SYN-ACK)
        libc::sock_filter {
            code: 0x15,
            jt: 2, // Matches SYN-ACK, jump to dst port check (012)
            jf: 0,
            k: 0x00000012,
        },
        // (010) Reload byte at offset X + 27 (TCP Flags)
        libc::sock_filter {
            code: 0x50,
            jt: 0,
            jf: 0,
            k: 0x0000001b,
        },
        // (011) Check if RST flag (0x04) is set
        libc::sock_filter {
            code: 0x45,
            jt: 0,  // Matches RST, proceed to dst port check (012)
            jf: 10, // Not RST, jump to reject (022)
            k: 0x00000004,
        },
        // (012) Load halfword at offset X + 16 (14 Ethernet + TCP Dst Port offset 2)
        libc::sock_filter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 0x00000010,
        },
        // (013) Check if dst_port >= sport_lo
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 8, // Below range, jump to reject (022)
            k: sport_lo as u32,
        },
        // (014) Check if dst_port > sport_hi
        libc::sock_filter {
            code: 0x25,
            jt: 7, // Above range, jump to reject (022)
            jf: 6, // Within range! Jump to accept (021)
            k: sport_hi as u32,
        },
        // (015) Check if Protocol == 1 (ICMP)
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 6, // Not ICMP, jump to reject (022)
            k: 0x00000001,
        },
        // (016) Load halfword at offset 20 (IP Flags & Frag Offset)
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x00000014,
        },
        // (017) Check if fragmented
        libc::sock_filter {
            code: 0x45,
            jt: 4, // Jump to reject (022)
            jf: 0,
            k: 0x00001fff,
        },
        // (018) Load IP header length into index register X
        libc::sock_filter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 0x0000000e,
        },
        // (019) Load byte at offset X + 14 (14 Ethernet + ICMP Type offset 0)
        libc::sock_filter {
            code: 0x50,
            jt: 0,
            jf: 0,
            k: 0x0000000e,
        },
        // (020) Check if ICMP Type == 3 (Destination Unreachable)
        libc::sock_filter {
            code: 0x15,
            jt: 0, // Matches ICMP Unreachable, proceed to accept (021)
            jf: 1, // Jump to reject (022)
            k: 0x00000003,
        },
        // (021) Accept packet (snapshot length 262144 bytes)
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00040000,
        },
        // (022) Reject packet (0 bytes)
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00000000,
        },
    ]
}

/// Attaches a Berkeley Packet Filter program to an open socket descriptor.
///
/// # Errors
/// Returns [`SynError::Bpf`] if the `setsockopt(..., SO_ATTACH_FILTER, ...)`
/// syscall returns an error.
pub fn attach_filter(fd: i32, filter: &[libc::sock_filter]) -> Result<(), SynError> {
    let fprog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: `fd` is an open socket file descriptor. `fprog` points to a contiguous
    // vector of `libc::sock_filter` instructions that is guaranteed to outlive the
    // `setsockopt` call. The kernel reads the filter into its own internal memory.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SynError::Bpf(format!("failed to attach BPF filter: {err}")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_filter_length_and_ports() {
        let filter = build_filter(61000, 61999);
        assert_eq!(filter.len(), 23);

        // Instruction 13 checks lower port bound
        assert_eq!(filter[13].k, 61000);
        // Instruction 14 checks upper port bound
        assert_eq!(filter[14].k, 61999);
    }
}
