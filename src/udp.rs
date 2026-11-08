use std::net::IpAddr;

use serde::Serialize;

/// DNS query for "example.com" (A record).
const DNS_QUERY: &[u8] = &[
    0x00, 0x01, // txid
    0x01, 0x00, // flags: standard query, recursion desired
    0x00, 0x01, // qdcount=1
    0x00, 0x00, // ancount=0
    0x00, 0x00, // nscount=0
    0x00, 0x00, // arcount=0
    // QNAME: "example.com"
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // root label
    0x00, 0x01, // QTYPE=A
    0x00, 0x01, // QCLASS=IN
];

/// NetBIOS Name Service (NBNS) wildcard '*' status query (port 137).
const NETBIOS_QUERY: &[u8] = &[
    0x80, 0x01, // Transaction ID
    0x00, 0x00, // Flags: Query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // Question Name: 32 bytes encoded wildcard "*"
    0x20, b'C', b'K', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', 0x00, 0x00, 0x21, // Type: NBSTAT (0x0021)
    0x00, 0x01, // Class: IN (0x0001)
];

/// SIP OPTIONS probe for VoIP / PBX discovery (port 5060).
const SIP_OPTIONS_PROBE: &[u8] = b"OPTIONS sip:nm@127.0.0.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-rayscan\r\n\
Max-Forwards: 70\r\n\
To: <sip:nm@127.0.0.1>\r\n\
From: <sip:rayscan@127.0.0.1>;tag=rayscan\r\n\
Call-ID: rayscan-probe@127.0.0.1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

/// NTP client request (version 3, mode 3) for port 123.
const NTP_QUERY: &[u8] = &[
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// SNMPv1 GET sysDescr.0 request for port 161.
const SNMP_GET_SYSDESCR: &[u8] = &[
    0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c, 0x02,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
];

/// RPC NULL call to the portmapper program (port 111).
const RPCBIND_NULL_CALL: &[u8] = &[
    0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// UDP ports probed by `--udp` even when the TCP port is not open.
pub const COMMON_UDP_PORTS: &[u16] = &[
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 631, 1900, 4500, 5060, 5353,
];

/// A service identified from a UDP response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UdpServiceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl UdpServiceInfo {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            product: None,
            version: None,
        }
    }

    fn with_product(mut self, product: Option<String>) -> Self {
        self.product = product;
        self
    }

    fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }
}

/// Service metadata plus a printable, bounded banner from a UDP response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdpDetection {
    pub service: Option<UdpServiceInfo>,
    pub banner: Option<String>,
}

/// Inspect the initial bytes received after a UDP probe.
///
/// Detection is passive: it only classifies data the peer sent. An
/// unrecognized text banner is preserved for the caller.
pub fn inspect_udp(data: &[u8]) -> UdpDetection {
    inspect_udp_port(0, data)
}

/// Port-aware UDP response classifier. `port` disambiguates binary protocols
/// (for example an RPC reply on 111 from a DNS reply on 53).
pub fn inspect_udp_port(port: u16, data: &[u8]) -> UdpDetection {
    if data.is_empty() {
        return UdpDetection::default();
    }

    // RPC portmapper reply: msg_type = REPLY (1), reply_stat = MSG_ACCEPTED (0).
    if port == 111 && data.len() >= 12 && data[4..8] == [0, 0, 0, 1] && data[8..12] == [0, 0, 0, 0]
    {
        return UdpDetection {
            service: Some(UdpServiceInfo::new("rpcbind")),
            banner: Some("RPC portmapper reply".to_string()),
        };
    }

    // SIP response: starts with "SIP/2.0 "
    if data.starts_with(b"SIP/2.0 ") {
        let (product, version, banner) = extract_sip_info(data);
        return UdpDetection {
            service: Some(
                UdpServiceInfo::new("sip")
                    .with_product(product)
                    .with_version(version),
            ),
            banner: Some(banner),
        };
    }

    // NetBIOS Name Service: Response containing NBSTAT (type 0x0021, class 0x0001)
    if data.len() >= 12 && (data[2] & 0x80) != 0 && contains_slice(data, &[0x00, 0x21, 0x00, 0x01])
    {
        let name = extract_netbios_name(data);
        let banner = match &name {
            Some(n) => format!("NetBIOS name: {n}"),
            None => "NetBIOS Name Service response".to_string(),
        };
        return UdpDetection {
            service: Some(UdpServiceInfo::new("netbios-ns").with_product(name)),
            banner: Some(banner),
        };
    }

    // DNS response: QR bit set (0x80 in second byte of flags), OPCODE=0
    if data.len() >= 4 && (data[2] & 0x80) != 0 && (data[2] & 0x78) == 0 {
        let product = extract_dns_server_field(data);
        let (prod, ver) = match product {
            Some((p, v)) => (Some(p), v),
            None => (None, None),
        };
        return UdpDetection {
            service: Some(
                UdpServiceInfo::new("dns")
                    .with_product(prod)
                    .with_version(ver),
            ),
            banner: Some("DNS response".to_string()),
        };
    }

    // SNMP: BER-encoded SEQUENCE (0x30) followed by INTEGER version
    if data.len() >= 2 && data[0] == 0x30 {
        return UdpDetection {
            service: Some(UdpServiceInfo::new("snmp")),
            banner: Some("SNMP response".to_string()),
        };
    }

    // NTP: mode 4 (server) response, version 3 or 4
    if !data.is_empty() {
        let mode = data[0] & 0x07;
        let version = (data[0] >> 3) & 0x07;
        if mode == 4 && (version == 3 || version == 4) {
            return UdpDetection {
                service: Some(UdpServiceInfo::new("ntp").with_version(Some(format!("v{version}")))),
                banner: Some(format!("NTP v{version} server")),
            };
        }
    }

    // Generic: preserve printable text banner (first line only, max 128 chars)
    let text = std::str::from_utf8(data).unwrap_or("");
    let first_line = text
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(128)
        .collect::<String>();

    if first_line.chars().any(|c| c.is_alphanumeric()) {
        UdpDetection {
            service: None,
            banner: Some(first_line),
        }
    } else {
        UdpDetection::default()
    }
}

fn contains_slice(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

fn extract_netbios_name(data: &[u8]) -> Option<String> {
    // Look for NBSTAT record type (0x0021 0x0001)
    let marker = &[0x00, 0x21, 0x00, 0x01];
    let pos = data.windows(marker.len()).position(|w| w == marker)?;

    // After type(2) + class(2) = marker (4 bytes):
    // In Answer section: TTL (4 bytes), RDLENGTH (2 bytes), Number of names (1 byte).
    // Total offset from pos: 4 + 4 + 2 = 10 bytes to number of names.
    let names_offset = pos + 10;
    if data.len() <= names_offset {
        return None;
    }
    let num_names = data[names_offset] as usize;
    if num_names == 0 {
        return None;
    }

    let first_name_offset = names_offset + 1;
    if data.len() < first_name_offset + 15 {
        return None;
    }

    let raw_name = &data[first_name_offset..first_name_offset + 15];
    let decoded = String::from_utf8_lossy(raw_name).trim().to_string();
    if decoded.is_empty() || !decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        None
    } else {
        Some(decoded)
    }
}

fn extract_sip_info(data: &[u8]) -> (Option<String>, Option<String>, String) {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or("SIP/2.0").to_string();

    let mut product = None;
    let mut version = None;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Server: ") {
            let server_val = rest.trim();
            let tokens: Vec<&str> = server_val.split_whitespace().collect();
            if tokens.len() > 1
                && tokens
                    .last()
                    .unwrap()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
            {
                version = Some(tokens.last().unwrap().to_string());
                product = Some(tokens[..tokens.len() - 1].join(" "));
            } else {
                product = Some(server_val.to_string());
            }
            break;
        }
    }

    (product, version, status_line)
}

/// Extract the Server field from a DNS response, returning (product, version).
fn extract_dns_server_field(data: &[u8]) -> Option<(String, Option<String>)> {
    // This is a best-effort heuristic over raw DNS bytes; real DNS parsing
    // is out of scope for the probe.  We skip it and return None.
    let _ = data;
    None
}

/// Send a UDP probe to the given host:port and read the response.
///
/// Sends a targeted probe based on port (137 = NetBIOS, 5060 = SIP, others = DNS).
/// Waits up to `probe_timeout` for a response.
pub async fn probe_udp(
    host: IpAddr,
    port: u16,
    probe_timeout: std::time::Duration,
) -> (Vec<u8>, UdpDetection) {
    let bind = if host.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(_) => return (Vec::new(), UdpDetection::default()),
    };

    if socket.connect((host, port)).await.is_err() {
        return (Vec::new(), UdpDetection::default());
    }

    let probe_payload = match port {
        111 => RPCBIND_NULL_CALL,
        123 => NTP_QUERY,
        137 => NETBIOS_QUERY,
        161 => SNMP_GET_SYSDESCR,
        5060 => SIP_OPTIONS_PROBE,
        _ => DNS_QUERY,
    };

    let _ = socket.send(probe_payload).await;

    let mut buf = [0u8; 1024];
    let result = tokio::time::timeout(probe_timeout, socket.recv(&mut buf)).await;

    match result {
        Ok(Ok(n)) => {
            let received = buf[..n].to_vec();
            let detection = inspect_udp_port(port, &received);
            (received, detection)
        }
        _ => (Vec::new(), UdpDetection::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ipv6_udp_probe_binds_and_classifies_dns() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (_, peer) = server.recv_from(&mut query).await.unwrap();
            let response = [
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            ];
            server.send_to(&response, peer).await.unwrap();
        });

        let (raw, detection) = probe_udp(
            "::1".parse().unwrap(),
            port,
            std::time::Duration::from_secs(1),
        )
        .await;
        assert_eq!(raw.len(), 12);
        assert_eq!(
            detection
                .service
                .as_ref()
                .map(|service| service.name.as_str()),
            Some("dns")
        );
    }

    #[test]
    fn inspect_dns_response() {
        // Minimal DNS response: QR=1, OPCODE=0 (standard query response)
        let mut data = vec![
            0x00, 0x01, // txid
            0x81, 0x80, // flags: QR=1, RD=1, RA=1
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        // Add a minimal question and answer (not fully valid but enough for detection)
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        let detection = inspect_udp(&data);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("dns")
        );
    }

    #[test]
    fn inspect_rpc_portmapper_reply() {
        // RPC reply: xid, msg_type=REPLY(1), reply_stat=MSG_ACCEPTED(0).
        let mut data = vec![
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0x00; 16]);
        let detection = inspect_udp_port(111, &data);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("rpcbind")
        );
    }

    #[test]
    fn inspect_snmp_response() {
        // SNMP begins with BER SEQUENCE tag 0x30
        let data = [0x30, 0x26, 0x02, 0x01, 0x00];
        let detection = inspect_udp(&data);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("snmp")
        );
    }

    #[test]
    fn inspect_ntp_response() {
        // NTP v4 server: LI=0, VN=4 (0b00100100 = 0x24), mode=4
        let mut data = vec![0x24u8]; // LI=0, VN=4, mode=4
        data.extend_from_slice(&[0x00; 47]); // rest of NTP packet
        let detection = inspect_udp(&data);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("ntp")
        );
    }

    #[test]
    fn inspect_netbios_response() {
        let mut data = vec![
            0x80, 0x01, // txid
            0x84, 0x00, // flags: response, authoritative
            0x00, 0x00, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            // RR:
            0xc0, 0x0c, // name pointer
            0x00, 0x21, // type: NBSTAT
            0x00, 0x01, // class: IN
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x18, // RDLENGTH = 24
            0x01, // Number of names = 1
        ];
        // 15-byte name + 1-byte suffix (0x00) + 2-byte flags (0x0000)
        data.extend_from_slice(b"METASPLOITABLE ");
        data.push(0x00);
        data.extend_from_slice(&[0x00, 0x00]);

        let detection = inspect_udp(&data);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("netbios-ns")
        );
        assert_eq!(
            detection
                .service
                .as_ref()
                .and_then(|s| s.product.as_deref()),
            Some("METASPLOITABLE")
        );
        assert_eq!(
            detection.banner.as_deref(),
            Some("NetBIOS name: METASPLOITABLE")
        );
    }

    #[test]
    fn inspect_sip_response() {
        let raw = b"SIP/2.0 200 OK\r\n\
Server: Asterisk PBX 18.2.0\r\n\
Content-Length: 0\r\n\r\n";
        let detection = inspect_udp(raw);
        assert_eq!(
            detection.service.as_ref().map(|s| s.name.as_str()),
            Some("sip")
        );
        assert_eq!(
            detection
                .service
                .as_ref()
                .and_then(|s| s.product.as_deref()),
            Some("Asterisk PBX")
        );
        assert_eq!(
            detection
                .service
                .as_ref()
                .and_then(|s| s.version.as_deref()),
            Some("18.2.0")
        );
        assert_eq!(detection.banner.as_deref(), Some("SIP/2.0 200 OK"));
    }

    #[test]
    fn preserves_text_banner() {
        let detection = inspect_udp(b"hello from custom service\r\n");
        assert!(detection.service.is_none());
        assert_eq!(
            detection.banner.as_deref(),
            Some("hello from custom service")
        );
    }

    #[test]
    fn empty_data_returns_default() {
        let detection = inspect_udp(b"");
        assert!(detection.service.is_none());
        assert!(detection.banner.is_none());
    }
}
