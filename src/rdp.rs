//! RDP (Remote Desktop) identity enrichment.
//!
//! Performs the MS-RDPBCGR connection negotiation, upgrades the connection to
//! TLS when the server supports it, and sends the same incomplete CredSSP
//! (NTLM) authentication request that nmap's `rdp-ntlm-info` uses.  NLA-enabled
//! Windows hosts answer with an NTLMSSP CHALLENGE that discloses the computer
//! name, domain, and OS build even when credentials are not supplied.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::discovery::socket_addr;
use crate::model::{PortResult, PortState, ScanReport};
use crate::service::ServiceInfo;

pub const RDP_PORT: u16 = 3389;
const MAX_READ: usize = 8192;
const NTLM_VERSION_FLAG: u32 = 0x0200_0000;

/// CredSSP TSRequest carrying an NTLMSSP NEGOTIATE from a Windows 10 client.
/// This is the proven `rdp-ntlm-info` blob; the wrapper is pre-encoded ASN.1.
const CREDSSP_NTLM_NEGOTIATE: &[u8] = &[
    0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04,
    0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0xB7, 0x82, 0x08,
    0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0A, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0F,
];

/// OS/protocol facts recovered from one RDP endpoint.
#[derive(Clone, Debug, Serialize)]
pub struct RdpInfo {
    /// Negotiated security protocol: `HYBRID_EX`, `HYBRID`, `SSL`, `RDP`, …
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

impl RdpInfo {
    /// Build the service identity derived from the fingerprint.
    fn service(&self) -> Option<ServiceInfo> {
        let product = self.product.clone()?;
        let version = self.os_version.clone();
        Some(ServiceInfo {
            name: "rdp".to_string(),
            product: Some(product),
            version: version.clone(),
            confidence: Some(if version.is_some() { 0.98 } else { 0.90 }),
        })
    }
}

/// Enrich every detected RDP result in a report.
pub async fn apply(report: &mut ScanReport, timeout: Duration, quiet: bool) -> usize {
    let candidates: Vec<(usize, IpAddr, u16)> = report
        .results
        .iter()
        .enumerate()
        .filter(|(_, result)| {
            result.state == PortState::Open
                || result.state == PortState::Silent
                || result.reset_during_verification()
        })
        .filter(|(_, result)| {
            result.port == RDP_PORT
                || result
                    .service
                    .as_ref()
                    .is_some_and(|service| service.name == "rdp")
        })
        .map(|(index, result)| (index, result.host, result.port))
        .collect();
    if candidates.is_empty() {
        return 0;
    }

    if !quiet {
        eprintln!(
            "[rdp] negotiating NLA against {} endpoint(s) …",
            candidates.len()
        );
    }

    let mut enriched = Vec::new();
    for chunk in candidates.chunks(16) {
        let mut tasks = JoinSet::new();
        for &(index, host, port) in chunk {
            tasks.spawn(async move { (index, inspect(host, port, timeout).await) });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Ok((index, Some(info))) = joined {
                enriched.push((index, info));
            }
        }
    }

    let matched = enriched.len();
    for (index, info) in enriched {
        if let Some(result) = report.results.get_mut(index) {
            let previous = result.state;
            annotate(result, info);
            if previous != PortState::Open {
                result.state = PortState::Open;
                report.counts.remove(previous);
                report.counts.add(PortState::Open);
            }
        }
    }
    if matched > 0 && !quiet {
        eprintln!("[rdp] identified {matched} endpoint(s)");
    }
    matched
}

fn annotate(result: &mut PortResult, info: RdpInfo) {
    if let Some(service) = info.service() {
        result.service = Some(service);
    }
    let mut banner = format!("RDP {}", info.protocol);
    if let Some(name) = &info.computer_name {
        banner.push_str(" / ");
        banner.push_str(name);
    }
    if let Some(version) = &info.os_version {
        banner.push_str(" / ");
        banner.push_str(version);
    }
    result.banner = Some(banner);
    let detail = format!("rdp:{}", info.protocol.to_ascii_lowercase());
    result.detail = Some(match result.detail.take() {
        Some(existing)
            if existing.contains("no banner")
                || existing.contains("connection closed during verification") =>
        {
            detail
        }
        Some(existing) if !existing.is_empty() => format!("{existing},{detail}"),
        _ => detail,
    });
    result.rdp = Some(info);
}

pub async fn inspect(host: IpAddr, port: u16, timeout: Duration) -> Option<RdpInfo> {
    tokio::task::spawn_blocking(move || inspect_blocking(host, port, timeout))
        .await
        .ok()
        .flatten()
}

fn inspect_blocking(host: IpAddr, port: u16, timeout: Duration) -> Option<RdpInfo> {
    let mut stream = TcpStream::connect_timeout(&socket_addr(host, port), timeout).ok()?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream.write_all(&connection_request()).ok()?;
    let response = read_tpkt(&mut stream)?;
    let negotiation = parse_negotiation(&response)?;

    if negotiation.failed {
        return Some(RdpInfo {
            protocol: format!("negotiation failed ({:#06x})", negotiation.protocol),
            target: None,
            computer_name: None,
            domain: None,
            os_version: None,
            product: Some("Microsoft RDP".to_string()),
        });
    }

    // Attempt CredSSP even when the server selected standard RDP security:
    // many hosts still accept a TLS handshake on the same connection.
    let Some(mut connection) = tls_handshake(&mut stream, host, timeout) else {
        return Some(negotiated_only(negotiation.protocol));
    };
    let Some(challenge) = credssp_challenge(&mut connection, &mut stream, timeout) else {
        return Some(negotiated_only(negotiation.protocol));
    };
    let parsed = parse_ntlm_challenge(&challenge);
    let os_version = parsed.as_ref().and_then(ntlm_version);
    let product = os_version
        .as_deref()
        .and_then(windows_product)
        .map(str::to_string)
        .or_else(|| Some("Microsoft RDP".to_string()));
    Some(RdpInfo {
        protocol: protocol_name(negotiation.protocol),
        target: parsed.as_ref().and_then(|value| value.target.clone()),
        computer_name: parsed
            .as_ref()
            .and_then(|value| value.computer_name.clone()),
        domain: parsed.as_ref().and_then(|value| value.domain.clone()),
        os_version,
        product,
    })
}

#[derive(Clone, Copy, Debug)]
struct Negotiation {
    protocol: u32,
    failed: bool,
}

fn negotiated_only(protocol: u32) -> RdpInfo {
    RdpInfo {
        protocol: protocol_name(protocol),
        target: None,
        computer_name: None,
        domain: None,
        os_version: None,
        product: Some("Microsoft RDP".to_string()),
    }
}

/// X.224 Connection Request requesting SSL, HYBRID, and HYBRID_EX.
fn connection_request() -> Vec<u8> {
    let cookie = b"Cookie: mstshash=rayscan\r\n";
    let mut body = Vec::with_capacity(8 + cookie.len() + 8);
    body.extend_from_slice(&[0, 0, 0, 0]); // destination and source reference
    body.push(0); // class options
    body.extend_from_slice(cookie);
    body.push(0x01); // TYPE_RDP_NEG_REQ
    body.push(0x00); // flags
    body.extend_from_slice(&8u16.to_le_bytes());
    body.extend_from_slice(&(1u32 | 2 | 8).to_le_bytes());

    let mut itut = Vec::with_capacity(body.len() + 2);
    itut.push((body.len() + 1) as u8);
    itut.push(0xE0); // X.224 Connection Request
    itut.extend_from_slice(&body);

    let total = (4 + itut.len()) as u16;
    let mut packet = Vec::with_capacity(total as usize);
    packet.push(3); // TPKT version
    packet.push(0);
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&itut);
    packet
}

fn read_tpkt(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).ok()?;
    if header[0] != 3 {
        return None;
    }
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(4..=MAX_READ).contains(&length) {
        return None;
    }
    let mut body = vec![0u8; length - 4];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

/// Extract the RDP_NEG_RSP / RDP_NEG_FAILURE block from the X.224 confirm.
fn parse_negotiation(data: &[u8]) -> Option<Negotiation> {
    // X.224 Connection Confirm: LI, code, dst-ref (2), src-ref (2), class (1),
    // followed by the optional RDP negotiation block at index 7. Some stacks
    // emit longer reference fields, so scan forward instead of hard-coding 7.
    if data.len() >= 8 {
        for index in 6..=data.len() - 8 {
            let kind = data[index];
            if kind != 0x02 && kind != 0x03 {
                continue;
            }
            let length = u16::from_le_bytes([data[index + 2], data[index + 3]]);
            if length != 8 {
                continue;
            }
            let value = u32::from_le_bytes([
                data[index + 4],
                data[index + 5],
                data[index + 6],
                data[index + 7],
            ]);
            return Some(Negotiation {
                protocol: value,
                failed: kind == 0x03,
            });
        }
    }
    // Windows XP-era servers omit the negotiation block entirely.
    Some(Negotiation {
        protocol: 0,
        failed: false,
    })
}

fn protocol_name(protocol: u32) -> String {
    match protocol {
        0 => "RDP",
        1 => "SSL",
        2 => "HYBRID",
        4 => "RDSTLS",
        8 => "HYBRID_EX",
        other => return format!("protocol {other}"),
    }
    .to_string()
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_handshake(
    stream: &mut TcpStream,
    host: IpAddr,
    timeout: Duration,
) -> Option<ClientConnection> {
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(AcceptAny);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string()).ok()?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name).ok()?;

    let deadline = Instant::now() + timeout;
    while connection.is_handshaking() {
        if Instant::now() >= deadline {
            return None;
        }
        connection.complete_io(stream).ok()?;
    }
    Some(connection)
}

/// Send the CredSSP NTLM negotiate and return the raw NTLMSSP CHALLENGE bytes.
fn credssp_challenge(
    connection: &mut ClientConnection,
    stream: &mut TcpStream,
    timeout: Duration,
) -> Option<Vec<u8>> {
    connection.writer().write_all(CREDSSP_NTLM_NEGOTIATE).ok()?;
    let deadline = Instant::now() + timeout.min(Duration::from_millis(1500));
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut done = false;

    loop {
        loop {
            match connection.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => data.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if find(&data, b"NTLMSSP").is_some() || done {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining));
        if connection.complete_io(stream).is_err() {
            done = true;
        }
    }
    find(&data, b"NTLMSSP").map(|_| data)
}

#[derive(Clone, Debug, Default)]
struct NtlmChallenge {
    target: Option<String>,
    computer_name: Option<String>,
    domain: Option<String>,
    version: Option<(u8, u8, u16)>,
}

fn parse_ntlm_challenge(data: &[u8]) -> Option<NtlmChallenge> {
    let start = find(data, b"NTLMSSP\0")?;
    let message = &data[start..];
    if message.len() < 48 {
        return None;
    }
    let kind = u32::from_le_bytes(message[8..12].try_into().ok()?);
    if kind != 2 {
        return None;
    }
    let flags = u32::from_le_bytes(message[20..24].try_into().ok()?);

    let mut challenge = NtlmChallenge {
        target: field_utf16(message, 12),
        ..NtlmChallenge::default()
    };

    if let Some(target_info) = field(message, 40) {
        parse_av_pairs(target_info, &mut challenge);
    }

    if flags & NTLM_VERSION_FLAG != 0 && message.len() >= 56 {
        let major = message[48];
        let minor = message[49];
        let build = u16::from_le_bytes([message[50], message[51]]);
        if major != 0 {
            challenge.version = Some((major, minor, build));
        }
    }
    Some(challenge)
}

fn parse_av_pairs(mut data: &[u8], challenge: &mut NtlmChallenge) {
    while data.len() >= 4 {
        let id = u16::from_le_bytes([data[0], data[1]]) as usize;
        let length = u16::from_le_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if length > data.len() {
            break;
        }
        let value = &data[..length];
        data = &data[length..];
        if id == 0 {
            break;
        }
        let text = decode_utf16(value);
        match id {
            1 if challenge.computer_name.is_none() => {
                challenge.computer_name = Some(text);
            }
            2 if challenge.domain.is_none() => challenge.domain = Some(text),
            3 => challenge.computer_name = Some(text),
            4 => challenge.domain = Some(text),
            5 if challenge.domain.is_none() => challenge.domain = Some(text),
            _ => {}
        }
    }
}

fn field_utf16(message: &[u8], offset: usize) -> Option<String> {
    field(message, offset).map(decode_utf16)
}

/// Read a (length, max-length, offset) security-buffer field.
fn field(message: &[u8], offset: usize) -> Option<&[u8]> {
    let length = u16::from_le_bytes(message.get(offset..offset + 2)?.try_into().ok()?) as usize;
    let start = u32::from_le_bytes(message.get(offset + 4..offset + 8)?.try_into().ok()?) as usize;
    if length == 0 {
        return None;
    }
    message.get(start..start + length)
}

fn decode_utf16(value: &[u8]) -> String {
    let units: Vec<u16> = value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn ntlm_version(challenge: &NtlmChallenge) -> Option<String> {
    challenge
        .version
        .map(|(major, minor, build)| format!("{major}.{minor}.{build}"))
}

fn windows_product(version: &str) -> Option<&'static str> {
    let mut parts = version.split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;
    let build: u16 = parts.next()?.parse().ok()?;
    Some(match (major, minor) {
        (10, 0) if build >= 22000 => "Windows 11 / Server 2025",
        (10, 0) if build >= 20348 => "Windows Server 2022",
        (10, 0) if build >= 17763 => "Windows 10 / Server 2019",
        (10, 0) => "Windows 10 / Server 2016",
        (6, 3) => "Windows 8.1 / Server 2012 R2",
        (6, 2) => "Windows 8 / Server 2012",
        (6, 1) => "Windows 7 / Server 2008 R2",
        (6, 0) => "Windows Vista / Server 2008",
        (5, 2) => "Windows Server 2003",
        (5, 1) => "Windows XP",
        (5, 0) => "Windows 2000",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_valid_x224_connection_request() {
        let packet = connection_request();
        assert_eq!(packet[0], 3, "TPKT version");
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        assert_eq!(total, packet.len());
        assert_eq!(packet[4] as usize + 1, packet.len() - 4, "X.224 LI");
        assert_eq!(packet[5], 0xE0);
        assert!(packet.windows(8).any(|window| window == b"mstshash"));
        assert!(packet.ends_with(&[0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn parses_the_selected_security_protocol() {
        let mut response = vec![0u8; 11];
        response.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00]);
        let negotiation = parse_negotiation(&response).unwrap();
        assert!(!negotiation.failed);
        assert_eq!(protocol_name(negotiation.protocol), "HYBRID_EX");

        let mut failure = vec![0u8; 11];
        failure.extend_from_slice(&[0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00]);
        let negotiation = parse_negotiation(&failure).unwrap();
        assert!(negotiation.failed);

        // Real Windows 11 confirm: LI, 0xD0, dst-ref, src-ref, class, then the
        // RDP_NEG_RSP block at index 7 (HYBRID_EX, flags 0x2F).
        let mut windows = vec![0u8; 7];
        windows.extend_from_slice(&[0x02, 0x2F, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00]);
        let negotiation = parse_negotiation(&windows).unwrap();
        assert!(!negotiation.failed);
        assert_eq!(protocol_name(negotiation.protocol), "HYBRID_EX");
    }

    #[test]
    fn parses_ntlm_challenge_version_and_names() {
        let mut av = Vec::new();
        for (id, value) in [
            (1u16, "WIN-SRV01"),
            (2, "LAB"),
            (3, "win-srv01.lab"),
            (4, "lab.local"),
        ] {
            let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
            av.extend_from_slice(&id.to_le_bytes());
            av.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
            av.extend_from_slice(&encoded);
        }
        let target = "LAB"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let target_off = 56u32;
        let info_off = target_off as usize + target.len();
        let mut message = Vec::new();
        message.extend_from_slice(b"NTLMSSP\0");
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&(target.len() as u16).to_le_bytes());
        message.extend_from_slice(&(target.len() as u16).to_le_bytes());
        message.extend_from_slice(&target_off.to_le_bytes());
        message.extend_from_slice(&(NTLM_VERSION_FLAG | 0x0000_0001).to_le_bytes());
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&(av.len() as u16).to_le_bytes());
        message.extend_from_slice(&(av.len() as u16).to_le_bytes());
        message.extend_from_slice(&(info_off as u32).to_le_bytes());
        message.extend_from_slice(&[10, 0, 0x39, 0x4A, 0, 0, 0, 15]);
        assert_eq!(message.len(), target_off as usize);
        message.extend_from_slice(&target);
        message.extend_from_slice(&av);

        let parsed = parse_ntlm_challenge(&message).unwrap();
        assert_eq!(parsed.target.as_deref(), Some("LAB"));
        assert_eq!(parsed.computer_name.as_deref(), Some("win-srv01.lab"));
        assert_eq!(parsed.domain.as_deref(), Some("lab.local"));
        assert_eq!(ntlm_version(&parsed).as_deref(), Some("10.0.19001"));
        assert_eq!(
            windows_product("10.0.19001"),
            Some("Windows 10 / Server 2019")
        );
        assert_eq!(
            windows_product("10.0.22631"),
            Some("Windows 11 / Server 2025")
        );
        assert_eq!(
            windows_product("6.1.7601"),
            Some("Windows 7 / Server 2008 R2")
        );
    }
}
