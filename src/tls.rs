//! TLS metadata inspection.
//!
//! Performs a real handshake with certificate verification intentionally
//! disabled (the scanner must be able to inspect self-signed and expired
//! endpoints), captures the presented chain, and reports protocol, cipher,
//! subject/issuer, SANs, validity, and hostname-match status.  STARTTLS is
//! supported for FTP, SMTP, POP3, and IMAP.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::task::JoinSet;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::model::{PortResult, PortState, ScanReport};
use crate::service::ServiceInfo;

const DIRECT_PORTS: &[u16] = &[
    443, 8443, 9443, 993, 995, 465, 636, 990, 5986, 2376, 8883, 5061,
];
const STARTTLS_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (25, "smtp"),
    (587, "smtp"),
    (110, "pop3"),
    (143, "imap"),
];
const MAX_READ: usize = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMode {
    /// Inspect well-known TLS and STARTTLS ports.
    #[default]
    Auto,
    /// Inspect every open TCP port (direct TLS; STARTTLS on known ports).
    Force,
    /// Do not inspect TLS.
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProbe {
    Direct,
    StartTls(&'static str),
}

/// Decide whether a port should be inspected and how.
pub fn probe_for(port: u16, mode: TlsMode) -> Option<TlsProbe> {
    if mode == TlsMode::Disabled {
        return None;
    }
    if let Some((_, protocol)) = STARTTLS_PORTS
        .iter()
        .find(|(candidate, _)| *candidate == port)
    {
        return Some(TlsProbe::StartTls(protocol));
    }
    if DIRECT_PORTS.contains(&port) {
        return Some(TlsProbe::Direct);
    }
    (mode == TlsMode::Force).then_some(TlsProbe::Direct)
}

#[derive(Clone, Debug, Serialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    pub expired: bool,
    pub not_yet_valid: bool,
    pub self_signed: bool,
    pub hostname_matches: bool,
    pub chain_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls: Option<String>,
}

/// Inspect every eligible open result in a report.
pub async fn apply(
    report: &mut ScanReport,
    mode: TlsMode,
    timeout: Duration,
    quiet: bool,
) -> usize {
    if mode == TlsMode::Disabled {
        return 0;
    }

    let candidates: Vec<(usize, IpAddr, u16, TlsProbe)> = report
        .results
        .iter()
        .enumerate()
        .filter(|(_, result)| result.state == PortState::Open)
        .filter(|(_, result)| {
            !result
                .service
                .as_ref()
                .is_some_and(|service| service.name.starts_with("udp:"))
        })
        .filter_map(|(index, result)| {
            probe_for(result.port, mode).map(|probe| (index, result.host, result.port, probe))
        })
        .collect();
    if candidates.is_empty() {
        return 0;
    }

    if !quiet {
        eprintln!("[tls] inspecting {} open port(s) …", candidates.len());
    }

    let mut inspected = Vec::new();
    for chunk in candidates.chunks(32) {
        let mut tasks = JoinSet::new();
        for &(index, host, port, probe) in chunk {
            tasks.spawn(async move { (index, inspect(host, port, timeout, probe).await) });
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, Some(info))) => inspected.push((index, info)),
                Ok((_, None)) => {}
                Err(error) => {
                    if !quiet {
                        eprintln!("[tls] inspection task failed: {error}");
                    }
                }
            }
        }
    }

    let matched = inspected.len();
    for (index, info) in inspected {
        if let Some(result) = report.results.get_mut(index) {
            annotate(result, info);
        }
    }

    if matched > 0 && !quiet {
        eprintln!("[tls] captured metadata for {matched} endpoint(s)");
    }
    matched
}

fn annotate(result: &mut PortResult, info: TlsInfo) {
    let default_name = service_name(result.port, info.starttls.as_deref());
    let should_replace = result
        .service
        .as_ref()
        .is_none_or(|service| service.name == "tls" || service.name.is_empty());
    if should_replace {
        result.service = Some(ServiceInfo {
            name: default_name.to_string(),
            product: None,
            version: None,
        });
    }
    if result.banner.is_none() {
        result.banner = Some(format!("TLS {} / {}", info.version, info.cipher));
    }
    let detail = format!(
        "tls:{} {}",
        info.version.to_ascii_lowercase().replace('v', ""),
        info.cipher
    );
    result.detail = Some(match result.detail.take() {
        Some(existing) if !existing.is_empty() && !existing.contains("tls:") => {
            format!("{existing},{detail}")
        }
        Some(existing) if !existing.is_empty() => existing,
        _ => detail,
    });
    result.tls = Some(info);
}

fn service_name(port: u16, starttls: Option<&str>) -> &'static str {
    if let Some(protocol) = starttls {
        return match protocol {
            "ftp" => "ftp-starttls",
            "smtp" => "smtp-starttls",
            "pop3" => "pop3-starttls",
            "imap" => "imap-starttls",
            _ => "starttls",
        };
    }
    match port {
        443 | 8443 => "https",
        9443 => "https-alt",
        993 => "imaps",
        995 => "pop3s",
        465 => "smtps",
        636 => "ldaps",
        990 => "ftps",
        5986 => "winrm-https",
        2376 => "docker-tls",
        8883 => "mqtts",
        5061 => "sip-tls",
        _ => "tls",
    }
}

pub async fn inspect(
    host: IpAddr,
    port: u16,
    timeout: Duration,
    probe: TlsProbe,
) -> Option<TlsInfo> {
    tokio::task::spawn_blocking(move || inspect_blocking(host, port, timeout, probe))
        .await
        .ok()
        .flatten()
}

fn inspect_blocking(
    host: IpAddr,
    port: u16,
    timeout: Duration,
    probe: TlsProbe,
) -> Option<TlsInfo> {
    let stream = connect(host, port, timeout)?;
    match probe {
        TlsProbe::Direct => handshake(stream, host, timeout, None),
        TlsProbe::StartTls(protocol) => {
            let stream = negotiate_starttls(stream, protocol, timeout)?;
            handshake(stream, host, timeout, Some(protocol))
        }
    }
}

fn connect(host: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let address = SocketAddr::new(host, port);
    let stream = TcpStream::connect_timeout(&address, timeout).ok()?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    Some(stream)
}

fn negotiate_starttls(
    mut stream: TcpStream,
    protocol: &str,
    timeout: Duration,
) -> Option<TcpStream> {
    let deadline = std::time::Instant::now() + timeout;
    let greeting = read_line(&mut stream, deadline)?;

    match protocol {
        "ftp" => {
            if !greeting.starts_with("220") {
                return None;
            }
            write_command(&mut stream, "AUTH TLS\r\n")?;
            let response = read_line(&mut stream, deadline)?;
            if !response.starts_with("234") {
                write_command(&mut stream, "AUTH SSL\r\n")?;
                let response = read_line(&mut stream, deadline)?;
                if !response.starts_with("234") {
                    return None;
                }
            }
        }
        "smtp" => {
            if !greeting.starts_with("220") {
                return None;
            }
            write_command(&mut stream, "EHLO rayscan\r\n")?;
            loop {
                let line = read_line(&mut stream, deadline)?;
                if line == "250" || line.starts_with("250 ") || !line.starts_with("250") {
                    break;
                }
            }
            write_command(&mut stream, "STARTTLS\r\n")?;
            if !read_line(&mut stream, deadline)?.starts_with("220") {
                return None;
            }
        }
        "pop3" => {
            if !greeting.starts_with("+OK") {
                return None;
            }
            write_command(&mut stream, "STLS\r\n")?;
            if !read_line(&mut stream, deadline)?.starts_with("+OK") {
                return None;
            }
        }
        "imap" => {
            if !greeting.starts_with("* OK") {
                return None;
            }
            write_command(&mut stream, "a001 STARTTLS\r\n")?;
            let mut accepted = false;
            for _ in 0..8 {
                let line = read_line(&mut stream, deadline)?;
                if line.starts_with("a001 OK") {
                    accepted = true;
                    break;
                }
                if line.starts_with("a001 NO") || line.starts_with("a001 BAD") {
                    break;
                }
            }
            if !accepted {
                return None;
            }
        }
        _ => return None,
    }

    Some(stream)
}

fn write_command(stream: &mut TcpStream, command: &str) -> Option<()> {
    stream.write_all(command.as_bytes()).ok()?;
    stream.flush().ok()
}

fn read_line(stream: &mut TcpStream, deadline: std::time::Instant) -> Option<String> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                bytes.push(byte[0]);
                if bytes.len() >= MAX_READ {
                    return None;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return None;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if bytes.is_empty() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\r')
            .to_string(),
    )
}

#[derive(Debug)]
struct CaptureVerifier {
    chain: Mutex<Vec<Vec<u8>>>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = self.chain.lock().unwrap();
        chain.clear();
        chain.push(end_entity.as_ref().to_vec());
        for certificate in intermediates {
            chain.push(certificate.as_ref().to_vec());
        }
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

fn handshake(
    mut stream: TcpStream,
    host: IpAddr,
    timeout: Duration,
    starttls: Option<&str>,
) -> Option<TlsInfo> {
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let capture = Arc::new(CaptureVerifier {
        chain: Mutex::new(Vec::new()),
    });
    let verifier: Arc<dyn ServerCertVerifier> = capture.clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string()).ok()?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name).ok()?;

    let deadline = std::time::Instant::now() + timeout;
    while connection.is_handshaking() {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let _ = connection.complete_io(&mut stream).ok()?;
    }

    let version = connection
        .protocol_version()
        .map(format_version)
        .unwrap_or_else(|| "unknown".to_string());
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".to_string());
    let chain = capture.chain.lock().unwrap().clone();
    Some(parse_info(host, &version, &cipher, &chain, starttls))
}

fn format_version(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        other => format!("{other:?}"),
    }
}

fn parse_info(
    host: IpAddr,
    version: &str,
    cipher: &str,
    chain: &[Vec<u8>],
    starttls: Option<&str>,
) -> TlsInfo {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);

    let mut info = TlsInfo {
        version: version.to_string(),
        cipher: cipher.to_string(),
        subject: None,
        issuer: None,
        san: Vec::new(),
        serial: None,
        not_before: None,
        not_after: None,
        days_remaining: None,
        expired: false,
        not_yet_valid: false,
        self_signed: false,
        hostname_matches: false,
        chain_len: chain.len(),
        starttls: starttls.map(str::to_string),
    };

    let Some(leaf) = chain.first() else {
        return info;
    };
    let Ok((_, certificate)) = parse_x509_certificate(leaf) else {
        return info;
    };

    info.subject = Some(certificate.subject().to_string());
    info.issuer = Some(certificate.issuer().to_string());
    info.serial = Some(certificate.raw_serial_as_string());
    info.self_signed = certificate.subject().to_string() == certificate.issuer().to_string();

    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    info.not_before = Some(not_before);
    info.not_after = Some(not_after);
    info.days_remaining = Some((not_after - now).div_euclid(86_400));
    info.expired = now > not_after;
    info.not_yet_valid = now < not_before;

    let mut ip_names = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            match name {
                GeneralName::DNSName(name) => {
                    info.san.push((*name).to_string());
                }
                GeneralName::IPAddress(bytes) => {
                    if let Some(address) = ip_from_bytes(bytes) {
                        ip_names.push(address);
                        info.san.push(address.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_string);

    // Targets are always IP literals (the resolver runs before scanning), so
    // match IP SANs first and fall back to an IP common name.  DNS SANs are
    // reported but cannot satisfy an IP-literal target.
    info.hostname_matches = if ip_names.contains(&host) {
        true
    } else if ip_names.is_empty() {
        common_name
            .as_deref()
            .and_then(|name| name.parse::<IpAddr>().ok())
            .is_some_and(|name| name == host)
    } else {
        false
    };

    info
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

pub fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host
            .split_once('.')
            .is_some_and(|(_, remainder)| remainder == suffix);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_plan_selects_known_ports_and_force_mode() {
        assert_eq!(probe_for(443, TlsMode::Auto), Some(TlsProbe::Direct));
        assert_eq!(
            probe_for(25, TlsMode::Auto),
            Some(TlsProbe::StartTls("smtp"))
        );
        assert_eq!(probe_for(8080, TlsMode::Auto), None);
        assert_eq!(probe_for(8080, TlsMode::Force), Some(TlsProbe::Direct));
        assert_eq!(probe_for(443, TlsMode::Disabled), None);
    }

    #[test]
    fn dns_names_support_exact_and_single_label_wildcards() {
        assert!(dns_name_matches("example.com", "EXAMPLE.COM"));
        assert!(dns_name_matches("*.example.com", "www.example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
    }

    #[test]
    fn parses_ip_san_bytes() {
        assert_eq!(
            ip_from_bytes(&[192, 0, 2, 1]),
            Some(IpAddr::from([192, 0, 2, 1]))
        );
        assert_eq!(ip_from_bytes(&[1, 2, 3]), None);
    }

    #[test]
    fn service_names_cover_direct_and_starttls() {
        assert_eq!(service_name(443, None), "https");
        assert_eq!(service_name(993, None), "imaps");
        assert_eq!(service_name(25, Some("smtp")), "smtp-starttls");
        assert_eq!(service_name(21, Some("ftp")), "ftp-starttls");
    }

    #[test]
    fn invalid_mode_defaults_are_stable() {
        assert_eq!(TlsMode::default(), TlsMode::Auto);
    }
}
