//! TLS metadata inspection.
//!
//! Performs a real handshake with certificate verification intentionally
//! disabled (the scanner must be able to inspect self-signed and expired
//! endpoints), captures the presented chain, and reports protocol, cipher,
//! subject/issuer, SANs, validity, and hostname-match status.  STARTTLS is
//! supported for FTP, SMTP, POP3, and IMAP.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::task::JoinSet;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::discovery::socket_addr;
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

/// Decide whether an observed result should be inspected and how.
///
/// In `Auto` mode a non-standard port whose banner already looks like TLS, or
/// whose service could not be identified at all, is inspected too: HTTPS and
/// other TLS services on arbitrary ports are common outside the well-known
/// list, and an unidentified open port is a cheap candidate.
pub fn probe_for_result(port: u16, service_name: Option<&str>, mode: TlsMode) -> Option<TlsProbe> {
    if mode == TlsMode::Disabled {
        return None;
    }
    if let Some(probe) = probe_for(port, mode) {
        return Some(probe);
    }
    match mode {
        TlsMode::Force => Some(TlsProbe::Direct),
        TlsMode::Auto if port == crate::rdp::RDP_PORT => None,
        TlsMode::Auto => match service_name {
            Some("tls") | None => Some(TlsProbe::Direct),
            _ => None,
        },
        TlsMode::Disabled => None,
    }
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
        .filter(|(_, result)| result.state == PortState::Open || result.reset_during_verification())
        .filter(|(_, result)| {
            !result
                .service
                .as_ref()
                .is_some_and(|service| service.name.starts_with("udp:"))
        })
        .filter_map(|(index, result)| {
            probe_for_result(
                result.port,
                result.service.as_ref().map(|service| service.name.as_str()),
                mode,
            )
            .map(|probe| (index, result.host, result.port, probe))
        })
        .collect();
    if candidates.is_empty() {
        return 0;
    }

    if !quiet {
        eprintln!("[tls] inspecting {} candidate port(s) …", candidates.len());
    }

    let mut inspected = Vec::new();
    for chunk in candidates.chunks(32) {
        let mut tasks = JoinSet::new();
        for &(index, host, port, probe) in chunk {
            tasks.spawn(async move { (index, inspect(host, port, timeout, probe).await) });
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, Some(outcome))) => inspected.push((index, outcome)),
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
    for (index, outcome) in inspected {
        if let Some(result) = report.results.get_mut(index) {
            let was_reset = result.state == PortState::Closed;
            if was_reset {
                result.detail = None;
            }
            annotate(result, outcome);
            if was_reset {
                result.state = PortState::Open;
                report.counts.remove(PortState::Closed);
                report.counts.add(PortState::Open);
            }
        }
    }

    if matched > 0 && !quiet {
        eprintln!("[tls] captured metadata for {matched} endpoint(s)");
    }
    matched
}

fn annotate(result: &mut PortResult, outcome: TlsOutcome) {
    let TlsOutcome { info, https } = outcome;
    let has_https = https.is_some();
    let default_name = service_name(result.port, info.starttls.as_deref());
    let should_replace = result.service.as_ref().is_none_or(|service| {
        service.name == "tls" || service.name.is_empty() || (has_https && service.name == "http")
    });
    if should_replace {
        result.service = Some(match https.and_then(|detection| detection.service) {
            Some(service) => ServiceInfo {
                name: "https".to_string(),
                product: service.product,
                version: service.version,
                confidence: service.confidence,
            },
            None => ServiceInfo {
                name: default_name.to_string(),
                product: None,
                version: None,
                confidence: None,
            },
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

pub struct TlsOutcome {
    info: TlsInfo,
    https: Option<crate::service::Detection>,
}

pub async fn inspect(
    host: IpAddr,
    port: u16,
    timeout: Duration,
    probe: TlsProbe,
) -> Option<TlsOutcome> {
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
) -> Option<TlsOutcome> {
    let stream = connect(host, port, timeout)?;
    match probe {
        TlsProbe::Direct => {
            let (info, mut connection, mut stream) = handshake(stream, host, timeout, None)?;
            let https = https_identity(&mut connection, &mut stream, host, port, timeout);
            Some(TlsOutcome { info, https })
        }
        TlsProbe::StartTls(protocol) => {
            let stream = negotiate_starttls(stream, protocol, timeout)?;
            handshake(stream, host, timeout, Some(protocol))
                .map(|(info, _, _)| TlsOutcome { info, https: None })
        }
    }
}

/// Fetch an HTTP response over the completed TLS session so HTTPS virtual
/// hosts can be identified with the same fingerprints as plain HTTP.
fn https_identity(
    connection: &mut ClientConnection,
    stream: &mut TcpStream,
    host: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<crate::service::Detection> {
    connection
        .writer()
        .write_all(&crate::service::http_probe(host))
        .ok()?;
    let deadline = std::time::Instant::now() + timeout.min(Duration::from_millis(700));
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        loop {
            match connection.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    data.extend_from_slice(&buffer[..read]);
                    if data.len() >= 1024 {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if data.len() >= 1024 || std::time::Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let _ = stream.set_read_timeout(Some(remaining));
        if connection.complete_io(stream).is_err() {
            break;
        }
    }

    if data.is_empty() {
        return None;
    }
    let detection = crate::service::inspect(port, &data);
    detection
        .service
        .as_ref()
        .is_some_and(|service| service.name == "http")
        .then_some(detection)
}

fn connect(host: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let address = socket_addr(host, port);
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
) -> Option<(TlsInfo, ClientConnection, TcpStream)> {
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
    Some((
        parse_info(host, &version, &cipher, &chain, starttls),
        connection,
        stream,
    ))
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

    fn tls_info() -> TlsInfo {
        TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
            subject: None,
            issuer: None,
            san: Vec::new(),
            serial: None,
            not_before: None,
            not_after: None,
            days_remaining: None,
            expired: false,
            not_yet_valid: false,
            self_signed: true,
            hostname_matches: false,
            chain_len: 1,
            starttls: None,
        }
    }

    #[test]
    fn https_identity_replaces_generic_http_on_tls_ports() {
        let mut result = PortResult::new(
            "127.0.0.1".parse().unwrap(),
            4443,
            PortState::Open,
            Duration::ZERO,
        );
        let detection = crate::service::Detection {
            service: Some(ServiceInfo {
                name: "http".to_string(),
                product: Some("Jenkins".to_string()),
                version: Some("2.426.1".to_string()),
                confidence: Some(0.98),
            }),
            banner: None,
        };

        annotate(
            &mut result,
            TlsOutcome {
                info: tls_info(),
                https: Some(detection),
            },
        );

        let service = result.service.unwrap();
        assert_eq!(service.name, "https");
        assert_eq!(service.product.as_deref(), Some("Jenkins"));
        assert_eq!(service.version.as_deref(), Some("2.426.1"));
        assert_eq!(service.confidence, Some(0.98));
    }

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
    fn auto_mode_inspects_tls_banners_on_non_standard_ports() {
        assert_eq!(
            probe_for_result(8080, Some("tls"), TlsMode::Auto),
            Some(TlsProbe::Direct)
        );
        assert_eq!(probe_for_result(8080, Some("http"), TlsMode::Auto), None);
        assert_eq!(probe_for_result(8080, Some("tls"), TlsMode::Disabled), None);
        assert_eq!(
            probe_for_result(443, Some("http"), TlsMode::Auto),
            Some(TlsProbe::Direct)
        );
        assert_eq!(
            probe_for_result(4443, None, TlsMode::Auto),
            Some(TlsProbe::Direct)
        );
        assert_eq!(probe_for_result(8080, None, TlsMode::Disabled), None);
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
