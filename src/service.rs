use std::net::IpAddr;

use serde::Serialize;

const MAX_BANNER_TEXT: usize = 160;

/// A service identified from the initial response of an open port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl ServiceInfo {
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

/// Service metadata plus a printable, bounded banner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detection {
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
}

/// Build the HTTP probe used when a service does not speak first.
pub fn http_probe(host: IpAddr) -> Vec<u8> {
    let host = match host {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    format!(
        "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rayscan/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

/// Inspect the initial bytes received after a successful TCP handshake.
///
/// Detection is passive: it classifies the peer's response. An unrecognized
/// text banner is still preserved for the caller.
pub fn inspect(port: u16, data: &[u8]) -> Detection {
    if data.is_empty() {
        return Detection::default();
    }

    let text = trim_start(data);

    if let Some(detection) = http(text) {
        return detection;
    }
    if let Some(detection) = ssh(text) {
        return detection;
    }
    if let Some(detection) = mysql(data) {
        return detection;
    }
    if let Some(detection) = redis(data) {
        return detection;
    }
    if let Some(detection) = postgresql(data) {
        return detection;
    }
    if let Some(detection) = smb(data) {
        return detection;
    }
    if let Some(detection) = rdp(data) {
        return detection;
    }
    if let Some(detection) = mongodb(text) {
        return detection;
    }
    if let Some(detection) = tls(data) {
        return detection;
    }
    if let Some(detection) = telnet(data) {
        return detection;
    }
    if let Some(detection) = text_protocol(port, text) {
        return detection;
    }

    Detection {
        service: None,
        banner: first_line_text(text),
    }
}

fn http(data: &[u8]) -> Option<Detection> {
    if !data.starts_with(b"HTTP/") {
        return None;
    }

    let text = String::from_utf8_lossy(data);
    let server = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("server")
            .then_some(value.trim())
    });
    let (product, version) = server.map(parse_product_version).unwrap_or((None, None));

    Some(Detection {
        service: Some(
            ServiceInfo::new("http")
                .with_product(product)
                .with_version(version),
        ),
        banner: first_line_text(data),
    })
}

fn ssh(data: &[u8]) -> Option<Detection> {
    let line = first_line_text(data)?;
    if !line.starts_with("SSH-") {
        return None;
    }

    let software = line.splitn(3, '-').nth(2)?.split_whitespace().next()?;
    let (product, version) = match software.split_once('_') {
        Some((product, version)) => (clean_token(product), clean_token(version)),
        None => (clean_token(software), None),
    };

    Some(Detection {
        service: Some(
            ServiceInfo::new("ssh")
                .with_product(product)
                .with_version(version),
        ),
        banner: Some(line),
    })
}

fn mysql(data: &[u8]) -> Option<Detection> {
    if data.len() < 6 || data[4] != 0x0a {
        return None;
    }

    let packet_len = data[0] as usize | (data[1] as usize) << 8 | (data[2] as usize) << 16;
    if packet_len < 2 {
        return None;
    }

    let end = data[5..].iter().position(|&byte| byte == 0)? + 5;
    if end == 5 {
        return None;
    }

    let version = std::str::from_utf8(&data[5..end]).ok()?;
    if version.len() > 64 || !version.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }

    let product = if version.to_ascii_lowercase().contains("mariadb") {
        "MariaDB"
    } else {
        "MySQL"
    };

    Some(Detection {
        service: Some(
            ServiceInfo::new("mysql")
                .with_product(Some(product.to_string()))
                .with_version(Some(version.to_string())),
        ),
        banner: Some(version.to_string()),
    })
}

fn tls(data: &[u8]) -> Option<Detection> {
    if data.len() < 3 || !matches!(data[0], 0x15 | 0x16) || data[1] != 0x03 {
        return None;
    }
    let banner = if data[0] == 0x15 {
        "TLS alert"
    } else {
        "TLS handshake"
    };
    Some(Detection {
        service: Some(ServiceInfo::new("tls")),
        banner: Some(banner.to_string()),
    })
}

fn telnet(data: &[u8]) -> Option<Detection> {
    (data.first() == Some(&0xff)).then(|| Detection {
        service: Some(ServiceInfo::new("telnet")),
        banner: Some("Telnet negotiation".to_string()),
    })
}

fn redis(data: &[u8]) -> Option<Detection> {
    let line = first_line_text(data)?;
    let upper = line.to_ascii_uppercase();
    let is_redis = upper.starts_with("-ERR ")
        || upper.starts_with("-NOAUTH ")
        || upper.starts_with("-DENIED ")
        || upper.starts_with("+PONG")
        || (line.starts_with('$') && line.contains("redis"))
        || upper.contains("REDIS");
    if !is_redis {
        return None;
    }
    let version = if let Some(idx) = line.find("redis_version:") {
        line[idx + 14..]
            .split_whitespace()
            .next()
            .and_then(clean_token)
    } else {
        None
    };
    Some(Detection {
        service: Some(
            ServiceInfo::new("redis")
                .with_product(Some("Redis".to_string()))
                .with_version(version),
        ),
        banner: Some(line),
    })
}

fn postgresql(data: &[u8]) -> Option<Detection> {
    if data.is_empty() {
        return None;
    }
    // PostgreSQL binary error packet starts with 'E' and contains SFATAL or SERROR
    let is_pg_binary = data[0] == b'E'
        && (data.windows(7).any(|w| w == b"SFATAL\0") || data.windows(7).any(|w| w == b"SERROR\0"));
    let text = String::from_utf8_lossy(data);
    let is_pg_text = text.starts_with("FATAL:")
        && (text.contains("pg_")
            || text.contains("database")
            || text.contains("role")
            || text.contains("PostgreSQL"));
    if is_pg_binary || is_pg_text {
        let banner = first_line_text(data).unwrap_or_else(|| "PostgreSQL response".to_string());
        return Some(Detection {
            service: Some(
                ServiceInfo::new("postgresql").with_product(Some("PostgreSQL".to_string())),
            ),
            banner: Some(banner),
        });
    }
    None
}

fn smb(data: &[u8]) -> Option<Detection> {
    if data.len() < 4 {
        return None;
    }
    let is_smb1 = data.starts_with(b"\xffSMB") || (data.len() >= 8 && &data[4..8] == b"\xffSMB");
    let is_smb2 = data.starts_with(b"\xfeSMB") || (data.len() >= 8 && &data[4..8] == b"\xfeSMB");
    if is_smb1 {
        return Some(Detection {
            service: Some(ServiceInfo::new("smb").with_product(Some("SMBv1".to_string()))),
            banner: Some("SMBv1 (NetBIOS-SSN)".to_string()),
        });
    }
    if is_smb2 {
        return Some(Detection {
            service: Some(ServiceInfo::new("smb").with_product(Some("SMBv2/v3".to_string()))),
            banner: Some("SMBv2/v3 (Microsoft-DS)".to_string()),
        });
    }
    None
}

fn rdp(data: &[u8]) -> Option<Detection> {
    if data.len() >= 6 && data[0] == 0x03 && data[1] == 0x00 && data[5] == 0xd0 {
        return Some(Detection {
            service: Some(ServiceInfo::new("rdp").with_product(Some("Microsoft RDP".to_string()))),
            banner: Some("RDP / TPKT connection confirm".to_string()),
        });
    }
    None
}

fn mongodb(data: &[u8]) -> Option<Detection> {
    let line = first_line_text(data)?;
    let lower = line.to_ascii_lowercase();
    if lower.contains("mongodb") || lower.contains("trying to access mongodb over http") {
        return Some(Detection {
            service: Some(ServiceInfo::new("mongodb").with_product(Some("MongoDB".to_string()))),
            banner: Some(line),
        });
    }
    None
}

fn text_protocol(port: u16, data: &[u8]) -> Option<Detection> {
    let line = first_line_text(data)?;
    let upper = line.to_ascii_uppercase();

    if line.starts_with("+OK") {
        return Some(simple("pop3", line));
    }
    if upper.starts_with("* OK") {
        return Some(simple("imap", line));
    }
    if let Some(rest) = line.strip_prefix("RFB ") {
        let version = rest.to_string();
        return Some(vnc(&version, line));
    }
    if shell_prompt(&line) {
        return Some(simple("shell", line));
    }
    if is_irc(port, &line, &upper) {
        return Some(simple("irc", line));
    }
    if line.contains("DRb::") {
        return Some(simple("ruby-drb", line));
    }
    if line == "Where are you?" {
        return Some(simple("exec", line));
    }
    if upper.starts_with("220") {
        let is_ftp = upper.contains("FTP") || port == 21;
        let is_smtp = !is_ftp && (upper.contains("SMTP") || matches!(port, 25 | 465 | 587));
        if is_ftp {
            let (product, version) = ftp_product(&line);
            return Some(Detection {
                service: Some(
                    ServiceInfo::new("ftp")
                        .with_product(product)
                        .with_version(version),
                ),
                banner: Some(line),
            });
        }
        if is_smtp {
            let (product, version) = smtp_product(&line);
            return Some(Detection {
                service: Some(
                    ServiceInfo::new("smtp")
                        .with_product(product)
                        .with_version(version),
                ),
                banner: Some(line),
            });
        }
    }

    None
}

fn simple(name: &str, line: String) -> Detection {
    Detection {
        service: Some(ServiceInfo::new(name)),
        banner: Some(line),
    }
}

fn shell_prompt(line: &str) -> bool {
    if line.len() > 96 || line.contains(' ') || !line.contains('@') {
        return false;
    }
    line.rsplit_once(':')
        .map(|(_, tail)| {
            let prompt = tail.trim();
            prompt.ends_with('#') || prompt.ends_with('$')
        })
        .unwrap_or(false)
}

fn is_irc(port: u16, line: &str, upper: &str) -> bool {
    let irc_port = matches!(port, 6667 | 6697 | 7000);
    (irc_port && (line.starts_with(':') || upper.starts_with("ERROR :")))
        || upper.contains(" NOTICE AUTH ")
        || (line.starts_with(':') && upper.contains("IRC"))
}

fn ftp_product(line: &str) -> (Option<String>, Option<String>) {
    const PRODUCTS: &[(&str, &str)] = &[
        ("vsftpd", "vsFTPd"),
        ("proftpd", "ProFTPD"),
        ("filezilla", "FileZilla"),
        ("pure-ftpd", "Pure-FTPd"),
        ("serv-u", "Serv-U"),
        ("microsoft ftp", "Microsoft FTP"),
        ("wu-ftpd", "WU-FTPD"),
        ("pyftpdlib", "pyftpdlib"),
    ];
    let lower = line.to_ascii_lowercase();
    for (needle, display) in PRODUCTS {
        if let Some(index) = lower.find(needle) {
            let rest = &line[index + needle.len()..];
            let version = rest.split_whitespace().next().and_then(numeric_version);
            return (Some((*display).to_string()), version);
        }
    }
    (None, None)
}

fn smtp_product(line: &str) -> (Option<String>, Option<String>) {
    const PRODUCTS: &[(&str, &str)] = &[
        ("postfix", "Postfix"),
        ("exim", "Exim"),
        ("sendmail", "Sendmail"),
        ("microsoft", "Microsoft"),
        ("haraka", "Haraka"),
        ("courier", "Courier"),
        ("opensmtpd", "OpenSMTPD"),
    ];
    let lower = line.to_ascii_lowercase();
    for (needle, display) in PRODUCTS {
        if let Some(index) = lower.find(needle) {
            let rest = &line[index + needle.len()..];
            let version = rest.split_whitespace().next().and_then(numeric_version);
            return (Some((*display).to_string()), version);
        }
    }
    (None, None)
}

fn numeric_version(token: &str) -> Option<String> {
    let token = token.trim_matches(|character: char| {
        character == '(' || character == ')' || character == ',' || character == ';'
    });
    if !token.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let token = token.split('/').next().unwrap_or(token);
    clean_token(token)
}

fn vnc(version: &str, banner: String) -> Detection {
    let version = version
        .split_once('.')
        .and_then(|(major, minor)| {
            Some(format!(
                "{}.{}",
                major.parse::<u16>().ok()?,
                minor.parse::<u16>().ok()?
            ))
        })
        .and_then(|version| clean_token(&version));

    Detection {
        service: Some(
            ServiceInfo::new("vnc")
                .with_product(Some("VNC".to_string()))
                .with_version(version),
        ),
        banner: Some(banner),
    }
}

fn parse_product_version(value: &str) -> (Option<String>, Option<String>) {
    let Some(token) = value.split_whitespace().next() else {
        return (None, None);
    };
    let token = token.trim_matches(|character: char| character == ',' || character == ';');

    match token.split_once('/') {
        Some((product, version)) => (clean_token(product), clean_token(version)),
        None => (clean_token(token), None),
    }
}

fn clean_token(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(|character: char| {
        character == ',' || character == ';' || character == '(' || character == ')'
    });
    if value.is_empty()
        || value.len() > 64
        || !value.chars().all(|character| character.is_ascii_graphic())
    {
        return None;
    }
    Some(value.to_string())
}

fn trim_start(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[start..]
}

fn first_line_text(data: &[u8]) -> Option<String> {
    let end = data
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .unwrap_or(data.len());
    let text = String::from_utf8_lossy(&data[..end]);
    let cleaned: String = text
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' || character == '\t' {
                character
            } else {
                ' '
            }
        })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    Some(collapsed.chars().take(MAX_BANNER_TEXT).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service<'a>(detection: &'a Detection, name: &str) -> &'a ServiceInfo {
        let service = detection.service.as_ref().expect("expected a service");
        assert_eq!(service.name, name);
        service
    }

    #[test]
    fn detects_http_and_server_product_version() {
        let detection = inspect(
            80,
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
        );
        let http = service(&detection, "http");
        assert_eq!(http.product.as_deref(), Some("nginx"));
        assert_eq!(http.version.as_deref(), Some("1.24.0"));
        assert_eq!(detection.banner.as_deref(), Some("HTTP/1.1 200 OK"));
    }

    #[test]
    fn detects_http_without_a_server_header() {
        let detection = inspect(
            443,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        );
        let http = service(&detection, "http");
        assert!(http.product.is_none());
        assert!(http.version.is_none());
    }

    #[test]
    fn detects_ssh_product_and_version() {
        let detection = inspect(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
        let ssh = service(&detection, "ssh");
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("9.6p1"));
        assert_eq!(
            detection.banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
        );
    }

    #[test]
    fn detects_mysql_handshake_version() {
        let version = b"8.0.36-rayscan-lab";
        let mut data = Vec::new();
        let packet_len = version.len() + 2;
        data.extend_from_slice(&[
            packet_len as u8,
            (packet_len >> 8) as u8,
            (packet_len >> 16) as u8,
            0,
            0x0a,
        ]);
        data.extend_from_slice(version);
        data.push(0);

        let detection = inspect(3306, &data);
        let mysql = service(&detection, "mysql");
        assert_eq!(mysql.product.as_deref(), Some("MySQL"));
        assert_eq!(mysql.version.as_deref(), Some("8.0.36-rayscan-lab"));
        assert_eq!(detection.banner.as_deref(), Some("8.0.36-rayscan-lab"));
    }

    #[test]
    fn detects_text_protocols_and_uses_port_hints_for_ambiguous_220() {
        let ftp = inspect(21, b"220 (vsFTPd 3.0.5)\r\n");
        service(&ftp, "ftp");

        let smtp = inspect(25, b"220 mail.example ESMTP Postfix\r\n");
        service(&smtp, "smtp");

        let hinted_ftp = inspect(21, b"220 service ready\r\n");
        service(&hinted_ftp, "ftp");

        let hinted_smtp = inspect(587, b"220 service ready\r\n");
        service(&hinted_smtp, "smtp");

        let pop3 = inspect(110, b"+OK POP3 ready\r\n");
        service(&pop3, "pop3");

        let imap = inspect(143, b"* OK IMAP4rev1 ready\r\n");
        service(&imap, "imap");
    }

    #[test]
    fn detects_live_metasploitable_banners() {
        let ftp = inspect(21, b"220 (vsFTPd 2.3.4)\r\n");
        let ftp_service = service(&ftp, "ftp");
        assert_eq!(ftp_service.product.as_deref(), Some("vsFTPd"));
        assert_eq!(ftp_service.version.as_deref(), Some("2.3.4"));

        let smtp = inspect(
            25,
            b"220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n",
        );
        let smtp_service = service(&smtp, "smtp");
        assert_eq!(smtp_service.product.as_deref(), Some("Postfix"));
        assert!(smtp_service.version.is_none());

        service(
            &inspect(
                6667,
                b":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...\r\n",
            ),
            "irc",
        );
        service(
            &inspect(
                6697,
                b"ERROR :Closing Link: [192.168.100.8] (Throttled: Reconnecting too fast)\r\n",
            ),
            "irc",
        );

        service(&inspect(1524, b"root@metasploitable:/#\r\n"), "shell");
        service(
            &inspect(8787, b"F o: DRb::DRbConnError : bt[ \"/usr/lib/ruby\"\r\n"),
            "ruby-drb",
        );
        service(&inspect(512, b"Where are you?\r\n"), "exec");
    }

    #[test]
    fn detects_tls_handshakes_and_alerts() {
        service(&inspect(443, b"\x16\x03\x03\x00\x01"), "tls");

        let alert = inspect(443, b"\x15\x03\x03\x00\x02\x02\x28");
        service(&alert, "tls");
        assert_eq!(alert.banner.as_deref(), Some("TLS alert"));
    }

    #[test]
    fn detects_telnet_and_vnc() {
        service(&inspect(23, b"\xff\xfb\x01"), "telnet");

        let vnc = inspect(5900, b"RFB 003.008\n");
        let vnc_service = service(&vnc, "vnc");
        assert_eq!(vnc_service.version.as_deref(), Some("3.8"));
    }

    #[test]
    fn builds_an_http_probe_with_a_valid_host_header() {
        let request = http_probe("10.77.0.2".parse().unwrap());
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("HEAD / HTTP/1.0\r\n"));
        assert!(text.contains("\r\nHost: 10.77.0.2\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn preserves_an_unknown_text_banner_without_guessing_a_service() {
        let detection = inspect(12345, b"hello from a custom service\r\n");
        assert!(detection.service.is_none());
        assert_eq!(
            detection.banner.as_deref(),
            Some("hello from a custom service")
        );
    }

    #[test]
    fn rejects_binary_garbage_and_bounds_text() {
        let binary = inspect(12345, b"\x00\x01\x02\x03");
        assert!(binary.service.is_none());
        assert!(binary.banner.is_none());

        let long = format!("{}\r\n", "A".repeat(400));
        let detection = inspect(12345, long.as_bytes());
        assert!(detection.service.is_none());
        assert_eq!(
            detection.banner.as_deref().unwrap().chars().count(),
            MAX_BANNER_TEXT
        );
    }

    #[test]
    fn sanitizes_control_characters_in_banners() {
        let detection = inspect(12345, b"hello\x00world\r\n");
        assert_eq!(detection.banner.as_deref(), Some("hello world"));
    }

    #[test]
    fn parses_common_server_tokens() {
        assert_eq!(
            parse_product_version("Apache/2.4.58 (Ubuntu)"),
            (Some("Apache".to_string()), Some("2.4.58".to_string()))
        );
        assert_eq!(
            parse_product_version("rayscan-lab"),
            (Some("rayscan-lab".to_string()), None)
        );
        assert_eq!(parse_product_version(""), (None, None));
    }

    #[test]
    fn detects_redis_banner() {
        let det = inspect(6379, b"-ERR unknown command 'HEAD'\r\n");
        let svc = service(&det, "redis");
        assert_eq!(svc.product.as_deref(), Some("Redis"));
        assert_eq!(det.banner.as_deref(), Some("-ERR unknown command 'HEAD'"));

        let det2 = inspect(6379, b"-NOAUTH Authentication required.\r\n");
        service(&det2, "redis");

        let det3 = inspect(6379, b"+PONG\r\n");
        service(&det3, "redis");
    }

    #[test]
    fn detects_postgresql_response() {
        let text_det = inspect(
            5432,
            b"FATAL:  no pg_hba.conf entry for host \"10.0.0.1\"\n",
        );
        let svc = service(&text_det, "postgresql");
        assert_eq!(svc.product.as_deref(), Some("PostgreSQL"));

        let binary_payload = b"E\x00\x00\x00\x40SFATAL\0C28000\0Mno pg_hba.conf\0";
        let bin_det = inspect(5432, binary_payload);
        service(&bin_det, "postgresql");
    }

    #[test]
    fn detects_smb_signatures() {
        let smb1 = inspect(445, b"\xffSMB\x72\x00\x00\x00\x00");
        let svc1 = service(&smb1, "smb");
        assert_eq!(svc1.product.as_deref(), Some("SMBv1"));

        let smb2 = inspect(445, b"\xfeSMB\x40\x00\x00\x00\x00");
        let svc2 = service(&smb2, "smb");
        assert_eq!(svc2.product.as_deref(), Some("SMBv2/v3"));
    }

    #[test]
    fn detects_rdp_tpkt_confirm() {
        let rdp_data = &[
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
        ];
        let det = inspect(3389, rdp_data);
        let svc = service(&det, "rdp");
        assert_eq!(svc.product.as_deref(), Some("Microsoft RDP"));
    }

    #[test]
    fn detects_mongodb_http_notice() {
        let data = b"It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n";
        let det = inspect(27017, data);
        let svc = service(&det, "mongodb");
        assert_eq!(svc.product.as_deref(), Some("MongoDB"));
    }
}
