use std::net::IpAddr;

use serde::Serialize;

const MAX_BANNER_TEXT: usize = 160;

/// A service identified from the initial response of an open port.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Confidence in the product/version identification (0.0–1.0):
    /// name-only ≈ 0.70, product-only ≈ 0.85, versioned ≈ 0.98.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}

impl ServiceInfo {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            product: None,
            version: None,
            confidence: Some(0.70),
        }
    }

    fn with_product(mut self, product: Option<String>) -> Self {
        if product.is_some() {
            self.confidence = Some(0.85);
        }
        self.product = product;
        self
    }

    fn with_version(mut self, version: Option<String>) -> Self {
        if version.is_some() {
            self.confidence = Some(0.98);
        }
        self.version = version;
        self
    }
}

/// Service metadata plus a printable, bounded banner.
#[derive(Clone, Debug, Default, PartialEq)]
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
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rayscan/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
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
    if let Some(detection) = mongodb(data) {
        return detection;
    }
    if let Some(detection) = memcached(port, data) {
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
    let lower = text.to_ascii_lowercase();
    let (product, version) = http_identity(&text, &lower);

    Some(Detection {
        service: Some(
            ServiceInfo::new("http")
                .with_product(product)
                .with_version(version),
        ),
        banner: first_line_text(data),
    })
}

/// Identify the application behind an HTTP response, preferring explicit
/// product headers and login-page fingerprints over the generic `Server` token.
fn http_identity(text: &str, lower: &str) -> (Option<String>, Option<String>) {
    if let Some(value) = header_value(text, "x-jenkins") {
        return (Some("Jenkins".to_string()), numeric_version(value));
    }
    if let Some(name) = header_value(text, "kbn-name") {
        let product = if name.eq_ignore_ascii_case("kibana") {
            "Kibana".to_string()
        } else {
            clean_token(name).unwrap_or_else(|| "Kibana".to_string())
        };
        return (
            Some(product),
            header_value(text, "kbn-version").and_then(numeric_version),
        );
    }
    if header_value(text, "x-elastic-product")
        .is_some_and(|value| value.eq_ignore_ascii_case("elasticsearch"))
    {
        return (
            "Elasticsearch".to_string().into(),
            json_version(text, "number"),
        );
    }
    if let Some(value) = header_value(text, "docker-distribution-api-version") {
        return ("Docker Registry".to_string().into(), numeric_version(value));
    }
    if lower.contains("you know, for search") && lower.contains("\"version\"") {
        return (
            "Elasticsearch".to_string().into(),
            json_version(text, "number"),
        );
    }
    if lower.contains("the opensearch project") && lower.contains("\"version\"") {
        return (
            "OpenSearch".to_string().into(),
            json_version(text, "number"),
        );
    }

    if let Some(product) = panel_fingerprint(lower) {
        let version = match product {
            "Apache Tomcat" => version_after(text, "apache tomcat/"),
            "Jira" | "Confluence" => meta_content(text, "ajs-version-number"),
            "phpMyAdmin" => meta_content(text, "generator").and_then(|value| {
                let lower = value.to_ascii_lowercase();
                lower.strip_prefix("phpmyadmin").and_then(|_| {
                    numeric_version(value.get("phpMyAdmin".len()..).unwrap_or_default())
                })
            }),
            _ => None,
        };
        return (Some(product.to_string()), version);
    }

    if let Some(server) = header_value(text, "server") {
        let (product, version) = parse_product_version(server);
        if product.is_some() {
            return (product, version);
        }
    }
    if let Some(powered) = header_value(text, "x-powered-by") {
        let (product, version) = parse_product_version(powered);
        if product.is_some() {
            return (product, version);
        }
    }
    (None, None)
}

fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
}

/// Detect common Bug Bounty web surfaces by their login/dashboard titles.
fn panel_fingerprint(lower: &str) -> Option<&'static str> {
    const PANELS: &[(&str, &str)] = &[
        ("<title>grafana", "Grafana"),
        ("<title>kibana", "Kibana"),
        ("<title>adminer", "Adminer"),
        ("<title>login to webmin", "Webmin"),
        ("<title>zabbix", "Zabbix"),
        ("<title>prometheus", "Prometheus"),
        ("<title>portainer", "Portainer"),
        ("<title>sonarqube", "SonarQube"),
        ("<title>kubernetes dashboard", "Kubernetes Dashboard"),
        ("<title>argo cd", "Argo CD"),
        ("<title>rabbitmq management", "RabbitMQ Management"),
        (
            "<title>nexus repository manager",
            "Nexus Repository Manager",
        ),
        ("<title>gitlab", "GitLab"),
        ("<title>minio console", "MinIO"),
        ("<title>rancher", "Rancher"),
        ("<title>proxmox", "Proxmox VE"),
        ("<title>pfsense", "pfSense"),
        ("<title>openwrt - luci", "OpenWrt LuCI"),
        ("<title>oracle weblogic", "Oracle WebLogic"),
        ("<title>websphere", "IBM WebSphere"),
        ("<title>jira", "Jira"),
        ("<title>confluence", "Confluence"),
        ("<title>apache tomcat/", "Apache Tomcat"),
    ];
    if lower.contains("phpmyadmin")
        && (lower.contains("<title>") || lower.contains("name=\"generator\""))
    {
        return Some("phpMyAdmin");
    }
    PANELS
        .iter()
        .find_map(|(needle, product)| lower.contains(needle).then_some(*product))
}

fn version_after(text: &str, needle: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let index = lower.find(needle)?;
    let rest = &text[index + needle.len()..];
    rest.split(|character: char| {
        character.is_whitespace() || matches!(character, '<' | '"' | '\'' | ')' | '(' | ';' | ',')
    })
    .next()
    .and_then(numeric_version)
}

fn meta_content(text: &str, name: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let needle = format!("name=\"{name}\"");
    let index = lower.find(&needle)?;
    let rest = &text[index + needle.len()..];
    let rest_lower = &lower[index + needle.len()..];
    let content_start = rest_lower.find("content=\"")? + "content=\"".len();
    let value = &rest[content_start..];
    let end = value.find('"')?;
    let value = value[..end].trim();
    if value.is_empty() || value.len() > 96 {
        return None;
    }
    Some(value.to_string())
}

fn json_version(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut offset = 0;
    while let Some(index) = text[offset..].find(&needle) {
        let position = offset + index + needle.len();
        let rest = text[position..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('"')
                && let Some(end) = rest.find('"')
            {
                return clean_token(&rest[..end]);
            }
        }
        offset = position;
    }
    None
}

fn ssh(data: &[u8]) -> Option<Detection> {
    let line = first_line_text(data)?;
    if !line.starts_with("SSH-") {
        return None;
    }

    let software = line.splitn(3, '-').nth(2)?.split_whitespace().next()?;
    let (product, version) = match software.split_once('_') {
        Some((product, version)) => (ssh_product(product), clean_token(version)),
        None => match software.split_once('-') {
            Some((product, version)) => (ssh_product(product), numeric_version(version)),
            None => (ssh_product(software), None),
        },
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

fn ssh_product(product: &str) -> Option<String> {
    const PRODUCTS: &[(&str, &str)] = &[
        ("openssh", "OpenSSH"),
        ("win32-openssh", "Win32-OpenSSH"),
        ("dropbear", "Dropbear"),
        ("libssh", "libssh"),
        ("cisco", "Cisco"),
        ("paramiko", "Paramiko"),
        ("asyncssh", "AsyncSSH"),
        ("putty", "PuTTY"),
        ("solaris", "SunSSH"),
        ("weonlydo", "WeOnlyDo"),
        ("rosssh", "ROSSSH"),
    ];
    let lower = product.to_ascii_lowercase();
    if let Some((_, display)) = PRODUCTS.iter().find(|(needle, _)| lower.contains(needle)) {
        return Some((*display).to_string());
    }
    clean_token(product)
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
    let text = String::from_utf8_lossy(data);
    let upper = line.to_ascii_uppercase();
    let version = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("redis_version:"))
        .map(str::trim)
        .and_then(clean_token);
    let is_redis = version.is_some()
        || upper.starts_with("-ERR ")
        || upper.starts_with("-NOAUTH ")
        || upper.starts_with("-DENIED ")
        || upper.contains("-WRONGPASS ")
        || upper.starts_with("+PONG")
        || (line.starts_with('$') && line.contains("redis"))
        || upper.contains("REDIS");
    if !is_redis {
        return None;
    }
    let banner = version
        .as_ref()
        .map(|version| format!("redis_version:{version}"))
        .unwrap_or(line);
    Some(Detection {
        service: Some(
            ServiceInfo::new("redis")
                .with_product(Some("Redis".to_string()))
                .with_version(version),
        ),
        banner: Some(banner),
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
        let (product, banner) = match smb2_dialect(data) {
            Some(dialect) => (
                format!("SMB {dialect}"),
                format!("SMB {dialect} (Microsoft-DS)"),
            ),
            None => (
                "SMBv2/v3".to_string(),
                "SMBv2/v3 (Microsoft-DS)".to_string(),
            ),
        };
        return Some(Detection {
            service: Some(ServiceInfo::new("smb").with_product(Some(product))),
            banner: Some(banner),
        });
    }
    None
}

/// Read the negotiated dialect revision from an SMB2 NEGOTIATE response.
fn smb2_dialect(data: &[u8]) -> Option<&'static str> {
    let start = data
        .windows(4)
        .position(|window| window == b"\xfeSMB")
        .unwrap_or(0);
    let dialect = data.get(start + 68..start + 70)?;
    let revision = u16::from_le_bytes([dialect[0], dialect[1]]);
    match revision {
        0x0202 => Some("2.0.2"),
        0x0210 => Some("2.1"),
        0x0300 => Some("3.0"),
        0x0302 => Some("3.0.2"),
        0x0311 => Some("3.1.1"),
        0x02ff => Some("2.0"),
        _ => None,
    }
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
    // Legacy `isMaster` replies and modern `buildInfo` replies both expose
    // stable BSON field names in the raw bytes.
    let is_ismaster = data.len() >= 8
        && data
            .windows(8)
            .any(|window| window.eq_ignore_ascii_case(b"ismaster"));
    let is_buildinfo = contains(data, b"gitVersion") || contains(data, b"versionArray");
    let requires_auth = contains(data, b"requires authentication")
        && (contains(data, b"buildInfo") || contains(data, b"ismaster"));
    if !is_ismaster && !is_buildinfo && !requires_auth {
        let line = first_line_text(data)?;
        let lower = line.to_ascii_lowercase();
        if lower.contains("mongodb") || lower.contains("trying to access mongodb over http") {
            return Some(Detection {
                service: Some(
                    ServiceInfo::new("mongodb").with_product(Some("MongoDB".to_string())),
                ),
                banner: Some(line),
            });
        }
        return None;
    }

    let version = bson_string(data, b"version");
    let banner = if version.is_some() {
        "MongoDB buildInfo response".to_string()
    } else if is_ismaster {
        "MongoDB isMaster response".to_string()
    } else {
        "MongoDB command response".to_string()
    };
    Some(Detection {
        service: Some(
            ServiceInfo::new("mongodb")
                .with_product(Some("MongoDB".to_string()))
                .with_version(version),
        ),
        banner: Some(banner),
    })
}

fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

/// Extract a BSON string element (`type 0x02`, cstring key, int32 length, bytes).
fn bson_string(data: &[u8], key: &[u8]) -> Option<String> {
    let mut needle = Vec::with_capacity(key.len() + 2);
    needle.push(0x02);
    needle.extend_from_slice(key);
    needle.push(0);
    let position = data
        .windows(needle.len())
        .position(|window| window == needle)?;
    let start = position + needle.len();
    let length = data.get(start..start + 4)?;
    let length = u32::from_le_bytes([length[0], length[1], length[2], length[3]]) as usize;
    if !(2..=128).contains(&length) {
        return None;
    }
    let raw = data.get(start + 4..start + 4 + length - 1)?;
    clean_token(std::str::from_utf8(raw).ok()?)
}

fn memcached(port: u16, data: &[u8]) -> Option<Detection> {
    let text = std::str::from_utf8(data).ok()?;
    let stats = text.starts_with("STAT ");
    let generic = port == 11211
        && (text.starts_with("END\r\n")
            || text.starts_with("ERROR\r\n")
            || text.starts_with("CLIENT_ERROR "));
    if !stats && !generic {
        return None;
    }
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("STAT version ").map(str::trim))
        .map(str::to_string);
    Some(Detection {
        service: Some(
            ServiceInfo::new("memcached")
                .with_product(Some("memcached".to_string()))
                .with_version(version),
        ),
        banner: first_line_text(data),
    })
}

/// Protocol-native probes for services that never speak first.
///
/// The HTTP probe already covers HTTP servers and makes Redis/MySQL/PostgreSQL
/// produce an error banner. These probes add coverage for SMB, MongoDB, Redis,
/// and memcached when the peer waits for a protocol-specific request. Port 445
/// tries SMB2 first (modern servers reject SMB1) and falls back to SMB1.
pub fn active_probes(port: u16) -> Vec<Vec<u8>> {
    match port {
        445 => vec![smb2_negotiate_probe(), smb1_negotiate_probe()],
        27017 => vec![MONGO_BUILDINFO.to_vec()],
        6379 => vec![b"INFO server\r\n".to_vec()],
        11211 => vec![b"stats\r\n".to_vec()],
        _ => Vec::new(),
    }
}

fn nbss_wrap(smb: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + smb.len());
    packet.push(0x00); // NetBIOS session message
    let length = (smb.len() as u32).to_be_bytes();
    packet.extend_from_slice(&length[1..]); // 24-bit session length
    packet.extend_from_slice(smb);
    packet
}

/// SMB2 NEGOTIATE request advertising dialects 2.0.2 through 3.0.2.
///
/// SMB 3.1.1 requires negotiate contexts (preauth integrity), so it is not
/// advertised here; servers answer with their highest supported dialect.
fn smb2_negotiate_probe() -> Vec<u8> {
    const DIALECTS: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let body_len = 36 + DIALECTS.len() * 2;
    let mut smb = Vec::with_capacity(64 + body_len);
    smb.extend_from_slice(b"\xfeSMB");
    smb.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    smb.extend_from_slice(&0u32.to_le_bytes()); // Status
    smb.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    smb.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    smb.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    smb.extend_from_slice(&0xfeffu32.to_le_bytes()); // ProcessId (reserved)
    smb.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    smb.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    smb.extend_from_slice(&[0u8; 16]); // Signature
    smb.extend_from_slice(&36u16.to_le_bytes()); // StructureSize (fixed base)
    smb.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    smb.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    smb.extend_from_slice(&[0u8; 16]); // ClientGuid
    smb.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    smb.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for dialect in DIALECTS {
        smb.extend_from_slice(&dialect.to_le_bytes());
    }
    nbss_wrap(&smb)
}

/// Minimal SMB1 negotiate request wrapped in a NetBIOS session header.
fn smb1_negotiate_probe() -> Vec<u8> {
    let dialects: &[u8] = b"\x02NT LM 0.12\x00";
    let mut smb = Vec::with_capacity(32 + 3 + dialects.len());
    smb.extend_from_slice(b"\xffSMB");
    smb.push(0x72); // SMB_COM_NEGOTIATE
    smb.extend_from_slice(&[0, 0, 0, 0]); // status
    smb.push(0x18); // flags
    smb.extend_from_slice(&[0x53, 0xc8]); // flags2
    smb.extend_from_slice(&[0, 0]); // PID high
    smb.extend_from_slice(&[0; 8]); // signature
    smb.extend_from_slice(&[0, 0]); // reserved
    smb.extend_from_slice(&[0, 0]); // TID
    smb.extend_from_slice(&[0, 0]); // PID
    smb.extend_from_slice(&[0, 0]); // UID
    smb.extend_from_slice(&[0, 0]); // MID
    smb.push(0); // word count
    smb.extend_from_slice(&(dialects.len() as u16).to_be_bytes());
    smb.extend_from_slice(dialects);
    nbss_wrap(&smb)
}

/// Legacy OP_QUERY `buildInfo` command (63 bytes) for MongoDB.
///
/// Header (16) + flags (4) + `admin.$cmd\0` (11) + skip (4) + return (4) +
/// BSON `{ buildInfo: 1.0 }` (24) = 63 bytes. `buildInfo` is preferred over
/// `isMaster` because its reply carries the server version.
const MONGO_BUILDINFO: &[u8] = b"\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x18\x00\x00\x00\x01buildInfo\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00";

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
    let token = token.trim();
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

    // `product/version`, `product(version)`, or just `product`.
    let (product, version) = if let Some((product, rest)) = token.split_once('/') {
        (product, Some(rest))
    } else if let Some((product, rest)) = token.split_once('(') {
        (product, Some(rest.trim_end_matches(')')))
    } else {
        (token, None)
    };
    let version = version
        .and_then(|value| value.split(['/', '(', ';', ',']).next())
        .and_then(numeric_version);
    (clean_token(product), version)
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
        assert!(text.starts_with("GET / HTTP/1.0\r\n"));
        assert!(text.contains("\r\nHost: 10.77.0.2\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn discovers_admin_panels_and_application_frameworks_over_http() {
        let jenkins = inspect(
            8080,
            b"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.53)\r\nX-Jenkins: 2.426.1\r\n\r\n",
        );
        let jenkins = service(&jenkins, "http");
        assert_eq!(jenkins.product.as_deref(), Some("Jenkins"));
        assert_eq!(jenkins.version.as_deref(), Some("2.426.1"));

        let kibana = inspect(
            5601,
            b"HTTP/1.1 200 OK\r\nkbn-name: kibana\r\nkbn-version: 8.13.4\r\n\r\n",
        );
        let kibana = service(&kibana, "http");
        assert_eq!(kibana.product.as_deref(), Some("Kibana"));
        assert_eq!(kibana.version.as_deref(), Some("8.13.4"));

        let elastic = inspect(
            9200,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
              {\"name\":\"node\",\"cluster_name\":\"lab\",\"version\":{\"number\":\"8.13.4\"},\
              \"tagline\":\"You Know, for Search\"}",
        );
        let elastic = service(&elastic, "http");
        assert_eq!(elastic.product.as_deref(), Some("Elasticsearch"));
        assert_eq!(elastic.version.as_deref(), Some("8.13.4"));

        let tomcat = inspect(
            8080,
            b"HTTP/1.1 200 OK\r\n\r\n<title>Apache Tomcat/9.0.85</title>",
        );
        let tomcat = service(&tomcat, "http");
        assert_eq!(tomcat.product.as_deref(), Some("Apache Tomcat"));
        assert_eq!(tomcat.version.as_deref(), Some("9.0.85"));

        let pma = inspect(
            80,
            b"HTTP/1.1 200 OK\r\n\r\n<meta name=\"generator\" content=\"phpMyAdmin 5.2.1deb3\">",
        );
        let pma = service(&pma, "http");
        assert_eq!(pma.product.as_deref(), Some("phpMyAdmin"));
        assert_eq!(pma.version.as_deref(), Some("5.2.1deb3"));

        let grafana = inspect(
            3000,
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Grafana</title>",
        );
        let grafana = service(&grafana, "http");
        assert_eq!(grafana.product.as_deref(), Some("Grafana"));
        assert!(grafana.version.is_none());

        let php = inspect(8080, b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.10\r\n\r\n");
        let php = service(&php, "http");
        assert_eq!(php.product.as_deref(), Some("PHP"));
        assert_eq!(php.version.as_deref(), Some("8.2.10"));
    }

    #[test]
    fn reports_identification_confidence_for_versions_and_products() {
        let versioned = inspect(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
        let versioned = service(&versioned, "ssh");
        assert_eq!(versioned.confidence, Some(0.98));

        let smtp = inspect(25, b"220 mail.example ESMTP Postfix\r\n");
        let smtp = service(&smtp, "smtp");
        assert_eq!(smtp.product.as_deref(), Some("Postfix"));
        assert_eq!(smtp.confidence, Some(0.85));

        let bare = inspect(110, b"+OK POP3 ready\r\n");
        let bare = service(&bare, "pop3");
        assert_eq!(bare.confidence, Some(0.70));
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

        let info = b"$87\r\n# Server\r\nredis_version:7.2.4\r\nredis_git_sha1:00000000\r\n";
        let det4 = inspect(6379, info);
        let svc4 = service(&det4, "redis");
        assert_eq!(svc4.version.as_deref(), Some("7.2.4"));
        assert_eq!(det4.banner.as_deref(), Some("redis_version:7.2.4"));
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

        let mut negotiate = vec![0u8; 74];
        negotiate[4..8].copy_from_slice(b"\xfeSMB");
        negotiate[72..74].copy_from_slice(&0x0311u16.to_le_bytes());
        let negotiated = inspect(445, &negotiate);
        let negotiated = service(&negotiated, "smb");
        assert_eq!(negotiated.product.as_deref(), Some("SMB 3.1.1"));
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

    #[test]
    fn detects_mongodb_ismaster_bson_reply() {
        let mut reply = Vec::from(&b"\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..]);
        reply.extend_from_slice(b"\x13\x00\x00\x00\x08ismaster\x00\x01\x00\x00\x00\x00");
        let det = inspect(27017, &reply);
        let svc = service(&det, "mongodb");
        assert_eq!(svc.product.as_deref(), Some("MongoDB"));
        assert_eq!(det.banner.as_deref(), Some("MongoDB isMaster response"));
    }

    #[test]
    fn detects_mongodb_buildinfo_reply_with_version() {
        let mut reply = vec![0u8; 16];
        reply.extend_from_slice(b"\x02gitVersion\x00\x06\x00\x00\x00abc123\x00");
        reply.extend_from_slice(b"\x02version\x00\x06\x00\x00\x00");
        reply.extend_from_slice(b"6.0.4\x00");
        let det = inspect(27017, &reply);
        let svc = service(&det, "mongodb");
        assert_eq!(svc.product.as_deref(), Some("MongoDB"));
        assert_eq!(svc.version.as_deref(), Some("6.0.4"));
        assert_eq!(det.banner.as_deref(), Some("MongoDB buildInfo response"));
    }

    #[test]
    fn detects_memcached_stats_response() {
        let data = b"STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT pointer_size 64\r\nEND\r\n";
        let det = inspect(11211, data);
        let svc = service(&det, "memcached");
        assert_eq!(svc.product.as_deref(), Some("memcached"));
        assert_eq!(svc.version.as_deref(), Some("1.6.21"));
    }

    #[test]
    fn active_probes_are_protocol_shaped() {
        let smb_probes = active_probes(445);
        assert_eq!(smb_probes.len(), 2, "SMB2 with SMB1 fallback");

        let smb2 = &smb_probes[0];
        assert_eq!(smb2[0], 0x00, "NetBIOS session header");
        assert_eq!(&smb2[4..8], b"\xfeSMB");
        assert_eq!(
            u32::from_be_bytes([0, smb2[1], smb2[2], smb2[3]]) as usize,
            smb2.len() - 4,
            "NetBIOS length must cover the SMB payload"
        );
        assert_eq!(&smb2[16..18], &0u16.to_le_bytes(), "NEGOTIATE command");

        let smb1 = &smb_probes[1];
        assert_eq!(&smb1[4..8], b"\xffSMB");

        let mongo = &active_probes(27017)[0];
        assert_eq!(mongo.len(), 63);
        assert_eq!(&mongo[12..16], b"\xd4\x07\x00\x00", "OP_QUERY opcode");
        assert_eq!(
            u32::from_le_bytes([mongo[0], mongo[1], mongo[2], mongo[3]]) as usize,
            mongo.len()
        );
        assert!(mongo.ends_with(b"buildInfo\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"));

        assert_eq!(active_probes(6379)[0].as_slice(), &b"INFO server\r\n"[..]);
        assert_eq!(active_probes(11211)[0].as_slice(), &b"stats\r\n"[..]);
        assert!(active_probes(80).is_empty());
    }
}
