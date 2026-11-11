//! Declarative probe packs.
//!
//! Plugins are TOML files that describe an optional request and a matcher.
//! They never execute code, and are applied after the main scan to open TCP
//! results.  A pack looks like:
//!
//! ```toml
//! name = "acme"
//! description = "Acme appliance probes"
//!
//! [[probe]]
//! name = "acme-admin"
//! service = "acme-admin"
//! ports = [8000, 8080]
//! send = "GET /admin HTTP/1.0\r\nHost: scan\r\n\r\n"
//! expect = "Acme Management"
//! product = "Acme Appliance"
//! version_regex = "Version: ([0-9.]+)"
//! ```
//!
//! Use `send_hex` instead of `send` for binary payloads.  Without either, the
//! probe only inspects the banner already collected by the scanner.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::discovery::socket_addr;
use crate::error::AppError;
use crate::model::{PortResult, PortState};
use crate::service::ServiceInfo;

const MAX_PACK_BYTES: u64 = 256 * 1024;
const MAX_PACKS: usize = 64;
const MAX_PROBES: usize = 256;
const MAX_PAYLOAD: usize = 4096;
const MAX_REGEX_CHARS: usize = 512;
const MAX_RESPONSE: usize = 8192;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default, rename = "probe")]
    probes: Vec<RawProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbe {
    name: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    send: Option<String>,
    #[serde(default)]
    send_hex: Option<String>,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    expect_regex: Option<String>,
    #[serde(default)]
    version_regex: Option<String>,
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug)]
struct CompiledProbe {
    pack: String,
    name: String,
    service: String,
    ports: Vec<u16>,
    product: Option<String>,
    version: Option<String>,
    payload: Option<Vec<u8>>,
    expect: Option<String>,
    expect_regex: Option<Regex>,
    version_regex: Option<Regex>,
    ignore_case: bool,
    timeout: Option<Duration>,
}

/// Loaded and validated probe packs.
#[derive(Debug, Default)]
pub struct Registry {
    probes: Vec<CompiledProbe>,
    packs: usize,
}

impl Registry {
    /// Load a TOML file or every `*.toml` file in a directory.
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            AppError::usage(format!(
                "cannot read plugins path {}: {error}",
                path.display()
            ))
        })?;

        let mut files = Vec::new();
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|error| {
                AppError::usage(format!(
                    "cannot read plugins directory {}: {error}",
                    path.display()
                ))
            })? {
                let entry = entry.map_err(|error| {
                    AppError::usage(format!(
                        "cannot read plugins directory {}: {error}",
                        path.display()
                    ))
                })?;
                let file_path = entry.path();
                if file_path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
                {
                    files.push(file_path);
                }
            }
            files.sort();
            if files.is_empty() {
                return Err(AppError::usage(format!(
                    "no .toml probe packs found in {}",
                    path.display()
                )));
            }
        } else {
            files.push(path.to_path_buf());
        }

        if files.len() > MAX_PACKS {
            return Err(AppError::usage(format!(
                "too many probe packs (maximum {MAX_PACKS})"
            )));
        }

        let mut registry = Self::default();
        for file in files {
            registry.load_file(&file)?;
        }
        Ok(registry)
    }

    fn load_file(&mut self, path: &Path) -> Result<(), AppError> {
        let size = std::fs::metadata(path)
            .map_err(|error| AppError::usage(format!("cannot stat {}: {error}", path.display())))?
            .len();
        if size > MAX_PACK_BYTES {
            return Err(AppError::usage(format!(
                "{} exceeds the {MAX_PACK_BYTES}-byte probe pack limit",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| AppError::usage(format!("cannot read {}: {error}", path.display())))?;
        self.parse(&text)
            .map_err(|error| AppError::usage(format!("{}: {error}", path.display())))
    }

    fn parse(&mut self, text: &str) -> Result<(), AppError> {
        let pack: Pack = toml::from_str(text)
            .map_err(|error| AppError::usage(format!("invalid probe pack: {error}")))?;
        validate_name("pack", &pack.name)?;
        if pack.probes.is_empty() {
            return Err(AppError::usage(format!(
                "probe pack '{}' contains no [[probe]] entries",
                pack.name
            )));
        }
        if self.probes.len() + pack.probes.len() > MAX_PROBES {
            return Err(AppError::usage(format!(
                "too many probe entries (maximum {MAX_PROBES})"
            )));
        }

        for raw in pack.probes {
            let probe = compile_probe(&pack.name, raw)?;
            self.probes.push(probe);
        }
        self.packs += 1;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub fn pack_count(&self) -> usize {
        self.packs
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Run matching probes against every open TCP result.
    ///
    /// Returns the number of results whose service was identified or refined.
    pub async fn apply(
        &self,
        results: &mut [PortResult],
        default_timeout: Duration,
        quiet: bool,
    ) -> usize {
        if self.is_empty() {
            return 0;
        }

        let mut matched = 0;
        for result in results.iter_mut() {
            if result.state != PortState::Open {
                continue;
            }
            if result
                .service
                .as_ref()
                .is_some_and(|service| service.name.starts_with("udp:"))
            {
                continue;
            }

            for probe in &self.probes {
                if !probe.ports.is_empty() && !probe.ports.contains(&result.port) {
                    continue;
                }
                let text = probe
                    .response_text(
                        result.host,
                        result.port,
                        result.banner.as_deref(),
                        default_timeout,
                    )
                    .await;
                let Some(text) = text else {
                    continue;
                };
                let Some(version) = probe.evaluate(&text) else {
                    continue;
                };

                let banner = first_line(&text);
                result.service = Some(ServiceInfo {
                    name: probe.service.clone(),
                    product: probe.product.clone(),
                    version: version.or_else(|| probe.version.clone()),
                    confidence: None,
                });
                if !banner.is_empty() {
                    result.banner = Some(banner);
                }
                let tag = format!("plugin:{}/{}", probe.pack, probe.name);
                result.detail = Some(match result.detail.take() {
                    Some(detail) if !detail.is_empty() => format!("{detail},{tag}"),
                    _ => tag.clone(),
                });
                result.evidence = Some(match result.evidence.take() {
                    Some(evidence) if !evidence.is_empty() => {
                        format!("{evidence} | plugin match {tag}")
                    }
                    _ => format!("plugin match {tag}"),
                });
                matched += 1;
                break;
            }
        }

        if matched > 0 && !quiet {
            eprintln!(
                "[plugins] {} result(s) matched from {} probe(s) in {} pack(s)",
                matched,
                self.probe_count(),
                self.pack_count()
            );
        }
        matched
    }
}

impl CompiledProbe {
    async fn response_text(
        &self,
        host: std::net::IpAddr,
        port: u16,
        existing_banner: Option<&str>,
        default_timeout: Duration,
    ) -> Option<String> {
        let Some(payload) = &self.payload else {
            return existing_banner
                .map(str::trim)
                .filter(|banner| !banner.is_empty())
                .map(str::to_string);
        };

        let timeout = self
            .timeout
            .unwrap_or(default_timeout)
            .clamp(Duration::from_millis(100), Duration::from_secs(10));
        let connect = tokio::time::timeout(timeout, TcpStream::connect(socket_addr(host, port)))
            .await
            .ok()?
            .ok()?;
        let _ = connect.set_nodelay(true);

        let mut stream = connect;
        tokio::time::timeout(timeout, stream.write_all(payload))
            .await
            .ok()?
            .ok()?;

        let deadline = Instant::now() + timeout;
        let idle = Duration::from_millis(200).min(timeout / 2);
        let mut response = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || response.len() >= MAX_RESPONSE {
                break;
            }
            match tokio::time::timeout(idle.min(remaining), stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(read)) => {
                    let take = read.min(MAX_RESPONSE - response.len());
                    response.extend_from_slice(&buffer[..take]);
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        if response.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&response).into_owned())
        }
    }

    fn evaluate(&self, text: &str) -> Option<Option<String>> {
        if let Some(expect) = &self.expect {
            let matched = if self.ignore_case {
                text.to_lowercase().contains(&expect.to_lowercase())
            } else {
                text.contains(expect)
            };
            if !matched {
                return None;
            }
        }
        if let Some(regex) = &self.expect_regex
            && !regex.is_match(text)
        {
            return None;
        }
        if self.expect.is_none() && self.expect_regex.is_none() && text.trim().is_empty() {
            return None;
        }

        let version = self.version_regex.as_ref().and_then(|regex| {
            regex.captures(text).and_then(|captures| {
                captures
                    .get(1)
                    .or_else(|| captures.get(0))
                    .map(|value| value.as_str().to_string())
            })
        });
        Some(version)
    }
}

fn compile_probe(pack: &str, raw: RawProbe) -> Result<CompiledProbe, AppError> {
    validate_name("probe", &raw.name)?;
    if raw.send.is_some() && raw.send_hex.is_some() {
        return Err(AppError::usage(format!(
            "probe '{}/{}' cannot set both send and send_hex",
            pack, raw.name
        )));
    }

    let payload = match (&raw.send, &raw.send_hex) {
        (Some(text), None) => Some(text.as_bytes().to_vec()),
        (None, Some(hex)) => Some(decode_hex(hex).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{}' send_hex: {error}", raw.name))
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    if let Some(payload) = &payload
        && (payload.is_empty() || payload.len() > MAX_PAYLOAD)
    {
        return Err(AppError::usage(format!(
            "probe '{pack}/{}' payload must be between 1 and {MAX_PAYLOAD} bytes",
            raw.name
        )));
    }

    let expect_regex = match raw.expect_regex {
        Some(pattern) => Some(compile_regex(&pattern, raw.ignore_case, pack, &raw.name)?),
        None => None,
    };
    let version_regex = match raw.version_regex {
        Some(pattern) => Some(compile_regex(&pattern, raw.ignore_case, pack, &raw.name)?),
        None => None,
    };

    let service = raw
        .service
        .filter(|service| !service.trim().is_empty())
        .unwrap_or_else(|| raw.name.clone());
    validate_name("service", &service)?;

    let mut ports = raw.ports;
    ports.sort_unstable();
    ports.dedup();

    Ok(CompiledProbe {
        pack: pack.to_string(),
        name: raw.name,
        service,
        ports,
        product: raw.product,
        version: raw.version,
        payload,
        expect: raw.expect,
        expect_regex,
        version_regex,
        ignore_case: raw.ignore_case,
        timeout: raw.timeout_ms.map(Duration::from_millis),
    })
}

fn validate_name(kind: &str, name: &str) -> Result<(), AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::usage(format!("{kind} name cannot be empty")));
    }
    if name.chars().count() > 128 {
        let preview: String = name.chars().take(128).collect();
        return Err(AppError::usage(format!(
            "{kind} name '{preview}' exceeds 128 characters"
        )));
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || " ._-:/()".contains(character))
    {
        return Err(AppError::usage(format!(
            "{kind} name '{name}' contains unsupported characters"
        )));
    }
    Ok(())
}

fn compile_regex(
    pattern: &str,
    ignore_case: bool,
    pack: &str,
    probe: &str,
) -> Result<Regex, AppError> {
    if pattern.chars().count() > MAX_REGEX_CHARS {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' regex exceeds {MAX_REGEX_CHARS} characters"
        )));
    }
    let pattern = if ignore_case {
        format!("(?i:{pattern})")
    } else {
        pattern.to_string()
    };
    Regex::new(&pattern).map_err(|error| {
        AppError::usage(format!(
            "probe '{pack}/{probe}' has an invalid regex: {error}"
        ))
    })
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex payload has an odd number of digits".to_string());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let chars: Vec<char> = cleaned.chars().collect();
    for pair in chars.chunks(2) {
        let pair: String = pair.iter().collect();
        let byte =
            u8::from_str_radix(&pair, 16).map_err(|_| format!("invalid hex byte '{pair}'"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    let sanitized: String = line
        .chars()
        .map(|character| {
            if character.is_ascii_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    sanitized.chars().take(160).collect()
}

/// Parse a pack directly (used by tests and tooling).
pub fn parse_pack(text: &str) -> Result<Registry, AppError> {
    let mut registry = Registry::default();
    registry.parse(text)?;
    Ok(registry)
}

/// Return the default plugin directory (`<config dir>/plugins`) when present.
pub fn default_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let path = base.join("rayscan").join("plugins");
    path.is_dir().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn result(port: u16, banner: Option<&str>) -> PortResult {
        let mut result = PortResult::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            PortState::Open,
            Duration::ZERO,
        );
        result.banner = banner.map(str::to_string);
        result
    }

    #[test]
    fn compiles_literal_and_regex_probes() {
        let registry = parse_pack(
            r#"
name = "example"

[[probe]]
name = "acme"
service = "acme-admin"
ports = [8000, 8080]
expect = "Acme"
version_regex = "Version: ([0-9.]+)"
"#,
        )
        .unwrap();
        assert_eq!(registry.pack_count(), 1);
        assert_eq!(registry.probe_count(), 1);
        let probe = &registry.probes[0];
        assert_eq!(
            probe.evaluate("Acme Version: 1.2.3"),
            Some(Some("1.2.3".into()))
        );
        assert_eq!(probe.evaluate("Other"), None);
    }

    #[test]
    fn rejects_invalid_payloads_and_regexes() {
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send = "a"
send_hex = "61"
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send_hex = "zz"
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
expect_regex = "("
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send = ""
"#
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_fields_and_duplicate_payloads() {
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
unexpected = true
"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn applies_passive_probe_to_matching_open_result() {
        let registry = parse_pack(
            r#"
name = "example"
[[probe]]
name = "acme"
service = "acme-admin"
ports = [8000]
expect = "Acme"
product = "Acme Appliance"
version_regex = "Version: ([0-9.]+)"
"#,
        )
        .unwrap();
        let mut results = vec![
            result(8000, Some("Acme Version: 9.1")),
            result(8001, Some("Acme Version: 9.1")),
        ];
        let matched = registry
            .apply(&mut results, Duration::from_millis(100), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "acme-admin");
        assert_eq!(service.product.as_deref(), Some("Acme Appliance"));
        assert_eq!(service.version.as_deref(), Some("9.1"));
        assert!(results[0].detail.as_deref().unwrap().contains("plugin"));
        assert!(results[1].service.is_none());
    }

    #[tokio::test]
    async fn sends_active_probe_and_reads_response() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 64];
            let read = stream.read(&mut request).await.unwrap();
            assert_eq!(&request[..read], b"hello");
            stream
                .write_all(b"HELLO/1.0\r\nProduct: Acme\r\n")
                .await
                .unwrap();
        });

        let registry = parse_pack(
            r#"
name = "active"
[[probe]]
name = "hello"
service = "hello"
send = "hello"
expect = "HELLO/1.0"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        assert_eq!(results[0].service.as_ref().unwrap().name, "hello");
        assert!(
            results[0]
                .banner
                .as_deref()
                .unwrap()
                .starts_with("HELLO/1.0")
        );
    }
}
