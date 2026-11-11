use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::task::JoinSet;

use crate::error::AppError;
use crate::limits::MAX_TARGETS;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Any,
    V4,
    V6,
}

impl AddressFamily {
    fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Any => "IP",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

pub async fn resolve_targets(
    specs: &[String],
    files: &[PathBuf],
    excludes: &[String],
    family: AddressFamily,
) -> Result<Vec<IpAddr>, AppError> {
    resolve_targets_with_ndp(specs, files, excludes, family, None).await
}

/// Resolve targets, optionally using NDP multicast discovery to expand broad
/// IPv6 CIDRs instead of failing on the address cap.
pub async fn resolve_targets_with_ndp(
    specs: &[String],
    files: &[PathBuf],
    excludes: &[String],
    family: AddressFamily,
    ndp_timeout: Option<Duration>,
) -> Result<Vec<IpAddr>, AppError> {
    let specs = expand_files(specs, files)?;
    if specs.is_empty() {
        return Err(AppError::usage("at least one target is required"));
    }

    let ndp_neighbors = match ndp_timeout {
        Some(timeout) if needs_ndp_discovery(&specs) => {
            if !crate::discovery::ndp_supported() {
                return Err(AppError::usage(
                    "--ndp is only supported on Linux with raw ICMPv6 privileges",
                ));
            }
            Some(
                tokio::task::spawn_blocking(move || {
                    crate::discovery::discover_ipv6_multicast(timeout)
                })
                .await
                .map_err(|error| {
                    AppError::runtime(format!("NDP discovery task failed: {error}"))
                })?,
            )
        }
        _ => None,
    };

    let mut targets = resolve_specs(&specs, family, ndp_neighbors.as_deref()).await?;

    let excludes = expand_files(excludes, &[])?;
    if !excludes.is_empty() {
        let excluded: HashSet<IpAddr> = resolve_specs(&excludes, family, None)
            .await?
            .into_iter()
            .collect();
        targets.retain(|address| !excluded.contains(address));
    }

    if targets.is_empty() {
        return Err(AppError::usage("no targets remain after exclusions"));
    }

    Ok(targets)
}

fn needs_ndp_discovery(specs: &[String]) -> bool {
    specs.iter().any(|spec| {
        let Some((address, prefix)) = spec.split_once('/') else {
            return false;
        };
        if !matches!(address.trim().parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return false;
        }
        prefix
            .trim()
            .parse::<u8>()
            .is_ok_and(|prefix| u32::from(prefix) < 128 - 16)
    })
}

/// Expand `@file` entries and target-file paths into individual target specs.
pub fn expand_target_specs(specs: &[String], files: &[PathBuf]) -> Result<Vec<String>, AppError> {
    expand_files(specs, files)
}

fn expand_files(specs: &[String], files: &[PathBuf]) -> Result<Vec<String>, AppError> {
    let mut expanded = Vec::new();

    for path in files {
        read_target_file(path, &mut expanded)?;
    }

    for spec in specs {
        if let Some(path) = spec.strip_prefix('@') {
            if path.is_empty() {
                return Err(AppError::usage("empty @file target"));
            }
            read_target_file(Path::new(path), &mut expanded)?;
        } else if Path::new(spec).is_file() {
            read_target_file(Path::new(spec), &mut expanded)?;
        } else {
            expanded.push(spec.clone());
        }
    }

    Ok(expanded)
}

fn read_target_file(path: &Path, output: &mut Vec<String>) -> Result<(), AppError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        AppError::usage(format!(
            "cannot read target file {}: {error}",
            path.display()
        ))
    })?;

    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.is_empty() {
            output.push(line.to_string());
        }
    }
    Ok(())
}

async fn resolve_specs(
    specs: &[String],
    family: AddressFamily,
    ndp_neighbors: Option<&[IpAddr]>,
) -> Result<Vec<IpAddr>, AppError> {
    enum Entry {
        Literal(Vec<IpAddr>),
        Name(String),
    }

    let mut entries = Vec::with_capacity(specs.len());
    for spec in specs {
        match parse_literal(spec, family, ndp_neighbors)? {
            Some(addresses) => entries.push(Entry::Literal(addresses)),
            None => entries.push(Entry::Name(spec.clone())),
        }
    }

    let mut pending = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if let Entry::Name(name) = entry {
            pending.push((index, name.clone()));
        }
    }

    let mut resolved: Vec<Option<Result<Vec<IpAddr>, AppError>>> = vec![None; entries.len()];
    if !pending.is_empty() {
        let mut tasks = JoinSet::new();
        for (index, name) in pending {
            tasks.spawn(async move { (index, resolve_name(&name, family).await) });
        }

        while let Some(joined) = tasks.join_next().await {
            let (index, result) =
                joined.map_err(|error| AppError::runtime(format!("DNS task failed: {error}")))?;
            resolved[index] = Some(result);
        }
    }

    let mut accumulator = Accumulator::default();
    for (index, entry) in entries.into_iter().enumerate() {
        match entry {
            Entry::Literal(addresses) => accumulator.extend(addresses)?,
            Entry::Name(_) => {
                let result = resolved[index]
                    .take()
                    .expect("resolved name must have a result")?;
                accumulator.extend(result)?;
            }
        }
    }

    if accumulator.addresses.is_empty() {
        return Err(AppError::usage("no target addresses were resolved"));
    }
    Ok(accumulator.addresses)
}

#[derive(Default)]
struct Accumulator {
    seen: HashSet<IpAddr>,
    addresses: Vec<IpAddr>,
}

impl Accumulator {
    fn extend(&mut self, addresses: Vec<IpAddr>) -> Result<(), AppError> {
        for address in addresses {
            if self.seen.insert(address) {
                if self.addresses.len() >= MAX_TARGETS {
                    return Err(AppError::usage(format!(
                        "target expansion exceeds the {MAX_TARGETS}-address limit"
                    )));
                }
                self.addresses.push(address);
            }
        }
        Ok(())
    }
}

fn parse_literal(
    spec: &str,
    family: AddressFamily,
    ndp_neighbors: Option<&[IpAddr]>,
) -> Result<Option<Vec<IpAddr>>, AppError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(AppError::usage("empty target"));
    }

    let unbracketed = spec
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(spec);

    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        ensure_family(address, family, spec)?;
        return Ok(Some(vec![address]));
    }

    if spec.contains('/') {
        return parse_cidr(spec, family, ndp_neighbors).map(Some);
    }

    if let Some(range) = parse_range(spec, family)? {
        return Ok(Some(range));
    }

    Ok(None)
}

fn ensure_family(address: IpAddr, family: AddressFamily, context: &str) -> Result<(), AppError> {
    if family.accepts(address) {
        Ok(())
    } else {
        Err(AppError::usage(format!(
            "{context:?} is {} but {} was requested",
            if address.is_ipv4() { "IPv4" } else { "IPv6" },
            family.label()
        )))
    }
}

fn parse_cidr(
    spec: &str,
    family: AddressFamily,
    ndp_neighbors: Option<&[IpAddr]>,
) -> Result<Vec<IpAddr>, AppError> {
    let (address_text, prefix_text) = spec.split_once('/').ok_or_else(|| {
        AppError::usage(format!("invalid CIDR {spec:?}; expected address/prefix"))
    })?;

    let address: IpAddr = address_text.trim().parse().map_err(|_| {
        AppError::usage(format!(
            "invalid CIDR {spec:?}; address must be an IPv4 or IPv6 literal"
        ))
    })?;
    let prefix: u8 = prefix_text
        .trim()
        .parse()
        .map_err(|_| AppError::usage(format!("invalid CIDR {spec:?}; prefix must be a number")))?;
    ensure_family(address, family, spec)?;

    match address {
        IpAddr::V4(address) => {
            if prefix > 32 {
                return Err(AppError::usage(format!(
                    "invalid IPv4 CIDR {spec:?}; prefix must be 0-32"
                )));
            }
            let host_bits = 32 - u32::from(prefix);
            let count = 1u64 << host_bits;
            if count > MAX_TARGETS as u64 {
                return Err(too_many(spec));
            }
            let mask = if host_bits == 32 {
                0
            } else {
                u32::MAX << host_bits
            };
            let base = u32::from(address) & mask;
            let mut addresses = Vec::with_capacity(count as usize);
            for offset in 0..count {
                addresses.push(IpAddr::V4(Ipv4Addr::from(base + offset as u32)));
            }
            Ok(addresses)
        }
        IpAddr::V6(address) => {
            if prefix > 128 {
                return Err(AppError::usage(format!(
                    "invalid IPv6 CIDR {spec:?}; prefix must be 0-128"
                )));
            }
            let host_bits = 128 - u32::from(prefix);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << host_bits
            };
            let base = u128::from(address) & mask;

            if host_bits >= 128 || (1u128 << host_bits.min(127)) > MAX_TARGETS as u128 {
                if let Some(neighbors) = ndp_neighbors {
                    let addresses: Vec<IpAddr> = neighbors
                        .iter()
                        .copied()
                        .filter(|address| {
                            matches!(address, IpAddr::V6(value) if u128::from(*value) & mask == base)
                        })
                        .collect();
                    if addresses.is_empty() {
                        return Err(AppError::usage(format!(
                            "NDP discovery found no active IPv6 neighbors inside {spec}"
                        )));
                    }
                    return Ok(addresses);
                }
                return Err(too_many(spec));
            }

            let count = 1u128 << host_bits;
            let mut addresses = Vec::with_capacity(count as usize);
            for offset in 0..count {
                addresses.push(IpAddr::V6(Ipv6Addr::from(base + offset)));
            }
            Ok(addresses)
        }
    }
}

fn parse_range(spec: &str, family: AddressFamily) -> Result<Option<Vec<IpAddr>>, AppError> {
    let Some((start_text, end_text)) = spec.split_once('-') else {
        return Ok(None);
    };

    let start: IpAddr = match start_text.trim().parse() {
        Ok(address) => address,
        Err(_) => return Ok(None),
    };
    let end_text = end_text.trim();

    let end = match end_text.parse::<IpAddr>() {
        Ok(address) => address,
        Err(_) => match start {
            IpAddr::V4(start_v4) => {
                let last_octet: u8 = end_text.parse().map_err(|_| {
                    AppError::usage(format!(
                        "invalid range {spec:?}; expected an IPv4 address or final octet"
                    ))
                })?;
                let octets = start_v4.octets();
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet))
            }
            IpAddr::V6(_) => {
                return Err(AppError::usage(format!(
                    "invalid IPv6 range {spec:?}; use full start and end addresses"
                )));
            }
        },
    };

    if std::mem::discriminant(&start) != std::mem::discriminant(&end) {
        return Err(AppError::usage(format!(
            "range {spec:?} mixes IPv4 and IPv6 addresses"
        )));
    }
    ensure_family(start, family, spec)?;
    ensure_family(end, family, spec)?;

    let start_value = match start {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    };
    let end_value = match end {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    };

    if start_value > end_value {
        return Err(AppError::usage(format!(
            "range {spec:?} starts after it ends"
        )));
    }

    let span = end_value - start_value;
    if span >= MAX_TARGETS as u128 {
        return Err(too_many(spec));
    }
    let count = span + 1;

    let mut addresses = Vec::with_capacity(count as usize);
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            for value in u32::from(start)..=u32::from(end) {
                addresses.push(IpAddr::V4(Ipv4Addr::from(value)));
            }
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            for value in u128::from(start)..=u128::from(end) {
                addresses.push(IpAddr::V6(Ipv6Addr::from(value)));
            }
        }
        _ => unreachable!("range families were checked above"),
    }

    Ok(Some(addresses))
}

fn too_many(spec: &str) -> AppError {
    AppError::usage(format!(
        "target {spec:?} expands to more than the {MAX_TARGETS}-address limit"
    ))
}

async fn resolve_name(name: &str, family: AddressFamily) -> Result<Vec<IpAddr>, AppError> {
    let query = name
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(name);

    if query.is_empty() {
        return Err(AppError::usage("empty target"));
    }

    if looks_like_malformed_ip(query) {
        return Err(AppError::usage(format!("invalid target address {name:?}")));
    }

    let lookup = tokio::time::timeout(DNS_TIMEOUT, lookup_host((query, 0)))
        .await
        .map_err(|_| AppError::runtime(format!("DNS lookup for {name:?} timed out")))?;
    let addresses = lookup
        .map_err(|error| AppError::runtime(format!("DNS lookup for {name:?} failed: {error}")))?;

    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for socket in addresses {
        let address = socket.ip();
        if family.accepts(address) && seen.insert(address) {
            resolved.push(address);
        }
    }

    if resolved.is_empty() {
        return Err(AppError::usage(format!(
            "target {name:?} has no addresses for the selected family"
        )));
    }

    Ok(resolved)
}

fn looks_like_malformed_ip(value: &str) -> bool {
    if value.contains(':') {
        return value.chars().all(|character| {
            character.is_ascii_hexdigit() || character == ':' || character == '.'
        });
    }

    value.contains('.')
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expands_cidrs_and_ranges() {
        let addresses = resolve_targets(
            &["192.0.2.0/30".to_string(), "198.51.100.10-12".to_string()],
            &[],
            &[],
            AddressFamily::Any,
        )
        .await
        .unwrap();

        assert_eq!(addresses.len(), 7);
        assert_eq!(addresses[0], "192.0.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[3], "192.0.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[4], "198.51.100.10".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[6], "198.51.100.12".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn expands_ipv6_cidrs_and_ranges() {
        let addresses = resolve_targets(
            &[
                "2001:db8::/126".to_string(),
                "2001:db8:1::1-2001:db8:1::3".to_string(),
            ],
            &[],
            &[],
            AddressFamily::V6,
        )
        .await
        .unwrap();

        assert_eq!(addresses.len(), 7);
        assert_eq!(addresses[0], "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[3], "2001:db8::3".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[4], "2001:db8:1::1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[6], "2001:db8:1::3".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn ndp_neighbors_expand_broad_ipv6_cidr() {
        let neighbors = vec![
            "fe80::1".parse::<IpAddr>().unwrap(),
            "fe80::2".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap(),
        ];
        let addresses = resolve_specs(
            &["fe80::/64".to_string()],
            AddressFamily::V6,
            Some(&neighbors),
        )
        .await
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|address| address.is_ipv6()));
    }

    #[tokio::test]
    async fn ndp_without_matching_neighbors_reports_a_clear_error() {
        let neighbors = vec!["2001:db8::1".parse::<IpAddr>().unwrap()];
        let error = resolve_specs(
            &["fe80::/64".to_string()],
            AddressFamily::V6,
            Some(&neighbors),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("NDP discovery found no active"));
    }

    #[tokio::test]
    async fn deduplicates_targets_and_applies_exclusions() {
        let addresses = resolve_targets(
            &[
                "192.0.2.1".to_string(),
                "192.0.2.1".to_string(),
                "192.0.2.0/30".to_string(),
            ],
            &[],
            &["192.0.2.0".to_string(), "192.0.2.3".to_string()],
            AddressFamily::Any,
        )
        .await
        .unwrap();

        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[1], "192.0.2.2".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn rejects_oversized_expansions_and_bad_families() {
        assert_eq!(
            resolve_targets(&["192.0.0.0/15".to_string()], &[], &[], AddressFamily::Any)
                .await
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(
            resolve_targets(&["127.0.0.1".to_string()], &[], &[], AddressFamily::V6)
                .await
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[tokio::test]
    async fn reads_explicit_files_and_at_files() {
        let path = std::env::temp_dir().join(format!(
            "rayscan-targets-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "# comment\n192.0.2.10\n\n192.0.2.11 # inline\n").unwrap();

        let explicit = resolve_targets(
            &["192.0.2.12".to_string()],
            std::slice::from_ref(&path),
            &[],
            AddressFamily::Any,
        )
        .await
        .unwrap();
        assert_eq!(explicit.len(), 3);

        let at_file = resolve_targets(
            &[format!("@{}", path.display())],
            &[],
            &[],
            AddressFamily::Any,
        )
        .await
        .unwrap();
        assert_eq!(at_file.len(), 2);

        let _ = std::fs::remove_file(path);
    }
}
