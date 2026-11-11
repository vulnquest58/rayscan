//! Scope Guard enforcement for bug bounty and authorized network assessments.
//!
//! Enforces strict in-scope target boundaries and explicitly denies out-of-scope
//! assets, preventing accidental scans of unauthorized targets on platforms
//! like HackerOne, Bugcrowd, or private engagement scopes.

use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// Scope specification file structure (e.g. `scope.toml`).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScopeFile {
    pub scope: ScopeConfig,
}

/// Scope definition specifying the program identity, allowed, and denied rules.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScopeConfig {
    /// Human-readable engagement or program name (e.g. "HackerOne - Target Org").
    pub program: Option<String>,
    /// Explicitly allowed targets, CIDRs, or wildcard domains (e.g. `*.example.com`, `10.0.0.0/8`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly forbidden targets or domains that take precedence over allow rules.
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedRule {
    ExactIp(IpAddr),
    Ipv4Cidr(Ipv4Addr, u8),
    Ipv6Cidr(Ipv6Addr, u8),
    Ipv4Range(Ipv4Addr, Ipv4Addr),
    ExactDomain(String),
    WildcardDomain(String), // suffix without leading "*." (e.g. "example.com")
}

impl fmt::Display for ParsedRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactIp(ip) => write!(f, "{ip}"),
            Self::Ipv4Cidr(ip, prefix) => write!(f, "{ip}/{prefix}"),
            Self::Ipv6Cidr(ip, prefix) => write!(f, "{ip}/{prefix}"),
            Self::Ipv4Range(start, end) => write!(f, "{start}-{end}"),
            Self::ExactDomain(dom) => write!(f, "{dom}"),
            Self::WildcardDomain(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

#[derive(Clone, Debug)]
enum TargetIpMatcher {
    Cidr(IpAddr, u8),
    Range(IpAddr, IpAddr),
}

impl TargetIpMatcher {
    fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        let unbracketed = spec
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(spec);
        if let Ok(address) = unbracketed.parse::<IpAddr>() {
            return Some(Self::Cidr(
                address,
                if address.is_ipv4() { 32 } else { 128 },
            ));
        }
        if let Some((address, prefix)) = spec.split_once('/')
            && let Ok(address) = address.trim().parse::<IpAddr>()
            && let Ok(prefix) = prefix.trim().parse::<u8>()
        {
            let max = if address.is_ipv4() { 32 } else { 128 };
            if prefix <= max {
                return Some(Self::Cidr(address, prefix));
            }
        }
        if let Some((start, end)) = spec.split_once('-')
            && let Ok(start) = start.trim().parse::<IpAddr>()
        {
            let end = end.trim().parse::<IpAddr>().or_else(|_| match start {
                IpAddr::V4(start_v4) => {
                    let last: u8 = end.trim().parse().map_err(|_| ())?;
                    let octets = start_v4.octets();
                    Ok::<IpAddr, ()>(IpAddr::V4(Ipv4Addr::new(
                        octets[0], octets[1], octets[2], last,
                    )))
                }
                IpAddr::V6(_) => Err(()),
            });
            if let Ok(end) = end
                && start.is_ipv4() == end.is_ipv4()
            {
                return Some(Self::Range(start, end));
            }
        }
        None
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::Cidr(network, prefix), actual) => match (network, actual) {
                (IpAddr::V4(network), IpAddr::V4(actual)) => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        !0u32 << (32 - u32::from(*prefix))
                    };
                    (u32::from(*network) & mask) == (u32::from(actual) & mask)
                }
                (IpAddr::V6(network), IpAddr::V6(actual)) => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        !0u128 << (128 - u32::from(*prefix))
                    };
                    (u128::from(*network) & mask) == (u128::from(actual) & mask)
                }
                _ => false,
            },
            (Self::Range(start, end), actual) => {
                let value = match actual {
                    IpAddr::V4(address) => u128::from(u32::from(address)),
                    IpAddr::V6(address) => u128::from(address),
                };
                let start = match start {
                    IpAddr::V4(address) => u128::from(u32::from(*address)),
                    IpAddr::V6(address) => u128::from(*address),
                };
                let end = match end {
                    IpAddr::V4(address) => u128::from(u32::from(*address)),
                    IpAddr::V6(address) => u128::from(*address),
                };
                value >= start && value <= end
            }
        }
    }
}

fn is_domain_spec(spec: &str) -> bool {
    TargetIpMatcher::parse(spec).is_none()
}

fn warn_or_error(force: bool, warning: &str, error: String) -> Result<(), AppError> {
    if force {
        eprintln!("{warning}");
        Ok(())
    } else {
        Err(AppError::usage(error))
    }
}

impl ParsedRule {
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(AppError::usage("empty scope rule"));
        }

        // 1. Single IP
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Self::ExactIp(ip));
        }

        // 2. CIDR notation
        if let Some((addr_part, prefix_part)) = trimmed.split_once('/') {
            let prefix: u8 = prefix_part.trim().parse().map_err(|_| {
                AppError::usage(format!("invalid CIDR prefix in scope rule {raw:?}"))
            })?;
            if let Ok(v4) = addr_part.trim().parse::<Ipv4Addr>() {
                if prefix > 32 {
                    return Err(AppError::usage(format!(
                        "IPv4 prefix /{prefix} out of bounds in scope rule {raw:?}"
                    )));
                }
                return Ok(Self::Ipv4Cidr(v4, prefix));
            } else if let Ok(v6) = addr_part.trim().parse::<Ipv6Addr>() {
                if prefix > 128 {
                    return Err(AppError::usage(format!(
                        "IPv6 prefix /{prefix} out of bounds in scope rule {raw:?}"
                    )));
                }
                return Ok(Self::Ipv6Cidr(v6, prefix));
            } else {
                return Err(AppError::usage(format!(
                    "invalid IP in CIDR scope rule {raw:?}"
                )));
            }
        }

        // 3. IPv4 range (e.g. 192.168.1.1-192.168.1.50)
        if let Some((start_part, end_part)) = trimmed.split_once('-')
            && let (Ok(start), Ok(end)) = (
                start_part.trim().parse::<Ipv4Addr>(),
                end_part.trim().parse::<Ipv4Addr>(),
            )
        {
            if u32::from(start) > u32::from(end) {
                return Err(AppError::usage(format!(
                    "inverted IP range in scope rule {raw:?}"
                )));
            }
            return Ok(Self::Ipv4Range(start, end));
        }

        // 4. Wildcard domain (*.example.com or .example.com)
        if let Some(suffix) = trimmed.strip_prefix("*.") {
            let lower = suffix.trim().to_ascii_lowercase();
            if lower.is_empty() {
                return Err(AppError::usage(format!(
                    "invalid wildcard domain in scope rule {raw:?}"
                )));
            }
            return Ok(Self::WildcardDomain(lower));
        }
        if let Some(suffix) = trimmed.strip_prefix('.') {
            let lower = suffix.trim().to_ascii_lowercase();
            if lower.is_empty() {
                return Err(AppError::usage(format!(
                    "invalid domain suffix in scope rule {raw:?}"
                )));
            }
            return Ok(Self::WildcardDomain(lower));
        }

        // 5. Exact domain name
        Ok(Self::ExactDomain(trimmed.to_ascii_lowercase()))
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::ExactIp(expected), actual) => *expected == actual,
            (Self::Ipv4Cidr(network, prefix), IpAddr::V4(actual)) => {
                if *prefix == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - *prefix);
                (u32::from(*network) & mask) == (u32::from(actual) & mask)
            }
            (Self::Ipv6Cidr(network, prefix), IpAddr::V6(actual)) => {
                if *prefix == 0 {
                    return true;
                }
                let net_u128 = u128::from(*network);
                let act_u128 = u128::from(actual);
                let mask = !0u128 << (128 - *prefix);
                (net_u128 & mask) == (act_u128 & mask)
            }
            (Self::Ipv4Range(start, end), IpAddr::V4(actual)) => {
                let start_u = u32::from(*start);
                let end_u = u32::from(*end);
                let act_u = u32::from(actual);
                act_u >= start_u && act_u <= end_u
            }
            _ => false,
        }
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        let clean = domain.trim().to_ascii_lowercase();
        match self {
            Self::ExactDomain(exact) => clean == *exact,
            Self::WildcardDomain(suffix) => {
                clean == *suffix || clean.ends_with(&format!(".{suffix}"))
            }
            _ => false,
        }
    }
}

/// Compiled Scope Guard validator holding parsed allow and deny rules.
#[derive(Clone, Debug)]
pub struct ScopeGuard {
    pub program: String,
    pub allow_rules: Vec<ParsedRule>,
    pub deny_rules: Vec<ParsedRule>,
}

impl ScopeGuard {
    /// Load and compile scope configuration from a TOML file or plain target list.
    pub fn load_from_file(path: &Path) -> Result<Self, AppError> {
        let content = fs::read_to_string(path).map_err(|error| {
            AppError::runtime(format!(
                "cannot read scope file {}: {error}",
                path.display()
            ))
        })?;

        Self::load_from_str(&content, path)
    }

    /// Parse scope configuration from string contents.
    pub fn load_from_str(content: &str, path_context: &Path) -> Result<Self, AppError> {
        // First try TOML deserialization (structured scope.toml)
        if let Ok(file) = toml::from_str::<ScopeFile>(content) {
            return Self::from_config(file.scope);
        }
        if let Ok(config) = toml::from_str::<ScopeConfig>(content) {
            return Self::from_config(config);
        }

        // Fallback: plaintext line-by-line allowlist
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(denied) = trimmed.strip_prefix('!') {
                deny.push(denied.trim().to_string());
            } else {
                allow.push(trimmed.to_string());
            }
        }

        Self::from_config(ScopeConfig {
            program: path_context
                .file_stem()
                .and_then(|s| s.to_str())
                .map(ToString::to_string),
            allow,
            deny,
        })
    }

    /// Compile a `ScopeConfig` into a validated `ScopeGuard`.
    pub fn from_config(config: ScopeConfig) -> Result<Self, AppError> {
        let program = config
            .program
            .unwrap_or_else(|| "Authorized Engagement".to_string());

        let mut allow_rules = Vec::with_capacity(config.allow.len());
        for rule_str in config.allow {
            allow_rules.push(ParsedRule::parse(&rule_str)?);
        }

        let mut deny_rules = Vec::with_capacity(config.deny.len());
        for rule_str in config.deny {
            deny_rules.push(ParsedRule::parse(&rule_str)?);
        }

        Ok(Self {
            program,
            allow_rules,
            deny_rules,
        })
    }

    /// Enforce scope boundaries against candidate target specifications and resolved IPs.
    ///
    /// Domain rules authorize domains and the addresses they resolve to. Explicit
    /// IP, CIDR, and range targets must additionally match an IP allow rule.
    pub fn validate(
        &self,
        specs: &[String],
        resolved_ips: &[IpAddr],
        force: bool,
    ) -> Result<(), AppError> {
        let mut explicit_matchers = Vec::new();

        for spec in specs {
            let spec_trimmed = spec.trim();

            for deny_rule in &self.deny_rules {
                if deny_rule.matches_domain(spec_trimmed) {
                    warn_or_error(
                        force,
                        &format!(
                            "[scope:warning] Target '{spec_trimmed}' violates deny rule '{deny_rule}' in scope '{}' (--force-out-of-scope active)",
                            self.program
                        ),
                        format!(
                            "SCOPE VIOLATION: Target '{spec_trimmed}' matches explicitly denied rule '{deny_rule}' for program '{}'. Scan aborted for legal safety (use --force-out-of-scope to override).",
                            self.program
                        ),
                    )?;
                }
            }

            if is_domain_spec(spec_trimmed) {
                if !self.allow_rules.is_empty()
                    && !self
                        .allow_rules
                        .iter()
                        .any(|rule| rule.matches_domain(spec_trimmed))
                {
                    warn_or_error(
                        force,
                        &format!(
                            "[scope:warning] Target '{spec_trimmed}' is not in allowed scope for '{}' (--force-out-of-scope active)",
                            self.program
                        ),
                        format!(
                            "SCOPE VIOLATION: Target domain '{spec_trimmed}' is NOT in the authorized scope for program '{}'. Scan aborted for legal safety (use --force-out-of-scope to override).",
                            self.program
                        ),
                    )?;
                }
            } else if let Some(matcher) = TargetIpMatcher::parse(spec_trimmed) {
                explicit_matchers.push(matcher);
            }
        }

        for &ip in resolved_ips {
            for deny_rule in &self.deny_rules {
                if deny_rule.matches_ip(ip) {
                    warn_or_error(
                        force,
                        &format!(
                            "[scope:warning] Resolved IP '{ip}' violates deny rule '{deny_rule}' in scope '{}' (--force-out-of-scope active)",
                            self.program
                        ),
                        format!(
                            "SCOPE VIOLATION: Resolved IP '{ip}' matches explicitly denied rule '{deny_rule}' for program '{}'. Scan aborted for legal safety (use --force-out-of-scope to override).",
                            self.program
                        ),
                    )?;
                }
            }

            if !self.allow_rules.is_empty() {
                let explicitly_targeted =
                    specs.is_empty() || explicit_matchers.iter().any(|matcher| matcher.matches(ip));
                if explicitly_targeted && !self.allow_rules.iter().any(|rule| rule.matches_ip(ip)) {
                    warn_or_error(
                        force,
                        &format!(
                            "[scope:warning] Resolved IP '{ip}' is not in allowed scope for '{}' (--force-out-of-scope active)",
                            self.program
                        ),
                        format!(
                            "SCOPE VIOLATION: Target IP '{ip}' is outside the authorized scope for program '{}'. Scan aborted for legal safety (use --force-out-of-scope to override).",
                            self.program
                        ),
                    )?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_ip_and_cidr_rules() {
        let config = ScopeConfig {
            program: Some("Test Bug Bounty".to_string()),
            allow: vec![
                "10.0.0.0/16".to_string(),
                "192.168.1.1-192.168.1.50".to_string(),
                "2001:db8::/64".to_string(),
            ],
            deny: vec!["10.0.5.1".to_string(), "10.0.99.0/24".to_string()],
        };

        let guard = ScopeGuard::from_config(config).unwrap();

        // In scope
        assert!(
            guard
                .validate(&[], &["10.0.1.5".parse().unwrap()], false)
                .is_ok()
        );
        assert!(
            guard
                .validate(&[], &["192.168.1.25".parse().unwrap()], false)
                .is_ok()
        );
        assert!(
            guard
                .validate(&[], &["2001:db8::cafe".parse().unwrap()], false)
                .is_ok()
        );

        // Denied specifically
        assert!(
            guard
                .validate(&[], &["10.0.5.1".parse().unwrap()], false)
                .is_err()
        );
        assert!(
            guard
                .validate(&[], &["10.0.99.10".parse().unwrap()], false)
                .is_err()
        );

        // Outside allowlist
        assert!(
            guard
                .validate(&[], &["8.8.8.8".parse().unwrap()], false)
                .is_err()
        );
        assert!(
            guard
                .validate(&[], &["192.168.1.100".parse().unwrap()], false)
                .is_err()
        );

        // Force override succeeds with warning
        assert!(
            guard
                .validate(&[], &["8.8.8.8".parse().unwrap()], true)
                .is_ok()
        );
    }

    #[test]
    fn parses_and_validates_domain_wildcards() {
        let config = ScopeConfig {
            program: Some("Acme Bounty".to_string()),
            allow: vec!["*.example.com".to_string(), "corp.net".to_string()],
            deny: vec!["admin.example.com".to_string()],
        };

        let guard = ScopeGuard::from_config(config).unwrap();

        // Allowed domains
        assert!(
            guard
                .validate(&["api.example.com".to_string()], &[], false)
                .is_ok()
        );
        assert!(
            guard
                .validate(&["foo.sub.example.com".to_string()], &[], false)
                .is_ok()
        );
        assert!(
            guard
                .validate(&["example.com".to_string()], &[], false)
                .is_ok()
        );
        assert!(
            guard
                .validate(&["corp.net".to_string()], &[], false)
                .is_ok()
        );

        // Denied domain
        assert!(
            guard
                .validate(&["admin.example.com".to_string()], &[], false)
                .is_err()
        );

        // Out of scope domain
        assert!(
            guard
                .validate(&["other.com".to_string()], &[], false)
                .is_err()
        );
        assert!(
            guard
                .validate(&["sub.corp.net".to_string()], &[], false)
                .is_err()
        );
    }

    #[test]
    fn domain_allow_rules_authorize_resolved_addresses() {
        let guard = ScopeGuard::from_config(ScopeConfig {
            program: Some("Bug Bounty".to_string()),
            allow: vec!["*.example.com".to_string()],
            deny: Vec::new(),
        })
        .unwrap();

        assert!(
            guard
                .validate(
                    &["api.example.com".to_string()],
                    &["93.184.216.34".parse().unwrap()],
                    false,
                )
                .is_ok()
        );
        assert!(
            guard
                .validate(
                    &["other.test".to_string()],
                    &["93.184.216.34".parse().unwrap()],
                    false,
                )
                .is_err()
        );
    }

    #[test]
    fn mixed_domain_and_ip_targets_enforce_explicit_ip_scope() {
        let guard = ScopeGuard::from_config(ScopeConfig {
            program: Some("Bug Bounty".to_string()),
            allow: vec!["*.example.com".to_string(), "10.0.0.0/8".to_string()],
            deny: Vec::new(),
        })
        .unwrap();

        assert!(
            guard
                .validate(
                    &["api.example.com".to_string(), "10.1.2.3".to_string()],
                    &[
                        "93.184.216.34".parse().unwrap(),
                        "10.1.2.3".parse().unwrap(),
                    ],
                    false,
                )
                .is_ok()
        );
        assert!(
            guard
                .validate(
                    &["api.example.com".to_string(), "8.8.8.8".to_string()],
                    &["93.184.216.34".parse().unwrap(), "8.8.8.8".parse().unwrap(),],
                    false,
                )
                .is_err()
        );
    }

    #[test]
    fn denied_addresses_are_rejected_even_when_a_domain_is_allowed() {
        let guard = ScopeGuard::from_config(ScopeConfig {
            program: Some("Bug Bounty".to_string()),
            allow: vec!["*.example.com".to_string()],
            deny: vec!["93.184.216.34".to_string()],
        })
        .unwrap();

        assert!(
            guard
                .validate(
                    &["api.example.com".to_string()],
                    &["93.184.216.34".parse().unwrap()],
                    false,
                )
                .is_err()
        );
    }

    #[test]
    fn parses_toml_scope_definition() {
        let toml_data = r#"
[scope]
program = "HackerOne Program X"
allow = ["*.target.corp", "172.16.0.0/12"]
deny = ["internal.target.corp", "172.16.1.1"]
"#;
        let guard = ScopeGuard::load_from_str(toml_data, Path::new("scope.toml")).unwrap();
        assert_eq!(guard.program, "HackerOne Program X");
        assert_eq!(guard.allow_rules.len(), 2);
        assert_eq!(guard.deny_rules.len(), 2);
    }
}
