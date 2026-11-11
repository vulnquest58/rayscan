//! Offline vulnerability advisory correlation.
//!
//! Matches detected service identity (product name, version, and optional
//! banner context) against two sources:
//!
//! 1. the local NVD database maintained by `rayscan db update` (see
//!    [`crate::db`]), which covers all CVE years through the current year; and
//! 2. a small bundled curated database in `data/advisories.json` that adds
//!    context-sensitive mappings (for example Debian/Ubuntu SSH banners).
//!
//! Correlation is advisory only: confirm findings against current vendor
//! advisories before acting.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::db::LocalIndex;
use crate::model::{PortResult, PortState, ScanReport};

const DATABASE_JSON: &str = include_str!("../data/advisories.json");
const CISA_KEV_JSON: &str = include_str!("../data/cisa_kev.json");

/// One bundled or downloaded threat-intelligence record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ThreatIntelEntry {
    pub id: String,
    #[serde(default)]
    pub cisa_kev: bool,
    #[serde(default)]
    pub epss: Option<f32>,
}

/// A threat-intelligence indicator for one CVE.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ThreatIndicator {
    pub cisa_kev: bool,
    pub epss: Option<f32>,
}

type ThreatIntelTable = HashMap<String, ThreatIndicator>;

fn threat_intel() -> &'static RwLock<ThreatIntelTable> {
    static THREAT_INTEL: OnceLock<RwLock<ThreatIntelTable>> = OnceLock::new();
    THREAT_INTEL.get_or_init(|| RwLock::new(bundled_threat_intel()))
}

fn bundled_threat_intel() -> ThreatIntelTable {
    let entries: Vec<ThreatIntelEntry> = serde_json::from_str(CISA_KEV_JSON).unwrap_or_default();
    entries
        .into_iter()
        .map(|entry| {
            (
                entry.id,
                ThreatIndicator {
                    cisa_kev: entry.cisa_kev,
                    epss: entry.epss,
                },
            )
        })
        .collect()
}

/// Return the small curated threat-intelligence set compiled into the binary.
pub fn bundled_threat_intel_entries() -> Vec<ThreatIntelEntry> {
    serde_json::from_str(CISA_KEV_JSON).unwrap_or_default()
}

/// Merge downloaded threat intelligence into the process-wide lookup table.
///
/// Bundled entries remain available for CVEs absent from the downloaded feed.
/// Reinstalling an overlay simply replaces indicator values for matching CVEs.
pub fn install_threat_intel(entries: impl IntoIterator<Item = ThreatIntelEntry>) {
    let mut table = threat_intel()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for entry in entries {
        table.insert(
            entry.id,
            ThreatIndicator {
                cisa_kev: entry.cisa_kev,
                epss: entry.epss,
            },
        );
    }
}

/// Lookup threat intelligence indicators (CISA KEV membership and FIRST.org EPSS score).
pub fn lookup_threat_intel(cve_id: &str) -> (bool, Option<f32>) {
    threat_intel()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(cve_id)
        .map(|indicator| (indicator.cisa_kev, indicator.epss))
        .unwrap_or((false, None))
}

/// Qualitative severity derived from the advisory's CVSS score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn from_cvss(cvss: f32) -> Self {
        if cvss >= 9.0 {
            Self::Critical
        } else if cvss >= 7.0 {
            Self::High
        } else if cvss >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// One advisory matched to a port result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryMatch {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: f32,
    #[serde(default)]
    pub cisa_kev: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
    /// Where the match came from: `curated` or `nvd`.
    pub source: &'static str,
}

#[derive(Clone, Debug, Deserialize)]
struct Advisory {
    id: String,
    title: String,
    cvss: f32,
    #[serde(default)]
    products: Vec<String>,
    #[serde(default)]
    version: VersionRule,
    #[serde(default)]
    banner_any: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum VersionRule {
    #[default]
    Any,
    Eq {
        value: String,
    },
    Lt {
        value: String,
    },
    Range {
        #[serde(default)]
        min: Option<String>,
        #[serde(default)]
        max_exclusive: Option<String>,
    },
}

impl VersionRule {
    fn matches(&self, detected: Option<&[u64]>) -> bool {
        let Some(detected) = detected else {
            return matches!(self, Self::Any);
        };
        match self {
            Self::Any => true,
            Self::Eq { value } => {
                parse_version(value).is_some_and(|rule| compare_versions(detected, &rule).is_eq())
            }
            Self::Lt { value } => {
                parse_version(value).is_some_and(|rule| compare_versions(detected, &rule).is_lt())
            }
            Self::Range { min, max_exclusive } => {
                let above_min = min
                    .as_deref()
                    .and_then(parse_version)
                    .is_none_or(|rule| compare_versions(detected, &rule).is_ge());
                let below_max = max_exclusive
                    .as_deref()
                    .and_then(parse_version)
                    .is_none_or(|rule| compare_versions(detected, &rule).is_lt());
                above_min && below_max
            }
        }
    }
}

impl Advisory {
    fn matches(
        &self,
        identities: &[String],
        version: Option<&[u64]>,
        banner: Option<&str>,
    ) -> bool {
        if self.products.is_empty()
            || !self
                .products
                .iter()
                .any(|product| identities.iter().any(|identity| identity == product))
        {
            return false;
        }

        if !self.version.matches(version) {
            return false;
        }

        if self.banner_any.is_empty() {
            return true;
        }
        let Some(banner) = banner else {
            return false;
        };
        self.banner_any
            .iter()
            .any(|term| banner.contains(term.as_str()))
    }
}

fn database() -> &'static [Advisory] {
    static DATABASE: OnceLock<Vec<Advisory>> = OnceLock::new();
    DATABASE.get_or_init(|| serde_json::from_str(DATABASE_JSON).unwrap_or_default())
}

/// Correlate a single port result with the bundled advisory database.
pub fn correlate(result: &PortResult) -> Vec<AdvisoryMatch> {
    correlate_with(result, None)
}

/// Correlate a single port result with the bundled and local databases.
///
/// Only open results that carry service metadata are evaluated.  Matches are
/// deduplicated by CVE identifier (curated entries take precedence) and
/// ordered with curated findings first, then by severity (critical first) and
/// advisory identifier within each source.
pub fn correlate_with(result: &PortResult, index: Option<&LocalIndex>) -> Vec<AdvisoryMatch> {
    if result.state != PortState::Open {
        return Vec::new();
    }
    let Some(service) = &result.service else {
        return Vec::new();
    };

    let mut identities = Vec::with_capacity(2);
    identities.push(service.name.to_ascii_lowercase());
    if let Some(product) = &service.product {
        identities.push(product.to_ascii_lowercase());
    }

    let version = service.version.as_deref().and_then(parse_version);
    let banner = result.banner.as_deref().map(str::to_ascii_lowercase);

    let mut matches: Vec<AdvisoryMatch> = database()
        .iter()
        .filter(|advisory| advisory.matches(&identities, version.as_deref(), banner.as_deref()))
        .map(|advisory| {
            let (cisa_kev, epss) = lookup_threat_intel(&advisory.id);
            AdvisoryMatch {
                id: advisory.id.clone(),
                title: advisory.title.clone(),
                severity: Severity::from_cvss(advisory.cvss),
                cvss: advisory.cvss,
                cisa_kev,
                epss,
                source: "curated",
            }
        })
        .collect();

    if let (Some(index), Some(product)) = (index, service.product.as_deref()) {
        for advisory in index.advisories_for(product, version.as_deref()) {
            if !matches.iter().any(|existing| existing.id == advisory.id) {
                matches.push(advisory);
            }
        }
    }

    sort_matches(&mut matches);
    matches
}

fn sort_matches(matches: &mut [AdvisoryMatch]) {
    matches.sort_by(|left, right| {
        let rank = |source: &str| u8::from(source != "curated");
        rank(left.source)
            .cmp(&rank(right.source))
            .then_with(|| right.severity.cmp(&left.severity))
            .then_with(|| left.id.cmp(&right.id))
    });
}

/// Correlate every open service in a scan report.
pub fn apply_advisories(report: &mut ScanReport) {
    apply_advisories_with(report, None);
}

/// Correlate every open service against both advisory sources.
pub fn apply_advisories_with(report: &mut ScanReport, index: Option<&LocalIndex>) {
    for result in &mut report.results {
        result.advisories = correlate_with(result, index);
    }
}

/// Filter advisory findings according to CISA KEV presence and minimum EPSS threshold.
pub fn filter_advisories(report: &mut ScanReport, kev_only: bool, min_epss: Option<f32>) {
    if !kev_only && min_epss.is_none() {
        return;
    }
    for result in &mut report.results {
        result.advisories.retain(|adv| {
            if kev_only && !adv.cisa_kev {
                return false;
            }
            if let Some(threshold) = min_epss
                && !adv.epss.is_some_and(|score| score >= threshold)
            {
                return false;
            }
            true
        });
    }
}

pub(crate) fn parse_version(version: &str) -> Option<Vec<u64>> {
    let core: String = version
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect();
    let parts: Vec<u64> = core
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u64>())
        .collect::<Result<_, _>>()
        .ok()?;
    (!parts.is_empty()).then_some(parts)
}

pub(crate) fn compare_versions(left: &[u64], right: &[u64]) -> Ordering {
    let len = left.len().max(right.len());
    for index in 0..len {
        let left_part = left.get(index).copied().unwrap_or(0);
        let right_part = right.get(index).copied().unwrap_or(0);
        match left_part.cmp(&right_part) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::*;
    use crate::service::ServiceInfo;

    fn sample(
        name: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> PortResult {
        let host: IpAddr = "192.168.100.37".parse().unwrap();
        let mut result = PortResult::new(host, 21, PortState::Open, Duration::from_millis(3));
        result.service = Some(ServiceInfo {
            name: name.to_string(),
            product: product.map(str::to_string),
            version: version.map(str::to_string),
            confidence: None,
        });
        result.banner = banner.map(str::to_string);
        result
    }

    #[test]
    fn bundled_database_loads() {
        assert!(!database().is_empty(), "bundled advisory DB must parse");
    }

    #[test]
    fn matches_vsftpd_backdoor() {
        let result = sample(
            "ftp",
            Some("vsFTPd"),
            Some("2.3.4"),
            Some("220 (vsFTPd 2.3.4)"),
        );
        let matches = correlate(&result);
        assert!(matches.iter().any(|m| m.id == "CVE-2011-2523"));
        assert_eq!(matches[0].severity, Severity::Critical);
    }

    #[test]
    fn patched_vsftpd_is_clean() {
        let result = sample("ftp", Some("vsFTPd"), Some("3.0.5"), None);
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn debian_openssh_prng_requires_debian_or_ubuntu_banner() {
        let debian = sample(
            "ssh",
            Some("OpenSSH"),
            Some("4.7p1"),
            Some("SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"),
        );
        assert!(correlate(&debian).iter().any(|m| m.id == "CVE-2008-0166"));

        let upstream = sample(
            "ssh",
            Some("OpenSSH"),
            Some("4.7p1"),
            Some("SSH-2.0-OpenSSH_4.7p1"),
        );
        assert!(!correlate(&upstream).iter().any(|m| m.id == "CVE-2008-0166"));
    }

    #[test]
    fn apache_coyote_does_not_match_httpd_advisories() {
        let result = sample(
            "http",
            Some("Apache-Coyote"),
            Some("1.1"),
            Some("HTTP/1.1 200 OK"),
        );
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn apache_228_matches_slowloris_and_range_dos() {
        let result = sample(
            "http",
            Some("Apache"),
            Some("2.2.8"),
            Some("HTTP/1.1 200 OK"),
        );
        let ids: Vec<String> = correlate(&result).into_iter().map(|m| m.id).collect();
        assert!(ids.contains(&"CVE-2007-6750".to_string()));
        assert!(ids.contains(&"CVE-2011-3192".to_string()));
    }

    #[test]
    fn modern_apache_is_clean() {
        let result = sample(
            "http",
            Some("Apache"),
            Some("2.4.62"),
            Some("HTTP/1.1 200 OK"),
        );
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn curated_matches_rank_before_nvd_matches() {
        let mut matches = vec![
            AdvisoryMatch {
                id: "CVE-2024-0002".to_string(),
                title: "nvd critical".to_string(),
                severity: Severity::Critical,
                cvss: 9.8,
                cisa_kev: false,
                epss: None,
                source: "nvd",
            },
            AdvisoryMatch {
                id: "CVE-2024-0001".to_string(),
                title: "curated medium".to_string(),
                severity: Severity::Medium,
                cvss: 5.0,
                cisa_kev: false,
                epss: None,
                source: "curated",
            },
        ];
        sort_matches(&mut matches);
        assert_eq!(matches[0].source, "curated");
        assert_eq!(matches[1].source, "nvd");
    }

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(parse_version("4.7p1"), Some(vec![4, 7]));
        assert_eq!(parse_version("5.0.51a-3ubuntu5"), Some(vec![5, 0, 51]));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(compare_versions(&[2, 2, 8], &[2, 2, 20]), Ordering::Less);
        assert_eq!(compare_versions(&[2, 3], &[2, 3, 0]), Ordering::Equal);
    }

    #[test]
    fn apply_advisories_annotates_only_open_services() {
        let host: IpAddr = "192.168.100.37".parse().unwrap();
        let mut ftp = sample("ftp", Some("vsFTPd"), Some("2.3.4"), None);
        ftp.port = 21;
        let mut closed = PortResult::new(host, 22, PortState::Closed, Duration::from_millis(1));
        closed.service = Some(ServiceInfo {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("4.7p1".to_string()),
            confidence: Some(0.98),
        });

        let mut report = ScanReport {
            targets: 1,
            ports: 2,
            jobs: 2,
            workers: 1,
            elapsed: Duration::from_millis(10),
            counts: crate::model::StateCounts {
                open: 1,
                closed: 1,
                ..Default::default()
            },
            results: vec![ftp, closed],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![21, 22],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        apply_advisories(&mut report);
        assert_eq!(report.results[0].advisories.len(), 1);
        assert!(report.results[1].advisories.is_empty());
    }

    #[test]
    fn cisa_kev_and_epss_enrichment_and_filtering() {
        let mut ftp = sample("ftp", Some("vsFTPd"), Some("2.3.4"), None);
        ftp.port = 21;
        let matches = correlate(&ftp);
        assert!(!matches.is_empty());
        let first = &matches[0];
        assert_eq!(first.id, "CVE-2011-2523");
        assert!(
            first.cisa_kev,
            "vsftpd backdoor must be flagged as CISA KEV"
        );
        assert!(
            first.epss.is_some_and(|e| e > 0.9),
            "vsftpd backdoor must have high EPSS"
        );

        let mut report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(5),
            counts: crate::model::StateCounts {
                open: 1,
                ..Default::default()
            },
            results: vec![ftp],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![21],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        apply_advisories(&mut report);
        assert_eq!(report.results[0].advisories.len(), 1);

        // Filter with high EPSS threshold (e.g. 0.99 which exceeds 0.941)
        filter_advisories(&mut report, false, Some(0.99));
        assert!(report.results[0].advisories.is_empty());
    }
}
