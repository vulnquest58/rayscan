//! Live CISA KEV and FIRST.org EPSS threat-intelligence ingestion.
//!
//! The scanner ships with a compact curated set of heavily exploited CVEs so
//! filtering works out of the box.  `rayscan db intel` refreshes the full CISA
//! Known Exploited Vulnerabilities catalog and the current EPSS score feed into
//! the local data directory, and every scan overlays that cache on top of the
//! bundled indicators.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

use crate::advisory::{self, ThreatIntelEntry};
use crate::db::DbPaths;
use crate::error::AppError;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const MAX_KEV_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EPSS_BYTES: u64 = 64 * 1024 * 1024;
const REFRESH_AFTER_SECS: u64 = 24 * 60 * 60;
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct IntelFile {
    schema: u32,
    updated_at: u64,
    kev_count: usize,
    epss_count: usize,
    entries: Vec<ThreatIntelEntry>,
}

/// Result of a successful intel refresh.
#[derive(Clone, Debug, Serialize)]
pub struct IntelSummary {
    pub path: String,
    pub updated_at: u64,
    pub kev_count: usize,
    pub epss_count: usize,
    pub total: usize,
    pub refreshed: bool,
}

/// Options for `rayscan db intel`.
#[derive(Clone, Copy, Debug)]
pub struct IntelUpdateOptions {
    pub force: bool,
    pub quiet: bool,
}

#[derive(Debug, Deserialize)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Deserialize)]
struct KevVulnerability {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// Download and atomically cache the CISA KEV catalog plus current EPSS scores.
pub fn update(paths: &DbPaths, options: IntelUpdateOptions) -> Result<IntelSummary, AppError> {
    let path = paths.intel_file();
    let now = now_unix();

    if !options.force
        && let Some(existing) = read_intel_file(&path)
        && now.saturating_sub(existing.updated_at) < REFRESH_AFTER_SECS
    {
        return Ok(summary(path, &existing, false));
    }

    if !options.quiet {
        eprintln!("[intel] downloading CISA KEV catalog …");
    }
    let kev = fetch_kev()?;
    if !options.quiet {
        eprintln!("[intel] downloading FIRST.org EPSS scores …");
    }
    let epss = fetch_epss()?;

    let entries = merge_entries(kev, epss, advisory::bundled_threat_intel_entries());
    let kev_count = entries.iter().filter(|entry| entry.cisa_kev).count();
    let epss_count = entries.iter().filter(|entry| entry.epss.is_some()).count();
    let file = IntelFile {
        schema: SCHEMA_VERSION,
        updated_at: now,
        kev_count,
        epss_count,
        entries,
    };
    write_intel_file(&path, &file)?;
    Ok(summary(path, &file, true))
}

/// Load a cached intel overlay. Corrupt or absent caches are ignored.
pub fn load_entries(paths: &DbPaths) -> Option<Vec<ThreatIntelEntry>> {
    read_intel_file(&paths.intel_file()).map(|file| file.entries)
}

/// Overlay the cached full feed on the bundled indicators for this process.
pub fn install_overlay(paths: &DbPaths) -> Option<usize> {
    let entries = load_entries(paths)?;
    let count = entries.len();
    advisory::install_threat_intel(entries);
    (count > 0).then_some(count)
}

fn summary(path: PathBuf, file: &IntelFile, refreshed: bool) -> IntelSummary {
    IntelSummary {
        path: path.display().to_string(),
        updated_at: file.updated_at,
        kev_count: file.kev_count,
        epss_count: file.epss_count,
        total: file.entries.len(),
        refreshed,
    }
}

fn fetch_kev() -> Result<Vec<ThreatIntelEntry>, AppError> {
    let agent = crate::db::feed::agent();
    let response = agent
        .get(KEV_URL)
        .call()
        .map_err(|error| AppError::runtime(format!("CISA KEV download failed: {error}")))?;
    let bytes = read_limited(response.into_reader(), MAX_KEV_BYTES)?;
    parse_kev_json(&bytes)
}

fn fetch_epss() -> Result<HashMap<String, f32>, AppError> {
    let agent = crate::db::feed::agent();
    let response = agent
        .get(EPSS_URL)
        .call()
        .map_err(|error| AppError::runtime(format!("EPSS download failed: {error}")))?;
    let bytes = read_limited(response.into_reader(), MAX_EPSS_BYTES)?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        parse_epss_csv(GzDecoder::new(bytes.as_slice()))
    } else {
        parse_epss_csv(bytes.as_slice())
    }
}

fn read_limited(mut reader: impl Read, limit: u64) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::runtime(format!("cannot read threat feed: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(AppError::runtime(
            "threat feed exceeds the maximum supported size",
        ));
    }
    Ok(bytes)
}

fn parse_kev_json(bytes: &[u8]) -> Result<Vec<ThreatIntelEntry>, AppError> {
    let feed: KevFeed = serde_json::from_slice(bytes)
        .map_err(|error| AppError::runtime(format!("cannot parse CISA KEV feed: {error}")))?;
    let mut entries = HashMap::new();
    for vulnerability in feed.vulnerabilities {
        let id = vulnerability.cve_id.trim().to_ascii_uppercase();
        if !id.starts_with("CVE-") {
            continue;
        }
        entries.insert(
            id.clone(),
            ThreatIntelEntry {
                id,
                cisa_kev: true,
                epss: None,
            },
        );
    }
    Ok(entries.into_values().collect())
}

fn parse_epss_csv(reader: impl Read) -> Result<HashMap<String, f32>, AppError> {
    let mut scores = HashMap::new();
    for (line_number, line) in BufReader::new(reader).lines().enumerate() {
        let line = line.map_err(|error| {
            AppError::runtime(format!(
                "cannot read EPSS feed line {}: {error}",
                line_number + 1
            ))
        })?;
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(',');
        let Some(id) = fields.next() else {
            continue;
        };
        let Some(score) = fields.next() else {
            continue;
        };
        let id = id.trim().trim_matches('"').to_ascii_uppercase();
        if !id.starts_with("CVE-") {
            continue;
        }
        let Ok(score) = score.trim().trim_matches('"').parse::<f32>() else {
            continue;
        };
        if score.is_finite() && (0.0..=1.0).contains(&score) {
            scores.insert(id, score);
        }
    }
    if scores.is_empty() {
        return Err(AppError::runtime(
            "EPSS feed contained no usable CVE scores",
        ));
    }
    Ok(scores)
}

fn merge_entries(
    kev: Vec<ThreatIntelEntry>,
    epss: HashMap<String, f32>,
    bundled: Vec<ThreatIntelEntry>,
) -> Vec<ThreatIntelEntry> {
    let mut merged: HashMap<String, ThreatIntelEntry> = epss
        .into_iter()
        .map(|(id, score)| {
            (
                id.clone(),
                ThreatIntelEntry {
                    id,
                    cisa_kev: false,
                    epss: Some(score),
                },
            )
        })
        .collect();

    for entry in kev {
        merged
            .entry(entry.id.clone())
            .and_modify(|existing| existing.cisa_kev = true)
            .or_insert(entry);
    }
    for entry in bundled {
        merged
            .entry(entry.id.clone())
            .and_modify(|existing| {
                existing.cisa_kev |= entry.cisa_kev;
                if existing.epss.is_none() {
                    existing.epss = entry.epss;
                }
            })
            .or_insert(entry);
    }

    let mut entries: Vec<_> = merged.into_values().collect();
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    entries
}

fn read_intel_file(path: &Path) -> Option<IntelFile> {
    let file = fs::File::open(path).ok()?;
    let mut decoder = GzDecoder::new(BufReader::new(file));
    let mut contents = String::new();
    decoder.read_to_string(&mut contents).ok()?;
    let file: IntelFile = serde_json::from_str(&contents).ok()?;
    (file.schema == SCHEMA_VERSION).then_some(file)
}

fn write_intel_file(path: &Path, file: &IntelFile) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| AppError::runtime(format!("create intel directory: {error}")))?;
    }
    let temporary = path.with_extension("json.gz.tmp");
    let output = fs::File::create(&temporary)
        .map_err(|error| AppError::runtime(format!("create intel cache: {error}")))?;
    let mut encoder = GzEncoder::new(BufWriter::new(output), Compression::default());
    serde_json::to_writer(&mut encoder, file)
        .map_err(|error| AppError::runtime(format!("encode intel cache: {error}")))?;
    let mut writer = encoder
        .finish()
        .map_err(|error| AppError::runtime(format!("finish intel cache: {error}")))?;
    writer
        .flush()
        .map_err(|error| AppError::runtime(format!("flush intel cache: {error}")))?;

    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| AppError::runtime(format!("replace intel cache: {error}")))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| AppError::runtime(format!("install intel cache: {error}")))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kev_feed_into_entries() {
        let json = br#"{
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                {"cveID": "not-a-cve"},
                {"cveID": "cve-2022-22965"}
            ]
        }"#;
        let entries = parse_kev_json(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.cisa_kev));
        assert!(entries.iter().any(|entry| entry.id == "CVE-2022-22965"));
    }

    #[test]
    fn parses_epss_csv_with_comment_and_header() {
        let csv = b"#model_version:v2026.06.15,score_date:2026-11-08T12:00:26Z\n\
                    cve,epss,percentile\n\
                    CVE-1999-0001,0.04753,0.91942\n\
                    CVE-2021-44228,0.99999,1.0\n\
                    BAD,0.5,0.5\n";
        let scores = parse_epss_csv(csv.as_slice()).unwrap();
        assert_eq!(scores.len(), 2);
        assert_eq!(scores["CVE-1999-0001"], 0.04753);
        assert_eq!(scores["CVE-2021-44228"], 0.99999);
    }

    #[test]
    fn merge_keeps_kev_membership_and_epss_scores() {
        let kev = vec![ThreatIntelEntry {
            id: "CVE-2021-44228".to_string(),
            cisa_kev: true,
            epss: None,
        }];
        let epss = HashMap::from([("CVE-2021-44228".to_string(), 0.99)]);
        let bundled = vec![ThreatIntelEntry {
            id: "CVE-2008-0166".to_string(),
            cisa_kev: true,
            epss: Some(0.745),
        }];
        let entries = merge_entries(kev, epss, bundled);
        let log4j = entries
            .iter()
            .find(|entry| entry.id == "CVE-2021-44228")
            .unwrap();
        assert!(log4j.cisa_kev);
        assert_eq!(log4j.epss, Some(0.99));
        let debian = entries
            .iter()
            .find(|entry| entry.id == "CVE-2008-0166")
            .unwrap();
        assert!(debian.cisa_kev);
        assert_eq!(debian.epss, Some(0.745));
    }

    #[test]
    fn intel_file_roundtrips_through_gzip() {
        let root = std::env::temp_dir().join(format!(
            "rayscan-intel-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let paths = DbPaths::at(&root);
        let file = IntelFile {
            schema: SCHEMA_VERSION,
            updated_at: 42,
            kev_count: 1,
            epss_count: 1,
            entries: vec![ThreatIntelEntry {
                id: "CVE-2021-44228".to_string(),
                cisa_kev: true,
                epss: Some(0.99),
            }],
        };
        write_intel_file(&paths.intel_file(), &file).unwrap();
        let loaded = read_intel_file(&paths.intel_file()).unwrap();
        assert_eq!(loaded.updated_at, 42);
        assert_eq!(loaded.entries.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }
}
