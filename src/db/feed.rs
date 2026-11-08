//! NVD CVE 2.0 feed retrieval and streaming extraction.
//!
//! Yearly feeds are large (tens of megabytes compressed, hundreds of
//! uncompressed), so records are deserialized one at a time through a custom
//! visitor instead of materializing the whole document.

use std::fmt;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

use super::{
    AffectedProduct, DbPaths, FeedMeta, MAX_RANGES_PER_PRODUCT, StoredEntry, VersionRange,
    runtime_error,
};
use crate::error::AppError;

const USER_AGENT: &str = concat!("rayscan/", env!("CARGO_PKG_VERSION"));

/// A change to apply to the local database.
pub enum Change {
    Upsert(StoredEntry),
    Remove(String),
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(USER_AGENT)
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(120))
        .timeout_write(Duration::from_secs(30))
        .build()
}

/// Retrieve and parse the `.meta` companion file for a feed kind
/// (`recent` or a four-digit year).
pub fn fetch_meta(agent: &ureq::Agent, kind: &str) -> Result<FeedMeta, AppError> {
    let url = format!("{}/nvdcve-2.0-{kind}.meta", super::FEED_BASE);
    let body = agent
        .get(&url)
        .call()
        .map_err(|error| AppError::runtime(format!("NVD metadata request failed: {error}")))?
        .into_string()
        .map_err(|error| AppError::runtime(format!("cannot read NVD metadata: {error}")))?;

    let mut meta = FeedMeta::default();
    for line in body.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "lastModifiedDate" => meta.last_modified = value.to_string(),
            "size" => meta.size = value.parse().unwrap_or(0),
            "gzSize" => meta.gz_size = value.parse().unwrap_or(0),
            "sha256" => meta.sha256 = value.to_string(),
            _ => {}
        }
    }
    if meta.sha256.is_empty() {
        return Err(AppError::runtime(format!(
            "NVD metadata for '{kind}' did not include a SHA-256 digest"
        )));
    }
    Ok(meta)
}

/// Download a compressed feed file to the local download directory and return
/// its temporary path.
///
/// NVD publishes digests for the uncompressed document, so callers must run
/// [`verify_feed`] before parsing.
pub fn download_feed(
    agent: &ureq::Agent,
    kind: &str,
    paths: &DbPaths,
) -> Result<PathBuf, AppError> {
    fs::create_dir_all(paths.downloads_dir())
        .map_err(|error| runtime_error("create download directory", error))?;
    let temporary = paths.downloads_dir().join(format!("{kind}.json.gz.part"));
    let url = format!("{}/nvdcve-2.0-{kind}.json.gz", super::FEED_BASE);

    let response = agent
        .get(&url)
        .call()
        .map_err(|error| AppError::runtime(format!("NVD feed download failed: {error}")))?;

    let result = (|| -> Result<(), AppError> {
        let mut reader = response.into_reader();
        let file = fs::File::create(&temporary)
            .map_err(|error| runtime_error("create feed download", error))?;
        let mut writer = BufWriter::new(file);
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| AppError::runtime(format!("cannot read NVD feed: {error}")))?;
            if read == 0 {
                break;
            }
            writer
                .write_all(&buffer[..read])
                .map_err(|error| runtime_error("write feed download", error))?;
        }
        writer
            .flush()
            .map_err(|error| runtime_error("flush feed download", error))?;
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(temporary)
}

/// Verify a downloaded feed against the digest published in its metadata.
///
/// The published digest covers the decompressed JSON document, so the feed is
/// streamed through the gzip decoder while hashing.
pub fn verify_feed(path: &Path, kind: &str, expected_sha256: &str) -> Result<(), AppError> {
    let file = fs::File::open(path).map_err(|error| runtime_error("open feed download", error))?;
    let mut decoder = GzDecoder::new(BufReader::new(file));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|error| AppError::runtime(format!("cannot decompress NVD feed: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex_digest(&hasher.finalize());
    if !digest.eq_ignore_ascii_case(expected_sha256) {
        return Err(AppError::runtime(format!(
            "NVD feed '{kind}' failed SHA-256 verification (expected {expected_sha256}, got {digest})"
        )));
    }
    Ok(())
}
fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02X}"));
    }
    output
}

/// Extract changes from a downloaded `.json.gz` feed file.
pub fn read_feed_file(path: &Path, sink: impl FnMut(Change)) -> Result<usize, AppError> {
    let file = fs::File::open(path).map_err(|error| runtime_error("open feed download", error))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    read_feed(decoder, sink)
}

/// Stream a feed document and invoke `sink` for each relevant CVE.
pub fn read_feed<R: Read>(reader: R, sink: impl FnMut(Change)) -> Result<usize, AppError> {
    let mut sink = sink;
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    deserializer
        .deserialize_map(FeedVisitor {
            sink: &mut sink,
            count: 0,
        })
        .map_err(|error| AppError::runtime(format!("cannot parse NVD feed: {error}")))
}

struct FeedVisitor<'a, F> {
    sink: &'a mut F,
    count: usize,
}

impl<'de, F: FnMut(Change)> Visitor<'de> for FeedVisitor<'_, F> {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an NVD CVE feed object")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<usize, A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "vulnerabilities" {
                map.next_value_seed(VulnSequence {
                    sink: &mut *self.sink,
                    count: &mut self.count,
                })?;
            } else {
                let _: IgnoredAny = map.next_value()?;
            }
        }
        Ok(self.count)
    }
}

struct VulnSequence<'a, F> {
    sink: &'a mut F,
    count: &'a mut usize,
}

impl<'de, F: FnMut(Change)> DeserializeSeed<'de> for VulnSequence<'_, F> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, F: FnMut(Change)> Visitor<'de> for VulnSequence<'_, F> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of NVD vulnerabilities")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while let Some(vulnerability) = sequence.next_element::<FeedVulnerability>()? {
            if let Some(change) = vulnerability.into_change() {
                (self.sink)(change);
                *self.count += 1;
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct FeedVulnerability {
    cve: FeedCve,
}

#[derive(Deserialize)]
struct FeedCve {
    id: String,
    #[serde(default, rename = "vulnStatus")]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<FeedDescription>,
    #[serde(default)]
    metrics: FeedMetrics,
    #[serde(default)]
    configurations: Vec<FeedConfiguration>,
}

#[derive(Deserialize)]
struct FeedDescription {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize, Default)]
struct FeedMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<FeedMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<FeedMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<FeedMetric>,
}

#[derive(Deserialize)]
struct FeedMetric {
    #[serde(rename = "cvssData")]
    data: FeedCvssData,
}

#[derive(Deserialize)]
struct FeedCvssData {
    #[serde(rename = "baseScore")]
    base_score: f32,
}

#[derive(Deserialize, Default)]
struct FeedConfiguration {
    #[serde(default)]
    nodes: Vec<FeedNode>,
}

#[derive(Deserialize, Default)]
struct FeedNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<FeedCpeMatch>,
}

#[derive(Deserialize, Default)]
struct FeedCpeMatch {
    #[serde(default)]
    vulnerable: bool,
    #[serde(default)]
    criteria: String,
    #[serde(default, rename = "versionStartIncluding")]
    start_incl: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    start_excl: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    end_incl: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    end_excl: Option<String>,
}

impl FeedVulnerability {
    fn into_change(self) -> Option<Change> {
        let cve = self.cve;
        if cve.id.is_empty() {
            return None;
        }
        if cve.vuln_status.to_ascii_lowercase().starts_with("rejected") {
            return Some(Change::Remove(cve.id));
        }

        let title = cve
            .descriptions
            .iter()
            .find(|description| description.lang.eq_ignore_ascii_case("en"))
            .map(|description| clean_title(&description.value))
            .filter(|title| !title.is_empty())
            .unwrap_or_else(|| "No description available".to_string());

        let cvss = cve
            .metrics
            .v31
            .first()
            .or_else(|| cve.metrics.v30.first())
            .or_else(|| cve.metrics.v2.first())
            .map(|metric| metric.data.base_score)
            .unwrap_or(0.0);

        let mut products: std::collections::BTreeMap<String, ProductAccumulator> =
            std::collections::BTreeMap::new();
        for configuration in &cve.configurations {
            for node in &configuration.nodes {
                for cpe in &node.cpe_match {
                    if !cpe.vulnerable {
                        continue;
                    }
                    let Some((product, exact_version)) = parse_cpe(&cpe.criteria) else {
                        continue;
                    };
                    let accumulator = products.entry(product).or_default();
                    let range = VersionRange {
                        start_incl: cpe.start_incl.clone(),
                        start_excl: cpe.start_excl.clone(),
                        end_incl: cpe.end_incl.clone(),
                        end_excl: cpe.end_excl.clone(),
                    };
                    if range.is_empty() {
                        match exact_version {
                            Some(version) => accumulator.push(VersionRange {
                                start_incl: Some(version.clone()),
                                start_excl: None,
                                end_incl: Some(version),
                                end_excl: None,
                            }),
                            None => accumulator.all_versions = true,
                        }
                    } else {
                        accumulator.push(range);
                    }
                }
            }
        }

        let affected = products
            .into_iter()
            .map(|(product, accumulator)| AffectedProduct {
                product,
                all_versions: accumulator.all_versions,
                ranges: accumulator.ranges,
            })
            .collect();

        Some(Change::Upsert(StoredEntry {
            id: cve.id,
            title,
            cvss,
            affected,
        }))
    }
}

#[derive(Default)]
struct ProductAccumulator {
    all_versions: bool,
    ranges: Vec<VersionRange>,
}

impl ProductAccumulator {
    fn push(&mut self, range: VersionRange) {
        if self.ranges.len() >= MAX_RANGES_PER_PRODUCT {
            return;
        }
        if !self.ranges.contains(&range) {
            self.ranges.push(range);
        }
    }
}

/// Parse a CPE 2.3 criteria string into `(product, exact_version)`.
///
/// Wildcard/not-applicable versions yield `None` for the version; the caller
/// falls back to range bounds or treats the product as affected in all
/// versions.
fn parse_cpe(criteria: &str) -> Option<(String, Option<String>)> {
    if !criteria.starts_with("cpe:2.3:") {
        return None;
    }
    let fields: Vec<String> = split_cpe(criteria);
    if fields.len() < 7 || fields[2] != "a" {
        return None;
    }
    let product = fields[4].trim().to_string();
    if product.is_empty() || product == "*" || product == "-" {
        return None;
    }
    let version = fields[5].as_str();
    let update = fields[6].as_str();
    let exact = if version == "*" || version == "-" {
        None
    } else {
        let mut value = version.to_string();
        if !update.is_empty() && update != "*" && update != "-" {
            value.push_str(update);
        }
        Some(value)
    };
    Some((product.to_ascii_lowercase(), exact))
}

fn split_cpe(criteria: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in criteria.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    fields.push(current);
    fields
}

fn clean_title(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= 160 {
        cleaned
    } else {
        let mut truncated: String = cleaned.chars().take(157).collect();
        truncated.push_str("...");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        r#"{
          "resultsPerPage": 3,
          "startIndex": 0,
          "totalResults": 3,
          "format": "NVD_CVE",
          "version": "2.0",
          "vulnerabilities": [
            {
              "cve": {
                "id": "CVE-2024-0001",
                "vulnStatus": "Analyzed",
                "descriptions": [
                  {"lang": "es", "value": "ignorado"},
                  {"lang": "en", "value": "Test overflow in vsftpd\nwith newline"}
                ],
                "metrics": {
                  "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                  "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
                },
                "configurations": [
                  {"nodes": [{"cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "3.0"}
                  ]}]}
                ]
              }
            },
            {
              "cve": {
                "id": "CVE-2024-0002",
                "vulnStatus": "Rejected",
                "descriptions": []
              }
            },
            {
              "cve": {
                "id": "CVE-2024-0003",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Exact version flaw"}],
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
                "configurations": [
                  {"nodes": [{"cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                  ]}]}
                ]
              }
            }
          ]
        }"#
    }

    #[test]
    fn extracts_products_versions_and_scores() {
        let mut changes = Vec::new();
        let count = read_feed(fixture().as_bytes(), |change| changes.push(change)).unwrap();
        assert_eq!(count, 3);

        match &changes[0] {
            Change::Upsert(entry) => {
                assert_eq!(entry.id, "CVE-2024-0001");
                assert_eq!(entry.cvss, 9.8);
                assert_eq!(entry.title, "Test overflow in vsftpd with newline");
                assert_eq!(entry.affected.len(), 1);
                assert_eq!(entry.affected[0].product, "vsftpd");
                assert!(!entry.affected[0].all_versions);
                assert_eq!(entry.affected[0].ranges[0].end_excl.as_deref(), Some("3.0"));
            }
            Change::Remove(_) => panic!("expected upsert"),
        }

        match &changes[1] {
            Change::Remove(id) => assert_eq!(id, "CVE-2024-0002"),
            Change::Upsert(_) => panic!("expected removal"),
        }

        match &changes[2] {
            Change::Upsert(entry) => {
                assert_eq!(entry.cvss, 5.0);
                assert_eq!(entry.affected[0].product, "http_server");
                assert_eq!(
                    entry.affected[0].ranges[0].start_incl.as_deref(),
                    Some("2.4.49")
                );
                assert_eq!(
                    entry.affected[0].ranges[0].end_incl.as_deref(),
                    Some("2.4.49")
                );
            }
            Change::Remove(_) => panic!("expected upsert"),
        }
    }

    #[test]
    fn cpe_parser_handles_escaping_and_wildcards() {
        assert_eq!(
            parse_cpe("cpe:2.3:a:vendor:some\\:product:1.0:*:*:*:*:*:*:*"),
            Some(("some:product".to_string(), Some("1.0".to_string())))
        );
        assert_eq!(
            parse_cpe("cpe:2.3:a:openssh:openssh:4.7:p1:*:*:*:*:*:*"),
            Some(("openssh".to_string(), Some("4.7p1".to_string())))
        );
        assert_eq!(
            parse_cpe("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
            Some(("product".to_string(), None))
        );
        assert_eq!(
            parse_cpe("cpe:2.3:h:vendor:product:1.0:*:*:*:*:*:*:*"),
            None
        );
        assert_eq!(parse_cpe("not-a-cpe"), None);
    }

    #[test]
    fn title_is_truncated_and_controls_are_removed() {
        let long = "x".repeat(300);
        let title = clean_title(&format!("start\n{long}"));
        assert!(title.len() <= 160);
        assert!(!title.contains('\n'));
        assert!(title.ends_with("..."));
    }

    #[test]
    fn feed_digest_covers_decompressed_document() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let plaintext = br#"{"vulnerabilities":[]}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();

        let dir = std::env::temp_dir().join(format!("rayscan-feed-digest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("feed.json.gz");
        fs::write(&path, compressed).unwrap();

        let digest = hex_digest(&Sha256::digest(plaintext));
        assert!(verify_feed(&path, "test", &digest).is_ok());
        assert!(verify_feed(&path, "test", &"0".repeat(64)).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
