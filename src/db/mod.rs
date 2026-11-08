//! Local NVD CVE database: storage layout, synchronization, and status.
//!
//! The database is a compact, sharded index derived from the official NVD
//! CVE 2.0 feeds.  It lives in a user-writable data directory so it can be
//! refreshed independently of the binary:
//!
//! ```text
//! <root>/manifest.json              sync state and totals
//! <root>/years/<year>.jsonl         compact CVE records grouped by CVE year
//! <root>/shards/<year>/<xx>.jsonl   product-bucketed lookup shards
//! ```
//!
//! `rayscan db update` performs a full or incremental synchronization and
//! every scan performs a lightweight check of the NVD `recent` feed so new
//! changes are applied automatically.

pub mod feed;
pub mod index;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::AppError;

pub use index::LocalIndex;

/// Base URL for the NVD CVE 2.0 feeds.
pub const FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
/// First year covered by the NVD CVE 2.0 yearly feeds.
pub const FIRST_YEAR: u16 = 2002;
/// On-disk schema version; a mismatch triggers a rebuild on update.
pub const SCHEMA_VERSION: u32 = 1;
/// A local database whose recent feed is older than this is considered stale.
pub const STALE_AFTER_SECS: u64 = 8 * 24 * 60 * 60;
/// Maximum number of version ranges retained per CVE/product pair.
const MAX_RANGES_PER_PRODUCT: usize = 256;

/// Inclusive/exclusive version bounds from a CPE match entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_incl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_incl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excl: Option<String>,
}

impl VersionRange {
    fn is_empty(&self) -> bool {
        self.start_incl.is_none()
            && self.start_excl.is_none()
            && self.end_incl.is_none()
            && self.end_excl.is_none()
    }
}

/// One product affected by a CVE, with the applicable version constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub product: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub all_versions: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<VersionRange>,
}

/// A compact CVE record stored in the yearly database files.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredEntry {
    pub id: String,
    pub title: String,
    pub cvss: f32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<AffectedProduct>,
}

/// A flattened record stored in a product shard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardEntry {
    pub id: String,
    pub title: String,
    pub cvss: f32,
    pub product: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub all_versions: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<VersionRange>,
}

/// Metadata published alongside each NVD feed file.
#[derive(Clone, Debug, Default)]
pub struct FeedMeta {
    pub last_modified: String,
    pub size: u64,
    pub gz_size: u64,
    pub sha256: String,
}

/// Synchronization state for one yearly feed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct YearState {
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub last_modified: String,
    #[serde(default)]
    pub cve_count: u64,
    #[serde(default)]
    pub entry_count: u64,
}

/// Synchronization state for the rolling `recent` feed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentState {
    pub sha256: String,
    #[serde(default)]
    pub last_modified: String,
    #[serde(default)]
    pub applied_at: u64,
}

/// Top-level database manifest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub generated_at: u64,
    #[serde(default)]
    pub last_full_sync: u64,
    #[serde(default)]
    pub last_auto_check: u64,
    #[serde(default)]
    pub cve_count: u64,
    #[serde(default)]
    pub entry_count: u64,
    #[serde(default)]
    pub years: BTreeMap<u16, YearState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent: Option<RecentState>,
}

impl Manifest {
    fn recompute_totals(&mut self) {
        self.cve_count = self.years.values().map(|year| year.cve_count).sum();
        self.entry_count = self.years.values().map(|year| year.entry_count).sum();
        self.generated_at = now_unix();
    }
}

/// Filesystem locations used by the local database.
#[derive(Clone, Debug)]
pub struct DbPaths {
    pub root: PathBuf,
}

impl DbPaths {
    /// Resolve the database directory using an explicit path, the
    /// `RAYSCAN_DB_DIR` environment variable, or the platform data directory.
    pub fn resolve(explicit: Option<&Path>) -> Option<Self> {
        let root = if let Some(path) = explicit {
            path.to_path_buf()
        } else if let Some(path) = std::env::var_os("RAYSCAN_DB_DIR") {
            PathBuf::from(path)
        } else {
            default_root()?
        };
        Some(Self { root })
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn manifest(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    pub fn years_dir(&self) -> PathBuf {
        self.root.join("years")
    }

    pub fn year_file(&self, year: u16) -> PathBuf {
        self.years_dir().join(format!("{year}.jsonl"))
    }

    pub fn shards_dir(&self) -> PathBuf {
        self.root.join("shards")
    }

    pub fn shard_dir(&self, year: u16) -> PathBuf {
        self.shards_dir().join(year.to_string())
    }

    pub fn shard_file(&self, year: u16, bucket: u8) -> PathBuf {
        self.shard_dir(year).join(format!("{bucket:02x}.jsonl"))
    }

    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.root.join(".update.lock")
    }

    pub fn is_initialized(&self) -> bool {
        load_manifest(self).is_some()
    }
}

#[cfg(windows)]
fn default_root() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|base| PathBuf::from(base).join("rayscan").join("db"))
}

#[cfg(not(windows))]
fn default_root() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(base).join("rayscan").join("db"));
    }
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("rayscan")
            .join("db")
    })
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Current UTC year derived from the system clock.
pub fn current_year() -> u16 {
    let days = (now_unix() / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2)) as u16
}

/// FNV-1a bucket used to shard products for fast lookup.
pub fn bucket(product: &str) -> u8 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in product.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash & 0xff) as u8
}

/// Map a detected service product to the CPE product names used by NVD.
///
/// Only products with a confident, unambiguous CPE mapping are included;
/// generic service names (`ftp`, `ssh`, `http`) are intentionally excluded.
pub fn cpe_products(product: &str) -> &'static [&'static str] {
    match product.to_ascii_lowercase().as_str() {
        "apache" | "httpd" | "apache httpd" => &["http_server"],
        "vsftpd" => &["vsftpd"],
        "openssh" => &["openssh"],
        "samba" => &["samba"],
        "exim" => &["exim"],
        "postfix" => &["postfix"],
        "mysql" => &["mysql"],
        "unrealircd" => &["unrealircd"],
        "distcc" | "distccd" => &["distcc"],
        "proftpd" => &["proftpd"],
        "nginx" => &["nginx"],
        "openssl" => &["openssl"],
        "tomcat" | "apache tomcat" => &["tomcat"],
        "squid" => &["squid"],
        "postgresql" => &["postgresql"],
        "redis" => &["redis"],
        "docker" => &["docker"],
        "node.js" | "nodejs" => &["node.js"],
        _ => &[],
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn load_manifest(paths: &DbPaths) -> Option<Manifest> {
    let contents = fs::read_to_string(paths.manifest()).ok()?;
    let manifest: Manifest = serde_json::from_str(&contents).ok()?;
    (manifest.schema == SCHEMA_VERSION).then_some(manifest)
}

pub fn save_manifest(paths: &DbPaths, manifest: &Manifest) -> Result<(), AppError> {
    fs::create_dir_all(&paths.root)
        .map_err(|error| runtime_error("create database directory", error))?;
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|error| AppError::runtime(format!("cannot encode database manifest: {error}")))?;
    let temporary = paths.manifest().with_extension("json.tmp");
    fs::write(&temporary, json).map_err(|error| runtime_error("write database manifest", error))?;
    replace_file(&temporary, &paths.manifest())
        .map_err(|error| runtime_error("store database manifest", error))
}

pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)
}

pub(crate) fn runtime_error(action: &str, error: std::io::Error) -> AppError {
    AppError::runtime(format!("cannot {action}: {error}"))
}

/// Parse a year specification: `all`, `2002-2026`, or `2024,2025,2026`.
pub fn parse_years(spec: &str, current: u16) -> Result<Vec<u16>, AppError> {
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("all") {
        return Ok((FIRST_YEAR..=current).collect());
    }
    let mut years = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| AppError::usage(format!("invalid year range '{part}'")))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| AppError::usage(format!("invalid year range '{part}'")))?;
            if start > end {
                return Err(AppError::usage(format!("invalid year range '{part}'")));
            }
            years.extend(start..=end);
        } else {
            let year: u16 = part
                .parse()
                .map_err(|_| AppError::usage(format!("invalid year '{part}'")))?;
            years.push(year);
        }
    }
    years.sort_unstable();
    years.dedup();
    if years.is_empty() {
        return Err(AppError::usage("no years selected for database update"));
    }
    if let Some(year) = years
        .iter()
        .find(|year| !(FIRST_YEAR..=current).contains(year))
    {
        return Err(AppError::usage(format!(
            "year {year} is outside the supported range {FIRST_YEAR}-{current}"
        )));
    }
    Ok(years)
}

struct UpdateLock {
    path: PathBuf,
}

impl UpdateLock {
    fn acquire(paths: &DbPaths) -> Result<Self, AppError> {
        fs::create_dir_all(&paths.root)
            .map_err(|error| runtime_error("create database directory", error))?;
        let path = paths.lock_file();
        if let Ok(metadata) = fs::metadata(&path)
            && let Ok(modified) = metadata.modified()
            && modified.elapsed().unwrap_or_default() > Duration::from_secs(6 * 60 * 60)
        {
            let _ = fs::remove_file(&path);
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let _ = writeln!(file, "pid={}", std::process::id());
                Ok(Self { path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(
                AppError::runtime("another advisory database update is already in progress"),
            ),
            Err(error) => Err(runtime_error("create database lock", error)),
        }
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug, Default)]
pub struct UpdateOptions {
    pub force: bool,
    pub years: Option<Vec<u16>>,
    pub quiet: bool,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateSummary {
    pub years: usize,
    pub cve_count: u64,
    pub entry_count: u64,
    pub downloaded: usize,
    pub recent_applied: bool,
}

/// Synchronize the local database with the NVD CVE 2.0 feeds.
pub fn update_database(
    paths: &DbPaths,
    options: &UpdateOptions,
) -> Result<UpdateSummary, AppError> {
    let lock = UpdateLock::acquire(paths)?;
    let mut manifest = load_manifest(paths).unwrap_or_default();
    if manifest.schema != SCHEMA_VERSION {
        manifest = Manifest {
            schema: SCHEMA_VERSION,
            ..Manifest::default()
        };
    }
    fs::create_dir_all(paths.years_dir())
        .map_err(|error| runtime_error("create yearly database directory", error))?;
    fs::create_dir_all(paths.downloads_dir())
        .map_err(|error| runtime_error("create download directory", error))?;

    let current = current_year();
    let full_sync = options.years.is_none();
    let years = options
        .years
        .clone()
        .unwrap_or_else(|| (FIRST_YEAR..=current).collect());
    let agent = feed::agent();
    let mut summary = UpdateSummary::default();

    for &year in &years {
        let kind = year.to_string();
        let meta = feed::fetch_meta(&agent, &kind)?;
        let unchanged = !options.force
            && manifest
                .years
                .get(&year)
                .is_some_and(|state| state.sha256.eq_ignore_ascii_case(&meta.sha256))
            && paths.year_file(year).exists()
            && paths.shard_dir(year).is_dir();
        if unchanged {
            if !options.quiet {
                eprintln!("[db] {year}: up to date");
            }
            continue;
        }

        if !options.quiet {
            eprintln!(
                "[db] {year}: downloading {:.1} MB",
                meta.gz_size as f64 / 1_048_576.0
            );
        }
        let download = feed::download_feed(&agent, &kind, paths)?;
        if let Err(error) = feed::verify_feed(&download, &kind, &meta.sha256) {
            let _ = fs::remove_file(&download);
            return Err(error);
        }
        let mut entries = Vec::new();
        if let Err(error) = feed::read_feed_file(&download, |change| {
            if let feed::Change::Upsert(entry) = change {
                entries.push(entry);
            }
        }) {
            let _ = fs::remove_file(&download);
            return Err(error);
        }

        let mut state = match index::write_year(paths, year, &entries) {
            Ok(state) => state,
            Err(error) => {
                let _ = fs::remove_file(&download);
                return Err(error);
            }
        };
        state.sha256 = meta.sha256;
        state.last_modified = meta.last_modified;
        summary.years += 1;
        summary.downloaded += 1;
        manifest.years.insert(year, state);
        if full_sync {
            manifest.last_full_sync = now_unix();
        }
        manifest.recompute_totals();
        save_manifest(paths, &manifest)?;
        let _ = fs::remove_file(&download);
        if !options.quiet {
            eprintln!(
                "[db] {year}: indexed {} CVEs ({} product mappings)",
                entries.len(),
                manifest
                    .years
                    .get(&year)
                    .map(|s| s.entry_count)
                    .unwrap_or(0)
            );
        }
    }

    // Apply the rolling recent feed so the database is current even when the
    // yearly feed snapshot lags behind intraday changes.
    match feed::fetch_meta(&agent, "recent").and_then(|meta| {
        let unchanged = manifest
            .recent
            .as_ref()
            .is_some_and(|state| state.sha256.eq_ignore_ascii_case(&meta.sha256));
        if unchanged {
            return Ok(false);
        }
        let download = feed::download_feed(&agent, "recent", paths)?;
        let parsed = (|| -> Result<Vec<feed::Change>, AppError> {
            feed::verify_feed(&download, "recent", &meta.sha256)?;
            let mut changes = Vec::new();
            feed::read_feed_file(&download, |change| changes.push(change))?;
            Ok(changes)
        })();
        let _ = fs::remove_file(&download);
        let changes = parsed?;
        index::apply_changes(paths, &mut manifest, &changes)?;
        manifest.recent = Some(RecentState {
            sha256: meta.sha256,
            last_modified: meta.last_modified,
            applied_at: now_unix(),
        });
        manifest.recompute_totals();
        save_manifest(paths, &manifest)?;
        Ok(true)
    }) {
        Ok(applied) => summary.recent_applied = applied,
        Err(error) => {
            if !options.quiet {
                eprintln!("[db] warning: could not apply recent feed: {error}");
            }
        }
    }

    summary.cve_count = manifest.cve_count;
    summary.entry_count = manifest.entry_count;
    drop(lock);
    Ok(summary)
}

/// Lightweight update check run before scans.
///
/// Only the small `recent` feed metadata is requested when the feed is
/// unchanged, and the `recent` feed itself (typically 1-8 MB) is downloaded
/// only when NVD publishes new data.  Network failures never fail a scan.
pub fn auto_update(paths: &DbPaths, quiet: bool, explain_skip: bool) {
    let Some(mut manifest) = load_manifest(paths) else {
        if explain_skip && !quiet {
            eprintln!(
                "[rayscan] local advisory database not initialized; using bundled advisories (run `rayscan db update`)"
            );
        }
        return;
    };

    let agent = feed::agent();
    let meta = match feed::fetch_meta(&agent, "recent") {
        Ok(meta) => meta,
        Err(error) => {
            if explain_skip && !quiet {
                eprintln!(
                    "[rayscan] advisory database check failed ({error}); using local database"
                );
            }
            return;
        }
    };

    let up_to_date = manifest
        .recent
        .as_ref()
        .is_some_and(|state| state.sha256.eq_ignore_ascii_case(&meta.sha256));

    if up_to_date {
        let stale = manifest
            .recent
            .as_ref()
            .map(|state| now_unix().saturating_sub(state.applied_at) > STALE_AFTER_SECS)
            .unwrap_or(true);
        if stale && explain_skip && !quiet {
            eprintln!(
                "[rayscan] advisory database may be stale; run `rayscan db update` for a full refresh"
            );
        }
        return;
    }

    let Ok(_lock) = UpdateLock::acquire(paths) else {
        return;
    };

    let result = (|| -> Result<(), AppError> {
        fs::create_dir_all(paths.years_dir())
            .map_err(|error| runtime_error("create yearly database directory", error))?;
        fs::create_dir_all(paths.downloads_dir())
            .map_err(|error| runtime_error("create download directory", error))?;
        let download = feed::download_feed(&agent, "recent", paths)?;
        let parsed = (|| -> Result<Vec<feed::Change>, AppError> {
            feed::verify_feed(&download, "recent", &meta.sha256)?;
            let mut changes = Vec::new();
            feed::read_feed_file(&download, |change| changes.push(change))?;
            Ok(changes)
        })();
        let _ = fs::remove_file(&download);
        let changes = parsed?;
        index::apply_changes(paths, &mut manifest, &changes)?;
        manifest.recent = Some(RecentState {
            sha256: meta.sha256,
            last_modified: meta.last_modified,
            applied_at: now_unix(),
        });
        manifest.last_auto_check = now_unix();
        manifest.recompute_totals();
        save_manifest(paths, &manifest)
    })();

    match result {
        Ok(()) if !quiet => {
            eprintln!(
                "[rayscan] advisory database updated from NVD ({} CVEs indexed)",
                manifest.cve_count
            );
        }
        Ok(()) => {}
        Err(error) => {
            if explain_skip && !quiet {
                eprintln!(
                    "[rayscan] advisory database update failed ({error}); using local database"
                );
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StatusReport {
    pub path: String,
    pub initialized: bool,
    pub schema: u32,
    pub cve_count: u64,
    pub entry_count: u64,
    pub years: Vec<u16>,
    pub full_years: Vec<u16>,
    pub last_full_sync: u64,
    pub recent_checked: Option<u64>,
    pub recent_modified: Option<String>,
    pub stale: bool,
}

pub fn status(paths: &DbPaths) -> StatusReport {
    match load_manifest(paths) {
        Some(manifest) => {
            let stale = manifest
                .recent
                .as_ref()
                .map(|state| now_unix().saturating_sub(state.applied_at) > STALE_AFTER_SECS)
                .unwrap_or(true);
            StatusReport {
                path: paths.root.display().to_string(),
                initialized: true,
                schema: manifest.schema,
                cve_count: manifest.cve_count,
                entry_count: manifest.entry_count,
                years: manifest.years.keys().copied().collect(),
                full_years: manifest
                    .years
                    .iter()
                    .filter(|(_, state)| !state.sha256.is_empty())
                    .map(|(year, _)| *year)
                    .collect(),
                last_full_sync: manifest.last_full_sync,
                recent_checked: manifest.recent.as_ref().map(|state| state.applied_at),
                recent_modified: manifest
                    .recent
                    .as_ref()
                    .map(|state| state.last_modified.clone()),
                stale,
            }
        }
        None => StatusReport {
            path: paths.root.display().to_string(),
            initialized: false,
            stale: true,
            ..StatusReport::default()
        },
    }
}

pub fn run_cli(
    args: crate::cli::DbArgs,
    db_dir: Option<&Path>,
    theme: Option<crate::theme::Theme>,
) -> Result<(), AppError> {
    use crate::cli::DbAction;
    let _ = theme;
    let paths = DbPaths::resolve(db_dir).ok_or_else(|| {
        AppError::usage(
            "cannot determine a database directory; set RAYSCAN_DB_DIR or pass --db-dir",
        )
    })?;

    match args.action {
        DbAction::Update(options) => {
            let years = options
                .years
                .as_deref()
                .map(|spec| parse_years(spec, current_year()))
                .transpose()?;
            let summary = update_database(
                &paths,
                &UpdateOptions {
                    force: options.force,
                    years,
                    quiet: options.quiet,
                },
            )?;
            if !options.quiet {
                eprintln!(
                    "[db] ready: {} CVEs, {} product mappings, {} yearly feeds updated{}",
                    summary.cve_count,
                    summary.entry_count,
                    summary.years,
                    if summary.recent_applied {
                        " (recent feed applied)"
                    } else {
                        ""
                    }
                );
                eprintln!("[db] location: {}", paths.root.display());
            }
            Ok(())
        }
        DbAction::Status(options) => {
            let report = status(&paths);
            if options.json {
                let json = serde_json::to_string_pretty(&report)
                    .map_err(|error| AppError::runtime(format!("cannot encode status: {error}")))?;
                println!("{json}");
            } else {
                println!("Advisory database: {}", report.path);
                if !report.initialized {
                    println!("  Status:          not initialized");
                    println!("  Initialize with: rayscan db update");
                    return Ok(());
                }
                println!("  Schema:          {}", report.schema);
                println!("  CVEs indexed:    {}", report.cve_count);
                println!("  Product mappings:{}", report.entry_count);
                println!(
                    "  Years indexed:   {} ({}-{})",
                    report.years.len(),
                    report.years.first().copied().unwrap_or(0),
                    report.years.last().copied().unwrap_or(0)
                );
                println!("  Full year feeds: {}", report.full_years.len());
                if report.last_full_sync == 0 {
                    println!("  Last full sync:  never");
                } else {
                    let age = now_unix().saturating_sub(report.last_full_sync);
                    println!("  Last full sync:  {} ago", human_age(age));
                }
                println!(
                    "  Recent changes:  {}",
                    if report.stale {
                        "stale (run `rayscan db update`)".to_string()
                    } else {
                        format!(
                            "current ({})",
                            report.recent_modified.as_deref().unwrap_or("unknown")
                        )
                    }
                );
            }
            Ok(())
        }
    }
}

fn human_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_parser_supports_ranges_lists_and_all() {
        assert_eq!(parse_years("all", 2026).unwrap().len(), 25);
        assert_eq!(
            parse_years("2024-2026", 2026).unwrap(),
            vec![2024, 2025, 2026]
        );
        assert_eq!(parse_years("2026,2024", 2026).unwrap(), vec![2024, 2026]);
        assert!(parse_years("2026-2024", 2026).is_err());
        assert!(parse_years("nope", 2026).is_err());
        assert!(parse_years("2001", 2026).is_err());
        assert!(parse_years("2027", 2026).is_err());
        assert!(parse_years("2001-2003", 2026).is_err());
    }

    #[test]
    fn current_year_is_plausible() {
        assert!(current_year() >= 2024);
    }

    #[test]
    fn cpe_alias_mapping_is_conservative() {
        assert_eq!(cpe_products("Apache"), &["http_server"]);
        assert_eq!(cpe_products("vsFTPd"), &["vsftpd"]);
        assert!(cpe_products("Apache-Coyote").is_empty());
        assert!(cpe_products("ftp").is_empty());
        assert!(cpe_products("http").is_empty());
    }

    #[test]
    fn bucket_is_deterministic_and_bounded() {
        assert_eq!(bucket("http_server"), bucket("http_server"));
        assert_eq!(bucket(""), 0xc5);
    }
}
