//! Sharded lookup index for the local advisory database.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::rc::Rc;

use super::feed::Change;
use super::{
    DbPaths, Manifest, ShardEntry, StoredEntry, VersionRange, YearState, replace_file,
    runtime_error,
};
use crate::advisory::{AdvisoryMatch, Severity, compare_versions, parse_version};
use crate::error::AppError;

/// Write a yearly compact file and rebuild its product shards.
pub fn write_year(
    paths: &DbPaths,
    year: u16,
    entries: &[StoredEntry],
) -> Result<YearState, AppError> {
    fs::create_dir_all(paths.years_dir())
        .map_err(|error| runtime_error("create yearly database directory", error))?;
    let destination = paths.year_file(year);
    let temporary = destination.with_extension("jsonl.tmp");
    {
        let file =
            File::create(&temporary).map_err(|error| runtime_error("create year file", error))?;
        let mut writer = BufWriter::new(file);
        for entry in entries {
            serde_json::to_writer(&mut writer, entry).map_err(|error| {
                AppError::runtime(format!("cannot encode year record: {error}"))
            })?;
            writer
                .write_all(b"\n")
                .map_err(|error| runtime_error("write year record", error))?;
        }
        writer
            .flush()
            .map_err(|error| runtime_error("flush year file", error))?;
    }
    replace_file(&temporary, &destination)
        .map_err(|error| runtime_error("store year file", error))?;
    rebuild_year_shards(paths, year)?;

    Ok(YearState {
        cve_count: entries.len() as u64,
        entry_count: entries
            .iter()
            .map(|entry| entry.affected.len() as u64)
            .sum(),
        ..YearState::default()
    })
}

/// Rebuild all product shards for a year from its compact year file.
pub fn rebuild_year_shards(paths: &DbPaths, year: u16) -> Result<(), AppError> {
    let source = paths.year_file(year);
    let temporary = paths
        .shards_dir()
        .join(format!(".tmp-{year}-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .map_err(|error| runtime_error("clear temporary shard directory", error))?;
    }
    fs::create_dir_all(&temporary)
        .map_err(|error| runtime_error("create temporary shard directory", error))?;

    let mut writers: HashMap<u8, BufWriter<File>> = HashMap::new();
    let file = File::open(&source).map_err(|error| runtime_error("open year file", error))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| runtime_error("read year file", error))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: StoredEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        for affected in &entry.affected {
            let bucket = super::bucket(&affected.product);
            if let std::collections::hash_map::Entry::Vacant(entry) = writers.entry(bucket) {
                let path = temporary.join(format!("{bucket:02x}.jsonl"));
                let file = File::create(&path)
                    .map_err(|error| runtime_error("create shard file", error))?;
                entry.insert(BufWriter::new(file));
            }
            let writer = writers.get_mut(&bucket).expect("writer inserted above");
            let shard = ShardEntry {
                id: entry.id.clone(),
                title: entry.title.clone(),
                cvss: entry.cvss,
                product: affected.product.clone(),
                all_versions: affected.all_versions,
                ranges: affected.ranges.clone(),
            };
            serde_json::to_writer(&mut *writer, &shard).map_err(|error| {
                AppError::runtime(format!("cannot encode shard record: {error}"))
            })?;
            writer
                .write_all(b"\n")
                .map_err(|error| runtime_error("write shard record", error))?;
        }
    }
    for (_, mut writer) in writers {
        writer
            .flush()
            .map_err(|error| runtime_error("flush shard file", error))?;
    }

    let destination = paths.shard_dir(year);
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .map_err(|error| runtime_error("replace shard directory", error))?;
    }
    fs::rename(&temporary, &destination)
        .map_err(|error| runtime_error("store shard directory", error))
}

fn load_year_entries(
    paths: &DbPaths,
    year: u16,
) -> Result<BTreeMap<String, StoredEntry>, AppError> {
    let path = paths.year_file(year);
    let mut entries = BTreeMap::new();
    let Ok(file) = File::open(path) else {
        return Ok(entries);
    };
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| runtime_error("read year file", error))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<StoredEntry>(&line) {
            entries.insert(entry.id.clone(), entry);
        }
    }
    Ok(entries)
}

/// Apply incremental changes from the rolling `recent` feed.
///
/// Only years touched by the changes are rewritten; each affected year's
/// shards are rebuilt from the updated compact file.
pub fn apply_changes(
    paths: &DbPaths,
    manifest: &mut Manifest,
    changes: &[Change],
) -> Result<(), AppError> {
    let mut grouped: BTreeMap<u16, Vec<&Change>> = BTreeMap::new();
    for change in changes {
        let id = match change {
            Change::Upsert(entry) => entry.id.as_str(),
            Change::Remove(id) => id.as_str(),
        };
        if let Some(year) = storage_year(id) {
            grouped.entry(year).or_default().push(change);
        }
    }

    for (year, year_changes) in grouped {
        let mut entries = load_year_entries(paths, year)?;
        for change in year_changes {
            match change {
                Change::Upsert(entry) => {
                    entries.insert(entry.id.clone(), entry.clone());
                }
                Change::Remove(id) => {
                    entries.remove(id);
                }
            }
        }
        let values: Vec<StoredEntry> = entries.into_values().collect();
        let mut state = write_year(paths, year, &values)?;
        if let Some(existing) = manifest.years.get(&year) {
            state.sha256.clone_from(&existing.sha256);
            state.last_modified.clone_from(&existing.last_modified);
        }
        manifest.years.insert(year, state);
    }
    Ok(())
}

/// Year file that owns a CVE record.
///
/// NVD groups all pre-2003 CVEs into the 2002 feed, so recent-feed updates for
/// earlier CVE years must be written back to that same file instead of
/// creating a parallel year file.
fn storage_year(id: &str) -> Option<u16> {
    let rest = id.strip_prefix("CVE-")?;
    let year: u16 = rest.split('-').next()?.parse().ok()?;
    (1999..=2100)
        .contains(&year)
        .then(|| year.max(super::FIRST_YEAR))
}

type ShardCache = HashMap<(u16, u8), Rc<Vec<ShardEntry>>>;

/// Read-only view over the local shard index.
pub struct LocalIndex {
    paths: DbPaths,
    years: Vec<u16>,
    cache: RefCell<ShardCache>,
}

impl LocalIndex {
    /// Load the index when a valid local database is present.
    pub fn load(paths: &DbPaths) -> Option<Self> {
        let manifest = super::load_manifest(paths)?;
        let years: Vec<u16> = manifest
            .years
            .iter()
            .filter(|(year, state)| state.entry_count > 0 && paths.shard_dir(**year).is_dir())
            .map(|(year, _)| *year)
            .collect();
        if years.is_empty() {
            return None;
        }
        Some(Self {
            paths: paths.clone(),
            years,
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// Return NVD advisories matching a detected product and version.
    pub fn advisories_for(&self, product: &str, version: Option<&[u64]>) -> Vec<AdvisoryMatch> {
        let products = super::cpe_products(product);
        if products.is_empty() {
            return Vec::new();
        }

        let mut best: HashMap<String, AdvisoryMatch> = HashMap::new();
        for &cpe_product in products {
            let bucket = super::bucket(cpe_product);
            for &year in &self.years {
                let shard = self.load_shard(year, bucket);
                for entry in shard.iter() {
                    if entry.product != cpe_product || !entry_matches(entry, version) {
                        continue;
                    }
                    let (cisa_kev, epss) = crate::advisory::lookup_threat_intel(&entry.id);
                    let advisory = AdvisoryMatch {
                        id: entry.id.clone(),
                        title: entry.title.clone(),
                        severity: Severity::from_cvss(entry.cvss),
                        cvss: entry.cvss,
                        cisa_kev,
                        epss,
                        source: "nvd",
                    };
                    match best.get_mut(&advisory.id) {
                        Some(existing) => {
                            if advisory.cvss > existing.cvss {
                                *existing = advisory;
                            }
                        }
                        None => {
                            best.insert(advisory.id.clone(), advisory);
                        }
                    }
                }
            }
        }
        best.into_values().collect()
    }

    fn load_shard(&self, year: u16, bucket: u8) -> Rc<Vec<ShardEntry>> {
        if let Some(cached) = self.cache.borrow().get(&(year, bucket)) {
            return Rc::clone(cached);
        }
        let path = self
            .paths
            .shard_dir(year)
            .join(format!("{bucket:02x}.jsonl"));
        let mut entries = Vec::new();
        if let Ok(file) = File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<ShardEntry>(&line) {
                    entries.push(entry);
                }
            }
        }
        let entries = Rc::new(entries);
        self.cache
            .borrow_mut()
            .insert((year, bucket), Rc::clone(&entries));
        entries
    }
}

fn entry_matches(entry: &ShardEntry, version: Option<&[u64]>) -> bool {
    if entry.all_versions {
        return true;
    }
    let Some(version) = version else {
        return false;
    };
    entry
        .ranges
        .iter()
        .any(|range| range_matches(range, version))
}

fn range_matches(range: &VersionRange, detected: &[u64]) -> bool {
    if let Some(value) = &range.start_incl {
        match parse_version(value) {
            Some(bound) if compare_versions(detected, &bound).is_ge() => {}
            _ => return false,
        }
    }
    if let Some(value) = &range.start_excl {
        match parse_version(value) {
            Some(bound) if compare_versions(detected, &bound).is_gt() => {}
            _ => return false,
        }
    }
    if let Some(value) = &range.end_incl {
        match parse_version(value) {
            Some(bound) if compare_versions(detected, &bound).is_le() => {}
            _ => return false,
        }
    }
    if let Some(value) = &range.end_excl {
        match parse_version(value) {
            Some(bound) if compare_versions(detected, &bound).is_lt() => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AffectedProduct, Manifest};

    struct TempDb {
        paths: DbPaths,
    }

    impl TempDb {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "rayscan-db-{name}-{}-{}",
                std::process::id(),
                crate::db::now_unix()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self {
                paths: DbPaths::at(root),
            }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.paths.root);
        }
    }

    fn entry(id: &str, products: Vec<AffectedProduct>) -> StoredEntry {
        StoredEntry {
            id: id.to_string(),
            title: format!("{id} title"),
            cvss: 9.8,
            affected: products,
        }
    }

    fn write_manifest(paths: &DbPaths, entries: &[StoredEntry]) {
        let mut manifest = Manifest {
            schema: crate::db::SCHEMA_VERSION,
            ..Manifest::default()
        };
        let state = YearState {
            cve_count: entries.len() as u64,
            entry_count: entries.iter().map(|e| e.affected.len() as u64).sum(),
            ..YearState::default()
        };
        manifest.years.insert(2024, state);
        manifest.cve_count = entries.len() as u64;
        manifest.entry_count = entries.iter().map(|e| e.affected.len() as u64).sum();
        crate::db::save_manifest(paths, &manifest).unwrap();
    }

    #[test]
    fn index_matches_products_and_versions() {
        let db = TempDb::new("match");
        let entries = vec![
            entry(
                "CVE-2024-0001",
                vec![AffectedProduct {
                    product: "http_server".to_string(),
                    all_versions: false,
                    ranges: vec![VersionRange {
                        start_incl: Some("2.4.49".to_string()),
                        start_excl: None,
                        end_incl: Some("2.4.49".to_string()),
                        end_excl: None,
                    }],
                }],
            ),
            entry(
                "CVE-2024-0002",
                vec![AffectedProduct {
                    product: "vsftpd".to_string(),
                    all_versions: true,
                    ranges: Vec::new(),
                }],
            ),
        ];
        write_year(&db.paths, 2024, &entries).unwrap();
        write_manifest(&db.paths, &entries);

        let index = LocalIndex::load(&db.paths).expect("index loads");
        let apache = index.advisories_for("Apache", parse_version("2.4.49").as_deref());
        assert_eq!(apache.len(), 1);
        assert_eq!(apache[0].id, "CVE-2024-0001");
        assert_eq!(apache[0].source, "nvd");

        let patched = index.advisories_for("Apache", parse_version("2.4.50").as_deref());
        assert!(patched.is_empty());
        let coyote = index.advisories_for("Apache-Coyote", None);
        assert!(coyote.is_empty());

        let vsftpd = index.advisories_for("vsFTPd", parse_version("3.0.5").as_deref());
        assert_eq!(vsftpd.len(), 1);
        assert_eq!(vsftpd[0].id, "CVE-2024-0002");
    }

    #[test]
    fn recent_changes_replace_and_remove_records() {
        let db = TempDb::new("recent");
        let entries = vec![entry(
            "CVE-2024-0001",
            vec![AffectedProduct {
                product: "openssh".to_string(),
                all_versions: false,
                ranges: vec![VersionRange {
                    start_incl: Some("4.0".to_string()),
                    start_excl: None,
                    end_incl: None,
                    end_excl: Some("5.0".to_string()),
                }],
            }],
        )];
        write_year(&db.paths, 2024, &entries).unwrap();
        write_manifest(&db.paths, &entries);

        let mut manifest = crate::db::load_manifest(&db.paths).unwrap();
        let changes = vec![
            Change::Upsert(entry(
                "CVE-2024-0001",
                vec![AffectedProduct {
                    product: "openssh".to_string(),
                    all_versions: true,
                    ranges: Vec::new(),
                }],
            )),
            Change::Upsert(entry(
                "CVE-2024-0003",
                vec![AffectedProduct {
                    product: "samba".to_string(),
                    all_versions: true,
                    ranges: Vec::new(),
                }],
            )),
        ];
        apply_changes(&db.paths, &mut manifest, &changes).unwrap();

        let index = LocalIndex::load(&db.paths).expect("index loads");
        let ssh = index.advisories_for("OpenSSH", parse_version("9.0").as_deref());
        assert_eq!(ssh.len(), 1);
        assert!(ssh[0].title.contains("CVE-2024-0001"));

        let mut manifest = crate::db::load_manifest(&db.paths).unwrap();
        apply_changes(
            &db.paths,
            &mut manifest,
            &[Change::Remove("CVE-2024-0001".to_string())],
        )
        .unwrap();
        let index = LocalIndex::load(&db.paths).expect("index loads");
        assert!(
            index
                .advisories_for("OpenSSH", parse_version("9.0").as_deref())
                .is_empty()
        );
    }

    #[test]
    fn range_bounds_are_inclusive_and_exclusive() {
        let inclusive = VersionRange {
            start_incl: Some("1.0".to_string()),
            start_excl: None,
            end_incl: Some("1.2".to_string()),
            end_excl: None,
        };
        assert!(range_matches(&inclusive, &[1, 0]));
        assert!(range_matches(&inclusive, &[1, 2]));
        assert!(!range_matches(&inclusive, &[1, 3]));

        let exclusive = VersionRange {
            start_incl: None,
            start_excl: Some("1.0".to_string()),
            end_incl: None,
            end_excl: Some("2.0".to_string()),
        };
        assert!(!range_matches(&exclusive, &[1, 0]));
        assert!(range_matches(&exclusive, &[1, 5]));
        assert!(!range_matches(&exclusive, &[2, 0]));
    }

    #[test]
    fn storage_year_clamps_pre_2003_records() {
        assert_eq!(storage_year("CVE-1999-0001"), Some(2002));
        assert_eq!(storage_year("CVE-2002-1234"), Some(2002));
        assert_eq!(storage_year("CVE-2026-0001"), Some(2026));
        assert_eq!(storage_year("not-a-cve"), None);
    }
}
