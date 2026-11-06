//! Resumable scan state — save and restore interrupted scans.
//!
//! When a scan is interrupted (Ctrl-C) or completes normally, the caller may
//! write a JSON state file via [`save_state`].  On the next invocation the
//! user passes `--resume <FILE>` to load the state, subtract already-scanned
//! ports from the full list, run only the remaining ports, and merge the
//! results together before output.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::model::{PortResult, PortState, ScanReport, StateCounts};
use crate::service::ServiceInfo;

/// Version tag written into every state file.
const STATE_VERSION: u32 = 1;

// ── Serialisable sub-types ────────────────────────────────────────────────────

/// Serialisable form of [`StateCounts`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedCounts {
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub silent: u64,
    pub unreachable: u64,
    pub error: u64,
}

impl From<StateCounts> for SavedCounts {
    fn from(c: StateCounts) -> Self {
        Self {
            open: c.open,
            closed: c.closed,
            filtered: c.filtered,
            silent: c.silent,
            unreachable: c.unreachable,
            error: c.error,
        }
    }
}

impl From<SavedCounts> for StateCounts {
    fn from(c: SavedCounts) -> Self {
        Self {
            open: c.open,
            closed: c.closed,
            filtered: c.filtered,
            silent: c.silent,
            unreachable: c.unreachable,
            error: c.error,
        }
    }
}

/// Serialisable form of a single port result, used inside the state file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedResult {
    pub host: String,
    pub port: u16,
    pub state: String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

impl From<&PortResult> for SavedResult {
    fn from(r: &PortResult) -> Self {
        let service = r.service.as_ref().map(|s| {
            let mut label = s.name.clone();
            if let Some(p) = &s.product {
                label.push(' ');
                label.push_str(p);
            }
            if let Some(v) = &s.version {
                label.push('/');
                label.push_str(v);
            }
            label
        });
        Self {
            host: r.host.to_string(),
            port: r.port,
            state: r.state.as_str().to_string(),
            latency_ms: r.latency.as_secs_f64() * 1000.0,
            service,
            service_name: r.service.as_ref().map(|s| s.name.clone()),
            service_product: r.service.as_ref().and_then(|s| s.product.clone()),
            service_version: r.service.as_ref().and_then(|s| s.version.clone()),
            banner: r.banner.clone(),
        }
    }
}

// ── Main state struct ─────────────────────────────────────────────────────────

/// The on-disk representation of an interrupted or completed scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanState {
    /// Format version; always 1.
    pub version: u32,
    /// Human-readable label of the scan target(s).
    pub target_label: String,
    /// Original ports specification string (e.g. `"1-65535"`).
    pub ports_spec: String,
    /// Every port index that was **probed** (regardless of outcome).
    /// Used to compute remaining ports on resume.
    pub ports_scanned: Vec<u16>,
    /// Only the results the scan retained (open / requested states).
    pub results: Vec<SavedResult>,
    /// Aggregate counts at the time of saving.
    pub counts: SavedCounts,
    /// Wall-clock elapsed time in milliseconds.
    pub elapsed_ms: f64,
    /// True when the state was written from an interrupted scan.
    pub partial: bool,
    /// ISO-8601 timestamp when the state was saved.
    pub timestamp: String,
}

impl ScanState {
    /// Build a [`ScanState`] from a completed or partial [`ScanReport`].
    pub fn from_report(
        report: &ScanReport,
        target_label: &str,
        ports_spec: &str,
        ports_scanned: Vec<u16>,
    ) -> Self {
        let results: Vec<SavedResult> = report.results.iter().map(SavedResult::from).collect();
        let timestamp = chrono_now();
        Self {
            version: STATE_VERSION,
            target_label: target_label.to_string(),
            ports_spec: ports_spec.to_string(),
            ports_scanned,
            results,
            counts: SavedCounts::from(report.counts),
            elapsed_ms: report.elapsed.as_secs_f64() * 1000.0,
            partial: report.partial,
            timestamp,
        }
    }
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

/// Serialise and write a [`ScanState`] to `path` (creates / overwrites).
pub fn save_state(path: &Path, state: &ScanState) -> Result<(), AppError> {
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| AppError::runtime(format!("failed to serialise scan state: {e}")))?;
    std::fs::write(path, json).map_err(|e| {
        AppError::runtime(format!(
            "failed to write state file {}: {e}",
            path.display()
        ))
    })
}

/// Read and deserialise a [`ScanState`] from `path`.
pub fn load_state(path: &Path) -> Result<ScanState, AppError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        AppError::runtime(format!("cannot read state file {}: {e}", path.display()))
    })?;
    let state: ScanState = serde_json::from_str(&data).map_err(|e| {
        AppError::runtime(format!(
            "state file {} is not valid rayscan state ({})",
            path.display(),
            e
        ))
    })?;
    if state.version != STATE_VERSION {
        return Err(AppError::runtime(format!(
            "state file version {} is not supported (expected {})",
            state.version, STATE_VERSION
        )));
    }
    Ok(state)
}

/// Return the ports from `all_ports` that are **not** in `already_scanned`.
/// Preserves the original order of `all_ports`.
pub fn remaining_ports(all_ports: &[u16], already_scanned: &[u16]) -> Vec<u16> {
    let done: HashSet<u16> = already_scanned.iter().copied().collect();
    all_ports
        .iter()
        .copied()
        .filter(|p| !done.contains(p))
        .collect()
}

/// Restore saved [`PortResult`]s from a [`ScanState`] into a Vec compatible
/// with the in-memory model.  Service info is preserved as-is in the banner
/// field because the full service struct cannot be round-tripped through the
/// compact saved form.
pub fn restore_results(state: &ScanState) -> (Vec<PortResult>, StateCounts) {
    let mut counts = StateCounts::from(state.counts.clone());
    let results: Vec<PortResult> = state
        .results
        .iter()
        .filter_map(|r| {
            let host: IpAddr = r.host.parse().ok()?;
            let state_val = match r.state.as_str() {
                "open" => PortState::Open,
                "closed" => PortState::Closed,
                "filtered" => PortState::Filtered,
                "silent" => PortState::Silent,
                "unreachable" => PortState::Unreachable,
                _ => PortState::Error,
            };
            let latency = std::time::Duration::from_secs_f64(r.latency_ms / 1000.0);
            let mut result = PortResult::new(host, r.port, state_val, latency);
            if let Some(name) = &r.service_name {
                result.service = Some(ServiceInfo {
                    name: name.clone(),
                    product: r.service_product.clone(),
                    version: r.service_version.clone(),
                });
            }
            if r.banner.is_some() || r.service.is_some() {
                result.banner = r.banner.clone().or_else(|| r.service.clone());
            }
            Some(result)
        })
        .collect();
    // Recompute counts from the restored results to avoid double-counting
    // since we merge these with the new scan's counts later.
    counts.open = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .count() as u64;
    counts.closed = results
        .iter()
        .filter(|r| r.state == PortState::Closed)
        .count() as u64;
    counts.filtered = results
        .iter()
        .filter(|r| r.state == PortState::Filtered)
        .count() as u64;
    counts.silent = results
        .iter()
        .filter(|r| r.state == PortState::Silent)
        .count() as u64;
    counts.unreachable = results
        .iter()
        .filter(|r| r.state == PortState::Unreachable)
        .count() as u64;
    counts.error = results
        .iter()
        .filter(|r| r.state == PortState::Error)
        .count() as u64;
    (results, counts)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return current UTC time in ISO-8601 format without depending on `chrono`.
fn chrono_now() -> String {
    // Use CLOCK_REALTIME via std; format manually.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Minimal ISO-8601 formatter: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;
    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Gregorian calendar computation.
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    y.is_multiple_of(400) || (y.is_multiple_of(4) && !y.is_multiple_of(100))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_ports_subtracts_scanned() {
        let all: Vec<u16> = (1..=10).collect();
        let scanned: Vec<u16> = vec![1, 2, 3, 5];
        let remaining = remaining_ports(&all, &scanned);
        assert_eq!(remaining, vec![4, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn remaining_ports_nothing_scanned() {
        let all: Vec<u16> = vec![22, 80, 443];
        let remaining = remaining_ports(&all, &[]);
        assert_eq!(remaining, vec![22, 80, 443]);
    }

    #[test]
    fn remaining_ports_all_scanned() {
        let all: Vec<u16> = vec![22, 80, 443];
        let remaining = remaining_ports(&all, &[22, 80, 443]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        use crate::model::{PortResult, PortState};
        use std::collections::HashMap;
        use std::time::Duration;

        let host: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let report = ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(500),
            counts: StateCounts {
                open: 1,
                closed: 1,
                filtered: 1,
                ..StateCounts::default()
            },
            results: vec![
                PortResult::new(host, 22, PortState::Open, Duration::from_millis(5)),
                PortResult::new(host, 23, PortState::Closed, Duration::from_millis(1)),
            ],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![22, 23],
            partial: true,
        };

        let state = ScanState::from_report(&report, "192.0.2.1", "1-100", vec![22, 23]);
        assert_eq!(state.version, 1);
        assert_eq!(state.ports_scanned, vec![22, 23]);
        assert!(state.partial);

        let dir = std::env::temp_dir();
        let path = dir.join("rayscan-test-state.json");
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.ports_scanned, vec![22, 23]);
        assert_eq!(loaded.results.len(), 2);
        assert_eq!(loaded.results[0].port, 22);
        assert_eq!(loaded.results[0].state, "open");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn restore_results_counts_match() {
        use crate::model::{PortResult, PortState};
        use std::collections::HashMap;
        use std::time::Duration;

        let host: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let report = ScanReport {
            targets: 1,
            ports: 2,
            jobs: 2,
            workers: 1,
            elapsed: Duration::from_millis(100),
            counts: StateCounts {
                open: 1,
                closed: 1,
                ..StateCounts::default()
            },
            results: vec![
                PortResult::new(host, 80, PortState::Open, Duration::from_millis(2)),
                PortResult::new(host, 81, PortState::Closed, Duration::from_millis(1)),
            ],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![80, 81],
            partial: false,
        };
        let state = ScanState::from_report(&report, "10.0.0.1", "80-81", vec![80, 81]);
        let (results, counts) = restore_results(&state);
        assert_eq!(results.len(), 2);
        assert_eq!(counts.open, 1);
        assert_eq!(counts.closed, 1);
    }

    #[test]
    fn restore_preserves_structured_service_metadata() {
        use crate::model::{PortResult, PortState};
        use std::collections::HashMap;
        use std::time::Duration;

        let host: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let mut ftp = PortResult::new(host, 21, PortState::Open, Duration::from_millis(1));
        ftp.service = Some(ServiceInfo {
            name: "ftp".to_string(),
            product: Some("vsFTPd".to_string()),
            version: Some("2.3.4".to_string()),
        });
        ftp.banner = Some("220 (vsFTPd 2.3.4)".to_string());

        let report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(1),
            counts: StateCounts {
                open: 1,
                ..StateCounts::default()
            },
            results: vec![ftp],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![21],
            partial: true,
        };
        let state = ScanState::from_report(&report, "192.0.2.10", "21", vec![21]);
        let (results, _) = restore_results(&state);
        let service = results[0].service.as_ref().expect("service metadata");
        assert_eq!(service.name, "ftp");
        assert_eq!(service.product.as_deref(), Some("vsFTPd"));
        assert_eq!(service.version.as_deref(), Some("2.3.4"));
    }
}
