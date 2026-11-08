//! Merge independent scan reports produced by sharded/distributed scans.
//!
//! Results are deduplicated by `(host, port)`: an open result wins over any
//! non-open state, and ties keep the result with the higher confidence.  The
//! merged document uses the same JSON schema as `rayscan scan --json`, so it
//! can feed `--diff`, SIEM ingestion, or the Markdown/SARIF renderers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::cli::MergeArgs;
use crate::error::AppError;

#[derive(Default)]
struct MergedReport {
    results: BTreeMap<(String, u64), Value>,
    targets: u64,
    ports: u64,
    jobs: u64,
    workers: u64,
    elapsed_ms: f64,
    os_fingerprints: Map<String, Value>,
    defense: Map<String, Value>,
    include_results: bool,
    summary_sum: StateTotals,
    summary_adjust: StateTotals,
    counted: StateTotals,
    saw_summary: bool,
    saw_jsonl: bool,
}

#[derive(Default, Clone, Copy)]
struct StateTotals {
    open: i64,
    closed: i64,
    filtered: i64,
    silent: i64,
    unreachable: i64,
    error: i64,
}

impl StateTotals {
    fn add(&mut self, state: &str) {
        match state {
            "open" => self.open += 1,
            "closed" => self.closed += 1,
            "filtered" => self.filtered += 1,
            "silent" => self.silent += 1,
            "unreachable" => self.unreachable += 1,
            _ => self.error += 1,
        }
    }

    fn remove(&mut self, state: &str) {
        match state {
            "open" => self.open -= 1,
            "closed" => self.closed -= 1,
            "filtered" => self.filtered -= 1,
            "silent" => self.silent -= 1,
            "unreachable" => self.unreachable -= 1,
            _ => self.error -= 1,
        }
    }

    fn add_other(&mut self, other: &Self) {
        self.open += other.open;
        self.closed += other.closed;
        self.filtered += other.filtered;
        self.silent += other.silent;
        self.unreachable += other.unreachable;
        self.error += other.error;
    }

    fn as_json(self) -> Value {
        json!({
            "open": self.open.max(0),
            "closed": self.closed.max(0),
            "filtered": self.filtered.max(0),
            "silent": self.silent.max(0),
            "unreachable": self.unreachable.max(0),
            "error": self.error.max(0),
        })
    }
}

pub fn run_cli(args: MergeArgs) -> Result<(), AppError> {
    if args.inputs.is_empty() {
        return Err(AppError::usage("merge requires at least one input report"));
    }

    let mut merged = MergedReport::default();
    for path in &args.inputs {
        merge_file(path, &mut merged)?;
    }

    let output = if args.jsonl {
        let mut lines = String::new();
        for value in merged.results.values() {
            lines.push_str(
                &serde_json::to_string(value)
                    .map_err(|error| AppError::runtime(format!("cannot encode JSON: {error}")))?,
            );
            lines.push('\n');
        }
        lines
    } else {
        let mut json = serde_json::to_string_pretty(&render_report(&merged))
            .map_err(|error| AppError::runtime(format!("cannot encode JSON: {error}")))?;
        json.push('\n');
        json
    };

    match args.output.as_deref() {
        Some(path) if path.as_os_str() != "-" => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|error| {
                    AppError::runtime(format!(
                        "cannot create output directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            std::fs::write(path, output).map_err(|error| {
                AppError::runtime(format!("cannot write {}: {error}", path.display()))
            })?;
            eprintln!("wrote {}", path.display());
        }
        _ => {
            print!("{output}");
        }
    }
    Ok(())
}

fn merge_file(path: &Path, merged: &mut MergedReport) -> Result<(), AppError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| AppError::runtime(format!("cannot read {}: {error}", path.display())))?;

    if let Ok(value) = serde_json::from_str::<Value>(&contents) {
        merge_value(value, merged, path)?;
        return Ok(());
    }

    let mut parsed_any = false;
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|error| {
            AppError::usage(format!(
                "invalid JSONL in {} at line {}: {error}",
                path.display(),
                line_number + 1
            ))
        })?;
        parsed_any = true;
        merged.saw_jsonl = true;
        insert_result(&value, merged);
    }

    if !parsed_any {
        return Err(AppError::usage(format!(
            "{} is not a rayscan JSON or JSONL report",
            path.display()
        )));
    }
    let unique_hosts = merged
        .results
        .keys()
        .map(|(host, _)| host.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u64;
    merged.targets = merged.targets.max(unique_hosts);
    Ok(())
}

fn merge_value(value: Value, merged: &mut MergedReport, path: &Path) -> Result<(), AppError> {
    let object = value.as_object().ok_or_else(|| {
        AppError::usage(format!("{} is not a rayscan report object", path.display()))
    })?;

    if object.contains_key("version") && object.contains_key("ports_scanned") {
        return Err(AppError::usage(format!(
            "{} is a resume state file; merge expects scan JSON reports",
            path.display()
        )));
    }

    let has_open = object.get("open").is_some_and(Value::is_array);
    let has_results = object.get("results").is_some_and(Value::is_array);
    if !has_open && !has_results {
        return Err(AppError::usage(format!(
            "{} contains neither 'open' nor 'results' arrays",
            path.display()
        )));
    }

    if has_results {
        merged.include_results = true;
        for result in object["results"].as_array().into_iter().flatten() {
            insert_result(result, merged);
        }
    } else if let Some(open) = object.get("open").and_then(Value::as_array) {
        for result in open {
            insert_result(result, merged);
        }
    }

    merged.targets += object.get("targets").and_then(Value::as_u64).unwrap_or(0);
    merged.ports = merged
        .ports
        .max(object.get("ports").and_then(Value::as_u64).unwrap_or(0));
    merged.jobs += object.get("jobs").and_then(Value::as_u64).unwrap_or(0);
    merged.workers = merged
        .workers
        .max(object.get("workers").and_then(Value::as_u64).unwrap_or(0));
    merged.elapsed_ms += object
        .get("elapsed_ms")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);

    if let Some(summary) = object.get("summary").and_then(Value::as_object) {
        merged.saw_summary = true;
        let totals = StateTotals {
            open: summary.get("open").and_then(Value::as_i64).unwrap_or(0),
            closed: summary.get("closed").and_then(Value::as_i64).unwrap_or(0),
            filtered: summary.get("filtered").and_then(Value::as_i64).unwrap_or(0),
            silent: summary.get("silent").and_then(Value::as_i64).unwrap_or(0),
            unreachable: summary
                .get("unreachable")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            error: summary.get("error").and_then(Value::as_i64).unwrap_or(0),
        };
        merged.summary_sum.add_other(&totals);
    }

    for key in ["os_fingerprints", "defense"] {
        if let Some(map) = object.get(key).and_then(Value::as_object) {
            let target = if key == "os_fingerprints" {
                &mut merged.os_fingerprints
            } else {
                &mut merged.defense
            };
            for (host, value) in map {
                target.insert(host.clone(), value.clone());
            }
        }
    }

    Ok(())
}

fn insert_result(value: &Value, merged: &mut MergedReport) {
    let Some(host) = value.get("host").and_then(Value::as_str) else {
        return;
    };
    let Some(port) = value.get("port").and_then(Value::as_u64) else {
        return;
    };

    let key = (host.to_string(), port);
    match merged.results.get_mut(&key) {
        None => {
            merged.counted.add(state_of(value));
            merged.results.insert(key, value.clone());
        }
        Some(existing) => {
            let keep_new = prefer(value, existing);
            if keep_new {
                merged.counted.remove(state_of(existing));
                merged.counted.add(state_of(value));
                merged.summary_adjust.remove(state_of(existing));
                let mut replacement = value.clone();
                merge_advisories(&mut replacement, existing);
                *existing = replacement;
            } else {
                merged.summary_adjust.remove(state_of(value));
                merge_advisories(existing, value);
            }
        }
    }
}

fn state_of(value: &Value) -> &str {
    value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("error")
}

fn state_rank(state: &str) -> u8 {
    match state {
        "open" => 5,
        "silent" => 4,
        "filtered" => 3,
        "unreachable" => 2,
        "closed" => 1,
        _ => 0,
    }
}

fn prefer(new: &Value, old: &Value) -> bool {
    let new_rank = state_rank(state_of(new));
    let old_rank = state_rank(state_of(old));
    if new_rank != old_rank {
        return new_rank > old_rank;
    }
    let confidence = |value: &Value| {
        value
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
    };
    confidence(new) > confidence(old)
}

fn merge_advisories(kept: &mut Value, other: &Value) {
    let Some(kept_object) = kept.as_object_mut() else {
        return;
    };
    let mut advisories: Vec<Value> = kept_object
        .get("advisories")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut seen: BTreeSet<String> = advisories
        .iter()
        .filter_map(|advisory| advisory.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();

    for advisory in other
        .get("advisories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = advisory
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if seen.insert(id) {
            advisories.push(advisory.clone());
        }
    }
    if !advisories.is_empty() {
        kept_object.insert("advisories".to_string(), Value::Array(advisories));
    }
}

fn render_report(merged: &MergedReport) -> Value {
    let mut results: Vec<&Value> = merged.results.values().collect();
    results.sort_by(|left, right| {
        let left_host = left.get("host").and_then(Value::as_str).unwrap_or("");
        let right_host = right.get("host").and_then(Value::as_str).unwrap_or("");
        left_host.cmp(right_host).then_with(|| {
            left.get("port")
                .and_then(Value::as_u64)
                .cmp(&right.get("port").and_then(Value::as_u64))
        })
    });

    let open: Vec<Value> = results
        .iter()
        .filter(|value| state_of(value) == "open")
        .map(|value| (*value).clone())
        .collect();

    let unique_hosts: BTreeSet<&str> = results
        .iter()
        .filter_map(|value| value.get("host").and_then(Value::as_str))
        .collect();
    let unique_ports: BTreeSet<u64> = results
        .iter()
        .filter_map(|value| value.get("port").and_then(Value::as_u64))
        .collect();

    let summary = if merged.saw_summary && !merged.saw_jsonl {
        let mut totals = merged.summary_sum;
        totals.add_other(&merged.summary_adjust);
        totals.as_json()
    } else {
        merged.counted.as_json()
    };

    let mut object = Map::new();
    object.insert("target".to_string(), json!("merged"));
    object.insert(
        "targets".to_string(),
        json!(if merged.targets > 0 {
            merged.targets
        } else {
            unique_hosts.len() as u64
        }),
    );
    object.insert(
        "ports".to_string(),
        json!(if merged.ports > 0 {
            merged.ports
        } else {
            unique_ports.len() as u64
        }),
    );
    object.insert(
        "jobs".to_string(),
        json!(if merged.jobs > 0 {
            merged.jobs
        } else {
            results.len() as u64
        }),
    );
    object.insert("workers".to_string(), json!(merged.workers.max(1)));
    object.insert("open".to_string(), Value::Array(open));
    if merged.include_results || merged.saw_jsonl {
        object.insert(
            "results".to_string(),
            Value::Array(results.iter().map(|value| (*value).clone()).collect()),
        );
    }
    if !merged.os_fingerprints.is_empty() {
        object.insert(
            "os_fingerprints".to_string(),
            Value::Object(merged.os_fingerprints.clone()),
        );
    }
    if !merged.defense.is_empty() {
        object.insert("defense".to_string(), Value::Object(merged.defense.clone()));
    }
    object.insert("summary".to_string(), summary);
    object.insert("elapsed_ms".to_string(), json!(merged.elapsed_ms));
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rayscan-merge-{}-{}-{name}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn report(results: Value, closed: i64) -> Value {
        let open = results.as_array().map_or(0, Vec::len);
        json!({
            "target": "shard",
            "targets": 2,
            "ports": 2,
            "jobs": 4,
            "workers": 8,
            "open": results,
            "summary": {"open": open, "closed": closed, "filtered": 0, "silent": 0, "unreachable": 0, "error": 0},
            "elapsed_ms": 12.0
        })
    }

    #[test]
    fn merges_disjoint_shards_and_recomputes_totals() {
        let first = report(
            json!([
                {"host": "192.0.2.1", "port": 80, "state": "open", "confidence": 0.9, "service": {"name": "http"}},
                {"host": "192.0.2.2", "port": 80, "state": "open", "confidence": 0.9}
            ]),
            2,
        );
        let second = report(
            json!([
                {"host": "192.0.2.3", "port": 22, "state": "open", "confidence": 0.9}
            ]),
            3,
        );
        let first_path = temp_path("a");
        let second_path = temp_path("b");
        std::fs::write(&first_path, first.to_string()).unwrap();
        std::fs::write(&second_path, second.to_string()).unwrap();

        let mut merged = MergedReport::default();
        merge_file(&first_path, &mut merged).unwrap();
        merge_file(&second_path, &mut merged).unwrap();
        let rendered = render_report(&merged);

        assert_eq!(rendered["open"].as_array().unwrap().len(), 3);
        assert!(rendered.get("results").is_none());
        assert_eq!(rendered["summary"]["open"], 3);
        assert_eq!(rendered["summary"]["closed"], 5);
        assert_eq!(rendered["targets"], 4);
        assert_eq!(rendered["ports"], 2);

        let _ = std::fs::remove_file(first_path);
        let _ = std::fs::remove_file(second_path);
    }

    #[test]
    fn duplicate_open_results_are_deduplicated_and_advisories_union() {
        let first = report(
            json!([
                {"host": "192.0.2.1", "port": 80, "state": "open", "confidence": 0.7,
                 "advisories": [{"id": "CVE-2024-0001"}]}
            ]),
            0,
        );
        let second = report(
            json!([
                {"host": "192.0.2.1", "port": 80, "state": "open", "confidence": 0.95,
                 "advisories": [{"id": "CVE-2024-0002"}]}
            ]),
            0,
        );
        let first_path = temp_path("c");
        let second_path = temp_path("d");
        std::fs::write(&first_path, first.to_string()).unwrap();
        std::fs::write(&second_path, second.to_string()).unwrap();

        let mut merged = MergedReport::default();
        merge_file(&first_path, &mut merged).unwrap();
        merge_file(&second_path, &mut merged).unwrap();
        let rendered = render_report(&merged);
        let open = rendered["open"].as_array().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["confidence"], 0.95);
        assert_eq!(open[0]["advisories"].as_array().unwrap().len(), 2);
        assert_eq!(rendered["summary"]["open"], 1);

        let _ = std::fs::remove_file(first_path);
        let _ = std::fs::remove_file(second_path);
    }

    #[test]
    fn open_result_wins_over_non_open_duplicate() {
        let mut merged = MergedReport::default();
        insert_result(
            &json!({"host": "192.0.2.1", "port": 80, "state": "closed"}),
            &mut merged,
        );
        insert_result(
            &json!({"host": "192.0.2.1", "port": 80, "state": "open"}),
            &mut merged,
        );
        let rendered = render_report(&merged);
        assert_eq!(rendered["open"].as_array().unwrap().len(), 1);
        assert_eq!(rendered["summary"]["open"], 1);
        assert_eq!(rendered["summary"]["closed"], 0);
    }
}
