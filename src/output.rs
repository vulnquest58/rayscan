use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

use clap::ValueEnum;
use comfy_table::{Attribute, Cell, ColumnConstraint, ContentArrangement, Table, Width};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::fingerprint::OsGuess;
use crate::model::{PortResult, PortState, ScanReport, StateCounts, StateSet};
use crate::service::ServiceInfo;
use crate::theme::{Theme, color_enabled};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Table,
    Json,
    Jsonl,
    Csv,
    /// Nmap-compatible XML output (compatible with nmap parsers / Metasploit).
    #[value(name = "nmap-xml")]
    NmapXml,
    /// Greppable output — one line per host, Nmap -oG style.
    #[value(name = "greppable")]
    Greppable,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
            Self::NmapXml => "nmap-xml",
            Self::Greppable => "greppable",
        }
    }
}

/// Options controlling scan report formatting and emission.
#[derive(Clone, Copy, Debug)]
pub struct EmitOptions<'a> {
    pub format: OutputFormat,
    pub show: StateSet,
    pub destination: Option<&'a Path>,
    pub quiet: bool,
    pub theme: Theme,
    pub streamed: bool,
    pub min_confidence: Option<u8>,
    pub explain: Option<u16>,
    pub defense: bool,
}

pub fn emit(report: &ScanReport, target: &str, options: EmitOptions<'_>) -> Result<(), AppError> {
    let min_conf_ratio = options.min_confidence.map(|c| (c as f32) / 100.0);
    let mut selected: Vec<&PortResult> = report
        .results
        .iter()
        .filter(|result| {
            if !options.show.contains(result.state) {
                return false;
            }
            if let Some(min) = min_conf_ratio
                && result.confidence.unwrap_or(1.0) < min
            {
                return false;
            }
            true
        })
        .collect();
    selected.sort_by(|left, right| compare_results(left, right));

    let stdout_is_tty = std::io::stdout().is_terminal();
    let contents = match options.format {
        OutputFormat::Table => render_table(
            report,
            &selected,
            options.theme,
            color_enabled(options.theme, stdout_is_tty) && options.destination.is_none(),
            stdout_is_tty,
            options.explain,
            options.defense,
        ),
        OutputFormat::Json => render_json(report, target, options.show, options.min_confidence)?,
        OutputFormat::Jsonl => render_jsonl(&selected)?,
        OutputFormat::Csv => render_csv(&selected),
        OutputFormat::NmapXml => render_nmap_xml(report, target, &selected),
        OutputFormat::Greppable => render_greppable(target, &selected),
    };

    if let Some(path) = options.destination {
        return write_destination(Some(path), &contents, options.quiet);
    }

    if options.streamed && options.format == OutputFormat::Table && stdout_is_tty {
        // Results were already streamed live to stdout. Output the summary footer & findings.
        println!(
            "{}",
            format_live_divider(color_enabled(options.theme, stdout_is_tty))
        );
        if !report.os_fingerprints.is_empty() {
            println!("OS Fingerprint Evidence:");
            for (host, guess) in &report.os_fingerprints {
                let ev = guess
                    .evidence
                    .as_deref()
                    .map(|e| format!(" | Evidence: {e}"))
                    .unwrap_or_default();
                println!(
                    "  {} → {} ({}) confidence={:.0}%{}",
                    host,
                    guess.detail,
                    guess.family,
                    guess.confidence * 100.0,
                    ev
                );
            }
            println!();
        }
        let defenses = crate::defense::analyze_defenses(report);
        let has_non_direct = defenses
            .values()
            .any(|d| d.defense_type != crate::defense::DefenseType::DirectHost);
        if options.defense || has_non_direct {
            println!("Defense & Middlebox Intelligence:");
            println!("{}", "─".repeat(70));
            for (host, assess) in &defenses {
                let badge = match assess.defense_type {
                    crate::defense::DefenseType::DirectHost => "[CLEAN] Direct Host",
                    crate::defense::DefenseType::SynProxy => "[ALERT] SYN-Proxy Middlebox Detected",
                    crate::defense::DefenseType::Tarpit => "[ALERT] TCP Tarpit Active",
                    crate::defense::DefenseType::RateLimiting => "[NOTICE] Rate-Limiting Active",
                    crate::defense::DefenseType::WafOrDpi => "[ALERT] Layer-7 WAF / DPI Detected",
                    crate::defense::DefenseType::MultiLayerDefense => {
                        "[ALERT] Multi-Layer Defense Active"
                    }
                };
                println!("Target {}:", host);
                println!("  Posture:             {}", badge);
                println!("  Confidence:          {:.0}%", assess.confidence * 100.0);
                println!("  Summary:             {}", assess.summary);
                if !assess.indicators.is_empty() {
                    println!("  Indicators:");
                    for ind in &assess.indicators {
                        println!("    • {}", ind);
                    }
                }
                if let Some(action) = &assess.recommended_action {
                    println!("  Recommended Action:  {}", action);
                }
                println!();
            }
        }
        if let Some(exp_port) = options.explain {
            println!("\nAccuracy & Evidence Explanations:");
            println!("{}", "─".repeat(70));
            let to_explain: Vec<&&PortResult> = if exp_port == 0 {
                selected.iter().collect()
            } else {
                selected.iter().filter(|r| r.port == exp_port).collect()
            };
            if to_explain.is_empty() {
                println!(
                    "  No matching responsive port found to explain for port {}",
                    exp_port
                );
            } else {
                for res in to_explain {
                    let guess = report.os_fingerprints.get(&res.host);
                    let score = crate::accuracy::AccuracyScore::calculate(res, guess);
                    let svc_desc = service_label(res);
                    println!(
                        "{}",
                        score.explain(
                            res.host,
                            res.port,
                            res.state,
                            if svc_desc.is_empty() {
                                None
                            } else {
                                Some(&svc_desc)
                            }
                        )
                    );
                }
            }
            println!();
        }
        print!("{}", format_summary(report.counts, report.elapsed));
        println!(
            "  targets {}  ports {}  probes {}  workers {}",
            report.targets, report.ports, report.jobs, report.workers
        );
        return Ok(());
    }

    write_destination(None, &contents, options.quiet)
}

fn compare_results(left: &PortResult, right: &PortResult) -> std::cmp::Ordering {
    left.host
        .cmp(&right.host)
        .then_with(|| left.port.cmp(&right.port))
}

fn render_table(
    report: &ScanReport,
    results: &[&PortResult],
    theme: Theme,
    use_color: bool,
    dynamic_width: bool,
    explain: Option<u16>,
    defense: bool,
) -> String {
    let has_os = !report.os_fingerprints.is_empty();

    let mut table = Table::new();
    table.load_preset(theme.table_preset());
    if !dynamic_width {
        table.force_no_tty();
    } else {
        table.set_content_arrangement(ContentArrangement::Dynamic);
    }

    let header = |label: &str| {
        let cell = Cell::new(label);
        if use_color {
            cell.fg(theme.accent()).add_attribute(Attribute::Bold)
        } else {
            cell
        }
    };
    let mut headers = vec![
        header("HOST"),
        header("PORT"),
        header("STATE"),
        header("CONFIDENCE"),
        header("SERVICE"),
        header("LATENCY_MS"),
    ];
    if has_os {
        headers.push(header("OS"));
    }
    table.set_header(headers);
    let mut constraints = vec![
        ColumnConstraint::LowerBoundary(Width::Fixed(15)),
        ColumnConstraint::LowerBoundary(Width::Fixed(6)),
        ColumnConstraint::LowerBoundary(Width::Fixed(10)),
        ColumnConstraint::LowerBoundary(Width::Fixed(12)),
        ColumnConstraint::LowerBoundary(Width::Fixed(16)),
        ColumnConstraint::LowerBoundary(Width::Fixed(12)),
    ];
    if has_os {
        constraints.push(ColumnConstraint::LowerBoundary(Width::Fixed(12)));
    }
    table.set_constraints(constraints);

    for result in results {
        let state_cell = match theme.state(result.state) {
            Some(color) if use_color => Cell::new(result.state.as_str()).fg(color),
            _ => Cell::new(result.state.as_str()),
        };
        let conf_str = match result.confidence {
            Some(conf) => format!("{:.0}%", conf * 100.0),
            None => "-".to_string(),
        };
        let conf_cell = if use_color {
            if let Some(conf) = result.confidence {
                if conf >= 0.80 {
                    Cell::new(conf_str).fg(comfy_table::Color::Green)
                } else if conf >= 0.50 {
                    Cell::new(conf_str).fg(comfy_table::Color::Yellow)
                } else {
                    Cell::new(conf_str).fg(comfy_table::Color::DarkGrey)
                }
            } else {
                Cell::new(conf_str)
            }
        } else {
            Cell::new(conf_str)
        };
        let service_cell = Cell::new(service_label(result));
        let mut row = vec![
            Cell::new(result.host),
            Cell::new(result.port),
            state_cell,
            conf_cell,
            service_cell,
            Cell::new(format!("{:.2}", result.latency.as_secs_f64() * 1000.0)),
        ];
        if has_os {
            let os_label = report
                .os_fingerprints
                .get(&result.host)
                .map(|g| format!("{} ({:.0}%)", g.detail, g.confidence * 100.0))
                .unwrap_or_default();
            row.push(Cell::new(os_label.chars().take(24).collect::<String>()));
        }
        table.add_row(row);
    }

    let mut output = table.to_string();
    output.push('\n');
    if results.is_empty() {
        output.push_str("no matching results\n");
    }
    if has_os {
        output.push_str("\nOS Fingerprint Evidence:\n");
        for (host, guess) in &report.os_fingerprints {
            let ev = guess
                .evidence
                .as_deref()
                .map(|e| format!(" | Evidence: {e}"))
                .unwrap_or_default();
            output.push_str(&format!(
                "  {} → {} ({}) confidence={:.0}%{}\n",
                host,
                guess.detail,
                guess.family,
                guess.confidence * 100.0,
                ev
            ));
        }
    }

    let defenses = crate::defense::analyze_defenses(report);
    let has_non_direct = defenses
        .values()
        .any(|d| d.defense_type != crate::defense::DefenseType::DirectHost);
    if defense || has_non_direct {
        output.push_str("\nDefense & Middlebox Intelligence:\n");
        output.push_str(&"─".repeat(70));
        output.push('\n');
        for (host, assess) in &defenses {
            let badge = assess.defense_type.badge();
            output.push_str(&format!("Target {}:\n", host));
            output.push_str(&format!("  Posture:             {}\n", badge));
            output.push_str(&format!(
                "  Confidence:          {:.0}%\n",
                assess.confidence * 100.0
            ));
            output.push_str(&format!("  Summary:             {}\n", assess.summary));
            if !assess.indicators.is_empty() {
                output.push_str("  Indicators:\n");
                for ind in &assess.indicators {
                    output.push_str(&format!("    • {}\n", ind));
                }
            }
            if let Some(action) = &assess.recommended_action {
                output.push_str(&format!("  Recommended Action:  {}\n", action));
            }
            output.push('\n');
        }
    }

    if let Some(exp_port) = explain {
        output.push_str("\nAccuracy & Evidence Explanations:\n");
        output.push_str(&"─".repeat(70));
        output.push('\n');
        let to_explain: Vec<&&PortResult> = if exp_port == 0 {
            results.iter().collect()
        } else {
            results.iter().filter(|r| r.port == exp_port).collect()
        };
        if to_explain.is_empty() {
            output.push_str(&format!(
                "  No matching responsive port found to explain for port {}\n",
                exp_port
            ));
        } else {
            for res in to_explain {
                let guess = report.os_fingerprints.get(&res.host);
                let score = crate::accuracy::AccuracyScore::calculate(res, guess);
                let svc_desc = service_label(res);
                output.push_str(&score.explain(
                    res.host,
                    res.port,
                    res.state,
                    if svc_desc.is_empty() {
                        None
                    } else {
                        Some(&svc_desc)
                    },
                ));
                output.push('\n');
            }
        }
    }

    output.push('\n');
    output.push_str(&format_summary(report.counts, report.elapsed));
    output.push_str(&format!(
        "  targets {}  ports {}  probes {}  workers {}\n",
        report.targets, report.ports, report.jobs, report.workers
    ));
    output
}

pub fn color_to_ansi(color: comfy_table::Color) -> &'static str {
    match color {
        comfy_table::Color::Black => "30",
        comfy_table::Color::DarkGrey => "90",
        comfy_table::Color::Red => "31",
        comfy_table::Color::DarkRed => "31",
        comfy_table::Color::Green => "32",
        comfy_table::Color::DarkGreen => "32",
        comfy_table::Color::Yellow => "33",
        comfy_table::Color::DarkYellow => "33",
        comfy_table::Color::Blue => "34",
        comfy_table::Color::DarkBlue => "34",
        comfy_table::Color::Magenta => "35",
        comfy_table::Color::DarkMagenta => "35",
        comfy_table::Color::Cyan => "36",
        comfy_table::Color::DarkCyan => "36",
        comfy_table::Color::White => "37",
        comfy_table::Color::Grey => "37",
        comfy_table::Color::Reset => "0",
        _ => "0",
    }
}

pub fn format_live_header(theme: Theme, use_color: bool) -> String {
    let host = "HOST";
    let port = "PORT";
    let state = "STATE";
    let conf = "CONF";
    let service = "SERVICE";
    let version = "VERSION";
    let latency = "LATENCY";
    let header = format!(
        "{:<17} {:<6} {:<10} {:<6} {:<18} {:<20} {:<8}",
        host, port, state, conf, service, version, latency
    );
    if use_color {
        format!("\x1b[1;{}m{}\x1b[0m", color_to_ansi(theme.accent()), header)
    } else {
        header
    }
}

pub fn format_live_divider(_use_color: bool) -> String {
    "─".repeat(90)
}

pub fn format_live_row(result: &PortResult, theme: Theme, use_color: bool) -> String {
    let host = result.host.to_string();
    let port = result.port.to_string();
    let state_str = result.state.as_str();

    let (svc_name, svc_ver) = match &result.service {
        Some(s) => {
            let name = match &s.product {
                Some(p) => format!("{} ({})", s.name, p),
                None => s.name.clone(),
            };
            let ver = s.version.clone().unwrap_or_default();
            (name, ver)
        }
        None => (result.detail.clone().unwrap_or_default(), String::new()),
    };
    let lat = format!("{:.1}ms", result.latency.as_secs_f64() * 1000.0);

    let state_col = if use_color {
        if let Some(col) = theme.state(result.state) {
            format!("\x1b[{}m{:<10}\x1b[0m", color_to_ansi(col), state_str)
        } else {
            format!("{:<10}", state_str)
        }
    } else {
        format!("{:<10}", state_str)
    };

    let conf_str = match result.confidence {
        Some(c) => format!("{:.0}%", c * 100.0),
        None => "-".to_string(),
    };
    let conf_col = if use_color {
        if let Some(c) = result.confidence {
            let color_code = if c >= 0.80 {
                "32" // green
            } else if c >= 0.50 {
                "33" // yellow
            } else {
                "90" // dark grey
            };
            format!("\x1b[{}m{:<6}\x1b[0m", color_code, conf_str)
        } else {
            format!("{:<6}", conf_str)
        }
    } else {
        format!("{:<6}", conf_str)
    };

    format!(
        "{:<17} {:<6} {} {} {:<18} {:<20} {:<8}",
        host,
        port,
        state_col,
        conf_col,
        svc_name.chars().take(18).collect::<String>(),
        svc_ver.chars().take(20).collect::<String>(),
        lat
    )
}

fn service_label(result: &PortResult) -> String {
    let Some(service) = &result.service else {
        return String::new();
    };

    let mut label = service.name.clone();
    if let Some(product) = &service.product {
        label.push(' ');
        label.push_str(product);
    }
    if let Some(version) = &service.version {
        label.push('/');
        label.push_str(version);
    }
    label.chars().take(30).collect()
}

fn format_summary(counts: StateCounts, elapsed: std::time::Duration) -> String {
    format!(
        "open {}  closed {}  filtered {}  silent {}  unreachable {}  error {}  elapsed {:.2}s\n",
        counts.open,
        counts.closed,
        counts.filtered,
        counts.silent,
        counts.unreachable,
        counts.error,
        elapsed.as_secs_f64()
    )
}

#[derive(Serialize)]
struct JsonReport<'a> {
    target: &'a str,
    targets: usize,
    ports: usize,
    jobs: u64,
    workers: usize,
    open: Vec<JsonResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<JsonResult>>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    os_fingerprints: HashMap<String, &'a OsGuess>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    defense: HashMap<String, crate::defense::HostDefenseAssessment>,
    summary: StateCounts,
    elapsed_ms: f64,
}

#[derive(Serialize)]
struct JsonResult {
    host: String,
    port: u16,
    state: PortState,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<ServiceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

impl JsonResult {
    fn from_result(result: &PortResult) -> Self {
        Self {
            host: result.host.to_string(),
            port: result.port,
            state: result.state,
            latency_ms: (result.latency.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
            banner: result.banner.clone(),
            service: result.service.clone(),
            detail: result.detail.clone(),
            confidence: result.confidence,
            evidence: result.evidence.clone(),
        }
    }
}

fn render_json(
    report: &ScanReport,
    target: &str,
    show: StateSet,
    min_confidence: Option<u8>,
) -> Result<String, AppError> {
    let min_conf_ratio = min_confidence.map(|c| (c as f32) / 100.0);
    let mut opens: Vec<&PortResult> = report
        .results
        .iter()
        .filter(|result| {
            if result.state != PortState::Open {
                return false;
            }
            if let Some(min) = min_conf_ratio
                && result.confidence.unwrap_or(1.0) < min
            {
                return false;
            }
            true
        })
        .collect();
    opens.sort_by(|left, right| compare_results(left, right));

    let include_results = PortState::ALL
        .into_iter()
        .any(|state| state != PortState::Open && show.contains(state));

    let mut selected: Vec<&PortResult> = report
        .results
        .iter()
        .filter(|result| {
            if !show.contains(result.state) {
                return false;
            }
            if let Some(min) = min_conf_ratio
                && result.confidence.unwrap_or(1.0) < min
            {
                return false;
            }
            true
        })
        .collect();
    selected.sort_by(|left, right| compare_results(left, right));

    let payload = JsonReport {
        target,
        targets: report.targets,
        ports: report.ports,
        jobs: report.jobs,
        workers: report.workers,
        open: opens.into_iter().map(JsonResult::from_result).collect(),
        results: include_results
            .then(|| selected.into_iter().map(JsonResult::from_result).collect()),
        os_fingerprints: report
            .os_fingerprints
            .iter()
            .map(|(ip, guess)| (ip.to_string(), guess))
            .collect(),
        defense: crate::defense::analyze_defenses(report)
            .into_iter()
            .map(|(ip, d)| (ip.to_string(), d))
            .collect(),
        summary: report.counts,
        elapsed_ms: (report.elapsed.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
    };

    let mut json = serde_json::to_string_pretty(&payload)
        .map_err(|error| AppError::runtime(format!("cannot encode JSON: {error}")))?;
    json.push('\n');
    Ok(json)
}

fn render_jsonl(results: &[&PortResult]) -> Result<String, AppError> {
    let mut output = String::new();
    for result in results {
        let item = JsonResult::from_result(result);
        let line = serde_json::to_string(&item)
            .map_err(|error| AppError::runtime(format!("cannot encode JSON line: {error}")))?;
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}

fn render_csv(results: &[&PortResult]) -> String {
    let mut output = String::from(
        "host,port,state,latency_ms,service,product,version,banner,detail,confidence\n",
    );
    for result in results {
        let service = result.service.as_ref();
        let detail = result.detail.as_deref().unwrap_or("");
        let name = service.map(|service| service.name.as_str()).unwrap_or("");
        let product = service
            .and_then(|service| service.product.as_deref())
            .unwrap_or("");
        let version = service
            .and_then(|service| service.version.as_deref())
            .unwrap_or("");
        let banner = result.banner.as_deref().unwrap_or("");
        let confidence = result
            .confidence
            .map(|c| format!("{c:.3}"))
            .unwrap_or_default();
        output.push_str(&format!(
            "{},{},{},{:.3},{},{},{},{},{},{}\n",
            result.host,
            result.port,
            result.state.as_str(),
            result.latency.as_secs_f64() * 1000.0,
            csv_field(name),
            csv_field(product),
            csv_field(version),
            csv_field(banner),
            csv_field(detail),
            confidence
        ));
    }
    output
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Render Nmap-compatible XML output.
///
/// The format is compatible with nmap XML parsers (e.g. Metasploit, nmap-parse-output)
/// and can be imported by any tool that understands nmap XML scan results.
fn render_nmap_xml(report: &ScanReport, target: &str, results: &[&PortResult]) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let start_secs = now_secs.saturating_sub(report.elapsed.as_secs());
    let version = env!("CARGO_PKG_VERSION");

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!DOCTYPE nmaprun>\n");
    xml.push_str(&format!(
        "<nmaprun scanner=\"rayscan\" args=\"rayscan scan --target {target}\" \
         start=\"{start_secs}\" version=\"{version}\" \
         xmloutputversion=\"1.04\">\n"
    ));

    // Group results by host.
    let mut by_host: std::collections::BTreeMap<String, Vec<&PortResult>> =
        std::collections::BTreeMap::new();
    for result in results {
        by_host
            .entry(result.host.to_string())
            .or_default()
            .push(result);
    }

    for (host_str, host_results) in &by_host {
        let end_secs = now_secs;
        xml.push_str(&format!(
            "  <host starttime=\"{start_secs}\" endtime=\"{end_secs}\">\n"
        ));

        // Determine address type.
        let addr_type = if host_str.contains(':') {
            "ipv6"
        } else {
            "ipv4"
        };
        xml.push_str(&format!(
            "    <address addr=\"{host_str}\" addrtype=\"{addr_type}\"/>\n"
        ));

        // OS fingerprint if available.
        if let Ok(ip) = host_str.parse::<std::net::IpAddr>()
            && let Some(os) = report.os_fingerprints.get(&ip)
        {
            let name = xml_escape(&os.detail);
            xml.push_str("    <os>\n");
            xml.push_str(&format!(
                "      <osmatch name=\"{name}\" accuracy=\"{:.0}\"/>\n",
                os.confidence * 100.0
            ));
            xml.push_str("    </os>\n");
        }

        xml.push_str("    <ports>\n");
        for result in host_results {
            let proto = "tcp";
            let state_str = result.state.as_str();
            let reason = match result.state {
                PortState::Open => "syn-ack",
                PortState::Closed => "rst",
                PortState::Filtered => "no-response",
                PortState::Silent => "no-response",
                PortState::Unreachable => "host-unreach",
                PortState::Error => "unknown",
            };
            xml.push_str(&format!(
                "      <port protocol=\"{proto}\" portid=\"{}\">\n",
                result.port
            ));
            xml.push_str(&format!(
                "        <state state=\"{state_str}\" reason=\"{reason}\" reason_ttl=\"0\"/>\n"
            ));
            if let Some(svc) = &result.service {
                let mut attrs = format!("name=\"{}\"", xml_escape(&svc.name));
                if let Some(product) = &svc.product {
                    attrs.push_str(&format!(" product=\"{}\"", xml_escape(product)));
                }
                if let Some(version) = &svc.version {
                    attrs.push_str(&format!(" version=\"{}\"", xml_escape(version)));
                }
                xml.push_str(&format!("        <service {attrs}/>\n"));
            }
            xml.push_str("      </port>\n");
        }
        xml.push_str("    </ports>\n");
        xml.push_str("  </host>\n");
    }

    let hosts_up = by_host.len();
    let elapsed = report.elapsed.as_secs_f64();
    let open_count = report.counts.open;
    xml.push_str("  <runstats>\n");
    xml.push_str(&format!(
        "    <finished time=\"{now_secs}\" elapsed=\"{elapsed:.2}\" \
         summary=\"rayscan done at {now_secs}; {open_count} open port(s)\"/>\n"
    ));
    xml.push_str(&format!(
        "    <hosts up=\"{hosts_up}\" down=\"0\" total=\"{hosts_up}\"/>\n"
    ));
    xml.push_str("  </runstats>\n");
    xml.push_str("</nmaprun>\n");
    xml
}

/// Escape special XML characters in attribute values and text.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render Nmap-compatible greppable output (-oG style).
///
/// Format: one line per host.
/// `Host: <ip> ()  Ports: <port>/<state>/<proto>//<service>/<product>/,…`
fn render_greppable(target: &str, results: &[&PortResult]) -> String {
    let mut output = String::new();
    output.push_str(&format!("# rayscan greppable output — target: {target}\n"));

    // Group by host.
    let mut by_host: std::collections::BTreeMap<String, Vec<&PortResult>> =
        std::collections::BTreeMap::new();
    for result in results {
        by_host
            .entry(result.host.to_string())
            .or_default()
            .push(result);
    }

    for (host_str, host_results) in &by_host {
        let ports_field: Vec<String> = host_results
            .iter()
            .map(|r| {
                let state = r.state.as_str();
                let proto = "tcp";
                let svc_name = r.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");
                let product = r
                    .service
                    .as_ref()
                    .and_then(|s| s.product.as_deref())
                    .unwrap_or("");
                let version = r
                    .service
                    .as_ref()
                    .and_then(|s| s.version.as_deref())
                    .unwrap_or("");
                let product_ver = if version.is_empty() {
                    product.to_string()
                } else {
                    format!("{product} {version}")
                };
                format!("{}/{state}/{proto}//{svc_name}/{product_ver}/", r.port)
            })
            .collect();

        output.push_str(&format!(
            "Host: {host_str} ()\tPorts: {}\n",
            ports_field.join(", ")
        ));
    }
    output
}

fn write_destination(
    destination: Option<&Path>,
    contents: &str,
    quiet: bool,
) -> Result<(), AppError> {
    let Some(path) = destination else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(contents.as_bytes())
            .and_then(|_| stdout.flush())
            .map_err(|error| AppError::runtime(format!("cannot write stdout: {error}")))?;
        return Ok(());
    };

    if path.as_os_str() == "-" {
        return write_destination(None, contents, quiet);
    }

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

    std::fs::write(path, contents)
        .map_err(|error| AppError::runtime(format!("cannot write {}: {error}", path.display())))?;

    if !quiet {
        eprintln!("wrote {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::*;
    use crate::service::{Detection, ServiceInfo};

    fn sample_report() -> ScanReport {
        let host: IpAddr = "192.0.2.1".parse().unwrap();
        let open = PortResult::new(host, 80, PortState::Open, Duration::from_millis(3))
            .with_detection(Detection {
                service: Some(ServiceInfo {
                    name: "http".to_string(),
                    product: Some("rayscan-lab".to_string()),
                    version: None,
                }),
                banner: Some("HTTP/1.1 200 OK".to_string()),
            });
        ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(250),
            counts: StateCounts {
                open: 1,
                closed: 1,
                filtered: 1,
                ..StateCounts::default()
            },
            results: vec![
                open,
                PortResult::new(host, 81, PortState::Closed, Duration::from_millis(1)),
                PortResult::new(host, 82, PortState::Filtered, Duration::from_millis(500)),
            ],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![80, 81, 82],
            partial: false,
        }
    }

    #[test]
    fn table_renders_rows_without_ansi_when_color_is_off() {
        let report = sample_report();
        let results: Vec<&PortResult> = report
            .results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .collect();
        let output = render_table(&report, &results, Theme::Minimal, false, false, None, false);
        assert!(output.contains("HOST"));
        assert!(output.contains("CONFIDENCE"));
        assert!(output.contains("SERVICE"));
        assert!(output.contains("192.0.2.1"));
        assert!(output.contains("80"));
        assert!(output.contains("open"));
        assert!(output.contains("http"));
        assert!(
            !output.contains("\u{1b}["),
            "plain table must not contain ANSI"
        );
    }

    #[test]
    fn dynamic_table_keeps_header_labels_intact() {
        let report = sample_report();
        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_table(&report, &results, Theme::Minimal, false, true, None, false);
        assert!(output.contains("HOST"));
        assert!(output.contains("CONFIDENCE"));
        assert!(output.contains("SERVICE"));
        assert!(output.contains("LATENCY_MS"));
    }

    #[test]
    fn table_explain_renders_breakdown() {
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);
        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_table(
            &report,
            &results,
            Theme::Minimal,
            false,
            false,
            Some(80),
            false,
        );
        assert!(output.contains("Accuracy & Evidence Explanations:"));
        assert!(output.contains("Port 80/tcp on 192.0.2.1"));
        assert!(output.contains("Criteria Breakdown:"));
        assert!(output.contains("Evidence String:"));
    }

    #[test]
    fn table_defense_renders_intelligence() {
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);
        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_table(&report, &results, Theme::Minimal, false, false, None, true);
        assert!(output.contains("Defense & Middlebox Intelligence:"));
        assert!(output.contains("Target 192.0.2.1:"));
        assert!(output.contains("Posture:"));
    }

    #[test]
    fn json_contains_open_and_optional_results() {
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);
        let output = render_json(&report, "192.0.2.1", StateSet::all(), None).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(payload["open"][0]["port"], 80);
        assert_eq!(payload["open"][0]["service"]["name"], "http");
        assert_eq!(payload["open"][0]["service"]["product"], "rayscan-lab");
        assert_eq!(payload["open"][0]["banner"], "HTTP/1.1 200 OK");
        assert!(payload["open"][0]["confidence"].as_f64().unwrap() > 0.0);
        assert!(payload["open"][0]["evidence"].is_string());
        assert_eq!(payload["results"].as_array().unwrap().len(), 3);
        assert_eq!(payload["summary"]["filtered"], 1);
    }

    #[test]
    fn json_min_confidence_filters_results() {
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);
        // Port 80 should have high confidence (>80%)
        let output_high = render_json(&report, "192.0.2.1", StateSet::open(), Some(80)).unwrap();
        let payload_high: serde_json::Value = serde_json::from_str(&output_high).unwrap();
        assert_eq!(payload_high["open"].as_array().unwrap().len(), 1);

        // Filter requiring 101% (impossible)
        let output_none = render_json(&report, "192.0.2.1", StateSet::open(), Some(101)).unwrap();
        let payload_none: serde_json::Value = serde_json::from_str(&output_none).unwrap();
        assert_eq!(payload_none["open"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn default_json_omits_non_open_results() {
        let report = sample_report();
        let output = render_json(&report, "192.0.2.1", StateSet::open(), None).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(payload.get("results").is_none());
    }

    #[test]
    fn csv_quotes_details() {
        let report = sample_report();
        let mut results: Vec<&PortResult> = report.results.iter().collect();
        let closed = PortResult::new(
            "192.0.2.1".parse().unwrap(),
            81,
            PortState::Closed,
            Duration::from_millis(1),
        )
        .with_detail("refused, then reset");
        results[1] = &closed;
        let output = render_csv(&results);
        assert!(
            output.contains("host,port,state,latency_ms,service,product,version,banner,detail")
        );
        assert!(output.contains("http,rayscan-lab"));
        assert!(output.contains("\"refused, then reset\""));
    }

    #[test]
    fn nmap_xml_contains_host_and_port() {
        let report = sample_report();
        let results: Vec<&PortResult> = report
            .results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .collect();
        let xml = render_nmap_xml(&report, "192.0.2.1", &results);
        assert!(xml.contains("<nmaprun"), "must have nmaprun element");
        assert!(xml.contains("addr=\"192.0.2.1\""), "must contain host addr");
        assert!(xml.contains("portid=\"80\""), "must contain port 80");
        assert!(xml.contains("state=\"open\""), "must mark port as open");
        assert!(xml.contains("name=\"http\""), "must include service name");
        assert!(xml.contains("</nmaprun>"), "must be closed");
    }

    #[test]
    fn nmap_xml_omits_absent_version_attribute() {
        let mut report = sample_report();
        if let Some(service) = report.results[0].service.as_mut() {
            service.version = None;
        }
        let results: Vec<&PortResult> = report
            .results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .collect();
        let xml = render_nmap_xml(&report, "192.0.2.1", &results);
        assert!(xml.contains("name=\"http\""));
        assert!(
            !xml.contains("version=\"\""),
            "empty version must be omitted"
        );
    }

    #[test]
    fn greppable_format_one_line_per_host() {
        let report = sample_report();
        let results: Vec<&PortResult> = report
            .results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .collect();
        let output = render_greppable("192.0.2.1", &results);
        // Should have a Host: line
        assert!(output.contains("Host: 192.0.2.1"), "must contain host line");
        assert!(output.contains("80/open/tcp"), "must contain port entry");
        assert!(output.contains("http"), "must include service name");
    }
}
