use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;

use clap::ValueEnum;
use comfy_table::{Attribute, Cell, ColumnConstraint, ContentArrangement, Table, Width};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::fingerprint::OsGuess;
use crate::model::{PortResult, PortState, ScanReport, StateCounts, StateSet};
use crate::service::ServiceInfo;
use crate::theme::{Theme, color_enabled};

/// Maximum advisory rows rendered per port in human-readable output.
const MAX_ADVISORY_LINES: usize = 10;

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
    /// SARIF 2.1.0 report for code-scanning and vulnerability dashboards.
    Sarif,
    /// Human-readable Markdown report for tickets and pull requests.
    Markdown,
    /// Plain `host:port` list — one open port per line for pipeline chaining.
    #[value(name = "host-port", alias = "hostport", alias = "plain")]
    HostPort,
    /// Comma-separated port numbers only — ready to paste into -p of any tool.
    /// Without --ports/--top-ports this discovery format scans the full TCP
    /// range (1-65535). Example: 53,88,139,445,3389,5985
    #[value(name = "port-list", alias = "ports", alias = "portlist")]
    PortList,
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
            Self::Sarif => "sarif",
            Self::Markdown => "markdown",
            Self::HostPort => "host-port",
            Self::PortList => "port-list",
        }
    }

    /// True for formats written for scripts and pipelines (`port-list`,
    /// `json`, `csv`, ...). When one of these is selected, scan progress and
    /// intelligence output is suppressed automatically so stdout stays pure
    /// and parseable — no `--quiet` required (RSC-BUG-002 / PROPOSAL-001).
    pub const fn is_machine_readable(self) -> bool {
        !matches!(self, Self::Table | Self::Markdown)
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
    pub advisories: bool,
    pub stream: bool,
    pub diff: Option<&'a crate::diff::ScanDiff>,
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
            TableOptions {
                theme: options.theme,
                use_color: color_enabled(options.theme, stdout_is_tty)
                    && options.destination.is_none(),
                dynamic_width: stdout_is_tty,
                explain: options.explain,
                defense: options.defense,
                advisories: options.advisories,
                diff: options.diff,
            },
        ),
        OutputFormat::Json => render_json(
            report,
            target,
            options.show,
            options.min_confidence,
            options.diff,
        )?,
        OutputFormat::Jsonl => render_jsonl(&selected)?,
        OutputFormat::Csv => render_csv(&selected),
        OutputFormat::NmapXml => render_nmap_xml(report, target, &selected),
        OutputFormat::Greppable => render_greppable(target, &selected),
        OutputFormat::Sarif => render_sarif(&selected)?,
        OutputFormat::Markdown => render_markdown(report, target, &selected, options.diff),
        OutputFormat::HostPort => render_host_port(&selected),
        OutputFormat::PortList => render_port_list(&selected),
    };

    if let Some(path) = options.destination {
        return write_destination(Some(path), &contents, options.quiet);
    }

    if options.stream {
        return Ok(());
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
                let role = guess
                    .role
                    .as_ref()
                    .map(|r| format!(" [{}]", r.as_str()))
                    .unwrap_or_default();
                println!(
                    "  {} → {} ({}) confidence={:.0}%{}{}",
                    host,
                    guess.detail,
                    guess.family,
                    guess.confidence * 100.0,
                    role,
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
        if options.advisories {
            print!("{}", render_advisory_section(&selected));
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
                    for line in advisory_explain_lines(res) {
                        println!("{line}");
                    }
                }
            }
            println!();
        }
        if let Some(diff) = options.diff {
            print!(
                "{}",
                diff.render_terminal(color_enabled(options.theme, stdout_is_tty))
            );
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

#[derive(Clone, Copy, Debug, Default)]
pub struct TableOptions<'a> {
    pub theme: Theme,
    pub use_color: bool,
    pub dynamic_width: bool,
    pub explain: Option<u16>,
    pub defense: bool,
    pub advisories: bool,
    pub diff: Option<&'a crate::diff::ScanDiff>,
}

fn render_table(report: &ScanReport, results: &[&PortResult], opts: TableOptions<'_>) -> String {
    let has_os = !report.os_fingerprints.is_empty();

    let mut table = Table::new();
    table.load_preset(opts.theme.table_preset());
    if !opts.dynamic_width {
        table.force_no_tty();
    } else {
        table.set_content_arrangement(ContentArrangement::Dynamic);
    }

    let header = |label: &str| {
        let cell = Cell::new(label);
        if opts.use_color {
            cell.fg(opts.theme.accent()).add_attribute(Attribute::Bold)
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
    ];
    if opts.advisories {
        headers.push(header("ADVISORIES"));
    }
    headers.push(header("LATENCY_MS"));
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
    ];
    if opts.advisories {
        constraints.push(ColumnConstraint::LowerBoundary(Width::Fixed(16)));
    }
    constraints.push(ColumnConstraint::LowerBoundary(Width::Fixed(12)));
    if has_os {
        constraints.push(ColumnConstraint::LowerBoundary(Width::Fixed(12)));
    }
    table.set_constraints(constraints);

    for result in results {
        let state_cell = match opts.theme.state(result.state) {
            Some(color) if opts.use_color => Cell::new(result.state.as_str()).fg(color),
            _ => Cell::new(result.state.as_str()),
        };
        let conf_str = match result.confidence {
            Some(conf) => format!("{:.0}%", conf * 100.0),
            None => "-".to_string(),
        };
        let conf_cell = if opts.use_color {
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
        ];
        if opts.advisories {
            let advisory_cell = if opts.use_color {
                match result.advisories.first() {
                    Some(advisory) => {
                        let color = match advisory.severity {
                            crate::advisory::Severity::Critical
                            | crate::advisory::Severity::High => comfy_table::Color::Red,
                            crate::advisory::Severity::Medium => comfy_table::Color::Yellow,
                            crate::advisory::Severity::Low => comfy_table::Color::DarkGrey,
                        };
                        Cell::new(advisory_summary(result)).fg(color)
                    }
                    None => Cell::new(""),
                }
            } else {
                Cell::new(advisory_summary(result))
            };
            row.push(advisory_cell);
        }
        row.push(Cell::new(format!(
            "{:.2}",
            result.latency.as_secs_f64() * 1000.0
        )));
        if has_os {
            let os_label = report
                .os_fingerprints
                .get(&result.host)
                .map(|g| {
                    let role = g
                        .role
                        .as_ref()
                        .map(|r| format!(" [{}]", r.as_str()))
                        .unwrap_or_default();
                    format!("{} ({:.0}%){}", g.detail, g.confidence * 100.0, role)
                })
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
            let role = guess
                .role
                .as_ref()
                .map(|r| format!(" [{}]", r.as_str()))
                .unwrap_or_default();
            output.push_str(&format!(
                "  {} → {} ({}) confidence={:.0}%{}{}\n",
                host,
                guess.detail,
                guess.family,
                guess.confidence * 100.0,
                role,
                ev
            ));
        }
    }

    let defenses = crate::defense::analyze_defenses(report);
    let has_non_direct = defenses
        .values()
        .any(|d| d.defense_type != crate::defense::DefenseType::DirectHost);
    if opts.defense || has_non_direct {
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

    if opts.advisories {
        output.push_str(&render_advisory_section(results));
    }

    if let Some(exp_port) = opts.explain {
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
                for line in advisory_explain_lines(res) {
                    output.push_str(&line);
                    output.push('\n');
                }
            }
        }
    }

    if let Some(diff) = opts.diff {
        output.push_str(&diff.render_terminal(opts.use_color));
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

fn advisory_summary(result: &PortResult) -> String {
    let Some(first) = result.advisories.first() else {
        return String::new();
    };
    let kev_badge = if result.advisories.iter().any(|a| a.cisa_kev) {
        " [KEV]"
    } else {
        ""
    };
    if result.advisories.len() == 1 {
        format!("{}{kev_badge}", first.id)
    } else {
        format!("{} +{}{kev_badge}", first.id, result.advisories.len() - 1)
    }
}

fn advisory_explain_lines(result: &PortResult) -> Vec<String> {
    if result.advisories.is_empty() {
        return vec!["  Advisory Matches:    none".to_string()];
    }
    let mut lines = vec!["  Advisory Matches:".to_string()];
    for advisory in result.advisories.iter().take(MAX_ADVISORY_LINES) {
        let kev = if advisory.cisa_kev { " [KEV]" } else { "" };
        let epss = match advisory.epss {
            Some(score) => format!("  EPSS {:>5.1}%", score * 100.0),
            None => String::new(),
        };
        lines.push(format!(
            "    [{}] {}{kev}  CVSS {:.1}{}  {}",
            advisory.severity.label(),
            advisory.id,
            advisory.cvss,
            epss,
            advisory.title
        ));
    }
    if result.advisories.len() > MAX_ADVISORY_LINES {
        lines.push(format!(
            "    ... and {} more (see JSON output for the full list)",
            result.advisories.len() - MAX_ADVISORY_LINES
        ));
    }
    lines
}

fn render_advisory_section(results: &[&PortResult]) -> String {
    let hits: Vec<&&PortResult> = results
        .iter()
        .filter(|result| !result.advisories.is_empty())
        .collect();
    if hits.is_empty() {
        return String::new();
    }

    let total: usize = hits.iter().map(|result| result.advisories.len()).sum();
    let mut output = String::from("\nVulnerability Advisory Correlation:\n");
    output.push_str(&"─".repeat(70));
    output.push('\n');
    for result in &hits {
        let label = service_label(result);
        let suffix = if label.is_empty() {
            String::new()
        } else {
            format!(" ({label})")
        };
        output.push_str(&format!(
            "  {}:{}/tcp{}\n",
            result.host, result.port, suffix
        ));
        for advisory in result.advisories.iter().take(MAX_ADVISORY_LINES) {
            let kev = if advisory.cisa_kev { " [KEV]" } else { "" };
            let epss = match advisory.epss {
                Some(score) => format!("  EPSS {:>5.1}%", score * 100.0),
                None => String::new(),
            };
            output.push_str(&format!(
                "    [{}] {}{kev}  CVSS {:.1}{}  {}\n",
                advisory.severity.label(),
                advisory.id,
                advisory.cvss,
                epss,
                advisory.title
            ));
        }
        if result.advisories.len() > MAX_ADVISORY_LINES {
            output.push_str(&format!(
                "    ... and {} more (see JSON output for the full list)\n",
                result.advisories.len() - MAX_ADVISORY_LINES
            ));
        }
    }
    output.push_str(&format!(
        "\n  {total} advisory match(es) across {} open service(s); offline CVE correlation (curated + local NVD database) — verify against vendor advisories.\n",
        hits.len()
    ));
    output
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
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<&'a crate::diff::ScanDiff>,
    summary: StateCounts,
    elapsed_ms: f64,
}

#[derive(Serialize)]
pub(crate) struct JsonResult {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) state: PortState,
    pub(crate) latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) service: Option<ServiceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) advisories: Vec<crate::advisory::AdvisoryMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<crate::tls::TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rdp: Option<crate::rdp::RdpInfo>,
}

impl JsonResult {
    pub(crate) fn from_result(result: &PortResult) -> Self {
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
            advisories: result.advisories.clone(),
            tls: result.tls.clone(),
            rdp: result.rdp.clone(),
        }
    }
}

fn render_json(
    report: &ScanReport,
    target: &str,
    show: StateSet,
    min_confidence: Option<u8>,
    diff: Option<&crate::diff::ScanDiff>,
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
        diff,
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
        "host,port,state,latency_ms,service,product,version,banner,detail,confidence,tls_version,tls_subject,tls_days_remaining\n",
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
        let tls_version = result
            .tls
            .as_ref()
            .map(|tls| tls.version.as_str())
            .unwrap_or("");
        let tls_subject = result
            .tls
            .as_ref()
            .and_then(|tls| tls.subject.as_deref())
            .unwrap_or("");
        let tls_days = result
            .tls
            .as_ref()
            .and_then(|tls| tls.days_remaining)
            .map(|days| days.to_string())
            .unwrap_or_default();
        output.push_str(&format!(
            "{},{},{},{:.3},{},{},{},{},{},{},{},{},{}\n",
            result.host,
            result.port,
            result.state.as_str(),
            result.latency.as_secs_f64() * 1000.0,
            csv_field(name),
            csv_field(product),
            csv_field(version),
            csv_field(banner),
            csv_field(detail),
            confidence,
            csv_field(tls_version),
            csv_field(tls_subject),
            tls_days
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

fn render_sarif(results: &[&PortResult]) -> Result<String, AppError> {
    use serde_json::{Value, json};

    let mut rules: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut findings: Vec<Value> = Vec::new();

    for result in results
        .iter()
        .filter(|result| result.state == PortState::Open)
    {
        for advisory in &result.advisories {
            let level = match advisory.severity {
                crate::advisory::Severity::Critical | crate::advisory::Severity::High => "error",
                crate::advisory::Severity::Medium => "warning",
                crate::advisory::Severity::Low => "note",
            };
            rules.entry(advisory.id.clone()).or_insert_with(|| {
                json!({
                    "id": advisory.id,
                    "name": advisory.id,
                    "shortDescription": {"text": advisory.title},
                    "fullDescription": {"text": format!("{} (source: {})", advisory.title, advisory.source)},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "severity": advisory.severity.label(),
                        "cvss": advisory.cvss,
                        "cisa_kev": advisory.cisa_kev,
                        "epss": advisory.epss,
                        "source": advisory.source,
                    }
                })
            });
            let service = Some(service_label(result)).filter(|label| !label.is_empty());
            findings.push(json!({
                "ruleId": advisory.id,
                "level": level,
                "message": {
                    "text": format!(
                        "{}:{} is affected by {} (CVSS {:.1}, {}): {}",
                        result.host,
                        result.port,
                        advisory.id,
                        advisory.cvss,
                        advisory.severity.label(),
                        advisory.title
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": format!("tcp://{}:{}", result.host, result.port)}
                    }
                }],
                "properties": {
                    "host": result.host.to_string(),
                    "port": result.port,
                    "service": service,
                    "confidence": result.confidence,
                    "tls": result.tls.as_ref().map(|tls| tls.version.clone()),
                }
            }));
        }
    }

    let payload = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rayscan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules.into_values().collect::<Vec<_>>()
                }
            },
            "results": findings,
            "invocations": [{"executionSuccessful": true}]
        }]
    });
    serde_json::to_string_pretty(&payload)
        .map(|mut json| {
            json.push('\n');
            json
        })
        .map_err(|error| AppError::runtime(format!("cannot encode SARIF report: {error}")))
}

fn md_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

fn render_markdown(
    report: &ScanReport,
    target: &str,
    results: &[&PortResult],
    diff: Option<&crate::diff::ScanDiff>,
) -> String {
    let mut out = String::new();
    out.push_str("# rayscan scan report\n\n");
    out.push_str(&format!("**Target:** `{}`  \n", md_cell(target)));
    out.push_str(&format!(
        "**Elapsed:** {:.2}s · **Workers:** {} · **Probes:** {}\n\n",
        report.elapsed.as_secs_f64(),
        report.workers,
        report.jobs
    ));

    out.push_str("## Summary\n\n");
    out.push_str("| Open | Closed | Filtered | Silent | Unreachable | Error | Total |\n");
    out.push_str("|---:|---:|---:|---:|---:|---:|---:|\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} |\n\n",
        report.counts.open,
        report.counts.closed,
        report.counts.filtered,
        report.counts.silent,
        report.counts.unreachable,
        report.counts.error,
        report.counts.total()
    ));

    if !report.os_fingerprints.is_empty() {
        out.push_str("## Operating Systems\n\n");
        out.push_str("| Host | Family | Detail | Confidence | Evidence |\n");
        out.push_str("|---|---|---|---:|---|\n");
        let mut hosts: Vec<_> = report.os_fingerprints.iter().collect();
        hosts.sort_by_key(|(host, _)| *host);
        for (host, guess) in hosts {
            out.push_str(&format!(
                "| {} | {} | {} | {:.0}% | {} |\n",
                host,
                md_cell(&guess.family.to_string()),
                md_cell(&guess.detail),
                guess.confidence * 100.0,
                md_cell(guess.evidence.as_deref().unwrap_or(""))
            ));
        }
        out.push('\n');
    }

    out.push_str("## Services\n\n");
    if results.is_empty() {
        out.push_str("_No results matched the selected state filters._\n\n");
    } else {
        out.push_str("| Host | Port | State | Service | Version | Confidence | TLS |\n");
        out.push_str("|---|---:|---|---|---|---:|---|\n");
        for result in results {
            let service = result
                .service
                .as_ref()
                .map(|service| service.name.clone())
                .unwrap_or_default();
            let version = service_label(result);
            let confidence = result
                .confidence
                .map(|value| format!("{:.0}%", value * 100.0))
                .unwrap_or_default();
            let tls = result
                .tls
                .as_ref()
                .map(|tls| tls.version.clone())
                .unwrap_or_default();
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                result.host,
                result.port,
                result.state.as_str(),
                md_cell(&service),
                md_cell(&version),
                confidence,
                md_cell(&tls)
            ));
        }
        out.push('\n');
    }

    let vulnerable: Vec<_> = results
        .iter()
        .filter(|result| !result.advisories.is_empty())
        .collect();
    out.push_str("## Vulnerabilities\n\n");
    if vulnerable.is_empty() {
        out.push_str("_No advisory matches._\n\n");
    } else {
        out.push_str("| Host | Port | Advisory | KEV | EPSS | Severity | CVSS | Title |\n");
        out.push_str("|---|---:|---|:---:|---:|---|---:|---|\n");
        for result in vulnerable {
            for advisory in &result.advisories {
                let kev = if advisory.cisa_kev { "Yes" } else { "-" };
                let epss = advisory
                    .epss
                    .map(|e| format!("{:.1}%", e * 100.0))
                    .unwrap_or_else(|| "-".to_string());
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {:.1} | {} |\n",
                    result.host,
                    result.port,
                    md_cell(&advisory.id),
                    kev,
                    epss,
                    advisory.severity.label(),
                    advisory.cvss,
                    md_cell(&advisory.title)
                ));
            }
        }
        out.push('\n');
    }

    let tls_results: Vec<_> = results
        .iter()
        .filter(|result| result.tls.is_some())
        .collect();
    if !tls_results.is_empty() {
        out.push_str("## TLS Certificates\n\n");
        out.push_str("| Host | Port | Version | Subject | Issuer | Expires In | Flags |\n");
        out.push_str("|---|---:|---|---|---|---:|---|\n");
        for result in tls_results {
            let Some(tls) = &result.tls else {
                continue;
            };
            let mut flags = Vec::new();
            if tls.expired {
                flags.push("expired");
            }
            if tls.not_yet_valid {
                flags.push("not-yet-valid");
            }
            if tls.self_signed {
                flags.push("self-signed");
            }
            if !tls.hostname_matches {
                flags.push("hostname-mismatch");
            }
            let expires = tls
                .days_remaining
                .map(|days| format!("{days} days"))
                .unwrap_or_default();
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                result.host,
                result.port,
                md_cell(&tls.version),
                md_cell(tls.subject.as_deref().unwrap_or("")),
                md_cell(tls.issuer.as_deref().unwrap_or("")),
                expires,
                flags.join(", ")
            ));
        }
        out.push('\n');
    }

    let defenses = crate::defense::analyze_defenses(report);
    if !defenses.is_empty() {
        out.push_str("## Defense Posture\n\n");
        out.push_str("| Host | Posture | Confidence | Summary |\n");
        out.push_str("|---|---|---:|---|\n");
        let mut hosts: Vec<_> = defenses.iter().collect();
        hosts.sort_by_key(|(host, _)| *host);
        for (host, assessment) in hosts {
            out.push_str(&format!(
                "| {} | {} | {:.0}% | {} |\n",
                host,
                assessment.defense_type.badge(),
                assessment.confidence * 100.0,
                md_cell(&assessment.summary)
            ));
        }
        out.push('\n');
    }

    if let Some(diff) = diff {
        out.push_str("## Differential Analysis\n\n");
        out.push_str(&format!(
            "Baseline: `{}` · {} new, {} gone, {} modified, {} unchanged, {} posture, {} new critical advisories.\n\n",
            md_cell(&diff.baseline_source),
            diff.summary.new_ports,
            diff.summary.gone_ports,
            diff.summary.modified_ports,
            diff.summary.unchanged_ports,
            diff.summary.posture_changes,
            diff.summary.critical_advisories
        ));
        if !diff.port_changes.is_empty() {
            out.push_str("| Change | Host:Port | Detail |\n");
            out.push_str("|---|---|---|\n");
            for change in &diff.port_changes {
                out.push_str(&format!(
                    "| {} | {}:{} | {} |\n",
                    change.kind.tag(),
                    change.host,
                    change.port,
                    md_cell(&change.summary)
                ));
            }
            out.push('\n');
        }
        if !diff.posture_changes.is_empty() {
            out.push_str("| Posture Change | Host | Detail |\n");
            out.push_str("|---|---|---|\n");
            for change in &diff.posture_changes {
                out.push_str(&format!(
                    "| {} | {} | {} → {} |\n",
                    "[~] POSTURE", change.host, change.old_posture, change.new_posture
                ));
            }
            out.push('\n');
        }
    }

    out
}

/// Render a plain `host:port` list of open results for pipeline chaining.
fn render_host_port(results: &[&PortResult]) -> String {
    let mut output = String::new();
    for result in results {
        if result.state != PortState::Open {
            continue;
        }
        match result.host {
            IpAddr::V4(host) => {
                output.push_str(&format!("{host}:{}\n", result.port));
            }
            IpAddr::V6(host) => {
                output.push_str(&format!("[{host}]:{}\n", result.port));
            }
        }
    }
    output
}

/// Render discovered ports as a single comma-separated list, sorted numerically.
///
/// Only ports whose state is `Open` or `Silent` are included (i.e., ports that
/// accepted or at least acknowledged a connection). The result is ready to paste
/// directly into the `-p` argument of nmap, rayscan, netexec, impacket, or any
/// other tool that accepts a comma-separated port list.
///
/// Example output: `53,88,139,389,445,593,3268,3389,5985`
fn render_port_list(results: &[&PortResult]) -> String {
    let mut ports: Vec<u16> = results
        .iter()
        .filter(|r| matches!(r.state, PortState::Open | PortState::Silent))
        .map(|r| r.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if list.is_empty() {
        list
    } else {
        format!("{list}\n")
    }
}

/// Write a standalone JSON report to `path`, regardless of the display format.
pub fn write_json_report(
    report: &ScanReport,
    target: &str,
    show: StateSet,
    min_confidence: Option<u8>,
    diff: Option<&crate::diff::ScanDiff>,
    path: &Path,
    quiet: bool,
) -> Result<(), AppError> {
    let contents = render_json(report, target, show, min_confidence, diff)?;
    write_destination(Some(path), &contents, quiet)
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
                    confidence: Some(0.85),
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
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
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
        let output = render_table(
            &report,
            &results,
            TableOptions {
                theme: Theme::Minimal,
                ..Default::default()
            },
        );
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
        let output = render_table(
            &report,
            &results,
            TableOptions {
                theme: Theme::Minimal,
                dynamic_width: true,
                ..Default::default()
            },
        );
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
            TableOptions {
                theme: Theme::Minimal,
                explain: Some(80),
                ..Default::default()
            },
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
        let output = render_table(
            &report,
            &results,
            TableOptions {
                theme: Theme::Minimal,
                defense: true,
                ..Default::default()
            },
        );
        assert!(output.contains("Defense & Middlebox Intelligence:"));
        assert!(output.contains("Target 192.0.2.1:"));
        assert!(output.contains("Posture:"));
    }

    #[test]
    fn port_list_is_sorted_deduplicated_and_state_filtered() {
        let host: IpAddr = "192.0.2.1".parse().unwrap();
        // RSC-BUG-003 regression: duplicate results for one port (e.g. a port
        // probed by two probers) must not duplicate entries in the list.
        let results = [
            PortResult::new(host, 445, PortState::Open, Duration::from_millis(1)),
            PortResult::new(host, 135, PortState::Open, Duration::from_millis(1)),
            PortResult::new(host, 135, PortState::Open, Duration::from_millis(2)),
            PortResult::new(host, 53, PortState::Silent, Duration::from_millis(1)),
            PortResult::new(host, 80, PortState::Closed, Duration::from_millis(1)),
            PortResult::new(host, 22, PortState::Filtered, Duration::from_millis(1)),
        ];
        let refs: Vec<&PortResult> = results.iter().collect();
        assert_eq!(render_port_list(&refs), "53,135,445\n");
    }

    #[test]
    fn port_list_emit_is_pure_with_defense_and_advisories_enabled() {
        // RSC-BUG-002 / RSC-BUG-004 regression: with a machine-readable
        // format the emitted document must contain only results, even when
        // defense intelligence and advisory extras are requested.
        let dir = std::env::temp_dir().join(format!(
            "rayscan-portlist-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = dir.join("ports.txt");
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);

        emit(
            &report,
            "127.0.0.1",
            EmitOptions {
                format: OutputFormat::PortList,
                show: StateSet::all(),
                destination: Some(&path),
                quiet: true,
                theme: Theme::Minimal,
                streamed: false,
                min_confidence: None,
                explain: None,
                defense: true,
                advisories: true,
                stream: false,
                diff: None,
            },
        )
        .expect("emit port list");

        let contents = std::fs::read_to_string(&path).expect("read port list");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(contents, "80\n", "port-list output must contain only ports");
        assert!(!contents.contains("Defense"));
        assert!(!contents.contains("Posture"));
    }

    #[test]
    fn machine_readable_formats_are_classified() {
        assert!(OutputFormat::PortList.is_machine_readable());
        assert!(OutputFormat::Json.is_machine_readable());
        assert!(OutputFormat::Csv.is_machine_readable());
        assert!(!OutputFormat::Table.is_machine_readable());
        assert!(!OutputFormat::Markdown.is_machine_readable());
    }

    #[test]
    fn table_advisories_render_column_and_section() {
        let mut report = sample_report();
        report.results[0].service = Some(ServiceInfo {
            name: "ftp".to_string(),
            product: Some("vsFTPd".to_string()),
            version: Some("2.3.4".to_string()),
            confidence: Some(0.98),
        });
        report.results[0].banner = Some("220 (vsFTPd 2.3.4)".to_string());
        crate::accuracy::score_report(&mut report);
        crate::advisory::apply_advisories(&mut report);

        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_table(
            &report,
            &results,
            TableOptions {
                theme: Theme::Minimal,
                advisories: true,
                ..Default::default()
            },
        );
        assert!(output.contains("ADVISORIES"));
        assert!(output.contains("CVE-2011-2523"));
        assert!(output.contains("Vulnerability Advisory Correlation:"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn table_advisories_truncate_long_lists() {
        let mut report = sample_report();
        report.results[0].advisories = (0..12)
            .map(|index| crate::advisory::AdvisoryMatch {
                id: format!("CVE-2026-{index:04}"),
                title: "synthetic advisory".to_string(),
                severity: crate::advisory::Severity::High,
                cvss: 7.5,
                cisa_kev: false,
                epss: None,
                source: "nvd",
            })
            .collect();
        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_table(
            &report,
            &results,
            TableOptions {
                theme: Theme::Minimal,
                advisories: true,
                ..Default::default()
            },
        );
        assert!(output.contains("... and 2 more"));
        assert!(!output.contains("CVE-2026-0011"));
    }

    #[test]
    fn json_includes_correlated_advisories() {
        let mut report = sample_report();
        report.results[0].service = Some(ServiceInfo {
            name: "ftp".to_string(),
            product: Some("vsFTPd".to_string()),
            version: Some("2.3.4".to_string()),
            confidence: Some(0.98),
        });
        report.results[0].banner = Some("220 (vsFTPd 2.3.4)".to_string());
        crate::accuracy::score_report(&mut report);
        crate::advisory::apply_advisories(&mut report);

        let output = render_json(&report, "192.0.2.1", StateSet::all(), None, None).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(payload["open"][0]["advisories"][0]["id"], "CVE-2011-2523");
        assert_eq!(payload["open"][0]["advisories"][0]["severity"], "critical");
    }

    #[test]
    fn sarif_contains_rules_and_locations() {
        let mut report = sample_report();
        report.results[0].service = Some(ServiceInfo {
            name: "ftp".to_string(),
            product: Some("vsFTPd".to_string()),
            version: Some("2.3.4".to_string()),
            confidence: Some(0.98),
        });
        report.results[0].banner = Some("220 (vsFTPd 2.3.4)".to_string());
        crate::advisory::apply_advisories(&mut report);

        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_sarif(&results).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(payload["version"], "2.1.0");
        assert_eq!(payload["runs"][0]["tool"]["driver"]["name"], "rayscan");
        assert_eq!(payload["runs"][0]["results"][0]["ruleId"], "CVE-2011-2523");
        assert_eq!(payload["runs"][0]["results"][0]["level"], "error");
        assert!(
            payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                ["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .starts_with("tcp://")
        );
        assert_eq!(
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "CVE-2011-2523"
        );
    }

    #[test]
    fn markdown_includes_services_vulnerabilities_and_tls() {
        let mut report = sample_report();
        report.results[0].service = Some(ServiceInfo {
            name: "ftp".to_string(),
            product: Some("vsFTPd".to_string()),
            version: Some("2.3.4".to_string()),
            confidence: Some(0.98),
        });
        report.results[0].banner = Some("220 (vsFTPd 2.3.4)".to_string());
        report.results[0].tls = Some(crate::tls::TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
            subject: Some("CN=example.test".to_string()),
            issuer: Some("CN=example.test".to_string()),
            san: Vec::new(),
            serial: None,
            not_before: None,
            not_after: None,
            days_remaining: Some(30),
            expired: false,
            not_yet_valid: false,
            self_signed: true,
            hostname_matches: false,
            chain_len: 1,
            starttls: None,
        });
        crate::advisory::apply_advisories(&mut report);

        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_markdown(&report, "192.0.2.1", &results, None);
        assert!(output.contains("# rayscan scan report"));
        assert!(output.contains("## Services"));
        assert!(output.contains("CVE-2011-2523"));
        assert!(output.contains("## TLS Certificates"));
        assert!(output.contains("TLSv1.3"));
        assert!(output.contains("self-signed"));
        assert!(output.contains("hostname-mismatch"));
    }

    #[test]
    fn json_contains_open_and_optional_results() {
        let mut report = sample_report();
        crate::accuracy::score_report(&mut report);
        let output = render_json(&report, "192.0.2.1", StateSet::all(), None, None).unwrap();
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
        let output_high =
            render_json(&report, "192.0.2.1", StateSet::open(), Some(80), None).unwrap();
        let payload_high: serde_json::Value = serde_json::from_str(&output_high).unwrap();
        assert_eq!(payload_high["open"].as_array().unwrap().len(), 1);

        // Filter requiring 101% (impossible)
        let output_none =
            render_json(&report, "192.0.2.1", StateSet::open(), Some(101), None).unwrap();
        let payload_none: serde_json::Value = serde_json::from_str(&output_none).unwrap();
        assert_eq!(payload_none["open"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn default_json_omits_non_open_results() {
        let report = sample_report();
        let output = render_json(&report, "192.0.2.1", StateSet::open(), None, None).unwrap();
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

    #[test]
    fn host_port_format_lists_only_open_targets() {
        let report = sample_report();
        let results: Vec<&PortResult> = report.results.iter().collect();
        let output = render_host_port(&results);
        assert_eq!(output, "192.0.2.1:80\n");

        let v6 = PortResult::new(
            "2001:db8::5".parse().unwrap(),
            443,
            PortState::Open,
            Duration::from_millis(1),
        );
        let closed = PortResult::new(
            "192.0.2.1".parse().unwrap(),
            81,
            PortState::Closed,
            Duration::from_millis(1),
        );
        let mixed = render_host_port(&[&v6, &closed]);
        assert_eq!(mixed, "[2001:db8::5]:443\n");
    }
}
