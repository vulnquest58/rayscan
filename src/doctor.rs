use std::io::IsTerminal;
use std::path::Path;

use comfy_table::{Attribute, Cell, ColumnConstraint, ContentArrangement, Table, Width};
use serde::Serialize;

use crate::cli::DoctorArgs;
use crate::config;
use crate::error::AppError;
use crate::theme::{Theme, color_enabled};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    const fn color(self) -> comfy_table::Color {
        match self {
            Self::Pass => comfy_table::Color::Green,
            Self::Warn => comfy_table::Color::Yellow,
            Self::Fail => comfy_table::Color::Red,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct Check {
    name: &'static str,
    status: CheckStatus,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorReport {
    version: &'static str,
    platform: String,
    theme: &'static str,
    checks: Vec<Check>,
}

pub fn run(args: DoctorArgs, theme: Option<Theme>) -> Result<(), AppError> {
    let theme = theme.unwrap_or_default();
    let report = collect(theme);

    if args.json {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|error| AppError::runtime(format!("cannot encode doctor JSON: {error}")))?;
        println!("{json}");
        return Ok(());
    }

    print_report(&report, theme);
    Ok(())
}

fn collect(theme: Theme) -> DoctorReport {
    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    let mut checks = Vec::new();

    checks.push(Check {
        name: "platform",
        status: CheckStatus::Pass,
        detail: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    });

    checks.push(Check {
        name: "terminal",
        status: if stdin_tty && stdout_tty {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: format!(
            "stdin={} stdout={} stderr={}",
            tty_label(stdin_tty),
            tty_label(stdout_tty),
            tty_label(stderr_tty)
        ),
    });

    let colored = color_enabled(theme, stdout_tty);
    checks.push(Check {
        name: "color",
        status: if colored {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if colored {
            format!("{} theme enabled", theme.as_str())
        } else {
            format!(
                "{} theme is plain (NO_COLOR, minimal, or non-TTY)",
                theme.as_str()
            )
        },
    });

    checks.push(Check {
        name: "workers",
        status: CheckStatus::Pass,
        detail: format!(
            "{} automatic workers for 65,535 probes",
            crate::limits::worker_count(0, 65_535)
        ),
    });

    checks.push(Check {
        name: "udp",
        status: CheckStatus::Pass,
        detail: "DNS, rpcbind, SNMP, NTP, NetBIOS, and SIP probes available".to_string(),
    });

    checks.push(config_check());
    checks.push(raw_syn_check());
    checks.push(route_check());

    DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        theme: theme.as_str(),
        checks,
    }
}

fn tty_label(is_tty: bool) -> &'static str {
    if is_tty { "tty" } else { "pipe" }
}

fn config_check() -> Check {
    let path = Path::new("rayscan.toml");
    if !path.is_file() {
        return Check {
            name: "config",
            status: CheckStatus::Pass,
            detail: "built-in defaults (no rayscan.toml)".to_string(),
        };
    }
    match config::load(Some(path)) {
        Ok(_) => Check {
            name: "config",
            status: CheckStatus::Pass,
            detail: format!("{} loaded", path.display()),
        },
        Err(error) => Check {
            name: "config",
            status: CheckStatus::Fail,
            detail: error.to_string(),
        },
    }
}

#[cfg(target_os = "linux")]
fn raw_syn_check() -> Check {
    match crate::syn::check_raw_privilege() {
        Ok(()) => Check {
            name: "raw-syn",
            status: CheckStatus::Pass,
            detail: "raw SYN and OS fingerprinting available".to_string(),
        },
        Err(error) => Check {
            name: "raw-syn",
            status: CheckStatus::Warn,
            detail: format!("{error}; run with sudo or grant CAP_NET_RAW"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn raw_syn_check() -> Check {
    Check {
        name: "raw-syn",
        status: CheckStatus::Warn,
        detail: "requires Linux; connect and UDP scanning are available".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn route_check() -> Check {
    match crate::syn::default_route() {
        Ok(route) => Check {
            name: "route",
            status: CheckStatus::Pass,
            detail: format!(
                "{} via {} ({})",
                route.iface, route.gateway_ip, route.src_ip
            ),
        },
        Err(error) => Check {
            name: "route",
            status: CheckStatus::Warn,
            detail: error.to_string(),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn route_check() -> Check {
    Check {
        name: "route",
        status: CheckStatus::Warn,
        detail: "raw route diagnostics are Linux-only".to_string(),
    }
}

fn print_report(report: &DoctorReport, theme: Theme) {
    let stdout_tty = std::io::stdout().is_terminal();
    let use_color = color_enabled(theme, stdout_tty);

    let mut table = Table::new();
    table.load_preset(theme.table_preset());
    if stdout_tty {
        table.set_content_arrangement(ContentArrangement::Dynamic);
    } else {
        table.force_no_tty();
    }

    let header = |label: &str| {
        let cell = Cell::new(label);
        if use_color {
            cell.fg(theme.accent()).add_attribute(Attribute::Bold)
        } else {
            cell
        }
    };
    table.set_header(vec![header("CHECK"), header("STATUS"), header("DETAIL")]);
    table.set_constraints(vec![
        ColumnConstraint::LowerBoundary(Width::Fixed(10)),
        ColumnConstraint::LowerBoundary(Width::Fixed(8)),
        ColumnConstraint::LowerBoundary(Width::Fixed(30)),
    ]);

    for check in &report.checks {
        let status = if use_color {
            Cell::new(check.status.label()).fg(check.status.color())
        } else {
            Cell::new(check.status.label())
        };
        table.add_row(vec![
            Cell::new(check.name),
            status,
            Cell::new(&check.detail),
        ]);
    }

    println!(
        "rayscan {} doctor — {} ({})",
        report.version, report.platform, report.theme
    );
    println!("{table}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serializes_without_terminal_control() {
        let report = collect(Theme::Minimal);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"platform\""));
        assert!(!report.checks.is_empty());
    }
}
