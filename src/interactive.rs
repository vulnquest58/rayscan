use std::io::IsTerminal;
use std::path::PathBuf;

use inquire::{Confirm, InquireError, Select, Text};

use crate::cli::ScanArgs;
use crate::config::Profile;
use crate::error::AppError;
use crate::output::OutputFormat;
use crate::theme::Theme;

pub async fn run(theme: Option<Theme>) -> Result<(), AppError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(AppError::usage(
            "interactive mode requires a terminal; use `rayscan scan ...` for scripts",
        ));
    }

    let target = Text::new("Target (IP, host, CIDR, range, or file):")
        .with_default("127.0.0.1")
        .prompt()
        .map_err(prompt_error)?;

    let port_choices = vec!["Top 100", "Top 1000", "Well-known (1-1024)", "Custom ports"];
    let port_choice = Select::new("Ports to scan:", port_choices)
        .with_starting_cursor(0)
        .prompt()
        .map_err(prompt_error)?;
    let (ports, top_ports) = match port_choice {
        "Top 100" => (None, Some(100)),
        "Top 1000" => (None, Some(1000)),
        "Well-known (1-1024)" => (Some("1-1024".to_string()), None),
        _ => {
            let custom = Text::new("Port specification:")
                .with_default("80,443")
                .prompt()
                .map_err(prompt_error)?;
            (Some(custom), None)
        }
    };

    let profile_choice = Select::new("Profile:", vec!["Balanced", "Fast", "Careful", "Stealth"])
        .with_starting_cursor(0)
        .prompt()
        .map_err(prompt_error)?;
    let profile = match profile_choice {
        "Fast" => Profile::Fast,
        "Careful" => Profile::Careful,
        "Stealth" => Profile::Stealth,
        _ => Profile::Balanced,
    };

    let raw_syn_available = crate::syn::check_raw_privilege().is_ok();
    let mut modes = vec!["TCP connect (no root)"];
    if raw_syn_available {
        modes.push("Raw SYN discovery + verification");
        modes.push("Raw SYN + OS fingerprint");
    } else {
        eprintln!(
            "[interactive] raw SYN unavailable; using TCP connect mode (run via sudo for SYN/OS)"
        );
    }
    let mode = Select::new("Scan mode:", modes)
        .with_starting_cursor(0)
        .prompt()
        .map_err(prompt_error)?;
    let syn = mode.starts_with("Raw SYN");
    let os = mode.ends_with("OS fingerprint");

    let udp = Confirm::new("Probe common UDP services too?")
        .with_default(false)
        .prompt()
        .map_err(prompt_error)?;

    let formats = vec!["table", "json", "jsonl", "csv", "nmap-xml", "greppable"];
    let format_choice = Select::new("Output format:", formats)
        .with_starting_cursor(0)
        .prompt()
        .map_err(prompt_error)?;
    let format = match format_choice {
        "json" => OutputFormat::Json,
        "jsonl" => OutputFormat::Jsonl,
        "csv" => OutputFormat::Csv,
        "nmap-xml" => OutputFormat::NmapXml,
        "greppable" => OutputFormat::Greppable,
        _ => OutputFormat::Table,
    };

    let output = Text::new("Output file (leave empty for stdout):")
        .prompt()
        .map_err(prompt_error)?;
    let output = (!output.trim().is_empty()).then(|| PathBuf::from(output.trim()));

    let args = ScanArgs {
        target: vec![target],
        target_file: Vec::new(),
        exclude: Vec::new(),
        ports,
        top_ports,
        json: false,
        format: Some(format),
        output,
        profile: Some(profile),
        stealth: false,
        config: None,
        timeout: None,
        probe_timeout_ms: None,
        rate: None,
        workers: None,
        retries: None,
        randomize: false,
        sequential: false,
        top_ports_first: false,
        no_top_ports_first: false,
        discover_only: false,
        no_live: false,
        connect_only: false,
        verify: false,
        no_service_detection: false,
        udp,
        no_udp_probe: false,
        os,
        all_states: false,
        show: Vec::new(),
        ipv4: false,
        ipv6: false,
        quiet: false,
        syn,
        no_aimd: false,
        aimd_min_rate: None,
        retry_rate: None,
        anomaly_threshold: None,
        resume: None,
        save_state: None,
        min_confidence: None,
        explain: None,
        defense: false,
        advisories: false,
        no_db_update: false,
        diff: None,
        plugins: None,
        ping_sweep: false,
        ping_count: None,
        ping_timeout_ms: None,
        jitter_ms: None,
        decoys: None,
        fragment_size: None,
        tls: false,
        no_tls: false,
        shard_index: None,
        shard_count: None,
    };

    let start = Confirm::new("Start scan?")
        .with_default(true)
        .prompt()
        .map_err(prompt_error)?;
    if !start {
        println!("scan cancelled");
        return Ok(());
    }

    crate::run_scan(args, theme, None).await
}

fn prompt_error(error: InquireError) -> AppError {
    match error {
        InquireError::NotTTY => {
            AppError::usage("interactive mode requires a terminal; use `rayscan scan ...` instead")
        }
        InquireError::OperationCanceled | InquireError::OperationInterrupted => {
            AppError::usage("interactive session cancelled")
        }
        other => AppError::runtime(format!("interactive prompt failed: {other}")),
    }
}
