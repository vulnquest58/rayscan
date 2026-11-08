pub mod accuracy;
pub mod advisory;
pub mod anomaly;
pub mod classify;
pub mod cli;
pub mod config;
pub mod db;
pub mod defense;
pub mod diff;
pub mod discovery;
pub mod doctor;
pub mod error;
pub mod fingerprint;
pub mod interactive;
pub mod limits;
pub mod merge;
pub mod model;
pub mod output;
pub mod plugin;
pub mod ports;
pub mod rate;
pub mod resume;
pub mod rtt;
pub mod scanner;
pub mod service;
pub mod shard;
pub mod syn;
pub mod targets;
pub mod theme;
pub mod tls;
pub mod udp;
pub mod verify;

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};

pub use crate::cli::{Cli, Command, ScanArgs};
use crate::error::AppError;
use crate::model::StateSet;
use crate::scanner::{ProgressCallback, ProgressEvent, ScanOptions};
use crate::theme::{Theme, color_enabled};

pub async fn run(cli: Cli) -> Result<(), AppError> {
    let Cli {
        theme,
        db_dir,
        command,
    } = cli;
    match command {
        Command::Scan(args) => run_scan(args, theme, db_dir.as_deref()).await,
        Command::Diff(args) => diff::run_cli(args, theme),
        Command::Merge(args) => merge::run_cli(args),
        Command::Doctor(args) => doctor::run(args, theme),
        Command::Db(args) => db::run_cli(args, db_dir.as_deref(), theme),
        Command::Interactive => interactive::run(theme).await,
    }
}

pub(crate) async fn run_scan(
    args: ScanArgs,
    theme: Option<Theme>,
    db_dir: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let mut resolved = args.resolve()?;
    resolved.theme = theme.unwrap_or(resolved.theme);
    let plugins = match resolved.plugins.as_deref() {
        Some(path) => plugin::Registry::load(path)?,
        None => plugin::Registry::default(),
    };

    let db_paths = db::DbPaths::resolve(db_dir);
    if !resolved.no_db_update
        && let Some(paths) = &db_paths
    {
        db::auto_update(paths, args.quiet, resolved.advisories);
    }
    let local_index = if resolved.advisories {
        db_paths.as_ref().and_then(db::LocalIndex::load)
    } else {
        None
    };
    let resume_state = resolved
        .resume_file
        .as_ref()
        .map(|path| resume::load_state(path))
        .transpose()?;
    let (all_ports, ports_spec) = match &resume_state {
        Some(state) if args.ports.is_none() && args.top_ports.is_none() => {
            let ports = crate::ports::parse_spec(&state.ports_spec)?;
            (ports, state.ports_spec.clone())
        }
        _ => args.resolve_ports()?,
    };
    let mut targets = targets::resolve_targets(
        &args.target,
        &args.target_file,
        &args.exclude,
        resolved.family,
    )
    .await?;
    if let Some((index, count)) = resolved.shard {
        let before = targets.len();
        targets = shard::select(targets, index, count);
        if !args.quiet {
            eprintln!(
                "shard {index}/{count}: assigned {} of {before} resolved target(s)",
                targets.len()
            );
        }
    }
    if resolved.ping_sweep && !targets.is_empty() {
        let before = targets.len();
        if !args.quiet {
            eprintln!(
                "[discover] probing {before} host(s) with {} ping probe(s), {} ms timeout …",
                resolved.ping_count,
                resolved.ping_timeout.as_millis()
            );
        }
        targets = discovery::sweep(
            &targets,
            discovery::DiscoveryOptions {
                count: resolved.ping_count,
                timeout: resolved.ping_timeout,
            },
        )
        .await;
        if !args.quiet {
            eprintln!("[discover] {} of {before} host(s) responded", targets.len());
        }
    }
    if (resolved.resume_file.is_some() || resolved.save_state_file.is_some()) && targets.len() > 1 {
        return Err(AppError::usage(
            "resumable scans currently support a single target",
        ));
    }

    // ── Phase 6: Resume — load previous state and compute remaining ports ────
    let (prior_results, prior_counts, prior_scanned, mut ports) =
        if let Some(state) = resume_state.as_ref() {
            if !args.quiet {
                let audit = resume::ResumeGapAudit::build(state, &all_ports);
                eprint!(
                    "{}",
                    audit.format_terminal(color_enabled(
                        resolved.theme,
                        std::io::stderr().is_terminal()
                    ))
                );
            }
            let remaining = resume::remaining_ports(&all_ports, &state.ports_scanned);
            let (results, counts) = resume::restore_results(state);
            (results, counts, state.ports_scanned.clone(), remaining)
        } else {
            (
                vec![],
                crate::model::StateCounts::default(),
                vec![],
                all_ports.clone(),
            )
        };

    if resolved.top_ports_first {
        crate::ports::prioritize_ports(&mut ports);
    }

    if ports.is_empty() && resolved.resume_file.is_some() {
        if !args.quiet {
            eprintln!("[resume] all ports already scanned — outputting saved results");
        }
        // Build a synthetic complete report from the saved state.
        let mut report = crate::model::ScanReport {
            targets: targets.len(),
            ports: all_ports.len(),
            jobs: (targets.len() as u64) * (all_ports.len() as u64),
            workers: resolved.workers,
            elapsed: std::time::Duration::from_millis(0),
            counts: prior_counts,
            results: prior_results,
            os_fingerprints: HashMap::new(),
            probed_ports: all_ports.clone(),
            partial: false,
            defense_observations: Vec::new(),
        };
        tls::apply(
            &mut report,
            resolved.tls_mode,
            resolved.timeout.min(std::time::Duration::from_secs(5)),
            args.quiet,
        )
        .await;
        plugins
            .apply(&mut report.results, resolved.probe_timeout, args.quiet)
            .await;
        accuracy::score_report(&mut report);
        if resolved.advisories {
            advisory::apply_advisories_with(&mut report, local_index.as_ref());
        }
        let diff_report = if let Some(ref diff_path) = resolved.diff_file {
            match diff::load_baseline(diff_path) {
                Ok(baseline) => {
                    let diff_res = diff::ScanDiff::compute(
                        &diff_path.display().to_string(),
                        &args.target_label(),
                        &baseline,
                        &report,
                    );
                    Some(diff_res)
                }
                Err(e) => {
                    eprintln!("[rayscan] warning: failed to load baseline diff file: {e}");
                    None
                }
            }
        } else {
            None
        };
        return output::emit(
            &report,
            &args.target_label(),
            output::EmitOptions {
                format: resolved.format,
                show: resolved.show,
                destination: args.output.as_deref(),
                quiet: args.quiet,
                theme: resolved.theme,
                streamed: false,
                min_confidence: resolved.min_confidence,
                explain: resolved.explain,
                defense: resolved.defense,
                advisories: resolved.advisories,
                diff: diff_report.as_ref(),
            },
        );
    }

    let jobs = (targets.len() as u64)
        .checked_mul(ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;
    let target_label = args.target_label();
    let profile_name = args.profile.map(|p| p.as_str()).unwrap_or("balanced");
    let scan_mode = if resolved.syn_mode {
        if resolved.connect_only {
            "SYN (raw)"
        } else {
            "SYN+Verify"
        }
    } else if resolved.connect_only {
        "Connect (raw)"
    } else {
        "Connect+Verify"
    };

    // State files capture every probed outcome so an interrupted scan can be
    // resumed without losing silent/filtered ports.  Display filtering still
    // happens later in `output::emit`.
    let retain = if resolved.save_state_file.is_some() {
        StateSet::all()
    } else {
        resolved.show.union(StateSet::open())
    };
    let progress = make_progress(
        jobs,
        args.quiet,
        resolved.theme,
        &target_label,
        profile_name,
        scan_mode,
    );

    // ── Phase 6: Graceful Ctrl-C signal handling ─────────────────────────────
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = Arc::clone(&shutdown);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\n[rayscan] interrupted — saving partial results…");
            shutdown_signal.store(true, Ordering::Relaxed);
        }
    });

    let live_table_enabled = resolved.live_table
        && std::io::stdout().is_terminal()
        && !args.quiet
        && resolved.format == output::OutputFormat::Table
        && args.output.is_none();

    let live_streamed = Arc::new(AtomicBool::new(false));
    let live_streamed_ref = Arc::clone(&live_streamed);

    let callback: Option<ProgressCallback> = progress.as_ref().map(|bar| {
        let bar = bar.clone();
        let opens = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicU64::new(0));
        let filtered = Arc::new(AtomicU64::new(0));
        let silent = Arc::new(AtomicU64::new(0));
        let header_printed = Arc::new(AtomicBool::new(false));
        let seen_ports = Arc::new(Mutex::new(HashSet::<(IpAddr, u16)>::new()));
        let stdout_is_tty = std::io::stdout().is_terminal();
        let show = resolved.show;
        let theme = resolved.theme;
        let use_color = color_enabled(theme, stdout_is_tty);

        Arc::new(move |event: ProgressEvent| {
            bar.inc(1);
            if let Some(state) = event.state {
                match state {
                    crate::model::PortState::Open => {
                        opens.fetch_add(1, Ordering::Relaxed);
                    }
                    crate::model::PortState::Closed => {
                        closed.fetch_add(1, Ordering::Relaxed);
                    }
                    crate::model::PortState::Filtered => {
                        filtered.fetch_add(1, Ordering::Relaxed);
                    }
                    crate::model::PortState::Silent => {
                        silent.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }

            if live_table_enabled
                && let Some(result) = &event.result
                && show.contains(result.state)
            {
                let mut seen = seen_ports.lock().unwrap();
                if seen.insert((result.host, result.port)) {
                    if !header_printed.swap(true, Ordering::Relaxed) {
                        bar.println(output::format_live_header(theme, use_color));
                        bar.println(output::format_live_divider(use_color));
                        live_streamed_ref.store(true, Ordering::Relaxed);
                    }
                    bar.println(output::format_live_row(result, theme, use_color));
                }
            }

            let position = bar.position();
            if position % 16 == 0
                || position == jobs
                || event.state == Some(crate::model::PortState::Open)
            {
                bar.set_message(format!(
                    "Open: {}  Closed: {}  Filtered: {}  Silent: {}",
                    opens.load(Ordering::Relaxed),
                    closed.load(Ordering::Relaxed),
                    filtered.load(Ordering::Relaxed),
                    silent.load(Ordering::Relaxed)
                ));
            }
        }) as ProgressCallback
    });

    let scan_options = ScanOptions {
        timeout: resolved.timeout,
        probe_timeout: resolved.probe_timeout,
        rate: resolved.rate,
        workers: resolved.workers,
        retries: resolved.retries,
        randomize: resolved.randomize,
        connect_only: resolved.connect_only,
        service_detection: resolved.service_detection,
        retain,
        jitter: resolved.jitter,
        shutdown: Arc::clone(&shutdown),
    };

    let mut report = if resolved.syn_mode {
        let syn_opts = syn::SynScanOptions {
            targets: targets.clone(),
            ports: ports.clone(),
            rate_pps: resolved.rate,
            retry_rate_pps: 0, // auto: rate / 4
            sport_range: (61000, 61999),
            timeout_ms: (resolved.timeout.as_millis() as u64).clamp(500, 10000),
            batch_size: 64,
            retries: resolved.retries,
            retain,
            aimd: resolved.aimd,
            aimd_min_pps: resolved.aimd_min_pps,
            jitter_ms: resolved.jitter.as_millis().min(u128::from(u64::MAX)) as u64,
            decoys: resolved.decoys.clone(),
            fragment_size: resolved.fragment_size,
        };
        let mut report =
            match tokio::task::spawn_blocking(move || syn::syn_scan(syn_opts, callback))
                .await
                .map_err(|e| AppError::runtime(e.to_string()))?
            {
                Ok(report) => {
                    if let Some(bar) = &progress {
                        bar.finish_and_clear();
                    }
                    report
                }
                Err(error) => {
                    if let Some(bar) = &progress {
                        bar.abandon();
                    }
                    return Err(error);
                }
            };

        if !resolved.connect_only {
            let started = std::time::Instant::now();
            // Run anomaly detection before verification to avoid verifying
            // tens of thousands of ports on a tarpit host.
            let (_, candidates) =
                anomaly::partition_candidates(&mut report, resolved.anomaly_threshold);
            verify::verify_syn_open_candidates(&mut report, &candidates, &scan_options, None)
                .await?;
            report.elapsed += started.elapsed();
        }
        report
    } else {
        match scanner::scan(&targets, &ports, &scan_options, callback).await {
            Ok(report) => {
                if let Some(bar) = &progress {
                    bar.finish_and_clear();
                }
                report
            }
            Err(error) => {
                if let Some(bar) = &progress {
                    bar.abandon();
                }
                return Err(error);
            }
        }
    };

    // A local target lets two of our own in-flight connections pair up (TCP
    // simultaneous open) and be reported as listeners that do not exist.
    // Recheck every open one connection at a time — a lone connection cannot
    // pair with anything — and drop the ones that refuse.  Remote targets are
    // skipped inside the recheck, so external scans send no extra packets.
    let recheck_started = std::time::Instant::now();
    verify::recheck_local_opens(&mut report, &scan_options).await;
    report.elapsed += recheck_started.elapsed();

    // Phase 4: UDP detection — probe open TCP ports with UDP to surface
    // co-located UDP services (e.g., DNS on 53, NTP on 123, SNMP on 161).
    if resolved.udp_detection {
        let probe_timeout = resolved.probe_timeout;
        for result in report.results.iter_mut() {
            if result.state == crate::model::PortState::Open && result.service.is_none() {
                let (_, udp_det) = udp::probe_udp(result.host, result.port, probe_timeout).await;
                if let Some(udp_svc) = udp_det.service {
                    // Attach UDP service info into the banner field for visibility.
                    let label = match (&udp_svc.product, &udp_svc.version) {
                        (Some(p), Some(v)) => format!("udp:{} {}/{}", udp_svc.name, p, v),
                        (Some(p), None) => format!("udp:{} {}", udp_svc.name, p),
                        (None, Some(v)) => format!("udp:{} v{}", udp_svc.name, v),
                        (None, None) => format!("udp:{}", udp_svc.name),
                    };
                    result.banner = Some(label);
                    result.service = Some(crate::service::ServiceInfo {
                        name: format!("udp:{}", udp_svc.name),
                        product: udp_svc.product,
                        version: udp_svc.version,
                    });
                    if result.detail.is_none() {
                        result.detail = Some("udp".to_string());
                    }
                } else if let Some(banner) = udp_det.banner {
                    // Preserve raw UDP banner even without service identification.
                    if result.banner.is_none() {
                        result.banner = Some(format!("udp:{banner}"));
                    }
                }
            }
        }

        // Probe curated UDP ports independently of TCP state. This surfaces
        // UDP-only services such as DNS on 53, NTP on 123, or rpcbind on 111.
        let requested: HashSet<u16> = ports.iter().copied().collect();
        let mut already_open: HashSet<(IpAddr, u16)> = report
            .results
            .iter()
            .filter(|result| result.state == crate::model::PortState::Open)
            .map(|result| (result.host, result.port))
            .collect();
        let udp_ports: Vec<u16> = udp::COMMON_UDP_PORTS
            .iter()
            .copied()
            .filter(|port| requested.contains(port))
            .collect();
        for &host in &targets {
            for &port in &udp_ports {
                if already_open.contains(&(host, port)) {
                    continue;
                }
                let (_, detection) = udp::probe_udp(host, port, probe_timeout).await;
                let Some(service) = detection.service else {
                    continue;
                };
                let label = match (&service.product, &service.version) {
                    (Some(p), Some(v)) => format!("udp:{} {}/{}", service.name, p, v),
                    (Some(p), None) => format!("udp:{} {}", service.name, p),
                    (None, Some(v)) => format!("udp:{} v{}", service.name, v),
                    (None, None) => format!("udp:{}", service.name),
                };
                let mut result = crate::model::PortResult::new(
                    host,
                    port,
                    crate::model::PortState::Open,
                    std::time::Duration::ZERO,
                )
                .with_detail("udp");
                result.banner = Some(label);
                result.service = Some(crate::service::ServiceInfo {
                    name: format!("udp:{}", service.name),
                    product: service.product,
                    version: service.version,
                });
                report.results.push(result);
                report.counts.add(crate::model::PortState::Open);
                already_open.insert((host, port));
            }
        }
    }

    // Phase 5: OS fingerprinting — send one raw SYN probe per unique host
    // and classify the SYN-ACK reply using the TCP/IP stack signature DB.
    // Requires CAP_NET_RAW / root; silently skipped otherwise.
    if resolved.os_detection {
        let probe_timeout = resolved.probe_timeout;

        // Collect one open port per unique host.
        let mut host_ports: HashMap<std::net::IpAddr, u16> = HashMap::new();
        for result in &report.results {
            if result.state == crate::model::PortState::Open {
                host_ports.entry(result.host).or_insert(result.port);
            }
        }

        if !args.quiet && !host_ports.is_empty() {
            eprintln!("[os] fingerprinting {} host(s) …", host_ports.len());
        }

        let mut os_map = HashMap::new();
        for (host, port) in host_ports {
            if let Some(guess) =
                fingerprint::probe_fingerprint_async(host, port, probe_timeout).await
            {
                if !args.quiet {
                    let ev = guess
                        .evidence
                        .as_deref()
                        .map(|e| format!(" | Evidence: {e}"))
                        .unwrap_or_default();
                    eprintln!(
                        "[os] {} → {} ({}) confidence={:.0}%{}",
                        host,
                        guess.detail,
                        guess.family,
                        guess.confidence * 100.0,
                        ev
                    );
                }
                os_map.insert(host, guess);
            }
        }
        report.os_fingerprints = os_map;
    }

    // ── Phase 6: Merge prior results (from --resume) with new scan ──────────
    if resolved.resume_file.is_some() {
        // Append prior retained results and add their counts.
        report.results.extend(prior_results);
        report.counts.open += prior_counts.open;
        report.counts.closed += prior_counts.closed;
        report.counts.filtered += prior_counts.filtered;
        report.counts.silent += prior_counts.silent;
        report.counts.unreachable += prior_counts.unreachable;
        report.counts.error += prior_counts.error;
        report.jobs += (targets.len() as u64) * ((all_ports.len() - ports.len()) as u64);
        report.ports = all_ports.len();
    }

    tls::apply(
        &mut report,
        resolved.tls_mode,
        resolved.timeout.min(std::time::Duration::from_secs(5)),
        args.quiet,
    )
    .await;

    // ── Phase 6: Save state if requested ────────────────────────────────────
    if let Some(ref save_path) = resolved.save_state_file {
        let mut probed: HashSet<u16> = prior_scanned.iter().copied().collect();
        probed.extend(report.probed_ports.iter().copied());
        let probed_ports: Vec<u16> = all_ports
            .iter()
            .copied()
            .filter(|port| probed.contains(port))
            .collect();
        let state =
            resume::ScanState::from_report(&report, &target_label, &ports_spec, probed_ports);
        match resume::save_state(save_path, &state) {
            Ok(()) => {
                if !args.quiet {
                    eprintln!("[rayscan] scan state saved to {}", save_path.display());
                }
            }
            Err(e) => {
                eprintln!("[rayscan] warning: could not save state: {e}");
            }
        }
    }

    // If scan was partial, print a warning on stderr.
    if report.partial && !args.quiet {
        eprintln!("[rayscan] partial results — scan was interrupted before completion");
    }

    plugins
        .apply(&mut report.results, resolved.probe_timeout, args.quiet)
        .await;
    accuracy::score_report(&mut report);
    if resolved.advisories {
        advisory::apply_advisories_with(&mut report, local_index.as_ref());
    }

    let diff_report = if let Some(ref diff_path) = resolved.diff_file {
        match diff::load_baseline(diff_path) {
            Ok(baseline) => {
                let diff_res = diff::ScanDiff::compute(
                    &diff_path.display().to_string(),
                    &target_label,
                    &baseline,
                    &report,
                );
                Some(diff_res)
            }
            Err(e) => {
                eprintln!("[rayscan] warning: failed to load baseline diff file: {e}");
                None
            }
        }
    } else {
        None
    };

    output::emit(
        &report,
        &target_label,
        output::EmitOptions {
            format: resolved.format,
            show: resolved.show,
            destination: args.output.as_deref(),
            quiet: args.quiet,
            theme: resolved.theme,
            streamed: live_streamed.load(Ordering::Relaxed),
            min_confidence: resolved.min_confidence,
            explain: resolved.explain,
            defense: resolved.defense,
            advisories: resolved.advisories,
            diff: diff_report.as_ref(),
        },
    )
}

fn make_progress(
    jobs: u64,
    quiet: bool,
    theme: Theme,
    target_label: &str,
    profile_name: &str,
    scan_mode: &str,
) -> Option<ProgressBar> {
    let stderr_is_tty = std::io::stderr().is_terminal();
    if quiet || !stderr_is_tty {
        return None;
    }

    let bar = ProgressBar::new(jobs);
    let active_theme = if color_enabled(theme, stderr_is_tty) {
        theme
    } else {
        Theme::Minimal
    };
    let style = ProgressStyle::with_template(active_theme.progress_template())
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-");
    bar.set_style(style);
    bar.set_message("Open: 0  Closed: 0  Filtered: 0  Silent: 0");
    if !quiet && stderr_is_tty {
        eprintln!(
            "Scanning {}  |  Profile: {}  |  Mode: {}",
            target_label, profile_name, scan_mode
        );
    }
    Some(bar)
}
