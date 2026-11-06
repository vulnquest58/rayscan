use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::config::{self, Profile, StateFilter};
use crate::error::AppError;
use crate::limits::MAX_WORKERS;
use crate::model::StateSet;
use crate::output::OutputFormat;
use crate::targets::AddressFamily;
use crate::theme::Theme;

#[derive(Debug, Parser)]
#[command(
    name = "rayscan",
    version,
    about = "An accuracy-first TCP port scanner",
    long_about = "An accuracy-first TCP/UDP scanner. Rayscan uses a bounded worker pool, \
                  adaptive per-host timeouts, a global rate limit, and a short \
                  service-verification read so a bare handshake from a tarpit or SYN \
                  proxy is not reported as an open service. Responsive services are \
                  identified from their banners, including common products and versions. \
                  On Linux, --syn performs raw SYN discovery and verifies responsive \
                  candidates over TCP. A UDP scanner is available for service \
                  detection on ports that accept UDP traffic.",
    arg_required_else_help = true,
    subcommand_required = true,
    after_help = "Examples:\n  rayscan scan --target 127.0.0.1 --ports 1-1024\n  rayscan scan -t 10.0.0.0/24 -p 22,80,443 --json\n  rayscan scan -t 10.77.0.2 -p 1-10000 --profile careful --show all"
)]
pub struct Cli {
    /// Color theme for tables, progress, and diagnostics.
    #[arg(long, global = true, value_enum, value_name = "THEME")]
    pub theme: Option<Theme>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Scan TCP ports on one or more targets.
    Scan(ScanArgs),
    /// Check permissions, terminal support, and scan capabilities.
    Doctor(DoctorArgs),
    /// Set up and run a scan with guided prompts.
    Interactive,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("target_source")
        .required(true)
        .multiple(true)
        .args(["target", "target_file"])
))]
pub struct ScanArgs {
    /// Target host, IP, CIDR, range, or file path. Repeatable.
    #[arg(short = 't', long = "target", value_name = "TARGET")]
    pub target: Vec<String>,

    /// Read targets from a file, one target or CIDR per line. Repeatable.
    #[arg(long = "target-file", value_name = "FILE")]
    pub target_file: Vec<PathBuf>,

    /// Exclude a target, CIDR, range, or @file. Repeatable.
    #[arg(long, value_name = "TARGET")]
    pub exclude: Vec<String>,

    /// Ports to scan, for example 80,443,8000-8100. Defaults to 1-1024 if omitted.
    #[arg(short = 'p', long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Scan the top N most common ports (e.g. 10, 100, 1000).
    #[arg(long, value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Emit the benchmark-compatible JSON report.
    #[arg(long, conflicts_with = "format")]
    pub json: bool,

    /// Output format.
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write results to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Configuration profile.
    #[arg(long, value_enum)]
    pub profile: Option<Profile>,

    /// Enable stealth mode (slow rate 20 pps, randomized order, high retries).
    #[arg(long)]
    pub stealth: bool,

    /// Read settings from a TOML file. Defaults to rayscan.toml if present.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Per-connect timeout ceiling in seconds.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<f64>,

    /// How long to wait for a banner before calling a handshake silent, in ms.
    #[arg(long, value_name = "MS")]
    pub probe_timeout_ms: Option<u64>,

    /// Global probes per second. 0 means unlimited.
    #[arg(long, visible_alias = "max-rate", value_name = "N")]
    pub rate: Option<u64>,

    /// Worker count. 0 means automatic: cores × 32 capped at 512, bounded by RLIMIT_NOFILE.
    #[arg(long, value_name = "N")]
    pub workers: Option<usize>,

    /// Retries for local resource failures such as EMFILE.
    #[arg(long, value_name = "N")]
    pub retries: Option<u32>,

    /// Shuffle target and port order.
    #[arg(long, conflicts_with = "sequential")]
    pub randomize: bool,

    /// Keep target and port order. Overrides config randomize.
    #[arg(long)]
    pub sequential: bool,

    /// Scan most common ports first to minimize time-to-first-result.
    #[arg(long, conflicts_with = "randomize")]
    pub top_ports_first: bool,

    /// Fast discovery mode: report open ports immediately without service/banner inspection.
    #[arg(long, conflicts_with = "verify")]
    pub discover_only: bool,

    /// Disable real-time live results table streaming during scan.
    #[arg(long)]
    pub no_live: bool,

    /// Report handshake success as open without banner or connect verification.
    #[arg(long, conflicts_with = "verify")]
    pub connect_only: bool,

    /// Verify that a handshake yields a banner or immediate close.
    #[arg(long)]
    pub verify: bool,

    /// Disable banner-based service and version detection.
    #[arg(long)]
    pub no_service_detection: bool,

    /// Enable UDP service detection (passive banner read + optional active probe).
    #[arg(long)]
    pub udp: bool,

    /// Disable UDP active probe; only perform the initial passive banner read.
    #[arg(long)]
    pub no_udp_probe: bool,

    /// Enable OS fingerprinting via TCP/IP stack analysis (requires root/CAP_NET_RAW).
    /// Sends one raw SYN probe per discovered host and classifies the SYN-ACK reply.
    #[arg(long)]
    pub os: bool,

    /// Show every port state.
    #[arg(long)]
    pub all_states: bool,

    /// States to display. Repeat or comma-separate.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "STATE")]
    pub show: Vec<StateFilter>,

    /// Resolve and scan only IPv4 targets.
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Resolve and scan only IPv6 targets.
    #[arg(short = '6', long)]
    pub ipv6: bool,

    /// Suppress progress and status messages.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Use raw SYN discovery, then verify responsive ports (root/CAP_NET_RAW, Linux only).
    #[arg(long)]
    pub syn: bool,

    /// Disable AIMD adaptive rate control during raw SYN scanning.
    #[arg(long)]
    pub no_aimd: bool,

    /// AIMD minimum rate floor in packets per second (default: 100).
    #[arg(long, value_name = "N")]
    pub aimd_min_rate: Option<u64>,

    /// Rate used for SYN retransmission passes in packets per second.
    /// 0 means auto (rate / 4, minimum 100). Default: 0.
    #[arg(long, value_name = "N")]
    pub retry_rate: Option<u64>,

    /// Per-host SYN-open count above which the host is treated as anomalous
    /// (tarpit/SYN-proxy farm) and verification is sampled.  0 disables.
    /// Default: 1000.
    #[arg(long, value_name = "N")]
    pub anomaly_threshold: Option<u32>,

    /// Resume a previous interrupted scan from a saved state file.
    /// Ports already probed in the state file are skipped; results are merged.
    #[arg(long, value_name = "FILE")]
    pub resume: Option<PathBuf>,

    /// Save scan state to a file on completion or interruption (Ctrl-C).
    /// Use with --resume to continue an interrupted scan.
    #[arg(long, value_name = "FILE")]
    pub save_state: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    pub timeout: Duration,
    pub probe_timeout: Duration,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
    pub randomize: bool,
    pub connect_only: bool,
    pub service_detection: bool,
    pub udp_detection: bool,
    /// Enable OS fingerprinting stage (Phase 5).
    pub os_detection: bool,
    pub format: OutputFormat,
    pub show: StateSet,
    pub family: AddressFamily,
    pub syn_mode: bool,
    /// Enable AIMD adaptive rate control during SYN scan.
    pub aimd: bool,
    /// AIMD minimum rate floor in packets per second.
    pub aimd_min_pps: u64,
    /// Per-host SYN-open count above which the host is treated as an anomaly.
    /// `0` disables anomaly detection.
    pub anomaly_threshold: u32,
    /// Scan most common ports first.
    pub top_ports_first: bool,
    /// Stream live results table during scan.
    pub live_table: bool,
    /// Path to a saved state file to resume from.
    pub resume_file: Option<PathBuf>,
    /// Path to write the scan state on completion or interruption.
    pub save_state_file: Option<PathBuf>,
    /// Selected color theme.
    pub theme: Theme,
}

impl ScanArgs {
    pub fn resolve(&self) -> Result<ResolvedConfig, AppError> {
        let file = config::load(self.config.as_deref())?;
        let profile = if self.stealth {
            self.profile.unwrap_or(Profile::Stealth)
        } else {
            self.profile.or(file.profile).unwrap_or_default()
        };
        let defaults = profile.defaults();

        let timeout_seconds = self
            .timeout
            .or(file.timeout)
            .unwrap_or(defaults.timeout_seconds);
        if !timeout_seconds.is_finite() || timeout_seconds <= 0.0 || timeout_seconds > 300.0 {
            return Err(AppError::usage(
                "--timeout must be greater than 0 and at most 300 seconds",
            ));
        }

        let probe_timeout_ms = self
            .probe_timeout_ms
            .or(file.probe_timeout_ms)
            .unwrap_or(defaults.probe_timeout_ms);
        if !(10..=60_000).contains(&probe_timeout_ms) {
            return Err(AppError::usage(
                "--probe-timeout-ms must be between 10 and 60000",
            ));
        }

        let rate = self.rate.or(file.rate).unwrap_or(defaults.rate);
        if rate > 1_000_000 {
            return Err(AppError::usage("--rate must be at most 1000000"));
        }

        let workers = self.workers.or(file.workers).unwrap_or(defaults.workers);
        if workers > MAX_WORKERS {
            return Err(AppError::usage(format!(
                "--workers must be at most {MAX_WORKERS}"
            )));
        }

        let retries = self.retries.or(file.retries).unwrap_or(defaults.retries);
        if retries > 10 {
            return Err(AppError::usage("--retries must be at most 10"));
        }

        let randomize = if self.randomize || (self.stealth && !self.sequential) {
            true
        } else if self.sequential {
            false
        } else {
            file.randomize.unwrap_or(false)
        };

        let connect_only = if self.discover_only || self.connect_only {
            true
        } else if self.verify {
            false
        } else {
            file.connect_only.unwrap_or(false)
        };

        let service_detection = if self.discover_only || self.no_service_detection {
            false
        } else {
            file.service_detection.unwrap_or(true)
        } && !connect_only;

        let udp_detection = if self.no_udp_probe {
            false
        } else {
            file.udp_probe.unwrap_or(true)
        } && self.udp;

        let format = if self.json {
            OutputFormat::Json
        } else {
            self.format.or(file.format).unwrap_or(OutputFormat::Table)
        };

        let show = if self.all_states {
            StateSet::all()
        } else if !self.show.is_empty() {
            config::state_set(&self.show)
        } else if let Some(filters) = file.show.as_deref() {
            config::state_set(filters)
        } else {
            StateSet::open()
        };

        let family = if self.ipv4 {
            AddressFamily::V4
        } else if self.ipv6 {
            AddressFamily::V6
        } else {
            AddressFamily::Any
        };

        Ok(ResolvedConfig {
            timeout: Duration::from_secs_f64(timeout_seconds),
            probe_timeout: Duration::from_millis(probe_timeout_ms),
            rate,
            workers,
            retries,
            randomize,
            connect_only,
            service_detection,
            udp_detection,
            os_detection: self.os,
            format,
            show,
            family,
            syn_mode: self.syn,
            aimd: !self.no_aimd,
            aimd_min_pps: self.aimd_min_rate.unwrap_or(100),
            anomaly_threshold: self.anomaly_threshold.unwrap_or(1000),
            top_ports_first: self.top_ports_first,
            live_table: !self.no_live,
            resume_file: self.resume.clone(),
            save_state_file: self.save_state.clone(),
            theme: file.theme.unwrap_or_default(),
        })
    }

    pub fn target_label(&self) -> String {
        let mut parts = self.target.clone();
        parts.extend(
            self.target_file
                .iter()
                .map(|path| path.display().to_string()),
        );
        if parts.is_empty() {
            "targets".to_string()
        } else {
            parts.join(",")
        }
    }

    /// Resolve the ports to scan and return `(ports_vec, spec_string)`.
    ///
    /// If `--ports` is given, parses that list/range.
    /// If `--top-ports N` is given, returns the top N most common ports.
    /// Otherwise, defaults to `"1-1024"`.
    pub fn resolve_ports(&self) -> Result<(Vec<u16>, String), AppError> {
        if let Some(ref p) = self.ports {
            let ports = crate::ports::parse_ports(p)?;
            Ok((ports, p.clone()))
        } else if let Some(n) = self.top_ports {
            let ports = crate::ports::top_ports(n)?;
            Ok((ports, format!("top-{n}")))
        } else {
            let default_spec = "1-1024";
            let ports = crate::ports::parse_ports(default_spec)?;
            Ok((ports, default_spec.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ScanArgs {
        ScanArgs {
            target: vec!["192.0.2.1".to_string()],
            target_file: Vec::new(),
            exclude: Vec::new(),
            ports: Some("80".to_string()),
            top_ports: None,
            json: false,
            format: None,
            output: None,
            profile: None,
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
            discover_only: false,
            no_live: false,
            connect_only: false,
            verify: false,
            no_service_detection: false,
            udp: false,
            no_udp_probe: false,
            os: false,
            all_states: false,
            show: Vec::new(),
            ipv4: false,
            ipv6: false,
            quiet: false,
            syn: false,
            no_aimd: false,
            aimd_min_rate: None,
            retry_rate: None,
            anomaly_threshold: None,
            resume: None,
            save_state: None,
        }
    }

    #[test]
    fn defaults_are_balanced_and_verified() {
        let resolved = args().resolve().unwrap();
        assert!(!resolved.connect_only);
        assert!(!resolved.randomize);
        assert!(resolved.service_detection);
        assert_eq!(resolved.format, OutputFormat::Table);
        assert!(resolved.show.contains(crate::model::PortState::Open));
        assert!(!resolved.show.contains(crate::model::PortState::Closed));
    }

    #[test]
    fn stealth_mode_activates_stealth_defaults_and_randomize() {
        let mut stealth_args = args();
        stealth_args.stealth = true;
        let resolved = stealth_args.resolve().unwrap();
        assert!(resolved.randomize);
        assert_eq!(resolved.rate, 20);
        assert_eq!(resolved.workers, 8);
        assert_eq!(resolved.retries, 3);
        assert_eq!(resolved.probe_timeout, Duration::from_millis(1000));

        // When sequential is explicitly requested, randomize stays false
        let mut seq_stealth = args();
        seq_stealth.stealth = true;
        seq_stealth.sequential = true;
        let resolved_seq = seq_stealth.resolve().unwrap();
        assert!(!resolved_seq.randomize);
        assert_eq!(resolved_seq.rate, 20);
    }

    #[test]
    fn service_detection_can_be_disabled_or_implied_off() {
        let mut disabled = args();
        disabled.no_service_detection = true;
        assert!(!disabled.resolve().unwrap().service_detection);

        let mut connect_only = args();
        connect_only.connect_only = true;
        assert!(!connect_only.resolve().unwrap().service_detection);

        let mut no_udp = args();
        no_udp.udp = true;
        no_udp.no_udp_probe = true;
        assert!(!no_udp.resolve().unwrap().udp_detection);
    }

    #[test]
    fn validation_rejects_bad_bounds() {
        let mut invalid = args();
        invalid.timeout = Some(0.0);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);

        let mut invalid = args();
        invalid.workers = Some(MAX_WORKERS + 1);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn resolve_ports_defaults_to_well_known_when_omitted() {
        let mut no_ports = args();
        no_ports.ports = None;
        no_ports.top_ports = None;
        let (ports, spec) = no_ports.resolve_ports().unwrap();
        assert_eq!(spec, "1-1024");
        assert_eq!(ports.len(), 1024);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[1023], 1024);
    }

    #[test]
    fn resolve_ports_top_ports_works() {
        let mut top = args();
        top.ports = None;
        top.top_ports = Some(20);
        let (ports, spec) = top.resolve_ports().unwrap();
        assert_eq!(spec, "top-20");
        assert_eq!(ports.len(), 20);
        assert_eq!(ports[0], 80);
    }

    #[test]
    fn discover_only_and_speed_flags_work() {
        let mut disc = args();
        disc.discover_only = true;
        let resolved = disc.resolve().unwrap();
        assert!(resolved.connect_only);
        assert!(!resolved.service_detection);

        let mut prioritized = args();
        prioritized.top_ports_first = true;
        assert!(prioritized.resolve().unwrap().top_ports_first);

        let mut no_live = args();
        no_live.no_live = true;
        assert!(!no_live.resolve().unwrap().live_table);
    }
}
