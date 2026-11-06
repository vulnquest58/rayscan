//! Raw SYN packet scanning engine.
//!
//! Provides high-speed raw TCP SYN scanning using Linux `AF_PACKET` sockets,
//! kernel BPF filtering, SipHash-1-3 SYN cookies, and BlackRock permutation.

#[cfg(target_os = "linux")]
pub mod aimd;
#[cfg(target_os = "linux")]
pub mod cookie;
#[cfg(target_os = "linux")]
pub mod engine;
#[cfg(target_os = "linux")]
pub mod filter;
#[cfg(target_os = "linux")]
pub mod packet;
#[cfg(target_os = "linux")]
pub mod permute;
#[cfg(target_os = "linux")]
pub mod route;

#[cfg(target_os = "linux")]
pub use aimd::{AimdConfig, AimdController};
#[cfg(target_os = "linux")]
pub use cookie::CookieKey;
#[cfg(target_os = "linux")]
pub use engine::{SynScanOptions, check_raw_privilege, syn_scan};
#[cfg(target_os = "linux")]
pub use filter::{attach_filter, build_filter};
#[cfg(target_os = "linux")]
pub use packet::{ParsedFrame, build_syn_frame, ip_checksum, parse_frame, tcp_checksum};
#[cfg(target_os = "linux")]
pub use permute::BlackRock;
#[cfg(target_os = "linux")]
pub use route::{
    RouteInfo, SynError, arp_resolve, default_route, iface_index, iface_ip, iface_mac,
};

#[cfg(not(target_os = "linux"))]
use crate::error::AppError;
#[cfg(not(target_os = "linux"))]
use crate::model::ScanReport;
#[cfg(not(target_os = "linux"))]
use crate::scanner::ProgressCallback;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Default)]
pub struct SynScanOptions {
    pub targets: Vec<std::net::IpAddr>,
    pub ports: Vec<u16>,
    pub rate_pps: u64,
    pub retry_rate_pps: u64,
    pub sport_range: (u16, u16),
    pub timeout_ms: u64,
    pub batch_size: usize,
    pub retries: u32,
    pub retain: crate::model::StateSet,
    pub aimd: bool,
    pub aimd_min_pps: u64,
}

#[cfg(not(target_os = "linux"))]
pub fn check_raw_privilege() -> Result<(), AppError> {
    Err(AppError::usage("raw SYN scanning requires Linux"))
}

#[cfg(not(target_os = "linux"))]
pub fn syn_scan(
    _opts: SynScanOptions,
    _progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    Err(AppError::usage("raw SYN scanning requires Linux"))
}
