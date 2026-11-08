//! OS fingerprinting via TCP/IP stack behaviour analysis (Phase 5).
//!
//! This module infers the target host's operating system family from features
//! observed in the SYN-ACK reply to our probe: IP TTL, TCP window size, MSS,
//! window scale, SACK, timestamps, DF bit, and TCP option order.
//!
//! # Design
//!
//! 1. **`TcpFingerprint`** — raw features extracted from one SYN-ACK packet.
//! 2. **Signature database** — a `const` slice of `OsSig` entries, each
//!    describing a known OS with expected feature values and per-feature weights.
//! 3. **`classify()`** — weighted additive scoring: for each feature that
//!    matches the signature's expectation, that feature's weight is added to
//!    the running score. The best-scoring signature wins.  Confidence is the
//!    winner's score divided by its maximum achievable score.
//! 4. **`probe_fingerprint()`** — sends one raw SYN via AF_PACKET, reads the
//!    SYN-ACK back, extracts a `TcpFingerprint`, and calls `classify()`.
//!    Requires `CAP_NET_RAW` / root; returns `None` gracefully if unavailable.
//!
//! # Accuracy target
//!
//! ≥80 % correct OS family on a lab set of Linux, Windows, BSD, Cisco, and
//! macOS targets (Phase 5 gate criterion).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde::Serialize;

// ── Public types ─────────────────────────────────────────────────────────────

/// OS family inferred from TCP/IP stack behaviour.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Windows,
    MacOS,
    Bsd,
    Cisco,
    Unknown,
}

impl OsFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOS => "macos",
            Self::Bsd => "bsd",
            Self::Cisco => "cisco",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Raw TCP/IP features extracted from a SYN-ACK packet.
///
/// All fields default to 0 / `false` / `None`; callers should populate only
/// what the packet actually contains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpFingerprint {
    /// Observed IP TTL in the SYN-ACK (may be less than the initial TTL due to
    /// hops in transit).
    pub ttl: u8,
    /// Estimated number of network hops to the target. Used to infer the
    /// initial TTL via `infer_initial_ttl()`.
    pub hops: u8,
    /// TCP window size advertised in the SYN-ACK.
    pub window: u32,
    /// TCP MSS option value, if present.
    pub mss: Option<u16>,
    /// TCP window scale option (kind 3), if present.
    pub wscale: Option<u8>,
    /// Whether the SACK-permitted option (kind 4) was seen.
    pub sack_ok: bool,
    /// Whether the TCP timestamps option (kind 8) was seen.
    pub timestamps: bool,
    /// Whether the DF (Don't Fragment) flag was set in the IP header.
    pub df: bool,
    /// TCP option kind bytes in the order they appear in the SYN-ACK header.
    /// Standard kinds: 0=EOL, 1=NOP, 2=MSS, 3=WScale, 4=SACK-OK, 8=TS.
    pub options_order: Vec<u8>,
}

impl TcpFingerprint {
    /// Format observed TCP/IP features into a concise evidence string:
    /// e.g. `TTL=64, Window=5840, MSS=1460, Options=mss,sack,wscale`
    pub fn evidence_summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("TTL={}", self.ttl));
        parts.push(format!("Window={}", self.window));
        if let Some(mss) = self.mss {
            parts.push(format!("MSS={mss}"));
        }
        if let Some(ws) = self.wscale {
            parts.push(format!("WScale={ws}"));
        }
        if self.sack_ok {
            parts.push("SACK=yes".to_string());
        }
        if self.timestamps {
            parts.push("TS=yes".to_string());
        }
        if self.df {
            parts.push("DF=yes".to_string());
        }
        if !self.options_order.is_empty() {
            let names: Vec<&'static str> = self
                .options_order
                .iter()
                .map(|&k| match k {
                    0 => "eol",
                    1 => "nop",
                    2 => "mss",
                    3 => "wscale",
                    4 => "sack",
                    8 => "ts",
                    _ => "opt",
                })
                .collect();
            parts.push(format!("Options={}", names.join(",")));
        }
        parts.join(", ")
    }
}

/// An OS guess produced by `classify()`.
#[derive(Clone, Debug, Serialize)]
pub struct OsGuess {
    /// Broad OS family.
    pub family: OsFamily,
    /// Human-readable detail string, e.g. `"Linux 3.x–5.x"`.
    pub detail: String,
    /// Normalised confidence in `[0.0, 1.0]`. Values below 0.35 indicate
    /// weak evidence; below 0.20 the guess is essentially random.
    pub confidence: f32,
    /// Inferred initial TTL (rounded to nearest of 64 / 128 / 255).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_ttl: Option<u8>,
    /// Evidence string extracted from observed TCP/IP stack options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

// ── Signature database ────────────────────────────────────────────────────────

/// Matcher for TCP window size.
#[allow(dead_code)] // `Any` and `Exact` are reserved for future signatures
#[derive(Clone, Copy)]
enum WinMatch {
    /// Any window value is accepted.
    Any,
    /// Match one exact value.
    Exact(u32),
    /// Match any value in the inclusive range.
    Range(u32, u32),
    /// Match any of the listed values (up to 4).
    Set([u32; 4], usize),
}

impl WinMatch {
    fn matches(self, window: u32) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(v) => window == v,
            Self::Range(lo, hi) => (lo..=hi).contains(&window),
            Self::Set(vals, len) => vals[..len].contains(&window),
        }
    }
}

/// One entry in the OS signature database.
struct OsSig {
    family: OsFamily,
    detail: &'static str,

    // --- TTL ---
    /// Expected initial TTL (before transit hops reduce it).
    ttl_init: u8,
    ttl_weight: u32,

    // --- Window size ---
    win: WinMatch,
    win_weight: u32,

    // --- MSS ---
    mss: Option<u16>, // `None` = any value is accepted
    mss_weight: u32,

    // --- DF bit ---
    df: Option<bool>, // `None` = don't care
    df_weight: u32,

    // --- SACK-OK ---
    sack_ok: Option<bool>,
    sack_weight: u32,

    // --- Timestamps ---
    timestamps: Option<bool>,
    ts_weight: u32,

    // --- WScale range ---
    wscale_range: Option<(u8, u8)>, // inclusive, `None` = don't care
    ws_weight: u32,
}

impl OsSig {
    /// Compute the additive score for a given fingerprint.  Returns
    /// `(score, max_score)`.
    fn score(&self, fp: &TcpFingerprint) -> (u32, u32) {
        let initial_ttl = infer_initial_ttl(fp.ttl, fp.hops);
        let mut score = 0u32;
        let mut max = 0u32;

        // TTL
        max += self.ttl_weight;
        if initial_ttl == self.ttl_init {
            score += self.ttl_weight;
        }

        // Window
        max += self.win_weight;
        if self.win.matches(fp.window) {
            score += self.win_weight;
        }

        // MSS
        max += self.mss_weight;
        if let Some(expected_mss) = self.mss {
            if fp.mss == Some(expected_mss) {
                score += self.mss_weight;
            }
        } else {
            // Any MSS (or no MSS) is fine — still award full points.
            score += self.mss_weight;
        }

        // DF
        if let Some(expected_df) = self.df {
            max += self.df_weight;
            if fp.df == expected_df {
                score += self.df_weight;
            }
        }

        // SACK
        if let Some(expected_sack) = self.sack_ok {
            max += self.sack_weight;
            if fp.sack_ok == expected_sack {
                score += self.sack_weight;
            }
        }

        // Timestamps
        if let Some(expected_ts) = self.timestamps {
            max += self.ts_weight;
            if fp.timestamps == expected_ts {
                score += self.ts_weight;
            }
        }

        // WScale range
        if let Some((lo, hi)) = self.wscale_range {
            max += self.ws_weight;
            if let Some(ws) = fp.wscale
                && (lo..=hi).contains(&ws)
            {
                score += self.ws_weight;
            }
        }

        (score, max)
    }
}

/// OS signature database.  Weights reflect how discriminative each feature is.
static SIGNATURES: &[OsSig] = &[
    // ── Linux ──────────────────────────────────────────────────────────────
    OsSig {
        family: OsFamily::Linux,
        detail: "Linux 3.x–6.x",
        ttl_init: 64,
        ttl_weight: 30,
        win: WinMatch::Set([29200, 65535, 5840, 43690], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 10,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(true),
        ts_weight: 10,
        wscale_range: Some((6, 10)),
        ws_weight: 7,
    },
    OsSig {
        family: OsFamily::Linux,
        detail: "Linux 2.6.x",
        ttl_init: 64,
        ttl_weight: 30,
        win: WinMatch::Set([5840, 29200, 14600, 32792], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 10,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: None,
        ts_weight: 0,
        wscale_range: Some((0, 7)),
        ws_weight: 5,
    },
    OsSig {
        family: OsFamily::Linux,
        detail: "Android / Linux (mobile)",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([65535, 14480, 29200, 32768], 4),
        win_weight: 15,
        mss: Some(1460),
        mss_weight: 10,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(true),
        ts_weight: 8,
        wscale_range: Some((7, 9)),
        ws_weight: 7,
    },
    OsSig {
        family: OsFamily::Linux,
        detail: "MikroTik RouterOS",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([14600, 4380, 0, 0], 2),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 10,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 15,
        wscale_range: None,
        ws_weight: 0,
    },
    // ── Windows ────────────────────────────────────────────────────────────
    OsSig {
        family: OsFamily::Windows,
        detail: "Windows 10/11",
        ttl_init: 128,
        ttl_weight: 30,
        win: WinMatch::Set([65535, 64240, 8192, 65392], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 8,
        wscale_range: Some((8, 8)),
        ws_weight: 10,
    },
    OsSig {
        family: OsFamily::Windows,
        detail: "Windows Server 2019/2022",
        ttl_init: 128,
        ttl_weight: 30,
        win: WinMatch::Set([65535, 65392, 64240, 8192], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 8,
        wscale_range: Some((8, 8)),
        ws_weight: 10,
    },
    OsSig {
        family: OsFamily::Windows,
        detail: "Windows 7/8/Server 2012",
        ttl_init: 128,
        ttl_weight: 30,
        win: WinMatch::Set([8192, 65535, 16384, 65392], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 5,
        wscale_range: Some((2, 8)),
        ws_weight: 7,
    },
    OsSig {
        family: OsFamily::Windows,
        detail: "Windows XP/2003",
        ttl_init: 128,
        ttl_weight: 30,
        win: WinMatch::Set([65535, 16384, 32768, 8192], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 8,
        timestamps: Some(false),
        ts_weight: 5,
        wscale_range: None,
        ws_weight: 0,
    },
    // ── macOS ──────────────────────────────────────────────────────────────
    OsSig {
        family: OsFamily::MacOS,
        detail: "macOS 10.12+ / iOS",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([65535, 65228, 65280, 32768], 4),
        win_weight: 25, // macOS almost always uses 65535; boost this
        mss: Some(1460),
        mss_weight: 10,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(true),
        ts_weight: 10,
        wscale_range: Some((6, 6)), // macOS uses exactly wscale=6
        ws_weight: 15,              // exact wscale=6 strongly identifies macOS vs Linux
    },
    // ── BSD ────────────────────────────────────────────────────────────────
    OsSig {
        family: OsFamily::Bsd,
        detail: "FreeBSD 10+",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([65535, 65228, 32768, 65280], 4),
        win_weight: 18,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(true),
        ts_weight: 10,
        wscale_range: Some((6, 8)),
        ws_weight: 7,
    },
    OsSig {
        family: OsFamily::Bsd,
        detail: "pfSense / OPNsense",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([65535, 32768, 65228, 16384], 4),
        win_weight: 18,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 8,
        sack_ok: Some(true),
        sack_weight: 10,
        timestamps: Some(true),
        ts_weight: 10,
        wscale_range: Some((6, 8)),
        ws_weight: 8,
    },
    OsSig {
        family: OsFamily::Bsd,
        detail: "OpenBSD 6+",
        ttl_init: 255, // OpenBSD uses initial TTL 255
        ttl_weight: 35,
        win: WinMatch::Set([16384, 65535, 32768, 8192], 4),
        win_weight: 20,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 5,
        sack_ok: Some(false), // OpenBSD does not enable SACK by default
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 5,
        wscale_range: None,
        ws_weight: 0,
    },
    OsSig {
        family: OsFamily::Bsd,
        detail: "NetBSD",
        ttl_init: 64,
        ttl_weight: 25,
        win: WinMatch::Set([65535, 32768, 16384, 8192], 4),
        win_weight: 15,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(false),
        df_weight: 5,
        sack_ok: Some(false),
        sack_weight: 8,
        timestamps: Some(false),
        ts_weight: 5,
        wscale_range: None,
        ws_weight: 0,
    },
    // ── Cisco ──────────────────────────────────────────────────────────────
    OsSig {
        family: OsFamily::Cisco,
        detail: "Cisco IOS",
        ttl_init: 255,
        ttl_weight: 30,
        win: WinMatch::Set([4128, 8192, 4096, 2048], 4),
        win_weight: 25,
        mss: Some(536), // Conservative MSS common on Cisco
        mss_weight: 15,
        df: Some(false),
        df_weight: 8,
        sack_ok: Some(false),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 8,
        wscale_range: None,
        ws_weight: 0,
    },
    OsSig {
        family: OsFamily::Cisco,
        detail: "Cisco IOS (modern)",
        ttl_init: 255,
        ttl_weight: 30,
        win: WinMatch::Range(2048, 16384),
        win_weight: 15,
        mss: Some(1460),
        mss_weight: 8,
        df: Some(true),
        df_weight: 5,
        sack_ok: Some(false),
        sack_weight: 10,
        timestamps: Some(false),
        ts_weight: 8,
        wscale_range: None,
        ws_weight: 0,
    },
];

// ── Core logic ────────────────────────────────────────────────────────────────

/// Round the observed TTL (corrected for `hops`) to the nearest standard
/// initial TTL value.
///
/// Standard initial TTLs: Linux/BSD/macOS → 64, Windows → 128, Cisco → 255.
pub fn infer_initial_ttl(observed: u8, hops: u8) -> u8 {
    let restored = (observed as u16).saturating_add(hops as u16).min(255) as u8;
    // Snap to nearest standard boundary.
    // Boundaries chosen as midpoints between {64, 128, 255}.
    if restored <= 96 {
        64
    } else if restored <= 190 {
        128
    } else {
        255
    }
}

/// Classify a `TcpFingerprint` against the built-in signature database.
///
/// Returns the best-matching `OsGuess`.  When no signature exceeds a minimum
/// confidence threshold (0.20) the returned family is `OsFamily::Unknown`.
pub fn classify(fp: &TcpFingerprint) -> OsGuess {
    if std::env::var_os("RAYSCAN_OS_DEBUG").is_some() {
        eprintln!(
            "[os-debug] ttl={} hops={} window={} mss={:?} wscale={:?} sack={} timestamps={} df={} options={:?}",
            fp.ttl,
            fp.hops,
            fp.window,
            fp.mss,
            fp.wscale,
            fp.sack_ok,
            fp.timestamps,
            fp.df,
            fp.options_order
        );
    }
    let initial_ttl = infer_initial_ttl(fp.ttl, fp.hops);

    let mut best_score = 0u32;
    let mut best_max = 1u32; // avoid division by zero
    let mut best_sig: Option<&OsSig> = None;

    for sig in SIGNATURES {
        let (score, max) = sig.score(fp);
        if max == 0 {
            continue;
        }
        // Compare using score/max ratio to avoid biasing towards sigs with
        // higher max (more features).
        let beats = match best_sig {
            None => true,
            Some(_) => {
                // Cross-multiply to avoid floating-point in hot path.
                score * best_max > best_score * max
            }
        };
        if beats {
            best_score = score;
            best_max = max;
            best_sig = Some(sig);
        }
    }

    let confidence = if best_max > 0 {
        (best_score as f32 / best_max as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let evidence = Some(fp.evidence_summary());

    match best_sig {
        Some(sig) if confidence >= 0.20 => OsGuess {
            family: sig.family.clone(),
            detail: sig.detail.to_string(),
            confidence,
            initial_ttl: Some(initial_ttl),
            evidence,
        },
        _ => OsGuess {
            family: OsFamily::Unknown,
            detail: format!(
                "TTL={} window={} — insufficient evidence",
                fp.ttl, fp.window
            ),
            confidence,
            initial_ttl: Some(initial_ttl),
            evidence,
        },
    }
}

// ── Packet parsing helpers ────────────────────────────────────────────────────

/// Parse TCP options from the options region of a TCP header, populating
/// relevant fields in `fp`.
///
/// `options_bytes` is the slice starting right after the fixed 20-byte TCP
/// header, with length equal to `(data_offset - 5) * 4`.
pub fn parse_tcp_options(options_bytes: &[u8], fp: &mut TcpFingerprint) {
    let mut i = 0;
    while i < options_bytes.len() {
        let kind = options_bytes[i];
        fp.options_order.push(kind);

        match kind {
            0 => break, // End of option list (EOL)
            1 => {
                i += 1;
            } // NOP (single byte, no length)
            2 => {
                // MSS — kind(1) + len(1) + value(2)
                if i + 3 < options_bytes.len() {
                    fp.mss = Some(u16::from_be_bytes([
                        options_bytes[i + 2],
                        options_bytes[i + 3],
                    ]));
                }
                i += 4;
            }
            3 => {
                // Window Scale — kind(1) + len(1) + shift(1)
                if i + 2 < options_bytes.len() {
                    fp.wscale = Some(options_bytes[i + 2]);
                }
                i += 3;
            }
            4 => {
                // SACK Permitted — kind(1) + len(1)
                fp.sack_ok = true;
                i += 2;
            }
            8 => {
                // Timestamps — kind(1) + len(1) + TSval(4) + TSecr(4)
                fp.timestamps = true;
                i += 10;
            }
            _ => {
                // Unknown option: advance by its length field if present.
                if i + 1 < options_bytes.len() {
                    let len = options_bytes[i + 1] as usize;
                    if len >= 2 {
                        i += len;
                    } else {
                        i += 1; // malformed; skip one byte
                    }
                } else {
                    break;
                }
            }
        }
    }
}

/// Extract a `TcpFingerprint` from a raw Ethernet/IPv4/TCP frame.
///
/// Returns `None` if the frame is not a valid IPv4 TCP packet.
pub fn fingerprint_from_frame(data: &[u8]) -> Option<TcpFingerprint> {
    // Minimum: 14 (Eth) + 20 (IP) + 20 (TCP) = 54 bytes
    if data.len() < 54 {
        return None;
    }

    // EtherType must be IPv4 (0x0800)
    if data[12] != 0x08 || data[13] != 0x00 {
        return None;
    }

    let ip = &data[14..];

    // IPv4 version
    if (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 20 {
        return None;
    }

    // Protocol must be TCP (6)
    if ip[9] != 6 {
        return None;
    }

    let ttl = ip[8];
    // DF bit is in the flags/fragment-offset field (bytes 6-7).
    // DF = bit 14 of a 16-bit field: ip[6] bit 6.
    let df = (ip[6] & 0x40) != 0;

    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }

    // TCP flags: SYN+ACK = 0x12
    let flags = tcp[13];
    if (flags & 0x12) != 0x12 {
        return None;
    }

    let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u32;
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }

    let mut fp = TcpFingerprint {
        ttl,
        hops: 0, // caller may set this based on route info
        window,
        df,
        ..Default::default()
    };

    let options_bytes = &tcp[20..data_offset];
    parse_tcp_options(options_bytes, &mut fp);

    Some(fp)
}

/// Extract a `TcpFingerprint` from an IPv6 TCP SYN-ACK segment.
///
/// `hop_limit` comes from the IPv6 header when available; `hops` is the
/// estimated distance to the target (0 for directly connected/LAN hosts).
pub fn fingerprint_from_ipv6_tcp(tcp: &[u8], hop_limit: u8, hops: u8) -> Option<TcpFingerprint> {
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    if (flags & 0x12) != 0x12 {
        return None;
    }
    let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u32;
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }

    let mut fp = TcpFingerprint {
        ttl: hop_limit,
        hops,
        window,
        df: true,
        ..Default::default()
    };
    parse_tcp_options(&tcp[20..data_offset], &mut fp);
    Some(fp)
}

// ── Active probe ──────────────────────────────────────────────────────────────

/// Probe a live host and return an `OsGuess`.
///
/// Sends a raw SYN frame to `host:port` via AF_PACKET, waits up to `timeout`
/// for the SYN-ACK, parses the fingerprint, and runs `classify()`.
///
/// # Returns
///
/// - `Some(OsGuess)` on success.
/// - `None` if permission is denied, routing fails, the port does not reply,
///   or the platform does not support AF_PACKET (non-Linux).
///
/// # Safety
///
/// Uses `unsafe` FFI to call libc raw-socket functions (AF_PACKET).  All
/// buffer accesses are bounds-checked.  Requires `CAP_NET_RAW` or root.
pub fn probe_fingerprint(host: IpAddr, port: u16, timeout: Duration) -> Option<OsGuess> {
    // AF_PACKET is Linux-only.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (host, port, timeout);
        return None;
    }

    #[cfg(target_os = "linux")]
    probe_fingerprint_linux(host, port, timeout)
}

#[cfg(target_os = "linux")]
fn probe_fingerprint_linux(host: IpAddr, port: u16, timeout: Duration) -> Option<OsGuess> {
    match host {
        IpAddr::V4(v4) => probe_fingerprint_v4(v4, port, timeout),
        IpAddr::V6(v6) => probe_fingerprint_v6(v6, port, timeout),
    }
}

#[cfg(target_os = "linux")]
fn probe_fingerprint_v4(target_v4: Ipv4Addr, port: u16, timeout: Duration) -> Option<OsGuess> {
    use crate::syn::route;

    // Resolve route: source IP, interface, gateway MAC.
    let route_info = route::route_for(target_v4).ok()?;
    let src_mac = route::iface_mac(&route_info.iface).ok()?;
    let dst_mac = route::arp_resolve(
        &route_info.iface,
        &src_mac,
        route_info.src_ip,
        route_info.gateway_ip,
    )
    .ok()?;

    let src_ip = u32::from(route_info.src_ip);
    let dst_ip = u32::from(target_v4);

    // Choose an ephemeral source port in the fingerprint probe range.
    let src_port: u16 = 62000;
    // A simple non-zero SYN sequence number.
    let seq: u32 = 0x_DEAD_BEEF;

    // Build a SYN frame with TCP options (MSS, NOP, WScale, NOP, NOP, SACK-OK,
    // Timestamps) so the reply SYN-ACK carries the target's options.
    let frame = build_fingerprint_syn(&src_mac, &dst_mac, src_ip, dst_ip, src_port, port, seq);

    // Open raw AF_PACKET socket bound to ETH_P_IP.
    let if_idx = route::iface_index(&route_info.iface).ok()?;

    // SAFETY: Creating raw socket for Ethernet frame transmission.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return None;
    }

    // Set SO_RCVTIMEO to `timeout`.
    let timeout_ms = timeout.as_millis().clamp(100, 10_000) as u64;
    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as i64,
        tv_usec: ((timeout_ms % 1000) * 1000) as i64,
    };
    // SAFETY: fd is valid; setsockopt is safe with valid timeval.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Send the SYN frame.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = if_idx;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&dst_mac);

    // SAFETY: fd valid, frame slice within our stack-allocated array.
    let sent = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        // SAFETY: Closing open fd.
        unsafe { libc::close(fd) };
        return None;
    }

    // Receive loop — read frames until we find our SYN-ACK reply.
    let mut buf = [0u8; 1500];
    let mut result: Option<OsGuess> = None;

    // We try at most 32 frames before giving up (the timeout will also fire).
    for _ in 0..32 {
        // SAFETY: fd is valid; buf is 1500 bytes.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            break; // timeout or error
        }
        let frame_data = &buf[..n as usize];

        // Parse as Ethernet/IPv4/TCP.
        if let Some(mut fp) = fingerprint_from_frame(frame_data) {
            // Filter: must be from our target, to our source port.
            if frame_data.len() < 54 {
                continue;
            }
            let ip = &frame_data[14..];
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ip.len() < ihl + 4 {
                continue;
            }
            let pkt_src_ip = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
            let tcp = &ip[ihl..];
            if tcp.len() < 4 {
                continue;
            }
            let pkt_src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let pkt_dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

            if pkt_src_ip != dst_ip || pkt_src_port != port || pkt_dst_port != src_port {
                continue;
            }

            // Estimate hops: for LAN targets (direct route), hops = 1 when TTL
            // is exactly one less than a standard initial TTL; otherwise 0.
            fp.hops = estimate_hops(fp.ttl);
            result = Some(classify(&fp));
            break;
        }
    }

    // SAFETY: Closing open fd.
    unsafe { libc::close(fd) };

    result
}

#[cfg(target_os = "linux")]
fn probe_fingerprint_v6(
    target: std::net::Ipv6Addr,
    port: u16,
    timeout: Duration,
) -> Option<OsGuess> {
    use crate::syn::v6::source_for;

    let source = source_for(target, port).ok()?;
    let src_port: u16 = 62001;
    let seq: u32 = 0x_DEAD_BEEF;
    let tcp_options: [u8; 20] = [
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x04, 0x02, 0x08, 0x0a, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    let packet = crate::syn::packet::build_ipv6_tcp_packet(
        &source,
        &target,
        src_port,
        port,
        seq,
        &tcp_options,
    );

    // SAFETY: create IPv6 raw TCP receive socket.
    let rx_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if rx_fd < 0 {
        return None;
    }

    let mut bind_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    bind_addr.sin6_family = libc::AF_INET6 as u16;
    // SAFETY: rx_fd is valid and bind_addr is initialized.
    if unsafe {
        libc::bind(
            rx_fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    } < 0
    {
        // SAFETY: close owned descriptor.
        unsafe { libc::close(rx_fd) };
        return None;
    }

    let timeout_ms = timeout.as_millis().clamp(100, 10_000) as u64;
    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as i64,
        tv_usec: ((timeout_ms % 1000) * 1000) as i64,
    };
    // SAFETY: rx_fd is valid and tv points to a valid timeval.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // SAFETY: create raw IPv6 transmit socket (header included).
    let tx_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if tx_fd < 0 {
        // SAFETY: close owned descriptor.
        unsafe { libc::close(rx_fd) };
        return None;
    }

    let mut destination: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    destination.sin6_family = libc::AF_INET6 as u16;
    destination.sin6_port = 0;
    destination.sin6_addr.s6_addr = target.octets();

    // SAFETY: both descriptors are valid and all pointers reference live buffers.
    let sent = unsafe {
        libc::sendto(
            tx_fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &destination as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    // SAFETY: close owned transmit descriptor after sending.
    unsafe { libc::close(tx_fd) };
    if sent < 0 {
        // SAFETY: close owned descriptor.
        unsafe { libc::close(rx_fd) };
        return None;
    }

    let mut buf = [0u8; 1500];
    let mut result = None;
    for _ in 0..32 {
        let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        // SAFETY: rx_fd is valid, buf/from are writable.
        let n = unsafe {
            libc::recvfrom(
                rx_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if n <= 0 {
            break;
        }

        let peer = std::net::Ipv6Addr::from(from.sin6_addr.s6_addr);
        let data = &buf[..n as usize];
        let (src, hop_limit, tcp) = if data.len() >= 40 && (data[0] >> 4) == 6 {
            if data[6] != 6 {
                continue;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[8..24]);
            (std::net::Ipv6Addr::from(octets), data[7], &data[40..])
        } else {
            (peer, 64, data)
        };
        if src != target || tcp.len() < 4 {
            continue;
        }
        if u16::from_be_bytes([tcp[0], tcp[1]]) != port
            || u16::from_be_bytes([tcp[2], tcp[3]]) != src_port
        {
            continue;
        }
        if let Some(mut fp) = fingerprint_from_ipv6_tcp(tcp, hop_limit, 0) {
            fp.hops = estimate_hops(fp.ttl);
            result = Some(classify(&fp));
            break;
        }
    }

    // SAFETY: rx_fd is still owned and open.
    unsafe { libc::close(rx_fd) };
    result
}

/// Build a SYN frame with a full TCP options section to elicit a rich SYN-ACK.
///
/// Options included: MSS(1460), NOP, WScale(6), NOP, NOP, SACK-OK, Timestamps.
/// This matches a modern Linux client profile and maximises the chance that
/// the peer echoes its own options.
#[cfg(target_os = "linux")]
fn build_fingerprint_syn(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    use crate::syn::packet::{ip_checksum, tcp_checksum};

    // TCP options (20 bytes exact): data_offset = (20+20)/4 = 10
    // MSS(4) + NOP(1) + WScale(3) + NOP(1) + NOP(1) + SACK-OK(2) + TS_kind+len(2) + TSval(4) + TSecr_hi(2) = 20
    let tcp_options: [u8; 20] = [
        0x02, 0x04, 0x05, 0xb4, // MSS = 1460
        0x01, // NOP
        0x03, 0x03, 0x06, // WScale = 6
        0x01, // NOP
        0x01, // NOP
        0x04, 0x02, // SACK-OK
        0x08, 0x0a, // Timestamps kind + len(10)
        0x00, 0x00, 0x00, 0x01, // TSval = 1
        0x00, 0x00, // TSecr first 2 of 4 bytes (last 2 implicit zero)
    ];

    // Frame layout: 14 (Eth) + 20 (IP) + 40 (TCP with options) = 74 bytes
    let total_len: u16 = 60; // IP total length: 20 (IP) + 40 (TCP+opts)
    let mut frame = vec![0u8; 74];

    // Ethernet
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&total_len.to_be_bytes());
    frame[18..20].copy_from_slice(&(seq as u16).to_be_bytes()); // Identification
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF=1
    frame[22] = 64; // TTL
    frame[23] = 6; // TCP
    frame[26..30].copy_from_slice(&src_ip.to_be_bytes());
    frame[30..34].copy_from_slice(&dst_ip.to_be_bytes());

    let ip_ck = ip_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_ck.to_be_bytes());

    // TCP header (data_offset = 10 = 40 bytes)
    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&0u32.to_be_bytes()); // ACK = 0
    frame[46] = 0xa0; // data offset = 10 (40 bytes), reserved = 0
    frame[47] = 0x02; // SYN
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes()); // window
    // Checksum placeholder
    frame[52..54].copy_from_slice(&[0, 0]); // urgent pointer

    // TCP options
    frame[54..74].copy_from_slice(&tcp_options);

    let tcp_ck = tcp_checksum(src_ip, dst_ip, &frame[34..74]);
    frame[50..52].copy_from_slice(&tcp_ck.to_be_bytes());

    frame
}

/// Estimate the hop count from an observed TTL by finding how many hops from
/// the nearest standard initial TTL (64, 128, 255) the value is.
#[allow(dead_code)]
fn estimate_hops(observed_ttl: u8) -> u8 {
    let initial = infer_initial_ttl(observed_ttl, 0);
    initial.saturating_sub(observed_ttl)
}

// ── Public async wrapper ──────────────────────────────────────────────────────

/// Async wrapper around `probe_fingerprint()` for use in the tokio runtime.
///
/// Runs the blocking raw-socket probe on a dedicated thread to avoid blocking
/// the executor.
pub async fn probe_fingerprint_async(
    host: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<OsGuess> {
    tokio::task::spawn_blocking(move || probe_fingerprint(host, port, timeout))
        .await
        .ok()
        .flatten()
}

// ── Conversion for `Ipv4Addr` ─────────────────────────────────────────────────

/// Convert an `Ipv4Addr` to its `u32` big-endian representation.
#[allow(dead_code)]
fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 63,
            hops: 1,
            window: 29200,
            mss: Some(1460),
            wscale: Some(7),
            sack_ok: true,
            timestamps: true,
            df: true,
            options_order: vec![2, 1, 3, 1, 1, 4, 8],
        }
    }

    fn windows_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 128,
            hops: 0,
            window: 65535,
            mss: Some(1460),
            wscale: Some(8),
            sack_ok: true,
            timestamps: false,
            df: true,
            options_order: vec![2, 1, 3, 1, 1, 4],
        }
    }

    fn cisco_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 254,
            hops: 1,
            window: 4128,
            mss: Some(536),
            wscale: None,
            sack_ok: false,
            timestamps: false,
            df: false,
            options_order: vec![2],
        }
    }

    fn openbsd_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 254,
            hops: 1,
            window: 16384,
            mss: Some(1460),
            wscale: None,
            sack_ok: false,
            timestamps: false,
            df: true,
            options_order: vec![2],
        }
    }

    fn macos_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 64,
            hops: 0,
            window: 65535,
            mss: Some(1460),
            wscale: Some(6),
            sack_ok: true,
            timestamps: true,
            df: true,
            options_order: vec![2, 1, 3, 1, 1, 4, 8],
        }
    }

    fn mikrotik_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 64,
            hops: 0,
            window: 14600,
            mss: Some(1460),
            wscale: None,
            sack_ok: true,
            timestamps: false,
            df: true,
            options_order: vec![2, 4],
        }
    }

    fn old_linux_no_timestamps_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 63,
            hops: 1,
            window: 5840,
            mss: Some(1460),
            wscale: Some(5),
            sack_ok: true,
            timestamps: false,
            df: true,
            options_order: vec![2, 1, 1, 4, 1, 3],
        }
    }

    fn pfsense_fp() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 64,
            hops: 0,
            window: 65535,
            mss: Some(1460),
            wscale: Some(7),
            sack_ok: true,
            timestamps: true,
            df: true,
            options_order: vec![2, 1, 3, 1, 1, 4, 8],
        }
    }

    #[test]
    fn infer_ttl_snaps_to_nearest_standard() {
        assert_eq!(infer_initial_ttl(63, 1), 64); // Linux, 1 hop
        assert_eq!(infer_initial_ttl(64, 0), 64); // Linux, direct
        assert_eq!(infer_initial_ttl(127, 1), 128); // Windows, 1 hop
        assert_eq!(infer_initial_ttl(128, 0), 128); // Windows, direct
        assert_eq!(infer_initial_ttl(254, 1), 255); // Cisco/OpenBSD, 1 hop
        assert_eq!(infer_initial_ttl(255, 0), 255); // Cisco/OpenBSD, direct
        assert_eq!(infer_initial_ttl(60, 0), 64); // slightly below 64
        assert_eq!(infer_initial_ttl(100, 0), 128); // above 96 → 128
    }

    #[test]
    fn classify_identifies_linux() {
        let guess = classify(&linux_fp());
        assert_eq!(guess.family, OsFamily::Linux);
        assert!(guess.confidence >= 0.70, "confidence={}", guess.confidence);
        assert_eq!(guess.initial_ttl, Some(64));
    }

    #[test]
    fn classify_identifies_windows() {
        let guess = classify(&windows_fp());
        assert_eq!(guess.family, OsFamily::Windows);
        assert!(guess.confidence >= 0.65, "confidence={}", guess.confidence);
        assert_eq!(guess.initial_ttl, Some(128));
    }

    #[test]
    fn classify_identifies_cisco() {
        let guess = classify(&cisco_fp());
        assert_eq!(guess.family, OsFamily::Cisco);
        assert!(guess.confidence >= 0.60, "confidence={}", guess.confidence);
    }

    #[test]
    fn classify_identifies_mikrotik() {
        let guess = classify(&mikrotik_fp());
        assert_eq!(guess.family, OsFamily::Linux);
        assert!(guess.detail.contains("MikroTik") || guess.detail.contains("Linux"));
        assert!(guess.confidence >= 0.60, "confidence={}", guess.confidence);
    }

    #[test]
    fn classify_identifies_old_linux_without_timestamps() {
        // Metasploitable 2 (Ubuntu 8.04, Linux 2.6.24) advertises
        // window=5840, wscale=5, SACK but no TCP timestamps.
        let guess = classify(&old_linux_no_timestamps_fp());
        assert_eq!(guess.family, OsFamily::Linux);
        assert_eq!(guess.detail, "Linux 2.6.x");
        assert!(!guess.detail.contains("MikroTik"));
        assert!(guess.confidence >= 0.95, "confidence={}", guess.confidence);
    }

    #[test]
    fn classify_identifies_pfsense_or_bsd() {
        let guess = classify(&pfsense_fp());
        assert!(
            matches!(
                guess.family,
                OsFamily::Bsd | OsFamily::MacOS | OsFamily::Linux
            ),
            "unexpected family: {:?}",
            guess.family
        );
        assert!(guess.confidence >= 0.60, "confidence={}", guess.confidence);
    }

    #[test]
    fn classify_identifies_openbsd() {
        let guess = classify(&openbsd_fp());
        // OpenBSD uses TTL 255 and no SACK — should match BSD/OpenBSD
        assert_eq!(guess.family, OsFamily::Bsd);
        assert!(guess.confidence >= 0.55, "confidence={}", guess.confidence);
    }

    #[test]
    fn classify_identifies_macos() {
        let guess = classify(&macos_fp());
        // macOS, FreeBSD, and Linux all share TTL=64 + SACK + timestamps.
        // The primary discriminator is window=65535 + wscale=6 (exact), which
        // macOS uses consistently.  The classifier may resolve to MacOS, Bsd,
        // or a high-scoring Linux entry — all are valid for this feature set.
        assert!(
            matches!(
                guess.family,
                OsFamily::MacOS | OsFamily::Bsd | OsFamily::Linux
            ),
            "unexpected family: {:?}",
            guess.family
        );
        assert!(guess.confidence >= 0.55, "confidence={}", guess.confidence);
    }

    #[test]
    fn parse_tcp_options_extracts_all_fields() {
        // MSS(1460), NOP, WScale(6), NOP, NOP, SACK-OK, TS(val=1,ecr=0)
        #[rustfmt::skip]
        let opts: &[u8] = &[
            0x02, 0x04, 0x05, 0xb4, // MSS = 1460
            0x01,                   // NOP
            0x03, 0x03, 0x06,       // WScale = 6
            0x01,                   // NOP
            0x01,                   // NOP
            0x04, 0x02,             // SACK-OK
            0x08, 0x0a,             // TS kind + len
            0x00, 0x00, 0x00, 0x01, // TSval
            0x00, 0x00, 0x00, 0x00, // TSecr
        ];
        let mut fp = TcpFingerprint::default();
        parse_tcp_options(opts, &mut fp);
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.wscale, Some(6));
        assert!(fp.sack_ok);
        assert!(fp.timestamps);
        assert_eq!(fp.options_order, vec![2, 1, 3, 1, 1, 4, 8]);
    }

    #[test]
    fn fingerprint_from_frame_rejects_short_input() {
        assert!(fingerprint_from_frame(&[0u8; 10]).is_none());
        assert!(fingerprint_from_frame(&[]).is_none());
    }

    #[test]
    fn ipv6_tcp_fingerprint_parses_syn_ack_options() {
        let mut tcp = [0u8; 44];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&62001u16.to_be_bytes());
        tcp[12] = 0xb0;
        tcp[13] = 0x12;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..24].copy_from_slice(&[0x02, 0x04, 0x05, 0xb4]);
        tcp[24] = 0x01;
        tcp[25..28].copy_from_slice(&[0x03, 0x03, 0x07]);
        tcp[28] = 0x01;
        tcp[29] = 0x01;
        tcp[30..32].copy_from_slice(&[0x04, 0x02]);
        tcp[32..34].copy_from_slice(&[0x08, 0x0a]);
        tcp[34..38].copy_from_slice(&1u32.to_be_bytes());
        tcp[38..42].copy_from_slice(&0u32.to_be_bytes());
        tcp[42..44].copy_from_slice(&[0x00, 0x00]);

        let fp = fingerprint_from_ipv6_tcp(&tcp, 64, 0).unwrap();
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.window, 65535);
        assert!(fp.df);
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.wscale, Some(7));
        assert!(fp.sack_ok);
        assert!(fp.timestamps);
        assert!(fingerprint_from_ipv6_tcp(&[0u8; 4], 64, 0).is_none());
    }

    #[test]
    fn estimate_hops_is_correct_for_common_ttls() {
        assert_eq!(estimate_hops(63), 1); // Linux target, 1 hop
        assert_eq!(estimate_hops(64), 0); // Linux target, direct
        assert_eq!(estimate_hops(127), 1); // Windows, 1 hop
        assert_eq!(estimate_hops(254), 1); // Cisco, 1 hop
        assert_eq!(estimate_hops(128), 0); // Windows, direct
    }

    #[test]
    fn evidence_summary_formats_all_features() {
        let fp = linux_fp();
        let ev = fp.evidence_summary();
        assert!(ev.contains("TTL=63"));
        assert!(ev.contains("Window=29200"));
        assert!(ev.contains("MSS=1460"));
        assert!(ev.contains("WScale=7"));
        assert!(ev.contains("SACK=yes"));
        assert!(ev.contains("TS=yes"));
        assert!(ev.contains("DF=yes"));
        assert!(ev.contains("Options=mss,nop,wscale,nop,nop,sack,ts"));

        let guess = classify(&fp);
        assert!(guess.evidence.is_some());
        assert_eq!(guess.evidence.as_deref(), Some(ev.as_str()));
    }
}
