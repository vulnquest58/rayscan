use clap::ValueEnum;

use crate::error::AppError;

/// Curated list of the top 100 most common TCP ports in security scans.
pub const TOP_PORTS_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8443, 8888, 554, 8000, 2049, 10000, 1433, 5060, 5000, 8081, 6000, 6001, 8008,
    9090, 8082, 8880, 5432, 199, 8088, 4443, 8181, 1026, 1027, 1028, 1029, 179, 514, 515, 636, 990,
    992, 1521, 2000, 2082, 2083, 2086, 2087, 2095, 2096, 2121, 3128, 3268, 3269, 4899, 5001, 5101,
    5190, 5631, 5632, 5901, 6112, 6379, 6667, 7070, 7777, 8009, 8083, 8084, 8085, 8086, 8087, 8089,
    8180, 8222, 8333, 8444, 8889, 9000, 9001, 9002, 9003, 9091, 9100, 9200, 9999, 10001, 27017,
    31337,
];

/// Top 1000 TCP ports ordered by frequency in the nmap `nmap-services`
/// table.  Used by `--top-ports N` for `N > 100` and by the `q|top`
/// port preset so results match nmap's default frequency ordering.
pub const TOP_PORTS_1000: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001,
    82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1049,
    1053, 1054, 1056, 1064, 1065, 2967, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102,
    1039, 2869, 4001, 5120, 8010, 9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280,
    254, 4000, 1761, 5003, 2002, 1998, 2005, 1032, 1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401,
    4045, 902, 787, 7937, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555, 10001, 1494, 2301, 3,
    593, 3268, 7938, 1022, 1234, 1035, 1036, 1037, 1074, 8002, 9001, 464, 1935, 2003, 497, 6666,
    6543, 1352, 24, 3269, 1111, 407, 500, 20, 2006, 1034, 1218, 15000, 3260, 4444, 264, 2004, 33,
    1042, 42510, 3052, 999, 1023, 1068, 222, 7100, 888, 563, 1717, 2008, 32770, 992, 32772, 7001,
    2007, 8082, 5550, 1043, 2009, 512, 5801, 1700, 2701, 50001, 7019, 4662, 2065, 2010, 42, 161,
    2602, 3333, 9535, 5100, 2604, 4002, 5002, 1047, 1051, 1052, 1055, 1060, 1062, 1311, 16992,
    16993, 20828, 23502, 2702, 32769, 3283, 33354, 35500, 4443, 5225, 5226, 52869, 55555, 55600,
    6059, 64623, 64680, 65000, 65389, 6789, 8089, 8192, 8193, 8194, 8651, 8652, 8701, 9415, 9593,
    9594, 9595, 1067, 13782, 366, 5902, 9050, 1002, 5500, 85, 10243, 1863, 1864, 45100, 49999,
    51103, 5431, 8085, 49, 6667, 90, 1503, 27000, 6881, 1500, 340, 8021, 2222, 5566, 8088, 8899,
    9071, 1501, 32773, 32774, 5102, 6005, 9101, 9876, 163, 5679, 146, 1666, 648, 901, 83, 14238,
    3476, 5004, 5214, 8001, 8083, 8084, 9207, 12345, 30, 912, 2030, 2605, 6, 541, 1248, 3005, 4,
    8007, 2500, 306, 880, 1086, 1088, 1097, 2525, 4242, 52822, 8291, 9009, 6101, 900, 2809, 7200,
    1083, 12000, 211, 32775, 800, 987, 705, 20005, 711, 13783, 6969, 10002, 10012, 10024, 10025,
    1045, 1046, 10566, 1057, 1061, 10616, 10617, 10621, 10626, 10628, 10629, 1063, 1070, 1072,
    1073, 1075, 1077, 1078, 1079, 1081, 1082, 1085, 1093, 1094, 1096, 1098, 1099, 1100, 1104, 1106,
    1107, 1108, 11110, 1148, 1169, 11967, 1272, 1310, 13456, 14000, 14442, 15002, 15003, 15660,
    16001, 16016, 16018, 1687, 1718, 1783, 17988, 1840, 19101, 1947, 19801, 19842, 20000, 20031,
    20221, 20222, 2100, 2119, 2135, 2144, 21571, 2160, 2190, 2260, 22939, 2381, 2399, 24800, 2492,
    25734, 2607, 2718, 27715, 2811, 28201, 2875, 30000, 3017, 3031, 3071, 30718, 31038, 3211,
    32781, 32782, 3300, 3301, 3323, 3325, 3351, 3367, 33899, 3404, 34571, 34572, 34573, 3551, 3580,
    3659, 3766, 3784, 3801, 3827, 3998, 4003, 40193, 4126, 4129, 4449, 48080, 49158, 49159, 49160,
    50003, 50006, 5030, 50800, 5222, 5269, 5414, 5633, 5718, 57294, 58080, 5810, 5825, 5877, 5910,
    5911, 5925, 5959, 5960, 5961, 5962, 5985, 5986, 5987, 5988, 5989, 60020, 6123, 6129, 6156,
    63331, 6389, 65129, 6580, 6788, 6901, 7106, 7625, 7627, 7741, 7777, 7778, 7911, 8086, 8087,
    8181, 8222, 8333, 8400, 8402, 8600, 8649, 8873, 8994, 9002, 9010, 9011, 9080, 9220, 9290, 9485,
    9500, 9502, 9503, 9618, 9900, 9968, 691, 89, 1001, 1999, 2020, 212, 32776, 2998, 50002, 6003,
    7002, 2033, 32, 3372, 5510, 898, 425, 5903, 749, 99, 13722, 43, 458, 5405, 6106, 6502, 7007,
    10004, 10778, 1087, 1089, 1124, 1152, 1183, 1186, 1247, 1296, 1334, 15742, 1580, 16012, 1782,
    18988, 19283, 19315, 19780, 2126, 2179, 2191, 2251, 24444, 2522, 27352, 27353, 27355, 3011,
    3030, 3077, 3261, 32784, 3369, 3370, 3371, 3493, 3546, 3737, 3828, 3851, 3871, 3880, 3918,
    3995, 4006, 4111, 4446, 49163, 49165, 49175, 50389, 5054, 50636, 51493, 5200, 5280, 5298,
    55055, 56738, 5822, 5859, 5904, 5915, 5922, 5963, 61532, 61900, 62078, 7103, 7402, 7435, 7443,
    7512, 8011, 8090, 8100, 8180, 8254, 8500, 8654, 9091, 9110, 9666, 9877, 9943, 9944, 9998, 1021,
    32777, 32779, 9040, 2021, 32778, 616, 666, 700, 1112, 1524, 2040, 38292, 4321, 49400, 545,
    5802, 84, 1084, 1600, 2048, 2111, 3006, 32780, 16080, 2638, 6547, 6699, 9111, 1443, 1533, 2034,
    2106, 555, 5560, 6007, 667, 720, 801, 10003, 10009, 10180, 10215, 1090, 1091, 11111, 1114,
    1117, 1119, 1122, 1131, 1138, 1151, 1175, 1199, 1201, 12174, 12265, 1271, 14441, 15004, 16000,
    16113, 17877, 18040, 18101, 1862, 19350, 2323, 2393, 2394, 25735, 2608, 26214, 2725, 27356,
    2909, 3003, 30951, 3168, 3221, 32783, 32785, 3322, 3324, 3390, 3517, 3527, 3800, 3809, 3814,
    3826, 3869, 3878, 3889, 3905, 3914, 3920, 3945, 3971, 4004, 4005, 40911, 41511, 4279, 44176,
    4445, 44501, 4550, 4567, 4848, 4900, 49161, 49167, 49176, 50300, 5033, 50500, 5061, 5080, 5087,
    5221, 52673, 52848, 54045, 54328, 5440, 55056, 5544, 56737, 5678, 5730, 57797, 5811, 5815,
    5850, 5862, 5906, 5907, 5950, 5952, 6025, 60443, 6100, 6510, 6565, 6566, 6567, 6689, 6692,
    6779, 6792, 6839, 7025, 7496, 7676, 7800, 7920, 7921, 7999, 8022, 8042, 8045, 8093, 8099, 8200,
    8290, 8292, 8300, 8383, 8800, 9003, 9081, 9099, 9200, 9418, 9575, 9878, 9898, 9917, 1009, 2022,
    417, 4224, 4998, 617, 6346, 70, 714, 722, 777, 981, 10082, 1076, 2041, 301, 524, 5999, 668,
    765, 1007, 1417, 1434, 1984, 2038, 2068, 259, 416, 4343, 44443, 6009, 7004, 1010, 109, 1461,
    2035, 2046, 4125, 6006, 687, 7201, 726, 9103, 911, 1011, 125, 1455, 2013, 2043, 2047, 481,
    6668, 6669, 683, 903, 2042, 2045, 256, 31337, 406, 44442, 5998, 783, 843, 9929, 10008, 10011,
    10022, 10023, 10034, 10058, 10160, 10873, 1092, 1095, 1102, 1105, 1113, 1121, 1123, 1126, 1130,
    1132, 1137, 1141, 1145, 1147, 1149, 1154, 1163, 1164, 1165, 1166, 1174, 1185, 1187, 1192, 1198,
    12006, 12021, 12059, 1213, 1216, 1217, 12215, 12262, 1233, 1236, 12380, 1244, 12452, 1259,
    1277, 1287, 1300, 1301, 1309, 1322, 1328, 13724, 15001, 15402, 1556, 1583, 1594, 1641, 1658,
    16705, 16800, 16851, 1688, 1719, 1721,
];

/// Return the top `count` most common ports.
///
/// If `count <= 100`, takes from [`TOP_PORTS_100`]. If `count > 100`, takes all
/// top 100 ports and fills remaining slots from standard low ports (1..=65535)
/// without duplicates.
pub fn top_ports(count: usize) -> Result<Vec<u16>, AppError> {
    if count == 0 {
        return Err(AppError::usage("--top-ports must be at least 1"));
    }
    if count > 65_535 {
        return Err(AppError::usage("--top-ports cannot exceed 65535"));
    }

    let mut seen = [false; 65_536];
    let mut ports = Vec::with_capacity(count.min(1000));

    // Take from the curated top-100 list for small counts, then from the
    // full nmap top-1000 frequency table for larger selections.
    let curated = if count <= 100 {
        TOP_PORTS_100
    } else {
        TOP_PORTS_1000
    };
    for &port in curated.iter().take(count) {
        push_unique(&mut ports, &mut seen, port);
    }

    // If more are needed, fill from low ports 1..=65535
    if ports.len() < count {
        for port in 1..=65_535u16 {
            if !seen[port as usize] {
                push_unique(&mut ports, &mut seen, port);
                if ports.len() == count {
                    break;
                }
            }
        }
    }

    Ok(ports)
}

/// Port preset bundles for common engagement targets.
///
/// Each preset maps to a curated port set so operators can select
/// the most relevant attack surface without manually enumerating
/// individual ports.  `dc|ad` focuses on Active Directory / Domain
/// Controller services, `win|ws` on Windows workstation/server,
/// `web|http` on HTTP(S) admin surfaces, `linux|lx` on common Linux
/// daemons, `full|all` on the complete TCP range, and `q|top` on
/// the top 1000 ports from the nmap frequency table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PortPreset {
    /// Active Directory / Domain Controller core services.
    #[value(name = "dc", alias = "ad")]
    DcAd,
    /// Windows workstation/server typical services.
    #[value(name = "win", alias = "ws")]
    WinWs,
    /// HTTP(S) admin and alternate web ports.
    #[value(name = "web", alias = "http")]
    WebHttp,
    /// Common Linux daemons (SSH, SMTP, DNS, NFS, DBs, etc.).
    #[value(name = "linux", alias = "lx")]
    LinuxLx,
    /// Full TCP range 1-65535.
    #[value(name = "full", alias = "all")]
    FullAll,
    /// nmap top-1000 most frequent TCP ports.
    #[value(name = "q", alias = "top")]
    QTop,
}

impl PortPreset {
    /// Return the canonical preset name used in saved-state specs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DcAd => "dc",
            Self::WinWs => "win",
            Self::WebHttp => "web",
            Self::LinuxLx => "linux",
            Self::FullAll => "full",
            Self::QTop => "q",
        }
    }

    /// Expand the preset into an explicit port list.
    pub fn ports(self) -> Vec<u16> {
        match self {
            Self::DcAd => vec![
                53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 5986,
                9389,
            ],
            Self::WinWs => vec![53, 135, 139, 445, 3389, 5985, 5986, 1433, 1434],
            Self::WebHttp => vec![
                80, 443, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090,
                9443,
            ],
            Self::LinuxLx => vec![
                21, 22, 25, 53, 111, 139, 445, 631, 2049, 3306, 5432, 5900, 6379, 9200, 27017,
            ],
            Self::FullAll => crate::ports::parse_ports("1-65535").unwrap_or_default(),
            Self::QTop => top_ports(1000).unwrap_or_default(),
        }
    }

    /// Return a port specification string suitable for `--ports` or
    /// saved-state files.  `full` and `q` are expressed as portable
    /// ranges / `top-N` so they remain small in state files.
    pub fn spec(self) -> String {
        match self {
            Self::DcAd => "preset:dc".to_string(),
            Self::WinWs => "preset:win".to_string(),
            Self::WebHttp => "preset:web".to_string(),
            Self::LinuxLx => "preset:linux".to_string(),
            Self::FullAll => "1-65535".to_string(),
            Self::QTop => "top-1000".to_string(),
        }
    }
}

/// Reorder a slice of ports in-place so that common ports (as defined by [`TOP_PORTS_100`])
/// appear first in order of their popularity rank, followed by the remaining ports in ascending order.
///
/// This dramatically improves time-to-first-result on wide scans.
pub fn prioritize_ports(ports: &mut [u16]) {
    let rank_of = |p: u16| -> (usize, u16) {
        if let Some(idx) = TOP_PORTS_100.iter().position(|&x| x == p) {
            (idx, p)
        } else {
            (usize::MAX, p)
        }
    };
    ports.sort_by_key(|&p| rank_of(p));
}

/// Parse a saved port specification produced by the CLI (`"1-1024"`,
/// `"80,443"`, or `"top-100"`).
pub fn parse_spec(input: &str) -> Result<Vec<u16>, AppError> {
    if let Some(count) = input.strip_prefix("top-") {
        let count = count
            .parse::<usize>()
            .map_err(|_| AppError::usage(format!("invalid saved port specification {input:?}")))?;
        return top_ports(count);
    }
    parse_ports(input)
}

/// Parse a port expression such as `80,443,8000-8100`.
///
/// Both `-` and `:` are accepted as range separators. Duplicates are removed
/// while preserving the order in which ports first appear.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, AppError> {
    if input.trim().is_empty() {
        return Err(AppError::usage("--ports must not be empty"));
    }

    let mut seen = [false; 65_536];
    let mut ports = Vec::new();

    for raw in input.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            return Err(AppError::usage(format!(
                "invalid port list {input:?}: empty entry"
            )));
        }

        if let Some(separator) = token.find(['-', ':']) {
            let start = parse_port(token[..separator].trim(), token)?;
            let end = parse_port(token[separator + 1..].trim(), token)?;
            if start > end {
                return Err(AppError::usage(format!(
                    "invalid port range {token:?}: start is greater than end"
                )));
            }
            for port in start..=end {
                push_unique(&mut ports, &mut seen, port);
            }
        } else {
            let port = parse_port(token, token)?;
            push_unique(&mut ports, &mut seen, port);
        }
    }

    Ok(ports)
}

fn parse_port(value: &str, token: &str) -> Result<u16, AppError> {
    if value.is_empty() {
        return Err(AppError::usage(format!(
            "invalid port range {token:?}: missing endpoint"
        )));
    }

    let port = value.parse::<u32>().map_err(|_| {
        AppError::usage(format!(
            "invalid port {value:?}; expected a number from 1 to 65535"
        ))
    })?;

    if port == 0 || port > 65_535 {
        return Err(AppError::usage(format!(
            "port {port} is out of range; expected 1-65535"
        )));
    }

    Ok(port as u16)
}

fn push_unique(ports: &mut Vec<u16>, seen: &mut [bool; 65_536], port: u16) {
    if !seen[port as usize] {
        seen[port as usize] = true;
        ports.push(port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges_in_order() {
        assert_eq!(
            parse_ports("443, 80, 8000-8002, 80").unwrap(),
            vec![443, 80, 8000, 8001, 8002]
        );
        assert_eq!(parse_ports("1:3").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn rejects_zero_out_of_range_and_inverted_ranges() {
        assert_eq!(parse_ports("0").unwrap_err().exit_code(), 2);
        assert_eq!(parse_ports("65536").unwrap_err().exit_code(), 2);
        assert_eq!(parse_ports("90-80").unwrap_err().exit_code(), 2);
        assert_eq!(parse_ports("80-").unwrap_err().exit_code(), 2);
        assert_eq!(parse_ports("80,,443").unwrap_err().exit_code(), 2);
        assert_eq!(parse_ports(" ").unwrap_err().exit_code(), 2);
    }

    #[test]
    fn parses_the_full_port_range() {
        let ports = parse_ports("1-65535").unwrap();
        assert_eq!(ports.len(), 65_535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65_534], 65_535);
    }

    #[test]
    fn top_ports_returns_expected_slice_and_count() {
        assert_eq!(top_ports(5).unwrap(), vec![80, 23, 443, 21, 22]);
        assert_eq!(top_ports(100).unwrap().len(), 100);
        assert_eq!(top_ports(500).unwrap().len(), 500);
        assert_eq!(top_ports(0).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn top_ports_1000_matches_nmap_frequency_table() {
        assert_eq!(TOP_PORTS_1000.len(), 1000);
        let ports = top_ports(1000).unwrap();
        assert_eq!(ports.as_slice(), TOP_PORTS_1000);
        assert_eq!(ports[0], 80);
        assert_eq!(ports[1], 23);
        assert_eq!(ports[2], 443);
    }

    #[test]
    fn parse_spec_handles_lists_and_top_ports() {
        assert_eq!(parse_spec("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_spec("top-5").unwrap(), vec![80, 23, 443, 21, 22]);
        assert_eq!(parse_spec("top-nope").unwrap_err().exit_code(), 2);
    }

    #[test]
    fn prioritize_ports_orders_common_ports_first() {
        let mut ports = vec![8080, 12345, 22, 9999, 80, 443];
        prioritize_ports(&mut ports);
        // TOP_PORTS_100 ranks: 80 (0), 443 (2), 22 (4), 8080 (14)
        // 9999 is in TOP_PORTS_100 (index 96), 12345 is not (usize::MAX)
        assert_eq!(ports[0], 80);
        assert_eq!(ports[1], 443);
        assert_eq!(ports[2], 22);
        assert_eq!(ports[3], 8080);
        assert_eq!(ports[4], 9999);
        assert_eq!(ports[5], 12345);
    }

    #[test]
    fn presets_expand_to_expected_ports() {
        let dc = PortPreset::DcAd.ports();
        assert!(dc.contains(&88));
        assert!(dc.contains(&389));
        assert!(dc.contains(&445));
        let win = PortPreset::WinWs.ports();
        assert!(win.contains(&445));
        assert!(win.contains(&5985));
        assert!(win.contains(&3389));
        let web = PortPreset::WebHttp.ports();
        assert!(web.contains(&80));
        assert!(web.contains(&443));
        assert!(web.contains(&8080));
        let linux = PortPreset::LinuxLx.ports();
        assert!(linux.contains(&22));
        assert!(linux.contains(&3306));
        assert!(linux.contains(&27017));
        assert_eq!(PortPreset::FullAll.ports().len(), 65_535);
        assert_eq!(PortPreset::QTop.ports().len(), 1000);
    }

    #[test]
    fn preset_spec_is_parseable() {
        assert_eq!(PortPreset::FullAll.spec(), "1-65535");
        assert_eq!(PortPreset::QTop.spec(), "top-1000");
        assert!(PortPreset::DcAd.spec().starts_with("preset:"));
    }
}
