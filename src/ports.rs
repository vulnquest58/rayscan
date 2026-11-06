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

    // First take from curated top ports list
    for &port in TOP_PORTS_100.iter().take(count) {
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
    fn parse_spec_handles_lists_and_top_ports() {
        assert_eq!(parse_spec("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_spec("top-5").unwrap(), vec![80, 23, 443, 21, 22]);
        assert_eq!(parse_spec("top-nope").unwrap_err().exit_code(), 2);
    }
}
