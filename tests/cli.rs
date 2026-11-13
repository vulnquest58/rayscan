use std::io::Write;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use serde_json::Value;

fn rayscan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rayscan"))
}

struct BannerServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl BannerServer {
    fn port(&self) -> u16 {
        self.port
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("test server thread");
        }
    }
}

/// Serve the same banner on every connection until [`BannerServer::stop`].
/// The scanner opens more than one connection per port (the probe plus the
/// post-scan local recheck), so a listener that stops after the first accept
/// would be reported closed by the recheck.
fn banner_server() -> BannerServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking test listener");
    let port = listener.local_addr().expect("listener address").port();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nServer: rayscan-lab\r\nContent-Length: 0\r\n\r\n",
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    BannerServer {
        port,
        stop,
        handle: Some(handle),
    }
}

#[test]
fn version_is_reported() {
    let output = rayscan().arg("--version").output().expect("run rayscan");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.starts_with("rayscan "));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_describes_the_scan_command() {
    let output = rayscan().arg("--help").output().expect("run rayscan");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("Usage: rayscan"));
    assert!(stdout.contains("accuracy-first"));
    assert!(stdout.contains("scan"));
}

#[test]
fn no_arguments_shows_help() {
    let output = rayscan().output().expect("run rayscan");
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Usage: rayscan"));
}

#[test]
fn json_scan_reports_an_open_port() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["host"], "127.0.0.1");
    assert_eq!(payload["open"][0]["port"], port);
    assert_eq!(payload["open"][0]["service"]["name"], "http");
    assert_eq!(payload["open"][0]["service"]["product"], "rayscan-lab");
    assert_eq!(payload["summary"]["open"], 1);
    server.stop();
}

#[test]
fn quiet_scan_emits_no_progress_on_stderr() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "quiet mode must not emit progress on stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.stop();
}

#[test]
fn no_service_detection_keeps_the_open_set_without_metadata() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--no-service-detection",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"].as_array().unwrap().len(), 1);
    assert!(payload["open"][0].get("service").is_none());
    assert!(payload["open"][0].get("banner").is_none());
    server.stop();
}

#[test]
fn json_scan_reports_a_closed_port_without_listing_it() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
    let port = listener.local_addr().expect("listener address").port();
    drop(listener);

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"].as_array().unwrap().len(), 0);
    assert_eq!(payload["summary"]["closed"], 1);
}

#[test]
fn doctor_json_reports_capability_checks() {
    let output = rayscan()
        .args(["doctor", "--json"])
        .output()
        .expect("run rayscan doctor");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    let checks = payload["checks"].as_array().expect("checks array");
    assert!(checks.iter().any(|check| check["name"] == "raw-syn"));
    assert!(checks.iter().any(|check| check["name"] == "config"));
}

#[test]
fn interactive_requires_a_terminal() {
    let output = rayscan()
        .arg("interactive")
        .output()
        .expect("run rayscan interactive");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("interactive mode requires a terminal")
    );
}

#[test]
fn invalid_ports_exit_with_usage_status() {
    let output = rayscan()
        .args(["scan", "--target", "127.0.0.1", "--ports", "0", "--json"])
        .output()
        .expect("run rayscan scan");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("out of range"));
}

#[test]
fn omitted_ports_defaults_to_well_known_range() {
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--rate",
            "10000",
            "--workers",
            "50",
            "--timeout",
            "0.1",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["ports"], 1024);
}

#[test]
fn stealth_flag_runs_scan() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--stealth",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["port"], port);
    assert_eq!(payload["summary"]["open"], 1);
    server.stop();
}

#[test]
fn scope_guard_blocks_unauthorized_target() {
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_block.toml");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "Engagement Alpha"
allow = ["10.0.0.0/8"]
"#,
    )
    .expect("write scope");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
        ])
        .output()
        .expect("run rayscan scan");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SCOPE VIOLATION"));
    assert!(stderr.contains("Engagement Alpha"));

    // Overriding with --force-out-of-scope succeeds
    let override_output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
            "--force-out-of-scope",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(override_output.status.success());
    let _ = std::fs::remove_file(scope_path);
}

#[test]
fn scope_guard_allows_authorized_target() {
    let server = banner_server();
    let port = server.port();
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_allow.toml");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "Localhost Lab"
allow = ["127.0.0.0/8"]
"#,
    )
    .expect("write scope");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--scope",
            scope_path.to_str().unwrap(),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["port"], port);
    let _ = std::fs::remove_file(scope_path);
    server.stop();
}

#[test]
fn scope_guard_checks_domains_from_target_files() {
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_file.toml");
    let targets_path = temp_dir.join("test_scope_targets.txt");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "File Scope"
allow = ["127.0.0.0/8"]
deny = ["localhost"]
"#,
    )
    .expect("write scope");
    std::fs::write(&targets_path, "localhost\n").expect("write targets");

    let output = rayscan()
        .args([
            "scan",
            "--target-file",
            targets_path.to_str().unwrap(),
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
        ])
        .output()
        .expect("run rayscan scan");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SCOPE VIOLATION"));
    let _ = std::fs::remove_file(scope_path);
    let _ = std::fs::remove_file(targets_path);
}

#[test]
fn stream_flag_emits_jsonl_records() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--stream",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found_port = false;
    for line in stdout.lines() {
        if let Ok(parsed) = serde_json::from_str::<Value>(line)
            && parsed["port"] == port
            && parsed["state"] == "open"
        {
            found_port = true;
            break;
        }
    }
    assert!(
        found_port,
        "Stream output must contain line-by-line JSON with port {port}: {stdout}"
    );
    server.stop();
}

#[test]
fn host_port_format_lists_open_ports_for_pipelines() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--format",
            "host-port",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("127.0.0.1:{port}")
    );
    server.stop();
}

#[test]
fn port_list_format_stdout_stays_machine_readable() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--format",
            "port-list",
            "--tls",
            "--os",
            "--defense",
            "--timeout",
            "1",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // RSC-BUG-002/003/004 regression: stdout for a machine-readable format
    // contains only the port list — no progress lines, no ANSI, no duplicate
    // ports and no defense intelligence blocks.
    assert!(
        stdout
            .trim_end()
            .chars()
            .all(|c| c.is_ascii_digit() || c == ','),
        "stdout must only contain a port list: {stdout:?}"
    );
    assert_eq!(stdout.trim(), port.to_string());

    // PROPOSAL-001 regression: progress phases auto-quiet for machine formats.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[tls]") && !stderr.contains("[os]"),
        "progress lines must be suppressed for machine-readable formats: {stderr:?}"
    );
    server.stop();
}

#[test]
fn exclude_ports_rejects_removing_the_entire_scan() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--exclude-ports",
            &port.to_string(),
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--exclude-ports removed every port"));
    server.stop();
}

#[test]
fn baseline_alerts_and_fail_on_change_drive_monitoring() {
    let server = banner_server();
    let port = server.port();
    let dir = std::env::temp_dir().join(format!("rayscan-monitor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create test directory");
    let baseline = dir.join("baseline.json");
    let alert = dir.join("alert.txt");

    let first = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--save-baseline",
            baseline.to_str().expect("baseline path"),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run baseline scan");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(baseline.exists(), "baseline file must be written");

    let second = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--diff",
            baseline.to_str().expect("baseline path"),
            "--fail-on-change",
            "--alert-file",
            alert.to_str().expect("alert path"),
            "--quiet",
        ])
        .output()
        .expect("run unchanged scan");
    assert!(
        second.status.success(),
        "no changes must exit 0; stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let unchanged = std::fs::read_to_string(&alert).expect("alert file");
    assert!(unchanged.contains("status: no changes"));

    let mut payload: Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).expect("read baseline"))
            .expect("baseline JSON");
    payload["open"] = serde_json::json!([]);
    if payload.get("results").is_some() {
        payload["results"] = serde_json::json!([]);
    }
    std::fs::write(
        &baseline,
        serde_json::to_string_pretty(&payload).expect("encode baseline"),
    )
    .expect("rewrite baseline");

    let third = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--diff",
            baseline.to_str().expect("baseline path"),
            "--fail-on-change",
            "--alert-file",
            alert.to_str().expect("alert path"),
            "--quiet",
        ])
        .output()
        .expect("run changed scan");
    assert_eq!(third.status.code(), Some(1));
    let changed = std::fs::read_to_string(&alert).expect("alert file");
    assert!(changed.contains("status: changes detected"));
    assert!(changed.contains(&format!("[+] NEW 127.0.0.1:{port}")));

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}
