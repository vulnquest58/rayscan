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
    assert!(stdout.contains("0.1.0"));
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
    assert_eq!(payload["version"], "0.1.0");
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
