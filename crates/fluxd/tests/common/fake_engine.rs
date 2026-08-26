//! The fake engine: this test binary doubling as `sing-box`.
//!
//! The integration tests point `FLUX_ENGINE_BIN` (or `EngineSpec::binary`) at
//! their own executable. When fluxd's spawn/check paths exec it with sing-box
//! argv (`run -c <config>` / `check -c <config>`), [`maybe_run`] takes over
//! before any test logic: it parses the effective config exactly as written by
//! `engine::write_effective`, binds the four listener sockets in this single
//! process — the same 2 family × 2 protocol shape the real engine holds, which
//! is what the Q2 readiness check verifies — and parks until `SIGTERM`.
//!
//! Failure injection, controlled by the parent's environment (inherited
//! through `execv`):
//!
//! * `FLUX_FAKE_CRASH=1`   — exit 7 immediately on `run` (cold-start failure).
//! * `FLUX_FAKE_FAIL_ONCE=<path>` — if `<path>` exists, delete it and exit 9;
//!   otherwise run normally. One candidate fails, the step-6 recovery respawn
//!   succeeds.
//! * `FLUX_FAKE_NOT_READY=1` — remain alive without binding any listener.
//! * `FLUX_FAKE_READY_DELAY_MS=<n>` — delay listener creation so overlapping
//!   control requests can exercise queued convergence deterministically.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

use std::net::{TcpListener, UdpSocket};

/// Runs the fake engine when argv says so; returns otherwise.
pub fn maybe_run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[2] != "-c" {
        return;
    }
    match args[1].as_str() {
        "check" => check(&args[3]),
        "run" => run(&args[3]),
        _ => {}
    }
}

fn check(config_path: &str) -> ! {
    let text = std::fs::read_to_string(config_path).unwrap_or_default();
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("fake-engine check: bad config: {e}");
            std::process::exit(1);
        }
    }
}

fn run(config_path: &str) -> ! {
    if let Some(path) = std::env::var_os("FLUX_FAKE_PID_FILE") {
        let _ = std::fs::write(path, std::process::id().to_string());
    }
    if std::env::var_os("FLUX_FAKE_CRASH").is_some() {
        eprintln!("fake-engine: crashing on request");
        std::process::exit(7);
    }
    if let Some(flag) = std::env::var_os("FLUX_FAKE_FAIL_ONCE") {
        let flag = std::path::PathBuf::from(flag);
        if flag.exists() {
            let _ = std::fs::remove_file(&flag);
            eprintln!("fake-engine: failing once as requested");
            std::process::exit(9);
        }
    }
    if std::env::var_os("FLUX_FAKE_NOT_READY").is_some() {
        eprintln!("fake-engine: staying alive without listeners");
        loop {
            std::thread::park();
        }
    }

    if let Some(delay) = std::env::var("FLUX_FAKE_READY_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }

    let text = std::fs::read_to_string(config_path).expect("fake-engine: config readable");
    let config: serde_json::Value =
        serde_json::from_str(&text).expect("fake-engine: config is JSON");
    let inbounds = config
        .get("inbounds")
        .and_then(|v| v.as_array())
        .expect("fake-engine: inbounds injected");
    let port = |tag: &str| -> u16 {
        inbounds
            .iter()
            .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(tag))
            .and_then(|i| i.get("listen_port"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u16)
            .unwrap_or_else(|| panic!("fake-engine: no {tag} inbound"))
    };
    let port_v4 = port("flux-in-v4");
    let port_v6 = port("flux-in-v6");

    // All four sockets held by THIS pid, like the real engine: that is what
    // the pid+inode cross-check must see. Bound on loopback because the test
    // spec expects loopback (non-root cannot bind the ABI tproxy addresses).
    let _tcp4 = TcpListener::bind(("127.0.0.1", port_v4)).expect("fake-engine: tcp4");
    let _udp4 = UdpSocket::bind(("127.0.0.1", port_v4)).expect("fake-engine: udp4");
    let _tcp6 = TcpListener::bind(("::1", port_v6)).expect("fake-engine: tcp6");
    let _udp6 = UdpSocket::bind(("::1", port_v6)).expect("fake-engine: udp6");
    println!("fake-engine: listening (v4 {port_v4}, v6 {port_v6})");

    // SIGTERM's default disposition (restored by the spawn path) terminates.
    loop {
        std::thread::park();
    }
}
