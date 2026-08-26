//! The daemon end to end, through the real `fluxd` binary and its CLI
//! (`harness = false`: this test binary is also the fake engine — the daemon
//! is pointed at it via `FLUX_ENGINE_BIN`).
//!
//! Scenarios:
//!
//! 1. Cold start through `fluxd daemon`: engine spawned, `status --json`
//!    reports Inactive (with the explicit pre-attachment reason), engine running,
//!    4/4 sockets (§17.5 exit criteria 1 and 4).
//! 2. A second `fluxd daemon` is rejected by the flock with a readable
//!    reason naming the holder pid (exit criterion 3).
//! 3. `fluxd disable` / `enable`: the state flips Disabled ⇄ Inactive, the
//!    engine stops and restarts with a new generation.
//! 4. `fluxd reload`: hot switch — generation grows, pid changes.
//! 5. Overlapping reload clients wait until the queued transaction converges.
//! 6. `fluxd bugreport`: a zip appears; no logcat entry by default; raw
//!    configs never included (exit criterion 5).
//! 7. `fluxd stop`: daemon exits cleanly, control socket removed, no
//!    effective file left behind; `status` then fails with a clear message.
//!
//! On kernels without `udp_diag` (some sandboxes) the engine cannot verify
//! its sockets; the run degrades to the daemon-only subset and says so.

#[path = "common/fake_engine.rs"]
mod fake_engine;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    println!("daemon_e2e: skipped (Linux/Android-only)");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    fake_engine::maybe_run();
    tests::run_all();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod tests {
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use flux_core::control_wire::{Response, State};

    const FLUXD: &str = env!("CARGO_BIN_EXE_fluxd");

    /// Stands in for a proxy credential inside sing-box.json.
    const CONFIG_SENTINEL: &str = "credential-sentinel-7b2b";

    struct Env {
        root: PathBuf,
    }

    impl Env {
        fn command(&self, args: &[&str]) -> Command {
            let mut cmd = Command::new(FLUXD);
            cmd.args(args)
                .env("FLUX_RUNTIME_ROOT", &self.root)
                .env(
                    "FLUX_ENGINE_BIN",
                    std::env::current_exe().expect("own path"),
                )
                .env("FLUX_LISTEN_V4", "127.0.0.1")
                .env("FLUX_LISTEN_V6", "::1")
                .env("FLUX_FAKE_READY_DELAY_MS", "400")
                // This E2E covers the reactor/engine transaction. Phase 3
                // rtnetlink ownership is exercised separately on a root ADB
                // device; the spawned test binary normally lacks CAP_NET_ADMIN.
                .env("FLUX_TEST_SKIP_DATAPLANE", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }

        fn run(&self, args: &[&str]) -> (i32, String, String) {
            let out = self.command(args).output().expect("spawn fluxd");
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }

        fn status(&self) -> Response {
            let (code, stdout, stderr) = self.run(&["status", "--json"]);
            assert_eq!(code, 0, "status must succeed; stderr: {stderr}");
            serde_json::from_str(stdout.trim()).expect("status is valid wire JSON")
        }
    }

    pub fn run_all() {
        let full = udp_diag_supported();
        if !full {
            println!(
                "daemon_e2e: kernel has no udp_diag handler (sandbox?) — running \
                 the daemon-only subset; CI runners and devices run the full flow"
            );
        }

        let mut root = std::env::temp_dir();
        root.push(format!("flux-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // 0700 like production: the daemon refuses looser modes (§23.1).
        for dir in [root.clone(), root.join("run"), root.join("config")] {
            std::fs::create_dir_all(&dir).expect("dirs");
            std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("chmod");
        }
        let env = Env { root: root.clone() };

        // A valid user engine config must exist before the daemon starts. The
        // sentinel tag stands in for proxy credentials: it must never leak
        // into a bug report.
        std::fs::write(
            root.join("config/sing-box.json"),
            serde_json::json!({
                "outbounds": [ { "type": "direct", "tag": CONFIG_SENTINEL } ]
            })
            .to_string(),
        )
        .expect("sing-box.json");

        let mut daemon = env.command(&["daemon"]).spawn().expect("daemon spawns");
        wait_for(&root.join("run/control.sock"), Duration::from_secs(10));

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenario_status_and_cold_start(&env, full);
            scenario_second_instance_rejected(&env, daemon.id());
            scenario_disable_enable(&env, full);
            if full {
                scenario_reload_hot_switch(&env);
                scenario_queued_reload_waits_for_convergence(&env);
            }
            scenario_bugreport(&env);
            scenario_stop(&env, &mut daemon, &root);
        }));

        if outcome.is_err() {
            // Leave no daemon behind on failure; then re-raise.
            let _ = daemon.kill();
            let _ = daemon.wait();
            dump_daemon_log(&root);
            std::process::exit(101);
        }
        let _ = std::fs::remove_dir_all(&root);
        println!(
            "daemon_e2e: all scenarios passed ({})",
            if full {
                "full flow"
            } else {
                "daemon-only subset"
            }
        );
    }

    fn scenario_status_and_cold_start(env: &Env, full: bool) {
        // Give the cold-start transaction a moment to close.
        let deadline = Instant::now() + Duration::from_secs(10);
        let response = loop {
            let response = env.status();
            if !full || response.engine.running || Instant::now() >= deadline {
                break response;
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        assert_eq!(response.state, State::Inactive, "no data plane => Inactive");
        assert!(
            response
                .warnings
                .iter()
                .any(|w| w.contains("no data plane")),
            "Inactive must carry its reason, not silence (§17.5 criterion 4): {:?}",
            response.warnings
        );
        if full {
            assert!(response.engine.running, "engine must be running");
            assert_eq!(response.engine.sockets_verified, 4, "4/4 sockets");
            assert_eq!(response.generation, 1);
            let effective = response
                .engine
                .effective_config
                .as_deref()
                .expect("effective path reported");
            assert!(
                effective.ends_with("effective-sing-box.1.json"),
                "generation-named effective config: {effective}"
            );
            assert!(Path::new(effective).exists());
            println!("PASS cold start via daemon (pid {:?})", response.engine.pid);
        } else {
            assert!(!response.engine.running);
            assert!(
                response.last_error.is_some(),
                "the failed start must be reported"
            );
            println!("PASS status reports Inactive with reason (daemon-only subset)");
        }

        // Human-readable form: never empty, names the state.
        let (code, stdout, _) = env.run(&["status"]);
        assert_eq!(code, 0);
        assert!(stdout.contains("state:      Inactive"), "{stdout}");
        assert!(stdout.contains("warning:"), "{stdout}");
    }

    fn scenario_second_instance_rejected(env: &Env, daemon_pid: u32) {
        let (code, _, stderr) = env.run(&["daemon"]);
        assert_eq!(code, 1, "second instance must exit 1");
        assert!(
            stderr.contains("another fluxd instance is already running"),
            "readable reason required, got: {stderr}"
        );
        assert!(
            stderr.contains(&format!("pid {daemon_pid}")),
            "the holder pid must be named, got: {stderr}"
        );
        println!("PASS second instance rejected by flock (pid {daemon_pid} named)");
    }

    fn scenario_disable_enable(env: &Env, full: bool) {
        let (code, _, stderr) = env.run(&["disable"]);
        assert_eq!(code, 0, "disable: {stderr}");
        let response = env.status();
        assert_eq!(response.state, State::Disabled);
        assert!(!response.engine.running, "disabled => engine stopped");
        assert!(env.root.join("disable").exists(), "the C9 switch file");

        let (code, _, stderr) = env.run(&["enable"]);
        assert_eq!(code, 0, "enable: {stderr}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let response = loop {
            let response = env.status();
            if !full || response.engine.running || Instant::now() >= deadline {
                break response;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(response.state, State::Inactive);
        assert!(!env.root.join("disable").exists());
        if full {
            assert!(response.engine.running, "enable => engine restarted");
            assert!(response.generation >= 2, "a fresh generation after enable");
        }
        println!("PASS disable/enable flips the switch file and the engine");
    }

    fn scenario_reload_hot_switch(env: &Env) {
        let before = env.status();
        let old_generation = before.generation;
        let old_pid = before.engine.pid;

        let (code, stdout, stderr) = env.run(&["reload"]);
        assert_eq!(code, 0, "reload failed: {stdout} {stderr}");
        let response = env.status();
        assert!(response.engine.running, "engine survives a reload");
        assert!(
            response.generation > old_generation,
            "hot switch must advance the generation ({} -> {})",
            old_generation,
            response.generation
        );
        assert_ne!(response.engine.pid, old_pid, "a fresh engine process");
        assert_eq!(response.engine.sockets_verified, 4);
        println!(
            "PASS reload hot switch (generation {} -> {}, pid {:?} -> {:?})",
            old_generation, response.generation, old_pid, response.engine.pid
        );
    }

    fn scenario_queued_reload_waits_for_convergence(env: &Env) {
        let before = env.status();
        let mut first = env.command(&["reload"]).spawn().expect("first reload");

        // The fake engine delays listener creation. Seeing no promoted engine
        // proves the first transaction is in its inactive switch window.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if !env.status().engine.running {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "first reload never entered its switch window"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let second = env.command(&["reload"]).spawn().expect("queued reload");
        let second_output = second.wait_with_output().expect("queued reload output");
        let first_output = first.wait().expect("first reload output");
        assert!(
            first_output.success(),
            "first reload failed: {first_output:?}"
        );
        assert!(
            second_output.status.success(),
            "queued reload failed: stdout={} stderr={}",
            String::from_utf8_lossy(&second_output.stdout),
            String::from_utf8_lossy(&second_output.stderr)
        );

        let after = env.status();
        assert!(after.engine.running, "queued convergence must be terminal");
        assert!(
            after.generation >= before.generation + 2,
            "queued client returned before its generation converged ({} -> {})",
            before.generation,
            after.generation
        );
        println!(
            "PASS overlapping reloads converged through generation {}",
            after.generation
        );
    }

    fn scenario_bugreport(env: &Env) {
        let out_dir = env.root.join("reports");
        std::fs::create_dir_all(&out_dir).expect("reports dir");
        let (code, stdout, stderr) = env.run(&[
            "bugreport",
            "-o",
            out_dir.to_str().expect("utf-8 temp path"),
        ]);
        assert_eq!(code, 0, "bugreport failed: {stdout} {stderr}");

        let zip: Vec<PathBuf> = std::fs::read_dir(&out_dir)
            .expect("read reports")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(zip.len(), 1, "exactly one zip: {zip:?}");
        let bytes = std::fs::read(&zip[0]).expect("read zip");
        assert!(bytes.starts_with(b"PK\x03\x04"), "zip magic");
        let contains = |name: &str| {
            bytes
                .windows(name.len())
                .any(|window| window == name.as_bytes())
        };
        for name in [
            "meta.txt",
            "status.json",
            "check.txt",
            "observe.txt",
            "README.txt",
        ] {
            assert!(contains(name), "{name} must be in the report");
        }
        assert!(
            !contains("logcat.txt"),
            "logcat MUST NOT be included by default (docs/ux.md §6)"
        );
        assert!(
            !contains(CONFIG_SENTINEL),
            "raw config CONTENT must never appear in a bug report"
        );
        println!("PASS bugreport zip written, no logcat by default");
    }

    fn scenario_stop(env: &Env, daemon: &mut Child, root: &Path) {
        let (code, stdout, _) = env.run(&["stop"]);
        assert_eq!(code, 0);
        assert!(stdout.contains("stopping"), "{stdout}");

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match daemon.try_wait().expect("try_wait") {
                Some(status) => {
                    assert!(status.success(), "daemon must exit 0, got {status:?}");
                    break;
                }
                None if Instant::now() >= deadline => panic!("daemon did not exit"),
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        assert!(
            !root.join("run/control.sock").exists(),
            "control socket unlinked on clean exit"
        );
        let leftovers: Vec<_> = std::fs::read_dir(root.join("run"))
            .expect("run dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("effective-sing-box."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no effective files left: {leftovers:?}"
        );

        // Idempotent stop; readable status refusal.
        let (code, stdout, _) = env.run(&["stop"]);
        assert_eq!(code, 0, "stop is idempotent (§10.3)");
        assert!(stdout.contains("not running"));
        let (code, _, stderr) = env.run(&["status"]);
        assert_eq!(code, 1, "status without a daemon fails clearly");
        assert!(stderr.contains("not reachable"), "{stderr}");
        println!("PASS graceful stop, socket unlinked, no leftovers");
    }

    fn wait_for(path: &Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn dump_daemon_log(root: &Path) {
        if let Ok(mut file) = std::fs::File::open(root.join("fluxd.log")) {
            let mut text = String::new();
            let _ = file.read_to_string(&mut text);
            eprintln!("--- fluxd.log ---\n{text}\n--- end fluxd.log ---");
        }
    }

    /// Whether this kernel can enumerate UDP sockets via `NETLINK_SOCK_DIAG`.
    /// Probed exactly like production does, but through a raw request here to
    /// avoid pulling the src modules into this test crate as well.
    fn udp_diag_supported() -> bool {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe bind");
        let port = probe.local_addr().unwrap().port();

        // SAFETY: plain socket(2); the fd is immediately owned.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return false;
        }
        // SAFETY: just returned by the kernel, not owned elsewhere.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut msg = [0u8; 72];
        msg[0..4].copy_from_slice(&72u32.to_ne_bytes());
        msg[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        msg[6..8].copy_from_slice(&flags.to_ne_bytes());
        msg[8..12].copy_from_slice(&1u32.to_ne_bytes());
        msg[16] = libc::AF_INET as u8;
        msg[17] = libc::IPPROTO_UDP as u8;
        msg[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        // SAFETY: msg is valid for its length for the duration of the call.
        let sent = unsafe { libc::send(sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if sent != msg.len() as isize {
            return false;
        }

        let mut buf = vec![0u8; 64 * 1024];
        let mut found = false;
        loop {
            // SAFETY: buf is valid for its length for the duration of the call.
            let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                return false;
            }
            let mut offset = 0usize;
            while offset + 16 <= n as usize {
                let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
                let kind = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
                if kind == libc::NLMSG_DONE as u16 || kind == libc::NLMSG_ERROR as u16 {
                    return found;
                }
                if len >= 16 + 6 {
                    let sport =
                        u16::from_be_bytes(buf[offset + 20..offset + 22].try_into().unwrap());
                    if sport == port {
                        found = true;
                    }
                }
                offset += (len + 3) & !3;
            }
        }
    }
}
