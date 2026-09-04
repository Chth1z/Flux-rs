//! Phase 7 root-device acceptance: fault coalescing, generation recovery and
//! crash backoff through the production daemon/reactor.
//!
//! Blast radius while `FLUX_PHASE7_DEVICE_TEST=1` is set: creates the exact
//! Flux veth/RPDB/TC/BPF objects, starts a private daemon plus engine child,
//! and sends TEST-NET traffic from sockets owned by one installed app UID.
//! Cleanup always restarts the daemon in Disabled state so its exact ownership
//! predicates remove only Flux objects, then removes the private runtime tree.

#[cfg(target_os = "android")]
#[path = "common/fake_engine.rs"]
mod fake_engine;

#[cfg(not(target_os = "android"))]
fn main() {
    println!("phase7 device test: skipped (Android-only)");
}

#[cfg(target_os = "android")]
fn main() {
    fake_engine::maybe_run();
    if std::env::var_os("FLUX_PHASE7_DEVICE_TEST").as_deref() != Some(std::ffi::OsStr::new("1")) {
        println!("phase7 device test: skipped (set FLUX_PHASE7_DEVICE_TEST=1)");
        return;
    }
    tests::run();
}

#[cfg(target_os = "android")]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use flux_core::abi::{APP_ID_MAX, APP_ID_MIN, USER_ID_STRIDE};
    use flux_core::control_wire::{Response, State};

    const DESTINATION: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
    const DESTINATION_PORT: u16 = 46_007;
    const FAULT_BURST: usize = 128;
    const DIRECT_TCP_PROBES: usize = 8;
    const DIRECT_UDP_PROBES: usize = 32;

    pub fn run() {
        // SAFETY: geteuid has no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(euid, 0, "Phase 7 device test needs root");
        let fluxd = PathBuf::from(
            std::env::var_os("FLUX_PHASE7_FLUXD")
                .expect("FLUX_PHASE7_FLUXD must name the Android fluxd binary"),
        );
        let official_engine = PathBuf::from(
            std::env::var_os("FLUX_PHASE7_ENGINE_BIN")
                .expect("FLUX_PHASE7_ENGINE_BIN must name the pinned official sing-box"),
        );
        let (package, uid) = network_app();
        let run_id = std::process::id();

        fault_generation_scenario(
            &fluxd,
            &package,
            uid,
            PathBuf::from(format!("/data/local/tmp/flux-phase7-fault-{run_id}")),
        );
        official_generation_scenario(
            &fluxd,
            &official_engine,
            &package,
            uid,
            PathBuf::from(format!("/data/local/tmp/flux-phase7-engine-{run_id}")),
        );
        assert!(
            !Path::new("/sys/class/net/flxrs0").exists()
                && !Path::new("/sys/class/net/flxrs1").exists(),
            "Phase 7 cleanup left a Flux veth"
        );
        println!(
            "phase7 device test: PASS (fault O(1), inactive-before-restart, stale-flow isolation, SIGKILL Direct, backoff recovery)"
        );
    }

    fn fault_generation_scenario(fluxd: &Path, package: &str, uid: u32, root: PathBuf) {
        prepare_layout(
            &root,
            package,
            &serde_json::json!({
                "outbounds": [ { "type": "direct", "tag": "direct" } ]
            }),
        );
        let fake_engine = std::env::current_exe().expect("current Phase 7 test binary");
        let mut daemon = DeviceDaemon::start(
            fluxd.to_path_buf(),
            root,
            fake_engine,
            Some((Ipv4Addr::LOCALHOST, "::1")),
        );
        let active = wait_status(&daemon, Duration::from_secs(60), |status| {
            status.state == State::Active && status.engine.sockets_verified == 4
        });
        let generation = active.generation;
        let iface = active_iface(&active);

        send_udp_fault_burst(&iface, uid, FAULT_BURST).expect("send fault burst");
        let inactive = wait_status(&daemon, Duration::from_secs(5), |status| {
            status.state == State::Inactive && status.generation == generation
        });
        assert_eq!(
            inactive.backoff_seconds, 0,
            "BPF faults restart immediately"
        );
        let recovered = wait_status(&daemon, Duration::from_secs(60), |status| {
            status.state == State::Active && status.generation > generation
        });
        assert!(recovered.generation > generation);

        let log = fs::read_to_string(daemon.root.join("fluxd.log")).expect("read fault log");
        let needle = format!(
            "BPF fault: generation={generation} family=4 protocol={} reason=1",
            libc::IPPROTO_UDP
        );
        assert_eq!(
            log.lines().filter(|line| line.contains(&needle)).count(),
            1,
            "one fault key must emit one event, not one event per packet"
        );
        daemon.stop_and_cleanup();
        println!("phase7 current-generation fault: PASS (one event, fresh generation)");
    }

    fn official_generation_scenario(
        fluxd: &Path,
        engine: &Path,
        package: &str,
        uid: u32,
        root: PathBuf,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind local responder");
        listener
            .set_nonblocking(true)
            .expect("make responder nonblocking");
        let responder_port = listener.local_addr().unwrap().port();
        prepare_layout(
            &root,
            package,
            &serde_json::json!({
                "outbounds": [ { "type": "direct", "tag": "direct" } ],
                "route": {
                    "rules": [
                        {
                            "package_name": [package],
                            "action": "route",
                            "outbound": "direct",
                            "override_address": "127.0.0.1",
                            "override_port": responder_port
                        },
                        { "action": "reject" }
                    ]
                }
            }),
        );
        let mut daemon = DeviceDaemon::start(fluxd.to_path_buf(), root, engine.to_path_buf(), None);
        let active = wait_status(&daemon, Duration::from_secs(60), |status| {
            status.state == State::Active && status.engine.sockets_verified == 4
        });
        let iface = active_iface(&active);

        let mut old_client = connect_selected(&iface, uid, Duration::from_secs(8))
            .expect("connect captured pre-switch flow");
        let mut old_server = accept_until(&listener, Duration::from_secs(8));
        round_trip(&mut old_client, &mut old_server, b"old-generation");

        let before_reload = active.generation;
        daemon.command(&["reload"]).expect("reload generation");
        let after_reload = wait_status(&daemon, Duration::from_secs(30), |status| {
            status.state == State::Active && status.generation > before_reload
        });
        assert!(after_reload.generation > before_reload);
        old_server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("old responder timeout");
        let _ = old_client.write(b"must-not-cross-generation");
        let mut old_bytes = [0u8; 64];
        assert!(
            match old_server.read(&mut old_bytes) {
                Ok(0) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::ConnectionReset
                    ) =>
                    true,
                _ => false,
            },
            "old established data reached the new generation"
        );

        let mut new_client = connect_selected(&iface, uid, Duration::from_secs(8))
            .expect("connect post-switch flow");
        let mut new_server = accept_until(&listener, Duration::from_secs(8));
        round_trip(&mut new_client, &mut new_server, b"new-generation");

        let before_kill = daemon.status().expect("status before SIGKILL");
        let engine_pid = before_kill.engine.pid.expect("promoted engine pid");
        // SAFETY: exact pid returned by this daemon's status; the daemon owns
        // and reaps it through pidfd. No process-name matching is involved.
        assert_eq!(unsafe { libc::kill(engine_pid as i32, libc::SIGKILL) }, 0);
        let backoff = wait_status(&daemon, Duration::from_secs(2), |status| {
            status.state == State::Inactive && !status.engine.running && status.backoff_seconds > 0
        });
        assert_eq!(backoff.backoff_seconds, 1);

        let mut tcp_probes = Vec::new();
        for _ in 0..DIRECT_TCP_PROBES {
            tcp_probes.push(start_tcp_probe(&iface, uid).expect("start direct TCP probe"));
        }
        send_udp_burst(&iface, uid, DIRECT_UDP_PROBES).expect("send direct UDP probes");
        let direct = wait_status(&daemon, Duration::from_secs(2), |status| {
            status.counters.direct_tcp >= before_kill.counters.direct_tcp + DIRECT_TCP_PROBES as u64
        });
        assert_eq!(
            direct.counters.admit_tcp, before_kill.counters.admit_tcp,
            "a post-SIGKILL TCP probe was admitted"
        );
        assert_eq!(
            direct.counters.admit_udp, before_kill.counters.admit_udp,
            "a post-SIGKILL UDP probe was admitted"
        );
        drop(tcp_probes);

        let recovered = wait_status(&daemon, Duration::from_secs(30), |status| {
            status.state == State::Active && status.generation > before_kill.generation
        });
        assert_eq!(recovered.backoff_seconds, 0);
        let mut recovered_client =
            connect_selected(&iface, uid, Duration::from_secs(8)).expect("connect recovered flow");
        let mut recovered_server = accept_until(&listener, Duration::from_secs(8));
        round_trip(&mut recovered_client, &mut recovered_server, b"recovered");

        daemon.stop_and_cleanup();
        println!("phase7 engine SIGKILL: PASS (all new probes Direct, generation recovered)");
    }

    struct DeviceDaemon {
        fluxd: PathBuf,
        root: PathBuf,
        engine: PathBuf,
        listen_override: Option<(Ipv4Addr, &'static str)>,
        child: Option<Child>,
        cleaned: bool,
    }

    impl DeviceDaemon {
        fn start(
            fluxd: PathBuf,
            root: PathBuf,
            engine: PathBuf,
            listen_override: Option<(Ipv4Addr, &'static str)>,
        ) -> Self {
            let child = spawn_daemon(&fluxd, &root, &engine, listen_override)
                .expect("start Phase 7 daemon");
            let daemon = Self {
                fluxd,
                root,
                engine,
                listen_override,
                child: Some(child),
                cleaned: false,
            };
            wait_for_path(
                &daemon.root.join("run/control.sock"),
                Duration::from_secs(10),
            );
            daemon
        }

        fn command(&self, args: &[&str]) -> io::Result<String> {
            let output = Command::new(&self.fluxd)
                .args(args)
                .env("FLUX_RUNTIME_ROOT", &self.root)
                .env("FLUX_MODULE_DIR", &self.root)
                .stdin(Stdio::null())
                .output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "fluxd command failed with {:?}",
                    output.status.code()
                )));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }

        fn status(&self) -> io::Result<Response> {
            let output = self.command(&["status", "--json"])?;
            serde_json::from_str(output.trim()).map_err(io::Error::other)
        }

        fn stop_and_cleanup(&mut self) {
            self.stop_best_effort();
            fs::write(self.root.join("disable"), b"").expect("create cleanup disable switch");
            let cleanup = spawn_daemon(&self.fluxd, &self.root, &self.engine, self.listen_override)
                .expect("start disabled cleanup daemon");
            self.child = Some(cleanup);
            wait_for_path(&self.root.join("run/control.sock"), Duration::from_secs(10));
            wait_status(self, Duration::from_secs(10), |status| {
                status.state == State::Disabled
            });
            self.stop_best_effort();
            assert!(
                !Path::new("/sys/class/net/flxrs0").exists()
                    && !Path::new("/sys/class/net/flxrs1").exists(),
                "disabled cleanup daemon left a Flux veth"
            );
            fs::remove_dir_all(&self.root).expect("remove private Phase 7 runtime");
            self.cleaned = true;
        }

        fn stop_best_effort(&mut self) {
            if self.child.is_none() {
                return;
            }
            let _ = self.command(&["stop"]);
            let mut child = self.child.take().expect("child checked above");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    _ => {
                        // SAFETY: spawn_daemon makes this child the leader of
                        // the exact process group containing its reactor.
                        let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
    }

    impl Drop for DeviceDaemon {
        fn drop(&mut self) {
            if self.cleaned {
                return;
            }
            self.stop_best_effort();
            if self.root.exists() {
                let _ = fs::write(self.root.join("disable"), b"");
                if let Ok(child) =
                    spawn_daemon(&self.fluxd, &self.root, &self.engine, self.listen_override)
                {
                    self.child = Some(child);
                    if wait_for_path_soft(
                        &self.root.join("run/control.sock"),
                        Duration::from_secs(3),
                    ) {
                        self.stop_best_effort();
                    }
                }
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn spawn_daemon(
        fluxd: &Path,
        root: &Path,
        engine: &Path,
        listen_override: Option<(Ipv4Addr, &'static str)>,
    ) -> io::Result<Child> {
        let mut command = Command::new(fluxd);
        command
            .arg("daemon")
            .process_group(0)
            .env("FLUX_RUNTIME_ROOT", root)
            .env("FLUX_MODULE_DIR", root)
            .env("FLUX_ENGINE_BIN", engine)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some((v4, v6)) = listen_override {
            command
                .env("FLUX_LISTEN_V4", v4.to_string())
                .env("FLUX_LISTEN_V6", v6)
                .env("FLUX_FAKE_READY_DELAY_MS", "400");
        }
        command.spawn()
    }

    fn prepare_layout(root: &Path, package: &str, engine: &serde_json::Value) {
        let _ = fs::remove_dir_all(root);
        for directory in [root.to_path_buf(), root.join("run"), root.join("config")] {
            fs::create_dir_all(&directory).expect("create private runtime directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("set private runtime mode");
        }
        let policy_path = root.join("config/flux.toml");
        fs::write(
            &policy_path,
            format!(
                "[apps]\nmode = \"whitelist\"\nlist = [\"0:{package}\"]\n\
                 [cidr]\nmode = \"blacklist\"\nlist = []\n"
            ),
        )
        .expect("write Phase 7 policy");
        let engine_path = root.join("config/template.json");
        fs::write(&engine_path, engine.to_string()).expect("write Phase 7 engine config");
        for path in [policy_path, engine_path] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("set private config mode");
        }
    }

    fn wait_status(
        daemon: &DeviceDaemon,
        timeout: Duration,
        mut predicate: impl FnMut(&Response) -> bool,
    ) -> Response {
        let deadline = Instant::now() + timeout;
        let mut last = None;
        loop {
            if let Ok(status) = daemon.status() {
                if predicate(&status) {
                    return status;
                }
                last = Some((
                    status.state,
                    status.generation,
                    status.engine.running,
                    status.engine.sockets_verified,
                    status.backoff_seconds,
                    status.last_error.clone(),
                    status
                        .ifaces
                        .iter()
                        .map(|iface| (iface.status.clone(), iface.reason.clone()))
                        .collect::<Vec<_>>(),
                ));
            }
            if Instant::now() >= deadline {
                let log_tail = fs::read_to_string(daemon.root.join("fluxd.log"))
                    .unwrap_or_default()
                    .lines()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                panic!("Phase 7 status convergence timed out: {last:?}; log={log_tail}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn active_iface(status: &Response) -> String {
        status
            .ifaces
            .iter()
            .find(|iface| iface.status == "active")
            .map(|iface| iface.name.clone())
            .expect("Phase 7 needs one active capture interface")
    }

    fn network_app() -> (String, u32) {
        let packages =
            fs::read_to_string("/data/system/packages.list").expect("read Android packages.list");
        let mut candidates = packages
            .lines()
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                let package = fields.first()?;
                let uid = fields.get(1)?.parse::<u32>().ok()?;
                let app_id = uid % USER_ID_STRIDE;
                let has_inet = fields
                    .get(5)
                    .is_some_and(|gids| gids.split(',').any(|gid| gid == "3003"));
                (has_inet && (APP_ID_MIN..=APP_ID_MAX).contains(&app_id))
                    .then(|| ((*package).to_string(), uid))
            })
            .collect::<Vec<_>>();
        assert!(
            !candidates.is_empty(),
            "Phase 7 needs one network-enabled application UID"
        );
        let index = candidates
            .iter()
            .position(|(package, _)| package == "com.android.vending")
            .unwrap_or(0);
        candidates.swap_remove(index)
    }

    fn connect_selected(iface: &str, uid: u32, timeout: Duration) -> io::Result<TcpStream> {
        let fd = socket(libc::SOCK_STREAM | libc::SOCK_NONBLOCK)?;
        prepare_owned_socket(fd.as_raw_fd(), iface, uid)?;
        let destination = sockaddr(DESTINATION, DESTINATION_PORT);
        // SAFETY: valid socket and sockaddr with its exact length.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&destination as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(io::Error::last_os_error());
        }
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one valid pollfd entry.
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout.as_millis() as i32) };
        if ready <= 0 {
            return Err(if ready == 0 {
                io::Error::new(io::ErrorKind::TimedOut, "captured connect timed out")
            } else {
                io::Error::last_os_error()
            });
        }
        let mut socket_error = 0i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: valid socket and output integer.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut i32).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
        // SAFETY: ownership moves from OwnedFd into TcpStream exactly once.
        let stream = unsafe { TcpStream::from_raw_fd(fd.into_raw_fd()) };
        stream.set_nonblocking(false)?;
        Ok(stream)
    }

    fn start_tcp_probe(iface: &str, uid: u32) -> io::Result<OwnedFd> {
        let fd = socket(libc::SOCK_STREAM | libc::SOCK_NONBLOCK)?;
        prepare_owned_socket(fd.as_raw_fd(), iface, uid)?;
        let destination = sockaddr(DESTINATION, DESTINATION_PORT);
        // SAFETY: valid socket and sockaddr with its exact length.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&destination as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if !error
                .raw_os_error()
                .is_some_and(|code| code == libc::EINPROGRESS || code == libc::EALREADY)
            {
                return Err(error);
            }
        }
        Ok(fd)
    }

    fn send_udp_burst(iface: &str, uid: u32, count: usize) -> io::Result<()> {
        send_udp_packets(iface, uid, count, false)
    }

    fn send_udp_fault_burst(iface: &str, uid: u32, count: usize) -> io::Result<()> {
        send_udp_packets(iface, uid, count, true)
    }

    fn send_udp_packets(
        iface: &str,
        uid: u32,
        count: usize,
        accept_tc_drop: bool,
    ) -> io::Result<()> {
        let fd = socket(libc::SOCK_DGRAM)?;
        prepare_owned_socket(fd.as_raw_fd(), iface, uid)?;
        let destination = sockaddr(DESTINATION, DESTINATION_PORT);
        for sequence in 0..count {
            let payload = (sequence as u64).to_ne_bytes();
            // SAFETY: valid socket, payload and sockaddr.
            let sent = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                    (&destination as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if !accept_tc_drop || error.raw_os_error() != Some(libc::EPERM) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn socket(kind: i32) -> io::Result<OwnedFd> {
        // SAFETY: plain AF_INET socket creation.
        let fd = unsafe { libc::socket(libc::AF_INET, kind | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful socket returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn prepare_owned_socket(fd: RawFd, iface: &str, uid: u32) -> io::Result<()> {
        let iface = CString::new(iface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in interface"))?;
        // SAFETY: valid socket and NUL-terminated interface name.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface.as_ptr().cast(),
                iface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: valid socket; changing the socket inode owner is the same
        // Android test mechanism already used by the Phase 6 acceptance test.
        if unsafe { libc::fchown(fd, uid, u32::MAX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn sockaddr(address: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    fn accept_until(listener: &TcpListener, timeout: Duration) -> TcpStream {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "local responder accept timed out"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("local responder accept failed: {error}"),
            }
        }
    }

    fn round_trip(client: &mut TcpStream, server: &mut TcpStream, payload: &[u8]) {
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client read timeout");
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("server read timeout");
        client.write_all(payload).expect("write app payload");
        let mut received = vec![0u8; payload.len()];
        server
            .read_exact(&mut received)
            .expect("read routed payload");
        assert_eq!(received, payload);
        server.write_all(payload).expect("write responder payload");
        let mut reply = vec![0u8; payload.len()];
        client.read_exact(&mut reply).expect("read routed reply");
        assert_eq!(reply, payload);
    }

    fn wait_for_path(path: &Path, timeout: Duration) {
        assert!(
            wait_for_path_soft(path, timeout),
            "daemon control socket timed out"
        );
    }

    fn wait_for_path_soft(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        path.exists()
    }
}
