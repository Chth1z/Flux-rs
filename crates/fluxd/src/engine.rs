//! sing-box supervision: effective config, `check`, spawn, readiness, the
//! §9.4 candidate switch and graceful stop.
//!
//! The engine is the **unmodified official asset** pinned by `engine.lock`;
//! Flux never patches it (blueprint §3.8, D19).
//!
//! Two ordering rules that are load-bearing, not style:
//!
//! * On a candidate switch the current generation file is **never renamed and
//!   never overwritten**, so step 6 can always restart the old generation from
//!   the exact bytes it was checked against (§9.4).
//! * In later phases, `active = 0` is published **before** the old child is
//!   terminated: kernels below 6.5 lack the unhashed-socket rejection in
//!   `bpf_sk_assign()`, so ingress must stop assigning before the listener can
//!   go away (§9.2, §9.4). Phase 2 has no data plane, so those reactor
//!   transaction publish points are documented no-ops; their order is final.
//!
//! Liveness is pidfd only. There is no heartbeat, no polling of any kind; the
//! bounded readiness backoff exists only during candidate startup and dies
//! with the reactor transaction (§9.5).

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flux_core::abi::{LISTEN_PORT_MAX, LISTEN_PORT_MIN, LISTEN_V4_STR, LISTEN_V6_STR};
#[cfg(test)]
use flux_core::engine_config::build_effective;
use flux_core::engine_config::{EngineConfigError, EngineParams};

use crate::layout::Layout;
use crate::netlink::sock_diag::{find_inode, pid_owns_inode, SocketExpectation};

/// Grace period between `SIGTERM` and `SIGKILL` on a normal stop (§9.4 step 3).
pub const TERMINATE_GRACE: Duration = Duration::from_secs(3);

/// Total readiness deadline for the four listener sockets (§9.5).
pub const READY_DEADLINE: Duration = Duration::from_secs(5);

/// Deadline for one `sing-box check -c` run. The check is a short-lived local
/// parse; crossing this means the engine binary is wedged, not slow.
pub const CHECK_DEADLINE: Duration = Duration::from_secs(15);

/// Bytes of engine output retained for diagnostics (per run).
const OUTPUT_CAP: usize = 64 * 1024;

/// One asynchronously supervised `sing-box check -c` process.
///
/// The daemon registers [`pidfd`](Self::pidfd) and
/// [`output_fd`](Self::output_fd) in epoll. Tests and the standalone `check`
/// command may instead drive [`finish`](Self::finish) in a bounded loop.
#[derive(Debug)]
pub struct EngineCheck {
    child: std::process::Child,
    pidfd: OwnedFd,
    output: OwnedFd,
    captured: Vec<u8>,
}

impl EngineCheck {
    /// The pidfd whose readability means the check process exited.
    pub fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }

    /// The non-blocking merged stdout/stderr pipe.
    pub fn output_fd(&self) -> RawFd {
        self.output.as_raw_fd()
    }

    /// Drains currently available output without waiting.
    pub fn drain_output(&mut self) {
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: `output` is a valid non-blocking fd and `chunk` is a
            // valid writable buffer for the duration of the call.
            let n = unsafe {
                libc::read(
                    self.output.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if n > 0 {
                if self.captured.len() < OUTPUT_CAP {
                    let n = n as usize;
                    let keep = n.min(OUTPUT_CAP - self.captured.len());
                    self.captured.extend_from_slice(&chunk[..keep]);
                }
                continue;
            }
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }

    /// Returns `None` while the process is live, otherwise reaps it and
    /// returns the completed check result. This method never waits for exit.
    pub fn finish(&mut self) -> Result<Option<Result<(), EngineError>>, EngineError> {
        self.drain_output();
        let status = match self.child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => return Ok(None),
            // Another wait path cannot exist in the single-threaded daemon,
            // but ECHILD still means there is nothing left to reap and must
            // not strand the transaction forever.
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                return Ok(Some(Err(EngineError::Io(e))))
            }
            Err(e) => return Err(EngineError::Io(e)),
        };
        self.drain_output();
        if status.success() {
            Ok(Some(Ok(())))
        } else {
            Ok(Some(Err(EngineError::CheckFailed {
                exit: describe_exit(status),
                output_head: head_lines(&self.captured, 8),
            })))
        }
    }

    /// Sends SIGKILL to a still-running check. Reaping remains event-driven
    /// through [`finish`](Self::finish).
    pub fn kill(&mut self) -> io::Result<()> {
        match self.child.kill() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Builds the stable timeout result from output captured so far.
    pub fn timeout_error(&mut self) -> EngineError {
        self.drain_output();
        EngineError::CheckFailed {
            exit: "timeout".to_string(),
            output_head: head_lines(&self.captured, 8),
        }
    }
}

/// How the engine is launched and which sockets prove it ready.
///
/// Production uses the ABI listener addresses; tests substitute loopback so a
/// fake engine can bind without `IP_TRANSPARENT` root privileges. This is
/// parameterisation of the same code path, not a second implementation.
#[derive(Debug, Clone)]
pub struct EngineSpec {
    /// The official sing-box binary.
    pub binary: PathBuf,
    /// Working directory for the child (relative engine paths land here).
    pub workdir: PathBuf,
    /// IPv4 listener address the readiness check expects.
    pub listen_v4: Ipv4Addr,
    /// IPv6 listener address the readiness check expects.
    pub listen_v6: Ipv6Addr,
}

/// Environment overrides for the listener addresses. Test hooks with the same
/// status as [`crate::layout::RUNTIME_ROOT_ENV`]: they let an integration test
/// run the full daemon with a fake engine bound to loopback, where binding the
/// ABI 198.18/16 addresses would need root. Production never sets them.
pub const LISTEN_V4_ENV: &str = "FLUX_LISTEN_V4";
/// IPv6 counterpart of [`LISTEN_V4_ENV`].
pub const LISTEN_V6_ENV: &str = "FLUX_LISTEN_V6";

impl EngineSpec {
    /// The production spec: module-shipped binary, ABI listener addresses
    /// (loopback overrides honoured only via the documented test hooks).
    pub fn product(layout: &Layout) -> Self {
        let listen_v4 = std::env::var(LISTEN_V4_ENV)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| LISTEN_V4_STR.parse().expect("abi constant parses"));
        let listen_v6 = std::env::var(LISTEN_V6_ENV)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| LISTEN_V6_STR.parse().expect("abi constant parses"));
        Self {
            binary: layout.engine_binary(),
            workdir: layout.root().to_path_buf(),
            listen_v4,
            listen_v6,
        }
    }

    fn expectations(&self, params: &EngineParams) -> [SocketExpectation; 4] {
        [
            SocketExpectation {
                protocol: libc::IPPROTO_TCP as u8,
                addr: IpAddr::V4(self.listen_v4),
                port: params.port_v4,
            },
            SocketExpectation {
                protocol: libc::IPPROTO_UDP as u8,
                addr: IpAddr::V4(self.listen_v4),
                port: params.port_v4,
            },
            SocketExpectation {
                protocol: libc::IPPROTO_TCP as u8,
                addr: IpAddr::V6(self.listen_v6),
                port: params.port_v6,
            },
            SocketExpectation {
                protocol: libc::IPPROTO_UDP as u8,
                addr: IpAddr::V6(self.listen_v6),
                port: params.port_v6,
            },
        ]
    }
}

/// A running (or just-exited, not yet reaped) sing-box child.
#[derive(Debug)]
pub struct EngineChild {
    pub pid: i32,
    /// Exact process identity; all signals go through `pidfd_send_signal`, so
    /// pid reuse can never kill a stranger (§13.3).
    pub pidfd: OwnedFd,
    /// `starttime` from `/proc/<pid>/stat` field 22, the second half of the
    /// `(pid, starttime)` composite identity (§13.3).
    pub start_time: u64,
    /// Becomes true only after `/proc/<pid>/exe` resolves to the configured
    /// engine binary. Spawn returns before exec completes, so readiness owns
    /// this final identity check.
    pub identity_verified: bool,
    pub params: EngineParams,
    /// The immutable generation file this child was started from.
    pub effective: PathBuf,
    /// Non-blocking read end of the child's merged stdout+stderr (§13.3
    /// requires capturing it; the reactor drains it into the log).
    pub output: OwnedFd,
    /// When the child was spawned; used only for the crash-backoff reset.
    pub spawned_at: Instant,
    /// How many of the four sockets the last readiness pass verified.
    pub sockets_verified: u8,
}

/// Why an engine operation failed. `token()` yields the stable §24.2
/// identifier; free-text detail belongs in `warnings`.
#[derive(Debug)]
pub enum EngineError {
    BinaryMissing(PathBuf),
    ConfigInvalid(EngineConfigError),
    WriteEffective(io::Error),
    CheckFailed { exit: String, output_head: String },
    SpawnFailed(String),
    Exited { exit: String, output_head: String },
    NotReady { verified: u8 },
    SocketOwnerMismatch { inode: u32 },
    Io(io::Error),
}

impl EngineError {
    /// The stable error token (§23.1, §24.2).
    pub fn token(&self) -> String {
        match self {
            EngineError::BinaryMissing(path) => {
                format!("engine_binary_missing:{}", path.display())
            }
            EngineError::ConfigInvalid(_) => "engine_config_invalid".to_string(),
            EngineError::CheckFailed { .. } => "engine_check_failed".to_string(),
            EngineError::SpawnFailed(_) => "engine_spawn_failed".to_string(),
            EngineError::Exited { exit, .. } => format!("engine_exited:{exit}"),
            EngineError::NotReady { verified } => {
                format!("engine_not_ready:{verified}/4 sockets")
            }
            EngineError::SocketOwnerMismatch { .. } => "engine_socket_owner_mismatch".to_string(),
            EngineError::WriteEffective(_) | EngineError::Io(_) => "engine_io_error".to_string(),
        }
    }

    /// Free-text context for the warnings channel.
    pub fn detail(&self) -> Option<String> {
        match self {
            EngineError::ConfigInvalid(e) => Some(describe_config_error(e)),
            EngineError::CheckFailed { exit, output_head } => Some(if output_head.is_empty() {
                format!("check exited with {exit}")
            } else {
                format!("check exited with {exit}: {output_head}")
            }),
            EngineError::Exited { output_head, .. } => {
                (!output_head.is_empty()).then(|| output_head.clone())
            }
            EngineError::SpawnFailed(detail) => Some(detail.clone()),
            EngineError::SocketOwnerMismatch { inode } => Some(format!(
                "socket inode {inode} is not held by the candidate pid"
            )),
            EngineError::WriteEffective(e) | EngineError::Io(e) => Some(e.to_string()),
            EngineError::BinaryMissing(_) | EngineError::NotReady { .. } => None,
        }
    }
}

pub fn describe_config_error(e: &EngineConfigError) -> String {
    match e {
        EngineConfigError::NotAnObject => "sing-box.json is not a JSON object".to_string(),
        EngineConfigError::UserSuppliedInbound => {
            "sing-box.json declares its own inbounds; Flux injects the only two (blueprint §9.1)"
                .to_string()
        }
        EngineConfigError::InboundsNotArray => "`inbounds` is not an array".to_string(),
        EngineConfigError::ReservedTag(tag) => {
            format!("tag `{tag}` uses the reserved `flux-` prefix (blueprint §9.6)")
        }
    }
}

/// Two distinct random listener ports from the §9.1 range, above Android's
/// ephemeral range. Ports are collision avoidance, never identity.
///
/// Keep a TCP and UDP wildcard reservation for each family while choosing the
/// pair. The sockets are dropped before sing-box starts, so this cannot remove
/// the final bind race, but it avoids selecting a port already occupied by
/// either protocol (the previous random-only draw made that a flaky startup).
pub fn draw_ports() -> io::Result<(u16, u16)> {
    let v4 = reserve_random_port(IpAddr::V4(Ipv4Addr::UNSPECIFIED), None)?;
    let v6 = reserve_random_port(IpAddr::V6(Ipv6Addr::UNSPECIFIED), Some(v4.port))?;
    Ok((v4.port, v6.port))
}

const PORT_DRAW_ATTEMPTS: usize = 128;

struct PortReservation {
    port: u16,
    _tcp: TcpListener,
    _udp: UdpSocket,
}

impl PortReservation {
    fn bind(address: IpAddr, port: u16) -> io::Result<Self> {
        let tcp = TcpListener::bind((address, port))?;
        let udp = UdpSocket::bind((address, port))?;
        Ok(Self {
            port,
            _tcp: tcp,
            _udp: udp,
        })
    }
}

fn reserve_random_port(address: IpAddr, excluded: Option<u16>) -> io::Result<PortReservation> {
    let mut last_collision = None;
    for _ in 0..PORT_DRAW_ATTEMPTS {
        let port = draw_port()?;
        if excluded == Some(port) {
            continue;
        }
        match PortReservation::bind(address, port) {
            Ok(reservation) => return Ok(reservation),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "could not reserve a distinct listener port",
        )
    }))
}

fn draw_port() -> io::Result<u16> {
    let span = (LISTEN_PORT_MAX - LISTEN_PORT_MIN) as u32 + 1;
    // Rejection sampling for a uniform draw without modulo bias.
    let limit = (u32::from(u16::MAX) + 1) / span * span;
    loop {
        let mut bytes = [0u8; 2];
        // SAFETY: the buffer is valid for its length; getrandom fills it.
        let rc = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), 2, 0) };
        if rc != 2 {
            return Err(io::Error::last_os_error());
        }
        let draw = u32::from(u16::from_ne_bytes(bytes));
        if draw < limit {
            return Ok(LISTEN_PORT_MIN + (draw % span) as u16);
        }
    }
}

/// §9.4 step 1: writes `run/sing-box.<generation>.json` with
/// `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, and fsyncs both the file and its
/// directory. The path is immutable for the life of the generation.
pub fn write_effective(
    layout: &Layout,
    effective: &serde_json::Value,
    generation: u64,
) -> Result<PathBuf, EngineError> {
    let path = layout.effective_path(generation);
    let bytes = serde_json::to_vec_pretty(effective)
        .map_err(|e| EngineError::WriteEffective(io::Error::new(io::ErrorKind::InvalidData, e)))?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)
        .map_err(EngineError::WriteEffective)?;

    let write_and_sync = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        let dir = fs::File::open(layout.run_dir())?;
        dir.sync_all()
    })();
    if let Err(e) = write_and_sync {
        let _ = fs::remove_file(&path);
        return Err(EngineError::WriteEffective(e));
    }
    Ok(path)
}

/// Starts §9.4 step 1's `sing-box check -c <exact path>` subprocess with a
/// pidfd and one non-blocking merged output pipe.
pub fn spawn_check(binary: &Path, config: &Path) -> Result<EngineCheck, EngineError> {
    if !binary.exists() {
        return Err(EngineError::BinaryMissing(binary.to_path_buf()));
    }
    let (output, writer) = pipe2_cloexec().map_err(EngineError::Io)?;
    let stdout = fs::File::from(writer);
    let stderr = stdout.try_clone().map_err(EngineError::Io)?;
    let mut child = std::process::Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(config)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|e| EngineError::SpawnFailed(format!("{}: {e}", binary.display())))?;

    let pid = i32::try_from(child.id()).map_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
        EngineError::SpawnFailed("check pid does not fit i32".to_string())
    })?;
    let pidfd = pidfd_open(pid).map_err(|e| {
        let _ = child.kill();
        let _ = child.wait();
        EngineError::Io(e)
    })?;
    set_nonblocking(output.as_raw_fd());
    Ok(EngineCheck {
        child,
        pidfd,
        output,
        captured: Vec::new(),
    })
}

/// Runs a check to completion for CLI/tests. The daemon uses
/// [`spawn_check`] directly so its reactor never sleeps or waits.
pub fn run_check(binary: &Path, config: &Path) -> Result<(), EngineError> {
    let mut check = spawn_check(binary, config)?;
    let deadline = Instant::now() + CHECK_DEADLINE;
    loop {
        if let Some(result) = check.finish()? {
            return result;
        }
        if Instant::now() >= deadline {
            let timeout = check.timeout_error();
            check.kill().map_err(EngineError::Io)?;
            while check.finish()?.is_none() {
                std::thread::sleep(Duration::from_millis(1));
            }
            return Err(timeout);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn describe_exit(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("code={code}"),
        (None, Some(sig)) => format!("signal={sig}"),
        (None, None) => "unknown".to_string(),
    }
}

fn head_lines(bytes: &[u8], n: usize) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .take(n)
        .collect::<Vec<_>>()
        .join("\n")
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fcntl F_GETFL/F_SETFL on a valid fd owned by the caller.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// pipe2(O_CLOEXEC): (read end, write end). CLOEXEC on both ends so the child
/// leaks neither across exec; the ends the child needs are dup2'd (which
/// clears CLOEXEC on the copy) before execve.
fn pipe2_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-element array for the duration of the call.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds were just returned by the kernel and are owned nowhere else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// §9.4 step 4: fork/exec the candidate in the fixed §13.3 order — restore
/// signal dispositions, `setsid()`, clear supplementary groups,
/// `PR_SET_PDEATHSIG(SIGKILL)`, re-check the parent pid, prepare fds, `execve`.
///
/// `PDEATHSIG` is `SIGKILL`, not `SIGTERM`: after an abnormal fluxd death
/// nobody is left to run a graceful deadline, and the engine owns no kernel
/// state that needs cleanup — its listeners vanishing immediately is exactly
/// the fail-open behaviour §2.2.1 wants.
pub fn spawn(
    spec: &EngineSpec,
    effective: &Path,
    params: EngineParams,
) -> Result<EngineChild, EngineError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if !spec.binary.exists() {
        return Err(EngineError::BinaryMissing(spec.binary.clone()));
    }

    // Everything the child needs, allocated before fork.
    let binary = CString::new(spec.binary.as_os_str().as_bytes())
        .map_err(|_| EngineError::SpawnFailed("binary path contains NUL".to_string()))?;
    let config = CString::new(effective.as_os_str().as_bytes())
        .map_err(|_| EngineError::SpawnFailed("config path contains NUL".to_string()))?;
    let workdir = CString::new(spec.workdir.as_os_str().as_bytes())
        .map_err(|_| EngineError::SpawnFailed("workdir contains NUL".to_string()))?;
    let arg_run = CString::new("run").unwrap();
    let arg_c = CString::new("-c").unwrap();
    let argv: [*const libc::c_char; 5] = [
        binary.as_ptr(),
        arg_run.as_ptr(),
        arg_c.as_ptr(),
        config.as_ptr(),
        std::ptr::null(),
    ];

    let (out_read, out_write) = pipe2_cloexec().map_err(EngineError::Io)?;
    let devnull = fs::OpenOptions::new()
        .read(true)
        .open("/dev/null")
        .map_err(EngineError::Io)?;

    // SAFETY: getpid has no preconditions and cannot fail.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: fluxd is single-threaded (blueprint §10.4), so fork() does not
    // strand any lock; the child calls only async-signal-safe functions plus
    // execve, with all allocations done above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(EngineError::Io(io::Error::last_os_error()));
    }

    if pid == 0 {
        // === child ===
        // SAFETY: only async-signal-safe calls until execve/_exit.
        unsafe {
            // 1. Restore signal dispositions (SIGKILL/SIGSTOP cannot change)
            //    and unblock everything the daemon's signalfd mask blocked.
            for sig in 1..=31 {
                if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                    libc::signal(sig, libc::SIG_DFL);
                }
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());

            // 2. Own session and process group, so the group can be signalled.
            if libc::setsid() < 0 {
                report_exec_failure(out_write.as_raw_fd());
            }

            // 3. Clear supplementary groups. EPERM (not root, e.g. host
            //    tests) is tolerable: there is nothing to drop then.
            if libc::setgroups(0, std::ptr::null()) != 0 && libc::geteuid() == 0 {
                report_exec_failure(out_write.as_raw_fd());
            }

            // 4. Die with the parent, immediately.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                libc::_exit(125);
            }

            // 5. Close the window where the parent died before PDEATHSIG
            //    took effect.
            if libc::getppid() != parent_pid {
                libc::_exit(124);
            }

            // 6. Prepare fds: stdin /dev/null, stdout+stderr into the pipe.
            if libc::chdir(workdir.as_ptr()) != 0 {
                report_exec_failure(out_write.as_raw_fd());
            }
            if libc::dup2(devnull.as_raw_fd(), 0) < 0
                || libc::dup2(out_write.as_raw_fd(), 1) < 0
                || libc::dup2(out_write.as_raw_fd(), 2) < 0
            {
                report_exec_failure(out_write.as_raw_fd());
            }

            // 7. execve. All our other fds are CLOEXEC.
            libc::execv(binary.as_ptr(), argv.as_ptr());
            report_exec_failure(out_write.as_raw_fd());
        }
        // `report_exec_failure` never returns; this is unreachable.
    }

    // === parent ===
    drop(out_write);
    drop(devnull);

    let pidfd = pidfd_open(pid).map_err(|e| {
        // Exec already succeeded but we cannot supervise without a pidfd.
        // Killing by pid is safe here: the child is not reaped yet, so the
        // pid cannot have been reused.
        // SAFETY: plain kill(2) on our own unreaped child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reap_and_ignore(pid);
        EngineError::Io(e)
    })?;
    let start_time = match proc_start_time(pid).filter(|time| *time != 0) {
        Some(start_time) => start_time,
        None => {
            let _ = pidfd_kill(&pidfd, libc::SIGKILL);
            reap_and_ignore(pid);
            return Err(EngineError::SpawnFailed(
                "child has no usable /proc starttime".to_string(),
            ));
        }
    };
    set_nonblocking(out_read.as_raw_fd());

    Ok(EngineChild {
        pid,
        pidfd,
        start_time,
        identity_verified: false,
        params,
        effective: effective.to_path_buf(),
        output: out_read,
        spawned_at: Instant::now(),
        sockets_verified: 0,
    })
}

/// Writes a fixed diagnostic and `_exit(126)`. Child-side only; formatting or
/// allocation after fork would not be async-signal-safe.
unsafe fn report_exec_failure(output_fd: RawFd) -> ! {
    const MESSAGE: &[u8] = b"fluxd: child setup or exec failed\n";
    // SAFETY: write(2) is async-signal-safe; the fd is the held pipe end.
    unsafe {
        libc::write(output_fd, MESSAGE.as_ptr().cast(), MESSAGE.len());
        libc::_exit(126);
    }
}

fn reap_and_ignore(pid: i32) {
    // SAFETY: waitpid on our own child; WNOHANG in a short loop.
    unsafe {
        let mut status = 0;
        for _ in 0..100 {
            let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if rc != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// pidfd_open(2). Available since 5.3; the kernel floor is 5.15 (§1.1).
fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: raw syscall with valid arguments; the fd is immediately owned.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned by the kernel, not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// pidfd_send_signal(2): signals the exact process the fd refers to, so pid
/// reuse can never make us kill a stranger (§13.3).
fn pidfd_kill(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: raw syscall; null siginfo means the kernel builds SI_USER info.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::c_void>(),
            0u32,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        // ESRCH: already gone. That is the goal state, not an error.
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Sends a signal to the exact child identity through its pidfd.
pub fn signal(child: &EngineChild, signal: i32) -> io::Result<()> {
    pidfd_kill(&child.pidfd, signal)
}

/// Whether the pidfd reports the process as exited (readable).
pub fn has_exited(pidfd: &OwnedFd) -> bool {
    poll_readable(pidfd.as_raw_fd(), Duration::ZERO)
}

fn poll_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is valid for the duration of the call.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

/// `starttime` (field 22) from `/proc/<pid>/stat`, located from the LAST `)`
/// because comm may itself contain parentheses (§13.3). `Z`/`X` states are
/// rejected: a zombie is not a usable identity.
pub fn proc_start_time(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_ascii_whitespace();
    let state = fields.next()?;
    if state == "Z" || state == "X" {
        return None;
    }
    // `state` was field 3; starttime is field 22 → 19 fields further on.
    fields.nth(18)?.parse().ok()
}

pub fn verify_process_identity(child: &mut EngineChild, spec: &EngineSpec) -> io::Result<bool> {
    if child.identity_verified {
        return Ok(true);
    }
    let current_start = proc_start_time(child.pid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("/proc/{}/stat is unavailable", child.pid),
        )
    })?;
    if current_start == 0 || current_start != child.start_time {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "child identity changed: starttime {} != {}",
                current_start, child.start_time
            ),
        ));
    }
    let actual = fs::read_link(format!("/proc/{}/exe", child.pid))?;
    let expected = fs::canonicalize(&spec.binary)?;
    if actual != expected {
        // `spawn` intentionally returns before the child reaches execve. The
        // first readiness tick may still see fluxd as /proc/<pid>/exe; keep
        // waiting, but never count a socket until the exact binary matches.
        return Ok(false);
    }
    child.identity_verified = true;
    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Pending { verified: u8 },
    Ready,
}

/// One non-blocking readiness pass. The reactor drives repeated passes from a
/// timerfd; no sleep or poll occurs here.
pub fn probe_ready(child: &mut EngineChild, spec: &EngineSpec) -> Result<Readiness, EngineError> {
    if has_exited(&child.pidfd) {
        let exit = reap(child);
        return Err(EngineError::Exited {
            exit,
            output_head: drain_output_head(child),
        });
    }
    if !verify_process_identity(child, spec).map_err(EngineError::Io)? {
        return Ok(Readiness::Pending { verified: 0 });
    }

    let expectations = spec.expectations(&child.params);
    let mut verified = 0u8;
    let mut all_present = true;
    for exp in &expectations {
        match find_inode(exp).map_err(EngineError::Io)? {
            Some(inode) => match pid_owns_inode(child.pid, inode) {
                Ok(true) => verified += 1,
                Ok(false) => return Err(EngineError::SocketOwnerMismatch { inode }),
                Err(e) => return Err(EngineError::Io(e)),
            },
            None => all_present = false,
        }
    }
    child.sockets_verified = verified;
    if all_present && verified == 4 {
        Ok(Readiness::Ready)
    } else {
        Ok(Readiness::Pending { verified })
    }
}

/// §9.5: waits for the four exact sockets with a 10/20/40… ms backoff capped
/// at 250 ms and a hard total deadline. Every found inode is cross-checked
/// against `/proc/<pid>/fd`. This is not steady-state polling — it exists only
/// between spawn and ready/failed, then stops forever.
#[cfg(test)]
#[allow(dead_code)] // Used by the path-included Linux integration harness.
pub fn wait_ready(child: &mut EngineChild, spec: &EngineSpec) -> Result<(), EngineError> {
    let deadline = Instant::now() + READY_DEADLINE;
    let mut backoff = Duration::from_millis(10);
    loop {
        let verified = match probe_ready(child, spec)? {
            Readiness::Ready => return Ok(()),
            Readiness::Pending { verified } => verified,
        };
        if Instant::now() + backoff > deadline {
            return Err(EngineError::NotReady { verified });
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(250));
    }
}

/// Drains whatever the child has written so far, for error context.
pub fn drain_output_head(child: &mut EngineChild) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: valid fd and buffer; the fd is non-blocking.
        let n = unsafe {
            libc::read(
                child.output.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len(),
            )
        };
        if n <= 0 || buf.len() >= OUTPUT_CAP {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    head_lines(&buf, 8)
}

fn reap(child: &EngineChild) -> String {
    // SAFETY: waitpid on our own child after pidfd reported exit.
    unsafe {
        let mut status = 0;
        let rc = libc::waitpid(child.pid, &mut status, 0);
        if rc != child.pid {
            return "unknown".to_string();
        }
        if libc::WIFEXITED(status) {
            format!("code={}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal={}", libc::WTERMSIG(status))
        } else {
            "unknown".to_string()
        }
    }
}

/// Normal termination: `SIGTERM` → grace deadline → `SIGKILL`, exit confirmed
/// via pidfd, child reaped (§9.4 step 3). Returns the exit description.
pub fn terminate(child: &EngineChild, grace: Duration) -> io::Result<String> {
    if !has_exited(&child.pidfd) {
        pidfd_kill(&child.pidfd, libc::SIGTERM)?;
        if !poll_readable(child.pidfd.as_raw_fd(), grace) {
            pidfd_kill(&child.pidfd, libc::SIGKILL)?;
            if !poll_readable(child.pidfd.as_raw_fd(), Duration::from_secs(2)) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child survived SIGKILL confirmation window",
                ));
            }
        }
    }
    Ok(reap(child))
}

/// The outcome of one §9.4 transaction.
#[cfg(test)]
#[allow(dead_code)] // Used by the path-included Linux integration harness.
pub struct GenerationOutcome {
    /// The running engine after the transaction: the promoted candidate, the
    /// recovered old generation, or `None`.
    pub engine: Option<EngineChild>,
    /// The candidate's fate. `Ok` means the candidate was promoted.
    pub result: Result<(), EngineError>,
    /// The step-6 recovery result, when recovery was attempted.
    pub recovery: Option<Result<(), EngineError>>,
    /// Free-text events for the daemon log.
    pub log: Vec<String>,
}

/// §9.4, the six-step generation transaction — the ONLY way an engine is ever
/// started or replaced. `current == None` makes it the cold-start case.
///
/// Publish points (steps 2, 4-latch, 5) are no-ops until the data plane exists
/// (Phase 4+); their positions in the sequence are already final.
#[cfg(test)]
#[allow(dead_code)] // Used by the path-included Linux integration harness.
pub fn run_generation_switch(
    layout: &Layout,
    spec: &EngineSpec,
    user: &serde_json::Value,
    current: Option<EngineChild>,
    generation: u64,
) -> GenerationOutcome {
    let mut log = Vec::new();

    // ---- step 1: candidate params, immutable effective file, engine check.
    // Any failure here leaves the current engine COMPLETELY untouched.
    let (port_v4, port_v6) = match draw_ports() {
        Ok(ports) => ports,
        Err(e) => {
            return GenerationOutcome {
                engine: current,
                result: Err(EngineError::Io(e)),
                recovery: None,
                log,
            }
        }
    };
    let params = EngineParams {
        generation,
        port_v4,
        port_v6,
    };
    let effective_json = match build_effective(user, &params) {
        Ok(v) => v,
        Err(e) => {
            return GenerationOutcome {
                engine: current,
                result: Err(EngineError::ConfigInvalid(e)),
                recovery: None,
                log,
            }
        }
    };
    let candidate_path = match write_effective(layout, &effective_json, generation) {
        Ok(p) => p,
        Err(e) => {
            return GenerationOutcome {
                engine: current,
                result: Err(e),
                recovery: None,
                log,
            }
        }
    };
    if let Err(e) = run_check(&spec.binary, &candidate_path) {
        // Only the candidate file is deleted; the current engine is not
        // touched in any way (§9.4 step 1).
        let _ = fs::remove_file(&candidate_path);
        return GenerationOutcome {
            engine: current,
            result: Err(e),
            recovery: None,
            log,
        };
    }
    log.push(format!(
        "generation {generation}: candidate checked (ports {port_v4}/{port_v6})"
    ));

    // ---- step 2: keep the current leaf and generation file; publish the
    // same-generation `active=0` leaf. No data plane yet: no-op by design.

    // ---- step 3: terminate the old child. Its generation file is never
    // renamed or overwritten, so step 6 can restart from it byte-identically.
    let old = match current {
        None => None,
        Some(old_child) => {
            let old_params = old_child.params;
            let old_path = old_child.effective.clone();
            match terminate(&old_child, TERMINATE_GRACE) {
                Ok(exit) => {
                    log.push(format!(
                        "generation {}: old engine stopped ({exit})",
                        old_params.generation
                    ));
                    Some((old_params, old_path))
                }
                Err(e) => {
                    log.push(format!(
                        "generation {}: old engine termination error: {e}; candidate not started",
                        old_params.generation
                    ));
                    let _ = fs::remove_file(&candidate_path);
                    return GenerationOutcome {
                        // Keep ownership even when termination is uncertain.
                        // Starting a candidate here would violate the one-engine invariant.
                        engine: Some(old_child),
                        result: Err(EngineError::Io(e)),
                        recovery: None,
                        log,
                    };
                }
            }
        }
    };

    // ---- step 4: clear fault_latch while inactive (no-op, Phase 4+); start
    // the candidate; verify the four sockets by PID + inode.
    let candidate_result = match spawn(spec, &candidate_path, params) {
        Err(e) => Err(e),
        Ok(mut child) => match wait_ready(&mut child, spec) {
            Ok(()) => Ok(child),
            Err(e @ EngineError::Exited { .. }) => Err(e),
            Err(e) => match terminate(&child, TERMINATE_GRACE) {
                Ok(exit) => {
                    log.push(format!(
                        "generation {generation}: unready candidate stopped ({exit})"
                    ));
                    Err(e)
                }
                Err(stop_error) => {
                    log.push(format!(
                        "generation {generation}: unready candidate could not be stopped: \
                         {stop_error}; recovery suppressed"
                    ));
                    let _ = fs::remove_file(&candidate_path);
                    return GenerationOutcome {
                        engine: Some(child),
                        result: Err(e),
                        recovery: Some(Err(EngineError::Io(stop_error))),
                        log,
                    };
                }
            },
        },
    };

    match candidate_result {
        Ok(child) => {
            // ---- step 5: freeze + publish active=1 and the single
            // control_root pointer swap — THE commit point (no-op until the
            // data plane exists). Afterwards the old generation file is
            // deleted best-effort; a deletion failure is a control-plane
            // error only and never rolls back the committed switch.
            log.push(format!(
                "generation {generation}: 4/4 sockets verified by pid+inode, promoted \
                 (pid {}, starttime {})",
                child.pid, child.start_time
            ));
            if let Some((old_params, old_path)) = old {
                if let Err(e) = fs::remove_file(&old_path) {
                    if e.kind() != io::ErrorKind::NotFound {
                        log.push(format!(
                            "generation {}: old file not deleted: {e} (not rolled back)",
                            old_params.generation
                        ));
                    }
                }
            }
            GenerationOutcome {
                engine: Some(child),
                result: Ok(()),
                recovery: None,
                log,
            }
        }
        Err(candidate_err) => {
            // ---- step 6: stop the failed candidate, restart the old
            // generation from its untouched file, and re-verify its sockets.
            log.push(format!(
                "generation {generation}: candidate failed: {}",
                candidate_err.token()
            ));
            let _ = fs::remove_file(&candidate_path);
            let (engine, recovery) = match old {
                None => (None, None),
                Some((old_params, old_path)) => {
                    let recovered = match spawn(spec, &old_path, old_params) {
                        Err(e) => Err(e),
                        Ok(mut child) => match wait_ready(&mut child, spec) {
                            Ok(()) => Ok(child),
                            Err(e @ EngineError::Exited { .. }) => Err(e),
                            Err(e) => match terminate(&child, TERMINATE_GRACE) {
                                Ok(exit) => {
                                    log.push(format!(
                                        "generation {}: unready recovery stopped ({exit})",
                                        old_params.generation
                                    ));
                                    Err(e)
                                }
                                Err(stop_error) => {
                                    log.push(format!(
                                        "generation {}: unready recovery could not be stopped: \
                                         {stop_error}",
                                        old_params.generation
                                    ));
                                    return GenerationOutcome {
                                        engine: Some(child),
                                        result: Err(candidate_err),
                                        recovery: Some(Err(EngineError::Io(stop_error))),
                                        log,
                                    };
                                }
                            },
                        },
                    };
                    match recovered {
                        Ok(child) => {
                            log.push(format!(
                                "generation {}: old generation recovered, 4/4 sockets verified",
                                old_params.generation
                            ));
                            (Some(child), Some(Ok(())))
                        }
                        Err(e) => {
                            log.push(format!(
                                "generation {}: recovery failed: {}",
                                old_params.generation,
                                e.token()
                            ));
                            (None, Some(Err(e)))
                        }
                    }
                }
            };
            GenerationOutcome {
                engine,
                result: Err(candidate_err),
                recovery,
                log,
            }
        }
    }
}

/// Graceful stop outside a switch: publish `active=0` first (no-op until the
/// data plane exists), then terminate, then delete the generation file — it is
/// a generated artifact and cold start regenerates it.
#[cfg(test)]
#[allow(dead_code)] // Used by the path-included Linux integration harness.
pub fn stop_engine(child: &EngineChild) -> io::Result<String> {
    let effective = child.effective.clone();
    let exit = terminate(child, TERMINATE_GRACE)?;
    match fs::remove_file(&effective) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_in_range_and_distinct() {
        for _ in 0..64 {
            let (a, b) = draw_ports().expect("getrandom");
            assert!(a >= LISTEN_PORT_MIN && b >= LISTEN_PORT_MIN);
            assert_ne!(a, b);
        }
    }

    #[test]
    fn port_reservation_checks_both_transports() {
        let held_udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("hold UDP port");
        let udp_port = held_udp.local_addr().expect("UDP address").port();
        let udp_error = PortReservation::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port)
            .err()
            .expect("occupied UDP port must be rejected");
        assert_eq!(udp_error.kind(), io::ErrorKind::AddrInUse);

        let held_tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("hold TCP port");
        let tcp_port = held_tcp.local_addr().expect("TCP address").port();
        let tcp_error = PortReservation::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tcp_port)
            .err()
            .expect("occupied TCP port must be rejected");
        assert_eq!(tcp_error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn start_time_parses_a_comm_with_parentheses() {
        // Our own stat must parse; we cannot control comm here, but the field
        // count from the LAST ')' is what §13.3 mandates.
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        assert!(proc_start_time(pid).unwrap() > 0);
    }

    #[test]
    fn effective_file_is_exclusive_0600_and_immutable_path() {
        use std::os::unix::fs::PermissionsExt;
        let mut root = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        root.push(format!("flux-engine-eff-{}", unsafe { libc::getpid() }));
        let _ = fs::remove_dir_all(&root);
        let layout = Layout::at(root.clone());
        layout.ensure().unwrap();

        let cfg = serde_json::json!({ "outbounds": [] });
        let path = write_effective(&layout, &cfg, 3).expect("first write");
        assert_eq!(path, layout.effective_path(3));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // O_EXCL: the same generation can never be overwritten.
        match write_effective(&layout, &cfg, 3) {
            Err(EngineError::WriteEffective(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::AlreadyExists)
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn check_reports_failure_output_and_missing_binary() {
        let mut dir = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        dir.push(format!("flux-engine-check-{}", unsafe { libc::getpid() }));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let missing = dir.join("no-such-engine");
        match run_check(&missing, Path::new("/dev/null")) {
            Err(EngineError::BinaryMissing(p)) => assert_eq!(p, missing),
            other => panic!("expected BinaryMissing, got {other:?}"),
        }

        let fake = dir.join("fake-engine");
        fs::write(&fake, "#!/bin/sh\necho 'bad config' >&2\nexit 1\n").unwrap();
        let mut perm = fs::metadata(&fake).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        fs::set_permissions(&fake, perm).unwrap();
        match run_check(&fake, Path::new("/dev/null")) {
            Err(EngineError::CheckFailed { exit, output_head }) => {
                assert_eq!(exit, "code=1");
                assert!(output_head.contains("bad config"));
            }
            other => panic!("expected CheckFailed, got {other:?}"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
