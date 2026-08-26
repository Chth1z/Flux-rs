//! Single-threaded epoll reactor: the event loop, the state machine and
//! convergence.
//!
//! Implements the Phase 2 subset of blueprint §10.1, §10.4 and §26: event
//! sources are signalfd, inotify, the control socket, the engine pidfd, the
//! engine output pipe and two timerfds (config debounce, crash backoff).
//! rtnetlink and the BPF fault ring buffer join in Phase 3+. **There is no
//! periodic polling anywhere** — that is a hard product constraint, not a
//! preference; both timers here are one-shot and armed only by an event.
//!
//! Reachable states in this phase are `Disabled` and `Inactive` (§26): with no
//! data plane there is no way into `Active`, and `status` says so explicitly
//! instead of leaving an empty field (§17.5 exit criterion 4).
//!
//! Convergence is non-reentrant by construction: the loop is single-threaded
//! and each transaction runs to completion while later events stay queued in
//! the level-triggered epoll set (§26 invariant 3).
//!
//! Crash backoff: 1/2/4/8/30 s, reset after 60 s of engine stability. The
//! backoff timer is armed only for retryable failures (crash, readiness
//! timeout, I/O); a config problem waits for the config to change — retrying
//! a deterministic failure on a timer would just be polling with extra steps.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::{Duration, SystemTime};

use flux_core::config::FluxConfig;
use flux_core::control_wire::{Counters, EngineStatus, PolicyCounts, Request, Response, State};
use flux_core::engine_config;

use crate::checks;
use crate::control::{ControlConn, ControlServer};
use crate::engine::{self, EngineChild, EngineError, EngineSpec};
use crate::layout::{InstanceLock, Layout, LockError};

/// Trailing debounce for config-directory churn: editors and `mv`-based
/// updates produce event bursts; one convergence per burst is enough.
const DEBOUNCE: Duration = Duration::from_millis(500);

/// Crash-restart delays (§10.1). The last entry repeats.
const BACKOFF_STEPS: [u64; 5] = [1, 2, 4, 8, 30];

/// Engine uptime after which the crash counter resets.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

/// The daemon log is rotated once to `.1` at startup past this size.
const LOG_ROTATE_BYTES: u64 = 4 * 1024 * 1024;

/// Cap on the buffered partial engine-output line.
const ENGINE_LINE_CAP: usize = 8 * 1024;

// epoll tokens: stable identities, never raw fd numbers.
const TOK_SIGNAL: u64 = 1;
const TOK_CONTROL: u64 = 2;
const TOK_INOTIFY: u64 = 3;
const TOK_DEBOUNCE: u64 = 4;
const TOK_BACKOFF: u64 = 5;
const TOK_ENGINE_PIDFD: u64 = 6;
const TOK_ENGINE_OUT: u64 = 7;

/// Runs the daemon in the foreground. Returns the process exit code.
pub fn run_daemon() -> u8 {
    let layout = Layout::product();
    if let Err(e) = layout.ensure() {
        eprintln!("fluxd: cannot create {}: {e}", layout.root().display());
        return 1;
    }

    // Single instance BEFORE anything else is touched. A rejected second
    // instance exits without unlinking sockets or cleaning files (§10.3).
    let lock = match InstanceLock::acquire(&layout) {
        Ok(lock) => lock,
        Err(e @ LockError::Held(_)) => {
            eprintln!("fluxd: {e}");
            return 1;
        }
        Err(e) => {
            eprintln!("fluxd: {e}");
            return 1;
        }
    };

    let mut logger = Logger::open(&layout);
    logger.log(&format!(
        "fluxd {} starting (root {})",
        flux_core::VERSION,
        layout.root().display()
    ));

    match Reactor::new(layout, logger) {
        Ok(mut reactor) => {
            let code = reactor.run();
            drop(lock);
            code
        }
        Err(e) => {
            eprintln!("fluxd: startup failed: {e}");
            drop(lock);
            1
        }
    }
}

struct Reactor {
    layout: Layout,
    spec: EngineSpec,
    logger: Logger,
    epoll: OwnedFd,
    signal_fd: OwnedFd,
    inotify_fd: OwnedFd,
    root_wd: i32,
    config_wd: i32,
    debounce_timer: OwnedFd,
    backoff_timer: OwnedFd,
    server: ControlServer,
    engine: Option<EngineChild>,
    /// Buffered partial line of engine output between reads.
    engine_line: Vec<u8>,
    /// Monotonic candidate counter (§6.5); the NEXT candidate gets +1.
    generation_counter: u64,
    /// The generation currently (or last) promoted, 0 before the first.
    generation: u64,
    last_error: Option<String>,
    last_error_detail: Option<String>,
    crash_count: u32,
    reload_requested: bool,
    config_changed: bool,
    /// `None` when the page size is the required 4096; otherwise the actual
    /// size. sing-box and the BPF maps both assume 4 KiB pages (§25).
    bad_page_size: Option<i64>,
}

impl Reactor {
    fn new(layout: Layout, logger: Logger) -> io::Result<Self> {
        // SAFETY: signal(2) with SIG_IGN; no handler code runs.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        let spec = EngineSpec::product(&layout);
        let epoll = epoll_create()?;
        let signal_fd = make_signalfd()?;
        let (inotify_fd, root_wd, config_wd) = make_inotify(&layout)?;
        let debounce_timer = make_timerfd()?;
        let backoff_timer = make_timerfd()?;
        let server = ControlServer::bind(&layout.control_socket())?;

        // Cold start: any effective file is a leftover of a previous instance
        // — we hold the lock and have no child yet (§11.1).
        let mut logger = logger;
        match layout.clean_stale_effective() {
            Ok(removed) if !removed.is_empty() => {
                logger.log(&format!(
                    "removed {} stale effective config(s)",
                    removed.len()
                ));
            }
            Ok(_) => {}
            Err(e) => logger.log(&format!("stale-file cleanup failed: {e}")),
        }

        // SAFETY: sysconf has no preconditions.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let bad_page_size = (page_size != 4096).then_some(page_size);

        epoll_add(&epoll, signal_fd.as_raw_fd(), TOK_SIGNAL)?;
        epoll_add(&epoll, server.as_raw_fd(), TOK_CONTROL)?;
        epoll_add(&epoll, inotify_fd.as_raw_fd(), TOK_INOTIFY)?;
        epoll_add(&epoll, debounce_timer.as_raw_fd(), TOK_DEBOUNCE)?;
        epoll_add(&epoll, backoff_timer.as_raw_fd(), TOK_BACKOFF)?;

        Ok(Self {
            layout,
            spec,
            logger,
            epoll,
            signal_fd,
            inotify_fd,
            root_wd,
            config_wd,
            debounce_timer,
            backoff_timer,
            server,
            engine: None,
            engine_line: Vec::new(),
            generation_counter: 0,
            generation: 0,
            last_error: None,
            last_error_detail: None,
            crash_count: 0,
            reload_requested: false,
            config_changed: false,
            bad_page_size,
        })
    }

    fn run(&mut self) -> u8 {
        self.converge("cold start");
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
        loop {
            // SAFETY: events is a valid buffer of the stated length; -1 means
            // block forever — every wakeup is a real event, never a poll.
            let n = unsafe {
                libc::epoll_wait(
                    self.epoll.as_raw_fd(),
                    events.as_mut_ptr(),
                    events.len() as i32,
                    -1,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                self.logger.log(&format!("epoll_wait failed: {err}"));
                return 1;
            }
            for event in &events[..n as usize] {
                match event.u64 {
                    TOK_SIGNAL => {
                        if self.handle_signals() {
                            self.shutdown("signal");
                            return 0;
                        }
                    }
                    TOK_CONTROL => {
                        if self.handle_control() {
                            self.shutdown("stop request");
                            return 0;
                        }
                    }
                    TOK_INOTIFY => self.handle_inotify(),
                    TOK_DEBOUNCE => {
                        drain_timer(&self.debounce_timer);
                        self.config_changed = true;
                        self.converge("config change");
                    }
                    TOK_BACKOFF => {
                        drain_timer(&self.backoff_timer);
                        self.converge("backoff retry");
                    }
                    TOK_ENGINE_PIDFD => self.handle_engine_exit(),
                    TOK_ENGINE_OUT => self.drain_engine_output(),
                    _ => {}
                }
            }
        }
    }

    /// Graceful exit: engine down first (publish `active=0` is a Phase 4+
    /// no-op at the same spot), then the control socket is unlinked — we hold
    /// the lock, so it is ours to remove.
    fn shutdown(&mut self, why: &str) {
        self.logger.log(&format!("shutting down ({why})"));
        if let Some(child) = self.engine.take() {
            self.drain_engine_output_of(&child);
            match engine::stop_engine(child) {
                Ok(exit) => self.logger.log(&format!("engine stopped ({exit})")),
                Err(e) => self.logger.log(&format!("engine stop failed: {e}")),
            }
        }
        let _ = fs::remove_file(self.layout.control_socket());
        self.logger.log("exited");
    }

    /// Returns true when the daemon must exit.
    fn handle_signals(&mut self) -> bool {
        let mut exit = false;
        loop {
            let mut info = std::mem::MaybeUninit::<libc::signalfd_siginfo>::uninit();
            // SAFETY: info is a valid buffer of exactly the size the kernel
            // writes; the fd is our non-blocking signalfd.
            let n = unsafe {
                libc::read(
                    self.signal_fd.as_raw_fd(),
                    info.as_mut_ptr().cast(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                )
            };
            if n != std::mem::size_of::<libc::signalfd_siginfo>() as isize {
                break;
            }
            // SAFETY: the kernel filled the full struct (checked above).
            let info = unsafe { info.assume_init() };
            match info.ssi_signo as i32 {
                libc::SIGHUP => {
                    self.logger.log("SIGHUP: reload");
                    self.reload_requested = true;
                    self.converge("SIGHUP");
                }
                libc::SIGTERM | libc::SIGINT => exit = true,
                _ => {}
            }
        }
        exit
    }

    /// Returns true when a `stop` request asks the daemon to exit.
    fn handle_control(&mut self) -> bool {
        loop {
            let conn = match self.server.accept() {
                Ok(Some(conn)) => conn,
                Ok(None) => return false,
                Err(e) => {
                    self.logger.log(&format!("accept failed: {e}"));
                    return false;
                }
            };
            if !conn.peer_allowed() {
                // Closing without a reply IS the protocol answer to an
                // unauthorised peer (§10.3).
                continue;
            }
            if self.dispatch(&conn) {
                return true;
            }
        }
    }

    /// Handles one request on one connection. Returns true for `stop`.
    fn dispatch(&mut self, conn: &ControlConn) -> bool {
        let request = match conn.recv_request() {
            Ok(request) => request,
            // Malformed, oversized or timed-out request: close, no reply.
            Err(_) => return false,
        };
        match request {
            Request::Status => {
                let response = self.build_status(true);
                let _ = conn.send_response(&response);
            }
            Request::Check => {
                let report = checks::quick_check(&self.layout, &self.spec);
                let mut response = self.build_status(report.ok());
                for error in &report.errors {
                    response.warnings.push(format!("check error: {error}"));
                }
                response.warnings.extend(report.warnings);
                let _ = conn.send_response(&response);
            }
            Request::Enable => {
                let result = self.layout.set_enabled();
                if let Err(e) = &result {
                    self.logger.log(&format!("enable failed: {e}"));
                }
                self.converge("enable");
                let mut response = self.build_status(result.is_ok());
                if let Err(e) = result {
                    response.warnings.push(format!("enable failed: {e}"));
                }
                let _ = conn.send_response(&response);
            }
            Request::Disable => {
                let result = self.layout.set_disabled();
                if let Err(e) = &result {
                    self.logger.log(&format!("disable failed: {e}"));
                }
                self.converge("disable");
                let mut response = self.build_status(result.is_ok());
                if let Err(e) = result {
                    response.warnings.push(format!("disable failed: {e}"));
                }
                let _ = conn.send_response(&response);
            }
            Request::Reload => {
                self.reload_requested = true;
                self.converge("reload");
                let ok = self.last_error.is_none();
                let response = self.build_status(ok);
                let _ = conn.send_response(&response);
            }
            Request::Stop => {
                // Reply while the socket still exists, then exit via the
                // caller. The engine goes down inside shutdown().
                let response = self.build_status(true);
                let _ = conn.send_response(&response);
                return true;
            }
        }
        false
    }

    fn handle_inotify(&mut self) {
        let mut buf = [0u8; 4096];
        let mut switch_changed = false;
        let mut config_changed = false;
        loop {
            // SAFETY: buf is a valid buffer for its length; the fd is our
            // non-blocking inotify fd.
            let n = unsafe {
                libc::read(
                    self.inotify_fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let mut offset = 0usize;
            let n = n as usize;
            const EVENT_HEAD: usize = std::mem::size_of::<libc::inotify_event>();
            while offset + EVENT_HEAD <= n {
                // SAFETY: offset+EVENT_HEAD <= n, so the header is fully
                // inside the buffer; read_unaligned handles any alignment.
                let event = unsafe {
                    std::ptr::read_unaligned(buf[offset..].as_ptr() as *const libc::inotify_event)
                };
                let name_len = event.len as usize;
                let name_bytes = &buf[offset + EVENT_HEAD..(offset + EVENT_HEAD + name_len).min(n)];
                let name = name_bytes
                    .split(|b| *b == 0)
                    .next()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .unwrap_or_default();
                if event.wd == self.root_wd && name == "disable" {
                    switch_changed = true;
                } else if event.wd == self.config_wd {
                    config_changed = true;
                }
                offset += EVENT_HEAD + name_len;
            }
        }
        // The switch acts immediately; config churn is debounced (§10.4).
        if switch_changed {
            self.converge("disable-file change");
        }
        if config_changed {
            arm_timer(&self.debounce_timer, DEBOUNCE);
        }
    }

    fn handle_engine_exit(&mut self) {
        let Some(child) = self.engine.take() else {
            return;
        };
        self.drain_engine_output_of(&child);
        let ran_for = child.spawned_at.elapsed();
        let generation = child.params.generation;
        let effective = child.effective.clone();
        // Grace 0: pidfd already reported the exit; terminate only reaps.
        let exit = match engine::terminate(child, Duration::ZERO) {
            Ok(exit) => exit,
            Err(e) => {
                self.logger.log(&format!("reaping dead engine failed: {e}"));
                "unknown".to_string()
            }
        };
        let _ = fs::remove_file(&effective);
        self.logger.log(&format!(
            "engine (generation {generation}) exited unexpectedly ({exit}) after {}s",
            ran_for.as_secs()
        ));
        self.last_error = Some(format!("engine_exited:{exit}"));
        self.last_error_detail = None;

        if ran_for >= BACKOFF_RESET_AFTER {
            self.crash_count = 0;
        }
        let step = BACKOFF_STEPS[(self.crash_count as usize).min(BACKOFF_STEPS.len() - 1)];
        self.crash_count += 1;
        self.logger
            .log(&format!("restart in {step}s (crash {})", self.crash_count));
        arm_timer(&self.backoff_timer, Duration::from_secs(step));
    }

    fn drain_engine_output(&mut self) {
        let Some(child) = self.engine.take() else {
            return;
        };
        self.drain_engine_output_of(&child);
        self.engine = Some(child);
    }

    /// Drains the engine's stdout+stderr pipe into the daemon log, one line at
    /// a time with the pid as prefix (§13.3: engine output must be captured).
    fn drain_engine_output_of(&mut self, child: &EngineChild) {
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: valid non-blocking fd and buffer.
            let n = unsafe {
                libc::read(
                    child.output.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if n <= 0 {
                break;
            }
            for byte in &chunk[..n as usize] {
                if *byte == b'\n' {
                    let line = String::from_utf8_lossy(&self.engine_line).into_owned();
                    self.logger.log(&format!("engine[{}]: {line}", child.pid));
                    self.engine_line.clear();
                } else if self.engine_line.len() < ENGINE_LINE_CAP {
                    self.engine_line.push(*byte);
                }
            }
        }
    }

    /// The §26 convergence for the Phase 2 subset: reconcile the disable
    /// switch and the engine domain. Policy/dataplane domains join in later
    /// phases.
    fn converge(&mut self, reason: &str) {
        if self.layout.disabled() {
            if let Some(child) = self.engine.take() {
                self.drain_engine_output_of(&child);
                match engine::stop_engine(child) {
                    Ok(exit) => self
                        .logger
                        .log(&format!("disabled ({reason}): engine stopped ({exit})")),
                    Err(e) => self
                        .logger
                        .log(&format!("disabled ({reason}): engine stop failed: {e}")),
                }
            }
            self.reload_requested = false;
            self.config_changed = false;
            disarm_timer(&self.backoff_timer);
            return;
        }

        if let Some(page_size) = self.bad_page_size {
            // §25: a non-4KiB kernel cannot run this build's data plane and
            // the pinned engine binary assumes 4 KiB pages too. Halt in
            // Inactive; status explains.
            self.last_error = Some(format!("unsupported_page_size:{page_size}"));
            return;
        }
        if let Some(mode_error) = self.layout.mode_error() {
            self.logger
                .log(&format!("runtime directory check failed: {mode_error}"));
            self.last_error = Some(mode_error);
            return;
        }

        let need_start = self.engine.is_none();
        let need_switch = self.engine.is_some() && (self.reload_requested || self.config_changed);
        self.reload_requested = false;
        self.config_changed = false;
        if !need_start && !need_switch {
            return;
        }

        let user = match self.read_user_config() {
            Ok(user) => user,
            Err((token, detail)) => {
                if self.engine.is_some() {
                    // Hot-invalid keeps the current generation running: the
                    // §9.4 candidate never got past step 1.
                    self.logger.log(&format!(
                        "config invalid ({token}); keeping the running generation {}",
                        self.generation
                    ));
                } else {
                    self.logger.log(&format!("cannot start engine: {token}"));
                }
                self.last_error = Some(token);
                self.last_error_detail = detail;
                return;
            }
        };

        self.generation_counter += 1;
        let generation = self.generation_counter;
        self.logger.log(&format!(
            "generation {generation}: transaction start ({reason})"
        ));
        let current = self.engine.take();
        let outcome =
            engine::run_generation_switch(&self.layout, &self.spec, &user, current, generation);
        for line in &outcome.log {
            self.logger.log(line);
        }
        self.engine = outcome.engine;
        if let Some(child) = &self.engine {
            self.generation = child.params.generation;
        }

        match outcome.result {
            Ok(()) => {
                self.last_error = None;
                self.last_error_detail = None;
                self.crash_count = 0;
                self.register_engine_fds();
            }
            Err(e) => {
                self.last_error = Some(e.token());
                self.last_error_detail = e.detail();
                // A failed step-6 recovery is a second, separate failure; it
                // must not disappear behind the candidate's error.
                if let Some(Err(recovery_err)) = &outcome.recovery {
                    let note = format!("recovery also failed: {}", recovery_err.token());
                    self.last_error_detail = Some(match self.last_error_detail.take() {
                        Some(detail) => format!("{detail}; {note}"),
                        None => note,
                    });
                }
                if self.engine.is_some() {
                    // Step 6 recovered the old generation; its fds are new.
                    self.register_engine_fds();
                } else if is_retryable(&e) {
                    let step =
                        BACKOFF_STEPS[(self.crash_count as usize).min(BACKOFF_STEPS.len() - 1)];
                    self.crash_count += 1;
                    self.logger.log(&format!("retry in {step}s"));
                    arm_timer(&self.backoff_timer, Duration::from_secs(step));
                }
                // Non-retryable (config/binary problems): the next config
                // change, reload or enable retries. No timer — that would be
                // polling a deterministic failure.
            }
        }
    }

    fn register_engine_fds(&mut self) {
        let Some(child) = &self.engine else {
            return;
        };
        if let Err(e) = epoll_add(&self.epoll, child.pidfd.as_raw_fd(), TOK_ENGINE_PIDFD) {
            self.logger.log(&format!("cannot watch engine pidfd: {e}"));
        }
        if let Err(e) = epoll_add(&self.epoll, child.output.as_raw_fd(), TOK_ENGINE_OUT) {
            self.logger.log(&format!("cannot watch engine output: {e}"));
        }
    }

    /// Reads and parses `config/sing-box.json`. Errors come back as
    /// `(stable token, optional detail)`.
    fn read_user_config(&self) -> Result<serde_json::Value, (String, Option<String>)> {
        let path = self.layout.sing_box_json();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err((
                    "engine_config_missing".to_string(),
                    Some(format!("{} does not exist", path.display())),
                ));
            }
            Err(e) => {
                return Err(("engine_config_missing".to_string(), Some(e.to_string())));
            }
        };
        let text = String::from_utf8(bytes).map_err(|_| {
            (
                "engine_config_invalid".to_string(),
                Some("sing-box.json is not UTF-8".to_string()),
            )
        })?;
        engine_config::parse_jsonc(&text)
            .map_err(|e| ("engine_config_invalid".to_string(), Some(e.to_string())))
    }

    /// Builds the §24.1 status response. Phase 2 always reports `Disabled` or
    /// `Inactive` — with an explicit warning explaining why Inactive, never an
    /// empty answer (§17.5 exit criterion 4).
    fn build_status(&self, ok: bool) -> Response {
        let disabled = self.layout.disabled();
        let state = if disabled {
            State::Disabled
        } else {
            State::Inactive
        };
        let engine_status = match &self.engine {
            Some(child) => EngineStatus {
                running: true,
                pid: Some(child.pid as u32),
                sockets_verified: child.sockets_verified,
                effective_config: Some(child.effective.display().to_string()),
            },
            None => EngineStatus {
                running: false,
                pid: None,
                sockets_verified: 0,
                effective_config: None,
            },
        };

        let mut warnings = Vec::new();
        if disabled {
            warnings.push(format!(
                "disabled: the switch file {} exists; `fluxd enable` removes it",
                self.layout.disable_file().display()
            ));
        } else {
            warnings.push(
                "phase-2 build: no data plane, traffic is NOT proxied; \
                 state stays Inactive by design (engine supervision only)"
                    .to_string(),
            );
        }
        if let Some(detail) = &self.last_error_detail {
            warnings.push(detail.clone());
        }

        Response {
            ok,
            version: flux_core::VERSION.to_string(),
            abi_magic: format!("{:#010X}", flux_core::abi::FLUX_ABI_MAGIC),
            state,
            generation: self.generation,
            engine: engine_status,
            policy: self.policy_counts(),
            ifaces: Vec::new(),
            counters: Counters::default(),
            sysctl: read_sysctl(),
            warnings,
            hints: Vec::new(),
            last_error: self.last_error.clone(),
        }
    }

    /// Policy counts from `flux.toml`, best effort: a status request must not
    /// fail because the config is momentarily broken.
    fn policy_counts(&self) -> PolicyCounts {
        let Ok(bytes) = fs::read(self.layout.flux_toml()) else {
            return PolicyCounts::default();
        };
        let Ok(config) = FluxConfig::parse(&bytes) else {
            return PolicyCounts::default();
        };
        let (fixed_v4, fixed_v6) = FluxConfig::fixed_bypass();
        PolicyCounts {
            selected: config.apps.len() as u32,
            draining: 0,
            bypass_v4: (config.bypass_v4.len() + fixed_v4.len()) as u32,
            bypass_v6: (config.bypass_v6.len() + fixed_v6.len()) as u32,
            self_addresses: 0,
        }
    }
}

/// `all.rp_filter`, read-only (§24.1). Best effort: absent on some hosts.
fn read_sysctl() -> BTreeMap<String, i64> {
    let mut sysctl = BTreeMap::new();
    if let Ok(text) = fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter") {
        if let Ok(value) = text.trim().parse::<i64>() {
            sysctl.insert("all.rp_filter".to_string(), value);
        }
    }
    sysctl
}

/// Whether a failed cold start should be retried on the backoff timer.
/// Deterministic config/binary failures wait for a config event instead.
fn is_retryable(e: &EngineError) -> bool {
    match e {
        EngineError::Exited { .. }
        | EngineError::NotReady { .. }
        | EngineError::SocketOwnerMismatch { .. }
        | EngineError::SpawnFailed(_)
        | EngineError::WriteEffective(_)
        | EngineError::Io(_) => true,
        EngineError::BinaryMissing(_)
        | EngineError::ConfigInvalid(_)
        | EngineError::CheckFailed { .. } => false,
    }
}

// ---------------------------------------------------------------- fd plumbing

fn epoll_create() -> io::Result<OwnedFd> {
    // SAFETY: plain epoll_create1; the fd is immediately owned.
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned by the kernel, not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn epoll_add(epoll: &OwnedFd, fd: RawFd, token: u64) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: token,
    };
    // SAFETY: valid epoll fd, valid target fd, valid event struct.
    let rc = unsafe { libc::epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut event) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocks `SIGTERM`/`SIGINT`/`SIGHUP` and returns a non-blocking signalfd for
/// them. Children undo the mask in [`engine::spawn`]'s child path.
fn make_signalfd() -> io::Result<OwnedFd> {
    // SAFETY: sigset manipulation on a local, fully initialised set.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut mask, sig);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Inotify on the root (the `disable` switch) and the config directory.
fn make_inotify(layout: &Layout) -> io::Result<(OwnedFd, i32, i32)> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: plain inotify_init1; the fd is immediately owned.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned by the kernel, not owned elsewhere.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let add = |dir: &Path, mask: u32| -> io::Result<i32> {
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: valid fd and NUL-terminated path.
        let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(wd)
    };

    let root_wd = add(
        layout.root(),
        libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM,
    )?;
    let config_wd = add(
        &layout.config_dir(),
        libc::IN_CLOSE_WRITE
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_TO
            | libc::IN_MOVED_FROM,
    )?;
    Ok((fd, root_wd, config_wd))
}

fn make_timerfd() -> io::Result<OwnedFd> {
    // SAFETY: plain timerfd_create; the fd is immediately owned.
    let fd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned by the kernel, not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Arms a one-shot expiry `after` from now. Re-arming replaces the previous
/// value — exactly the trailing-debounce semantics we need.
fn arm_timer(fd: &OwnedFd, after: Duration) {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: after.as_secs() as libc::time_t,
            // A zero it_value would DISARM; clamp to 1ns for "immediately".
            tv_nsec: (after
                .subsec_nanos()
                .max(if after.as_secs() == 0 { 1 } else { 0 }))
                as libc::c_long,
        },
    };
    // SAFETY: valid timerfd and a fully initialised itimerspec.
    unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) };
}

fn disarm_timer(fd: &OwnedFd) {
    // SAFETY: valid timerfd; an all-zero itimerspec disarms.
    unsafe {
        let spec: libc::itimerspec = std::mem::zeroed();
        libc::timerfd_settime(fd.as_raw_fd(), 0, &spec, std::ptr::null_mut());
    }
}

fn drain_timer(fd: &OwnedFd) {
    let mut expirations = [0u8; 8];
    // SAFETY: valid fd and an 8-byte buffer, as timerfd reads require.
    unsafe {
        libc::read(fd.as_raw_fd(), expirations.as_mut_ptr().cast(), 8);
    }
}

// -------------------------------------------------------------------- logging

/// Timestamped append-only logger: the daemon log file plus a stderr mirror.
pub struct Logger {
    file: Option<fs::File>,
}

impl Logger {
    /// Opens (and once-rotates) the daemon log. A missing or unwritable log
    /// never stops the daemon; stderr still gets everything.
    pub fn open(layout: &Layout) -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        let path = layout.log_file();
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > LOG_ROTATE_BYTES {
                let _ = fs::rename(&path, layout.root().join("fluxd.log.1"));
            }
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .ok();
        Self { file }
    }

    pub fn log(&mut self, line: &str) {
        let full = format!("[{}] {line}\n", format_utc(SystemTime::now()));
        eprint!("{full}");
        if let Some(file) = &mut self.file {
            let _ = file.write_all(full.as_bytes());
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` without a date-time dependency (Howard Hinnant's
/// civil-from-days algorithm).
pub(crate) fn format_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { y + 1 } else { y }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // leap year
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(format_utc(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn backoff_schedule_is_capped() {
        assert_eq!(BACKOFF_STEPS[BACKOFF_STEPS.len() - 1], 30);
        let step = |count: usize| BACKOFF_STEPS[count.min(BACKOFF_STEPS.len() - 1)];
        assert_eq!(step(0), 1);
        assert_eq!(step(4), 30);
        assert_eq!(step(100), 30);
    }

    #[test]
    fn retryability_split_matches_the_design() {
        // Crash-like failures retry on the timer…
        assert!(is_retryable(&EngineError::NotReady { verified: 2 }));
        assert!(is_retryable(&EngineError::Exited {
            exit: "code=1".into(),
            output_head: String::new(),
        }));
        // …deterministic config problems wait for a config event instead.
        assert!(!is_retryable(&EngineError::BinaryMissing("x".into())));
        assert!(!is_retryable(&EngineError::CheckFailed {
            exit: "code=1".into(),
            output_head: String::new(),
        }));
    }
}
