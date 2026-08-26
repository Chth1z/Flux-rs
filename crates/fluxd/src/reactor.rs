//! Single-threaded epoll reactor: the event loop, the state machine and
//! convergence.
//!
//! Implements the Phase 2 subset of blueprint §10.1, §10.4 and §26: event
//! sources are signalfd, inotify, the control socket, child pidfds, child
//! output pipes and one-shot timerfds (config debounce, crash backoff and
//! engine-transaction deadlines).
//! rtnetlink and the BPF fault ring buffer join in Phase 3+. **There is no
//! periodic polling anywhere** — that is a hard product constraint, not a
//! preference; both timers here are one-shot and armed only by an event.
//!
//! Reachable states in this phase are `Disabled` and `Inactive` (§26): with no
//! data plane there is no way into `Active`, and `status` says so explicitly
//! instead of leaving an empty field (§17.5 exit criterion 4).
//!
//! Convergence is non-reentrant by construction: the loop is single-threaded,
//! while each engine transaction advances one fd/timer event at a time. Later
//! requests remain serviceable and merely queue another convergence.
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
use std::time::{Duration, Instant, SystemTime};

use flux_core::config::FluxConfig;
use flux_core::control_wire::{Counters, EngineStatus, PolicyCounts, Request, Response, State};
use flux_core::engine_config::{self, MAX_ENGINE_CONFIG_BYTES};

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
const TOK_CONTROL_TIMEOUT: u64 = 8;
const TOK_ENGINE_TIMER: u64 = 9;
const TOK_TX_PIDFD: u64 = 10;
const TOK_TX_OUT: u64 = 11;
const TOK_CHECK_PIDFD: u64 = 12;
const TOK_CHECK_OUT: u64 = 13;
const TOK_CONTROL_CONN_BASE: u64 = 1_024;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_CONVERGE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONTROL_CONNECTIONS: usize = 32;

#[derive(Debug)]
struct OldGeneration {
    params: engine_config::EngineParams,
    effective: std::path::PathBuf,
}

#[derive(Debug)]
struct SwitchPlan {
    generation: u64,
    params: engine_config::EngineParams,
    candidate: std::path::PathBuf,
    old: Option<OldGeneration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckDisposition {
    Normal,
    TimedOut,
    Cancelled,
    SupervisionFailed,
}

#[derive(Debug)]
enum WaitRole {
    Candidate(SwitchPlan),
    Recovery { candidate_error: EngineError },
}

#[derive(Debug)]
enum StopNext {
    StartCandidate(SwitchPlan),
    Recover {
        plan: SwitchPlan,
        candidate_error: EngineError,
    },
    FinishRecoveryFailure {
        candidate_error: EngineError,
        recovery_error: EngineError,
    },
    Cancelled,
}

#[derive(Debug)]
enum EngineTransaction {
    Checking {
        check: engine::EngineCheck,
        plan: SwitchPlan,
        deadline: Instant,
        disposition: CheckDisposition,
    },
    Waiting {
        child: EngineChild,
        role: WaitRole,
        deadline: Instant,
        backoff: Duration,
    },
    Stopping {
        child: EngineChild,
        next: StopNext,
        deadline: Instant,
        kill_sent: bool,
    },
}

enum PendingControl {
    Reading {
        conn: ControlConn,
        deadline: Instant,
    },
    Writing {
        conn: ControlConn,
        response: Box<Response>,
        deadline: Instant,
        stop_after: bool,
    },
    Converging {
        conn: ControlConn,
        deadline: Instant,
    },
}

impl PendingControl {
    fn deadline(&self) -> Instant {
        match self {
            Self::Reading { deadline, .. }
            | Self::Writing { deadline, .. }
            | Self::Converging { deadline, .. } => *deadline,
        }
    }
}

/// Runs the daemon in the foreground. Returns the process exit code.
pub fn run_daemon() -> u8 {
    let layout = Layout::product();
    if let Err(e) = layout.ensure() {
        eprintln!("fluxd: cannot create {}: {e}", layout.root().display());
        return 1;
    }
    if let Some(error) = layout.mode_error() {
        eprintln!("fluxd: runtime directory check failed: {error}");
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
    control_timer: OwnedFd,
    engine_timer: OwnedFd,
    server: ControlServer,
    control_conns: BTreeMap<u64, PendingControl>,
    next_control_token: u64,
    engine: Option<EngineChild>,
    engine_transaction: Option<EngineTransaction>,
    engine_cancel_requested: bool,
    shutdown_requested: bool,
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
        let control_timer = make_timerfd()?;
        let engine_timer = make_timerfd()?;
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
        epoll_add(&epoll, control_timer.as_raw_fd(), TOK_CONTROL_TIMEOUT)?;
        epoll_add(&epoll, engine_timer.as_raw_fd(), TOK_ENGINE_TIMER)?;

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
            control_timer,
            engine_timer,
            server,
            control_conns: BTreeMap::new(),
            next_control_token: TOK_CONTROL_CONN_BASE,
            engine: None,
            engine_transaction: None,
            engine_cancel_requested: false,
            shutdown_requested: false,
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
                // `epoll_event` is packed on musl; copy before matching so a
                // guard never forms an unaligned reference to `u64`.
                let token = event.u64;
                match token {
                    TOK_SIGNAL => {
                        if self.handle_signals() {
                            self.request_shutdown("signal");
                        }
                    }
                    TOK_CONTROL => {
                        if self.handle_control() {
                            self.request_shutdown("stop request");
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
                        if self.shutdown_requested || self.layout.disabled() {
                            self.engine_cancel_requested = true;
                            self.cancel_engine_work();
                        } else {
                            self.converge("backoff retry");
                        }
                    }
                    TOK_ENGINE_PIDFD => self.handle_engine_exit(),
                    TOK_ENGINE_OUT => self.drain_engine_output(),
                    TOK_CONTROL_TIMEOUT => self.expire_control_connections(),
                    TOK_ENGINE_TIMER => self.handle_engine_timer(),
                    TOK_TX_PIDFD => self.handle_transaction_pidfd(),
                    TOK_TX_OUT => self.drain_transaction_output(),
                    TOK_CHECK_PIDFD => self.handle_check_exit(),
                    TOK_CHECK_OUT => self.drain_check_output(),
                    token if token >= TOK_CONTROL_CONN_BASE => {
                        if self.handle_control_connection(token) {
                            self.request_shutdown("stop request");
                        }
                    }
                    _ => {}
                }
            }
            if self.shutdown_requested && self.engine.is_none() && self.engine_transaction.is_none()
            {
                self.finish_shutdown();
                return 0;
            }
        }
    }

    /// Starts graceful shutdown without occupying the event loop. Engine
    /// termination is driven by pidfd plus the transaction timer.
    fn request_shutdown(&mut self, why: &str) {
        if self.shutdown_requested {
            return;
        }
        self.logger.log(&format!("shutting down ({why})"));
        self.shutdown_requested = true;
        self.engine_cancel_requested = true;
        self.cancel_engine_work();
    }

    /// Final shutdown publish point: no supervised child remains.
    fn finish_shutdown(&mut self) {
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
            if self.control_conns.len() >= MAX_CONTROL_CONNECTIONS {
                self.logger
                    .log("control connection cap reached; closing peer");
                continue;
            }
            let token = self.next_control_token;
            self.next_control_token = self
                .next_control_token
                .checked_add(1)
                .filter(|next| *next >= TOK_CONTROL_CONN_BASE)
                .unwrap_or(TOK_CONTROL_CONN_BASE);
            if let Err(e) = epoll_add(&self.epoll, conn.as_raw_fd(), token) {
                self.logger
                    .log(&format!("cannot watch control connection: {e}"));
                continue;
            }
            self.control_conns.insert(
                token,
                PendingControl::Reading {
                    conn,
                    deadline: Instant::now() + CONTROL_TIMEOUT,
                },
            );
            self.rearm_control_timer();
            // The client normally sends immediately after connect. Try once
            // now; EAGAIN simply leaves the connection registered in epoll.
            if self.handle_control_connection(token) {
                return true;
            }
        }
    }

    /// Advances one non-blocking, one-request/one-response control connection.
    /// Returns true only after a `stop` response was sent (or the peer closed).
    fn handle_control_connection(&mut self, token: u64) -> bool {
        let Some(pending) = self.control_conns.remove(&token) else {
            return false;
        };
        match pending {
            PendingControl::Reading { conn, deadline } => match conn.recv_request() {
                Ok(request) => {
                    let (response, stop_after) = self.dispatch_request(request);
                    let Some(response) = response else {
                        self.control_conns.insert(
                            token,
                            PendingControl::Converging {
                                conn,
                                deadline: Instant::now() + CONTROL_CONVERGE_TIMEOUT,
                            },
                        );
                        self.rearm_control_timer();
                        return false;
                    };
                    match conn.send_response(&response) {
                        Ok(()) => {
                            self.rearm_control_timer();
                            stop_after
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if let Err(watch_err) = epoll_mod_events(
                                &self.epoll,
                                conn.as_raw_fd(),
                                token,
                                libc::EPOLLOUT as u32,
                            ) {
                                self.logger.log(&format!(
                                    "cannot watch writable control connection: {watch_err}"
                                ));
                                self.rearm_control_timer();
                                return stop_after;
                            }
                            self.control_conns.insert(
                                token,
                                PendingControl::Writing {
                                    conn,
                                    response: Box::new(response),
                                    deadline,
                                    stop_after,
                                },
                            );
                            self.rearm_control_timer();
                            false
                        }
                        Err(_) => {
                            self.rearm_control_timer();
                            stop_after
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.control_conns
                        .insert(token, PendingControl::Reading { conn, deadline });
                    self.rearm_control_timer();
                    false
                }
                // Malformed or oversized request: close without a reply.
                Err(_) => {
                    self.rearm_control_timer();
                    false
                }
            },
            PendingControl::Writing {
                conn,
                response,
                deadline,
                stop_after,
            } => match conn.send_response(&response) {
                Ok(()) => {
                    self.rearm_control_timer();
                    stop_after
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.control_conns.insert(
                        token,
                        PendingControl::Writing {
                            conn,
                            response,
                            deadline,
                            stop_after,
                        },
                    );
                    self.rearm_control_timer();
                    false
                }
                Err(_) => {
                    self.rearm_control_timer();
                    stop_after
                }
            },
            PendingControl::Converging { conn, deadline } => {
                self.control_conns
                    .insert(token, PendingControl::Converging { conn, deadline });
                self.rearm_control_timer();
                false
            }
        }
    }

    fn rearm_control_timer(&self) {
        match self
            .control_conns
            .values()
            .map(PendingControl::deadline)
            .min()
        {
            Some(deadline) => arm_timer(
                &self.control_timer,
                deadline.saturating_duration_since(Instant::now()),
            ),
            None => disarm_timer(&self.control_timer),
        }
    }

    fn expire_control_connections(&mut self) {
        drain_timer(&self.control_timer);
        let now = Instant::now();
        self.control_conns
            .retain(|_, pending| pending.deadline() > now);
        self.rearm_control_timer();
    }

    /// Completes commands that asked for convergence only after the engine
    /// transaction reached a terminal state. The peer remains non-blocking;
    /// backpressure transitions to the normal EPOLLOUT state.
    fn complete_convergence_controls(&mut self) {
        let tokens: Vec<u64> = self
            .control_conns
            .iter()
            .filter_map(|(token, pending)| {
                matches!(pending, PendingControl::Converging { .. }).then_some(*token)
            })
            .collect();
        for token in tokens {
            let Some(PendingControl::Converging { conn, deadline }) =
                self.control_conns.remove(&token)
            else {
                continue;
            };
            let response = self.build_status(self.last_error.is_none());
            match conn.send_response(&response) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if epoll_mod_events(&self.epoll, conn.as_raw_fd(), token, libc::EPOLLOUT as u32)
                        .is_ok()
                    {
                        self.control_conns.insert(
                            token,
                            PendingControl::Writing {
                                conn,
                                response: Box::new(response),
                                deadline,
                                stop_after: false,
                            },
                        );
                    }
                }
                Err(_) => {}
            }
        }
        self.rearm_control_timer();
    }

    /// Executes an already-decoded request. Socket I/O remains outside this
    /// function so a slow peer can never occupy the reactor.
    fn dispatch_request(&mut self, request: Request) -> (Option<Response>, bool) {
        let response = match request {
            Request::Status => Some(self.build_status(true)),
            Request::Check => {
                let report = checks::quick_check(&self.layout, &self.spec);
                let mut response = self.build_status(report.ok());
                for error in &report.errors {
                    response.warnings.push(format!("check error: {error}"));
                }
                response.warnings.extend(report.warnings);
                Some(response)
            }
            Request::Enable => {
                let result = self.layout.set_enabled();
                if let Err(e) = &result {
                    self.logger.log(&format!("enable failed: {e}"));
                }
                self.converge("enable");
                if result.is_ok() && self.engine_transaction.is_some() {
                    return (None, false);
                }
                let mut response = self.build_status(result.is_ok());
                if let Err(e) = result {
                    response.warnings.push(format!("enable failed: {e}"));
                }
                Some(response)
            }
            Request::Disable => {
                let result = self.layout.set_disabled();
                if let Err(e) = &result {
                    self.logger.log(&format!("disable failed: {e}"));
                }
                self.converge("disable");
                if result.is_ok() && self.engine_transaction.is_some() {
                    return (None, false);
                }
                let mut response = self.build_status(result.is_ok());
                if let Err(e) = result {
                    response.warnings.push(format!("disable failed: {e}"));
                }
                Some(response)
            }
            Request::Reload => {
                self.reload_requested = true;
                self.converge("reload");
                if self.engine_transaction.is_some() {
                    return (None, false);
                }
                let ok = self.last_error.is_none();
                Some(self.build_status(ok))
            }
            Request::Stop => {
                // Reply while the socket still exists; the connection state
                // reports `stop_after` once the frame is sent.
                Some(self.build_status(true))
            }
        };
        (response, matches!(request, Request::Stop))
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
        let Some(mut child) = self.engine.take() else {
            return;
        };
        self.flush_engine_line(child.pid);
        let output_head = engine::drain_output_head(&mut child);
        let ran_for = child.spawned_at.elapsed();
        let generation = child.params.generation;
        let effective = child.effective.clone();
        // Grace 0: pidfd already reported the exit; terminate only reaps.
        let exit = match engine::terminate(&child, Duration::ZERO) {
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
        self.last_error_detail = (!output_head.is_empty()).then_some(output_head);

        if ran_for >= BACKOFF_RESET_AFTER {
            self.crash_count = 0;
        }
        if self.engine_transaction.is_none() {
            let step = BACKOFF_STEPS[(self.crash_count as usize).min(BACKOFF_STEPS.len() - 1)];
            self.crash_count += 1;
            self.logger
                .log(&format!("restart in {step}s (crash {})", self.crash_count));
            arm_timer(&self.backoff_timer, Duration::from_secs(step));
        } else {
            self.logger
                .log("current engine exited while its replacement was being checked");
        }
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

    fn flush_engine_line(&mut self, pid: i32) {
        if self.engine_line.is_empty() {
            return;
        }
        let line = String::from_utf8_lossy(&self.engine_line).into_owned();
        self.logger.log(&format!("engine[{pid}]: {line}"));
        self.engine_line.clear();
    }

    /// The §26 convergence for the Phase 2 subset: reconcile the disable
    /// switch and the engine domain. Policy/dataplane domains join in later
    /// phases.
    fn converge(&mut self, reason: &str) {
        if self.shutdown_requested {
            self.engine_cancel_requested = true;
            self.cancel_engine_work();
            return;
        }
        if self.layout.disabled() {
            self.engine_cancel_requested = true;
            self.cancel_engine_work();
            self.reload_requested = false;
            self.config_changed = false;
            disarm_timer(&self.backoff_timer);
            return;
        }

        if self.engine_transaction.is_some() {
            self.logger.log(&format!(
                "{reason}: engine transaction already in progress; queued"
            ));
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
        disarm_timer(&self.backoff_timer);
        self.logger.log(&format!(
            "generation {generation}: transaction start ({reason})"
        ));
        self.start_generation_check(user, generation);
    }

    fn start_generation_check(&mut self, user: serde_json::Value, generation: u64) {
        let (port_v4, port_v6) = match engine::draw_ports() {
            Ok(ports) => ports,
            Err(e) => {
                self.finish_transaction_error(EngineError::Io(e), None);
                return;
            }
        };
        let params = engine_config::EngineParams {
            generation,
            port_v4,
            port_v6,
        };
        let effective = match engine_config::build_effective(&user, &params) {
            Ok(value) => value,
            Err(e) => {
                self.finish_transaction_error(EngineError::ConfigInvalid(e), None);
                return;
            }
        };
        let candidate = match engine::write_effective(&self.layout, &effective, generation) {
            Ok(path) => path,
            Err(e) => {
                self.finish_transaction_error(e, None);
                return;
            }
        };
        let mut check = match engine::spawn_check(&self.spec.binary, &candidate) {
            Ok(check) => check,
            Err(e) => {
                let _ = fs::remove_file(&candidate);
                self.finish_transaction_error(e, None);
                return;
            }
        };
        let registration = epoll_add(&self.epoll, check.pidfd(), TOK_CHECK_PIDFD)
            .and_then(|()| epoll_add(&self.epoll, check.output_fd(), TOK_CHECK_OUT));
        let disposition = match registration {
            Ok(()) => CheckDisposition::Normal,
            Err(e) => {
                self.last_error = Some("engine_io_error".to_string());
                self.last_error_detail = Some(format!("cannot watch engine check: {e}"));
                self.logger.log(&format!("cannot watch engine check: {e}"));
                let _ = check.kill();
                CheckDisposition::SupervisionFailed
            }
        };
        self.engine_transaction = Some(EngineTransaction::Checking {
            check,
            plan: SwitchPlan {
                generation,
                params,
                candidate,
                old: None,
            },
            deadline: Instant::now() + engine::CHECK_DEADLINE,
            disposition,
        });
        arm_timer(
            &self.engine_timer,
            if disposition == CheckDisposition::Normal {
                engine::CHECK_DEADLINE
            } else {
                Duration::from_millis(10)
            },
        );
    }

    fn handle_check_exit(&mut self) {
        let Some(transaction) = self.engine_transaction.take() else {
            return;
        };
        let EngineTransaction::Checking {
            mut check,
            plan,
            deadline,
            disposition,
        } = transaction
        else {
            // A check fd can already be present in the current epoll batch
            // when successful completion closes it and starts the candidate.
            // Never discard that newer transaction on the stale event.
            self.engine_transaction = Some(transaction);
            return;
        };
        match check.finish() {
            Ok(Some(result)) => self.complete_check(check, plan, disposition, result),
            Ok(None) => {
                self.engine_transaction = Some(EngineTransaction::Checking {
                    check,
                    plan,
                    deadline,
                    disposition,
                });
            }
            Err(e) => {
                self.logger.log(&format!(
                    "engine check supervision failed: {} ({:?})",
                    e.token(),
                    e.detail()
                ));
                self.last_error = Some(e.token());
                self.last_error_detail = e.detail();
                let _ = check.kill();
                self.engine_transaction = Some(EngineTransaction::Checking {
                    check,
                    plan,
                    deadline: Instant::now() + Duration::from_secs(2),
                    disposition: CheckDisposition::SupervisionFailed,
                });
                arm_timer(&self.engine_timer, Duration::from_millis(10));
            }
        }
    }

    fn drain_check_output(&mut self) {
        if let Some(EngineTransaction::Checking { check, .. }) = self.engine_transaction.as_mut() {
            check.drain_output();
        }
    }

    fn complete_check(
        &mut self,
        mut check: engine::EngineCheck,
        mut plan: SwitchPlan,
        disposition: CheckDisposition,
        result: Result<(), EngineError>,
    ) {
        disarm_timer(&self.engine_timer);
        match disposition {
            CheckDisposition::Cancelled => {
                let _ = fs::remove_file(&plan.candidate);
                self.finish_cancelled();
            }
            CheckDisposition::TimedOut => {
                let error = check.timeout_error();
                let _ = fs::remove_file(&plan.candidate);
                self.finish_transaction_error(error, None);
            }
            CheckDisposition::SupervisionFailed => {
                let detail = self
                    .last_error_detail
                    .take()
                    .unwrap_or_else(|| "engine check supervision failed".to_string());
                let _ = fs::remove_file(&plan.candidate);
                self.finish_transaction_error(EngineError::Io(io::Error::other(detail)), None);
            }
            CheckDisposition::Normal => match result {
                Err(error) => {
                    let _ = fs::remove_file(&plan.candidate);
                    self.finish_transaction_error(error, None);
                }
                Ok(()) => {
                    self.logger.log(&format!(
                        "generation {}: candidate checked (ports {}/{})",
                        plan.generation, plan.params.port_v4, plan.params.port_v6
                    ));
                    if self.engine_cancel_requested {
                        let _ = fs::remove_file(&plan.candidate);
                        self.finish_cancelled();
                    } else if let Some(child) = self.engine.take() {
                        plan.old = Some(OldGeneration {
                            params: child.params,
                            effective: child.effective.clone(),
                        });
                        self.begin_stop(child, StopNext::StartCandidate(plan));
                    } else {
                        self.start_candidate(plan);
                    }
                }
            },
        }
    }

    fn handle_engine_timer(&mut self) {
        drain_timer(&self.engine_timer);
        let Some(transaction) = self.engine_transaction.take() else {
            return;
        };
        match transaction {
            EngineTransaction::Checking {
                mut check,
                plan,
                deadline,
                mut disposition,
            } => {
                if disposition == CheckDisposition::Normal && Instant::now() >= deadline {
                    disposition = CheckDisposition::TimedOut;
                    if let Err(e) = check.kill() {
                        self.logger
                            .log(&format!("cannot kill timed-out check: {e}"));
                    }
                }
                match check.finish() {
                    Ok(Some(result)) => self.complete_check(check, plan, disposition, result),
                    Ok(None) => {
                        self.engine_transaction = Some(EngineTransaction::Checking {
                            check,
                            plan,
                            deadline,
                            disposition,
                        });
                        arm_timer(
                            &self.engine_timer,
                            if disposition == CheckDisposition::Normal {
                                deadline.saturating_duration_since(Instant::now())
                            } else {
                                Duration::from_millis(10)
                            },
                        );
                    }
                    Err(e) => {
                        let _ = check.kill();
                        self.last_error = Some(e.token());
                        self.last_error_detail = e.detail();
                        self.engine_transaction = Some(EngineTransaction::Checking {
                            check,
                            plan,
                            deadline: Instant::now() + Duration::from_secs(2),
                            disposition: CheckDisposition::SupervisionFailed,
                        });
                        arm_timer(&self.engine_timer, Duration::from_millis(10));
                    }
                }
            }
            EngineTransaction::Waiting {
                child,
                role,
                deadline,
                backoff,
            } => self.advance_waiting(child, role, deadline, backoff),
            EngineTransaction::Stopping {
                child,
                next,
                deadline,
                kill_sent,
            } => {
                if engine::has_exited(&child.pidfd) {
                    self.complete_stopped(child, next);
                } else if Instant::now() < deadline {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    self.engine_transaction = Some(EngineTransaction::Stopping {
                        child,
                        next,
                        deadline,
                        kill_sent,
                    });
                    arm_timer(&self.engine_timer, remaining);
                } else if !kill_sent {
                    if let Err(e) = engine::signal(&child, libc::SIGKILL) {
                        self.logger.log(&format!("cannot SIGKILL engine: {e}"));
                    }
                    let deadline = Instant::now() + Duration::from_secs(2);
                    self.engine_transaction = Some(EngineTransaction::Stopping {
                        child,
                        next,
                        deadline,
                        kill_sent: true,
                    });
                    arm_timer(&self.engine_timer, Duration::from_secs(2));
                } else {
                    self.stop_confirmation_failed(child, next);
                }
            }
        }
    }

    fn handle_transaction_pidfd(&mut self) {
        let Some(transaction) = self.engine_transaction.take() else {
            return;
        };
        match transaction {
            EngineTransaction::Waiting {
                child,
                role,
                deadline,
                backoff,
            } => self.advance_waiting(child, role, deadline, backoff),
            EngineTransaction::Stopping { child, next, .. } => self.complete_stopped(child, next),
            checking @ EngineTransaction::Checking { .. } => {
                self.engine_transaction = Some(checking)
            }
        }
    }

    fn drain_transaction_output(&mut self) {
        let Some(transaction) = self.engine_transaction.take() else {
            return;
        };
        match &transaction {
            EngineTransaction::Waiting { child, .. }
            | EngineTransaction::Stopping { child, .. } => self.drain_engine_output_of(child),
            EngineTransaction::Checking { .. } => {}
        }
        self.engine_transaction = Some(transaction);
    }

    fn start_candidate(&mut self, plan: SwitchPlan) {
        match engine::spawn(&self.spec, &plan.candidate, plan.params) {
            Err(error) => self.begin_candidate_failure(plan, error),
            Ok(child) => match self.register_new_transaction_child(&child) {
                Ok(()) => self.wait_for_child(child, WaitRole::Candidate(plan)),
                Err(e) => self.begin_stop(
                    child,
                    StopNext::Recover {
                        plan,
                        candidate_error: EngineError::Io(e),
                    },
                ),
            },
        }
    }

    fn wait_for_child(&mut self, child: EngineChild, role: WaitRole) {
        self.engine_transaction = Some(EngineTransaction::Waiting {
            child,
            role,
            deadline: Instant::now() + engine::READY_DEADLINE,
            backoff: Duration::from_millis(10),
        });
        arm_timer(&self.engine_timer, Duration::from_millis(10));
    }

    fn advance_waiting(
        &mut self,
        mut child: EngineChild,
        role: WaitRole,
        deadline: Instant,
        backoff: Duration,
    ) {
        if self.engine_cancel_requested {
            self.cleanup_cancelled_wait_role(&role);
            self.begin_stop(child, StopNext::Cancelled);
            return;
        }
        match engine::probe_ready(&mut child, &self.spec) {
            Ok(engine::Readiness::Ready) => self.promote_ready_child(child, role),
            Ok(engine::Readiness::Pending { verified }) => {
                if Instant::now() >= deadline {
                    let error = EngineError::NotReady { verified };
                    let next = match role {
                        WaitRole::Candidate(plan) => StopNext::Recover {
                            plan,
                            candidate_error: error,
                        },
                        WaitRole::Recovery { candidate_error } => StopNext::FinishRecoveryFailure {
                            candidate_error,
                            recovery_error: error,
                        },
                    };
                    self.begin_stop(child, next);
                } else {
                    let wait = backoff.min(deadline.saturating_duration_since(Instant::now()));
                    self.engine_transaction = Some(EngineTransaction::Waiting {
                        child,
                        role,
                        deadline,
                        backoff: (backoff * 2).min(Duration::from_millis(250)),
                    });
                    arm_timer(&self.engine_timer, wait);
                }
            }
            Err(error @ EngineError::Exited { .. }) => match role {
                WaitRole::Candidate(plan) => {
                    self.flush_engine_line(child.pid);
                    self.begin_candidate_failure(plan, error);
                }
                WaitRole::Recovery { candidate_error } => {
                    self.flush_engine_line(child.pid);
                    self.finish_transaction_error(candidate_error, Some(error))
                }
            },
            Err(error) => {
                let next = match role {
                    WaitRole::Candidate(plan) => StopNext::Recover {
                        plan,
                        candidate_error: error,
                    },
                    WaitRole::Recovery { candidate_error } => StopNext::FinishRecoveryFailure {
                        candidate_error,
                        recovery_error: error,
                    },
                };
                self.begin_stop(child, next);
            }
        }
    }

    fn promote_ready_child(&mut self, child: EngineChild, role: WaitRole) {
        if let Err(e) = self.retag_transaction_child(&child, TOK_ENGINE_PIDFD, TOK_ENGINE_OUT) {
            let next = match role {
                WaitRole::Candidate(plan) => StopNext::Recover {
                    plan,
                    candidate_error: EngineError::Io(e),
                },
                WaitRole::Recovery { candidate_error } => StopNext::FinishRecoveryFailure {
                    candidate_error,
                    recovery_error: EngineError::Io(e),
                },
            };
            self.begin_stop(child, next);
            return;
        }
        disarm_timer(&self.engine_timer);
        self.generation = child.params.generation;
        match role {
            WaitRole::Candidate(plan) => {
                if let Some(old) = plan.old {
                    let _ = fs::remove_file(old.effective);
                }
                self.logger.log(&format!(
                    "generation {}: 4/4 sockets verified by pid+inode, promoted (pid {}, starttime {})",
                    child.params.generation, child.pid, child.start_time
                ));
                self.engine = Some(child);
                self.last_error = None;
                self.last_error_detail = None;
                self.engine_cancel_requested = false;
            }
            WaitRole::Recovery { candidate_error } => {
                self.logger.log(&format!(
                    "generation {}: old generation recovered, 4/4 sockets verified",
                    child.params.generation
                ));
                self.engine = Some(child);
                self.last_error = Some(candidate_error.token());
                self.last_error_detail = candidate_error.detail();
                self.engine_cancel_requested = false;
            }
        }
        self.run_queued_convergence();
        if self.engine_transaction.is_none() {
            self.complete_convergence_controls();
        }
    }

    fn begin_candidate_failure(&mut self, mut plan: SwitchPlan, error: EngineError) {
        self.logger.log(&format!(
            "generation {}: candidate failed: {}",
            plan.generation,
            error.token()
        ));
        let _ = fs::remove_file(&plan.candidate);
        if self.engine_cancel_requested {
            if let Some(old) = plan.old.take() {
                let _ = fs::remove_file(old.effective);
            }
            self.finish_cancelled();
            return;
        }
        let Some(old) = plan.old.take() else {
            self.finish_transaction_error(error, None);
            return;
        };
        match engine::spawn(&self.spec, &old.effective, old.params) {
            Err(recovery_error) => {
                self.finish_transaction_error(error, Some(recovery_error));
            }
            Ok(child) => match self.register_new_transaction_child(&child) {
                Ok(()) => self.wait_for_child(
                    child,
                    WaitRole::Recovery {
                        candidate_error: error,
                    },
                ),
                Err(e) => self.begin_stop(
                    child,
                    StopNext::FinishRecoveryFailure {
                        candidate_error: error,
                        recovery_error: EngineError::Io(e),
                    },
                ),
            },
        }
    }

    fn begin_stop(&mut self, child: EngineChild, next: StopNext) {
        if let Err(e) = self.retag_transaction_child(&child, TOK_TX_PIDFD, TOK_TX_OUT) {
            self.logger
                .log(&format!("cannot retag engine supervision fds: {e}"));
        }
        if let Err(e) = engine::signal(&child, libc::SIGTERM) {
            self.logger.log(&format!("cannot SIGTERM engine: {e}"));
        }
        self.engine_transaction = Some(EngineTransaction::Stopping {
            child,
            next,
            deadline: Instant::now() + engine::TERMINATE_GRACE,
            kill_sent: false,
        });
        arm_timer(&self.engine_timer, engine::TERMINATE_GRACE);
    }

    fn complete_stopped(&mut self, mut child: EngineChild, next: StopNext) {
        disarm_timer(&self.engine_timer);
        self.flush_engine_line(child.pid);
        let output = engine::drain_output_head(&mut child);
        let exit =
            engine::terminate(&child, Duration::ZERO).unwrap_or_else(|e| format!("reap-error:{e}"));
        if !output.is_empty() {
            self.logger
                .log(&format!("engine[{}] final output: {output}", child.pid));
        }
        self.logger.log(&format!(
            "engine generation {} stopped ({exit})",
            child.params.generation
        ));
        match next {
            StopNext::StartCandidate(plan) => {
                if self.engine_cancel_requested {
                    let _ = fs::remove_file(&child.effective);
                    let _ = fs::remove_file(&plan.candidate);
                    self.finish_cancelled();
                } else {
                    self.start_candidate(plan);
                }
            }
            StopNext::Recover {
                plan,
                candidate_error,
            } => {
                let _ = fs::remove_file(&child.effective);
                self.begin_candidate_failure(plan, candidate_error);
            }
            StopNext::FinishRecoveryFailure {
                candidate_error,
                recovery_error,
            } => {
                let _ = fs::remove_file(&child.effective);
                self.finish_transaction_error(candidate_error, Some(recovery_error));
            }
            StopNext::Cancelled => {
                let _ = fs::remove_file(&child.effective);
                self.finish_cancelled();
            }
        }
    }

    fn stop_confirmation_failed(&mut self, child: EngineChild, next: StopNext) {
        match &next {
            StopNext::StartCandidate(plan) => {
                let _ = fs::remove_file(&plan.candidate);
            }
            StopNext::Recover { plan, .. } => {
                if let Some(old) = &plan.old {
                    let _ = fs::remove_file(&old.effective);
                }
            }
            StopNext::FinishRecoveryFailure { .. } | StopNext::Cancelled => {}
        }
        self.logger
            .log("engine survived SIGKILL confirmation window; retaining supervision");
        self.last_error = Some("engine_stop_failed".to_string());
        self.last_error_detail = Some(
            "engine survived SIGKILL confirmation window; no replacement was started".to_string(),
        );
        if let Err(e) = self.retag_transaction_child(&child, TOK_ENGINE_PIDFD, TOK_ENGINE_OUT) {
            self.logger
                .log(&format!("cannot restore engine supervision tags: {e}"));
        }
        self.generation = child.params.generation;
        self.engine = Some(child);
        self.engine_transaction = None;
        self.engine_cancel_requested = false;
        disarm_timer(&self.engine_timer);
        self.complete_convergence_controls();
        arm_timer(&self.backoff_timer, Duration::from_secs(1));
    }

    fn cancel_engine_work(&mut self) {
        let Some(transaction) = self.engine_transaction.take() else {
            if let Some(child) = self.engine.take() {
                self.begin_stop(child, StopNext::Cancelled);
            } else {
                self.engine_cancel_requested = false;
            }
            return;
        };
        match transaction {
            EngineTransaction::Checking {
                mut check,
                plan,
                deadline,
                ..
            } => {
                let _ = check.kill();
                self.engine_transaction = Some(EngineTransaction::Checking {
                    check,
                    plan,
                    deadline,
                    disposition: CheckDisposition::Cancelled,
                });
                arm_timer(&self.engine_timer, Duration::from_millis(10));
            }
            EngineTransaction::Waiting { child, role, .. } => {
                self.cleanup_cancelled_wait_role(&role);
                self.begin_stop(child, StopNext::Cancelled);
            }
            EngineTransaction::Stopping { child, next, .. } => {
                self.cleanup_cancelled_stop_next(&next);
                self.begin_stop(child, StopNext::Cancelled);
            }
        }
    }

    fn cleanup_cancelled_wait_role(&self, role: &WaitRole) {
        if let WaitRole::Candidate(plan) = role {
            if let Some(old) = &plan.old {
                let _ = fs::remove_file(&old.effective);
            }
        }
    }

    fn cleanup_cancelled_stop_next(&self, next: &StopNext) {
        match next {
            StopNext::StartCandidate(plan) => {
                let _ = fs::remove_file(&plan.candidate);
            }
            StopNext::Recover { plan, .. } => {
                if let Some(old) = &plan.old {
                    let _ = fs::remove_file(&old.effective);
                }
            }
            StopNext::FinishRecoveryFailure { .. } | StopNext::Cancelled => {}
        }
    }

    fn finish_cancelled(&mut self) {
        self.engine_transaction = None;
        disarm_timer(&self.engine_timer);
        if let Some(child) = self.engine.take() {
            self.begin_stop(child, StopNext::Cancelled);
        } else {
            self.engine_cancel_requested = false;
            if self.layout.disabled() {
                self.last_error = None;
                self.last_error_detail = None;
                self.complete_convergence_controls();
            } else if !self.shutdown_requested {
                self.converge("post-cancel enable");
                if self.engine_transaction.is_none() {
                    self.complete_convergence_controls();
                }
            }
        }
    }

    fn finish_transaction_error(
        &mut self,
        error: EngineError,
        recovery_error: Option<EngineError>,
    ) {
        self.engine_transaction = None;
        disarm_timer(&self.engine_timer);
        let retryable = is_retryable(&error);
        self.last_error = Some(error.token());
        self.last_error_detail = error.detail();
        if let Some(recovery_error) = recovery_error {
            let note = format!("recovery also failed: {}", recovery_error.token());
            self.last_error_detail = Some(match self.last_error_detail.take() {
                Some(detail) => format!("{detail}; {note}"),
                None => note,
            });
        }
        if self.engine.is_none() && !self.layout.disabled() && !self.shutdown_requested && retryable
        {
            let step = BACKOFF_STEPS[(self.crash_count as usize).min(BACKOFF_STEPS.len() - 1)];
            self.crash_count += 1;
            self.logger.log(&format!("retry in {step}s"));
            arm_timer(&self.backoff_timer, Duration::from_secs(step));
        }
        self.run_queued_convergence();
        if self.engine_transaction.is_none() {
            self.complete_convergence_controls();
        }
    }

    fn run_queued_convergence(&mut self) {
        if !self.shutdown_requested
            && !self.layout.disabled()
            && (self.reload_requested || self.config_changed)
        {
            self.converge("queued change");
        }
    }

    fn register_new_transaction_child(&self, child: &EngineChild) -> io::Result<()> {
        epoll_add(&self.epoll, child.pidfd.as_raw_fd(), TOK_TX_PIDFD)?;
        epoll_add(&self.epoll, child.output.as_raw_fd(), TOK_TX_OUT)
    }

    fn retag_transaction_child(
        &self,
        child: &EngineChild,
        pidfd_token: u64,
        output_token: u64,
    ) -> io::Result<()> {
        epoll_retag(
            &self.epoll,
            child.pidfd.as_raw_fd(),
            pidfd_token,
            libc::EPOLLIN as u32,
        )?;
        epoll_retag(
            &self.epoll,
            child.output.as_raw_fd(),
            output_token,
            libc::EPOLLIN as u32,
        )
    }

    /// Reads and parses `config/sing-box.json`. Errors come back as
    /// `(stable token, optional detail)`.
    fn read_user_config(&self) -> Result<serde_json::Value, (String, Option<String>)> {
        let path = self.layout.sing_box_json();
        let bytes = match checks::read_capped(&path, MAX_ENGINE_CONFIG_BYTES + 1) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err((
                    "engine_config_missing".to_string(),
                    Some(format!("{} does not exist", path.display())),
                ));
            }
            Err(e) => {
                return Err((
                    format!(
                        "engine_config_unreadable:{}",
                        e.raw_os_error()
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| format!("{:?}", e.kind()))
                    ),
                    Some(e.to_string()),
                ));
            }
        };
        if bytes.len() > MAX_ENGINE_CONFIG_BYTES {
            return Err((
                "engine_config_too_large".to_string(),
                Some(format!("{} exceeds the 8 MiB limit", path.display())),
            ));
        }
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
        let state = if disabled && self.engine.is_none() && self.engine_transaction.is_none() {
            State::Disabled
        } else {
            State::Inactive
        };
        // Only a promoted generation is reported as running. A candidate may
        // already have a pid and some sockets, but exposing it here would let
        // clients mistake partial readiness for the commit point.
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
            if self.engine.is_some() || self.engine_transaction.is_some() {
                warnings.push(
                    "disable is pending: the engine has not confirmed termination".to_string(),
                );
            }
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
            protocol_version: flux_core::control_wire::PROTOCOL_VERSION,
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

fn epoll_mod_events(epoll: &OwnedFd, fd: RawFd, token: u64, events: u32) -> io::Result<()> {
    let mut event = libc::epoll_event { events, u64: token };
    // SAFETY: valid epoll fd, target fd and event struct.
    let rc = unsafe { libc::epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_MOD, fd, &mut event) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn epoll_retag(epoll: &OwnedFd, fd: RawFd, token: u64, events: u32) -> io::Result<()> {
    match epoll_mod_events(epoll, fd, token, events) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            let mut event = libc::epoll_event { events, u64: token };
            // SAFETY: valid epoll fd, target fd and event struct.
            let rc =
                unsafe { libc::epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut event) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
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
            tv_sec: after.as_secs() as _,
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
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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
