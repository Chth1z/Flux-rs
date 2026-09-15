//! Single-threaded epoll reactor: the event loop, the state machine and
//! convergence.
//!
//! Implements blueprint §10.1, §10.4 and §26: event
//! sources are signalfd, inotify, the control socket, child pidfds, child
//! output pipes and one-shot timerfds (config debounce, crash backoff,
//! engine-transaction deadlines and TC liveness). rtnetlink and the BPF fault
//! ring buffer are included. **There is no
//! periodic polling anywhere** — that is a hard product constraint, not a
//! preference; both timers here are one-shot and armed only by an event.
//!
//! Phase 6 publishes `active=1` only after policy preparation, four verified
//! engine sockets and positively verified ingress/egress TC attachment.
//!
//! Convergence is non-reentrant by construction: the loop is single-threaded,
//! while each engine transaction advances one fd/timer event at a time. Later
//! requests remain serviceable and merely queue another convergence.
//!
//! Crash backoff: 1/2/4/8/30 s, reset after 60 s of engine stability. The
//! backoff timer is armed only for retryable failures (crash, readiness
//! timeout, I/O); a config problem waits for the config to change — retrying
//! a deterministic failure on a timer would just be polling with extra steps.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use flux_core::abi::{FaultEvent, FaultKey, FaultReason};
use flux_core::config::{FluxConfig, ListMode, SubscriptionConfig};
use flux_core::control_wire::{
    Counters, EngineStatus, Request, Response, RootManagerStatus, SsidStatus, State,
};
use flux_core::engine_config::{self, MAX_ENGINE_CONFIG_BYTES};
use flux_core::selector::PackageIndex;
use flux_core::ssid::ssid_verdict;

use crate::checks;
use crate::control::{ControlConn, ControlServer};
use crate::engine::{self, EngineChild, EngineError, EngineSpec};
use crate::layout::{InstanceLock, Layout, LockError};
use crate::supervisor::{BACKOFF_RESET_AFTER, BACKOFF_STEPS, LOCK_HELD_EXIT_CODE};
use crate::time::format_utc;

/// Trailing debounce for config-directory churn: editors and `mv`-based
/// updates produce event bursts; one convergence per burst is enough.
const DEBOUNCE: Duration = Duration::from_millis(1_500);

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
const TOK_RTNETLINK: u64 = 14;
const TOK_TC_VERIFY: u64 = 15;
const TOK_BPF_RING: u64 = 16;
const TOK_SUBSCRIPTION_RESULT: u64 = 17;
const TOK_SUBSCRIPTION_TIMER: u64 = 18;
const TOK_NL80211: u64 = 19;
const TOK_CONTROL_CONN_BASE: u64 = 1_024;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound a mutating request below the CLI's 30-second socket timeout. TC
/// liveness is intentionally sequential and can exceed any small fixed budget
/// on multi-interface devices; at this deadline the daemon returns an honest
/// intermediate status instead of letting the client mistake a live daemon
/// for a missing one.
const CONTROL_CONVERGE_TIMEOUT: Duration = Duration::from_secs(20);
const CONTROL_SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(120);
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
    user: serde_json::Value,
    old: Option<OldGeneration>,
}

#[derive(Debug, Clone)]
struct PolicyCandidate {
    flux: FluxConfig,
    desired: crate::dataplane::DesiredPolicy,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SsidPolicy {
    mode: ListMode,
    entries: Vec<String>,
}

struct SsidTransport {
    socket: crate::netlink::GenlSocket,
    family: crate::netlink::Nl80211Family,
}

#[derive(Debug)]
struct PendingSubscription {
    url: String,
    raw: Vec<u8>,
    /// The engine generation built from `raw`, once candidate validation has
    /// begun. This keeps an unrelated transaction failure from discarding a
    /// fetched response that merely arrived while that transaction was live.
    generation: Option<u64>,
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
    Subscribing {
        conn: ControlConn,
        deadline: Instant,
    },
}

impl PendingControl {
    fn deadline(&self) -> Instant {
        match self {
            Self::Reading { deadline, .. }
            | Self::Writing { deadline, .. }
            | Self::Converging { deadline, .. }
            | Self::Subscribing { deadline, .. } => *deadline,
        }
    }
}

/// Runs the daemon in the foreground. Returns the process exit code.
pub fn run_daemon() -> u8 {
    let layout = Layout::product();
    let repairs = match layout.ensure() {
        Ok(repairs) => repairs,
        Err(e) => {
            eprintln!("fluxd: {e}");
            return 1;
        }
    };

    // Single instance BEFORE anything else is touched. A rejected second
    // instance exits without unlinking sockets or cleaning files (§10.3).
    let lock = match InstanceLock::acquire(&layout) {
        Ok(lock) => lock,
        Err(e @ LockError::Held(_)) => {
            eprintln!("fluxd: {e}");
            return LOCK_HELD_EXIT_CODE;
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
    for repair in repairs {
        logger.log(&format!("state root repaired: {repair}"));
    }

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
    module_wd: i32,
    config_wd: i32,
    packages_wd: Option<i32>,
    debounce_timer: OwnedFd,
    backoff_timer: OwnedFd,
    control_timer: OwnedFd,
    engine_timer: OwnedFd,
    tc_verify_timer: OwnedFd,
    subscription_timer: OwnedFd,
    subscription_worker: crate::subscription::Worker,
    server: ControlServer,
    dataplane: crate::dataplane::Manager,
    control_conns: BTreeMap<u64, PendingControl>,
    next_control_token: u64,
    engine: Option<EngineChild>,
    engine_transaction: Option<EngineTransaction>,
    /// A socket-ready child waiting for the Phase 6 TC/control commit point.
    activation_role: Option<WaitRole>,
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
    policy_error: Option<(String, Option<String>)>,
    subscription_error: Option<(String, Option<String>)>,
    subscription_retry_on_route: bool,
    default_route_was_ready: bool,
    route_recovery_epoch: u64,
    subscription_fetch_route_epoch: u64,
    subscription_schedule: Option<(String, u64)>,
    pending_subscription: Option<PendingSubscription>,
    subscription_fetch_queued: bool,
    subscription_reconfigure_queued: bool,
    crash_count: u32,
    /// Deadline of the one-shot crash retry, exposed as `backoff_seconds`.
    /// `None` means no crash retry is armed; this is never a health poll.
    backoff_until: Option<Instant>,
    reload_requested: bool,
    policy_changed: bool,
    engine_config_changed: bool,
    topology_changed: bool,
    wifi_changed: bool,
    dataplane_error_active: bool,
    config_warnings: Vec<String>,
    current_policy: Option<PolicyCandidate>,
    current_engine_user: Option<serde_json::Value>,
    ssid_transport: Option<SsidTransport>,
    ssid_setup_failure: Option<SsidPolicy>,
    ssid_status: Option<SsidStatus>,
    ssid_paused: bool,
    policy_retry_available: bool,
    /// `None` when the page size is the required 4096; otherwise the actual
    /// size. sing-box and the BPF maps both assume 4 KiB pages (§25).
    bad_page_size: Option<i64>,
    /// Root manager identity supplied by the sole boot entry, `service.sh`.
    root_manager: RootManagerStatus,
    /// Last status line written to `module.prop`, so an unchanged state does
    /// not rewrite the manager's file on every event.
    module_prop_status: Option<String>,
}

impl Reactor {
    fn new(layout: Layout, logger: Logger) -> io::Result<Self> {
        // SAFETY: signal(2) with SIG_IGN; no handler code runs.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        let spec = EngineSpec::product(&layout);
        let epoll = epoll_create()?;
        let signal_fd = make_signalfd()?;
        let (inotify_fd, module_wd, config_wd, packages_wd) = make_inotify(&layout)?;
        let debounce_timer = make_timerfd()?;
        let backoff_timer = make_timerfd()?;
        let control_timer = make_timerfd()?;
        let engine_timer = make_timerfd()?;
        let tc_verify_timer = make_timerfd()?;
        let subscription_timer = make_timerfd()?;
        let subscription_worker = crate::subscription::Worker::new()?;
        let server = ControlServer::bind(&layout.control_socket())?;
        let dataplane = crate::dataplane::Manager::open()?;
        let root_manager = root_manager_from_env();

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
        match layout.clean_stale_subscription_temps() {
            Ok(removed) if !removed.is_empty() => logger.log(&format!(
                "removed {} stale subscription cache temporary file(s)",
                removed.len()
            )),
            Ok(_) => {}
            Err(error) => logger.log(&format!(
                "stale subscription cache temporary cleanup failed: {error}"
            )),
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
        epoll_add(&epoll, tc_verify_timer.as_raw_fd(), TOK_TC_VERIFY)?;
        epoll_add(&epoll, dataplane.event_fd(), TOK_RTNETLINK)?;
        epoll_add(
            &epoll,
            subscription_worker.event_fd(),
            TOK_SUBSCRIPTION_RESULT,
        )?;
        epoll_add(
            &epoll,
            subscription_timer.as_raw_fd(),
            TOK_SUBSCRIPTION_TIMER,
        )?;

        Ok(Self {
            layout,
            spec,
            logger,
            epoll,
            signal_fd,
            inotify_fd,
            module_wd,
            config_wd,
            packages_wd,
            debounce_timer,
            backoff_timer,
            control_timer,
            engine_timer,
            tc_verify_timer,
            subscription_timer,
            subscription_worker,
            server,
            dataplane,
            control_conns: BTreeMap::new(),
            next_control_token: TOK_CONTROL_CONN_BASE,
            engine: None,
            engine_transaction: None,
            activation_role: None,
            engine_cancel_requested: false,
            shutdown_requested: false,
            engine_line: Vec::new(),
            generation_counter: 0,
            generation: 0,
            last_error: None,
            last_error_detail: None,
            policy_error: None,
            subscription_error: None,
            subscription_retry_on_route: false,
            default_route_was_ready: false,
            route_recovery_epoch: 0,
            subscription_fetch_route_epoch: 0,
            subscription_schedule: None,
            pending_subscription: None,
            subscription_fetch_queued: false,
            subscription_reconfigure_queued: false,
            crash_count: 0,
            backoff_until: None,
            reload_requested: false,
            policy_changed: false,
            engine_config_changed: false,
            topology_changed: false,
            wifi_changed: false,
            dataplane_error_active: false,
            config_warnings: Vec::new(),
            current_policy: None,
            current_engine_user: None,
            ssid_transport: None,
            ssid_setup_failure: None,
            ssid_status: None,
            ssid_paused: false,
            policy_retry_available: true,
            bad_page_size,
            root_manager,
            module_prop_status: None,
        })
    }

    fn run(&mut self) -> u8 {
        self.converge("cold start");
        self.sync_module_prop();
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
                        let topology_changed = self.topology_changed;
                        self.converge("debounced filesystem/network change");
                        if topology_changed {
                            self.maybe_retry_subscription_on_route();
                        }
                    }
                    TOK_BACKOFF => {
                        drain_timer(&self.backoff_timer);
                        self.backoff_until = None;
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
                    TOK_RTNETLINK => self.handle_rtnetlink(),
                    TOK_NL80211 => self.handle_nl80211(),
                    TOK_TC_VERIFY => self.handle_tc_verify(),
                    TOK_BPF_RING => self.handle_bpf_faults(),
                    TOK_SUBSCRIPTION_RESULT => self.handle_subscription_result(),
                    TOK_SUBSCRIPTION_TIMER => {
                        drain_timer(&self.subscription_timer);
                        self.rearm_subscription_timer();
                        self.start_scheduled_subscription_fetch("scheduled refresh");
                    }
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
                self.sync_module_prop();
                self.finish_shutdown();
                return 0;
            }
            // Once per wakeup rather than per transition: the state a user
            // should see is the settled one, and the write is skipped unless
            // the rendered line actually changed.
            self.sync_module_prop();
        }
    }

    /// Mirrors the current state into the manager's `module.prop`, so the
    /// module list doubles as a status readout (`docs/spec/interaction.md` §27.1.3).
    ///
    /// Best effort by construction: `module.prop` belongs to the manager, and
    /// a status readout must never be able to fail the daemon.
    fn sync_module_prop(&mut self) {
        let status = self.module_prop_line();
        if self.module_prop_status.as_deref() == Some(status.as_str()) {
            return;
        }
        let path = self.layout.module_prop();
        let Ok(current) = fs::read_to_string(&path) else {
            return;
        };
        let updated = flux_core::version::module_prop_with_status(&current, &status);
        if updated != current && write_replace(&path, updated.as_bytes()).is_err() {
            return;
        }
        self.module_prop_status = Some(status);
    }

    /// The one-line status the manager shows. Built from committed in-memory
    /// state only — no BPF or netlink read — because it runs on every wakeup.
    fn module_prop_line(&self) -> String {
        let dataplane = self.dataplane.status();
        if self.layout.disabled() {
            return if self.engine.is_some() || self.convergence_busy() {
                "\u{1f634} [Disabled] stopping".to_string()
            } else {
                "\u{1f634} [Disabled] toggle this module on to enable Flux".to_string()
            };
        }
        if dataplane.active
            && self.engine.is_some()
            && self.activation_role.is_none()
            && !self.ssid_paused
        {
            let ifaces: Vec<&str> = dataplane
                .ifaces
                .iter()
                .filter(|iface| iface.status == "active")
                .map(|iface| iface.name.as_str())
                .collect();
            return format!(
                "\u{1f970} [Active] gen {} \u{b7} {} apps \u{b7} {}",
                self.generation,
                dataplane.policy.selected,
                ifaces.join(", ")
            );
        }
        if self.ssid_paused {
            return "\u{1f634} [Inactive] paused on this Wi-Fi network".to_string();
        }
        match self
            .policy_error
            .as_ref()
            .map(|(token, _)| token.as_str())
            .or(self.last_error.as_deref())
        {
            Some(error) => format!("\u{1f92f} [Inactive] {error}"),
            None => "\u{1f914} [Inactive] converging".to_string(),
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
        if let Err(error) = self.dataplane.publish_inactive() {
            self.logger
                .log(&format!("cannot freeze capture during shutdown: {error}"));
        }
        disarm_timer(&self.tc_verify_timer);
        disarm_timer(&self.subscription_timer);
        if let Err(error) = self.dataplane.cancel_attachment() {
            self.logger
                .log(&format!("cannot cancel TC verification: {error}"));
        }
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
                    self.policy_retry_available = true;
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
                    let subscribing = request == Request::Subscribe;
                    let (response, stop_after) = self.dispatch_request(request);
                    let Some(response) = response else {
                        let pending = if subscribing {
                            PendingControl::Subscribing {
                                conn,
                                deadline: Instant::now() + CONTROL_SUBSCRIBE_TIMEOUT,
                            }
                        } else {
                            PendingControl::Converging {
                                conn,
                                deadline: Instant::now() + CONTROL_CONVERGE_TIMEOUT,
                            }
                        };
                        self.control_conns.insert(token, pending);
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
            PendingControl::Subscribing { conn, deadline } => {
                self.control_conns
                    .insert(token, PendingControl::Subscribing { conn, deadline });
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
        let expired = self
            .control_conns
            .iter()
            .filter_map(|(token, pending)| (pending.deadline() <= now).then_some(*token))
            .collect::<Vec<_>>();
        for token in expired {
            let Some(pending) = self.control_conns.remove(&token) else {
                continue;
            };
            let (conn, subscribing) = match pending {
                PendingControl::Converging { conn, .. } => (conn, false),
                PendingControl::Subscribing { conn, .. } => (conn, true),
                _ => continue,
            };
            self.logger
                .log("control convergence response budget elapsed; returning current status");
            let mut response = self.build_status(!subscribing && self.overall_ok());
            if subscribing {
                response
                    .warnings
                    .push("subscription refresh is still in progress".to_string());
                if response.last_error.is_none() {
                    response.last_error = Some("subscription_refresh_in_progress".to_string());
                }
            }
            let response = Box::new(response);
            if let Err(error) = conn.send_response(&response) {
                if error.kind() == io::ErrorKind::WouldBlock
                    && epoll_mod_events(&self.epoll, conn.as_raw_fd(), token, libc::EPOLLOUT as u32)
                        .is_ok()
                {
                    self.control_conns.insert(
                        token,
                        PendingControl::Writing {
                            conn,
                            response,
                            deadline: Instant::now() + CONTROL_TIMEOUT,
                            stop_after: false,
                        },
                    );
                }
            }
        }
        self.rearm_control_timer();
    }

    /// Completes commands that asked for convergence only after the engine
    /// transaction reached a terminal state. The peer remains non-blocking;
    /// backpressure transitions to the normal EPOLLOUT state.
    fn complete_convergence_controls(&mut self) {
        self.complete_waiting_controls(false, None);
        if !self.subscription_worker.is_busy()
            && !self.convergence_busy()
            && (self.pending_subscription.is_none() || !self.overall_ok())
        {
            self.complete_waiting_controls(true, None);
        }
        self.rearm_control_timer();
    }

    fn complete_waiting_controls(
        &mut self,
        subscription: bool,
        response_error: Option<(&str, &str)>,
    ) {
        let tokens: Vec<u64> = self
            .control_conns
            .iter()
            .filter_map(|(token, pending)| {
                let matches = if subscription {
                    matches!(pending, PendingControl::Subscribing { .. })
                } else {
                    matches!(pending, PendingControl::Converging { .. })
                };
                matches.then_some(*token)
            })
            .collect();
        for token in tokens {
            let Some(pending) = self.control_conns.remove(&token) else {
                continue;
            };
            let (conn, deadline) = match pending {
                PendingControl::Converging { conn, deadline }
                | PendingControl::Subscribing { conn, deadline } => (conn, deadline),
                _ => continue,
            };
            let mut response = self.build_status(response_error.is_none() && self.overall_ok());
            if let Some((token, warning)) = response_error {
                response.last_error = Some(token.to_string());
                response.warnings.push(warning.to_string());
            }
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
                if result.is_ok() && self.convergence_busy() {
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
                if result.is_ok() && self.convergence_busy() {
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
                self.policy_retry_available = true;
                self.converge("reload");
                if self.convergence_busy() {
                    return (None, false);
                }
                let ok = self.overall_ok();
                Some(self.build_status(ok))
            }
            Request::Subscribe => match self.start_subscription_fetch("manual refresh") {
                Ok(()) if self.subscription_worker.is_busy() || self.convergence_busy() => {
                    return (None, false);
                }
                Ok(()) => Some(self.build_status(self.overall_ok())),
                Err((token, detail)) => {
                    let mut response = self.build_status(false);
                    response.last_error = Some(token);
                    if let Some(detail) = detail {
                        response.warnings.push(detail);
                    }
                    Some(response)
                }
            },
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
        let mut policy_changed = false;
        let mut engine_config_changed = false;
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
                if event.mask & libc::IN_Q_OVERFLOW != 0 {
                    policy_changed = true;
                    engine_config_changed = true;
                } else if event.wd == self.module_wd && name == "disable" {
                    switch_changed = true;
                } else if event.wd == self.config_wd && !name.is_empty() {
                    // Every config child can affect policy, generation, or
                    // both. Recompute both pure outputs; generated-byte
                    // equality, not the filename, decides whether to rotate
                    // the engine (blueprint §28.6, Batch C5).
                    policy_changed = true;
                    engine_config_changed = true;
                } else if self.packages_wd == Some(event.wd) && name == "packages.list" {
                    policy_changed = true;
                }
                offset += EVENT_HEAD + name_len;
            }
        }
        // The switch acts immediately; config churn is debounced (§10.4).
        if switch_changed {
            self.converge("disable-file change");
        }
        if policy_changed || engine_config_changed {
            self.policy_changed |= policy_changed;
            self.engine_config_changed |= engine_config_changed;
            if policy_changed {
                self.policy_retry_available = true;
            }
            arm_timer(&self.debounce_timer, DEBOUNCE);
        }
    }

    fn handle_rtnetlink(&mut self) {
        match self.dataplane.drain_events() {
            Ok(crate::netlink::DrainResult::Quiet) => {}
            Ok(crate::netlink::DrainResult::Changed) => {
                self.topology_changed = true;
                arm_timer(&self.debounce_timer, DEBOUNCE);
            }
            Ok(crate::netlink::DrainResult::Resync) => {
                self.logger
                    .log("rtnetlink overrun: scheduling a full topology dump");
                self.topology_changed = true;
                arm_timer(&self.debounce_timer, DEBOUNCE);
            }
            Err(error) => {
                self.logger
                    .log(&format!("rtnetlink event read failed: {error}"));
                self.topology_changed = true;
                arm_timer(&self.debounce_timer, DEBOUNCE);
            }
        }
    }

    fn handle_nl80211(&mut self) {
        let Some(transport) = self.ssid_transport.as_mut() else {
            return;
        };
        let changed = match transport.socket.drain(transport.family.id) {
            Ok(crate::netlink::DrainResult::Quiet) => false,
            Ok(crate::netlink::DrainResult::Changed) => true,
            Ok(crate::netlink::DrainResult::Resync) => {
                self.logger
                    .log("nl80211 overrun: scheduling a fresh interface dump");
                true
            }
            Err(error) => {
                self.logger
                    .log(&format!("nl80211 event read failed: {error}"));
                true
            }
        };
        // The §26 Disabled row ignores Wi-Fi changes. The socket is still
        // drained so a subscribed descriptor can never spin epoll.
        if changed && !self.layout.disabled() {
            self.wifi_changed = true;
            arm_timer(&self.debounce_timer, DEBOUNCE);
        }
    }

    /// Reconciles the generic-netlink lifetime and returns whether `[ssid]`
    /// currently holds activation. Raw SSID bytes stay in this stack frame.
    fn evaluate_ssid(&mut self, policy: Option<&SsidPolicy>, retry_setup: bool) -> bool {
        let Some(policy) = policy.filter(|policy| !policy.entries.is_empty()) else {
            self.close_ssid_transport();
            self.ssid_setup_failure = None;
            self.ssid_status = None;
            self.ssid_paused = false;
            self.wifi_changed = false;
            return false;
        };

        // A remembered setup failure is retried when the policy that failed
        // changes, or when a policy edit asks for another attempt; otherwise
        // it stays remembered, so a device without cfg80211 is not probed on
        // every convergence.
        let retry_after_failure = (retry_setup && self.ssid_transport.is_none())
            || self
                .ssid_setup_failure
                .as_ref()
                .is_some_and(|failed| failed != policy);
        if retry_after_failure {
            self.ssid_setup_failure = None;
        }

        if self.ssid_transport.is_none() && self.ssid_setup_failure.as_ref() != Some(policy) {
            let mut socket = match crate::netlink::GenlSocket::open() {
                Ok(socket) => socket,
                Err(error) => {
                    self.mark_ssid_setup_failed(policy, "cannot open NETLINK_GENERIC", &error);
                    return false;
                }
            };
            let family = match socket.resolve_nl80211() {
                Ok(Some(family)) => family,
                Ok(None) => {
                    self.logger
                        .log("nl80211 is unavailable; the [ssid] list is not applied");
                    self.ssid_setup_failure = Some(policy.clone());
                    self.mark_ssid_unreadable();
                    return false;
                }
                Err(error) => {
                    self.mark_ssid_setup_failed(policy, "cannot resolve nl80211", &error);
                    return false;
                }
            };
            if let Err(error) = socket.join(family.mlme_group) {
                self.mark_ssid_setup_failed(policy, "cannot join nl80211 mlme", &error);
                return false;
            }
            if let Err(error) = epoll_add(&self.epoll, socket.as_raw_fd(), TOK_NL80211) {
                self.mark_ssid_setup_failed(policy, "cannot watch nl80211", &error);
                return false;
            }
            self.logger
                .log("nl80211 SSID event source joined before the initial dump");
            self.ssid_transport = Some(SsidTransport { socket, family });
            self.ssid_setup_failure = None;
        }

        let Some(transport) = self.ssid_transport.as_mut() else {
            self.mark_ssid_unreadable();
            return false;
        };
        let interfaces = match transport.socket.dump_interfaces(transport.family.id) {
            Ok(interfaces) => interfaces,
            Err(error) => {
                self.logger
                    .log(&format!("nl80211 interface dump failed: {error}"));
                self.mark_ssid_unreadable();
                return false;
            }
        };
        let follow_up = match transport.socket.drain(transport.family.id) {
            Ok(crate::netlink::DrainResult::Quiet) => false,
            Ok(crate::netlink::DrainResult::Changed) => true,
            Ok(crate::netlink::DrainResult::Resync) => {
                self.logger
                    .log("nl80211 changed during the dump; scheduling a fresh snapshot");
                true
            }
            Err(error) => {
                self.logger
                    .log(&format!("nl80211 post-dump drain failed: {error}"));
                true
            }
        };
        let connected: Vec<Vec<u8>> = interfaces
            .into_iter()
            .filter(|interface| interface.iftype == crate::netlink::NL80211_IFTYPE_STATION)
            .filter_map(|interface| interface.ssid)
            .collect();
        let connected_count = connected.len();
        let verdict = ssid_verdict(policy.mode, &policy.entries, &connected);
        self.ssid_status = Some(SsidStatus {
            connected: Some(!connected.is_empty()),
            paused: verdict.paused,
            matched_entry: verdict.matched_entry,
        });
        self.ssid_paused = verdict.paused;
        self.wifi_changed = follow_up;
        if follow_up {
            arm_timer(&self.debounce_timer, DEBOUNCE);
        }

        if verdict.paused {
            match verdict.matched_entry {
                Some(entry) => self.logger.log(&format!(
                    "{connected_count} associated station interface(s); [ssid] blacklist matched entry {entry}; paused"
                )),
                None => self.logger.log(&format!(
                    "{connected_count} associated station interface(s); [ssid] whitelist has no match; paused"
                )),
            }
        } else {
            self.logger.log(&format!(
                "{connected_count} associated station interface(s); [ssid] does not pause activation"
            ));
        }
        verdict.paused
    }

    fn mark_ssid_setup_failed(&mut self, policy: &SsidPolicy, context: &str, error: &io::Error) {
        self.logger.log(&format!("{context}: {error}"));
        self.ssid_setup_failure = Some(policy.clone());
        self.mark_ssid_unreadable();
    }

    fn mark_ssid_unreadable(&mut self) {
        self.ssid_status = Some(SsidStatus {
            connected: None,
            paused: false,
            matched_entry: None,
        });
        self.ssid_paused = false;
        self.wifi_changed = false;
    }

    fn close_ssid_transport(&mut self) {
        let Some(transport) = self.ssid_transport.take() else {
            return;
        };
        if let Err(error) = epoll_del(&self.epoll, transport.socket.as_raw_fd()) {
            self.logger
                .log(&format!("cannot remove nl80211 from epoll: {error}"));
        }
        // Dropping the sole owner closes the generic-netlink socket.
        drop(transport);
    }

    fn handle_tc_verify(&mut self) {
        drain_timer(&self.tc_verify_timer);
        self.logger.log("TC liveness verification timer fired");
        match self.dataplane.advance_attachment() {
            Ok(crate::dataplane::AttachmentProgress::Wait(delay)) => {
                self.logger.log(&format!(
                    "TC liveness verification rearmed for {}ms",
                    delay.as_millis()
                ));
                arm_timer(&self.tc_verify_timer, delay);
            }
            Ok(crate::dataplane::AttachmentProgress::Complete) => {
                if !self.capture_interface_ready() {
                    self.logger
                        .log("no usable capture interface; waiting for rtnetlink change");
                    return;
                }
                if self.activation_role.is_some() || !self.dataplane.status().active {
                    self.finish_phase6_activation();
                } else {
                    self.logger.log(
                        "Phase 6 TC attachment maintenance and liveness verification complete",
                    );
                }
                self.run_queued_convergence();
            }
            Err(error) => {
                if self.activation_role.is_some() || !self.dataplane.status().active {
                    self.fail_phase6_activation("TC liveness verification", error);
                } else {
                    self.record_dataplane_error("TC liveness verification", error);
                }
            }
        }
    }

    fn handle_bpf_faults(&mut self) {
        match self.dataplane.drain_faults() {
            Ok(events) => {
                for event in events {
                    self.logger.log(&format!(
                        "BPF fault: generation={} family={} protocol={} reason={} seq={}",
                        event.generation, event.family, event.protocol, event.reason, event.seq
                    ));

                    let Some(key) = fault_key(&event) else {
                        self.logger.log("ignoring malformed BPF fault record");
                        continue;
                    };
                    let is_current = event.generation == self.generation
                        && self.dataplane.status().active
                        && self
                            .engine
                            .as_ref()
                            .is_some_and(|child| child.params.generation == event.generation)
                        && !self.layout.disabled()
                        && !self.shutdown_requested;
                    if !is_current {
                        if let Err(error) = self.dataplane.delete_fault_latch(&key) {
                            self.logger
                                .log(&format!("cannot clear ignored BPF fault latch: {error}"));
                        }
                        self.logger.log(&format!(
                            "ignored stale/repeated BPF fault for generation {}",
                            event.generation
                        ));
                        continue;
                    }

                    // §7.4/§26: leaving Active starts with one inactive control
                    // publication. Stopping the supervised child then funnels
                    // through the normal enabled convergence path, which
                    // allocates a fresh, monotonically increasing generation.
                    if let Err(error) = self.dataplane.publish_inactive() {
                        self.record_dataplane_error("BPF fault inactive publication", error);
                    }
                    self.logger.log(&format!(
                        "generation {} faulted; capture frozen before engine restart",
                        event.generation
                    ));
                    self.engine_cancel_requested = true;
                    self.cancel_engine_work();
                }
            }
            Err(error) => self.record_dataplane_error("BPF fault ring", error),
        }
    }

    fn handle_engine_exit(&mut self) {
        if let Err(error) = self.dataplane.publish_inactive() {
            self.logger
                .log(&format!("cannot freeze capture after engine exit: {error}"));
        }
        disarm_timer(&self.tc_verify_timer);
        if let Err(error) = self.dataplane.cancel_attachment() {
            self.logger
                .log(&format!("cannot cancel TC verification: {error}"));
        }
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
        let activation_error = EngineError::Exited {
            exit: exit.clone(),
            output_head: output_head.clone(),
        };
        if let Some(role) = self.activation_role.take() {
            match role {
                WaitRole::Candidate(plan) => {
                    self.begin_candidate_failure(plan, activation_error);
                }
                WaitRole::Recovery { candidate_error } => {
                    self.finish_transaction_error(candidate_error, Some(activation_error));
                }
            }
            return;
        }
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
            self.schedule_backoff(step);
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

    fn register_bpf_ring(&mut self) -> io::Result<()> {
        let Some(fd) = self.dataplane.fault_fd() else {
            return Ok(());
        };
        // A core-topology repair may replace the entire anonymous BPF runtime.
        // The old fd is then removed from epoll by close, and Linux may reuse
        // the same numeric fd for the new ring. MOD-or-ADD proves registration
        // against the current open-file description every convergence.
        epoll_retag(&self.epoll, fd, TOK_BPF_RING, libc::EPOLLIN as u32)
    }

    fn start_phase6_attachment(&mut self, params: engine_config::EngineParams) {
        let activating = self.activation_role.is_some() || !self.dataplane.status().active;
        if activating {
            if let Err(error) =
                self.dataplane
                    .prepare_generation(params.generation, params.port_v4, params.port_v6)
            {
                self.fail_phase6_activation("inactive control publication", error);
                return;
            }
            if let Err(error) = self.dataplane.clear_fault_latch() {
                self.fail_phase6_activation("fault-latch reset", error);
                return;
            }
        }
        match self.dataplane.begin_attachment() {
            Ok(crate::dataplane::AttachmentProgress::Wait(delay)) => {
                self.logger.log(&format!(
                    "TC liveness verification armed for {}ms",
                    delay.as_millis()
                ));
                arm_timer(&self.tc_verify_timer, delay);
            }
            Ok(crate::dataplane::AttachmentProgress::Complete) => {
                disarm_timer(&self.tc_verify_timer);
                if !self.capture_interface_ready() {
                    self.logger
                        .log("no usable capture interface; waiting for rtnetlink change");
                    return;
                }
                if activating || !self.dataplane.status().active {
                    self.finish_phase6_activation();
                } else {
                    self.logger.log("Phase 6 TC maintenance complete");
                }
            }
            Err(error) => {
                if activating || !self.dataplane.status().active {
                    self.fail_phase6_activation("TC attachment", error);
                } else {
                    self.record_dataplane_error("TC attachment maintenance", error);
                }
            }
        }
    }

    fn finish_phase6_activation(&mut self) {
        let candidate_generation = match self.activation_role.as_ref() {
            Some(WaitRole::Candidate(plan)) => Some(plan.generation),
            _ => None,
        };
        if let Some(generation) = candidate_generation {
            if !self.commit_pending_subscription(Some(generation)) {
                let error = EngineError::Io(io::Error::other(
                    "subscription cache could not be committed",
                ));
                let Some(WaitRole::Candidate(plan)) = self.activation_role.take() else {
                    return;
                };
                let Some(child) = self.engine.take() else {
                    self.finish_transaction_error(error, None);
                    return;
                };
                self.begin_stop(
                    child,
                    StopNext::Recover {
                        plan,
                        candidate_error: error,
                    },
                );
                return;
            }
        }
        if let Err(error) = self.dataplane.publish_active() {
            self.fail_phase6_activation("active control publication", error);
            return;
        }
        let Some(child) = self.engine.as_ref() else {
            let error = crate::dataplane::DataplaneError {
                code: "engine_not_ready".to_string(),
                detail: "TC became ready without a supervised engine child".to_string(),
            };
            self.fail_phase6_activation("activation commit", error);
            return;
        };
        self.generation = child.params.generation;
        match self.activation_role.take() {
            Some(WaitRole::Candidate(plan)) => {
                if let Some(old) = plan.old {
                    let _ = fs::remove_file(old.effective);
                }
                self.current_engine_user = Some(plan.user);
                self.last_error = None;
                self.last_error_detail = None;
                self.logger.log(&format!(
                    "generation {}: policy, 4/4 sockets and TC verified; active=1 committed",
                    child.params.generation
                ));
            }
            Some(WaitRole::Recovery { candidate_error }) => {
                self.last_error = Some(candidate_error.token());
                self.last_error_detail = candidate_error.detail();
                self.logger.log(&format!(
                    "generation {}: old generation recovered and active=1 committed",
                    child.params.generation
                ));
            }
            None => {
                self.logger.log(&format!(
                    "generation {}: inactive data plane reactivated",
                    child.params.generation
                ));
            }
        }
        self.engine_cancel_requested = false;
        self.refresh_config_warnings();
        self.resume_queued_subscription_work();
        self.run_queued_convergence();
        if self.engine_transaction.is_none() && self.activation_role.is_none() {
            self.complete_convergence_controls();
        }
    }

    fn fail_phase6_activation(&mut self, operation: &str, error: crate::dataplane::DataplaneError) {
        let detail = format!("{operation} failed: {error}");
        let engine_error = EngineError::Io(io::Error::other(detail.clone()));
        self.record_dataplane_error(operation, error);
        let Some(role) = self.activation_role.take() else {
            let _ = self.dataplane.publish_inactive();
            return;
        };
        let Some(child) = self.engine.take() else {
            self.finish_transaction_error(engine_error, None);
            return;
        };
        let next = match role {
            WaitRole::Candidate(plan) => StopNext::Recover {
                plan,
                candidate_error: engine_error,
            },
            WaitRole::Recovery { candidate_error } => StopNext::FinishRecoveryFailure {
                candidate_error,
                recovery_error: engine_error,
            },
        };
        self.begin_stop(child, next);
    }

    fn record_dataplane_error(&mut self, operation: &str, error: crate::dataplane::DataplaneError) {
        disarm_timer(&self.tc_verify_timer);
        if let Err(cancel_error) = self.dataplane.cancel_attachment() {
            self.logger.log(&format!(
                "cannot cancel TC verification after {operation} failure: {cancel_error}"
            ));
        }
        self.logger.log(&format!("{operation} failed: {error}"));
        self.last_error = Some(error.code);
        self.last_error_detail = Some(error.detail);
        self.dataplane_error_active = true;
    }

    /// Reconciles the disable switch, network/BPF seam and engine domain.
    fn converge(&mut self, reason: &str) {
        if self.shutdown_requested {
            self.engine_cancel_requested = true;
            self.cancel_engine_work();
            return;
        }
        if self.layout.disabled() {
            self.ssid_paused = false;
            if let Some(status) = self.ssid_status.as_mut() {
                status.paused = false;
                status.matched_entry = None;
            }
            self.complete_waiting_controls(
                true,
                Some((
                    "subscription_fetch_failed:disabled",
                    "subscription refresh was cancelled because Flux was disabled",
                )),
            );
            self.rearm_control_timer();
            disarm_timer(&self.subscription_timer);
            self.subscription_schedule = None;
            self.subscription_retry_on_route = false;
            self.default_route_was_ready = false;
            self.pending_subscription = None;
            self.subscription_fetch_queued = false;
            self.subscription_reconfigure_queued = false;
            self.deactivate_runtime();
            return;
        }

        if let Some(page_size) = self.bad_page_size {
            // §25: a non-4KiB kernel cannot run this build's data plane and
            // the pinned engine binary assumes 4 KiB pages too. Halt in
            // Inactive; status explains.
            self.last_error = Some(format!("unsupported_page_size:{page_size}"));
            return;
        }
        // The state root is Flux's own: a drifted mode or owner is put back
        // and logged. Only a foreign object at one of the paths stops here.
        match self.layout.ensure() {
            Ok(repairs) => {
                for repair in repairs {
                    self.logger.log(&format!("state root repaired: {repair}"));
                }
            }
            Err(error) => {
                self.logger.log(&format!("state root unusable: {error}"));
                self.last_error = Some(error.token());
                return;
            }
        }

        // Installing or verifying our own TC filters emits rtnetlink events.
        // Restarting an in-flight verification for those events creates a
        // self-sustaining debounce loop. Preserve a pure topology change and
        // reconcile it as soon as the bounded attachment run completes. A
        // reload or config change still supersedes the attachment immediately.
        if self.topology_changed
            && self.dataplane.attachment_in_progress()
            && !self.reload_requested
            && !self.policy_changed
            && !self.engine_config_changed
        {
            self.logger
                .log("rtnetlink change deferred until TC verification completes");
            return;
        }

        let refresh_self_addresses = self.topology_changed;
        let engine_busy = self.convergence_busy();
        let need_start = !engine_busy && self.engine.is_none();
        let want_engine =
            !engine_busy && (need_start || self.reload_requested || self.engine_config_changed);
        let want_policy = self.current_policy.is_none()
            || self.reload_requested
            || self.policy_changed
            || self.topology_changed;

        let retry_ssid_setup = self.policy_changed;
        let ssid_only_change = self.wifi_changed
            && !self.reload_requested
            && !self.policy_changed
            && !self.engine_config_changed
            && !self.topology_changed;
        let was_active = self.dataplane.status().active
            && self.engine.is_some()
            && self.activation_role.is_none()
            && !self.ssid_paused;
        let mut candidate_policy = if want_policy {
            match self.read_policy_config() {
                Ok(candidate) => Some(candidate),
                Err((token, detail)) => {
                    self.logger
                        .log(&format!("policy candidate rejected: {token}"));
                    self.set_policy_error(token, detail);
                    None
                }
            }
        } else {
            None
        };
        self.policy_changed = false;

        let subscription_url_changed = candidate_policy.as_ref().is_some_and(|candidate| {
            self.current_policy.as_ref().is_some_and(|current| {
                current.flux.subscription.url != candidate.flux.subscription.url
            })
        });
        let engine_flux = candidate_policy
            .as_ref()
            .map(|policy| policy.flux.clone())
            .or_else(|| {
                self.current_policy
                    .as_ref()
                    .map(|policy| policy.flux.clone())
            });
        let mut candidate_user = if want_engine {
            match engine_flux.as_ref() {
                Some(flux)
                    if subscription_url_changed
                        && !flux.subscription.url.is_empty()
                        && self.current_engine_user.is_some()
                        && self
                            .pending_subscription
                            .as_ref()
                            .is_none_or(|pending| pending.url != flux.subscription.url) =>
                {
                    // A new URL has no matching cache yet. Keep the current
                    // generated artifact until its fetch completes instead of
                    // rotating to a template-only intermediate generation.
                    self.current_engine_user.clone()
                }
                Some(flux) => {
                    self.ensure_subscription_schedule(&flux.subscription);
                    match self.read_engine_config(flux, !subscription_url_changed) {
                        Ok(user) => {
                            if self
                                .subscription_error
                                .as_ref()
                                .is_some_and(|(token, _)| token == "flux_config_invalid")
                            {
                                self.clear_subscription_error();
                            }
                            if self.policy_error.is_none()
                                && self.last_error.as_deref() == Some("flux_config_invalid")
                            {
                                self.last_error = None;
                                self.last_error_detail = None;
                            }
                            Some(user)
                        }
                        Err((token, _)) if token == "subscription_cache_missing" => {
                            if self.subscription_retry_on_route {
                                self.logger
                                    .log("engine generation is waiting for default-route recovery");
                            } else {
                                match self.start_subscription_fetch_with(
                                    &flux.subscription,
                                    "raw cache is missing",
                                ) {
                                    Ok(()) => self.logger.log(
                                        "engine generation is waiting for a subscription response",
                                    ),
                                    Err((token, detail)) => {
                                        self.set_subscription_error(token, detail);
                                    }
                                }
                            }
                            None
                        }
                        Err((token, detail)) => {
                            self.logger
                                .log(&format!("engine candidate rejected: {token}"));
                            if token.starts_with("subscription_") {
                                self.set_subscription_error(token, detail);
                            } else {
                                self.last_error = Some(token);
                                self.last_error_detail = detail;
                            }
                            None
                        }
                    }
                }
                None => {
                    self.last_error = Some("flux_config_invalid".to_string());
                    self.last_error_detail =
                        Some("no valid policy exists for the engine candidate".to_string());
                    None
                }
            }
        } else {
            None
        };

        // A new policy must be safe for the currently active engine before it
        // is installed. A new engine is validated against the policy that will
        // remain installed if its sibling domain is invalid (§10.5).
        if let Some(policy) = candidate_policy.as_ref() {
            if let Some(user) = self
                .current_engine_user
                .as_ref()
                .or(candidate_user.as_ref())
            {
                if let Err(error) = checks::validate_fakeip_bypass(&policy.flux, user) {
                    self.logger
                        .log(&format!("policy candidate rejected: {error}"));
                    self.set_policy_error("fakeip_bypass_overlap".to_string(), Some(error));
                    candidate_policy = None;
                }
            }
        }
        if let Some(user) = candidate_user.as_ref() {
            let flux = candidate_policy
                .as_ref()
                .map(|policy| &policy.flux)
                .or_else(|| self.current_policy.as_ref().map(|policy| &policy.flux));
            match flux {
                Some(flux) => {
                    if let Err(error) = checks::validate_fakeip_bypass(flux, user) {
                        self.logger
                            .log(&format!("engine candidate rejected: {error}"));
                        self.last_error = Some("fakeip_bypass_overlap".to_string());
                        self.last_error_detail = Some(error);
                        candidate_user = None;
                    }
                }
                None => {
                    self.last_error = Some("flux_config_invalid".to_string());
                    self.last_error_detail =
                        Some("no valid policy exists for the engine candidate".to_string());
                    candidate_user = None;
                }
            }
        }

        let ssid_policy = candidate_policy
            .as_ref()
            .map(|policy| &policy.flux)
            .or_else(|| self.current_policy.as_ref().map(|policy| &policy.flux))
            .map(|flux| SsidPolicy {
                mode: flux.ssid_mode,
                entries: flux.ssids.clone(),
            });
        if self.evaluate_ssid(ssid_policy.as_ref(), retry_ssid_setup) {
            self.deactivate_runtime();
            return;
        }
        if ssid_only_change && was_active && !engine_busy {
            return;
        }

        if !engine_busy && self.engine.is_none() && candidate_user.is_none() {
            // Cold invalid input performs stale cleanup only and cannot create
            // a topology or an inactive BPF runtime (§8.7).
            self.dataplane.converge(false);
            self.reload_requested = false;
            self.engine_config_changed = false;
            self.topology_changed = false;
            return;
        }

        disarm_timer(&self.tc_verify_timer);
        if let Err(error) = self.dataplane.cancel_attachment() {
            self.record_dataplane_error("TC verification cancellation", error);
            return;
        }
        if let Some(policy) = candidate_policy.as_ref() {
            self.dataplane.stage_interface_policy(&policy.desired);
        }
        self.dataplane.converge_with_bpf(true, crate::BPF_OBJECT);
        if let Some(error) = self.dataplane.status().error.clone() {
            disarm_timer(&self.tc_verify_timer);
            if let Err(cancel_error) = self.dataplane.cancel_attachment() {
                self.logger
                    .log(&format!("cannot cancel TC verification: {cancel_error}"));
            }
            self.logger
                .log(&format!("data-plane convergence blocked: {error}"));
            self.last_error = Some(error.code.clone());
            self.last_error_detail = Some(error.detail.clone());
            self.dataplane_error_active = true;
            if self.engine.is_some() || self.engine_transaction.is_some() {
                self.engine_cancel_requested = true;
                self.cancel_engine_work();
            }
            return;
        }
        if let Err(error) = self.register_bpf_ring() {
            self.last_error = Some("ringbuf_epoll_register_failed".to_string());
            self.last_error_detail = Some(error.to_string());
            self.logger
                .log(&format!("cannot register BPF fault ring: {error}"));
            return;
        }
        if self.dataplane_error_active {
            self.last_error = None;
            self.last_error_detail = None;
            self.dataplane_error_active = false;
        }

        if let Some(policy) = candidate_policy {
            match self.dataplane.apply_policy(&policy.desired) {
                Ok(()) => {
                    self.current_policy = Some(policy);
                    self.policy_retry_available = true;
                    self.clear_policy_error();
                    self.configure_subscription(subscription_url_changed);
                    self.refresh_config_warnings();
                }
                Err(error) => {
                    self.set_policy_error(error.code.clone(), Some(error.detail.clone()));
                    self.queue_policy_retry();
                    self.record_dataplane_error("policy convergence", error);
                    if self.current_policy.is_none() {
                        candidate_user = None;
                    }
                }
            }
        } else if refresh_self_addresses {
            if let Some(desired) = self
                .current_policy
                .as_ref()
                .map(|policy| policy.desired.clone())
            {
                if let Err(error) = self.dataplane.apply_policy(&desired) {
                    self.set_policy_error(error.code.clone(), Some(error.detail.clone()));
                    self.queue_policy_retry();
                    self.record_dataplane_error("self-address refresh", error);
                }
            }
        }
        if self.subscription_schedule.is_none() && self.current_policy.is_some() {
            self.configure_subscription(false);
        }
        self.topology_changed = false;

        // A socket-ready candidate can legitimately wait with active=0 while
        // the device has no upstream. A later rtnetlink event must resume its
        // TC phase instead of being trapped behind `convergence_busy()`.
        if self.activation_role.is_some() {
            if let Some(params) = self.engine.as_ref().map(|child| child.params) {
                self.start_phase6_attachment(params);
            }
            return;
        }

        if engine_busy {
            self.logger.log(&format!(
                "{reason}: engine transaction already in progress; queued"
            ));
            return;
        }

        self.reload_requested = false;
        self.engine_config_changed = false;
        let need_switch = self.engine.is_some()
            && candidate_user.as_ref().is_some_and(|user| {
                self.current_engine_user
                    .as_ref()
                    .is_none_or(|current| !generated_bytes_equal(current, user))
            });
        if !need_start && !need_switch {
            if candidate_user.is_some() {
                let committed = self.commit_pending_subscription(None);
                if committed
                    && self.policy_error.is_none()
                    && self.subscription_error.is_none()
                    && !self.dataplane_error_active
                {
                    self.last_error = None;
                    self.last_error_detail = None;
                }
            } else {
                self.pending_subscription = None;
            }
            if let Some(params) = self.engine.as_ref().map(|child| child.params) {
                self.start_phase6_attachment(params);
            }
            return;
        }
        let Some(user) = candidate_user else {
            return;
        };

        self.generation_counter += 1;
        let generation = self.generation_counter;
        self.cancel_backoff();
        self.logger.log(&format!(
            "generation {generation}: transaction start ({reason})"
        ));
        self.start_generation_check(user, generation);
    }

    /// The one deactivation tail shared by the module switch and an SSID
    /// pause (§29.5). It freezes capture, stops all engine work, and preserves
    /// a complete authority-file recomputation for the next activation.
    fn deactivate_runtime(&mut self) {
        disarm_timer(&self.tc_verify_timer);
        if let Err(error) = self.dataplane.cancel_attachment() {
            self.logger
                .log(&format!("cannot cancel TC verification: {error}"));
        }
        self.dataplane.converge(false);
        self.engine_cancel_requested = true;
        self.cancel_engine_work();
        self.reload_requested = true;
        self.policy_changed = true;
        self.engine_config_changed = true;
        self.topology_changed = false;
        self.cancel_backoff();
    }

    fn start_generation_check(&mut self, user: serde_json::Value, generation: u64) {
        if let (Some(pending), Some(policy)) = (
            self.pending_subscription.as_mut(),
            self.current_policy.as_ref(),
        ) {
            if pending.url == policy.flux.subscription.url {
                pending.generation = Some(generation);
            }
        }
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
                user,
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
                        if let Err(error) = self.dataplane.publish_inactive() {
                            self.logger.log(&format!(
                                "generation {}: cannot freeze capture before switch: {error}",
                                plan.generation
                            ));
                            let _ = fs::remove_file(&plan.candidate);
                            self.engine = Some(child);
                            self.finish_transaction_error(
                                EngineError::Io(io::Error::other(error.to_string())),
                                None,
                            );
                            return;
                        }
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
        let params = child.params;
        self.logger.log(&format!(
            "generation {}: 4/4 sockets verified by pid+inode; waiting for Phase 6 commit (pid {}, starttime {})",
            child.params.generation, child.pid, child.start_time
        ));
        self.engine = Some(child);
        self.activation_role = Some(role);
        self.engine_cancel_requested = false;
        self.start_phase6_attachment(params);
    }

    fn begin_candidate_failure(&mut self, mut plan: SwitchPlan, error: EngineError) {
        self.discard_pending_subscription_generation(plan.generation);
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
        let failed_generation = match &next {
            StopNext::StartCandidate(plan) | StopNext::Recover { plan, .. } => {
                Some(plan.generation)
            }
            StopNext::FinishRecoveryFailure { .. } | StopNext::Cancelled => None,
        };
        if let Some(generation) = failed_generation {
            self.discard_pending_subscription_generation(generation);
        }
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
        self.resume_queued_subscription_work();
        self.complete_convergence_controls();
        self.schedule_backoff(1);
    }

    fn cancel_engine_work(&mut self) {
        let Some(transaction) = self.engine_transaction.take() else {
            if let Some(role) = self.activation_role.take() {
                self.cleanup_cancelled_wait_role(&role);
            }
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
                if !self.convergence_busy() {
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
        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.generation.is_some())
        {
            self.pending_subscription = None;
        }
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
            self.schedule_backoff(step);
        }
        self.resume_queued_subscription_work();
        self.run_queued_convergence();
        if !self.convergence_busy() {
            self.complete_convergence_controls();
        }
    }

    fn run_queued_convergence(&mut self) {
        if !self.shutdown_requested
            && !self.layout.disabled()
            && (self.reload_requested
                || self.policy_changed
                || self.engine_config_changed
                || self.topology_changed)
        {
            self.converge("queued change");
        }
    }

    fn subscription_config_from_authority(
        &self,
    ) -> Result<SubscriptionConfig, (String, Option<String>)> {
        let path = self.layout.flux_toml();
        let flux = match checks::read_capped(&path, flux_core::config::MAX_CONFIG_BYTES + 1) {
            Ok(bytes) => checks::parse_flux_config(&self.layout, &bytes).map_err(|error| {
                (
                    "flux_config_invalid".to_string(),
                    Some(checks::describe_flux_error(&error)),
                )
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => FluxConfig::default(),
            Err(error) => {
                return Err((
                    "flux_config_unreadable".to_string(),
                    Some(format!("{}: {error}", path.display())),
                ));
            }
        };
        Ok(flux.subscription)
    }

    fn start_subscription_fetch(&mut self, reason: &str) -> Result<(), (String, Option<String>)> {
        if self.layout.disabled() {
            return Err((
                "subscription_fetch_failed:disabled".to_string(),
                Some("subscription refresh is unavailable while Flux is disabled".to_string()),
            ));
        }
        let config = self.subscription_config_from_authority()?;
        self.start_subscription_fetch_with(&config, reason)?;
        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.generation.is_none())
        {
            self.engine_config_changed = true;
            self.converge("pending subscription refresh");
        }
        Ok(())
    }

    fn start_subscription_fetch_with(
        &mut self,
        config: &SubscriptionConfig,
        reason: &str,
    ) -> Result<(), (String, Option<String>)> {
        if self.layout.disabled() {
            return Err((
                "subscription_fetch_failed:disabled".to_string(),
                Some("subscription refresh is unavailable while Flux is disabled".to_string()),
            ));
        }
        if config.url.is_empty() {
            return Err((
                "subscription_fetch_failed:disabled".to_string(),
                Some("subscription.url is empty".to_string()),
            ));
        }
        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.url == config.url)
        {
            return Ok(());
        }
        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.generation.is_some())
        {
            self.subscription_fetch_queued = true;
            return Ok(());
        }
        if self.subscription_worker.is_busy() {
            return Ok(());
        }
        self.pending_subscription = None;
        self.refresh_default_route_observation("subscription fetch start");
        self.subscription_fetch_route_epoch = self.route_recovery_epoch;
        let request = crate::subscription::FetchRequest {
            url: config.url.clone(),
            timeout: Duration::from_secs(config.timeout),
            retries: config.retries,
        };
        match self.subscription_worker.start(request) {
            Ok(true) => {
                self.logger
                    .log(&format!("subscription fetch started ({reason})"));
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(error) => Err((
                "subscription_fetch_failed:worker".to_string(),
                Some(format!("cannot start subscription worker: {error}")),
            )),
        }
    }

    fn handle_subscription_result(&mut self) {
        let Some(completed) = self.subscription_worker.take_result() else {
            return;
        };
        let config = match self.subscription_config_from_authority() {
            Ok(config) => config,
            Err((token, detail)) => {
                self.set_subscription_error(token, detail);
                self.complete_convergence_controls();
                return;
            }
        };

        if completed.url != config.url || config.url.is_empty() || self.layout.disabled() {
            self.logger
                .log("discarded a subscription result for a superseded configuration");
            let unavailable = config.url.is_empty() || self.layout.disabled();
            if !unavailable {
                if let Err((token, detail)) =
                    self.start_subscription_fetch_with(&config, "configured URL changed")
                {
                    self.set_subscription_error(token, detail);
                }
            } else {
                self.complete_waiting_controls(
                    true,
                    Some((
                        "subscription_fetch_failed:disabled",
                        "subscription refresh was discarded because subscription is disabled",
                    )),
                );
                self.rearm_control_timer();
            }
            if !self.subscription_worker.is_busy() {
                self.complete_convergence_controls();
            }
            return;
        }

        let raw = match completed.result {
            Ok(raw) => raw,
            Err(error) => {
                self.pending_subscription = None;
                self.set_subscription_error(error.token, Some(error.detail));
                self.refresh_default_route_observation("subscription fetch failure");
                if self.route_recovery_epoch != self.subscription_fetch_route_epoch {
                    self.subscription_retry_on_route = false;
                    self.logger.log(
                        "default route recovered while the subscription request was in flight; retrying once",
                    );
                    self.start_scheduled_subscription_fetch(
                        "default route recovered during failed request",
                    );
                    return;
                }
                self.subscription_retry_on_route = true;
                disarm_timer(&self.subscription_timer);
                self.logger
                    .log("subscription fetch failed; waiting for default-route recovery");
                self.complete_convergence_controls();
                return;
            }
        };

        // A completed HTTP exchange ends the route-recovery wait even when
        // its content is rejected. Resume the user-configured refresh cadence.
        self.subscription_retry_on_route = false;
        self.rearm_subscription_timer();

        if let Err(error) = flux_core::subscription::parse_and_refine(&raw, &config) {
            let (token, detail) = subscription_error_status(&error);
            self.pending_subscription = None;
            self.set_subscription_error(token, Some(detail));
            self.logger.log("subscription content was rejected");
            self.complete_convergence_controls();
            return;
        }

        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.generation.is_some())
        {
            // Never replace the raw input that an in-flight generation is
            // waiting to commit. Re-fetch current authority after that
            // transaction reaches a terminal state.
            self.subscription_fetch_queued = true;
            self.logger.log(
                "deferred a newer subscription response until the active transaction finishes",
            );
            if !self.convergence_busy() {
                self.resume_queued_subscription_work();
            }
            return;
        }

        self.pending_subscription = Some(PendingSubscription {
            url: completed.url,
            raw,
            generation: None,
        });
        self.subscription_retry_on_route = false;
        self.clear_subscription_error();
        // The fetch authority is the file on disk, which may be newer than
        // `current_policy` when a manual command races the inotify debounce.
        // Re-read both domains so the validated response is applied to the
        // exact policy that requested it.
        self.policy_changed = true;
        self.policy_retry_available = true;
        self.engine_config_changed = true;
        self.converge("subscription refresh");
        if !self.convergence_busy() {
            self.complete_convergence_controls();
        }
    }

    fn configure_subscription(&mut self, url_changed: bool) {
        let Some(config) = self
            .current_policy
            .as_ref()
            .map(|policy| policy.flux.subscription.clone())
        else {
            return;
        };
        let raw_path = self.layout.subscription_raw();

        if config.url.is_empty() {
            self.complete_waiting_controls(
                true,
                Some((
                    "subscription_fetch_failed:disabled",
                    "subscription refresh was cancelled because subscription.url is empty",
                )),
            );
            self.rearm_control_timer();
        }

        if url_changed
            && self
                .pending_subscription
                .as_ref()
                .is_some_and(|pending| pending.generation.is_some())
        {
            self.subscription_reconfigure_queued = true;
            self.subscription_schedule = None;
            disarm_timer(&self.subscription_timer);
            return;
        }

        if config.url.is_empty() {
            self.subscription_schedule = None;
            self.subscription_retry_on_route = false;
            self.pending_subscription = None;
            self.subscription_fetch_queued = false;
            self.subscription_reconfigure_queued = false;
            disarm_timer(&self.subscription_timer);
            if self.remove_subscription_cache_files("subscription was disabled") {
                self.clear_subscription_error();
            }
            return;
        }

        let pending_matches = self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.url == config.url);
        let cache_matches = match self.subscription_cache_matches(&config.url) {
            Ok(matches) => matches,
            Err(error) => {
                self.set_subscription_error(
                    "subscription_fetch_failed:cache_read".to_string(),
                    Some(format!(
                        "cannot read {}: {error}",
                        self.layout.subscription_url_binding().display()
                    )),
                );
                false
            }
        } && raw_path.is_file();
        let needs_fetch = url_changed || !cache_matches;
        if needs_fetch {
            if !pending_matches {
                self.pending_subscription = None;
            }
            self.remove_subscription_cache_files(if url_changed {
                "the configured URL changed"
            } else {
                "the cache authority binding was absent or stale"
            });
        }

        self.ensure_subscription_schedule(&config);

        if needs_fetch && !pending_matches && (!self.subscription_retry_on_route || url_changed) {
            if let Err((token, detail)) =
                self.start_subscription_fetch_with(&config, "subscription configuration")
            {
                self.set_subscription_error(token, detail);
            }
        }
    }

    fn ensure_subscription_schedule(&mut self, config: &SubscriptionConfig) {
        if config.url.is_empty() {
            self.subscription_schedule = None;
            disarm_timer(&self.subscription_timer);
            return;
        }
        let schedule = (config.url.clone(), config.interval);
        if self.subscription_schedule.as_ref() != Some(&schedule) {
            self.subscription_schedule = Some(schedule);
            self.rearm_subscription_timer();
        }
    }

    fn subscription_cache_matches(&self, url: &str) -> io::Result<bool> {
        let path = self.layout.subscription_url_binding();
        let bytes =
            match checks::read_capped(&path, flux_core::config::MAX_CONFIG_BYTES.saturating_add(1))
            {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
        if bytes.len() > flux_core::config::MAX_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "subscription URL binding exceeds the Flux config limit",
            ));
        }
        Ok(bytes == url.as_bytes())
    }

    fn remove_subscription_cache_files(&mut self, reason: &str) -> bool {
        let mut ok = true;
        for path in [
            self.layout.subscription_raw(),
            self.layout.subscription_url_binding(),
        ] {
            match fs::remove_file(&path) {
                Ok(()) => self.logger.log(&format!(
                    "removed subscription cache state because {reason}"
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    ok = false;
                    self.set_subscription_error(
                        "subscription_fetch_failed:cache_remove".to_string(),
                        Some(format!("cannot remove {}: {error}", path.display())),
                    );
                }
            }
        }
        ok
    }

    fn rearm_subscription_timer(&self) {
        let config = self
            .current_policy
            .as_ref()
            .map(|policy| policy.flux.subscription.clone())
            .or_else(|| self.subscription_config_from_authority().ok());
        let Some(config) = config else {
            disarm_timer(&self.subscription_timer);
            return;
        };
        if self.shutdown_requested
            || self.layout.disabled()
            || self.subscription_retry_on_route
            || config.url.is_empty()
            || config.interval == 0
        {
            disarm_timer(&self.subscription_timer);
        } else {
            arm_timer(
                &self.subscription_timer,
                Duration::from_secs(config.interval),
            );
        }
    }

    fn start_scheduled_subscription_fetch(&mut self, reason: &str) {
        if self.subscription_retry_on_route {
            disarm_timer(&self.subscription_timer);
            return;
        }
        let config = self
            .current_policy
            .as_ref()
            .map(|policy| policy.flux.subscription.clone())
            .or_else(|| self.subscription_config_from_authority().ok());
        let Some(config) = config else {
            return;
        };
        if config.url.is_empty() {
            return;
        }
        if let Err((token, detail)) = self.start_subscription_fetch_with(&config, reason) {
            self.set_subscription_error(token, detail);
            self.complete_convergence_controls();
        }
    }

    fn maybe_retry_subscription_on_route(&mut self) {
        let recovery_epoch = self.route_recovery_epoch;
        self.refresh_default_route_observation("subscription route recovery");
        if !self.subscription_retry_on_route || self.route_recovery_epoch == recovery_epoch {
            return;
        }
        self.subscription_retry_on_route = false;
        self.start_scheduled_subscription_fetch("default route recovered");
    }

    fn refresh_default_route_observation(&mut self, context: &str) {
        let route_ready = match self.dataplane.refresh_default_route_ready() {
            Ok(ready) => ready,
            Err(error) => {
                self.logger.log(&format!(
                    "cannot evaluate the default route during {context}: {error}"
                ));
                return;
            }
        };
        if !self.default_route_was_ready && route_ready {
            self.route_recovery_epoch = self.route_recovery_epoch.wrapping_add(1);
        }
        self.default_route_was_ready = route_ready;
    }

    fn resume_queued_subscription_work(&mut self) {
        if self.convergence_busy() {
            return;
        }
        if self.subscription_reconfigure_queued {
            self.subscription_reconfigure_queued = false;
            self.subscription_fetch_queued = false;
            self.engine_config_changed = true;
            let url_changed = self
                .current_policy
                .as_ref()
                .map(|policy| {
                    !self
                        .subscription_cache_matches(&policy.flux.subscription.url)
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            self.configure_subscription(url_changed);
            return;
        }
        if self.subscription_fetch_queued {
            self.subscription_fetch_queued = false;
            if let Err((token, detail)) =
                self.start_subscription_fetch("queued subscription refresh")
            {
                self.set_subscription_error(token, detail);
            }
        }
    }

    fn commit_pending_subscription(&mut self, generation: Option<u64>) -> bool {
        let should_commit = self.pending_subscription.as_ref().is_some_and(|pending| {
            pending.generation == generation
                && (generation.is_some()
                    || self
                        .current_policy
                        .as_ref()
                        .is_some_and(|policy| policy.flux.subscription.url == pending.url))
        });
        if !should_commit {
            return true;
        }
        let pending = self
            .pending_subscription
            .take()
            .expect("pending subscription was just matched");
        let path = self.layout.subscription_raw();
        let binding_path = self.layout.subscription_url_binding();
        let unchanged = fs::read(&path)
            .map(|current| current == pending.raw)
            .unwrap_or(false);
        let raw_result = if unchanged {
            Ok(())
        } else {
            write_private_replace(&path, &pending.raw)
        };
        let binding_unchanged = fs::read(&binding_path)
            .map(|current| current == pending.url.as_bytes())
            .unwrap_or(false);
        let result = raw_result.and_then(|()| {
            if binding_unchanged {
                Ok(())
            } else {
                // Raw first, authority second: a crash between the renames can
                // only leave an unbound response, never bind old raw to a new
                // URL.
                write_private_replace(&binding_path, pending.url.as_bytes())
            }
        });
        match result {
            Ok(()) => {
                self.clear_subscription_error();
                self.logger.log(if unchanged {
                    "subscription cache already matched the accepted response"
                } else {
                    "subscription cache committed atomically"
                });
                true
            }
            Err(error) => {
                self.set_subscription_error(
                    "subscription_fetch_failed:cache_write".to_string(),
                    Some(format!(
                        "cannot write subscription cache state ({} or {}): {error}",
                        path.display(),
                        binding_path.display()
                    )),
                );
                self.logger.log("subscription cache commit failed");
                false
            }
        }
    }

    fn discard_pending_subscription_generation(&mut self, generation: u64) {
        if self
            .pending_subscription
            .as_ref()
            .is_some_and(|pending| pending.generation == Some(generation))
        {
            self.pending_subscription = None;
        }
    }

    fn convergence_busy(&self) -> bool {
        self.engine_transaction.is_some() || self.activation_role.is_some()
    }

    fn queue_policy_retry(&mut self) {
        if !self.policy_retry_available {
            return;
        }
        self.policy_retry_available = false;
        self.policy_changed = true;
        arm_timer(&self.debounce_timer, DEBOUNCE);
    }

    fn set_policy_error(&mut self, token: String, detail: Option<String>) {
        self.policy_error = Some((token.clone(), detail.clone()));
        self.last_error = Some(token);
        self.last_error_detail = detail;
    }

    fn clear_policy_error(&mut self) {
        let Some((token, _)) = self.policy_error.take() else {
            return;
        };
        if self.last_error.as_deref() == Some(token.as_str()) {
            self.last_error = None;
            self.last_error_detail = None;
        }
    }

    fn set_subscription_error(&mut self, token: String, detail: Option<String>) {
        self.subscription_error = Some((token.clone(), detail.clone()));
        self.last_error = Some(token);
        self.last_error_detail = detail;
    }

    fn clear_subscription_error(&mut self) {
        let Some((token, _)) = self.subscription_error.take() else {
            return;
        };
        if self.last_error.as_deref() == Some(token.as_str()) {
            self.last_error = None;
            self.last_error_detail = None;
        }
    }

    fn overall_ok(&self) -> bool {
        self.last_error.is_none()
            && self.policy_error.is_none()
            && self.subscription_error.is_none()
    }

    fn schedule_backoff(&mut self, seconds: u64) {
        let delay = Duration::from_secs(seconds);
        self.backoff_until = Some(Instant::now() + delay);
        arm_timer(&self.backoff_timer, delay);
    }

    fn cancel_backoff(&mut self) {
        self.backoff_until = None;
        disarm_timer(&self.backoff_timer);
    }

    fn backoff_seconds(&self) -> u64 {
        let Some(deadline) = self.backoff_until else {
            return 0;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() != 0))
    }

    fn capture_interface_ready(&self) -> bool {
        self.dataplane.status().attachment_ready
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

    /// Reads only the engine domain. Policy parsing and package resolution are
    /// deliberately independent so a broken sibling file cannot roll back a
    /// valid update (§10.5).
    fn read_engine_config(
        &self,
        flux: &FluxConfig,
        use_cache: bool,
    ) -> Result<serde_json::Value, (String, Option<String>)> {
        let path = self.layout.template_json();
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
                Some("template.json is not UTF-8".to_string()),
            )
        })?;
        let template = engine_config::parse_jsonc(&text)
            .map_err(|e| ("engine_config_invalid".to_string(), Some(e.to_string())))?;

        let nodes = if flux.subscription.url.is_empty() {
            Vec::new()
        } else {
            let pending = self.pending_subscription.as_ref().and_then(|pending| {
                (pending.url == flux.subscription.url).then_some(pending.raw.as_slice())
            });
            let cache_matches = if use_cache {
                self.subscription_cache_matches(&flux.subscription.url)
                    .map_err(|error| {
                        (
                            "subscription_fetch_failed:cache_read".to_string(),
                            Some(format!(
                                "cannot read {}: {error}",
                                self.layout.subscription_url_binding().display()
                            )),
                        )
                    })?
            } else {
                false
            };
            let cached;
            let raw = if let Some(raw) = pending {
                raw
            } else if cache_matches {
                let raw_path = self.layout.subscription_raw();
                cached = match checks::read_capped(
                    &raw_path,
                    crate::subscription::MAX_SUBSCRIPTION_BYTES + 1,
                ) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Err((
                            "subscription_cache_missing".to_string(),
                            Some(format!("{} does not exist", raw_path.display())),
                        ));
                    }
                    Err(error) => {
                        return Err((
                            "subscription_fetch_failed:cache_read".to_string(),
                            Some(format!("cannot read {}: {error}", raw_path.display())),
                        ));
                    }
                };
                if cached.len() > crate::subscription::MAX_SUBSCRIPTION_BYTES {
                    return Err((
                        "subscription_fetch_failed:too_large".to_string(),
                        Some(format!(
                            "{} exceeds the {}-byte limit",
                            raw_path.display(),
                            crate::subscription::MAX_SUBSCRIPTION_BYTES
                        )),
                    ));
                }
                cached.as_slice()
            } else {
                return Err((
                    "subscription_cache_missing".to_string(),
                    Some("no raw response matches the configured subscription URL".to_string()),
                ));
            };
            flux_core::subscription::parse_and_refine(raw, &flux.subscription).map_err(|error| {
                let (token, detail) = subscription_error_status(&error);
                (token, Some(detail))
            })?
        };

        engine_config::generate_from_template(&template, &nodes).map_err(|error| {
            let token = match error {
                engine_config::EngineConfigError::UnfilledGroups(_) => "engine_config_unfilled",
                _ => "engine_config_invalid",
            };
            (
                token.to_string(),
                Some(engine::describe_config_error(&error)),
            )
        })
    }

    fn read_policy_config(&self) -> Result<PolicyCandidate, (String, Option<String>)> {
        let flux = match checks::read_capped(
            &self.layout.flux_toml(),
            flux_core::config::MAX_CONFIG_BYTES + 1,
        ) {
            Ok(bytes) => checks::parse_flux_config(&self.layout, &bytes).map_err(|error| {
                (
                    "flux_config_invalid".to_string(),
                    Some(checks::describe_flux_error(&error)),
                )
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => FluxConfig::default(),
            Err(error) => {
                return Err((
                    "flux_config_unreadable".to_string(),
                    Some(error.to_string()),
                ));
            }
        };

        let mut warnings = Vec::new();
        let selected_uids =
            if flux.apps_mode == flux_core::config::ListMode::Whitelist && flux.apps.is_empty() {
                warnings.push("flux.toml selects no apps: nothing will be proxied".to_string());
                BTreeSet::new()
            } else {
                let packages = crate::packages::read().map_err(|error| {
                    (
                        "packages_list_unreadable".to_string(),
                        Some(error.to_string()),
                    )
                })?;
                let index = PackageIndex::parse(&packages);
                // Diagnose every entry before resolving the set: set resolution
                // stops at the first bad selector without naming it, and the
                // user needs every offending line at once.
                let failures: Vec<String> = flux
                    .apps
                    .iter()
                    .filter_map(|selector| {
                        index
                            .resolve(selector)
                            .err()
                            .map(|error| checks::describe_selector_failure(selector, &error))
                    })
                    .collect();
                if !failures.is_empty() {
                    return Err(("selector_invalid".to_string(), Some(failures.join("; "))));
                }
                let selected = flux.resolve_selected_uids(&index).map_err(|error| {
                    (
                        "flux_config_invalid".to_string(),
                        Some(checks::describe_flux_error(&error)),
                    )
                })?;
                for selector in &flux.apps {
                    let selection = index.resolve(selector).map_err(|error| {
                        (
                            "selector_invalid".to_string(),
                            Some(checks::describe_selector_failure(selector, &error)),
                        )
                    })?;
                    if let Some(warning) = checks::system_uid_warning(selector, selection.uid) {
                        warnings.push(warning);
                    }
                    let siblings = index
                        .shared_with(selection.uid % flux_core::abi::USER_ID_STRIDE)
                        .into_iter()
                        .filter(|package| *package != selector.package)
                        .collect::<Vec<_>>();
                    if !siblings.is_empty() {
                        warnings.push(format!(
                            "uid {} also covers: {}",
                            selection.uid,
                            siblings.join(", ")
                        ));
                    }
                }
                selected
            };

        let (fixed_v4, fixed_v6) = FluxConfig::fixed_bypass();
        // Insert user policy first so an exact duplicate in the mechanism set
        // is forced back to RESERVED rather than weakening the invariant.
        let bypass_v4 = flux
            .bypass_v4
            .iter()
            .copied()
            .map(flux_core::cidr::BypassEntry::policy)
            .chain(fixed_v4.iter().copied())
            .map(|entry| (entry.cidr.to_lpm_key(), entry.tag))
            .collect();
        let bypass_v6 = flux
            .bypass_v6
            .iter()
            .copied()
            .map(flux_core::cidr::BypassEntry::policy)
            .chain(fixed_v6.iter().copied())
            .map(|entry| (entry.cidr.to_lpm_key(), entry.tag))
            .collect();

        let desired = crate::dataplane::DesiredPolicy {
            apps_mode: flux.apps_mode,
            cidr_mode: flux.cidr_mode,
            interfaces_mode: flux.interfaces_mode,
            interfaces: flux.interfaces.iter().cloned().collect(),
            selected_uids,
            bypass_v4,
            bypass_v6,
        };
        Ok(PolicyCandidate {
            flux,
            desired,
            warnings,
        })
    }

    fn refresh_config_warnings(&mut self) {
        self.config_warnings = self
            .current_policy
            .as_ref()
            .map(|policy| policy.warnings.clone())
            .unwrap_or_default();
        if let Some(user) = self.current_engine_user.as_ref() {
            self.config_warnings.extend(checks::sing_box_warnings(user));
            if !engine_config::has_dns_hijack_rule(user) {
                self.config_warnings.push(
                    "no hijack-dns rule; selected apps' DNS will be forwarded verbatim and domain rules will not apply"
                        .to_string(),
                );
            }
        }
    }

    /// Builds the §24.1 status response from committed runtime state.
    fn build_status(&self, ok: bool) -> Response {
        let disabled = self.layout.disabled();
        let state = if disabled && self.engine.is_none() && !self.convergence_busy() {
            State::Disabled
        } else if !self.ssid_paused
            && self.dataplane.status().active
            && self.engine.is_some()
            && self.activation_role.is_none()
        {
            State::Active
        } else {
            State::Inactive
        };
        // Only a promoted generation is reported as running. A candidate may
        // already have a pid and some sockets, but exposing it here would let
        // clients mistake partial readiness for the commit point.
        let engine_status = match (&self.engine, &self.activation_role) {
            (Some(child), None) => EngineStatus {
                running: true,
                pid: Some(child.pid as u32),
                sockets_verified: child.sockets_verified,
                effective_config: Some(child.effective.display().to_string()),
            },
            _ => EngineStatus {
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
            if self.engine.is_some() || self.convergence_busy() {
                warnings.push(
                    "disable is pending: the engine has not confirmed termination".to_string(),
                );
            }
        } else {
            warnings.extend(self.dataplane.status().warnings.iter().cloned());
            if state != State::Active && self.dataplane.status().attachment_ready {
                warnings.push(
                    "traffic is NOT proxied yet: TC is attached but the Phase 6 active control commit is pending"
                        .to_string(),
                );
            } else if state != State::Active && self.dataplane.status().bpf_ready {
                warnings.push(
                    "traffic is NOT proxied yet: the inactive BPF runtime is ready and TC liveness verification is pending"
                        .to_string(),
                );
            } else if state != State::Active && self.dataplane.status().topology_ready {
                warnings.push(
                    "traffic is NOT proxied yet: the network seam is ready but no BPF runtime is loaded"
                        .to_string(),
                );
            }
        }
        if let Some(detail) = &self.last_error_detail {
            warnings.push(detail.clone());
        }
        if let Some((_, Some(detail))) = &self.policy_error {
            if self.last_error_detail.as_ref() != Some(detail) {
                warnings.push(detail.clone());
            }
        }
        if let Some((_, Some(detail))) = &self.subscription_error {
            if self.last_error_detail.as_ref() != Some(detail)
                && !warnings.iter().any(|warning| warning == detail)
            {
                warnings.push(detail.clone());
            }
        }
        if !disabled {
            if self
                .ssid_status
                .as_ref()
                .is_some_and(|status| status.connected.is_none())
            {
                warnings.push(
                    "ssid_unreadable: Wi-Fi state cannot be read; the [ssid] list is not applied"
                        .to_string(),
                );
            }
            if self.ssid_paused {
                warnings.push(
                    "ssid_paused: the connected Wi-Fi network is excluded by [ssid]; Flux resumes when it changes"
                        .to_string(),
                );
            }
        }
        warnings.extend(self.config_warnings.iter().cloned());

        let counters = match self.dataplane.counters() {
            Ok(counters) => counters,
            Err(error) => {
                warnings.push(format!("counter read failed: {error}"));
                Counters::default()
            }
        };
        let hints = counter_hints(state, &counters);

        Response {
            ok,
            version: flux_core::VERSION.to_string(),
            abi_magic: format!("{:#010X}", flux_core::abi::FLUX_ABI_MAGIC),
            state,
            generation: self.generation,
            backoff_seconds: self.backoff_seconds(),
            root_manager: self.root_manager.clone(),
            engine: engine_status,
            policy: self.dataplane.status().policy,
            ssid: self.ssid_status,
            ifaces: self.dataplane.status().ifaces.clone(),
            counters,
            sysctl: self.dataplane.status().sysctl.clone(),
            warnings,
            hints,
            last_error: if self.ssid_paused {
                None
            } else {
                self.policy_error
                    .as_ref()
                    .map(|(token, _)| token.clone())
                    .or_else(|| {
                        self.subscription_error
                            .as_ref()
                            .map(|(token, _)| token.clone())
                    })
                    .or_else(|| self.last_error.clone())
            },
        }
    }
}

fn root_manager_from_env() -> RootManagerStatus {
    let name = clean_manager_value(std::env::var("FLUX_ROOT_MANAGER").ok(), "unknown");
    let name = match name.as_str() {
        "magisk" | "kernelsu" | "apatch" => name,
        _ => "unknown".to_string(),
    };
    let version = clean_manager_value(std::env::var("FLUX_ROOT_MANAGER_VERSION").ok(), "unknown");
    let runtime_mode = if name == "kernelsu" {
        let mode = clean_manager_value(std::env::var("FLUX_ROOT_MANAGER_MODE").ok(), "unknown");
        match mode.as_str() {
            "built-in" | "lkm" | "late-load" => mode,
            _ => "unknown".to_string(),
        }
    } else {
        "n/a".to_string()
    };
    RootManagerStatus {
        name,
        version,
        runtime_mode,
    }
}

fn clean_manager_value(value: Option<String>, fallback: &str) -> String {
    value
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
                })
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn fault_key(event: &FaultEvent) -> Option<FaultKey> {
    let valid = event.generation != 0
        && matches!(event.family, 4 | 6)
        && matches!(event.protocol, value if value == libc::IPPROTO_TCP as u8 || value == libc::IPPROTO_UDP as u8)
        && matches!(
            event.reason,
            value if value == FaultReason::EgressListener as u16
                || value == FaultReason::IngressAssign as u16
        )
        && event.pad0 == 0
        && event.pad1 == 0;
    valid.then_some(FaultKey {
        generation: event.generation,
        family: event.family,
        protocol: event.protocol,
        reason: event.reason,
        pad0: 0,
    })
}

fn counter_hints(state: State, counters: &Counters) -> Vec<String> {
    let admitted = counters.admit_tcp.saturating_add(counters.admit_udp);
    let mut hints = Vec::new();
    if admitted > 0 && counters.in_drop_assign > 0 {
        hints.push(
            "assign is failing; if this is 100% the engine listener may have SO_REUSEPORT (kernels < 6.5 reject it)"
                .to_string(),
        );
    }
    if admitted > 0 && counters.in_drop_no_listener > 0 {
        hints.push(
            "packets reached the veth but no listener was found; engine may be restarting"
                .to_string(),
        );
    }
    if counters.egress_listener_miss > 0 && admitted == 0 {
        hints.push("nothing is being captured because the engine listener is absent".to_string());
    }
    if counters.direct_tcp > 0 && counters.admit_tcp == 0 {
        hints.push(
            "selected UIDs are matching but every first SYN chose DIRECT; check the [cidr] mode and list, and active"
                .to_string(),
        );
    }
    if state == State::Active && *counters == Counters::default() {
        hints.push(
            "no selected traffic observed; verify the app list resolves to the UIDs you expect"
                .to_string(),
        );
    }
    if counters.drop_udp_frag > 0 {
        hints.push(
            "fragmented UDP from selected apps is dropped by design (§7.3); large DNS/QUIC payloads may fail"
                .to_string(),
        );
    }
    hints
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

fn subscription_error_status(
    error: &flux_core::subscription::SubscriptionError,
) -> (String, String) {
    use flux_core::subscription::SubscriptionError;
    let token = match error {
        SubscriptionError::ZeroNodes => "subscription_empty",
        SubscriptionError::InvalidExcludePattern(_)
        | SubscriptionError::InvalidRenamePattern { .. } => "flux_config_invalid",
        _ => "subscription_fetch_failed:invalid_content",
    };
    (token.to_string(), error.to_string())
}

/// Engine rotation is decided by the serialized generated artifact, including
/// insertion order. `Value` equality is intentionally not the criterion.
fn generated_bytes_equal(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    match (serde_json::to_vec(left), serde_json::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
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

fn epoll_del(epoll: &OwnedFd, fd: RawFd) -> io::Result<()> {
    // SAFETY: both descriptors are live; EPOLL_CTL_DEL ignores the event pointer.
    let rc = unsafe {
        libc::epoll_ctl(
            epoll.as_raw_fd(),
            libc::EPOLL_CTL_DEL,
            fd,
            std::ptr::null_mut(),
        )
    };
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

/// Inotify on the manager's module directory (the switch), the config
/// directory and the parent of packages.list.
fn make_inotify(layout: &Layout) -> io::Result<(OwnedFd, i32, i32, Option<i32>)> {
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

    // The manager creates and removes `disable` here when the user toggles the
    // module, which is why the toggle takes effect without a reboot.
    let module_wd = add(
        layout.module_dir(),
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
    // Linux development hosts do not have Android's /data/system. On Android,
    // watching the parent rather than the inode catches atomic replacement.
    let packages_wd = Path::new(crate::packages::PACKAGES_LIST_PATH)
        .parent()
        .filter(|parent| parent.exists())
        .and_then(|parent| {
            add(
                parent,
                libc::IN_CLOSE_WRITE
                    | libc::IN_CREATE
                    | libc::IN_DELETE
                    | libc::IN_MOVED_TO
                    | libc::IN_MOVED_FROM,
            )
            .ok()
        });
    Ok((fd, module_wd, config_wd, packages_wd))
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

/// Replaces a file's contents through a same-directory temporary and a rename,
/// so a reader (the manager parsing `module.prop`) never observes a half-written
/// file and a failed write leaves the original intact.
fn write_replace(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    // SAFETY: getpid has no preconditions and cannot fail.
    let pid = unsafe { libc::getpid() };
    let tmp = dir.join(format!(
        ".{}.flux.{pid}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp")
    ));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o644)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Writes one machine-owned secret with the same fsync-then-rename shape as
/// the engine candidate transaction, while keeping the previous path intact
/// until the final atomic replacement.
fn write_private_replace(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.subscription.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("raw")
    ));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_is_capped() {
        assert_eq!(BACKOFF_STEPS[BACKOFF_STEPS.len() - 1], 30);
        let step = |count: usize| BACKOFF_STEPS[count.min(BACKOFF_STEPS.len() - 1)];
        assert_eq!(step(0), 1);
        assert_eq!(step(4), 30);
        assert_eq!(step(100), 30);
    }

    #[test]
    fn equal_generated_bytes_skip_rotation() {
        let generated: serde_json::Value =
            serde_json::from_str(r#"{"outbounds":[{"type":"direct","tag":"DIRECT"}]}"#).unwrap();
        assert!(generated_bytes_equal(&generated, &generated.clone()));
    }

    #[test]
    fn different_generated_key_order_requires_rotation() {
        let left: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let right: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert!(!generated_bytes_equal(&left, &right));
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

    #[test]
    fn manager_metadata_rejects_control_characters_and_unbounded_values() {
        assert_eq!(
            clean_manager_value(Some("1.2.3".into()), "unknown"),
            "1.2.3"
        );
        assert_eq!(
            clean_manager_value(Some("bad\nvalue".into()), "unknown"),
            "unknown"
        );
        assert_eq!(
            clean_manager_value(Some("x".repeat(65)), "unknown"),
            "unknown"
        );
    }

    #[test]
    fn status_hints_follow_the_documented_counter_combinations() {
        let counters = Counters {
            admit_tcp: 1,
            in_drop_assign: 1,
            in_drop_no_listener: 1,
            drop_udp_frag: 1,
            ..Counters::default()
        };
        let hints = counter_hints(State::Active, &counters);
        assert!(hints
            .iter()
            .any(|hint| hint.starts_with("assign is failing")));
        assert!(hints
            .iter()
            .any(|hint| hint.starts_with("packets reached the veth")));
        assert!(hints.iter().any(|hint| hint.starts_with("fragmented UDP")));

        let empty = counter_hints(State::Active, &Counters::default());
        assert_eq!(empty.len(), 1);
        assert!(empty[0].starts_with("no selected traffic observed"));
    }

    #[test]
    fn fault_records_are_validated_before_they_drive_recovery() {
        let valid = FaultEvent {
            generation: 7,
            family: 4,
            protocol: libc::IPPROTO_TCP as u8,
            reason: FaultReason::EgressListener as u16,
            pad0: 0,
            seq: 0,
            pad1: 0,
        };
        assert_eq!(
            fault_key(&valid),
            Some(FaultKey {
                generation: 7,
                family: 4,
                protocol: libc::IPPROTO_TCP as u8,
                reason: FaultReason::EgressListener as u16,
                pad0: 0,
            })
        );

        for malformed in [
            FaultEvent {
                generation: 0,
                ..valid
            },
            FaultEvent { family: 5, ..valid },
            FaultEvent {
                protocol: libc::IPPROTO_ICMP as u8,
                ..valid
            },
            FaultEvent {
                reason: 99,
                ..valid
            },
            FaultEvent { pad0: 1, ..valid },
            FaultEvent { pad1: 1, ..valid },
        ] {
            assert_eq!(fault_key(&malformed), None);
        }
    }
}
