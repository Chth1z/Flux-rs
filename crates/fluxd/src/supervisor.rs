//! Process-only supervision for the daemon reactor (blueprint §13.2.2).
//!
//! The supervisor deliberately owns no Flux state. Its complete interface to
//! the reactor is spawning `/proc/self/exe`, waiting for it, and forwarding
//! signals.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

/// A reactor that cannot acquire the single-instance lock must not restart.
pub(crate) const LOCK_HELD_EXIT_CODE: u8 = 3;

/// Crash-restart delays shared by the reactor's engine and its supervisor.
pub(crate) const BACKOFF_STEPS: [u64; 5] = [1, 2, 4, 8, 30];

/// Child uptime after which either crash counter resets.
pub(crate) const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

const STOP_GRACE: Duration = Duration::from_secs(10);
const SUPERVISED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReactorOutcome {
    Exited(u8),
    Signaled(libc::c_int),
}

impl ReactorOutcome {
    fn conservative_exit_code(self) -> u8 {
        match self {
            Self::Exited(code) => code,
            Self::Signaled(_) => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    Exit(u8),
    DoNotRestart(u8),
    Restart {
        after: Duration,
        next_crash_count: usize,
    },
}

/// Decides the supervisor's next action without performing process I/O.
fn decide_reactor_outcome(
    outcome: ReactorOutcome,
    stopping: bool,
    ran_for: Duration,
    crash_count: usize,
) -> Decision {
    if stopping {
        return Decision::DoNotRestart(outcome.conservative_exit_code());
    }

    match outcome {
        ReactorOutcome::Exited(0) => Decision::Exit(0),
        ReactorOutcome::Exited(LOCK_HELD_EXIT_CODE) => Decision::DoNotRestart(LOCK_HELD_EXIT_CODE),
        ReactorOutcome::Exited(_) | ReactorOutcome::Signaled(_) => {
            let crash_count = if ran_for >= BACKOFF_RESET_AFTER {
                0
            } else {
                crash_count
            };
            let step = BACKOFF_STEPS[crash_count.min(BACKOFF_STEPS.len() - 1)];
            Decision::Restart {
                after: Duration::from_secs(step),
                next_crash_count: crash_count.saturating_add(1),
            }
        }
    }
}

/// Runs the process supervisor and returns its process exit code.
pub(crate) fn run() -> u8 {
    let signal_set = match block_supervised_signals() {
        Ok(signal_set) => signal_set,
        Err(error) => {
            log(format_args!("supervisor cannot block signals: {error}"));
            return 1;
        }
    };
    if let Err(error) = reset_supervised_dispositions() {
        log(format_args!(
            "supervisor cannot reset signal dispositions: {error}"
        ));
        return 1;
    }
    let mut crash_count = 0usize;

    loop {
        let reactor_pid = match spawn_reactor() {
            Ok(pid) => pid,
            Err(error) => {
                let Decision::Restart {
                    after,
                    next_crash_count,
                } = decide_reactor_outcome(
                    ReactorOutcome::Exited(1),
                    false,
                    Duration::ZERO,
                    crash_count,
                )
                else {
                    log(format_args!("cannot start reactor: {error}"));
                    return 1;
                };
                log(format_args!(
                    "cannot start reactor: {error}; restarting in {} s",
                    after.as_secs()
                ));
                crash_count = next_crash_count;
                match wait_backoff(&signal_set, after) {
                    Ok(BackoffAction::Restart) => continue,
                    Ok(BackoffAction::Stop) => {
                        log(format_args!(
                            "stop requested during reactor backoff; exiting"
                        ));
                        return 0;
                    }
                    Err(error) => {
                        log(format_args!("cannot wait through reactor backoff: {error}"));
                        return 1;
                    }
                }
            }
        };
        let started_at = Instant::now();
        let (outcome, stopping) = match wait_for_reactor(reactor_pid, &signal_set) {
            Ok(result) => result,
            Err(error) => {
                // Leaving the reactor alive is the conservative failure mode:
                // §13.2.2 explicitly permits a working, unsupervised reactor.
                log(format_args!(
                    "cannot supervise reactor {reactor_pid}: {error}"
                ));
                return 1;
            }
        };

        match decide_reactor_outcome(outcome, stopping, started_at.elapsed(), crash_count) {
            Decision::Exit(code) => {
                log_outcome(outcome, "not restarting");
                return code;
            }
            Decision::DoNotRestart(code) => {
                if !stopping && outcome == ReactorOutcome::Exited(LOCK_HELD_EXIT_CODE) {
                    log(format_args!(
                        "another fluxd instance holds the lock; not restarting"
                    ));
                } else {
                    log_outcome(outcome, "not restarting");
                }
                return code;
            }
            Decision::Restart {
                after,
                next_crash_count,
            } => {
                log_restart(outcome, after);
                crash_count = next_crash_count;
                match wait_backoff(&signal_set, after) {
                    Ok(BackoffAction::Restart) => {}
                    Ok(BackoffAction::Stop) => {
                        log(format_args!(
                            "stop requested during reactor backoff; exiting"
                        ));
                        return 0;
                    }
                    Err(error) => {
                        log(format_args!("cannot wait through reactor backoff: {error}"));
                        return 1;
                    }
                }
            }
        }
    }
}

fn block_supervised_signals() -> io::Result<libc::sigset_t> {
    let signal_set = make_signal_set()?;
    // SAFETY: `signal_set` is fully initialized and the old mask is not needed.
    let rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &signal_set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(signal_set)
}

fn make_signal_set() -> io::Result<libc::sigset_t> {
    // SAFETY: sigemptyset initializes the local set before it is observed.
    unsafe {
        let mut signal_set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut signal_set) != 0 {
            return Err(io::Error::last_os_error());
        }
        for signal in SUPERVISED_SIGNALS {
            if libc::sigaddset(&mut signal_set, signal) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(signal_set)
    }
}

fn reset_supervised_dispositions() -> io::Result<()> {
    for signal in SUPERVISED_SIGNALS {
        // SAFETY: each value is a valid catchable signal or SIGCHLD.
        if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn spawn_reactor() -> io::Result<libc::pid_t> {
    let mut command = Command::new("/proc/self/exe");
    command
        .arg0("fluxd")
        .arg("daemon")
        .env("FLUX_SUPERVISOR", std::process::id().to_string());

    // SAFETY: the closure calls only libc signal-mask/disposition functions.
    // It performs no allocation between fork and exec.
    unsafe {
        command.pre_exec(|| {
            reset_supervised_dispositions()?;
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut empty) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn()?;
    let pid = child.id() as libc::pid_t;
    Ok(pid)
}

fn wait_for_reactor(
    reactor_pid: libc::pid_t,
    signal_set: &libc::sigset_t,
) -> io::Result<(ReactorOutcome, bool)> {
    let mut stopping = false;
    let mut stop_deadline = None;

    loop {
        let signal = match stop_deadline {
            Some(deadline) => match wait_signal_until(signal_set, deadline)? {
                Some(signal) => signal,
                None => return force_stop(reactor_pid).map(|outcome| (outcome, true)),
            },
            None => wait_signal(signal_set)?,
        };

        match signal {
            libc::SIGCHLD => {
                if let Some(status) = try_reap(reactor_pid)? {
                    return decode_wait_status(status).map(|outcome| (outcome, stopping));
                }
            }
            libc::SIGTERM | libc::SIGINT => {
                if let Err(error) = send_signal(reactor_pid, signal) {
                    log(format_args!(
                        "cannot forward signal {signal} to reactor {reactor_pid}: {error}"
                    ));
                }
                if !stopping {
                    stopping = true;
                    stop_deadline = Instant::now().checked_add(STOP_GRACE);
                    if stop_deadline.is_none() {
                        log(format_args!(
                            "cannot represent reactor stop deadline; forcing stop"
                        ));
                        return force_stop(reactor_pid).map(|outcome| (outcome, true));
                    }
                }
            }
            libc::SIGHUP => {
                if let Err(error) = send_signal(reactor_pid, libc::SIGHUP) {
                    log(format_args!(
                        "cannot forward SIGHUP to reactor {reactor_pid}: {error}"
                    ));
                }
            }
            other => {
                log(format_args!("received unexpected signal {other}; ignoring"));
            }
        }
    }
}

/// The untimed wait. `sigtimedwait` with a null timeout is what both bionic
/// and glibc implement `sigwaitinfo` as — the kernel's `rt_sigtimedwait` waits
/// indefinitely when no timeout is passed — and the `libc` crate exposes no
/// `sigwaitinfo` binding for Android at all.
fn wait_signal(signal_set: &libc::sigset_t) -> io::Result<libc::c_int> {
    loop {
        // SAFETY: `signal_set` is initialized and its signals are blocked; a
        // null siginfo and a null timeout are both permitted by the syscall.
        let signal =
            unsafe { libc::sigtimedwait(signal_set, std::ptr::null_mut(), std::ptr::null()) };
        if signal >= 0 {
            return Ok(signal);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

fn wait_signal_until(
    signal_set: &libc::sigset_t,
    deadline: Instant,
) -> io::Result<Option<libc::c_int>> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let timeout = libc::timespec {
            tv_sec: remaining.as_secs() as libc::time_t,
            tv_nsec: remaining.subsec_nanos() as libc::c_long,
        };
        // SAFETY: the set and relative timeout are initialized local values.
        let signal = unsafe { libc::sigtimedwait(signal_set, std::ptr::null_mut(), &timeout) };
        if signal >= 0 {
            return Ok(Some(signal));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EAGAIN) => return Ok(None),
            Some(libc::EINTR) => continue,
            _ => return Err(error),
        }
    }
}

fn try_reap(reactor_pid: libc::pid_t) -> io::Result<Option<libc::c_int>> {
    loop {
        let mut status = 0;
        // SAFETY: waitpid targets the exact child pid and writes to `status`.
        let result = unsafe { libc::waitpid(reactor_pid, &mut status, libc::WNOHANG) };
        if result == reactor_pid {
            return Ok(Some(status));
        }
        if result == 0 {
            return Ok(None);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        return Err(io::Error::other(format!(
            "waitpid returned unexpected pid {result} for reactor {reactor_pid}"
        )));
    }
}

fn reap_blocking(reactor_pid: libc::pid_t) -> io::Result<libc::c_int> {
    loop {
        let mut status = 0;
        // SAFETY: waitpid targets the exact child pid and writes to `status`.
        let result = unsafe { libc::waitpid(reactor_pid, &mut status, 0) };
        if result == reactor_pid {
            return Ok(status);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        return Err(io::Error::other(format!(
            "waitpid returned unexpected pid {result} for reactor {reactor_pid}"
        )));
    }
}

fn force_stop(reactor_pid: libc::pid_t) -> io::Result<ReactorOutcome> {
    if let Some(status) = try_reap(reactor_pid)? {
        return decode_wait_status(status);
    }

    match send_signal(reactor_pid, libc::SIGKILL) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
        Err(error) => return Err(error),
    }
    decode_wait_status(reap_blocking(reactor_pid)?)
}

fn send_signal(reactor_pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: kill targets the exact unreaped child pid.
    if unsafe { libc::kill(reactor_pid, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn decode_wait_status(status: libc::c_int) -> io::Result<ReactorOutcome> {
    if libc::WIFEXITED(status) {
        return Ok(ReactorOutcome::Exited(libc::WEXITSTATUS(status) as u8));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(ReactorOutcome::Signaled(libc::WTERMSIG(status)));
    }
    Err(io::Error::other(format!(
        "reactor produced unsupported wait status {status:#x}"
    )))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackoffAction {
    Restart,
    Stop,
}

fn wait_backoff(signal_set: &libc::sigset_t, delay: Duration) -> io::Result<BackoffAction> {
    let Some(deadline) = Instant::now().checked_add(delay) else {
        return Err(io::Error::other(
            "cannot represent reactor backoff deadline",
        ));
    };
    loop {
        match wait_signal_until(signal_set, deadline)? {
            None => return Ok(BackoffAction::Restart),
            Some(libc::SIGTERM | libc::SIGINT) => return Ok(BackoffAction::Stop),
            // There is no child during backoff. Discard stale SIGCHLD and
            // ignore reloads without shortening the one-shot deadline.
            Some(libc::SIGCHLD | libc::SIGHUP) => {}
            Some(other) => log(format_args!(
                "received unexpected signal {other} during backoff; ignoring"
            )),
        }
    }
}

fn log_restart(outcome: ReactorOutcome, delay: Duration) {
    match outcome {
        ReactorOutcome::Exited(code) => log(format_args!(
            "reactor exited with code {code}; restarting in {} s",
            delay.as_secs()
        )),
        ReactorOutcome::Signaled(signal) => log(format_args!(
            "reactor killed by signal {signal}; restarting in {} s",
            delay.as_secs()
        )),
    }
}

fn log_outcome(outcome: ReactorOutcome, action: &str) {
    match outcome {
        ReactorOutcome::Exited(code) => {
            log(format_args!("reactor exited with code {code}; {action}"));
        }
        ReactorOutcome::Signaled(signal) => {
            log(format_args!("reactor killed by signal {signal}; {action}"));
        }
    }
}

/// Writes a best-effort single line without panicking when stderr is broken.
fn log(arguments: std::fmt::Arguments<'_>) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"fluxd: ");
    let _ = stderr.write_fmt(arguments);
    let _ = stderr.write_all(b"\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_exit_ends_the_supervisor() {
        assert_eq!(
            decide_reactor_outcome(ReactorOutcome::Exited(0), false, Duration::ZERO, 0),
            Decision::Exit(0)
        );
    }

    #[test]
    fn held_lock_does_not_restart() {
        assert_eq!(
            decide_reactor_outcome(
                ReactorOutcome::Exited(LOCK_HELD_EXIT_CODE),
                false,
                Duration::ZERO,
                0,
            ),
            Decision::DoNotRestart(LOCK_HELD_EXIT_CODE)
        );
    }

    #[test]
    fn first_crash_restarts_after_one_second() {
        assert_eq!(
            decide_reactor_outcome(ReactorOutcome::Exited(1), false, Duration::ZERO, 0),
            Decision::Restart {
                after: Duration::from_secs(1),
                next_crash_count: 1,
            }
        );
    }

    #[test]
    fn consecutive_crashes_follow_the_shared_schedule() {
        let mut crash_count = 0;
        let mut observed = Vec::new();
        for _ in 0..5 {
            let Decision::Restart {
                after,
                next_crash_count,
            } = decide_reactor_outcome(
                ReactorOutcome::Signaled(libc::SIGKILL),
                false,
                Duration::from_secs(1),
                crash_count,
            )
            else {
                panic!("a crash must restart");
            };
            observed.push(after.as_secs());
            crash_count = next_crash_count;
        }
        assert_eq!(observed, [1, 2, 4, 8, 30]);
    }

    #[test]
    fn sixty_stable_seconds_reset_the_crash_count() {
        assert_eq!(
            decide_reactor_outcome(ReactorOutcome::Exited(1), false, Duration::from_secs(60), 4),
            Decision::Restart {
                after: Duration::from_secs(1),
                next_crash_count: 1,
            }
        );
    }

    #[test]
    fn stopping_never_restarts_for_any_outcome() {
        assert_eq!(
            decide_reactor_outcome(ReactorOutcome::Exited(9), true, Duration::ZERO, 4),
            Decision::DoNotRestart(9)
        );
        assert_eq!(
            decide_reactor_outcome(
                ReactorOutcome::Signaled(libc::SIGKILL),
                true,
                Duration::ZERO,
                4,
            ),
            Decision::DoNotRestart(1)
        );
    }
}
