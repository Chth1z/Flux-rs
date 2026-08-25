//! Runtime directory layout, permissions and the single-instance lock.
//!
//! Implements blueprint §11.2 and §13.1. The lock is `flock(LOCK_EX|LOCK_NB)`
//! on a file the daemon holds open for its whole life, so it is released by the
//! kernel even on `SIGKILL` — there is no stale-lock recovery path to get wrong.
//!
//! Not implemented yet — Phase 2 (blueprint §17).

/// Root of all runtime state.
pub const RUNTIME_ROOT: &str = "/data/adb/flux-rs";

/// Single-instance lock, held for the daemon's entire lifetime.
pub const LOCK_PATH: &str = "/data/adb/flux-rs/fluxd.lock";

/// Control socket. Root-only, checked via `SO_PEERCRED`.
pub const CONTROL_SOCKET_PATH: &str = "/data/adb/flux-rs/control.sock";
