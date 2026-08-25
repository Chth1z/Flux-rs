//! sing-box supervision: effective config, `check`, spawn, readiness, candidate
//! switch and crash recovery.
//!
//! Implements blueprint §9. The engine is the **unmodified official asset**
//! pinned by `engine.lock`; Flux never patches it (§3.8).
//!
//! Readiness is event-driven: `SOCK_DIAG` enumeration plus PID and inode
//! verification, driven by pidfd and timerfd. The old tree's
//! `flux-platform/src/sing_box.rs` polls every 10 ms (`POLL_INTERVAL`), which
//! violates §10.1 — read it for the fork/exec and pinning logic, then implement
//! readiness differently (blueprint §18.3.2).
//!
//! One ordering rule that closes a real kernel bug: on a candidate switch,
//! publish `active = 0` **before** terminating the old child. Kernels below 6.5
//! lack the unhashed-socket rejection in `bpf_sk_assign()`, so assigning a
//! just-unhashed listener leaks a socket reference permanently. Publishing
//! `active = 0` first makes ingress stop assigning before the listener can go
//! away (§9.2, §9.4).
//!
//! Not implemented yet — Phase 6 (blueprint §17).
