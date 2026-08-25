//! Single-threaded epoll reactor: the event loop, the state machine and
//! convergence.
//!
//! Implements blueprint §10.1, §10.4 and §26. Event sources are rtnetlink,
//! inotify, pidfd, signalfd, the BPF fault ring buffer, the control socket and
//! timerfd. **There is no periodic polling anywhere** — that is a hard product
//! constraint, not a preference.
//!
//! Four invariants from §26 that the implementation must preserve:
//!
//! 1. The only way into `Active` is the single `control_root` pointer swap in
//!    §8.7 step 10; the first action on leaving `Active` is always publishing
//!    `active = 0`.
//! 2. Policy transactions never change the top-level state.
//! 3. Events arriving during a transaction are queued, never dropped and never
//!    processed re-entrantly.
//! 4. **Capture-side drift must be handled locally and must never be escalated
//!    to a global transaction.** netd deletes the `clsact` qdisc every time an
//!    interface joins or leaves a network, so treating that as core drift would
//!    blip every proxied flow on the device on every Wi-Fi reconnect
//!    (blueprint §8.5.1).
//!
//! The old tree's `flux-platform/src/reactor.rs` is a **reference only**: it is
//! wired directly to the abandoned inventory driver and has neither a timerfd
//! nor a ring-buffer source (blueprint §18.3.2).
//!
//! Not implemented yet — Phase 3 (blueprint §17).
