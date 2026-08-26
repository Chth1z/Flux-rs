//! rtnetlink: the only place in the daemon allowed to touch raw netlink bytes.
//!
//! Implements blueprint §8.9 and §10.4.1. Callers get typed operations
//! (`create_veth`, `add_rule`, `add_local_route`, `ensure_clsact`,
//! `attach_filter`) and never see an `nlmsghdr`, a sequence number or an ACK.
//!
//! Everything here is netlink, never a subprocess. Shelling out to `ip` or `tc`
//! is forbidden: on Android those binaries run in their own SELinux domains and
//! the call would either be denied or silently do something different
//! (blueprint §12.8).
//!
//! Three hard rules for event handling (blueprint §10.4.1):
//!
//! 1. On `ENOBUFS` or `NLMSG_OVERRUN`, discard the batch and re-dump in full.
//!    Never try to patch up a partial view.
//! 2. Debounce convergence; Android interface churn arrives in bursts.
//! 3. Resolve `ifindex` once per convergence and use it consistently; names and
//!    indices can both be reused.
//!
//! What must be written from scratch, because the old tree has **zero**
//! occurrences of any of it (blueprint §18.3.1):
//!
//! * `RTM_NEWQDISC` / `RTM_NEWTFILTER`, `TCA_*`, `clsact` — the whole TC path.
//! * veth creation: `RTM_NEWLINK` with `IFLA_LINKINFO` / `IFLA_INFO_DATA` /
//!   `VETH_INFO_PEER`. The old tree only ever decoded `IFLA_INFO_KIND`.
//!
//! Port candidates: `netlink.rs` (framing), `netlink/socket.rs`, and the route
//! and rule **mutation builders** in `netlink/policy_routing.rs`, which are the
//! only netlink write path that ever existed (blueprint §18.3.2).
//!
//! Phase 2 implements only the read-only `sock_diag` half (blueprint §9.5);
//! rtnetlink and TC arrive with Phase 3 (blueprint §17).

pub mod sock_diag;
