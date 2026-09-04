//! Typed rtnetlink and generic-netlink boundaries for Flux network state.
//!
//! Raw message construction, sequence/ACK handling and TLV parsing stay in
//! this module. Callers work with typed snapshots and mutations only. See
//! blueprint §8.5, §8.6, §8.9 and §10.4.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

mod genl;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod route;
mod wire;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod sock_diag;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use genl::{GenlSocket, Nl80211Family, NL80211_IFTYPE_STATION};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use route::Address;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use route::{
    EventSocket, Filter, Link, NetworkSnapshot, Qdisc, Route, RouteNetlink, Rule, IFF_LOOPBACK,
    IFF_UP, TC_CLSACT_HANDLE, TC_H_CLSACT, TC_H_EGRESS,
};
// Phase 3 establishes the typed filter mutation seam. Its first runtime
// consumer is the Phase 4/5 loader/attachment work, so these exports are
// intentionally dormant in the current binary.
#[allow(unused_imports)]
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use route::{FilterIdentity, TcAttach, ETH_P_ALL, TC_H_INGRESS};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use wire::DrainResult;
