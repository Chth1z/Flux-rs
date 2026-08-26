//! Typed rtnetlink boundary for Flux-owned network objects.
//!
//! Raw message construction, sequence/ACK handling and TLV parsing stay in
//! this module. Callers work with typed snapshots and mutations only. See
//! blueprint §8.5, §8.6, §8.9 and §10.4.

mod route;
mod wire;

pub mod sock_diag;

#[cfg(test)]
pub use route::Address;
pub use route::{
    EventSocket, Filter, Link, NetworkSnapshot, Qdisc, Route, RouteNetlink, Rule, IFF_LOOPBACK,
    IFF_UP, TC_CLSACT_HANDLE, TC_H_CLSACT, TC_H_EGRESS,
};
// Phase 3 establishes the typed filter mutation seam. Its first runtime
// consumer is the Phase 4/5 loader/attachment work, so these exports are
// intentionally dormant in the current binary.
#[allow(unused_imports)]
pub use route::{FilterIdentity, TcAttach, ETH_P_ALL, TC_H_INGRESS};
pub use wire::DrainResult;
