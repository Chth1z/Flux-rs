//! rtnetlink: the only place in the daemon allowed to touch raw netlink bytes.
//!
//! Implements blueprint §8.9 and §10.4.1. Phase 3 adds the mutation path for
//! veth, route/RPDB, clsact ownership and interface admission. BPF filter
//! attach and full egress TC dump are Phase 5; the helpers below are already
//! implemented so Phase 5 does not reshuffle message encoding.
#![allow(dead_code)] // until Phase 5 attaches filters and reads egress dumps

pub mod admission;
pub mod attr;
pub mod consts;
pub mod link;
pub mod route;
pub mod rt_socket;
pub mod rule;
pub mod sock_diag;
pub mod sysctl;
pub mod tc;
