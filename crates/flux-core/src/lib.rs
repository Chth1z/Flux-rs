//! Pure logic for Flux-rs.
//!
//! This crate holds everything that needs no syscall: configuration parsing,
//! app selector resolution, CIDR canonicalisation, the PolicyEpoch model,
//! dump completeness, the data-plane ABI mirror, parse bound arithmetic, the control-protocol wire types, the §26
//! lifecycle Planner (`plan` / `step`), and version arithmetic. It therefore compiles and tests
//! on any host, including Windows.
//!
//! Boundaries that must not erode (blueprint §5):
//!
//! * `flux-core` depends on no other workspace crate. `fluxd` and `xtask`
//!   depend on it, never the reverse.
//! * No `libc`, no `unsafe`, no I/O. `unsafe_code` is `forbid`den above.
//! * No trait abstraction layers for a single implementation.
//!
//! The design contract is `docs/spec/blueprint.md`. Section references in these
//! modules point at it and are load-bearing: do not implement a module without
//! reading the section it cites.

pub mod abi;
pub mod btf;
pub mod cidr;
pub mod config;
pub mod control_wire;
pub mod engine_config;
pub mod migration;
pub mod parse_bounds;
pub mod policy_epoch;
pub mod runtime;
pub mod selector;
pub mod sha256;
pub mod snapshot;
pub mod ssid;
pub mod subscription;
pub mod version;

/// Product version, kept in lockstep with the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
