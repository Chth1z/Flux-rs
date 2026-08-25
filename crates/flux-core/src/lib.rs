//! Pure logic for Flux-rs 0.9.0.
//!
//! This crate holds everything that needs no syscall: configuration parsing,
//! app selector resolution, CIDR canonicalisation, the data-plane ABI mirror,
//! the control-protocol wire types, and version arithmetic. It therefore
//! compiles and tests on any host, including Windows.
//!
//! Boundaries that must not erode (blueprint §5):
//!
//! * `flux-core` depends on no other workspace crate. `fluxd` and `xtask`
//!   depend on it, never the reverse.
//! * No `libc`, no `unsafe`, no I/O. `unsafe_code` is `forbid`den above.
//! * No trait abstraction layers for a single implementation.
//!
//! The design contract is `docs/blueprint.md`. Section references in these
//! modules point at it and are load-bearing: do not implement a module without
//! reading the section it cites.

pub mod abi;
pub mod cidr;
pub mod config;
pub mod control_wire;
pub mod engine_config;
pub mod selector;
pub mod version;

/// Product version, kept in lockstep with the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
