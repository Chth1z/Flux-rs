//! Validation of the user's `sing-box.json` and generation of the effective
//! configuration.
//!
//! Implements blueprint §9.1. Two invariants the generator must enforce:
//!
//! * The user config may not declare any `inbound`. Flux injects exactly two
//!   tproxy inbounds (one per family) and owns their addresses and ports.
//! * The engine binary is the unmodified official asset pinned by
//!   `engine.lock`. No patching, ever (blueprint §3.8).
//!
//! Not implemented yet — Phase 5 (blueprint §17).

/// Why a user engine configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineConfigError {
    /// The file was not valid JSON.
    Syntax(String),
    /// The user declared an inbound, which Flux owns exclusively.
    UserSuppliedInbound,
    /// A key Flux must control was present in the user config.
    ReservedKey(String),
}
