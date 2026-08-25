//! `flux.toml` parsing, canonicalisation and hard limits.
//!
//! Implements blueprint §11. The parser is strict: unknown keys are an error,
//! not a warning, so a typo can never silently disable capture.
//!
//! Not implemented yet — Phase 1 (blueprint §17).

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file was not valid TOML.
    Syntax(String),
    /// A key the current schema does not define.
    UnknownKey(String),
    /// A value was outside its documented range.
    OutOfRange(String),
    /// More selectors or prefixes than the ABI reserves room for.
    CapacityExceeded(String),
}
