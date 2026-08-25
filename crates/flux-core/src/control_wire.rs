//! Control-protocol wire types.
//!
//! Implements blueprint §10.3 and §24. The transport is `SOCK_SEQPACKET` with a
//! root-only peer check; this module only owns the encoding.
//!
//! Not implemented yet — Phase 3 (blueprint §17).

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped only on an incompatible change; the daemon
/// rejects requests carrying an unknown version rather than guessing.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted request size. Larger requests close the connection.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Top-level daemon state, as reported by `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Configuration disables Flux; nothing is attached.
    Disabled,
    /// Enabled but not attached, e.g. a capability or conflict check failed.
    Inactive,
    /// Attached and carrying traffic.
    Active,
}

/// A command from the CLI to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum Request {
    /// Report state without changing anything.
    Status,
    /// Re-validate configuration without changing anything.
    Check,
    /// Persist `enabled = true` and try to activate.
    Enable,
    /// Persist `enabled = false` and detach.
    Disable,
    /// Re-read configuration and converge.
    Reload,
    /// Detach and exit zero.
    Stop,
}
