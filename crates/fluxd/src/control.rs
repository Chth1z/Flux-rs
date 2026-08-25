//! `SOCK_SEQPACKET` control server and client.
//!
//! Implements blueprint §10.3. Every accepted connection is checked with
//! `SO_PEERCRED` and dropped unless the peer is uid 0; requests larger than
//! [`flux_core::control_wire::MAX_REQUEST_BYTES`] close the connection.
//!
//! Port candidate: `flux-platform/src/seqpacket.rs` (2476 lines) from the old
//! tree is architecture-neutral and should be adapted rather than rewritten
//! (blueprint §18.3.2).
//!
//! Not implemented yet — Phase 3 (blueprint §17).
