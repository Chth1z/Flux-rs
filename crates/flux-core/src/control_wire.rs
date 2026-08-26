//! Control-protocol wire types.
//!
//! Implements blueprint §10.3 and §24. The transport is `SOCK_SEQPACKET` with a
//! root-only peer check and one single-line JSON message per packet; this
//! module owns only the encoding, so it is fully testable on any host
//! (blueprint §15.2 test 7).
//!
//! This protocol is the product's public API, not just the CLI's private wire
//! (`docs/ux.md` §5.1): adding a field is fine, changing a field's meaning
//! requires bumping [`PROTOCOL_VERSION`]. The daemon rejects an unknown version
//! rather than guessing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped only on an incompatible change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted request size. Larger requests close the connection.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Top-level daemon state (blueprint §10.1, §24.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// The `disable` file is present; nothing is attached.
    Disabled,
    /// Enabled but not attached, e.g. starting up or blocked by an error.
    Inactive,
    /// Attached and carrying traffic (`control active == 1`).
    Active,
}

/// A command from a client to the daemon.
///
/// All six commands are idempotent by construction (blueprint §10.3), so the
/// protocol needs no request-id de-duplication. New commands must preserve that
/// property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Report state without changing anything.
    Status,
    /// Re-validate configuration and capability without changing anything.
    Check,
    /// Persist enabled and try to activate.
    Enable,
    /// Persist disabled and detach.
    Disable,
    /// Re-read configuration and converge.
    Reload,
    /// Detach and exit zero.
    Stop,
}

#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    protocol_version: u32,
    #[serde(flatten)]
    request: Request,
}

/// A request frame was syntactically valid JSON but used an incompatible
/// public protocol version.
#[derive(Debug)]
pub enum RequestDecodeError {
    /// The request was not valid JSON or did not match the request schema.
    Json(serde_json::Error),
    /// The request declared a protocol version this binary does not implement.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for RequestDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{e}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported control protocol version {v}; expected {PROTOCOL_VERSION}"
            ),
        }
    }
}

impl std::error::Error for RequestDecodeError {}

/// The engine child's status (blueprint §24.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatus {
    /// Whether a sing-box child is running.
    pub running: bool,
    /// The child pid, if running.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pid: Option<u32>,
    /// How many of the four expected listener sockets were verified; fewer than
    /// four means readiness did not close (blueprint §9.5).
    pub sockets_verified: u8,
    /// The effective config path in use, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub effective_config: Option<String>,
}

/// Policy population counts (blueprint §24.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyCounts {
    /// Selected UIDs.
    pub selected: u32,
    /// Draining UIDs.
    pub draining: u32,
    /// IPv4 bypass entries, including fixed and self-address ones.
    pub bypass_v4: u32,
    /// IPv6 bypass entries, including fixed and self-address ones.
    pub bypass_v6: u32,
    /// Dynamically injected device-own address entries.
    pub self_addresses: u32,
}

/// Per-interface status (blueprint §24.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfaceStatus {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub ifindex: u32,
    /// Link type, e.g. `ether` / `rawip` / `none`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arphrd: Option<String>,
    /// The capture entry attached, e.g. `flx_cap_l2`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry: Option<String>,
    /// `active` / `excluded` / other stable status token (blueprint §24.2).
    pub status: String,
    /// The attached program's id, when active.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prog_id: Option<u32>,
    /// The attached program's 8-byte tag, when active.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prog_tag: Option<String>,
    /// Whether our filter is first-applicable in the dump order.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub first_applicable: Option<bool>,
    /// A stable reason token when excluded (blueprint §24.2).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// The data-plane counters, summed across CPUs (blueprint §6.1, §24.1).
///
/// One field per `counters` slot except `saw_packet`, which is internal to the
/// liveness probe and not part of the status surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    /// First SYN installed CAPTURED.
    pub admit_tcp: u64,
    /// First SYN installed DIRECT.
    pub direct_tcp: u64,
    /// Datagram admitted.
    pub admit_udp: u64,
    /// Captured socket seen while inactive.
    pub drop_inactive: u64,
    /// Captured socket seen with an old generation.
    pub drop_stale_gen: u64,
    /// Ethernet write or change_head failed.
    pub drop_handoff: u64,
    /// Selected and active UDP fragment dropped.
    pub drop_udp_frag: u64,
    /// Decision magic or reserved bytes were bad.
    pub drop_corrupt: u64,
    /// Storage create and re-read both failed.
    pub decision_alloc_fail: u64,
    /// Egress could not find a live listener.
    pub egress_listener_miss: u64,
    /// Ingress assigned a TCP listener.
    pub in_assign_tcp: u64,
    /// Ingress assigned a UDP socket.
    pub in_assign_udp: u64,
    /// Ingress passed an established TCP packet to the normal lookup.
    pub in_pass_established: u64,
    /// Ingress passed a fragment to the normal lookup.
    pub in_pass_fragment: u64,
    /// Ingress found no listener.
    pub in_drop_no_listener: u64,
    /// Ingress assign failed.
    pub in_drop_assign: u64,
    /// Ingress could not parse the packet.
    pub in_drop_parse: u64,
    /// Ingress saw an invalid control snapshot.
    pub in_drop_snapshot: u64,
}

/// The daemon's reply to a [`Request`] (blueprint §24.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Public control protocol version used to encode this response.
    pub protocol_version: u32,
    /// Whether the request succeeded.
    pub ok: bool,
    /// Product version, e.g. `0.9.0`.
    pub version: String,
    /// ABI magic as a hex string, e.g. `0xF10C0903`.
    pub abi_magic: String,
    /// Top-level state.
    pub state: State,
    /// Current generation, 0 before the first activation.
    pub generation: u64,
    /// Engine child status.
    pub engine: EngineStatus,
    /// Policy population counts.
    pub policy: PolicyCounts,
    /// Per-interface status.
    pub ifaces: Vec<IfaceStatus>,
    /// Summed data-plane counters.
    pub counters: Counters,
    /// Selected sysctl values, e.g. `all.rp_filter` (blueprint §24.1).
    pub sysctl: BTreeMap<String, i64>,
    /// Free-text warnings (blueprint §24.3).
    pub warnings: Vec<String>,
    /// Derived hints translating counter combinations into hypotheses (§24.4).
    pub hints: Vec<String>,
    /// A stable error token, or null when there is no error (blueprint §24.2).
    pub last_error: Option<String>,
}

/// Encodes a value as a single-line JSON string, ready for one SEQPACKET frame.
pub fn to_line<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

/// Decodes a single-line JSON frame.
pub fn from_line<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(line)
}

/// Encodes one versioned request frame.
pub fn request_to_line(request: &Request) -> Result<String, serde_json::Error> {
    to_line(&RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request: *request,
    })
}

/// Decodes one request and rejects every version other than the one this
/// binary implements. Compatibility is never guessed.
pub fn request_from_line(line: &str) -> Result<Request, RequestDecodeError> {
    let envelope: RequestEnvelope = from_line(line).map_err(RequestDecodeError::Json)?;
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(RequestDecodeError::UnsupportedVersion(
            envelope.protocol_version,
        ));
    }
    Ok(envelope.request)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Blueprint §15.2 test 7: control-protocol request/response round-trip.

    #[test]
    fn request_round_trips_over_the_op_tag() {
        for request in [
            Request::Status,
            Request::Check,
            Request::Enable,
            Request::Disable,
            Request::Reload,
            Request::Stop,
        ] {
            let line = request_to_line(&request).expect("serialise");
            let back = request_from_line(&line).expect("deserialise");
            assert_eq!(request, back);
        }
        // The wire form uses the "op" tag exactly as blueprint §10.3 shows.
        assert_eq!(
            request_to_line(&Request::Status).unwrap(),
            r#"{"protocol_version":1,"op":"status"}"#
        );
    }

    #[test]
    fn unknown_request_op_is_rejected() {
        assert!(request_from_line(r#"{"protocol_version":1,"op":"nuke"}"#).is_err());
    }

    #[test]
    fn unknown_protocol_version_is_rejected() {
        let err = request_from_line(r#"{"protocol_version":999,"op":"status"}"#)
            .expect_err("must reject an incompatible client");
        assert!(matches!(err, RequestDecodeError::UnsupportedVersion(999)));
    }

    #[test]
    fn state_serialises_in_the_blueprint_casing() {
        assert_eq!(to_line(&State::Active).unwrap(), r#""Active""#);
        assert_eq!(to_line(&State::Disabled).unwrap(), r#""Disabled""#);
        assert_eq!(to_line(&State::Inactive).unwrap(), r#""Inactive""#);
    }

    #[test]
    fn response_round_trips() {
        let mut sysctl = BTreeMap::new();
        sysctl.insert("all.rp_filter".to_string(), 0);
        sysctl.insert("flxrs1.rp_filter".to_string(), 0);
        sysctl.insert("flxrs1.accept_local".to_string(), 1);

        let response = Response {
            protocol_version: PROTOCOL_VERSION,
            ok: true,
            version: "0.9.0".to_string(),
            abi_magic: format!("{:#010X}", crate::abi::FLUX_ABI_MAGIC),
            state: State::Active,
            generation: 7,
            engine: EngineStatus {
                running: true,
                pid: Some(1234),
                sockets_verified: 4,
                effective_config: Some("run/effective-sing-box.7.json".to_string()),
            },
            policy: PolicyCounts {
                selected: 3,
                draining: 1,
                bypass_v4: 12,
                bypass_v6: 6,
                self_addresses: 4,
            },
            ifaces: vec![
                IfaceStatus {
                    name: "wlan0".to_string(),
                    ifindex: 24,
                    arphrd: Some("ether".to_string()),
                    entry: Some("flx_cap_l2".to_string()),
                    status: "active".to_string(),
                    prog_id: Some(118),
                    prog_tag: Some("a1b2c3d4e5f60718".to_string()),
                    first_applicable: Some(true),
                    reason: None,
                },
                IfaceStatus {
                    name: "v4-rmnet_data0".to_string(),
                    ifindex: 31,
                    arphrd: Some("none".to_string()),
                    entry: None,
                    status: "excluded".to_string(),
                    prog_id: None,
                    prog_tag: None,
                    first_applicable: None,
                    reason: Some("clat_order_unverified".to_string()),
                },
            ],
            counters: Counters {
                admit_tcp: 41,
                direct_tcp: 190,
                admit_udp: 388,
                egress_listener_miss: 2,
                in_assign_tcp: 41,
                in_assign_udp: 388,
                in_pass_established: 5120,
                ..Counters::default()
            },
            sysctl,
            warnings: vec!["system private DNS is on; name resolution bypasses Flux".to_string()],
            hints: vec![],
            last_error: None,
        };

        let line = to_line(&response).expect("serialise");
        assert!(!line.contains('\n'), "a frame must be a single line");
        let back: Response = from_line(&line).expect("deserialise");
        assert_eq!(response, back);
    }

    #[test]
    fn counters_default_to_zero_when_absent() {
        // Forward compatibility: a partial counters object still decodes.
        let counters: Counters = from_line(r#"{"admit_tcp":5}"#).expect("partial decode");
        assert_eq!(counters.admit_tcp, 5);
        assert_eq!(counters.in_drop_assign, 0);
    }
}
