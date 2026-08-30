//! Control-protocol wire types.
//!
//! Implements the blueprint §10.3 and §24. The
//! transport is `SOCK_SEQPACKET` with a root-only peer check and one single-line
//! JSON message per packet; this module owns only the encoding, so it is fully
//! testable on any host (0.9.0 §15.2 test 7).
//!
//! The CLI is currently the only real adapter. The JSON shape stays stable to
//! avoid gratuitous breakage, but 0.9.1 does not pretend that an independent
//! wire-version or migration framework already exists.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Maximum accepted request size. Larger requests close the connection.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Top-level daemon state (blueprint §10.1, §24.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// The `disable` file is present; control is inactive and the engine is
    /// stopped. Owned kernel objects may remain until a later converge/reboot.
    Disabled,
    /// Enabled but control is inactive, e.g. starting up or blocked by an
    /// error. This does not by itself prove that no owned objects exist.
    Inactive,
    /// The engine generation is committed (`control active == 1`) and at least
    /// one physical capture interface is active; per-interface status describes
    /// the rest of the coverage.
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
    /// Persist disabled, publish inactive, and stop the engine. It does not
    /// promise synchronous TC/veth/rule/route/map teardown.
    Disable,
    /// Re-read configuration and converge.
    Reload,
    /// Publish inactive, stop the engine, and exit zero without a broad flush.
    Stop,
}

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
    /// IPv4 LPM entries, including fixed and user `bypass_cidrs`, but not the
    /// separate self-address HASH.
    pub bypass_v4: u32,
    /// IPv6 LPM entries, including fixed and user `bypass_cidrs`, but not the
    /// separate self-address HASH.
    pub bypass_v6: u32,
    /// Dynamically injected device-own address entries.
    pub self_addresses: u32,
}

/// Root-module manager identity exported by `service.sh` (blueprint §13.2.0).
///
/// KernelSU's runtime mode is operationally important: `lkm` and `late-load`
/// use the vendor kernel and therefore have a different BPF capability profile
/// from `built-in`.  Keeping this structured avoids burying the first support
/// question in a free-text warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RootManagerStatus {
    /// `magisk`, `kernelsu`, `apatch`, or `unknown` for a manual launch.
    pub name: String,
    /// Manager version as supplied by its documented environment.
    pub version: String,
    /// KernelSU `built-in` / `lkm` / `late-load`; `n/a` otherwise.
    pub runtime_mode: String,
}

impl Default for RootManagerStatus {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            version: "unknown".to_string(),
            runtime_mode: "n/a".to_string(),
        }
    }
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
    /// The TC preference this interface's capture filter occupies. Chosen per
    /// interface, so two interfaces on one device may differ (§8.5.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pref: Option<u16>,
    /// Whether liveness verification established filter reachability. Absent
    /// until reachability has actually been decided one way or the other.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reachable: Option<bool>,
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
    /// Whole seconds remaining before the next crash-recovery attempt; zero
    /// when no one-shot backoff is armed (blueprint §25).
    #[serde(default)]
    pub backoff_seconds: u64,
    /// Root manager and, for KernelSU, its runtime mode (§13.2.0).
    #[serde(default)]
    pub root_manager: RootManagerStatus,
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
            let line = to_line(&request).expect("serialise");
            let back: Request = from_line(&line).expect("deserialise");
            assert_eq!(request, back);
        }
        // The wire form uses the "op" tag exactly as blueprint §10.3 shows.
        assert_eq!(to_line(&Request::Status).unwrap(), r#"{"op":"status"}"#);
    }

    #[test]
    fn unknown_request_op_is_rejected() {
        assert!(from_line::<Request>(r#"{"op":"nuke"}"#).is_err());
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
            ok: true,
            version: "0.9.0".to_string(),
            abi_magic: format!("{:#010X}", crate::abi::FLUX_ABI_MAGIC),
            state: State::Active,
            generation: 7,
            backoff_seconds: 0,
            root_manager: RootManagerStatus {
                name: "kernelsu".to_string(),
                version: "1.0.5".to_string(),
                runtime_mode: "lkm".to_string(),
            },
            engine: EngineStatus {
                running: true,
                pid: Some(1234),
                sockets_verified: 4,
                effective_config: Some("run/sing-box.7.json".to_string()),
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
                    pref: Some(2),
                    reachable: Some(true),
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
                    pref: None,
                    reachable: None,
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
    fn reachable_preserves_all_three_wire_states() {
        let absent: IfaceStatus = from_line(r#"{"name":"wlan0","ifindex":24,"status":"admitted"}"#)
            .expect("decode absent reachability");
        assert_eq!(absent.reachable, None);
        assert!(!to_line(&absent).unwrap().contains("\"reachable\""));

        let unreachable: IfaceStatus =
            from_line(r#"{"name":"wlan0","ifindex":24,"status":"excluded","reachable":false}"#)
                .expect("decode negative reachability");
        assert_eq!(unreachable.reachable, Some(false));
        assert!(to_line(&unreachable)
            .unwrap()
            .contains("\"reachable\":false"));

        let reachable: IfaceStatus =
            from_line(r#"{"name":"wlan0","ifindex":24,"status":"active","reachable":true}"#)
                .expect("decode positive reachability");
        assert_eq!(reachable.reachable, Some(true));
        assert!(to_line(&reachable).unwrap().contains("\"reachable\":true"));
    }

    #[test]
    fn counters_default_to_zero_when_absent() {
        // Forward compatibility: a partial counters object still decodes.
        let counters: Counters = from_line(r#"{"admit_tcp":5}"#).expect("partial decode");
        assert_eq!(counters.admit_tcp, 5);
        assert_eq!(counters.in_drop_assign, 0);
    }
}
