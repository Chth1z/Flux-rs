//! Rust mirror of `bpf/include/flux_abi.h`.
//!
//! `bpf/include/flux_abi.h` is the ONLY source of truth. This module is a hand
//! written mirror, and the tests at the bottom assert `size_of`, `align_of` and
//! every field offset against the values documented in the header. Blueprint §6
//! requires those assertions to exist; CI additionally has clang print the C
//! offsets and compares them against this file.
//!
//! Changing any layout REQUIRES bumping [`FLUX_ABI_MAGIC`] on both sides.
//!
//! Byte-order rule inherited from the header: fields documented `be` are network
//! byte order because they are compared against packet bytes directly. Every
//! other multi-byte field is host order.

/// Bumped on ANY layout, map-set or semantic change. Unrelated to SemVer.
///
/// * `0xF10C0903` map set 9 to 12: local addresses move out of the bypass LPM
///   tries into exact HASH maps, a per-UID byte counter is added, and the
///   listener addresses move clear of sing-box's conventional fakeip range
///   (blueprint D20, D21, D23).
/// * `0xF10C0902` added the [`PROG_VERIFY`] probe program and
///   [`Counter::SawPacket`] for the positive liveness check (blueprint §8.5.4).
/// * `0xF10C0901` dropped `peer_mac` / `host_mac`; ingress forces
///   `PACKET_HOST` instead (blueprint D17).
pub const FLUX_ABI_MAGIC: u32 = 0xF10C_0903;

/// Guards against reading uninitialised or foreign socket storage.
pub const FLUX_DECISION_MAGIC: u32 = 0xD3C1_5100;

// ------------------------------------------------------------------ map names

/// `HASH`, `u32 -> u8`.
pub const MAP_UID_POLICY: &str = "uid_policy";
/// `LPM_TRIE`, `BPF_F_NO_PREALLOC`. Prefixes only.
pub const MAP_BYPASS_V4: &str = "bypass_v4";
/// `LPM_TRIE`, `BPF_F_NO_PREALLOC`. Prefixes only.
pub const MAP_BYPASS_V6: &str = "bypass_v6";

/// The device's own IPv4 addresses, kept out of the LPM trie on purpose.
///
/// They are always full-length prefixes, so a trie buys nothing over exact
/// hashing, `HASH` deletes cleanly as addresses come and go, and it sidesteps
/// the LPM trie UBSAN crash on 6.6.0–6.6.46 (blueprint D20, §1.5.3a).
pub const MAP_SELF_ADDR_V4: &str = "self_addr_v4";
/// The device's own IPv6 addresses. See [`MAP_SELF_ADDR_V4`].
pub const MAP_SELF_ADDR_V6: &str = "self_addr_v6";

/// `PERCPU_HASH`, per-UID byte and packet counters.
///
/// Updated only on captured packets, so unselected traffic is untouched.
/// Carries no address, port or time series — nothing that could reconstruct
/// browsing history (blueprint D23, §1.5.6).
pub const MAP_UID_STATS: &str = "uid_stats";
/// `SK_STORAGE`, `BPF_F_NO_PREALLOC`, requires BTF.
pub const MAP_TCP_DECISION: &str = "tcp_decision";
/// `ARRAY_OF_MAPS`, 1 entry: holds the current control leaf.
pub const MAP_CONTROL_ROOT: &str = "control_root";
/// `ARRAY`, 1 entry, frozen after write, published via `control_root`.
pub const MAP_CONTROL_LEAF: &str = "control_leaf";
/// `HASH`, 64 entries: de-duplicates fault notifications.
pub const MAP_FAULT_LATCH: &str = "fault_latch";
/// `RINGBUF`, 16384 bytes.
pub const MAP_FAULT_EVENTS: &str = "fault_events";
/// `PERCPU_ARRAY`, 32 slots, `u32 -> u64`.
pub const MAP_COUNTERS: &str = "counters";

/// Every map symbol name the loader must bind, in declaration order.
pub const MAP_NAMES: [&str; 12] = [
    MAP_UID_POLICY,
    MAP_BYPASS_V4,
    MAP_BYPASS_V6,
    MAP_SELF_ADDR_V4,
    MAP_SELF_ADDR_V6,
    MAP_UID_STATS,
    MAP_TCP_DECISION,
    MAP_CONTROL_ROOT,
    MAP_CONTROL_LEAF,
    MAP_FAULT_LATCH,
    MAP_FAULT_EVENTS,
    MAP_COUNTERS,
];

// --------------------------------------------------------------------- limits

/// `uid_policy` capacity.
///
/// Must hold the selected set plus every `DRAINING` entry accumulated during a
/// boot, since those are never deleted (see [`UidMode::Draining`]).
pub const UID_POLICY_MAX_ENTRIES: u32 = 4096;

/// Hard cap on simultaneously selected UIDs.
///
/// Sized from measurement: SM-S9180 carries 429 packages inside the
/// `[10000, 19999]` application range, so the previous cap of 128 made
/// "select every third-party app" structurally impossible (blueprint §1.5.3).
pub const UID_SELECTED_MAX: u32 = 1024;

/// Capacity of each bypass LPM trie.
///
/// The kernel forces `BPF_F_NO_PREALLOC` on `LPM_TRIE`, so this is a ceiling
/// rather than an allocation and an unused 65536 costs nothing. It is what
/// lets the bypass set hold a country-scale route list and skip a userspace
/// round trip for traffic that would have gone direct anyway (blueprint
/// §1.5.1).
pub const LPM_MAX_ENTRIES: u32 = 65536;

/// Capacity of each self-address `HASH` map.
///
/// No longer carved out of the LPM capacity, since local addresses have their
/// own maps now (D20). The reactor filters on `IFA_FLAGS` — `tentative` and
/// `dadfailed` are never inserted, `deprecated` is kept because existing
/// connections still use it — and evicts least-recently-seen within this bound
/// as IPv6 privacy addresses rotate (blueprint §1.5.4).
pub const SELF_ADDR_MAX_ENTRIES: u32 = 256;

/// `uid_stats` capacity. Matches [`UID_POLICY_MAX_ENTRIES`]: a UID that can be
/// selected must be countable.
pub const UID_STATS_MAX_ENTRIES: u32 = 4096;
/// `fault_latch` capacity.
pub const FAULT_LATCH_MAX_ENTRIES: u32 = 64;
/// Power of two AND page-size aligned for both 4 KiB and 16 KiB base pages.
pub const FAULT_RINGBUF_BYTES: u32 = 16384;
/// `counters` slot count.
pub const COUNTER_SLOTS: u32 = 32;

// ----------------------------------------------------------- selector bounds

/// Lowest Android application UID (`FIRST_APPLICATION_UID`).
pub const APP_ID_MIN: u32 = 10_000;
/// Highest Android application UID (`LAST_APPLICATION_UID`).
pub const APP_ID_MAX: u32 = 19_999;
/// Android per-user UID stride.
pub const USER_ID_STRIDE: u32 = 100_000;
/// Highest accepted Android user id.
pub const USER_ID_MAX: u32 = 999;

// ------------------------------------------------------- listener identities

/// RFC 5737 TEST-NET-2 address the TProxy listener binds for IPv4.
///
/// Deliberately clear of `198.18.0.0/15`, which sing-box conventionally uses
/// for fakeip. The old choice reserved that whole `/15` in the fixed bypass,
/// which made every fakeip address un-capturable and broke fakeip silently and
/// completely (blueprint D21, §9.0).
pub const LISTEN_V4_STR: &str = "198.51.100.1";
/// RFC 3849 documentation address the TProxy listener binds for IPv6.
///
/// Narrowed from the whole `2001:db8::/32` for the same reason as
/// [`LISTEN_V4_STR`], leaving the rest of the documentation range usable.
pub const LISTEN_V6_STR: &str = "2001:db8:0:1::2";
/// RFC 5737 TEST-NET-1 address used as the liveness probe remote.
pub const PROBE_REMOTE_V4_STR: &str = "192.0.2.1";
/// Documentation-range IPv6 liveness probe remote.
pub const PROBE_REMOTE_V6_STR: &str = "2001:db8:ffff::1";
/// Discard port, used only as a probe tuple component.
pub const PROBE_REMOTE_PORT: u16 = 9;
/// Above Android's usual `ip_local_port_range` so it cannot collide.
pub const LISTEN_PORT_MIN: u16 = 61_000;
/// Inclusive upper bound of the listener port draw.
pub const LISTEN_PORT_MAX: u16 = 65_535;

// -------------------------------------------------------------- parse limits

/// Ethernet header length.
pub const ETH_HLEN: u32 = 14;
/// Maximum IPv6 extension headers walked before giving up.
pub const IPV6_MAX_EXT_HDRS: u32 = 4;
/// Maximum IPv6 extension header bytes walked before giving up.
pub const IPV6_MAX_EXT_BYTES: u32 = 256;
/// Worst-case linear header bytes needed to reach the L4 header.
pub const MAX_PULL_BYTES: u32 = ETH_HLEN + 40 + IPV6_MAX_EXT_BYTES + 20;

// ------------------------------------------------------------- program names

/// Egress entry for `ARPHRD_ETHER` interfaces.
pub const PROG_CAP_L2: &str = "flx_cap_l2";
/// Egress entry for `ARPHRD_RAWIP` / confirmed CLAT tun interfaces.
pub const PROG_CAP_L3: &str = "flx_cap_l3";
/// Ingress entry on the veth peer.
pub const PROG_IN: &str = "flx_in";
/// Liveness probe, attached and removed during activation (blueprint §8.5.4).
pub const PROG_VERIFY: &str = "flx_verify";

/// Every program symbol the loader must find in the embedded object.
pub const PROG_NAMES: [&str; 4] = [PROG_CAP_L2, PROG_CAP_L3, PROG_IN, PROG_VERIFY];

// ------------------------------------------------------------- ELF sections

/// ELF section holding [`PROG_CAP_L2`].
pub const SEC_CAP_L2: &str = "tc";
/// ELF section holding [`PROG_CAP_L3`].
pub const SEC_CAP_L3: &str = "classifier";
/// ELF section holding [`PROG_IN`].
pub const SEC_IN: &str = "tc/ingress";
/// ELF section holding [`PROG_VERIFY`].
pub const SEC_VERIFY: &str = "tc/egress";

/// Program symbol paired with the section that holds it, in the order the
/// loader walks them.
///
/// These names are constrained, not chosen for looks. libbpf recognises only a
/// fixed set of section names for `BPF_PROG_TYPE_SCHED_CLS`, and an object using
/// anything else cannot be loaded by `bpftool` at all -- which would cost the
/// project its cheapest verifier gate. Measured on the baseline in
/// `docs/verification/phase0.md` §16.7: `tc`, `classifier`, `tc/ingress`,
/// `tc/egress` and `tcx/egress` all load and attach through legacy tc, any
/// `<prefix>/<custom>` form fails to load, and `action` loads as `SCHED_ACT`
/// and then cannot attach.
///
/// One program per section is also deliberate: several programs can share a
/// single section, but then relocation offsets are section-relative rather than
/// program-relative and the loader has to rebase them per function. Keeping one
/// program per section removes that class of bug outright.
pub const PROG_SECTIONS: [(&str, &str); 4] = [
    (PROG_CAP_L2, SEC_CAP_L2),
    (PROG_CAP_L3, SEC_CAP_L3),
    (PROG_IN, SEC_IN),
    (PROG_VERIFY, SEC_VERIFY),
];

// ----------------------------------------------------------- network objects

/// veth end that receives redirected packets.
pub const VETH_HOST: &str = "flxrs0";
/// veth end that carries the ingress program.
pub const VETH_PEER: &str = "flxrs1";
/// `IFLA_IFALIAS` on the host end, used by the ownership predicate.
pub const VETH_HOST_ALIAS: &str = "flux-rs:managed:v1:host";
/// `IFLA_IFALIAS` on the peer end, used by the ownership predicate.
pub const VETH_PEER_ALIAS: &str = "flux-rs:managed:v1:peer";
/// MTU set on both veth ends so GSO super-packets are never rejected.
pub const VETH_MTU: u32 = 65_535;
/// `ip rule` priority, inside the 1..9999 window netd leaves free.
pub const RULE_PRIORITY: u32 = 100;
/// Routing table id, outside netd's `1000 + ifindex` range.
pub const ROUTE_TABLE: u32 = 20_260;
/// `rtm_protocol` tag for exact self-identification.
pub const ROUTE_PROTO: u8 = 202;
/// TC chain the filters live on.
pub const TC_CHAIN: u32 = 0;
/// TC handle of the egress filter.
pub const TC_HANDLE_EGRESS: u32 = 0x1;
/// TC handle of the ingress filter.
pub const TC_HANDLE_INGRESS: u32 = 0x2;
/// TC handle used by the liveness probe while attached. Distinct from the
/// capture handle so the ownership predicate can never confuse the two, and so
/// a crash mid-verification leaves an object we can still identify and remove.
pub const TC_HANDLE_VERIFY: u32 = 0x3;

/// First-choice egress preference, deliberately past the preference vendors
/// use.
///
/// Egress preference is chosen at attach time, not fixed. Measured on
/// SM-S9180 / Android 16, Samsung's `semUidBPF` already holds chain 0 /
/// pref 1 / handle 0x1 / protocol all on `wlan0`'s clsact egress, and `tc`
/// preferences start at 1, so there is no way to order ahead of it there.
/// See 0.9.0 `docs/blueprint.md` §8.5.3 as corrected by R091-05.
pub const TC_PREF_PREFERRED: u16 = 2;

/// The `tc` floor. Used only when no higher preference can satisfy the
/// ordering constraints, and never preferred: the vendor attaches late, so
/// taking pref 1 either breaks its attach or gets silently replaced by it.
pub const TC_PREF_MIN: u16 = 1;

/// On a CLAT `v4-*` interface the chosen preference must be strictly below
/// this, because AOSP's CLAT egress translation sits at 4. If nothing below is
/// free, exclude the interface rather than ordering after CLAT.
pub const TC_PREF_CLAT_MAX: u16 = 4;

// ------------------------------------------------------------------ uid_policy

/// Value stored in `uid_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UidMode {
    /// New TCP may install DIRECT or CAPTURED; UDP may be admitted.
    Selected = 1,
    /// Existing decisions keep working; a first SYN installs DIRECT and UDP
    /// goes direct. Entries are NEVER deleted within a boot once they could
    /// have created socket storage, because a `uid_policy` miss is the short
    /// direct path and deleting would leak a captured socket's packets.
    Draining = 2,
}

// ---------------------------------------------------------------- tcp_decision

/// Per-socket first decision mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DecisionMode {
    /// Pinned to the Android path. NOT an admission.
    Direct = 1,
    /// Admitted. Observing this value is the TCP admission boundary: from the
    /// next instruction on, failure means drop, never a silent fall back.
    Captured = 2,
}

/// Per-app-socket first decision. Created once, never updated in place,
/// released with the socket.
///
/// C: `struct flux_decision`, size 16, align 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Decision {
    /// Must equal [`FLUX_DECISION_MAGIC`], else treat the storage as corrupt.
    pub magic: u32,
    /// A [`DecisionMode`] discriminant.
    pub mode: u8,
    /// Must be zero; non-zero means corrupt, which means drop.
    pub reserved: [u8; 3],
    /// Admitting generation when CAPTURED, zero when DIRECT.
    pub generation: u64,
}

// ---------------------------------------------------------------- control leaf

/// Immutable control snapshot. Written once, `BPF_MAP_FREEZE`d, then published
/// by a single `bpf_map_update_elem` on `control_root` (map-in-map pointer swap
/// under RCU).
///
/// A BPF invocation must look `control_root` up exactly once and hold the
/// returned inner pointer for the rest of the invocation, so it can only ever
/// observe a complete old or a complete new snapshot.
///
/// There are deliberately no MAC fields: ingress calls
/// `bpf_skb_change_type(skb, PACKET_HOST)` instead of rewriting the MAC on the
/// egress hot path (blueprint D17).
///
/// C: `struct flux_control`, size 96, align 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Control {
    /// Must equal [`FLUX_ABI_MAGIC`].
    pub abi_magic: u32,
    /// 0 or 1.
    pub active: u32,
    /// Monotonic within a boot, >= 1.
    pub generation: u64,
    /// `bpf_redirect()` target.
    pub flxrs0_ifindex: u32,
    /// Ingress anchor, diagnostics only.
    pub flxrs1_ifindex: u32,
    /// Listener port, network byte order.
    pub listen_port_v4: u16,
    /// Listener port, network byte order.
    pub listen_port_v6: u16,
    /// Listener address, network byte order.
    pub listen_v4: [u8; 4],
    /// Liveness probe remote, network byte order.
    pub probe_remote_v4: [u8; 4],
    /// Liveness probe remote port, network byte order.
    pub probe_remote_port: u16,
    /// Must be zero.
    pub pad0: [u8; 2],
    /// Listener address, network byte order.
    pub listen_v6: [u8; 16],
    /// Liveness probe remote, network byte order.
    pub probe_remote_v6: [u8; 16],
    /// Diagnostics only.
    pub selected_count: u32,
    /// Diagnostics only.
    pub draining_count: u32,
    /// Diagnostics only.
    pub bypass_v4_count: u32,
    /// Diagnostics only.
    pub bypass_v6_count: u32,
    /// Must be zero.
    pub pad1: [u8; 8],
}

// ------------------------------------------------------------------ uid_stats

/// Per-UID totals, updated only on captured packets.
///
/// Unselected traffic never touches this map, so the §14.1 budget is
/// unaffected. Deliberately carries no address, no port and no time series: it
/// answers "how much did this app send through the proxy" and nothing that
/// could reconstruct where it went (blueprint D23, §1.6.6).
///
/// C: `struct flux_uid_stats`, size 16, align 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct UidStats {
    /// Captured packets attributed to this UID.
    pub packets: u64,
    /// Captured bytes attributed to this UID.
    pub bytes: u64,
}

// --------------------------------------------------------------------- bypass

/// LPM trie key for the IPv4 bypass set. C: size 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct LpmV4Key {
    /// Prefix length in bits.
    pub prefixlen: u32,
    /// Network byte order.
    pub addr: [u8; 4],
}

/// LPM trie key for the IPv6 bypass set. C: size 20.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct LpmV6Key {
    /// Prefix length in bits.
    pub prefixlen: u32,
    /// Network byte order.
    pub addr: [u8; 16],
}

// ---------------------------------------------------------------------- fault

/// Why the data plane raised a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FaultReason {
    /// Egress listener lookup or guard failed. The packet was NOT modified, so
    /// the caller returns `TC_ACT_UNSPEC` and the flow goes direct.
    EgressListener = 1,
    /// Ingress is already past admission; lookup, guard or assign failed and
    /// the packet is dropped.
    IngressAssign = 2,
}

/// De-duplication key. Must be fully zeroed before use because the padding
/// participates in hashing. C: size 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FaultKey {
    /// Generation the fault belongs to.
    pub generation: u64,
    /// 4 or 6.
    pub family: u8,
    /// `IPPROTO_TCP` or `IPPROTO_UDP`.
    pub protocol: u8,
    /// A [`FaultReason`] discriminant.
    pub reason: u16,
    /// Must be zero.
    pub pad0: u32,
}

/// Ring-buffer record. Carries no header, UID, address or payload. Ever.
/// C: size 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FaultEvent {
    /// Generation the fault belongs to.
    pub generation: u64,
    /// 4 or 6.
    pub family: u8,
    /// `IPPROTO_TCP` or `IPPROTO_UDP`.
    pub protocol: u8,
    /// A [`FaultReason`] discriminant.
    pub reason: u16,
    /// Must be zero.
    pub pad0: u32,
    /// Optional debug correlation, may be zero.
    pub seq: u64,
    /// Must be zero.
    pub pad1: u64,
}

// ------------------------------------------------------------------- counters

/// `counters` slot indices. Incremented ONLY on decision, drop and fault edges,
/// never on the steady-state per-packet path of unselected traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Counter {
    /// First SYN installed CAPTURED.
    AdmitTcp = 0,
    /// First SYN installed DIRECT.
    DirectTcp = 1,
    /// Datagram admitted.
    AdmitUdp = 2,
    /// Captured socket seen while `active == 0`.
    DropInactive = 3,
    /// Captured socket seen with an old generation.
    DropStaleGen = 4,
    /// Ethernet write or `bpf_skb_change_head` failed.
    DropHandoff = 5,
    /// Selected and active UDP fragment.
    DropUdpFrag = 6,
    /// Decision magic or reserved bytes were bad.
    DropCorrupt = 7,
    /// `BPF_F_CREATE` and the re-read both returned NULL.
    DecisionAllocFail = 8,
    /// Egress could not find a live listener.
    EgressListenerMiss = 9,
    /// Ingress assigned a TCP listener.
    InAssignTcp = 10,
    /// Ingress assigned a UDP socket.
    InAssignUdp = 11,
    /// Ingress passed an established TCP packet to the normal lookup.
    InPassEstablished = 12,
    /// Ingress passed a fragment to the normal lookup.
    InPassFragment = 13,
    /// Ingress found no listener.
    InDropNoListener = 14,
    /// Ingress `bpf_sk_assign` failed.
    InDropAssign = 15,
    /// Ingress could not parse the packet.
    InDropParse = 16,
    /// Ingress saw an invalid control snapshot.
    InDropSnapshot = 17,
    /// Touched only by the [`PROG_VERIFY`] probe, never by the capture or
    /// ingress entries (blueprint §8.5.4).
    SawPacket = 18,
}

impl Counter {
    /// One past the highest slot in use. Must stay `<= COUNTER_SLOTS`.
    pub const MAX: u32 = 19;
}

// -------------------------------------------------- compile-time ABI checks
//
// These are build-time, not test-time, on purpose: an ABI that cannot hold its
// own invariants must not compile at all.

const _: () = assert!(
    Counter::MAX <= COUNTER_SLOTS,
    "counter enum outgrew the reserved PERCPU_ARRAY slots"
);

const _: () = assert!(
    UID_STATS_MAX_ENTRIES >= UID_POLICY_MAX_ENTRIES,
    "a UID that can be selected must be countable"
);

const _: () = assert!(
    FAULT_RINGBUF_BYTES.is_power_of_two()
        && FAULT_RINGBUF_BYTES.is_multiple_of(4096)
        && FAULT_RINGBUF_BYTES.is_multiple_of(16384),
    "ringbuf size must be a power of two and page aligned for 4 KiB and 16 KiB pages"
);

const _: () = assert!(
    UID_SELECTED_MAX <= UID_POLICY_MAX_ENTRIES,
    "selected UID cap exceeds uid_policy capacity"
);

const _: () = assert!(
    APP_ID_MIN < APP_ID_MAX && APP_ID_MAX < USER_ID_STRIDE,
    "application id range must fit inside one per-user stride"
);

const _: () = assert!(
    LISTEN_PORT_MIN < LISTEN_PORT_MAX,
    "listener port draw range is empty"
);

const _: () = assert!(
    TC_PREF_MIN <= TC_PREF_PREFERRED && TC_PREF_PREFERRED < TC_PREF_CLAT_MAX,
    "the preferred TC egress preference must be usable on a CLAT interface"
);

// The ownership predicate distinguishes our objects by handle, so a collision
// here would make a leftover verification filter indistinguishable from a live
// capture filter after a crash.
const _: () = assert!(
    TC_HANDLE_EGRESS != TC_HANDLE_INGRESS
        && TC_HANDLE_EGRESS != TC_HANDLE_VERIFY
        && TC_HANDLE_INGRESS != TC_HANDLE_VERIFY,
    "TC handles must be pairwise distinct"
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn decision_layout_matches_header() {
        assert_eq!(size_of::<Decision>(), 16);
        assert_eq!(align_of::<Decision>(), 8);
        assert_eq!(offset_of!(Decision, magic), 0);
        assert_eq!(offset_of!(Decision, mode), 4);
        assert_eq!(offset_of!(Decision, reserved), 5);
        assert_eq!(offset_of!(Decision, generation), 8);
    }

    #[test]
    fn control_layout_matches_header() {
        assert_eq!(size_of::<Control>(), 96);
        assert_eq!(align_of::<Control>(), 8);
        assert_eq!(offset_of!(Control, abi_magic), 0);
        assert_eq!(offset_of!(Control, active), 4);
        assert_eq!(offset_of!(Control, generation), 8);
        assert_eq!(offset_of!(Control, flxrs0_ifindex), 16);
        assert_eq!(offset_of!(Control, flxrs1_ifindex), 20);
        assert_eq!(offset_of!(Control, listen_port_v4), 24);
        assert_eq!(offset_of!(Control, listen_port_v6), 26);
        assert_eq!(offset_of!(Control, listen_v4), 28);
        assert_eq!(offset_of!(Control, probe_remote_v4), 32);
        assert_eq!(offset_of!(Control, probe_remote_port), 36);
        assert_eq!(offset_of!(Control, pad0), 38);
        assert_eq!(offset_of!(Control, listen_v6), 40);
        assert_eq!(offset_of!(Control, probe_remote_v6), 56);
        assert_eq!(offset_of!(Control, selected_count), 72);
        assert_eq!(offset_of!(Control, draining_count), 76);
        assert_eq!(offset_of!(Control, bypass_v4_count), 80);
        assert_eq!(offset_of!(Control, bypass_v6_count), 84);
        assert_eq!(offset_of!(Control, pad1), 88);
    }

    #[test]
    fn uid_stats_layout_matches_header() {
        assert_eq!(size_of::<UidStats>(), 16);
        assert_eq!(align_of::<UidStats>(), 8);
        assert_eq!(offset_of!(UidStats, packets), 0);
        assert_eq!(offset_of!(UidStats, bytes), 8);
    }

    #[test]
    fn lpm_key_layout_matches_header() {
        assert_eq!(size_of::<LpmV4Key>(), 8);
        assert_eq!(offset_of!(LpmV4Key, prefixlen), 0);
        assert_eq!(offset_of!(LpmV4Key, addr), 4);

        assert_eq!(size_of::<LpmV6Key>(), 20);
        assert_eq!(offset_of!(LpmV6Key, prefixlen), 0);
        assert_eq!(offset_of!(LpmV6Key, addr), 4);
    }

    #[test]
    fn fault_layout_matches_header() {
        assert_eq!(size_of::<FaultKey>(), 16);
        assert_eq!(offset_of!(FaultKey, generation), 0);
        assert_eq!(offset_of!(FaultKey, family), 8);
        assert_eq!(offset_of!(FaultKey, protocol), 9);
        assert_eq!(offset_of!(FaultKey, reason), 10);
        assert_eq!(offset_of!(FaultKey, pad0), 12);

        assert_eq!(size_of::<FaultEvent>(), 32);
        assert_eq!(offset_of!(FaultEvent, generation), 0);
        assert_eq!(offset_of!(FaultEvent, family), 8);
        assert_eq!(offset_of!(FaultEvent, protocol), 9);
        assert_eq!(offset_of!(FaultEvent, reason), 10);
        assert_eq!(offset_of!(FaultEvent, pad0), 12);
        assert_eq!(offset_of!(FaultEvent, seq), 16);
        assert_eq!(offset_of!(FaultEvent, pad1), 24);
    }

    #[test]
    fn map_name_table_has_no_duplicates() {
        let mut seen = MAP_NAMES;
        seen.sort_unstable();
        for pair in seen.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate map name in MAP_NAMES");
        }
    }

    #[test]
    fn prog_name_table_has_no_duplicates() {
        let mut seen = PROG_NAMES;
        seen.sort_unstable();
        for pair in seen.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate program name in PROG_NAMES");
        }
    }

    #[test]
    fn object_symbol_names_are_plausible_c_identifiers() {
        // The loader binds relocations by symbol name, so a stray space or
        // hyphen here would fail at load time on a device rather than in CI.
        for name in MAP_NAMES.iter().chain(PROG_NAMES.iter()) {
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{name} is not a valid C identifier"
            );
            assert!(
                !name.starts_with(|c: char| c.is_ascii_digit()),
                "{name} starts with a digit"
            );
        }
    }
}
