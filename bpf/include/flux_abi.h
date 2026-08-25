/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Flux-rs 0.9.0 — data-plane ABI.
 *
 * This header is the ONLY source of truth for every byte exchanged between
 * bpf/flux.bpf.c and crates/fluxd. crates/flux-core/src/abi.rs mirrors it by
 * hand and MUST carry #[test] assertions on size_of and every field offset.
 *
 * Changing any layout REQUIRES bumping FLUX_ABI_MAGIC.
 *
 * Byte order rules:
 *   - Fields documented as "be" are network byte order and are compared
 *     against packet bytes directly.
 *   - Every other multi-byte field is host byte order (same machine, same
 *     architecture on both sides).
 *   - Reminder of a kernel ABI inconsistency: struct bpf_sock::src_port is
 *     HOST order while struct bpf_sock::dst_port is NETWORK order.
 */

#ifndef FLUX_ABI_H
#define FLUX_ABI_H

#include <linux/types.h>

/* ------------------------------------------------------------------ magic */

/* Bump on ANY layout, map-set or semantic change. Not related to SemVer.
 * 0xF10C0901: dropped peer_mac/host_mac; ingress forces PACKET_HOST instead.
 */
#define FLUX_ABI_MAGIC 0xF10C0901u

/* Guards against reading uninitialised or foreign socket storage. */
#define FLUX_DECISION_MAGIC 0xD3C15100u

/* --------------------------------------------------------------- map names
 *
 * The loader (fluxd/src/bpf/maps.rs) owns the authoritative map parameters
 * and binds relocations by these exact symbol names. The declarations in
 * flux.bpf.c are documentation; the two MUST agree and a flux-core test
 * checks the table against this header.
 */
#define FLUX_MAP_UID_POLICY   "uid_policy"    /* HASH        512   u32 -> u8   */
#define FLUX_MAP_BYPASS_V4    "bypass_v4"     /* LPM_TRIE    128   NO_PREALLOC */
#define FLUX_MAP_BYPASS_V6    "bypass_v6"     /* LPM_TRIE    128   NO_PREALLOC */
#define FLUX_MAP_TCP_DECISION "tcp_decision"  /* SK_STORAGE  0     NO_PREALLOC + BTF */
#define FLUX_MAP_CONTROL_ROOT "control_root"  /* ARRAY_OF_MAPS 1                */
#define FLUX_MAP_CONTROL_LEAF "control_leaf"  /* ARRAY       1     inner        */
#define FLUX_MAP_FAULT_LATCH  "fault_latch"   /* HASH        64                 */
#define FLUX_MAP_FAULT_EVENTS "fault_events"  /* RINGBUF     16384 bytes        */
#define FLUX_MAP_COUNTERS     "counters"      /* PERCPU_ARRAY 32   u32 -> u64   */

#define FLUX_UID_POLICY_MAX_ENTRIES 512u
#define FLUX_UID_SELECTED_MAX       128u
#define FLUX_LPM_MAX_ENTRIES        128u
#define FLUX_LPM_SELF_ADDR_RESERVE   32u
#define FLUX_FAULT_LATCH_MAX_ENTRIES 64u
/* Power of two AND PAGE_SIZE aligned for both 4 KiB and 16 KiB pages. */
#define FLUX_FAULT_RINGBUF_BYTES     16384u
#define FLUX_COUNTER_SLOTS           32u

/* ------------------------------------------------------------ uid_policy */

enum flux_uid_mode {
	/* New TCP may install DIRECT or CAPTURED; UDP may be admitted. */
	FLUX_UID_SELECTED = 1,
	/* Existing TCP decisions keep working; a first SYN with no decision
	 * installs DIRECT; UDP goes direct. Entries are NEVER deleted within a
	 * boot once they could have created socket storage, because "uid_policy
	 * miss" is the short direct path and deleting would leak an already
	 * captured socket's packets to the real destination.
	 */
	FLUX_UID_DRAINING = 2,
};

/* Android per-user app UID range. Anything outside is a configuration error;
 * this is what structurally guarantees the root-owned engine (uid 0) can
 * never appear in uid_policy.
 */
#define FLUX_APP_ID_MIN 10000u
#define FLUX_APP_ID_MAX 19999u
#define FLUX_USER_ID_STRIDE 100000u
#define FLUX_USER_ID_MAX 999u

/* --------------------------------------------------------- tcp_decision */

enum flux_decision_mode {
	/* This socket is pinned to the Android path. NOT an admission. */
	FLUX_DEC_DIRECT = 1,
	/* This socket is admitted. Observing this value is the TCP admission
	 * boundary: from the next instruction on, failure means drop, never
	 * a silent fall back to the real destination.
	 */
	FLUX_DEC_CAPTURED = 2,
};

/* Per-app-socket first decision. Created once with an initial value and then
 * NEVER updated in place. Released with the socket; there is no LRU capacity
 * so an active flow can never be evicted.
 *
 * size 16, align 8
 */
struct flux_decision {
	__u32 magic;       /* 0  == FLUX_DECISION_MAGIC, else treat as corrupt */
	__u8 mode;         /* 4  enum flux_decision_mode                       */
	__u8 reserved[3];  /* 5  MUST be 0; non-zero => corrupt => drop        */
	__u64 generation;  /* 8  CAPTURED: admitting generation. DIRECT: 0     */
};

/* ---------------------------------------------------------- control leaf */

/* Immutable snapshot. Written once, BPF_MAP_FREEZE'd, then published by a
 * single bpf_map_update_elem on control_root (map-in-map pointer swap under
 * RCU). A BPF invocation MUST look control_root up exactly once and hold the
 * returned inner pointer for the rest of the invocation, so it can only ever
 * observe a complete old or complete new snapshot.
 *
 * size 96, align 8
 */
struct flux_control {
	__u32 abi_magic;            /*  0  == FLUX_ABI_MAGIC                   */
	__u32 active;               /*  4  0 or 1                              */
	__u64 generation;           /*  8  monotonic within a boot, >= 1       */
	__u32 flxrs0_ifindex;       /* 16  bpf_redirect() target               */
	__u32 flxrs1_ifindex;       /* 20  ingress anchor (diagnostics)        */
	__u16 listen_port_v4;       /* 24  be                                  */
	__u16 listen_port_v6;       /* 26  be                                  */
	__u8 listen_v4[4];          /* 28  be, 198.18.0.2                      */
	__u8 probe_remote_v4[4];    /* 32  be, 192.0.2.1                       */
	__u16 probe_remote_port;    /* 36  be, 9                               */
	__u8 pad0[2];               /* 38  MUST be 0                           */
	__u8 listen_v6[16];         /* 40  be, 2001:db8::2                     */
	__u8 probe_remote_v6[16];   /* 56  be, 2001:db8:ffff::1                */
	__u32 selected_count;       /* 72  diagnostics only                    */
	__u32 draining_count;       /* 76  diagnostics only                    */
	__u32 bypass_v4_count;      /* 80  diagnostics only                    */
	__u32 bypass_v6_count;      /* 84  diagnostics only                    */
	__u8 pad1[8];               /* 88  MUST be 0                           */
};

/* No MAC addresses here, on purpose.
 *
 * veth_xmit -> eth_type_trans() re-derives skb->pkt_type from the destination
 * MAC and marks anything that is not the receiving device's dev_addr as
 * PACKET_OTHERHOST, which ip_rcv() drops. Rather than rewriting the MAC on the
 * egress hot path so that eth_type_trans() happens to agree, flx_in calls
 * bpf_skb_change_type(skb, PACKET_HOST) at ingress -- TC ingress runs before
 * ip_rcv(), so the corrected pkt_type is what the IP layer observes.
 *
 * Consequences:
 *   - the L2 egress entry writes NOTHING into the packet (no bpf_skb_store_bytes,
 *     therefore no skb_ensure_writable / clone copy on the captured steady state);
 *   - the L3 egress entry only writes the 2-byte EtherType, because
 *     bpf_skb_change_head() already zeroes the new head;
 *   - the injected packet carries a zero or stale destination MAC on flxrs1.
 *     Nothing performs L2 forwarding there, so this is cosmetic.
 *
 * Precedent: dae does the same thing at its veth peer ingress
 * (control/kern/tproxy.c, tproxy_dae0peer_ingress -> bpf_skb_change_type).
 */

/* Fixed listener bind addresses. Both prefixes are permanently in the fixed
 * bypass set so a selected app can never target them and self-loop.
 */
#define FLUX_LISTEN_V4_STR "198.18.0.2"          /* RFC 2544 benchmarking  */
#define FLUX_LISTEN_V6_STR "2001:db8::2"         /* RFC 3849 documentation */
#define FLUX_PROBE_REMOTE_V4_STR "192.0.2.1"     /* RFC 5737 TEST-NET-1    */
#define FLUX_PROBE_REMOTE_V6_STR "2001:db8:ffff::1"
#define FLUX_PROBE_REMOTE_PORT 9

/* Random per generation, distinct, drawn from a range above Android's usual
 * ip_local_port_range (32768..60999) so it cannot collide with ephemeral
 * allocation. Ports are collision avoidance, NOT an identity credential.
 */
#define FLUX_LISTEN_PORT_MIN 61000u
#define FLUX_LISTEN_PORT_MAX 65535u

/* ---------------------------------------------------------------- bypass */

struct flux_lpm_v4_key {
	__u32 prefixlen; /* 0 */
	__u8 addr[4];    /* 4  be */
};                       /* size 8 */

struct flux_lpm_v6_key {
	__u32 prefixlen; /* 0 */
	__u8 addr[16];   /* 4  be */
};                       /* size 20 */

/* ----------------------------------------------------------------- fault */

enum flux_fault_reason {
	/* egress: listener lookup or guard failed. Packet was NOT modified,
	 * so the caller returns TC_ACT_UNSPEC and the flow goes direct.
	 */
	FLUX_FAULT_EGRESS_LISTENER = 1,
	/* ingress: already past admission, lookup/guard/assign failed, the
	 * packet is dropped.
	 */
	FLUX_FAULT_INGRESS_ASSIGN = 2,
};

/* Hash key. MUST be fully zeroed before use (padding participates in hashing). */
struct flux_fault_key {
	__u64 generation; /*  0 */
	__u8 family;      /*  8  4 or 6 */
	__u8 protocol;    /*  9  IPPROTO_TCP or IPPROTO_UDP */
	__u16 reason;     /* 10  enum flux_fault_reason */
	__u32 pad0;       /* 12  MUST be 0 */
};                        /* size 16 */

/* Carries no header, UID, address or payload. Ever. */
struct flux_fault_event {
	__u64 generation; /*  0 */
	__u8 family;      /*  8 */
	__u8 protocol;    /*  9 */
	__u16 reason;     /* 10 */
	__u32 pad0;       /* 12  MUST be 0 */
	__u64 seq;        /* 16  optional debug correlation, may be 0 */
	__u64 pad1;       /* 24  MUST be 0 */
};                        /* size 32 */

/* -------------------------------------------------------------- counters
 *
 * PERCPU_ARRAY, incremented ONLY on decision / drop / fault edges, never on
 * steady-state per-packet paths of unselected traffic. No per-flow data, no
 * addresses, no UIDs. Read on demand by `fluxd status`.
 */
enum flux_counter {
	FLUX_CNT_ADMIT_TCP = 0,           /* first SYN installed CAPTURED      */
	FLUX_CNT_DIRECT_TCP = 1,          /* first SYN installed DIRECT        */
	FLUX_CNT_ADMIT_UDP = 2,           /* datagram admitted                 */
	FLUX_CNT_DROP_INACTIVE = 3,       /* captured socket, active == 0      */
	FLUX_CNT_DROP_STALE_GEN = 4,      /* captured socket, old generation   */
	FLUX_CNT_DROP_HANDOFF = 5,        /* eth write / change_head failed    */
	FLUX_CNT_DROP_UDP_FRAG = 6,       /* selected+active UDP fragment      */
	FLUX_CNT_DROP_CORRUPT = 7,        /* decision magic / reserved bad     */
	FLUX_CNT_DECISION_ALLOC_FAIL = 8, /* CREATE and re-read both NULL      */
	FLUX_CNT_EGRESS_LISTENER_MISS = 9,
	FLUX_CNT_IN_ASSIGN_TCP = 10,
	FLUX_CNT_IN_ASSIGN_UDP = 11,
	FLUX_CNT_IN_PASS_ESTABLISHED = 12,
	FLUX_CNT_IN_PASS_FRAGMENT = 13,
	FLUX_CNT_IN_DROP_NO_LISTENER = 14,
	FLUX_CNT_IN_DROP_ASSIGN = 15,
	FLUX_CNT_IN_DROP_PARSE = 16,
	FLUX_CNT_IN_DROP_SNAPSHOT = 17,
	FLUX_CNT__MAX = 18, /* <= FLUX_COUNTER_SLOTS */
};

/* ------------------------------------------------------------ parse limits
 *
 * Every bound below must be a compile-time constant so the verifier can see it.
 */
#define FLUX_ETH_HLEN 14
#define FLUX_IPV6_MAX_EXT_HDRS 4
#define FLUX_IPV6_MAX_EXT_BYTES 256
/* Worst case linear header bytes we may need to reach the L4 header:
 * eth + IPv6 + extension headers + TCP fixed header.
 */
#define FLUX_MAX_PULL_BYTES (FLUX_ETH_HLEN + 40 + FLUX_IPV6_MAX_EXT_BYTES + 20)

/* ------------------------------------------------------------- program IDs */

#define FLUX_PROG_CAP_L2 "flx_cap_l2" /* egress, ARPHRD_ETHER               */
#define FLUX_PROG_CAP_L3 "flx_cap_l3" /* egress, ARPHRD_RAWIP / CLAT tun    */
#define FLUX_PROG_IN     "flx_in"     /* ingress on flxrs1                  */

/* TC identity. The full ownership predicate additionally covers netns,
 * ifindex, ifname, parent/direction, kind == "bpf", direct-action, program
 * name, the program's map set, and the dump ORDER (first applicable).
 */
#define FLUX_TC_CHAIN 0
#define FLUX_TC_PREF 1
#define FLUX_TC_HANDLE_EGRESS 0x1
#define FLUX_TC_HANDLE_INGRESS 0x2

/* --------------------------------------------------------- network objects */

#define FLUX_VETH_HOST "flxrs0"
#define FLUX_VETH_PEER "flxrs1"
#define FLUX_VETH_HOST_ALIAS "flux-rs:managed:v1:host"
#define FLUX_VETH_PEER_ALIAS "flux-rs:managed:v1:peer"
#define FLUX_VETH_MTU 65535

#define FLUX_RULE_PRIORITY 100
#define FLUX_ROUTE_TABLE 20260
#define FLUX_ROUTE_PROTO 202 /* rtm_protocol tag for exact self-identification */

#endif /* FLUX_ABI_H */
