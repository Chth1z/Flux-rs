// SPDX-License-Identifier: GPL-3.0-only
//
// Flux-rs 0.9.0 — the entire data plane.
//
// Build:
//   clang -target bpf -O2 -g -Wall -Wextra -Werror -mcpu=v3 \
//         -Ibpf/include -Ibpf/vendor/libbpf/include \
//         -c bpf/flux.bpf.c -o $OUT_DIR/flux.bpf.o
//
// Dependencies: only the vendored HEADER-ONLY libbpf macros/helper prototypes
// (bpf_helpers.h, bpf_helper_defs.h, bpf_endian.h) plus Linux UAPI. No libbpf
// library, no libelf, no zlib, no vmlinux.h, no CO-RE relocations. The map
// declarations below are documentation: crates/fluxd/src/bpf/maps.rs owns the
// authoritative parameters and binds relocations by symbol name.
//
// Contract reminders that the implementer MUST NOT relax:
//   * egress "not taking over" is ALWAYS TC_ACT_UNSPEC, never TC_ACT_OK and
//     never TC_ACT_PIPE. Two independent reasons:
//       - on clsact, TC_ACT_OK ends the classifier chain and would skip AOSP
//         CLAT and the OEM filters that must still run for direct traffic;
//       - on TCX (if the attach layer ever takes that path), TC_ACT_PIPE
//         truncates the TCX program array before it is mapped to "next", so it
//         skips programs attached after us. Only TC_ACT_UNSPEC continues into
//         both the remaining TCX programs and the legacy clsact chain.
//     The TCX half is not our discovery: chizi's Android sing-box fork records
//     it in common/ebpf/native/shared_network.bpf.c, and for the same reason.
//     Note that dae returns TC_ACT_OK on 23 paths in control/kern/tproxy.c,
//     which is fine on a Linux router and would be a bug here. Do not copy it.
//   * once a valid CAPTURED decision has been observed, every later failure
//     is TC_ACT_SHOT. Never fall back to the real destination.
//   * every bpf_sk_lookup_* reference is released exactly once on every
//     branch. bpf_sk_assign() does NOT release. bpf_sk_fullsock() takes no
//     reference and MUST NOT be released.
//   * never write packet bytes with raw pointer stores; bpf_skb_store_bytes()
//     and bpf_skb_pull_data() un-share cloned skbs (TCP retransmit skbs are
//     clones sharing the write-queue buffer).
//   * control_root is looked up exactly once per invocation and the returned
//     inner pointer is held for the rest of the invocation, so an invocation
//     can only see a complete old or complete new snapshot.
//   * NEVER call bpf_sk_assign() on an established/data TCP packet. Only a
//     bare SYN gets the listener. This is not a performance choice, it is a
//     correctness one, and the reason is subtle enough to spell out:
//
//     bpf_sk_assign() sets skb->destructor = sock_pfree, and ip_rcv_core()
//     does `if (!skb_sk_is_prefetched(skb)) skb_orphan(skb);` where
//     skb_sk_is_prefetched() is exactly `destructor == sock_pfree`. A veth
//     crossing does NOT orphan, so a non-assigned packet still carries the
//     ORIGINATING APP's socket into ip_rcv_core(), where that orphan drops it
//     and the normal tuple lookup then finds the engine's transparent
//     accepted child (local side == the original destination). Correct.
//     Assigning the listener to a data segment instead hands tcp_v4_rcv() a
//     listener for mid-stream data. Wrong.
//
//     Corollary, equally important: never set skb->destructor = sock_pfree by
//     any other means. That would skip the ip_rcv_core() orphan and leave the
//     app's own socket available to skb_steal_sock(), i.e. deliver the app's
//     packet straight back to the app.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "flux_abi.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef BPF_SK_STORAGE_GET_F_CREATE
#define BPF_SK_STORAGE_GET_F_CREATE (1ULL << 0)
#endif

#define OVERFLOWUID 65534u

#ifndef PACKET_HOST
#define PACKET_HOST 0
#endif

// ---------------------------------------------------------------------- maps

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUX_UID_POLICY_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u8);
} uid_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FLUX_LPM_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct flux_lpm_v4_key);
	__type(value, __u8);
} bypass_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FLUX_LPM_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct flux_lpm_v6_key);
	__type(value, __u8);
} bypass_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flux_decision);
} tcp_decision SEC(".maps");

struct control_leaf {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct flux_control);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__array(values, struct control_leaf);
} control_root SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUX_FAULT_LATCH_MAX_ENTRIES);
	__type(key, struct flux_fault_key);
	__type(value, __u8);
} fault_latch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, FLUX_FAULT_RINGBUF_BYTES);
} fault_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FLUX_COUNTER_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

// ------------------------------------------------------------------ helpers

static __always_inline void cnt(enum flux_counter which)
{
	__u32 k = (__u32)which;
	__u64 *v = bpf_map_lookup_elem(&counters, &k);
	if (v)
		*v += 1;
}

// Exactly one control_root lookup per invocation. Returns NULL when the
// snapshot is absent or does not belong to this ABI.
static __always_inline const struct flux_control *ctrl(void)
{
	__u32 zero = 0;
	void *leaf = bpf_map_lookup_elem(&control_root, &zero);
	if (!leaf)
		return NULL;
	const struct flux_control *c = bpf_map_lookup_elem(leaf, &zero);
	if (!c || c->abi_magic != FLUX_ABI_MAGIC)
		return NULL;
	return c;
}

// First occurrence of a {generation, family, protocol, reason} tuple emits one
// fixed-size event; later occurrences are latched away so a persistent failure
// cannot become an event storm. If the ring buffer is full the latch is removed
// so a later packet can retry. fluxd clears the whole latch map before
// activating a new generation.
static __always_inline void fault_once(const struct flux_control *c, __u8 family,
				       __u8 proto, __u16 reason)
{
	struct flux_fault_key k = {};
	k.generation = c->generation;
	k.family = family;
	k.protocol = proto;
	k.reason = reason;

	__u8 one = 1;
	if (bpf_map_update_elem(&fault_latch, &k, &one, BPF_NOEXIST) != 0)
		return; // already latched

	struct flux_fault_event *e =
		bpf_ringbuf_reserve(&fault_events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&fault_latch, &k);
		return;
	}
	e->generation = c->generation;
	e->family = family;
	e->protocol = proto;
	e->reason = reason;
	e->pad0 = 0;
	e->seq = 0;
	e->pad1 = 0;
	bpf_ringbuf_submit(e, 0);
}

// --------------------------------------------------------------- parse layer

struct flux_pkt {
	__u8 family;     // 4 or 6
	__u8 l4proto;    // IPPROTO_TCP / IPPROTO_UDP, 0 when unknown
	__u8 fragment;   // 1 when this is an IP fragment
	__u8 have_l4;    // 1 when the L4 fixed header was fully readable
	__u16 l4_off;    // offset from skb->data to the L4 header
	__u8 tcp_syn;    // valid when l4proto == TCP && have_l4
	__u8 tcp_ack;
	__u8 daddr[16];  // network order; 4 bytes used for IPv4
};

// Make FLUX_MAX_PULL_BYTES (clamped to skb->len) linear and writable. Called
// once on the slow path only. Invalidates every previously read data pointer.
static __always_inline int pull_headers(struct __sk_buff *skb)
{
	__u32 want = FLUX_MAX_PULL_BYTES;
	if (want > skb->len)
		want = skb->len;
	return bpf_skb_pull_data(skb, want);
}

// nh_off is FLUX_ETH_HLEN for the L2 entry and on ingress (cls_bpf pushes the
// mac header before running ingress programs), 0 for the raw-IP L3 entry.
// Returns 0 on a usable parse, -1 when the packet is out of scope.
static __always_inline int parse_pkt(struct __sk_buff *skb, __u16 nh_off,
				     struct flux_pkt *p)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	__builtin_memset(p, 0, sizeof(*p));

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		p->family = 4;
		struct iphdr *ip = data + nh_off;
		if ((void *)(ip + 1) > end)
			return -1;
		if (ip->version != 4)
			return -1;
		// Explicit clamp so the verifier sees a constant upper bound on
		// l4_off even though ihl is a packet-derived bitfield.
		__u16 ihl_bytes = (__u16)ip->ihl * 4;
		if (ihl_bytes < 20 || ihl_bytes > 60)
			return -1;
		__builtin_memcpy(p->daddr, &ip->daddr, 4);

		__u16 frag = bpf_ntohs(ip->frag_off);
		if ((frag & 0x1fff) != 0 || (frag & 0x2000) != 0) {
			p->fragment = 1;
			return 0; // destination is known, L4 is not
		}
		p->l4proto = ip->protocol;
		p->l4_off = nh_off + ihl_bytes;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		p->family = 6;
		struct ipv6hdr *ip6 = data + nh_off;
		if ((void *)(ip6 + 1) > end)
			return -1;
		if (ip6->version != 6)
			return -1;
		__builtin_memcpy(p->daddr, &ip6->daddr, 16);

		__u8 nexthdr = ip6->nexthdr;
		__u16 off = nh_off + (__u16)sizeof(*ip6);
		__u16 ext_bytes = 0;

#pragma unroll
		for (int i = 0; i < FLUX_IPV6_MAX_EXT_HDRS; i++) {
			if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)
				break;
			if (nexthdr == IPPROTO_FRAGMENT) {
				p->fragment = 1;
				return 0;
			}
			// ESP, NONE and anything we do not model leave scope.
			if (nexthdr != IPPROTO_HOPOPTS &&
			    nexthdr != IPPROTO_ROUTING &&
			    nexthdr != IPPROTO_DSTOPTS)
				return -1;

			struct ipv6_opt_hdr *opt = data + off;
			if ((void *)(opt + 1) > end)
				return -1;
			__u16 len = (__u16)((opt->hdrlen + 1) * 8);
			ext_bytes += len;
			if (ext_bytes > FLUX_IPV6_MAX_EXT_BYTES)
				return -1;
			nexthdr = opt->nexthdr;
			off += len;
		}
		if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
			return -1;
		p->l4proto = nexthdr;
		p->l4_off = off;
	} else {
		return -1;
	}

	if (p->l4proto == IPPROTO_TCP) {
		struct tcphdr *th = data + p->l4_off;
		if ((void *)(th + 1) > end)
			return -1;
		p->tcp_syn = th->syn;
		p->tcp_ack = th->ack;
		p->have_l4 = 1;
	} else if (p->l4proto == IPPROTO_UDP) {
		struct udphdr *uh = data + p->l4_off;
		if ((void *)(uh + 1) > end)
			return -1;
		p->have_l4 = 1;
	} else {
		return -1;
	}
	return 0;
}

static __always_inline int bypass_hit(const struct flux_pkt *p)
{
	if (p->family == 4) {
		struct flux_lpm_v4_key k = {};
		k.prefixlen = 32;
		__builtin_memcpy(k.addr, p->daddr, 4);
		return bpf_map_lookup_elem(&bypass_v4, &k) != NULL;
	}
	struct flux_lpm_v6_key k = {};
	k.prefixlen = 128;
	__builtin_memcpy(k.addr, p->daddr, 16);
	return bpf_map_lookup_elem(&bypass_v6, &k) != NULL;
}

// ------------------------------------------------------- listener liveness
//
// A fixed synthetic remote makes the lookup key identical on every call:
// deterministic, cache friendly, and unable to accidentally match an
// established socket. The looked-up socket is the SAME object the ingress
// program will assign; a miss here is the mechanism that turns "engine gone"
// into pre-redirect fail-open instead of a black hole.

static __always_inline struct bpf_sock *listener_lookup(struct __sk_buff *skb,
							const struct flux_control *c,
							__u8 family, __u8 proto)
{
	if (family == 4) {
		struct bpf_sock_tuple t = {};
		__builtin_memcpy(&t.ipv4.saddr, c->probe_remote_v4, 4);
		t.ipv4.sport = c->probe_remote_port;
		__builtin_memcpy(&t.ipv4.daddr, c->listen_v4, 4);
		t.ipv4.dport = c->listen_port_v4;
		return proto == IPPROTO_TCP
			       ? bpf_sk_lookup_tcp(skb, &t, sizeof(t.ipv4),
						   BPF_F_CURRENT_NETNS, 0)
			       : bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv4),
						   BPF_F_CURRENT_NETNS, 0);
	}
	struct bpf_sock_tuple t = {};
	__builtin_memcpy(t.ipv6.saddr, c->probe_remote_v6, 16);
	t.ipv6.sport = c->probe_remote_port;
	__builtin_memcpy(t.ipv6.daddr, c->listen_v6, 16);
	t.ipv6.dport = c->listen_port_v6;
	return proto == IPPROTO_TCP
		       ? bpf_sk_lookup_tcp(skb, &t, sizeof(t.ipv6),
					   BPF_F_CURRENT_NETNS, 0)
		       : bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv6),
					   BPF_F_CURRENT_NETNS, 0);
}

// Misconfiguration guard, NOT an ownership proof. See blueprint 1.5.
// NOTE: bpf_sock::src_port is HOST order while dst_port is NETWORK order.
static __always_inline int listener_guard(const struct bpf_sock *sk,
					  const struct flux_control *c,
					  __u8 family, __u8 proto)
{
	if (proto == IPPROTO_TCP && sk->state != BPF_TCP_LISTEN)
		return 0;
	if (family == 4) {
		if (sk->family != AF_INET)
			return 0;
		__u32 want;
		__builtin_memcpy(&want, c->listen_v4, 4);
		if (sk->src_ip4 != want)
			return 0;
		return sk->src_port == (__u32)bpf_ntohs(c->listen_port_v4);
	}
	if (sk->family != AF_INET6)
		return 0;
	__u32 want[4];
	__builtin_memcpy(want, c->listen_v6, 16);
	if (sk->src_ip6[0] != want[0] || sk->src_ip6[1] != want[1] ||
	    sk->src_ip6[2] != want[2] || sk->src_ip6[3] != want[3])
		return 0;
	return sk->src_port == (__u32)bpf_ntohs(c->listen_port_v6);
}

static __always_inline int listener_alive(struct __sk_buff *skb,
					  const struct flux_control *c,
					  __u8 family, __u8 proto)
{
	struct bpf_sock *sk = listener_lookup(skb, c, family, proto);
	if (!sk) {
		cnt(FLUX_CNT_EGRESS_LISTENER_MISS);
		fault_once(c, family, proto, FLUX_FAULT_EGRESS_LISTENER);
		return 0;
	}
	int ok = listener_guard(sk, c, family, proto);
	bpf_sk_release(sk);
	if (!ok) {
		cnt(FLUX_CNT_EGRESS_LISTENER_MISS);
		fault_once(c, family, proto, FLUX_FAULT_EGRESS_LISTENER);
	}
	return ok;
}

// ------------------------------------------------------------------ handoff
//
// Hands the skb to the veth. No MAC rewriting: flx_in forces PACKET_HOST at
// ingress instead (see flux_abi.h). Therefore the L2 path writes nothing at
// all -- no bpf_skb_store_bytes, so no skb_ensure_writable and no copy of a
// cloned TCP retransmit skb -- and the L3 path writes only the EtherType,
// because bpf_skb_change_head() already zeroes the 14 new bytes.

static __always_inline int handoff(struct __sk_buff *skb,
				   const struct flux_control *c, int l3)
{
	if (l3) {
		// EtherType must be correct: eth_type_trans() derives
		// skb->protocol from it on the receiving side, and a zero
		// h_proto would never reach ip_rcv().
		__be16 ethertype = (__be16)skb->protocol;
		if (bpf_skb_change_head(skb, FLUX_ETH_HLEN, 0) != 0) {
			cnt(FLUX_CNT_DROP_HANDOFF);
			return TC_ACT_SHOT;
		}
		if (bpf_skb_store_bytes(skb, 12, &ethertype, sizeof(ethertype),
					0) != 0) {
			cnt(FLUX_CNT_DROP_HANDOFF);
			return TC_ACT_SHOT;
		}
	}
	return bpf_redirect(c->flxrs0_ifindex, 0);
}

// ------------------------------------------------------------ egress core

static __always_inline int cap_core(struct __sk_buff *skb, int l3)
{
	// E0 -- cheap layout gate.
	if (skb->protocol != bpf_htons(ETH_P_IP) &&
	    skb->protocol != bpf_htons(ETH_P_IPV6))
		return TC_ACT_UNSPEC;
	if (!l3 && skb->vlan_present)
		return TC_ACT_UNSPEC;

	// E1 -- socket identity. This is the entire cost paid by traffic that
	// belongs to an unselected UID: one helper call and one hash miss.
	struct bpf_sock *skc = skb->sk;
	if (!skc)
		return TC_ACT_UNSPEC;
	struct bpf_sock *sk = bpf_sk_fullsock(skc);
	if (!sk)
		return TC_ACT_UNSPEC; // no reference taken, nothing to release

	__u32 uid = bpf_get_socket_uid(skb);
	if (uid == OVERFLOWUID)
		return TC_ACT_UNSPEC;
	__u8 *mode = bpf_map_lookup_elem(&uid_policy, &uid);
	if (!mode)
		return TC_ACT_UNSPEC;

	__u16 nh_off = l3 ? 0 : FLUX_ETH_HLEN;

	// E2 -- an existing decision short-circuits everything, without parsing
	// L3/L4. This is what makes a captured flow's IP fragments follow the
	// decision instead of leaking to the real destination.
	struct flux_decision *d =
		bpf_sk_storage_get(&tcp_decision, sk, NULL, 0);
	if (d) {
		if (d->magic != FLUX_DECISION_MAGIC || d->reserved[0] ||
		    d->reserved[1] || d->reserved[2]) {
			cnt(FLUX_CNT_DROP_CORRUPT);
			return TC_ACT_SHOT;
		}
		if (d->mode == FLUX_DEC_DIRECT)
			return TC_ACT_UNSPEC;
		if (d->mode != FLUX_DEC_CAPTURED) {
			cnt(FLUX_CNT_DROP_CORRUPT);
			return TC_ACT_SHOT;
		}
		const struct flux_control *c = ctrl();
		if (!c) {
			cnt(FLUX_CNT_DROP_INACTIVE);
			return TC_ACT_SHOT;
		}
		if (!c->active) {
			cnt(FLUX_CNT_DROP_INACTIVE);
			return TC_ACT_SHOT;
		}
		if (d->generation != c->generation) {
			cnt(FLUX_CNT_DROP_STALE_GEN);
			return TC_ACT_SHOT;
		}
		return handoff(skb, c, l3);
	}

	// E3 -- no decision yet, so headers are required. Slow path only.
	if (pull_headers(skb) < 0)
		return TC_ACT_UNSPEC;
	struct flux_pkt p;
	if (parse_pkt(skb, nh_off, &p) < 0)
		return TC_ACT_UNSPEC;

	if (p.fragment) {
		// The destination is known even without an L4 header, so the
		// bypass decision is still exact.
		if (bypass_hit(&p))
			return TC_ACT_UNSPEC;
		const struct flux_control *c = ctrl();
		if (*mode == FLUX_UID_SELECTED && c && c->active) {
			// Never direct: a fragment of a datagram that would
			// have been proxied must not reach the real
			// destination. 0.9.0 accepts breaking fragmented UDP.
			cnt(FLUX_CNT_DROP_UDP_FRAG);
			return TC_ACT_SHOT;
		}
		return TC_ACT_UNSPEC;
	}
	if (!p.have_l4)
		return TC_ACT_UNSPEC;

	if (p.l4proto == IPPROTO_TCP) {
		// E4 -- only locally initiated connections get a decision.
		// Connections that already existed before capture was enabled
		// never pay the control lookup.
		if (!(p.tcp_syn && !p.tcp_ack))
			return TC_ACT_UNSPEC;

		const struct flux_control *c = ctrl();

		// Structured so that every c-> dereference sits inside a branch
		// where the verifier has already proven c != NULL. Do NOT
		// collapse this into `cand.generation = capture ? c->generation
		// : 0` -- the verifier cannot correlate the flag with the
		// pointer and will reject the load.
		struct flux_decision cand = {};
		cand.magic = FLUX_DECISION_MAGIC;
		cand.mode = FLUX_DEC_DIRECT;
		cand.generation = 0;
		if (*mode == FLUX_UID_SELECTED && c && c->active &&
		    !bypass_hit(&p) &&
		    listener_alive(skb, c, p.family, IPPROTO_TCP)) {
			cand.mode = FLUX_DEC_CAPTURED;
			cand.generation = c->generation;
		}

		d = bpf_sk_storage_get(&tcp_decision, sk, &cand,
				       BPF_SK_STORAGE_GET_F_CREATE);
		if (!d) {
			// Lost a concurrent BPF_NOEXIST race, or allocation
			// failed. Re-read to pick up the winner.
			d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0);
		}
		if (!d) {
			// Nothing landed, so this packet is still pre-admission
			// and may go direct. A later SYN can decide again; this
			// is the documented no-stickiness edge.
			cnt(FLUX_CNT_DECISION_ALLOC_FAIL);
			return TC_ACT_UNSPEC;
		}

		// Obey the winner unconditionally, even when it contradicts the
		// candidate this invocation computed.
		if (d->mode == FLUX_DEC_DIRECT) {
			cnt(FLUX_CNT_DIRECT_TCP);
			return TC_ACT_UNSPEC;
		}
		if (d->mode != FLUX_DEC_CAPTURED) {
			cnt(FLUX_CNT_DROP_CORRUPT);
			return TC_ACT_SHOT;
		}
		if (!c || !c->active) {
			cnt(FLUX_CNT_DROP_INACTIVE);
			return TC_ACT_SHOT;
		}
		if (d->generation != c->generation) {
			cnt(FLUX_CNT_DROP_STALE_GEN);
			return TC_ACT_SHOT;
		}
		cnt(FLUX_CNT_ADMIT_TCP);
		return handoff(skb, c, l3);
	}

	// E5 -- UDP has no socket stickiness: policy is evaluated per datagram
	// so that per-destination bypass stays exact and `active=0` takes
	// effect immediately.
	if (*mode != FLUX_UID_SELECTED)
		return TC_ACT_UNSPEC;
	const struct flux_control *c = ctrl();
	if (!c || !c->active)
		return TC_ACT_UNSPEC;
	if (bypass_hit(&p))
		return TC_ACT_UNSPEC;
	if (!listener_alive(skb, c, p.family, IPPROTO_UDP))
		return TC_ACT_UNSPEC;
	cnt(FLUX_CNT_ADMIT_UDP);
	return handoff(skb, c, l3);
}

// ----------------------------------------------------------------- programs

// Liveness probe. Attached at the SAME parent and preference the capture entry
// is about to take, with handle FLUX_TC_HANDLE_VERIFY, then removed once
// fluxd has read the counter. Its only job is to prove the classifier chain
// actually reaches that position.
//
// This has to be a separate program rather than a flag inside cap_core,
// because unselected traffic returns at E1 and never reaches ctrl() -- a
// control-flag design would have forced the snapshot lookup to the top of the
// hot path for every packet on the device. Here the cost is paid only while
// the probe is attached, and the capture entries stay untouched.
//
// TC_ACT_UNSPEC so the chain continues exactly as it would without us: the
// probe must not change the fate of a single packet. See blueprint 8.5.4.
SEC("tc/verify")
int flx_verify(struct __sk_buff *skb)
{
	(void)skb;
	cnt(FLUX_CNT_SAW_PACKET);
	return TC_ACT_UNSPEC;
}

// Ethernet-like egress (Wi-Fi and friends). Attached at chain 0, direct-action,
// protocol all, handle 0x1, at a preference chosen by dumping the parent first
// (FLUX_TC_PREF_PREFERRED and friends -- pref 1 is NOT ours to assume; Samsung
// holds it on wlan0 on the measured device). It MUST be the first applicable
// classifier so that TC_ACT_UNSPEC still reaches AOSP/OEM filters.
SEC("tc/cap_l2")
int flx_cap_l2(struct __sk_buff *skb)
{
	return cap_core(skb, 0);
}

// Raw-IP egress: Qualcomm rmnet (ARPHRD_RAWIP) and strictly identified CLAT
// `v4-*` tunnels. skb->data is at the network header, so a 14 byte internal
// Ethernet header is pushed before redirecting into the veth.
SEC("tc/cap_l3")
int flx_cap_l3(struct __sk_buff *skb)
{
	return cap_core(skb, 1);
}

// Ingress on flxrs1. Only Flux redirects into this device, which is the
// provenance boundary; no token, magic number or skb metadata is needed.
//
// Note: skb->mark WOULD survive this hop -- skb_scrub_packet() only clears it
// when crossing a netns, and both veth ends live in the root netns. We simply
// have nothing to pass, and spending an Android fwmark bit to pass it would be
// worse than free. Do not "fix" this by adding a mark.
SEC("tc/in")
int flx_in(struct __sk_buff *skb)
{
	const struct flux_control *c = ctrl();
	if (!c || !c->active) {
		cnt(FLUX_CNT_IN_DROP_SNAPSHOT);
		return TC_ACT_SHOT;
	}

	// veth_xmit -> eth_type_trans() has already re-derived pkt_type from the
	// destination MAC, which for a redirected packet is not flxrs1's
	// dev_addr, so it is PACKET_OTHERHOST and ip_rcv() would drop it. TC
	// ingress runs before ip_rcv(), so correcting it here is what makes the
	// egress side able to skip MAC rewriting entirely. Metadata only: no
	// packet bytes are touched, so no un-cloning is triggered.
	bpf_skb_change_type(skb, PACKET_HOST);

	// cls_bpf pushes the mac header before running ingress programs, so the
	// Ethernet header is readable at offset 0.
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end) {
		cnt(FLUX_CNT_IN_DROP_PARSE);
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP) &&
	    eth->h_proto != bpf_htons(ETH_P_IPV6)) {
		cnt(FLUX_CNT_IN_DROP_PARSE);
		return TC_ACT_SHOT;
	}

	if (pull_headers(skb) < 0) {
		cnt(FLUX_CNT_IN_DROP_PARSE);
		return TC_ACT_SHOT;
	}
	struct flux_pkt p;
	if (parse_pkt(skb, FLUX_ETH_HLEN, &p) < 0) {
		cnt(FLUX_CNT_IN_DROP_PARSE);
		return TC_ACT_SHOT;
	}

	if (p.fragment) {
		// Only reachable for an already captured TCP flow. Let the
		// local stack reassemble (ip_local_deliver -> ip_defrag) and
		// find the established socket. Never assign a fragment.
		cnt(FLUX_CNT_IN_PASS_FRAGMENT);
		return TC_ACT_OK;
	}
	if (!p.have_l4) {
		cnt(FLUX_CNT_IN_DROP_PARSE);
		return TC_ACT_SHOT;
	}

	if (p.l4proto == IPPROTO_TCP && !(p.tcp_syn && !p.tcp_ack)) {
		// Final ACK, data, FIN, RST: no re-assign. The kernel's
		// transparent request/established lookup takes over. This is
		// not a promise of delivery; a missing socket yields RST/drop.
		cnt(FLUX_CNT_IN_PASS_ESTABLISHED);
		return TC_ACT_OK;
	}

	struct bpf_sock *sk = listener_lookup(skb, c, p.family, p.l4proto);
	if (!sk) {
		cnt(FLUX_CNT_IN_DROP_NO_LISTENER);
		fault_once(c, p.family, p.l4proto, FLUX_FAULT_INGRESS_ASSIGN);
		return TC_ACT_SHOT;
	}
	if (!listener_guard(sk, c, p.family, p.l4proto)) {
		bpf_sk_release(sk);
		cnt(FLUX_CNT_IN_DROP_NO_LISTENER);
		fault_once(c, p.family, p.l4proto, FLUX_FAULT_INGRESS_ASSIGN);
		return TC_ACT_SHOT;
	}

	long r = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	if (r != 0) {
		// -ESOCKTNOSUPPORT here means the listener has SO_REUSEPORT,
		// which kernels before 6.5 refuse. See blueprint 9.2.
		cnt(FLUX_CNT_IN_DROP_ASSIGN);
		fault_once(c, p.family, p.l4proto, FLUX_FAULT_INGRESS_ASSIGN);
		return TC_ACT_SHOT;
	}

	cnt(p.l4proto == IPPROTO_TCP ? FLUX_CNT_IN_ASSIGN_TCP
				     : FLUX_CNT_IN_ASSIGN_UDP);
	// Delivery now depends on the RPDB rule `iif flxrs1 lookup 20260` and
	// `local default dev lo` in that table, plus rp_filter == 0 and
	// accept_local == 1 taking effect on flxrs1 (blueprint 8.4).
	return TC_ACT_OK;
}
