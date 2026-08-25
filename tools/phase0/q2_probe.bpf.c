// Phase 0 Q2 -- the ingress half of the architecture, without fluxd.
//
// Everything measured so far covers the EGRESS half: capture, UID attribution,
// and whether the programs verify. The ingress half rests on two claims that
// have only ever been argued from source:
//
//   * bpf_sk_lookup_tcp/udp finds the official sing-box tproxy listener, and
//     the fields it returns match what was configured;
//   * bpf_sk_assign() SUCCEEDS on that listener -- which on a pre-6.5 kernel is
//     precisely the runtime proof that sing-box sets no SO_REUSEPORT, because
//     the helper returns -ESOCKTNOSUPPORT for a reuseport socket and blueprint
//     9.2 depends on it not doing so.
//
// The lookup mirrors listener_lookup() in bpf/flux.bpf.c exactly, including the
// synthetic remote tuple, so a pass here transfers to the product rather than to
// some simplified stand-in.
//
// bpf_sk_assign() is legal only at TC ingress, so this attaches to the veth
// peer -- which also means the only packets it ever sees are the ones the
// harness generates. Nothing of the user's traffic reaches it.
//
// Reference discipline follows the product's rule: bpf_sk_assign() does NOT
// consume the lookup's reference, so every lookup is still released exactly
// once on every path. assign's own reference belongs to the skb from then on
// and is released by sock_pfree when the skb is freed.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// Baked in rather than passed through a map: one less moving part, and a
// botched hex map update would look exactly like a failed lookup.
#define Q2_PORT 61234 /* inside the 61000..65535 range blueprint 9.1 mandates */

// The synthetic remote used to make the lookup miss every established socket
// and land on the listener. Same role as flux_control.probe_remote_v4.
#define Q2_PROBE_REMOTE_V4 0xC0000201u /* 192.0.2.1, RFC 5737 TEST-NET-1 */
#define Q2_PROBE_REMOTE_PORT 12345

// 198.51.100.1 -- RFC 5737 TEST-NET-2, per D21 moved clear of the fakeip ranges
#define Q2_LISTEN_V4 0xC6336401u

enum q2_slot {
	// Six slots per (family, proto) combination, in this order.
	Q2_FOUND = 0,
	Q2_FAMILY = 1,
	Q2_STATE = 2,
	Q2_SRC_PORT = 3,
	Q2_SRC_IP4 = 4,
	Q2_ASSIGN_RC = 5,
	Q2_STRIDE = 6,

	Q2_BASE_V4_TCP = 0,
	Q2_BASE_V4_UDP = 6,
	Q2_BASE_V6_TCP = 12,
	Q2_BASE_V6_UDP = 18,

	Q2_INVOCATIONS = 24,
	Q2_SLOTS = 32,
};

// A plain ARRAY, not PERCPU: these are observed values, not counts, and
// last-write-wins is exactly right for a value that should be constant.
//
// The value type is SIGNED on purpose. One slot holds bpf_sk_assign()'s return
// code, which is a negative errno on failure, and BTF makes bpftool print the
// value using this type -- so a signed type yields "-94" instead of a 2^64
// two's complement that no shell can compare. An earlier version used __u64 and
// the harness reported "?" for a perfectly good result.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, Q2_SLOTS);
	__type(key, __u32);
	__type(value, __s64);
} q2_out SEC(".maps");

static __always_inline void put(__u32 slot, __s64 v)
{
	bpf_map_update_elem(&q2_out, &slot, &v, BPF_ANY);
}

static __always_inline void bump(__u32 slot)
{
	__s64 *p = bpf_map_lookup_elem(&q2_out, &slot);
	if (p)
		*p += 1;
}

// One (family, proto) combination: look up the listener, record what came back,
// optionally assign, then release. `do_assign` is a compile-time constant at
// every call site so the verifier sees straight-line code.
static __always_inline void probe(struct __sk_buff *skb, __u32 base,
				  int v6, int udp, int do_assign)
{
	struct bpf_sock *sk;

	if (!v6) {
		struct bpf_sock_tuple t = {};
		t.ipv4.saddr = bpf_htonl(Q2_PROBE_REMOTE_V4);
		t.ipv4.sport = bpf_htons(Q2_PROBE_REMOTE_PORT);
		t.ipv4.daddr = bpf_htonl(Q2_LISTEN_V4);
		t.ipv4.dport = bpf_htons(Q2_PORT);
		sk = udp ? bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv4),
					     BPF_F_CURRENT_NETNS, 0)
			 : bpf_sk_lookup_tcp(skb, &t, sizeof(t.ipv4),
					     BPF_F_CURRENT_NETNS, 0);
	} else {
		struct bpf_sock_tuple t = {};
		// 2001:db8:0:1::2
		t.ipv6.saddr[0] = bpf_htonl(0x20010db8u);
		t.ipv6.saddr[3] = bpf_htonl(1u); /* 2001:db8::1 as the remote */
		t.ipv6.sport = bpf_htons(Q2_PROBE_REMOTE_PORT);
		t.ipv6.daddr[0] = bpf_htonl(0x20010db8u);
		t.ipv6.daddr[1] = bpf_htonl(0x00000001u);
		t.ipv6.daddr[3] = bpf_htonl(2u);
		t.ipv6.dport = bpf_htons(Q2_PORT);
		sk = udp ? bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv6),
					     BPF_F_CURRENT_NETNS, 0)
			 : bpf_sk_lookup_tcp(skb, &t, sizeof(t.ipv6),
					     BPF_F_CURRENT_NETNS, 0);
	}

	if (!sk) {
		put(base + Q2_FOUND, 0);
		return;
	}

	put(base + Q2_FOUND, 1);
	put(base + Q2_FAMILY, sk->family);
	put(base + Q2_STATE, sk->state);
	// src_port is HOST order while dst_port is NETWORK order. That asymmetry
	// is real ABI and easy to get wrong, so it is recorded raw and checked in
	// the harness rather than normalised away here.
	put(base + Q2_SRC_PORT, sk->src_port);
	put(base + Q2_SRC_IP4, sk->src_ip4);

	if (do_assign)
		put(base + Q2_ASSIGN_RC, (__s64)bpf_sk_assign(skb, sk, 0));

	bpf_sk_release(sk);
}

SEC("tc/ingress")
int q2_probe(struct __sk_buff *skb)
{
	bump(Q2_INVOCATIONS);

	// Only the v4 TCP combination is assigned. Assigning four times in one
	// invocation would work -- each assign orphans the previous, releasing it
	// through sock_pfree -- but it would prove nothing extra and would make
	// the reference accounting harder to read.
	probe(skb, Q2_BASE_V4_TCP, 0, 0, 1);
	probe(skb, Q2_BASE_V4_UDP, 0, 1, 0);
	probe(skb, Q2_BASE_V6_TCP, 1, 0, 0);
	probe(skb, Q2_BASE_V6_UDP, 1, 1, 0);

	// SHOT, not OK: the skb carries an assigned socket now, and dropping it
	// here frees it through sock_pfree with the reference accounting intact.
	// Letting it continue would hand a harness packet to the real engine,
	// which answers no question this probe is asking.
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
