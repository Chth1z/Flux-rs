// SPDX-License-Identifier: GPL-3.0-only
//
// Phase 0 Q1 -- SK_STORAGE first-decision.
//
// Mirrors the real algorithm from blueprint section 7.3 (E1 socket identity,
// E2 existing decision, E3 first decision) against the real ABI header, so a
// pass here means the shipped shape works rather than some simplified stand-in.
//
// Four things it answers:
//
//   1. Does the verifier accept bpf_sk_storage_get() on the pointer returned
//      by bpf_sk_fullsock(skb->sk) at TC egress? That combination is the one
//      the whole design rests on.
//   2. Does F_CREATE give first-decision-wins under concurrent connects? The
//      read-only probe and the create are two separate calls, so two CPUs can
//      both see NULL. If the kernel's create is atomic, the loser gets the
//      winner's value -- and counts itself as RACE_LOSER, which makes the
//      semantics measurable instead of assumed.
//   3. Does the stored value stay immutable afterwards? Any change to magic or
//      reserved shows up as CORRUPT.
//   4. Is storage released with the socket, with no capacity eviction? Read
//      SEEN against the connection count after the sockets close.
//
// Build (WSL or any Linux host with clang and libbpf headers):
//   clang -target bpf -O2 -g -mcpu=v3 \
//         -I bpf/include -I /usr/include/$(uname -m)-linux-gnu \
//         -c tools/phase0/q1_probe.bpf.c -o /tmp/q1_probe.o
//
// A newer host is a rehearsal, not a verdict: the baseline is 5.15 and the
// behaviours that differ most changed inside the 5.15..6.6 window. But a
// program the 6.x verifier rejects is certainly rejected on 5.15, so failing
// here is conclusive while passing here is not.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "flux_abi.h"

// Counter slots for this probe only. Deliberately not the product's
// flux_counter enum: this measures the experiment, not the product.
enum q1_slot {
	Q1_SEEN = 0,        /* existing decision found and intact              */
	Q1_CREATED = 1,     /* we created it and our generation stuck          */
	Q1_RACE_LOSER = 2,  /* someone created first; we got their value       */
	Q1_ALLOC_FAIL = 3,  /* F_CREATE returned NULL                          */
	Q1_CORRUPT = 4,     /* magic or reserved bytes wrong                   */
	Q1_NO_FULLSOCK = 5, /* bpf_sk_fullsock returned NULL                   */
	Q1_NOT_TCP = 6,     /* full socket, but not TCP                        */
	Q1__MAX = 7,
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flux_decision);
} tcp_decision SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, Q1__MAX);
	__type(key, __u32);
	__type(value, __u64);
} q1_counters SEC(".maps");

// Unique-id source. The first version used __sync_fetch_and_add() on a map
// value, and the baseline kernel refused the program with -ENOTSUPP (524) --
// verification itself passed, 167 instructions processed with no complaint,
// then the load failed. Cause: taking the RESULT of the atomic emits a
// BPF_ATOMIC with BPF_FETCH, which the arm64 JIT does not implement on 5.15.
//
// bpf_ktime_get_ns() serves the same purpose here. Monotonic nanoseconds are
// distinct enough per invocation to detect a lost race, and the helper has been
// available to SCHED_CLS since long before the baseline.
//
// The product is unaffected -- its generation number comes from
// flux_control.generation, published by userspace -- but the constraint is real
// and now recorded: no atomic-with-fetch in BPF on the arm64 baseline.

static __always_inline void cnt(enum q1_slot slot)
{
	__u32 key = slot;
	__u64 *v = bpf_map_lookup_elem(&q1_counters, &key);
	if (v)
		*v += 1;
}

SEC("tc")
int q1_probe(struct __sk_buff *skb)
{
	// E0 -- cheap layout gate.
	if (skb->protocol != bpf_htons(ETH_P_IP) &&
	    skb->protocol != bpf_htons(ETH_P_IPV6))
		return TC_ACT_UNSPEC;

	// E1 -- socket identity. This is the exact sequence section 7.1 requires:
	// skb->sk may be a request or timewait socket, so it must go through
	// bpf_sk_fullsock() before it can be handed to a socket-typed helper.
	// bpf_sk_fullsock() takes no reference, so there is nothing to release.
	struct bpf_sock *skc = skb->sk;
	if (!skc)
		return TC_ACT_UNSPEC;
	struct bpf_sock *sk = bpf_sk_fullsock(skc);
	if (!sk) {
		cnt(Q1_NO_FULLSOCK);
		return TC_ACT_UNSPEC;
	}
	if (sk->protocol != IPPROTO_TCP) {
		cnt(Q1_NOT_TCP);
		return TC_ACT_UNSPEC;
	}

	// E2 -- read-only probe. Costs nothing when absent and keeps the create
	// path off the steady state, which is what makes an existing decision
	// short-circuit without parsing anything.
	struct flux_decision *d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0);
	if (d) {
		if (d->magic != FLUX_DECISION_MAGIC || d->reserved[0] ||
		    d->reserved[1] || d->reserved[2])
			cnt(Q1_CORRUPT);
		else
			cnt(Q1_SEEN);
		return TC_ACT_UNSPEC;
	}

	// E3 -- first decision for this socket.
	__u64 mine = bpf_ktime_get_ns();

	struct flux_decision init = {
		.magic = FLUX_DECISION_MAGIC,
		.mode = FLUX_DEC_CAPTURED,
		.reserved = {0, 0, 0},
		.generation = mine,
	};

	d = bpf_sk_storage_get(&tcp_decision, sk, &init,
			       BPF_SK_STORAGE_GET_F_CREATE);
	if (!d)
		cnt(Q1_ALLOC_FAIL);
	else if (d->generation == mine)
		cnt(Q1_CREATED);
	else
		cnt(Q1_RACE_LOSER);

	// Never changes a packet's fate: this is an observer.
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
