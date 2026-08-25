// Phase 0 Q9 -- does bpf_get_socket_uid() attribute DNS to the asking app?
//
// This is the single most consequential measurement in Phase 0, because D18
// (precise per-app DNS with no extra mechanism) rests entirely on one claim:
// netd calls fchown() on the plaintext DNS socket to hand it to the app that
// asked, sk->sk_uid follows, and bpf_get_socket_uid() reads sk->sk_uid. The
// source chain is in blueprint 1.3.1. This program checks the conclusion on
// real hardware.
//
// It observes only. Every path returns TC_ACT_UNSPEC, so no packet's fate
// changes and no traffic is redirected anywhere.
//
// The discriminator is blunt and hard to argue with: bucket egress packets by
// (socket UID, port kind). If plaintext :53 packets carry app UIDs in the
// 10000+ range, D18 holds. If they all carry 1051 (netd's own UID) or 0, D18
// is dead and the DNS design has to change.
//
// Ports 853 and 443 are recorded next to :53 on purpose. private_dns_mode is
// "opportunistic" by default on Android, which means netd prefers DoT on :853
// and only falls back to plaintext when the upstream refuses. So "no :53 seen"
// is an expected outcome on some networks, not a probe failure -- and telling
// the two apart requires seeing where the DNS actually went.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

enum q9_kind {
	Q9_UDP_53 = 0,  /* plaintext DNS -- the D18 question                  */
	Q9_TCP_53 = 1,  /* plaintext DNS over TCP (large answers, or fallback)*/
	Q9_TCP_853 = 2, /* DoT, netd's own socket, expected to be UID 1051    */
	Q9_UDP_443 = 3, /* QUIC: HTTP/3 and DoH3 are indistinguishable here   */
	Q9_TCP_443 = 4, /* HTTPS, and DoH rides inside it                     */
	Q9_OTHER = 5,   /* control group: ordinary traffic's UID attribution  */
};

struct q9_key {
	__u32 uid;
	__u32 kind;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct q9_key);
	__type(value, __u64);
} q9_uid_port SEC(".maps");

// Separate accounting for packets we could not classify, so a low :53 count is
// never confused with a program that failed to parse anything.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} q9_diag SEC(".maps");

enum q9_diag {
	Q9_D_TOTAL = 0,
	Q9_D_NOT_IP = 1,
	Q9_D_V4 = 2,
	Q9_D_V6 = 3,
	Q9_D_NO_L4 = 4,   /* fragment, or an extension-header chain we skip   */
	Q9_D_READ_FAIL = 5,
	Q9_D_UID_OVF = 6, /* bpf_get_socket_uid() returned the no-socket value */
};

static __always_inline void diag(enum q9_diag which)
{
	__u32 k = (__u32)which;
	__u64 *v = bpf_map_lookup_elem(&q9_diag, &k);
	if (v)
		*v += 1;
}

static __always_inline void bump(__u32 uid, enum q9_kind kind)
{
	struct q9_key k = {.uid = uid, .kind = (__u32)kind};
	__u64 *v = bpf_map_lookup_elem(&q9_uid_port, &k);
	if (v) {
		*v += 1;
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(&q9_uid_port, &k, &one, BPF_ANY);
}

static __always_inline enum q9_kind classify(__u8 proto, __u16 dport)
{
	if (proto == IPPROTO_UDP) {
		if (dport == 53)
			return Q9_UDP_53;
		if (dport == 443)
			return Q9_UDP_443;
	} else if (proto == IPPROTO_TCP) {
		if (dport == 53)
			return Q9_TCP_53;
		if (dport == 853)
			return Q9_TCP_853;
		if (dport == 443)
			return Q9_TCP_443;
	}
	return Q9_OTHER;
}

// Every read goes through bpf_skb_load_bytes() rather than data/data_end
// arithmetic. A probe has no hot path worth optimising, and this keeps the
// verifier's job trivial -- the point is to measure UID attribution, not to
// re-litigate pointer bounds.
SEC("tc") // not "tc/q9": libbpf accepts only tc/ingress and tc/egress under "tc/"
int q9_probe(struct __sk_buff *skb)
{
	diag(Q9_D_TOTAL);

	__u16 h_proto = bpf_ntohs(skb->protocol);
	if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6) {
		diag(Q9_D_NOT_IP);
		return TC_ACT_UNSPEC;
	}

	// Raw-IP interfaces (rmnet, CLAT) hand us a packet that starts at the IP
	// header; Ethernet ones start 14 bytes earlier. Rather than compile two
	// programs, infer it: if byte 0 already looks like the IP version that
	// skb->protocol claims, there is no MAC header in front of it.
	__u32 l3 = 0;
	__u8 first = 0;
	if (bpf_skb_load_bytes(skb, 0, &first, 1) < 0) {
		diag(Q9_D_READ_FAIL);
		return TC_ACT_UNSPEC;
	}
	__u8 ver = first >> 4;
	if (!((h_proto == ETH_P_IP && ver == 4) || (h_proto == ETH_P_IPV6 && ver == 6)))
		l3 = ETH_HLEN;

	__u8 proto = 0;
	__u32 l4 = 0;

	if (h_proto == ETH_P_IP) {
		diag(Q9_D_V4);
		struct iphdr ip4;
		if (bpf_skb_load_bytes(skb, l3, &ip4, sizeof(ip4)) < 0) {
			diag(Q9_D_READ_FAIL);
			return TC_ACT_UNSPEC;
		}
		// Non-zero fragment offset means the L4 header is in an earlier
		// fragment, so there are no ports to read here.
		if (bpf_ntohs(ip4.frag_off) & 0x1fff) {
			diag(Q9_D_NO_L4);
			return TC_ACT_UNSPEC;
		}
		__u32 ihl = (__u32)ip4.ihl * 4;
		if (ihl < sizeof(ip4) || ihl > 60) {
			diag(Q9_D_NO_L4);
			return TC_ACT_UNSPEC;
		}
		proto = ip4.protocol;
		l4 = l3 + ihl;
	} else {
		diag(Q9_D_V6);
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, l3, &ip6, sizeof(ip6)) < 0) {
			diag(Q9_D_READ_FAIL);
			return TC_ACT_UNSPEC;
		}
		// No extension-header walk. DNS and HTTPS do not arrive behind one
		// in practice, and anything that does lands in NO_L4 where it is
		// visible rather than silently miscounted.
		proto = ip6.nexthdr;
		l4 = l3 + sizeof(ip6);
	}

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		diag(Q9_D_NO_L4);
		return TC_ACT_UNSPEC;
	}

	__u16 dport_be = 0;
	if (bpf_skb_load_bytes(skb, l4 + 2, &dport_be, sizeof(dport_be)) < 0) {
		diag(Q9_D_READ_FAIL);
		return TC_ACT_UNSPEC;
	}

	__u32 uid = bpf_get_socket_uid(skb);
	if (uid == 0xffffffffu)
		diag(Q9_D_UID_OVF);

	bump(uid, classify(proto, bpf_ntohs(dport_be)));
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
