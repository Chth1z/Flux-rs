/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * NF_INET_LOCAL_OUT classifier. Unselected floor is always:
 * live, skb->sk, sk_fullsock, sk_uid, one HASH probe, NF_ACCEPT.
 *
 * Handoff is a compile-time stage (Makefile FLUXRS_STAGE), not an ioctl:
 *   0  classify only. Accidental insmod cannot steal (live=0 until fd).
 *   2  NF_STOLEN + worker kfree_skb. No tproxy, no deliver.
 *   3  worker: nf_tproxy lookup, sock_gen_put, kfree. No assign/deliver.
 *   4  skb_scrub_packet + assign_sock, then kfree. No ip_local_deliver.
 *   5  deliver without a local dst (falsified 2026-09-18, do not insmod).
 *   6  after scrub, attach loopback local dst, then deliver (product).
 *
 * Never call ip_local_deliver, netif_rx, or netif_receive_skb on the
 * LOCAL_OUT stack (2026-09-18 hang/reboot). Stages 2-4 must not deliver.
 */
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/atomic.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/sock.h>
#include "fluxrs.h"

#ifndef FLUXRS_STAGE
#define FLUXRS_STAGE 0
#endif

#define FLUXRS_OVERFLOWUID 65534
#define FLUXRS_UID_CAP 256u
#define FLUXRS_UID_PROBE 8u

#if FLUXRS_STAGE >= 2
#include <linux/workqueue.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/ipv6.h>
#define FLUXRS_STEAL_QMAX 4096u
#endif

#if FLUXRS_STAGE >= 6
#include <linux/err.h>
#include <net/route.h>
#include <net/ip6_route.h>
#endif

#if defined(FLUXRS_NOCFI) && FLUXRS_NOCFI
#define FLUXRS_CFI_WRAP __nocfi
#else
#define FLUXRS_CFI_WRAP
#endif

static atomic_t live = ATOMIC_INIT(0);
static atomic64_t selected_seen;
static atomic64_t stolen;
static atomic64_t miss_listener;

static u32 uid_tab[FLUXRS_UID_CAP];
static struct fluxrs_listeners listeners;
static bool listeners_set;

#if FLUXRS_STAGE >= 2
static struct sk_buff_head steal_q;
static struct work_struct steal_work;
#endif

void fluxrs_set_live(bool on)
{
	atomic_set(&live, on ? 1 : 0);
	if (!on) {
		listeners_set = false;
		memset(&listeners, 0, sizeof(listeners));
		memset(uid_tab, 0, sizeof(uid_tab));
#if FLUXRS_STAGE >= 2
		cancel_work_sync(&steal_work);
		skb_queue_purge(&steal_q);
#endif
	}
}

void fluxrs_set_listeners(const struct fluxrs_listeners *l)
{
	listeners = *l;
	listeners_set = l->v4_port != 0 || l->v6_port != 0;
}

void fluxrs_clear_uids(void)
{
	memset(uid_tab, 0, sizeof(uid_tab));
}

int fluxrs_set_uids(const struct fluxrs_uids *u)
{
	u32 i;

	if (u->count > ARRAY_SIZE(u->uids))
		return -EINVAL;
	memset(uid_tab, 0, sizeof(uid_tab));
	for (i = 0; i < u->count; i++) {
		u32 uid = u->uids[i];
		u32 slot = (uid * 0x9e3779b1u) & (FLUXRS_UID_CAP - 1);
		u32 j;
		bool placed = false;

		if (uid == 0 || uid == FLUXRS_OVERFLOWUID)
			continue;
		for (j = 0; j < FLUXRS_UID_PROBE; j++) {
			u32 idx = (slot + j) & (FLUXRS_UID_CAP - 1);

			if (uid_tab[idx] == 0 || uid_tab[idx] == uid) {
				uid_tab[idx] = uid;
				placed = true;
				break;
			}
		}
		if (!placed)
			return -ENOSPC;
	}
	return 0;
}

void fluxrs_get_status(struct fluxrs_status *s)
{
	s->live = atomic_read(&live) ? 1 : 0;
#if FLUXRS_STAGE < 2
	s->steal_ready = 0;
#elif FLUXRS_STAGE == 2
	s->steal_ready = 1;
#else
	s->steal_ready = fluxrs_sym_ready() ? 1 : 0;
#endif
	s->selected_seen = atomic64_read(&selected_seen);
	s->stolen = atomic64_read(&stolen);
	s->miss_listener = atomic64_read(&miss_listener);
	(void)listeners_set;
}

static bool uid_selected(u32 uid)
{
	u32 slot = (uid * 0x9e3779b1u) & (FLUXRS_UID_CAP - 1);
	u32 i;

	if (uid == 0 || uid == FLUXRS_OVERFLOWUID)
		return false;

	for (i = 0; i < FLUXRS_UID_PROBE; i++) {
		u32 v = READ_ONCE(uid_tab[(slot + i) & (FLUXRS_UID_CAP - 1)]);

		if (v == uid)
			return true;
		if (v == 0)
			return false;
	}
	return false;
}

/*
 * Keep in lockstep with crates/flux-core/src/cidr.rs FIXED_BYPASS_* plus
 * the ABI listener hosts. User CIDR / self-addr are still ioctl work.
 */
static bool fluxrs_reserved_dest(struct sk_buff *skb, u8 pf)
{
	if (pf == NFPROTO_IPV4) {
		u32 a = ntohl(ip_hdr(skb)->daddr);

		if ((a & 0xff000000u) == 0x00000000u)
			return true;
		if ((a & 0xff000000u) == 0x0a000000u)
			return true;
		if ((a & 0xff000000u) == 0x7f000000u)
			return true;
		if ((a & 0xffff0000u) == 0xa9fe0000u)
			return true;
		if ((a & 0xfff00000u) == 0xac100000u)
			return true;
		if ((a & 0xffff0000u) == 0xc0a80000u)
			return true;
		if ((a & 0xf0000000u) == 0xe0000000u)
			return true;
		if (a == 0xffffffffu)
			return true;
		if (a == 0xc6336401u)
			return true;
		return false;
	}
	if (pf == NFPROTO_IPV6) {
		const struct in6_addr *d = &ipv6_hdr(skb)->daddr;
		u32 w0 = ntohl(d->s6_addr32[0]);
		u32 w1 = ntohl(d->s6_addr32[1]);
		u32 w2 = ntohl(d->s6_addr32[2]);
		u32 w3 = ntohl(d->s6_addr32[3]);

		if (w0 == 0 && w1 == 0 && w2 == 0 && (w3 == 0 || w3 == 1))
			return true;
		if ((w0 & 0xfe000000u) == 0xfc000000u)
			return true;
		if ((w0 & 0xffc00000u) == 0xfe800000u)
			return true;
		if ((w0 & 0xff000000u) == 0xff000000u)
			return true;
		if (w0 == 0x20010db8u && w1 == 0x00000001u && w2 == 0 && w3 == 2)
			return true;
		return false;
	}
	return false;
}

#if FLUXRS_STAGE >= 2
static bool proto_stealable(u8 proto)
{
	return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

static void fluxrs_drop(struct sk_buff *skb)
{
	kfree_skb(skb);
}

#if FLUXRS_STAGE >= 3
static const struct net_device *steal_in_dev(struct sk_buff *skb,
					     struct net *net)
{
	if (skb->dev)
		return skb->dev;
	if (skb_dst(skb) && skb_dst(skb)->dev)
		return skb_dst(skb)->dev;
	return net->loopback_dev;
}

static void FLUXRS_CFI_WRAP fluxrs_put_lookup(struct sock *sk)
{
	if (sk)
		sock_gen_put(sk);
}

static struct sock *FLUXRS_CFI_WRAP fluxrs_lookup_v4(struct sk_buff *skb,
						     struct net *net)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct net_device *in;
	struct fluxrs_listeners l;
	struct udphdr _hdr, *hp;
	struct sock *sk;
	__be32 laddr;
	__be16 lport;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(*hp), &_hdr);
	if (!hp)
		return NULL;
	l = listeners;
	if (!l.v4_port)
		return NULL;
	in = steal_in_dev(skb, net);
	if (!in)
		return NULL;
	sk = fluxrs_get_sock_v4(net, skb, iph->protocol, iph->saddr, iph->daddr,
				hp->source, hp->dest, in,
				NF_TPROXY_LOOKUP_ESTABLISHED);
	laddr = fluxrs_laddr4(skb, l.v4_addr, iph->daddr);
	lport = l.v4_port;
	if (sk && sk->sk_state == TCP_TIME_WAIT)
		sk = fluxrs_tw4(net, skb, laddr, lport, sk);
	else if (!sk)
		sk = fluxrs_get_sock_v4(net, skb, iph->protocol, iph->saddr,
					laddr, hp->source, lport, in,
					NF_TPROXY_LOOKUP_LISTENER);
	return sk;
}

static struct sock *FLUXRS_CFI_WRAP fluxrs_lookup_v6(struct sk_buff *skb,
						     struct net *net)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct net_device *in;
	const struct in6_addr *laddr;
	struct fluxrs_listeners l;
	struct udphdr _hdr, *hp;
	struct sock *sk;
	__be16 lport;
	int thoff = 0;
	int tproto;

	tproto = ipv6_find_hdr(skb, &thoff, -1, NULL, NULL);
	if (tproto < 0)
		return NULL;
	hp = skb_header_pointer(skb, thoff, sizeof(*hp), &_hdr);
	if (!hp)
		return NULL;
	l = listeners;
	if (!l.v6_port)
		return NULL;
	in = steal_in_dev(skb, net);
	if (!in)
		return NULL;
	sk = fluxrs_get_sock_v6(net, skb, thoff, tproto, &iph->saddr,
				&iph->daddr, hp->source, hp->dest, in,
				NF_TPROXY_LOOKUP_ESTABLISHED);
	laddr = fluxrs_laddr6(skb, &l.v6_addr, &iph->daddr);
	lport = l.v6_port;
	if (sk && sk->sk_state == TCP_TIME_WAIT)
		sk = fluxrs_tw6(skb, tproto, thoff, net, &l.v6_addr, lport, sk);
	else if (!sk)
		sk = fluxrs_get_sock_v6(net, skb, thoff, tproto, &iph->saddr,
					laddr, hp->source, lport, in,
					NF_TPROXY_LOOKUP_LISTENER);
	return sk;
}
#endif /* stage >= 3 */

#if FLUXRS_STAGE >= 4
static bool fluxrs_prepare_rx(struct sk_buff *skb)
{
	if (skb_linearize(skb))
		return false;
	skb_scrub_packet(skb, false);
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return false;
	skb->pkt_type = PACKET_HOST;
	return true;
}

#if FLUXRS_STAGE >= 5
/*
 * STAGE 5 called these with skb_dst == NULL after scrub and panicked
 * in ip6_protocol_deliver_rcu (0.6.39). STAGE 6 attaches a loopback
 * local dst first. This is not lo bounce: no netif_rx(lo), no iif-lo
 * rule. Second ip_rcv / dummy inject is rejected (0.6.40).
 */
static void fluxrs_deliver(struct sk_buff *skb, u8 family)
{
	if (!skb->dev)
		skb->dev = init_net.loopback_dev;
	local_bh_disable();
	if (family == NFPROTO_IPV4)
		ip_local_deliver(skb);
	else
		ip6_input(skb);
	local_bh_enable();
}
#endif

#if FLUXRS_STAGE >= 6
static bool fluxrs_attach_local_dst(struct sk_buff *skb, u8 family)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : &init_net;
	struct net_device *dev = net->loopback_dev;
	struct dst_entry *dst;

	if (!dev)
		return false;
	skb->dev = dev;
	skb->skb_iif = dev->ifindex;

	if (family == NFPROTO_IPV4) {
		struct rtable *rt = ip_route_output(net, htonl(INADDR_LOOPBACK),
						    0, 0, 0);

		if (IS_ERR_OR_NULL(rt))
			return false;
		skb_dst_set(skb, &rt->dst);
		return true;
	}

	{
		struct flowi6 fl6 = {};

		fl6.daddr = in6addr_loopback;
		fl6.flowi6_oif = dev->ifindex;
		dst = ip6_route_output(net, NULL, &fl6);
		if (!dst || dst->error) {
			dst_release(dst);
			return false;
		}
		skb_dst_set(skb, dst);
		return true;
	}
}
#endif
#endif /* stage >= 4 */

static void FLUXRS_CFI_WRAP fluxrs_steal_one(struct sk_buff *skb)
{
#if FLUXRS_STAGE >= 3
	struct net *net;
	struct sock *sk = NULL;
	u8 family;
#endif

	if (!atomic_read(&live)) {
		fluxrs_drop(skb);
		return;
	}
#if FLUXRS_STAGE == 2
	atomic64_inc(&stolen);
	fluxrs_drop(skb);
	return;
#else
	if (!listeners_set || !fluxrs_sym_ready()) {
		atomic64_inc(&miss_listener);
		fluxrs_drop(skb);
		return;
	}
	net = skb->dev ? dev_net(skb->dev) : &init_net;
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		family = NFPROTO_IPV4;
		rcu_read_lock();
		sk = fluxrs_lookup_v4(skb, net);
		rcu_read_unlock();
		break;
	case htons(ETH_P_IPV6):
		family = NFPROTO_IPV6;
		rcu_read_lock();
		sk = fluxrs_lookup_v6(skb, net);
		rcu_read_unlock();
		break;
	default:
		fluxrs_drop(skb);
		return;
	}
	if (!sk || !nf_tproxy_sk_is_transparent(sk)) {
		atomic64_inc(&miss_listener);
		fluxrs_drop(skb);
		return;
	}
#if FLUXRS_STAGE < 5
	(void)family;
#endif
#if FLUXRS_STAGE == 3
	fluxrs_put_lookup(sk);
	atomic64_inc(&stolen);
	fluxrs_drop(skb);
	return;
#endif
#if FLUXRS_STAGE >= 4
	if (!fluxrs_prepare_rx(skb)) {
		fluxrs_put_lookup(sk);
		atomic64_inc(&miss_listener);
		fluxrs_drop(skb);
		return;
	}
#if FLUXRS_STAGE >= 6
	if (!fluxrs_attach_local_dst(skb, family)) {
		fluxrs_put_lookup(sk);
		atomic64_inc(&miss_listener);
		fluxrs_drop(skb);
		return;
	}
	/*
	 * TX TCP uses tcp_skb_cb in skb->cb; ip6_input_finish reads
	 * IP6CB(skb)->nhoff to dispatch. ip6_rcv_core would have set
	 * this; we skip it, so IPv6 TCP SYNs never reached tcp_v6_rcv
	 * (UDP IPv6 already had nhoff from ip6_xmit).
	 */
	if (family == NFPROTO_IPV6) {
		memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));
		IP6CB(skb)->iif = skb->skb_iif;
		IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	}
#endif
	nf_tproxy_assign_sock(skb, sk);
	atomic64_inc(&stolen);
#if FLUXRS_STAGE >= 5
	fluxrs_deliver(skb, family);
#else
	fluxrs_drop(skb);
#endif
#endif
#endif /* stage != 2 */
}

static void FLUXRS_CFI_WRAP fluxrs_steal_workfn(struct work_struct *work)
{
	struct sk_buff *skb;

	(void)work;
	while ((skb = skb_dequeue(&steal_q)))
		fluxrs_steal_one(skb);
}
#endif /* stage >= 2 */

static unsigned int fluxrs_local_out(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct sock *sk;
	u32 uid;
#if FLUXRS_STAGE >= 2
	u8 proto;
#endif

	(void)priv;
	(void)state;
	if (!atomic_read(&live))
		return NF_ACCEPT;
	sk = skb->sk;
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;
	uid = __kuid_val(sk->sk_uid);
	if (uid == 0 || uid == FLUXRS_OVERFLOWUID)
		return NF_ACCEPT;
	if (!uid_selected(uid))
		return NF_ACCEPT;
	if (fluxrs_reserved_dest(skb, state->pf))
		return NF_ACCEPT;
	atomic64_inc(&selected_seen);
#if FLUXRS_STAGE < 2
	return NF_ACCEPT;
#else
	if (state->pf == NFPROTO_IPV4)
		proto = ip_hdr(skb)->protocol;
	else
		proto = ipv6_hdr(skb)->nexthdr;
	if (!proto_stealable(proto))
		return NF_ACCEPT;
#if FLUXRS_STAGE >= 3
	if (!listeners_set || !fluxrs_sym_ready())
		return NF_ACCEPT;
#endif
	if (skb_queue_len_lockless(&steal_q) >= FLUXRS_STEAL_QMAX)
		return NF_ACCEPT;
	skb_orphan(skb);
	skb_queue_tail(&steal_q, skb);
	schedule_work(&steal_work);
	return NF_STOLEN;
#endif
}

static struct nf_hook_ops fluxrs_ops[] = {
	{
		.hook = fluxrs_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = fluxrs_local_out,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_FILTER,
	},
#endif
};

int fluxrs_hook_register(void)
{
#if FLUXRS_STAGE >= 2
	skb_queue_head_init(&steal_q);
	INIT_WORK(&steal_work, fluxrs_steal_workfn);
#endif
	return nf_register_net_hooks(&init_net, fluxrs_ops,
				     ARRAY_SIZE(fluxrs_ops));
}

void fluxrs_hook_unregister(void)
{
	nf_unregister_net_hooks(&init_net, fluxrs_ops, ARRAY_SIZE(fluxrs_ops));
#if FLUXRS_STAGE >= 2
	cancel_work_sync(&steal_work);
	skb_queue_purge(&steal_q);
#endif
	pr_info("fluxrs: stage=%d selected_seen=%llu stolen=%llu miss=%llu\n",
		FLUXRS_STAGE,
		(unsigned long long)atomic64_read(&selected_seen),
		(unsigned long long)atomic64_read(&stolen),
		(unsigned long long)atomic64_read(&miss_listener));
}
