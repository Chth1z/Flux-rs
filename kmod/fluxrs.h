/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef FLUXRS_H
#define FLUXRS_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/in6.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_tproxy.h>

#define FLUXRS_IOCTL_MAGIC 'F'

struct fluxrs_listeners {
	__be32 v4_addr;
	__be16 v4_port;
	__be16 pad0;
	struct in6_addr v6_addr;
	__be16 v6_port;
	__be16 pad1;
};

struct fluxrs_uids {
	__u32 count;
	__u32 uids[64];
};

struct fluxrs_status {
	__u32 live;
	__u32 steal_ready;
	__u64 selected_seen;
	__u64 stolen;
	__u64 miss_listener;
};

#define FLUXRS_SET_LISTENERS \
	_IOW(FLUXRS_IOCTL_MAGIC, 1, struct fluxrs_listeners)
#define FLUXRS_SET_UIDS _IOW(FLUXRS_IOCTL_MAGIC, 2, struct fluxrs_uids)
#define FLUXRS_CLEAR_UIDS _IO(FLUXRS_IOCTL_MAGIC, 3)
#define FLUXRS_GET_STATUS _IOR(FLUXRS_IOCTL_MAGIC, 4, struct fluxrs_status)

typedef struct sock *(*fluxrs_get_sock_v4_t)(struct net *net, struct sk_buff *skb,
					     const u8 protocol, const __be32 saddr,
					     const __be32 daddr, const __be16 sport,
					     const __be16 dport,
					     const struct net_device *in,
					     const enum nf_tproxy_lookup_t lookup_type);

typedef struct sock *(*fluxrs_get_sock_v6_t)(struct net *net, struct sk_buff *skb,
					     int thoff, const u8 protocol,
					     const struct in6_addr *saddr,
					     const struct in6_addr *daddr,
					     const __be16 sport, const __be16 dport,
					     const struct net_device *in,
					     const enum nf_tproxy_lookup_t lookup_type);

typedef struct sock *(*fluxrs_tw4_t)(struct net *net, struct sk_buff *skb,
				     __be32 laddr, __be16 lport, struct sock *sk);

typedef struct sock *(*fluxrs_tw6_t)(struct sk_buff *skb, int tproto, int thoff,
				     struct net *net, const struct in6_addr *laddr,
				     const __be16 lport, struct sock *sk);

typedef __be32 (*fluxrs_laddr4_t)(struct sk_buff *skb, __be32 user_laddr,
				  __be32 daddr);

typedef const struct in6_addr *(*fluxrs_laddr6_t)(struct sk_buff *skb,
						  const struct in6_addr *user_laddr,
						  const struct in6_addr *daddr);

extern fluxrs_get_sock_v4_t fluxrs_get_sock_v4;
extern fluxrs_get_sock_v6_t fluxrs_get_sock_v6;
extern fluxrs_tw4_t fluxrs_tw4;
extern fluxrs_tw6_t fluxrs_tw6;
extern fluxrs_laddr4_t fluxrs_laddr4;
extern fluxrs_laddr6_t fluxrs_laddr6;

int fluxrs_sym_init(void);
void fluxrs_sym_exit(void);
bool fluxrs_sym_ready(void);

int fluxrs_hook_register(void);
void fluxrs_hook_unregister(void);
void fluxrs_set_live(bool live);
void fluxrs_set_listeners(const struct fluxrs_listeners *l);
int fluxrs_set_uids(const struct fluxrs_uids *u);
void fluxrs_clear_uids(void);
void fluxrs_get_status(struct fluxrs_status *s);

int fluxrs_ctl_register(void);
void fluxrs_ctl_unregister(void);

#endif
