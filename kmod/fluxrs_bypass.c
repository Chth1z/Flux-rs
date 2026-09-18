/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * User CIDR + self-addr for LOCAL_OUT. Unselected traffic never gets here:
 * the hook calls this only after uid_selected. Lookup is longest-prefix
 * per plen bucket (binary search), not a 65536-walk.
 */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/uaccess.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/string.h>
#include "fluxrs.h"

struct fluxrs_pfx4_live {
	u32 net;
	u8 plen;
	u8 tag;
};

struct fluxrs_pfx6_live {
	u8 net[16];
	u8 plen;
	u8 tag;
};

struct fluxrs_set {
	u32 cidr_mode;
	u32 v4_n;
	u32 v6_n;
	u32 s4_n;
	u32 s6_n;
	u32 v4_off[34];
	u32 v6_off[130];
	struct fluxrs_pfx4_live *v4;
	struct fluxrs_pfx6_live *v6;
	u32 *self4;
	struct in6_addr *self6;
};

static DEFINE_MUTEX(bypass_mu);
static struct fluxrs_set __rcu *bypass_live;

static u32 plen4_mask(u8 plen)
{
	if (plen == 0)
		return 0;
	if (plen >= 32)
		return 0xffffffffu;
	return ~0u << (32 - plen);
}

static void mask_v6(const u8 *addr, u8 plen, u8 *out)
{
	int full = plen / 8;
	int bits = plen % 8;

	memset(out, 0, 16);
	if (full)
		memcpy(out, addr, full);
	if (bits)
		out[full] = addr[full] & (u8)(0xff << (8 - bits));
}

static int cmp_pfx4(const void *a, const void *b)
{
	const struct fluxrs_pfx4_live *pa = a;
	const struct fluxrs_pfx4_live *pb = b;

	if (pa->plen != pb->plen)
		return (int)pa->plen - (int)pb->plen;
	if (pa->net < pb->net)
		return -1;
	if (pa->net > pb->net)
		return 1;
	return 0;
}

static int cmp_pfx6(const void *a, const void *b)
{
	const struct fluxrs_pfx6_live *pa = a;
	const struct fluxrs_pfx6_live *pb = b;
	int c;

	if (pa->plen != pb->plen)
		return (int)pa->plen - (int)pb->plen;
	c = memcmp(pa->net, pb->net, 16);
	if (c < 0)
		return -1;
	if (c > 0)
		return 1;
	return 0;
}

static int cmp_u32(const void *a, const void *b)
{
	u32 va = *(const u32 *)a;
	u32 vb = *(const u32 *)b;

	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}

static int cmp_in6(const void *a, const void *b)
{
	int c = memcmp(a, b, sizeof(struct in6_addr));

	if (c < 0)
		return -1;
	if (c > 0)
		return 1;
	return 0;
}

static u32 unique_pfx4(struct fluxrs_pfx4_live *p, u32 n)
{
	u32 i, o = 0;

	if (n == 0)
		return 0;
	for (i = 1; i < n; i++) {
		if (p[i].plen == p[o].plen && p[i].net == p[o].net)
			p[o] = p[i];
		else
			p[++o] = p[i];
	}
	return o + 1;
}

static u32 unique_pfx6(struct fluxrs_pfx6_live *p, u32 n)
{
	u32 i, o = 0;

	if (n == 0)
		return 0;
	for (i = 1; i < n; i++) {
		if (p[i].plen == p[o].plen &&
		    memcmp(p[i].net, p[o].net, 16) == 0)
			p[o] = p[i];
		else
			p[++o] = p[i];
	}
	return o + 1;
}

static u32 unique_u32(u32 *p, u32 n)
{
	u32 i, o = 0;

	if (n == 0)
		return 0;
	for (i = 1; i < n; i++) {
		if (p[i] != p[o])
			p[++o] = p[i];
	}
	return o + 1;
}

static u32 unique_in6(struct in6_addr *p, u32 n)
{
	u32 i, o = 0;

	if (n == 0)
		return 0;
	for (i = 1; i < n; i++) {
		if (memcmp(&p[i], &p[o], sizeof(*p)) != 0)
			p[++o] = p[i];
	}
	return o + 1;
}

static void fill_off4(struct fluxrs_set *s)
{
	u32 i = 0;
	u32 plen;

	for (plen = 0; plen <= 32; plen++) {
		s->v4_off[plen] = i;
		while (i < s->v4_n && s->v4[i].plen == plen)
			i++;
	}
	s->v4_off[33] = s->v4_n;
}

static void fill_off6(struct fluxrs_set *s)
{
	u32 i = 0;
	u32 plen;

	for (plen = 0; plen <= 128; plen++) {
		s->v6_off[plen] = i;
		while (i < s->v6_n && s->v6[i].plen == plen)
			i++;
	}
	s->v6_off[129] = s->v6_n;
}

static bool pfx4_find(const struct fluxrs_pfx4_live *p, u32 lo, u32 hi,
		      u32 key, u8 *tag)
{
	while (lo < hi) {
		u32 mid = lo + ((hi - lo) >> 1);

		if (p[mid].net == key) {
			*tag = p[mid].tag;
			return true;
		}
		if (p[mid].net < key)
			lo = mid + 1;
		else
			hi = mid;
	}
	return false;
}

static bool pfx6_find(const struct fluxrs_pfx6_live *p, u32 lo, u32 hi,
		      const u8 *key, u8 *tag)
{
	while (lo < hi) {
		u32 mid = lo + ((hi - lo) >> 1);
		int c = memcmp(p[mid].net, key, 16);

		if (c == 0) {
			*tag = p[mid].tag;
			return true;
		}
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return false;
}

static bool lpm4(const struct fluxrs_set *s, u32 addr, u8 *tag)
{
	int plen;

	for (plen = 32; plen >= 0; plen--) {
		u32 lo = s->v4_off[plen];
		u32 hi = s->v4_off[plen + 1];
		u32 key;

		if (lo == hi)
			continue;
		key = addr & plen4_mask((u8)plen);
		if (pfx4_find(s->v4, lo, hi, key, tag))
			return true;
	}
	return false;
}

static bool lpm6(const struct fluxrs_set *s, const u8 *addr, u8 *tag)
{
	int plen;
	u8 key[16];

	for (plen = 128; plen >= 0; plen--) {
		u32 lo = s->v6_off[plen];
		u32 hi = s->v6_off[plen + 1];

		if (lo == hi)
			continue;
		mask_v6(addr, (u8)plen, key);
		if (pfx6_find(s->v6, lo, hi, key, tag))
			return true;
	}
	return false;
}

static bool self4_hit(const struct fluxrs_set *s, u32 addr)
{
	u32 i;

	for (i = 0; i < s->s4_n; i++) {
		if (s->self4[i] == addr)
			return true;
	}
	return false;
}

static bool self6_hit(const struct fluxrs_set *s, const struct in6_addr *addr)
{
	u32 i;

	for (i = 0; i < s->s6_n; i++) {
		if (memcmp(&s->self6[i], addr, sizeof(*addr)) == 0)
			return true;
	}
	return false;
}

static bool tag_direct(u32 cidr_mode, bool hit, u8 tag)
{
	if (hit && tag == FLUXRS_BYPASS_RESERVED)
		return true;
	if (cidr_mode == FLUXRS_CIDR_WHITELIST)
		return !hit || tag != FLUXRS_BYPASS_POLICY;
	return hit;
}

static bool set_direct(const struct fluxrs_set *s, struct sk_buff *skb, u8 pf)
{
	u8 tag = 0;
	bool hit;

	if (!s)
		return false;
	if (pf == NFPROTO_IPV4) {
		u32 a = ntohl(ip_hdr(skb)->daddr);

		if (self4_hit(s, a))
			return true;
		hit = lpm4(s, a, &tag);
		return tag_direct(s->cidr_mode, hit, tag);
	}
	if (pf == NFPROTO_IPV6) {
		const struct in6_addr *d = &ipv6_hdr(skb)->daddr;

		if (self6_hit(s, d))
			return true;
		hit = lpm6(s, d->s6_addr, &tag);
		return tag_direct(s->cidr_mode, hit, tag);
	}
	return false;
}

bool fluxrs_policy_direct(struct sk_buff *skb, u8 pf)
{
	const struct fluxrs_set *s;
	bool direct;

	rcu_read_lock();
	s = rcu_dereference(bypass_live);
	direct = set_direct(s, skb, pf);
	rcu_read_unlock();
	return direct;
}

static void fluxrs_set_free(struct fluxrs_set *s)
{
	if (!s)
		return;
	kvfree(s->v4);
	kvfree(s->v6);
	kvfree(s->self4);
	kvfree(s->self6);
	kvfree(s);
}

static int parse_v4(struct fluxrs_set *s, const struct fluxrs_pfx4 *in, u32 n)
{
	u32 i;

	if (n == 0)
		return 0;
	s->v4 = kvmalloc((size_t)n * sizeof(*s->v4), GFP_KERNEL);
	if (!s->v4)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		u8 plen = in[i].prefixlen;
		u8 tag = in[i].tag;
		u32 addr;

		if (plen > 32)
			return -EINVAL;
		if (tag != FLUXRS_BYPASS_RESERVED && tag != FLUXRS_BYPASS_POLICY)
			return -EINVAL;
		addr = ntohl(in[i].addr);
		s->v4[i].net = addr & plen4_mask(plen);
		s->v4[i].plen = plen;
		s->v4[i].tag = tag;
	}
	sort(s->v4, n, sizeof(*s->v4), cmp_pfx4, NULL);
	s->v4_n = unique_pfx4(s->v4, n);
	fill_off4(s);
	return 0;
}

static int parse_v6(struct fluxrs_set *s, const struct fluxrs_pfx6 *in, u32 n)
{
	u32 i;

	if (n == 0)
		return 0;
	s->v6 = kvmalloc((size_t)n * sizeof(*s->v6), GFP_KERNEL);
	if (!s->v6)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		u8 plen = in[i].prefixlen;
		u8 tag = in[i].tag;

		if (plen > 128)
			return -EINVAL;
		if (tag != FLUXRS_BYPASS_RESERVED && tag != FLUXRS_BYPASS_POLICY)
			return -EINVAL;
		mask_v6(in[i].addr.s6_addr, plen, s->v6[i].net);
		s->v6[i].plen = plen;
		s->v6[i].tag = tag;
	}
	sort(s->v6, n, sizeof(*s->v6), cmp_pfx6, NULL);
	s->v6_n = unique_pfx6(s->v6, n);
	fill_off6(s);
	return 0;
}

static int parse_self4(struct fluxrs_set *s, const __be32 *in, u32 n)
{
	u32 i;

	if (n == 0)
		return 0;
	s->self4 = kvmalloc((size_t)n * sizeof(*s->self4), GFP_KERNEL);
	if (!s->self4)
		return -ENOMEM;
	for (i = 0; i < n; i++)
		s->self4[i] = ntohl(in[i]);
	sort(s->self4, n, sizeof(*s->self4), cmp_u32, NULL);
	s->s4_n = unique_u32(s->self4, n);
	return 0;
}

static int parse_self6(struct fluxrs_set *s, const struct in6_addr *in, u32 n)
{
	if (n == 0)
		return 0;
	s->self6 = kvmalloc((size_t)n * sizeof(*s->self6), GFP_KERNEL);
	if (!s->self6)
		return -ENOMEM;
	memcpy(s->self6, in, n * sizeof(*in));
	sort(s->self6, n, sizeof(*s->self6), cmp_in6, NULL);
	s->s6_n = unique_in6(s->self6, n);
	return 0;
}

int fluxrs_set_bypass(void __user *arg)
{
	struct fluxrs_bypass hdr;
	struct fluxrs_set *new_set, *old;
	u8 *buf;
	size_t v4b, v6b, s4b, s6b, total;
	int err;

	if (copy_from_user(&hdr, arg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.cidr_mode > FLUXRS_CIDR_WHITELIST)
		return -EINVAL;
	if (hdr.v4_count > FLUXRS_LPM_MAX || hdr.v6_count > FLUXRS_LPM_MAX)
		return -ENOSPC;
	if (hdr.self4_count > FLUXRS_SELF_MAX ||
	    hdr.self6_count > FLUXRS_SELF_MAX)
		return -ENOSPC;

	v4b = (size_t)hdr.v4_count * sizeof(struct fluxrs_pfx4);
	v6b = (size_t)hdr.v6_count * sizeof(struct fluxrs_pfx6);
	s4b = (size_t)hdr.self4_count * sizeof(__be32);
	s6b = (size_t)hdr.self6_count * sizeof(struct in6_addr);
	total = sizeof(hdr) + v4b + v6b + s4b + s6b;
	buf = kvmalloc(total, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (copy_from_user(buf, arg, total)) {
		kvfree(buf);
		return -EFAULT;
	}

	new_set = kvzalloc(sizeof(*new_set), GFP_KERNEL);
	if (!new_set) {
		kvfree(buf);
		return -ENOMEM;
	}
	new_set->cidr_mode = hdr.cidr_mode;
	fill_off4(new_set);
	fill_off6(new_set);

	err = parse_v4(new_set,
		       (const struct fluxrs_pfx4 *)(buf + sizeof(hdr)),
		       hdr.v4_count);
	if (err)
		goto fail;
	err = parse_v6(new_set,
		       (const struct fluxrs_pfx6 *)(buf + sizeof(hdr) + v4b),
		       hdr.v6_count);
	if (err)
		goto fail;
	err = parse_self4(new_set,
			  (const __be32 *)(buf + sizeof(hdr) + v4b + v6b),
			  hdr.self4_count);
	if (err)
		goto fail;
	err = parse_self6(new_set,
			  (const struct in6_addr *)(buf + sizeof(hdr) + v4b +
						    v6b + s4b),
			  hdr.self6_count);
	if (err)
		goto fail;
	kvfree(buf);
	buf = NULL;

	mutex_lock(&bypass_mu);
	old = rcu_dereference_protected(bypass_live,
					lockdep_is_held(&bypass_mu));
	rcu_assign_pointer(bypass_live, new_set);
	mutex_unlock(&bypass_mu);
	synchronize_rcu();
	fluxrs_set_free(old);
	return 0;

fail:
	kvfree(buf);
	fluxrs_set_free(new_set);
	return err;
}

void fluxrs_bypass_exit(void)
{
	struct fluxrs_set *old;

	mutex_lock(&bypass_mu);
	old = rcu_dereference_protected(bypass_live,
					lockdep_is_held(&bypass_mu));
	rcu_assign_pointer(bypass_live, NULL);
	mutex_unlock(&bypass_mu);
	synchronize_rcu();
	fluxrs_set_free(old);
}
