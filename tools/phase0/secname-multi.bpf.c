// Four sched_cls programs sharing one recognised section name.
//
// If bpftool can load all four out of a single SEC("tc"), then the product does
// not need four distinct section names -- but its own hand-written loader would
// then have to locate each function inside a shared section and rebase that
// section's relocations per function, which is precisely where hand-rolled
// loaders go wrong. Knowing whether this even works is what decides whether
// that complexity is worth considering at all.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

// A map reference in each program, so the object carries real relocations
// rather than being a trivially position-independent stub.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} multi_cnt SEC(".maps");

static __always_inline int hit(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&multi_cnt, &slot);
	if (v)
		*v += 1;
	return TC_ACT_UNSPEC;
}

SEC("tc")
int m_cap_l2(struct __sk_buff *skb)
{
	(void)skb;
	return hit(0);
}

SEC("tc")
int m_cap_l3(struct __sk_buff *skb)
{
	(void)skb;
	return hit(1);
}

SEC("tc")
int m_in(struct __sk_buff *skb)
{
	(void)skb;
	return hit(2);
}

SEC("tc")
int m_verify(struct __sk_buff *skb)
{
	(void)skb;
	return hit(3);
}

char _l[] SEC("license") = "GPL";
