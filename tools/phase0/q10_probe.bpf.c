// SPDX-License-Identifier: GPL-3.0-only
//
// Phase 0 Q10 probe. The smallest program that can answer one question:
// does the classifier chain actually reach the preference we attached at?
//
// Counts every invocation and returns TC_ACT_UNSPEC, so it changes the fate of
// no packet. Read the counter with `bpftool map dump`.
//
// Build (in WSL, not on the device):
//   clang -target bpf -O2 -g -mcpu=v3 -c tools/phase0/q10_probe.bpf.c \
//         -o /tmp/q10_probe.o
//
// Deploy:
//   adb push /tmp/q10_probe.o /data/local/tmp/
//   bpftool prog load /data/local/tmp/q10_probe.o /sys/fs/bpf/q10_probe
//   tc filter add dev wlan0 parent ffff:fff3 pref 9 bpf da pinned /sys/fs/bpf/q10_probe
//
// No libbpf, no vmlinux.h, no CO-RE: helpers are declared by hand and the map
// uses the BTF-defined `.maps` layout written out longhand. Compiles with
// nothing but clang and linux/bpf.h.
//
// The map definition style is not a free choice. The first version of this
// probe used the legacy `SEC("maps")` form, which bpf2socks and asteriskd both
// ship on Android -- and the device's own bpftool rejected it outright:
//
//     libbpf: elf: legacy map definitions in 'maps' section are not
//             supported by libbpf v1.0+
//
// So legacy definitions only work with a loader that still understands them.
// See blueprint section 12.9.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#ifndef __section
#define __section(x) __attribute__((section(x), used))
#endif
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

// BTF-defined map. Requires -g so clang emits .BTF.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, unsigned long long);
} q10_counter __section(".maps");

__section("tc") int q10_probe(struct __sk_buff *skb)
{
	unsigned int key = 0;
	unsigned long long *slot;

	(void)skb;
	slot = bpf_map_lookup_elem(&q10_counter, &key);
	if (slot)
		*slot += 1; // per-CPU, so no atomic needed

	// The whole point: do not alter the chain. TC_ACT_UNSPEC continues to the
	// next classifier exactly as if we were not here.
	return TC_ACT_UNSPEC;
}

char _license[] __section("license") = "GPL";
