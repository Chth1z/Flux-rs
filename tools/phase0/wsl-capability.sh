#!/usr/bin/env bash
# Checks whether this Linux host can be used as a Phase 0 rehearsal
# environment. READ ONLY.
#
# Rehearsal, not verdict: Phase 0's authoritative answers must come from the
# product's baseline kernel (5.15) on a real Android device, because the two
# behaviours that matter most -- bpf_sk_assign's reuseport rejection and TCX
# availability -- both changed inside the 5.15 to 6.6 window. A newer host is
# permissive in exactly the places the baseline is not.
#
# What a newer host IS good for: catching program-level errors for free. A
# program the 6.x verifier rejects will certainly be rejected on 5.15.

echo "########## kernel"
uname -r
echo "id: $(id -u)"

echo
echo "########## tools"
for t in bpftool clang llvm-strip ip tc; do
	p=$(command -v "$t" 2>/dev/null)
	printf '  %-12s %s\n' "$t" "${p:-MISSING}"
done

echo
echo "########## bpf filesystem"
if mount | grep -q ' /sys/fs/bpf '; then
	echo "  /sys/fs/bpf mounted"
else
	echo "  /sys/fs/bpf NOT mounted (mount -t bpf bpf /sys/fs/bpf)"
fi

echo
echo "########## BTF"
if [ -r /sys/kernel/btf/vmlinux ]; then
	echo "  /sys/kernel/btf/vmlinux present, bytes=$(wc -c </sys/kernel/btf/vmlinux)"
else
	echo "  ABSENT -- SK_STORAGE map creation needs BTF"
fi

echo
echo "########## kernel config"
if [ -f /proc/config.gz ]; then
	for k in CONFIG_BPF_SYSCALL CONFIG_NET_CLS_BPF CONFIG_NET_CLS_ACT \
		CONFIG_NET_SCH_INGRESS CONFIG_DEBUG_INFO_BTF CONFIG_VETH CONFIG_NET_NS; do
		v=$(zcat /proc/config.gz 2>/dev/null | grep -E "^$k=")
		[ -z "$v" ] && v="$k NOT SET"
		echo "  $v"
	done
else
	echo "  /proc/config.gz absent; probing by capability instead"
fi

echo
echo "########## capability probes (do not trust config, try it)"
echo -n "  create a PERCPU_ARRAY map: "
if command -v bpftool >/dev/null 2>&1; then
	if bpftool map create /sys/fs/bpf/flux_probe_tmp type percpu_array key 4 value 8 entries 1 name flux_probe 2>/dev/null; then
		echo "OK"
		bpftool map delete pinned /sys/fs/bpf/flux_probe_tmp 2>/dev/null
		rm -f /sys/fs/bpf/flux_probe_tmp 2>/dev/null
	else
		echo "FAILED"
	fi
else
	echo "skipped (no bpftool)"
fi

echo -n "  create a netns: "
if ip netns add flux_probe_tmp 2>/dev/null; then
	echo "OK"
	ip netns del flux_probe_tmp 2>/dev/null
else
	echo "FAILED"
fi

echo -n "  create a veth pair: "
if ip link add flux_p0 type veth peer name flux_p1 2>/dev/null; then
	echo "OK"
	ip link del flux_p0 2>/dev/null
else
	echo "FAILED"
fi

echo
echo "########## done"
