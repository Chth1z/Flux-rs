#!/usr/bin/env bash
# Which ELF section names can a stock bpftool actually load a sched_cls from?
#
# Prompted by a real defect: bpf/flux.bpf.c shipped SEC("tc/cap_l2") and
# friends, and libbpf recognises only tc/ingress and tc/egress under "tc/".
# Every product program would have failed with "failed to guess program type
# from ELF section". Guessing a replacement is not good enough, so this
# enumerates candidates and lets the loader decide.
#
# Compiles one object per candidate. Run the companion loader half on whichever
# bpftool matters -- the device's, since that is the debugging target.
set -u
cd "$(dirname "$0")" || exit 1
OUT=${1:-/tmp/secprobe}
mkdir -p "$OUT"

cat >"$OUT/s.c" <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#ifndef NAME
#define NAME "tc"
#endif
SEC(NAME)
int p(struct __sk_buff *skb)
{
	(void)skb;
	return -1;
}
char _l[] SEC("license") = "GPL";
EOF

INC=""
[ -d /usr/include/x86_64-linux-gnu ] && INC="-I /usr/include/x86_64-linux-gnu"

: >"$OUT/names.txt"
while IFS= read -r n; do
	[ -z "$n" ] && continue
	f=$(printf '%s' "$n" | tr '/' '_')
	if clang -target bpf -O2 -g -mcpu=v3 $INC -DNAME="\"$n\"" \
		-c "$OUT/s.c" -o "$OUT/o_$f.o" 2>/dev/null; then
		printf '%s\t%s\n' "$f" "$n" >>"$OUT/names.txt"
		echo "compiled  $n"
	else
		echo "COMPILE FAILED  $n"
	fi
done <<'EOF'
tc
classifier
action
tc/egress
tc/ingress
tc/cap_l2
classifier/cap_l2
action/cap_l2
tcx/egress
EOF

echo
echo "objects in $OUT:"
ls -1 "$OUT"/o_*.o
