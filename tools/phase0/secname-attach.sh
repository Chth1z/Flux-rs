#!/system/bin/sh
# Second half of the section-name question: loading is not the bar, attaching is.
#
# libbpf maps SEC("tc/ingress") and SEC("tc/egress") onto SCHED_CLS with an
# expected_attach_type of BPF_TCX_*. TCX did not exist until 6.6, so on the 5.15
# baseline those programs might load and then refuse to attach through the
# legacy tc path -- which is the only path the product uses. Find out.
#
# Also checks whether SEC("action") is a trap: it selects BPF_PROG_TYPE_SCHED_ACT,
# a different program type that `tc filter ... bpf da` cannot take.

D=/data/local/tmp/secprobe
EGRESS=ffff:fff3
PREF=3

IF=""
for cand in $(tc qdisc show 2>/dev/null | grep clsact | sed 's/.*dev \([^ ]*\).*/\1/'); do
	case "$cand" in flxrs* | lo) continue ;; esac
	IF="$cand"
	break
done
[ -n "$IF" ] || { echo "ABORT: no clsact interface"; exit 1; }

cleanup() {
	tc filter del dev "$IF" parent "$EGRESS" pref "$PREF" 2>/dev/null
	rm -f /sys/fs/bpf/_sn 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "interface: $IF"
echo
printf '%-20s %-10s %-12s %s\n' "SECTION" "LOAD" "PROG TYPE" "LEGACY tc ATTACH"
printf '%-20s %-10s %-12s %s\n' "-------" "----" "---------" "----------------"

while IFS="$(printf '\t')" read -r f n; do
	[ -z "$f" ] && continue
	obj="$D/o_$f.o"
	[ -f "$obj" ] || continue

	tc filter del dev "$IF" parent "$EGRESS" pref "$PREF" 2>/dev/null
	rm -f /sys/fs/bpf/_sn 2>/dev/null

	if ! bpftool prog load "$obj" /sys/fs/bpf/_sn >/dev/null 2>&1; then
		printf '%-20s %-10s %-12s %s\n' "$n" "fail" "-" "-"
		continue
	fi
	ptype=$(bpftool prog show pinned /sys/fs/bpf/_sn 2>/dev/null |
		head -1 | sed 's/^[0-9]*: *\([a-z_]*\).*/\1/')

	err=$(tc filter add dev "$IF" parent "$EGRESS" pref "$PREF" protocol all \
		bpf da pinned /sys/fs/bpf/_sn 2>&1)
	if tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref $PREF "; then
		att="OK"
	else
		att="fail: $(echo "$err" | head -1)"
	fi

	printf '%-20s %-10s %-12s %s\n' "$n" "OK" "$ptype" "$att"
	tc filter del dev "$IF" parent "$EGRESS" pref "$PREF" 2>/dev/null
	rm -f /sys/fs/bpf/_sn 2>/dev/null
done <"$D/names.txt"

echo
echo "--- can one object hold several sched_cls programs in one SEC(\"tc\")?"
if [ -f "$D/multi.o" ]; then
	rm -rf /sys/fs/bpf/_snd 2>/dev/null
	out=$(bpftool prog loadall "$D/multi.o" /sys/fs/bpf/_snd 2>&1)
	if [ -d /sys/fs/bpf/_snd ]; then
		echo "  loadall OK, pinned programs:"
		ls -1 /sys/fs/bpf/_snd | sed 's/^/    /'
	else
		echo "  loadall failed:"
		echo "$out" | head -4 | sed 's/^/    /'
	fi
	rm -rf /sys/fs/bpf/_snd 2>/dev/null
else
	echo "  multi.o not pushed, skipped"
fi
