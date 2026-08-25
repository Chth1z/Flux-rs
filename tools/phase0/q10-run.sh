#!/system/bin/sh
# Phase 0 Q10 -- the decisive measurement.
#
# MODIFIES DEVICE STATE. Everything is removed by the cleanup trap on every
# exit path. Blast radius: one extra TC filter that returns TC_ACT_UNSPEC, so
# it alters the fate of no packet.
#
# Question: when a vendor program holds TC egress preference 1, does a filter
# at preference 2 ever execute? __tcf_classify stops iterating the moment a
# filter returns an action >= 0, so if the vendor returns TC_ACT_OK ours never
# runs -- and the attach still succeeds with no error anywhere.

IF=${FLUX_Q10_IF:-wlan0}
EGRESS=ffff:fff3
PREF=2
OBJ=/data/local/tmp/q10_probe.o
PIN=/sys/fs/bpf/q10_probe
PROBE_SECONDS=8

pinned=0
attached=0

cleanup() {
	echo
	echo "########## cleanup"
	if [ "$attached" = 1 ]; then
		tc filter del dev "$IF" parent "$EGRESS" pref "$PREF" 2>&1 | sed 's/^/  /'
		echo "  detached pref $PREF"
	fi
	if [ "$pinned" = 1 ]; then
		rm -f "$PIN" && echo "  unpinned $PIN"
	fi
	echo "--- final state on $IF egress (only the vendor filter should remain)"
	tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'
}
trap cleanup EXIT INT TERM

echo "########## 0. preconditions"
existing=$(tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null)
if [ -z "$existing" ]; then
	echo "  egress chain on $IF is EMPTY"
	echo "  NOTE: without a vendor filter at pref 1 this measures only that"
	echo "        pref $PREF works in isolation, which is the weaker result."
	VENDOR=0
else
	echo "  existing filters:"
	echo "$existing" | sed 's/^/    /'
	if echo "$existing" | grep -q "pref 1 "; then
		echo "  >>> vendor occupies pref 1 -- this is the measurement that matters"
		VENDOR=1
	else
		VENDOR=0
	fi
fi

echo
echo "########## 1. load the probe"
[ -f "$OBJ" ] || { echo "  ABORT: $OBJ not pushed"; exit 1; }
rm -f "$PIN" 2>/dev/null
if bpftool prog load "$OBJ" "$PIN" 2>&1 | sed 's/^/  /'; then
	:
fi
if [ ! -e "$PIN" ]; then
	echo "  ABORT: prog load failed"
	exit 1
fi
pinned=1
echo "  loaded and pinned"
bpftool prog show pinned "$PIN" 2>&1 | sed 's/^/  /'

echo
echo "########## 2. attach at pref $PREF"
# `protocol all` is mandatory: omitting it yields "RTNETLINK answers: Invalid
# argument" because the kernel gets protocol 0. And `pinned` is the only usable
# form here -- `bpf da obj <file>` fails with "No ELF library support compiled
# in", since Android's tc is built without libbpf. So a loader of our own is not
# a preference, it is the only option (blueprint section 12.8).
tc filter add dev "$IF" parent "$EGRESS" pref "$PREF" protocol all \
	bpf da pinned "$PIN" 2>&1 | sed 's/^/  /'
if tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref $PREF "; then
	attached=1
	echo "  attached"
	tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'
else
	echo "  ABORT: filter did not appear"
	exit 1
fi

echo
echo "########## 3. measure"
mapid=$(bpftool prog show pinned "$PIN" 2>/dev/null | grep -oE 'map_ids [0-9]+' | grep -oE '[0-9]+')
echo "  counter map id: ${mapid:-unknown}"
tx0=$(cat "/sys/class/net/$IF/statistics/tx_packets" 2>/dev/null)
echo "  tx_packets before: $tx0"
echo "  generating traffic for ${PROBE_SECONDS}s ..."
ping -c "$PROBE_SECONDS" -i 1 -W 1 223.5.5.5 >/dev/null 2>&1 &
sleep "$PROBE_SECONDS"
wait 2>/dev/null
tx1=$(cat "/sys/class/net/$IF/statistics/tx_packets" 2>/dev/null)
echo "  tx_packets after:  $tx1  (delta $((tx1 - tx0)))"
echo "  counter:"
[ -n "$mapid" ] && bpftool map dump id "$mapid" 2>&1 | sed 's/^/    /'

echo
echo "########## 4. verdict"
total=0
if [ -n "$mapid" ]; then
	# Sum the per-CPU values. bpftool prints one "value" line per CPU.
	total=$(bpftool map dump id "$mapid" 2>/dev/null |
		grep -oE '"value": *[0-9]+' | grep -oE '[0-9]+' |
		awk '{s+=$1} END {print s+0}')
	[ -z "$total" ] && total=0
fi
echo "  invocations counted: $total"
echo "  interface tx delta:  $((tx1 - tx0))"
if [ "$total" -gt 0 ]; then
	echo "  VERDICT: pref $PREF IS reached."
	[ "$VENDOR" = 1 ] && echo "           The vendor filter at pref 1 does NOT terminate the chain."
	[ "$VENDOR" = 1 ] && echo "           The clsact design works on this device."
elif [ "$((tx1 - tx0))" -gt 0 ]; then
	echo "  VERDICT: SHADOWED. Traffic left the interface but our program saw none."
	[ "$VENDOR" = 1 ] && echo "           The vendor filter at pref 1 terminates the chain."
	echo "           This is a scope change -- see blueprint section 21."
else
	echo "  VERDICT: inconclusive, no traffic during the window. Retry."
fi
