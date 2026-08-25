#!/system/bin/sh
# Phase 0 Q1 on the real baseline -- SK_STORAGE first-decision.
#
# MODIFIES DEVICE STATE, all removed by the cleanup trap on every exit path.
# The program returns TC_ACT_UNSPEC on every path, so it changes the fate of no
# packet; the only footprint is one extra TC filter and one pin.
#
# This run IS authoritative: the device is on 5.15, the product baseline. The
# netns variant (q1-run.sh) is the rehearsal for a dev host.
#
# What makes the result decisive without knowing the exact socket count: if
# SEEN greatly exceeds CREATED while CORRUPT stays zero, then a decision was
# made once per socket and every later packet found it unchanged. That is
# exactly first-decision-wins plus immutability.

IF=${FLUX_Q1_IF:-wlan0}
EGRESS=ffff:fff3
PREF=2
OBJ=/data/local/tmp/q1_probe.o
PIN=/sys/fs/bpf/q1_probe
WINDOW=${1:-20}

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
	echo "--- residue on $IF egress (vendor filters may legitimately remain)"
	tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'
}
trap cleanup EXIT INT TERM

fail() {
	echo "  ABORT: $*"
	exit 1
}

echo "########## 0. environment"
echo "  kernel: $(uname -r)"
case "$(uname -r)" in
5.15.*) echo "  ON THE PRODUCT BASELINE -- this result is authoritative" ;;
*) echo "  NOT 5.15 -- treat as rehearsal" ;;
esac
[ -f "$OBJ" ] || fail "$OBJ not pushed"
[ -d "/sys/class/net/$IF" ] || fail "no interface $IF"
tc qdisc show dev "$IF" 2>/dev/null | grep -q clsact ||
	fail "no clsact on $IF -- netd only creates it while the interface is on a network"

echo "  traffic tools:"
for t in curl wget nc ping; do
	p=$(command -v "$t" 2>/dev/null)
	printf '    %-6s %s\n' "$t" "${p:-MISSING}"
done

echo
echo "########## 1. load"
rm -f "$PIN" 2>/dev/null
bpftool prog load "$OBJ" "$PIN" 2>&1 | sed 's/^/  /'
[ -e "$PIN" ] || fail "verifier rejected the program -- THIS IS THE Q1 ANSWER, and it is a failure"
pinned=1
bpftool prog show pinned "$PIN" 2>&1 | sed 's/^/  /'
echo "  >>> the verifier ACCEPTED bpf_sk_storage_get() on bpf_sk_fullsock(skb->sk)"
echo "      at TC egress, with a BTF-defined SK_STORAGE map. That is Q1's core question."

echo
echo "########## 2. attach at pref $PREF"
tc filter add dev "$IF" parent "$EGRESS" pref "$PREF" protocol all \
	bpf da pinned "$PIN" 2>&1 | sed 's/^/  /'
tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref $PREF " ||
	fail "filter did not appear"
attached=1
tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'

# Resolve the counters map by name among the program's maps.
ids=$(bpftool prog show pinned "$PIN" 2>/dev/null | grep -oE 'map_ids [0-9,]+' | grep -oE '[0-9,]+')
mapid=""
for m in $(echo "$ids" | tr ',' ' '); do
	if bpftool map show id "$m" 2>/dev/null | grep -q 'q1_counters'; then
		mapid="$m"
		break
	fi
done
[ -n "$mapid" ] || fail "cannot locate the q1_counters map"
echo "  counters map id: $mapid"

slot() {
	k=$(printf '%02x 00 00 00' "$1")
	bpftool map lookup id "$mapid" key hex $k 2>/dev/null |
		grep -oE '"value": *[0-9]+' | grep -oE '[0-9]+' |
		awk '{s+=$1} END {print s+0}'
}

echo
echo "########## 3. generate traffic for ${WINDOW}s"
tx0=$(cat "/sys/class/net/$IF/statistics/tx_packets")
# Ambient phone traffic plus deliberate TCP connects. Several distinct
# destinations so multiple sockets are created rather than one reused.
i=0
while [ "$i" -lt 8 ]; do
	if command -v curl >/dev/null 2>&1; then
		curl -s -m 4 -o /dev/null "http://connectivitycheck.gstatic.com/generate_204" &
	elif command -v wget >/dev/null 2>&1; then
		wget -q -T 4 -O /dev/null "http://connectivitycheck.gstatic.com/generate_204" &
	fi
	i=$((i + 1))
done
ping -c "$WINDOW" -i 1 -W 1 223.5.5.5 >/dev/null 2>&1 &
sleep "$WINDOW"
wait 2>/dev/null
tx1=$(cat "/sys/class/net/$IF/statistics/tx_packets")

echo
echo "########## 4. counters"
seen=$(slot 0)
created=$(slot 1)
loser=$(slot 2)
allocfail=$(slot 3)
corrupt=$(slot 4)
nofull=$(slot 5)
nottcp=$(slot 6)
printf '  %-22s %s\n' "SEEN (existing)" "$seen"
printf '  %-22s %s\n' "CREATED (first)" "$created"
printf '  %-22s %s\n' "RACE_LOSER" "$loser"
printf '  %-22s %s\n' "ALLOC_FAIL" "$allocfail"
printf '  %-22s %s\n' "CORRUPT" "$corrupt"
printf '  %-22s %s\n' "NO_FULLSOCK" "$nofull"
printf '  %-22s %s\n' "NOT_TCP" "$nottcp"
printf '  %-22s %s\n' "interface tx delta" "$((tx1 - tx0))"

echo
echo "########## 5. verdict"
ok=1
[ "$corrupt" != 0 ] && { echo "  FAIL: stored value mutated or corrupted ($corrupt)"; ok=0; }
[ "$allocfail" != 0 ] && { echo "  FAIL: F_CREATE returned NULL $allocfail times"; ok=0; }
decisions=$((created + loser))
if [ "$decisions" = 0 ]; then
	echo "  INCONCLUSIVE: no first decisions recorded."
	if [ "$((tx1 - tx0))" -gt 0 ]; then
		echo "               tx moved, so either nothing TCP left this interface,"
		echo "               or the filter is shadowed (see Q10 / section 8.5.4)."
	else
		echo "               no traffic at all during the window."
	fi
	ok=0
fi
if [ "$ok" = 1 ]; then
	echo "  PASS on the 5.15 baseline:"
	echo "    - verifier accepts the real E1/E2/E3 shape"
	echo "    - $decisions first decisions, $seen later packets found one already there"
	echo "    - zero corruption, zero allocation failure"
	if [ "$seen" -gt "$decisions" ] 2>/dev/null; then
		echo "    - SEEN > first decisions, so a decision is made once per socket"
		echo "      and every later packet reuses it unchanged"
	fi
	[ "$loser" -gt 0 ] 2>/dev/null &&
		echo "    - $loser concurrent losers took the winner's value, which is"
		echo "      first-decision-wins behaving as designed under contention"
fi
