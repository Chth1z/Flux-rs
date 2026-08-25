#!/system/bin/sh
# Phase 0 Q10 -- does a lower-preference TC filter shadow a higher one?
#
# THIS SCRIPT MODIFIES DEVICE STATE. It is the only Phase 0 tool that does.
# Everything it installs is removed by the cleanup trap on every exit path,
# including Ctrl-C and unexpected failure.
#
# WHAT IT MEASURES
#   The design attaches at TC egress and returns TC_ACT_UNSPEC when it does not
#   take a packet over. On the measured Samsung device a vendor program holds
#   preference 1, so ours has to sit above it -- and __tcf_classify stops
#   iterating the moment a filter returns an action >= 0. If the vendor filter
#   returns TC_ACT_OK, ours never executes and the attach call still succeeds
#   with no error anywhere. That is the failure this script exists to confirm
#   or refute.
#
# HOW, WITHOUT WRITING ANY BPF
#   `tc -s filter show` and `tc -s action show` return nothing on this device's
#   iproute2 (ss171113), so filter-level counters are unavailable. But
#   `tc -s qdisc show` does report the clsact qdisc's drop counter, and a
#   TC_ACT_SHOT at egress bumps exactly that via mini_qdisc_qstats_cpu_drop().
#   So: install a filter that drops traffic to one unroutable test address,
#   generate that traffic, and watch the clsact drop counter.
#
# BLAST RADIUS
#   Only packets addressed to 192.0.2.1 (RFC 5737 TEST-NET-1, not routable on
#   the public internet) are dropped, and only while the script runs. The
#   preference-1 filters it installs return TC_ACT_OK or TC_ACT_UNSPEC, neither
#   of which drops or alters anything.
#
# Usage: adb shell 'su -c "sh /data/local/tmp/q10.sh"'

IF=${FLUX_Q10_IF:-wlan0}
EGRESS=ffff:fff3
TEST_DST=192.0.2.1
PROBE_COUNT=5

installed_p1=0
installed_p2=0

cleanup() {
	echo
	echo "########## cleanup"
	if [ "$installed_p2" = 1 ]; then
		tc filter del dev "$IF" parent "$EGRESS" pref 2 2>&1 | sed 's/^/  /'
		echo "  removed pref 2"
	fi
	if [ "$installed_p1" = 1 ]; then
		tc filter del dev "$IF" parent "$EGRESS" pref 1 2>&1 | sed 's/^/  /'
		echo "  removed pref 1"
	fi
	echo "--- final filter state on $IF egress (must be empty or vendor-only)"
	tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'
	echo "  (nothing of ours must remain)"
}
trap cleanup EXIT INT TERM

# clsact drop counter for this interface.
drops() {
	tc -s qdisc show dev "$IF" 2>/dev/null |
		awk '/qdisc clsact/{f=1;next} f&&/dropped/{gsub(/[(),]/,"");for(i=1;i<=NF;i++)if($i=="dropped")print $(i+1);exit}'
}

probe() {
	# Generates egress packets addressed to TEST_DST. Return value ignored:
	# the address is unroutable, so failure is the expected outcome either way.
	ping -c "$PROBE_COUNT" -W 1 "$TEST_DST" >/dev/null 2>&1
}

report() {
	printf "  %-46s %s\n" "$1" "$2"
}

echo "########## 0. preconditions"
echo "interface: $IF"
if [ ! -d "/sys/class/net/$IF" ]; then
	echo "  ABORT: no such interface"
	exit 1
fi
if ! tc qdisc show dev "$IF" 2>/dev/null | grep -q clsact; then
	echo "  ABORT: no clsact on $IF -- netd only creates it while the interface is on a network"
	exit 1
fi
existing=$(tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null)
if [ -n "$existing" ]; then
	echo "  vendor/other filters already present:"
	echo "$existing" | sed 's/^/    /'
	if echo "$existing" | grep -q "pref 1 "; then
		echo "  NOTE: preference 1 is occupied. Skipping the synthetic pref-1 cases"
		echo "        and testing against the REAL occupant instead -- that is the"
		echo "        more valuable measurement."
		REAL_OCCUPANT=1
	fi
else
	echo "  egress chain is empty"
	REAL_OCCUPANT=0
fi
echo "  clsact drops at start: $(drops)"
echo "  tx_packets at start:   $(cat "/sys/class/net/$IF/statistics/tx_packets")"

# ---------------------------------------------------------------------------
echo
echo "########## 1. control: is preference 2 reachable with nothing below it?"
echo "installing: pref 2, u32 match ip dst $TEST_DST, action drop"
if [ "$REAL_OCCUPANT" = 1 ]; then
	echo "  (a real occupant holds pref 1, so this doubles as the vendor test)"
fi
tc filter add dev "$IF" parent "$EGRESS" pref 2 protocol ip \
	u32 match ip dst "$TEST_DST"/32 action drop 2>&1 | sed 's/^/  /'
if tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref 2 "; then
	installed_p2=1
	echo "  installed"
else
	echo "  ABORT: pref 2 filter did not appear"
	exit 1
fi

before=$(drops)
probe
sleep 1
after=$(drops)
report "clsact drops before / after" "$before / $after"
delta_control=$((after - before))
report "delta" "$delta_control"
if [ "$delta_control" -gt 0 ]; then
	report "VERDICT" "preference 2 IS reachable"
else
	report "VERDICT" "preference 2 NOT reached (or probe generated no packets)"
	report "sanity: tx_packets now" "$(cat "/sys/class/net/$IF/statistics/tx_packets")"
fi

if [ "$REAL_OCCUPANT" = 1 ]; then
	echo
	echo "########## done -- a real occupant was present, so cases 2 and 3 are skipped"
	echo "This is the answer that matters: with the vendor filter at preference 1,"
	echo "a filter at preference 2 was $([ "$delta_control" -gt 0 ] && echo REACHED || echo SHADOWED)."
	exit 0
fi

# ---------------------------------------------------------------------------
echo
echo "########## 2. does TC_ACT_OK at preference 1 shadow preference 2?"
echo "installing: pref 1, matchall, action pass   (action pass == TC_ACT_OK)"
tc filter add dev "$IF" parent "$EGRESS" pref 1 protocol all \
	matchall action pass 2>&1 | sed 's/^/  /'
if tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref 1 "; then
	installed_p1=1
	echo "  installed"
else
	echo "  WARN: pref 1 filter did not appear; skipping this case"
fi

if [ "$installed_p1" = 1 ]; then
	before=$(drops)
	probe
	sleep 1
	after=$(drops)
	delta_ok=$((after - before))
	report "clsact drops before / after" "$before / $after"
	report "delta" "$delta_ok"
	if [ "$delta_ok" -gt 0 ]; then
		report "VERDICT" "TC_ACT_OK does NOT shadow -- chain continued"
	else
		report "VERDICT" "TC_ACT_OK SHADOWS preference 2 (expected from kernel source)"
	fi
fi

# ---------------------------------------------------------------------------
echo
echo "########## 3. does TC_ACT_UNSPEC at preference 1 let the chain continue?"
if [ "$installed_p1" = 1 ]; then
	tc filter del dev "$IF" parent "$EGRESS" pref 1 2>/dev/null
	installed_p1=0
fi
echo "installing: pref 1, matchall, action continue   (== TC_ACT_UNSPEC)"
tc filter add dev "$IF" parent "$EGRESS" pref 1 protocol all \
	matchall action continue 2>&1 | sed 's/^/  /'
if tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref 1 "; then
	installed_p1=1
	before=$(drops)
	probe
	sleep 1
	after=$(drops)
	delta_unspec=$((after - before))
	report "clsact drops before / after" "$before / $after"
	report "delta" "$delta_unspec"
	if [ "$delta_unspec" -gt 0 ]; then
		report "VERDICT" "TC_ACT_UNSPEC lets the chain continue -- as designed"
	else
		report "VERDICT" "UNEXPECTED: even TC_ACT_UNSPEC did not continue"
	fi
fi

# ---------------------------------------------------------------------------
echo
echo "########## 4. does a direct-action filter print 'direct-action'?"
echo "Establishes whether the ABSENCE of that string in the vendor's"
echo "'tc filter show' output is meaningful on this iproute2 build."
tc filter show dev "$IF" parent "$EGRESS" 2>&1 | sed 's/^/  /'

echo
echo "########## summary"
report "pref 2 reachable with empty chain" "${delta_control:-n/a}"
report "pref 2 reachable under TC_ACT_OK" "${delta_ok:-skipped}"
report "pref 2 reachable under TC_ACT_UNSPEC" "${delta_unspec:-skipped}"
