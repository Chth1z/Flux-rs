#!/system/bin/sh
# Q10 pre-flight: can this device answer the question at all? READ ONLY.
#
# Q10 asks whether a TC filter at a preference above a vendor's is ever
# reached. The cheapest way to answer it needs no BPF: attach a `matchall`
# classifier with `action continue` (which is literally TC_ACT_UNSPEC, so it
# changes no packet's fate) and read the action's packet counter.
#
# That plan only works if three things hold, and this script checks them
# without touching anything.

echo "########## 1. classifier and action support in the kernel"
for k in CONFIG_NET_CLS_MATCHALL CONFIG_NET_CLS_U32 CONFIG_NET_CLS_BASIC \
	CONFIG_NET_ACT_GACT CONFIG_NET_CLS_ACT CONFIG_NET_CLS_BPF; do
	v=$(zcat /proc/config.gz 2>/dev/null | grep -E "^$k=")
	[ -z "$v" ] && v="$k NOT SET"
	echo "  $v"
done

echo
echo "########## 2. does 'tc -s' work AT ALL on this iproute2 build?"
echo "--- tc -s qdisc show dev wlan0 (should print Sent/bytes lines)"
tc -s qdisc show dev wlan0 2>&1 | head -6
echo "--- tc -s class show dev wlan0"
tc -s class show dev wlan0 2>&1 | head -4
echo "--- tc -s filter show dev wlan0 parent ffff:fff3"
tc -s filter show dev wlan0 parent ffff:fff3 2>&1 | head -6
echo "--- tc -s action show action gact"
tc -s action show action gact 2>&1 | head -10
echo "--- tc -s action show action bpf"
tc -s action show action bpf 2>&1 | head -6

echo
echo "########## 3. what does the vendor filter actually return? (indirect evidence)"
echo "--- is it direct-action? (da => return value IS the verdict)"
tc filter show dev wlan0 parent ffff:fff3 2>&1
echo "--- same, with -d for extra detail"
tc -d filter show dev wlan0 parent ffff:fff3 2>&1
echo "--- the program's own metadata"
bpftool prog show name schedcls_egress 2>&1 | head -12

echo
echo "########## 4. baseline traffic counters (needed to tell 'shadowed' from 'idle')"
for i in wlan0 rmnet_data1 rmnet_data8; do
	[ -d "/sys/class/net/$i" ] || continue
	echo "  $i tx_packets=$(cat /sys/class/net/$i/statistics/tx_packets 2>/dev/null) rx_packets=$(cat /sys/class/net/$i/statistics/rx_packets 2>/dev/null)"
done

echo
echo "########## 5. is preference 2 free on wlan0 egress right now?"
tc filter show dev wlan0 parent ffff:fff3 2>&1 | grep -oE "pref [0-9]+" | sort -u
echo "  (only 'pref 1' above means 2 is free)"

echo
echo "########## done"
