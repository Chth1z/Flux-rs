#!/system/bin/sh
# Phase 0 Q6 observational half, plus the veth lifecycle from sections 8.4/8.7.
#
# Two things are answered here without an engine or a data plane:
#
#   1. What is on the egress side of the real interfaces, and which OEM firewall
#      chains exist that could drop packets we deliver locally. box4magisk ships
#      an oneplus_a16_fix() that flushes fw_INPUT/fw_OUTPUT to make TProxy work
#      (box.service:72-79), so at least one OEM's filter chains do kill this
#      kind of traffic. Knowing what is present here is the prerequisite to
#      answering whether ours would survive.
#
#   2. Whether the veth pair and the sysctls section 8.4 depends on can actually
#      be created and set on a real device, and whether they leave anything
#      behind when removed. Section 8.7 claims delete-then-recreate reaches a
#      determined state; this checks the delete half for real.
#
# Everything created is torn down by the cleanup trap. No addresses and no
# routes are configured, so the pair is inert while it exists.
#
# Addresses and MACs are redacted: the shape of the configuration is the
# evidence, the values are the user's.

V0=flxrs0
V1=flxrs1
created=0

redact() {
	sed -E \
		-e 's/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/MAC/g' \
		-e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/IPV4/g' \
		-e 's/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/IPV6/g'
}

cleanup() {
	echo
	echo "########## cleanup"
	if [ "$created" = 1 ]; then
		ip link del "$V0" 2>&1 | sed 's/^/  /'
		echo "  deleted $V0 (and $V1 with it -- deleting one end removes both)"
	fi
	echo "  residue check:"
	for n in "$V0" "$V1"; do
		if [ -d "/sys/class/net/$n" ]; then
			echo "    STILL PRESENT: $n   <-- leak"
		else
			echo "    gone: $n"
		fi
	done
	echo "  ip rule / route entries mentioning flxrs:"
	{ ip rule show; ip route show table all; ip -6 rule show; } 2>/dev/null |
		grep -c flxrs | sed 's/^/    matches: /'
}
trap cleanup EXIT INT TERM

echo "########## 0. kernel"
echo "  $(uname -r)"

echo
echo "########## 1. egress side of the real interfaces"
echo "  (no prior art exists for this: asteriskd only ever inspected the"
echo "   INGRESS of a hotspot interface, so nobody has published what sits on"
echo "   the egress of a physical Android interface)"
for d in /sys/class/net/*; do
	n=$(basename "$d")
	case "$n" in lo | flxrs*) continue ;; esac
	tc qdisc show dev "$n" 2>/dev/null | grep -q clsact || continue
	echo
	echo "  --- $n (type $(cat "$d/type"), state $(cat "$d/operstate" 2>/dev/null))"
	echo "      egress:"
	tc filter show dev "$n" parent ffff:fff3 2>/dev/null | redact | sed 's/^/        /'
	echo "      ingress:"
	tc filter show dev "$n" parent ffff:fff2 2>/dev/null | redact | sed 's/^/        /'
done

echo
echo "########## 2. filter table: which chains could drop a locally delivered packet"
for cmd in iptables ip6tables; do
	command -v "$cmd" >/dev/null 2>&1 || continue
	echo
	echo "  --- $cmd -t filter, chains and policies"
	"$cmd" -t filter -L -n 2>/dev/null | grep -E '^Chain' | sed 's/^/      /'
done

echo
echo "  --- chains whose names look OEM-specific"
echo "      (fw_*, oem_*, oplus_*, miui_*, sem*, knox*, and anything else that"
echo "       is not an AOSP bw_/fw_/idletimer_/natctrl_/oem_ standard chain)"
for cmd in iptables ip6tables; do
	command -v "$cmd" >/dev/null 2>&1 || continue
	"$cmd" -t filter -L -n 2>/dev/null | grep -E '^Chain' |
		grep -iE 'oplus|miui|sem|knox|vivo|oppo|huawei|honor|xiaomi|samsung' |
		sed "s/^/      $cmd: /"
done
echo "      (empty above means no vendor-named chains in the filter table)"

echo
echo "  --- INPUT chain in full, with counters"
echo "      This is the chain that decides the fate of a packet we deliver to"
echo "      the engine. AndroidTProxyShell never opens a hole here and still"
echo "      works (tproxy.sh:968 touches only mangle), which is the reason to"
echo "      expect AOSP's default to accept -- but its packets arrive on lo and"
echo "      ours arrive on flxrs1, and a '-i lo' shortcut would hide the"
echo "      difference. Look for one."
for cmd in iptables ip6tables; do
	command -v "$cmd" >/dev/null 2>&1 || continue
	echo
	echo "      --- $cmd INPUT"
	"$cmd" -t filter -L INPUT -v -n 2>/dev/null | redact | sed 's/^/        /'
done

echo
echo "########## 3. sysctl starting point for section 8.4"
printf '  %-34s %s\n' "net.ipv4.conf.all.rp_filter" "$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null)"
printf '  %-34s %s\n' "net.ipv4.conf.default.rp_filter" "$(cat /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null)"
printf '  %-34s %s\n' "net.ipv4.ip_forward" "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
printf '  %-34s %s\n' "net.ipv4.conf.all.arp_filter" "$(cat /proc/sys/net/ipv4/conf/all/arp_filter 2>/dev/null)"
printf '  %-34s %s\n' "net.ipv4.conf.all.accept_local" "$(cat /proc/sys/net/ipv4/conf/all/accept_local 2>/dev/null)"
echo "  Design requires all.rp_filter == 0. If it is not, section 8.4 says fail"
echo "  activation with a diagnostic rather than changing a global setting."

echo
echo "########## 4. veth lifecycle"
ip link add "$V0" type veth peer name "$V1" 2>&1 | sed 's/^/  /'
if [ ! -d "/sys/class/net/$V0" ]; then
	echo "  ABORT: could not create the pair"
	exit 1
fi
created=1
echo "  created $V0 <-> $V1"
ip link show "$V0" 2>/dev/null | redact | sed 's/^/    /'
ip link show "$V1" 2>/dev/null | redact | sed 's/^/    /'

echo
echo "  per-interface sysctls the design needs on the peer:"
for kv in "rp_filter=0" "accept_local=1"; do
	k=${kv%%=*}
	v=${kv#*=}
	p="/proc/sys/net/ipv4/conf/$V1/$k"
	if [ -w "$p" ]; then
		echo "$v" >"$p" 2>/dev/null
		echo "    $k -> $(cat "$p" 2>/dev/null)  (wanted $v)"
	else
		echo "    $k NOT WRITABLE at $p"
	fi
done

echo
echo "  can a clsact be attached to the peer?"
tc qdisc add dev "$V1" clsact 2>&1 | sed 's/^/    /'
tc qdisc show dev "$V1" 2>/dev/null | sed 's/^/    /'

echo
echo "  did anything in the system react to a new interface appearing?"
echo "    (netd logs an interface add; a reaction that reconfigures or removes"
echo "     our objects would be a problem for section 8.7)"
if command -v logcat >/dev/null 2>&1; then
	logcat -d -t 200 2>/dev/null | grep -iE 'flxrs' | tail -10 |
		redact | sed 's/^/      /'
	echo "      (empty means nothing mentioned flxrs at all)"
fi

echo
echo "  bringing both ends up:"
ip link set "$V0" up 2>&1 | sed 's/^/    /'
ip link set "$V1" up 2>&1 | sed 's/^/    /'
for n in "$V0" "$V1"; do
	printf '    %-8s operstate=%s\n' "$n" "$(cat /sys/class/net/$n/operstate)"
done
