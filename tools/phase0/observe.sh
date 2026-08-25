#!/system/bin/sh
# Flux-rs Phase 0 -- observation probe. STRICTLY READ ONLY.
#
# Answers "what is this device actually like" for every assumption the design
# makes about Android. Writes nothing, loads nothing, attaches nothing: every
# command either reads a file or asks the kernel to describe existing state.
#
# Usage:
#   adb push tools/phase0/observe.sh /data/local/tmp/
#   adb shell 'su -c "sh /data/local/tmp/observe.sh"' > result.txt
#
# Output is REDACTED by default: host portions of addresses, MAC addresses and
# NFLOG cookies are masked, because the analytical value is in whether an
# address exists and what scope it has, never in its value. Set
# FLUX_PROBE_RAW=1 to disable redaction; never commit unredacted output.
#
# Each section names the blueprint section it exists to verify. Keep that
# mapping current: a probe whose findings cannot be traced to a design claim is
# just noise.

sec() { echo; echo "########## $1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------- output
# Redaction runs as a filter over the whole script's stdout. MAC first, because
# a MAC also matches the IPv6 shape; both are identifying, so either masking is
# acceptable, but doing MAC first keeps the output readable.
redact() {
	if [ "$FLUX_PROBE_RAW" = "1" ]; then
		cat
		return
	fi
	# No \b anywhere: toybox sed -E does not implement word boundaries, and it
	# fails SILENTLY -- the substitution simply never fires. That is how an
	# IPv4 address leaked into a committed result file once. Always audit the
	# output before publishing it.
	sed -E \
		-e 's/([0-9a-f]{2}:){5}[0-9a-f]{2}/MAC:redacted/g' \
		-e 's/([0-9a-f]{1,4}:[0-9a-f]{1,4}):[0-9a-f:]{4,}/\1:redacted/g' \
		-e 's/([0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.x.x/g' \
		-e 's/"[0-9]{6,}:/"cookie:redacted:/g'
}

main() {

	sec "0. context"
	echo "probe_version: 1"
	echo "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
	echo "uptime_s: $(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
	echo "id: $(id)"
	echo "selinux: $(getenforce 2>/dev/null)"
	echo "kernel: $(uname -r)"
	echo "pagesize: $(getconf PAGESIZE)"
	# Serial is deliberately never read.
	for p in ro.build.version.release ro.build.version.sdk \
		ro.build.version.security_patch ro.product.cpu.abi \
		ro.soc.manufacturer ro.soc.model ro.board.platform ro.product.model; do
		echo "$p: $(getprop $p)"
	done
	echo "root_manager: $([ "$KSU" = true ] && echo kernelsu || { [ "$APATCH" = true ] && echo apatch || echo magisk-or-unknown; })"

	# ------------------------------------------------- blueprint section 4
	sec "1. kernel config (blueprint section 4)"
	CFG=""
	if [ -f /proc/config.gz ]; then
		CFG=$(zcat /proc/config.gz 2>/dev/null)
		echo "source: /proc/config.gz"
	elif [ -f /proc/config ]; then
		CFG=$(cat /proc/config)
		echo "source: /proc/config"
	else
		echo "source: ABSENT"
	fi
	if [ -n "$CFG" ]; then
		for k in CONFIG_VETH CONFIG_DUMMY CONFIG_TUN CONFIG_NETKIT \
			CONFIG_NET_SCH_INGRESS CONFIG_NET_CLS_BPF CONFIG_NET_CLS_ACT \
			CONFIG_NET_ACT_BPF CONFIG_NET_ACT_MIRRED \
			CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_BPF_JIT_ALWAYS_ON \
			CONFIG_CGROUP_BPF CONFIG_DEBUG_INFO_BTF CONFIG_DEBUG_INFO_BTF_MODULES \
			CONFIG_IP_ADVANCED_ROUTER CONFIG_IP_MULTIPLE_TABLES \
			CONFIG_NF_CONNTRACK CONFIG_NETFILTER_XT_TARGET_TPROXY \
			CONFIG_NETFILTER_XT_MATCH_SOCKET CONFIG_NAMESPACES CONFIG_NET_NS; do
			v=$(echo "$CFG" | grep -E "^$k=" | head -1)
			[ -z "$v" ] && v=$(echo "$CFG" | grep -E "^# $k is not set" | head -1)
			[ -z "$v" ] && v="$k ABSENT"
			echo "  $v"
		done
	fi

	# ------------------------------- blueprint D10, section 12 (SK_STORAGE)
	sec "2. BTF availability"
	if [ -r /sys/kernel/btf/vmlinux ]; then
		echo "/sys/kernel/btf/vmlinux bytes=$(wc -c </sys/kernel/btf/vmlinux)"
	else
		echo "/sys/kernel/btf/vmlinux ABSENT or unreadable -- SK_STORAGE map creation will fail"
	fi

	# ------------------------------------------------- blueprint section 8.4
	sec "3. sysctls that decide whether the veth return path works"
	for f in /proc/sys/net/ipv4/conf/all/rp_filter \
		/proc/sys/net/ipv4/conf/default/rp_filter \
		/proc/sys/net/ipv4/conf/all/accept_local \
		/proc/sys/net/ipv4/conf/all/arp_filter \
		/proc/sys/net/ipv4/conf/all/route_localnet \
		/proc/sys/net/ipv4/conf/all/src_valid_mark \
		/proc/sys/net/ipv4/ip_forward \
		/proc/sys/net/ipv6/conf/all/forwarding \
		/proc/sys/net/ipv4/ip_local_port_range \
		/proc/sys/net/core/bpf_jit_enable \
		/proc/sys/net/core/bpf_jit_harden \
		/proc/sys/kernel/unprivileged_bpf_disabled; do
		[ -r "$f" ] && echo "  $f = $(cat "$f" 2>/dev/null)" || echo "  $f = UNREADABLE"
	done
	echo "--- any interface with a NON-ZERO rp_filter or non-default accept_local?"
	for d in /proc/sys/net/ipv4/conf/*/; do
		n=$(basename "$d")
		r=$(cat "$d/rp_filter" 2>/dev/null)
		a=$(cat "$d/accept_local" 2>/dev/null)
		[ "$r" != "0" ] || [ "$a" != "0" ] && printf "  %-18s rp_filter=%s accept_local=%s\n" "$n" "$r" "$a"
	done
	echo "  (nothing listed above means every interface is rp_filter=0 accept_local=0)"
	echo "--- sysctl node label (can a module domain write it?)"
	ls -lZ /proc/sys/net/ipv4/conf/all/accept_local 2>/dev/null

	# ----------------------------------------------- blueprint section 3.3.1
	sec "4. link types -- ARPHRD decides the L2 vs L3 egress entry"
	printf "  %-16s %-20s %-8s %s\n" NAME TYPE FLAGS MTU
	for i in /sys/class/net/*/; do
		n=$(basename "$i")
		t=$(cat "$i/type" 2>/dev/null)
		case "$t" in
		1) tn="ARPHRD_ETHER" ;;
		519) tn="ARPHRD_RAWIP" ;;
		65534) tn="ARPHRD_NONE/tun" ;;
		772) tn="ARPHRD_LOOPBACK" ;;
		*) tn="type=$t" ;;
		esac
		printf "  %-16s %-20s %-8s %s\n" "$n" "$tn" "$(cat "$i/flags" 2>/dev/null)" "$(cat "$i/mtu" 2>/dev/null)"
	done
	echo "--- type histogram"
	for i in /sys/class/net/*/; do cat "$i/type" 2>/dev/null; done | sort -n | uniq -c
	echo "--- interfaces carrying a global address (the ones admission would consider)"
	ip -o addr show scope global 2>/dev/null | awk '{print "  "$2"  "$4}'

	# ------------------------------------------------- blueprint section 8.5
	sec "5. qdisc: does clsact exist, and on which interfaces?"
	tc qdisc show 2>/dev/null | grep -E "clsact|ingress" || echo "  no clsact anywhere"
	echo "--- interfaces WITH clsact"
	tc qdisc show 2>/dev/null | grep clsact | sed -E 's/.*dev ([^ ]+).*/  \1/'

	# ----------------------------------------------- blueprint section 8.5.2
	# Uses explicit clsact parent handles rather than the ingress/egress
	# shorthand. Both work on iproute2-ss171113, but the handles are what the
	# design's ownership predicate actually matches on, so print those.
	#
	# Sampled TWICE with a delay, because a vendor can attach its egress
	# program minutes after the interface carries traffic. Observed on
	# SM-S9180: wlan0 had clsact and a global address but no filter, and
	# semUidBPF's egress program appeared several minutes later. A one-shot
	# conflict check at activation time would have missed it.
	tc_filters() {
		found=0
		for i in /sys/class/net/*/; do
			n=$(basename "$i")
			ig=$(tc filter show dev "$n" parent ffff:fff2 2>/dev/null)
			eg=$(tc filter show dev "$n" parent ffff:fff3 2>/dev/null)
			if [ -n "$ig" ] || [ -n "$eg" ]; then
				found=1
				echo "  --- $n"
				[ -n "$ig" ] && echo "$ig" | sed 's/^/      ingress: /'
				[ -n "$eg" ] && echo "$eg" | sed 's/^/      egress:  /'
			fi
		done
		[ "$found" = 0 ] && echo "  (none on any interface)"
	}
	sec "6. TC filters already attached (the AOSP/vendor priority map, in practice)"
	echo "sample 1:"
	tc_filters
	echo "sample 2, after 20s:"
	sleep 20
	tc_filters
	echo "--- does anything hold OUR reserved triple? chain 0 pref 1 handle 0x1 egress"
	for i in /sys/class/net/*/; do
		n=$(basename "$i")
		tc filter show dev "$n" parent ffff:fff3 2>/dev/null |
			grep -q "pref 1 .*handle 0x1" && echo "  COLLISION on $n egress"
	done
	echo "  (blueprint reserves chain 0 / pref 1 / handle 0x1; see FLUX_TC_* in flux_abi.h)"

	# ------------------------------------------------- blueprint section 8.3
	sec "7. ip rule ladder -- is the 1..9999 window free?"
	echo "--- lowest non-zero priority, v4 and v6"
	ip -4 rule show 2>/dev/null | grep -vE "^0:" | head -1
	ip -6 rule show 2>/dev/null | grep -vE "^0:" | head -1
	echo "--- any rule below 10000 (other than the kernel's local at 0)?"
	ip -4 rule show 2>/dev/null | awk -F: '$1+0>0 && $1+0<10000'
	ip -6 rule show 2>/dev/null | awk -F: '$1+0>0 && $1+0<10000'
	echo "  (nothing listed means 1..9999 is entirely free)"
	echo "--- is our chosen priority 100 taken?"
	echo "  v4 matches: $(ip -4 rule show 2>/dev/null | grep -c '^100:')"
	echo "  v6 matches: $(ip -6 rule show 2>/dev/null | grep -c '^100:')"
	echo "--- is our chosen table 20260 empty?"
	echo "  v4 routes: $(ip -4 route show table 20260 2>/dev/null | wc -l)"
	echo "  v6 routes: $(ip -6 route show table 20260 2>/dev/null | wc -l)"
	echo "--- full v4 ladder (for the record)"
	ip -4 rule show 2>/dev/null | sed 's/^/  /'

	# ------------------------------------------------- blueprint section 3.1
	sec "8. fwmark bits actually in use"
	echo "--- distinct masks in iptables mangle"
	{ iptables -t mangle -S 2>/dev/null; ip6tables -t mangle -S 2>/dev/null; } |
		grep -oE "0x[0-9a-f]+/0x[0-9a-f]+" | sort -u | sed 's/^/  /'
	echo "--- rules that zero the whole mark (would destroy any mark-based design)"
	{ iptables -t mangle -S 2>/dev/null; ip6tables -t mangle -S 2>/dev/null; } |
		grep -E "set-xmark 0x0/0xffffffff" | sed 's/^/  /'

	# --------------------------------------------- blueprint section 0.1 item 2
	sec "9. cgroup BPF occupancy -- is any SOCK_ADDR slot actually attached?"
	echo "cgroup2 mount: $(grep cgroup2 /proc/mounts 2>/dev/null | head -1)"
	if have bpftool; then
		echo "--- attachments at the v2 root"
		bpftool cgroup show /sys/fs/cgroup 2>&1 | sed 's/^/  /'
		echo "--- full tree walk"
		bpftool cgroup tree /sys/fs/cgroup 2>&1 | sed 's/^/  /' | head -30
		echo "--- depth-1 children, each checked individually"
		for p in /sys/fs/cgroup/*/; do
			[ -d "$p" ] || continue
			out=$(bpftool cgroup show "$p" 2>/dev/null | grep -vE "^ID|^$")
			[ -n "$out" ] && echo "  == $p" && echo "$out" | sed 's/^/    /'
		done
		echo "  (no == lines above means no descendant holds an attachment either)"
	else
		echo "bpftool ABSENT -- cannot settle occupancy here"
	fi

	sec "10. loaded BPF programs by type (loaded is not the same as attached)"
	if have bpftool; then
		bpftool prog show 2>/dev/null | grep -oE "^[0-9]+: [a-z_]+" |
			awk '{print $2}' | sort | uniq -c | sort -rn | sed 's/^/  /'
		echo "--- where is anything attached? (xdp / tc / flow_dissector / netfilter)"
		bpftool net show 2>&1 | sed 's/^/  /'
		echo "--- pin counts"
		echo "  prog pins: $(find /sys/fs/bpf -name 'prog_*' 2>/dev/null | wc -l)"
		echo "  map pins:  $(find /sys/fs/bpf -name 'map_*' 2>/dev/null | wc -l)"
		echo "--- vendor BPF families present (prefix before the first underscore group)"
		ls /sys/fs/bpf/ 2>/dev/null | grep -E "^(map|prog)_" |
			sed -E 's/^(map|prog)_([A-Za-z]+).*/  \2/' | sort -u
	fi

	# ------------------------------------------------- blueprint section 1.3
	sec "11. DNS posture"
	echo "private_dns_mode: $(settings get global private_dns_mode 2>/dev/null)"
	echo "private_dns_specifier: $(settings get global private_dns_specifier 2>/dev/null)"

	# --------------------------------------------------- blueprint D8
	sec "12. packages.list shape"
	if [ -r /data/system/packages.list ]; then
		echo "readable, lines=$(wc -l </data/system/packages.list)"
		echo "fields on first line: $(head -1 /data/system/packages.list | awk '{print NF}')"
		echo "uid column min/max: $(awk '{print $2}' /data/system/packages.list | sort -n | sed -n '1p;$p' | tr '\n' ' ')"
		echo "count inside the app range 10000..19999: $(awk '$2>=10000 && $2<=19999' /data/system/packages.list | wc -l)"
	else
		echo "UNREADABLE"
	fi

	# ----------------------------------------------- leftover / conflict check
	sec "13. conflicting or leftover state"
	for d in /data/adb/flux /data/adb/flux-rs /sys/fs/bpf/flux /sys/fs/bpf/flux-rs; do
		[ -e "$d" ] && echo "  PRESENT: $d" || echo "  absent:  $d"
	done
	echo "--- installed root modules"
	ls /data/adb/modules/ 2>/dev/null | sed 's/^/  /'
	echo "--- other proxies running?"
	ps -A -o NAME 2>/dev/null | grep -iE "sing|clash|xray|v2ray|tun2socks|hysteria" | sort -u | sed 's/^/  /'
	echo "--- veth or dummy interfaces already present?"
	ip -o link show type veth 2>/dev/null | sed 's/^/  /'
	echo "--- names colliding with ours?"
	for n in flxrs0 flxrs1; do
		ip link show "$n" >/dev/null 2>&1 && echo "  COLLISION: $n exists" || echo "  free: $n"
	done

	sec "14. limits relevant to BPF"
	echo "memlock_rlimit_kb: $(ulimit -l 2>/dev/null)"
	echo "note: kernel >= 5.11 accounts BPF memory to memcg, so memlock should not bind"
	echo "nr_open: $(cat /proc/sys/fs/nr_open 2>/dev/null)"
	echo "nproc: $(nproc 2>/dev/null)"

	sec "done"
}

main 2>&1 | redact
