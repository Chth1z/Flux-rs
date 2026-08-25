#!/system/bin/sh
# Phase 0 Q2 -- official sing-box tproxy listener, sk_lookup, and sk_assign.
#
# Runs the PINNED, UNMODIFIED official binary (engine.lock: v1.13.19, both
# digests verified before pushing) with exactly the inbound shape blueprint 9.1
# specifies, then asks the kernel the two questions that the ingress half of the
# design rests on.
#
# State touched, all undone by the cleanup trap: one sing-box process, one veth
# pair, two per-interface sysctls on the peer, one clsact, one TC filter, one
# pin, and files under /data/local/tmp/q2.
#
# The probe drops every packet it sees (TC_ACT_SHOT) and only ever sees packets
# this harness generates on its own veth, so no real traffic is affected.

SB=/data/local/tmp/q2/sing-box
CFG=/data/local/tmp/q2/config.json
LOG=/data/local/tmp/q2/sing-box.log
OBJ=/data/local/tmp/q2/q2_probe.o
PIN=/sys/fs/bpf/q2_probe
PORT=61234
V0=flxrs0
V1=flxrs1

sbpid=""
veth=0
pinned=0
attached=0

cleanup() {
	echo
	echo "########## cleanup"
	if [ -n "$sbpid" ] && kill -0 "$sbpid" 2>/dev/null; then
		kill "$sbpid" 2>/dev/null
		i=0
		while kill -0 "$sbpid" 2>/dev/null && [ "$i" -lt 20 ]; do
			sleep 0.2
			i=$((i + 1))
		done
		kill -9 "$sbpid" 2>/dev/null
		echo "  stopped sing-box (pid $sbpid)"
	fi
	[ "$attached" = 1 ] && tc filter del dev "$V1" parent ffff:fff2 pref 1 2>/dev/null &&
		echo "  detached probe"
	[ "$pinned" = 1 ] && rm -f "$PIN" && echo "  unpinned"
	if [ "$veth" = 1 ]; then
		ip link del "$V0" 2>/dev/null
		echo "  deleted veth pair"
	fi
	for n in "$V0" "$V1"; do
		[ -d "/sys/class/net/$n" ] && echo "    STILL PRESENT: $n  <-- leak"
	done
	echo "  residue: $({ ip rule show; ip route show table all; } 2>/dev/null | grep -c flxrs) flxrs lines in rules/routes"
}
trap cleanup EXIT INT TERM

fail() {
	echo "  ABORT: $*"
	exit 1
}

echo "########## 0. environment"
echo "  kernel: $(uname -r)"
[ -x "$SB" ] || fail "$SB missing or not executable"
echo "  engine: $("$SB" version 2>&1 | head -1)"

echo
echo "########## 1. config, and sing-box's own validation of it"
# Exactly the shape blueprint 9.1 mandates: type/tag/listen/listen_port and
# nothing else. Both families share one port, as 9.1 requires. The outbound is
# direct because no traffic is ever proxied here -- only the listener sockets
# matter.
cat >"$CFG" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    { "type": "tproxy", "tag": "flux-in-v4", "listen": "198.51.100.1", "listen_port": $PORT },
    { "type": "tproxy", "tag": "flux-in-v6", "listen": "2001:db8:0:1::2", "listen_port": $PORT }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
# This is step 1 of blueprint 9.4, run for real.
"$SB" check -c "$CFG" 2>&1 | sed 's/^/  /'
echo "  check exit: $?"

echo
echo "########## 2. start the engine"
"$SB" run -c "$CFG" >"$LOG" 2>&1 &
sbpid=$!
echo "  pid $sbpid"
i=0
while [ "$i" -lt 50 ]; do
	sleep 0.2
	i=$((i + 1))
	ss -lntH 2>/dev/null | grep -q ":$PORT" && break
done
kill -0 "$sbpid" 2>/dev/null || {
	echo "  engine exited immediately, log:"
	sed 's/^/    /' "$LOG"
	fail "engine did not stay up"
}
echo "  waited $((i * 200))ms for the first listener"

echo
echo "########## 3. the four kernel sockets"
echo "  Binding to a non-local address only works because the tproxy inbound"
echo "  sets IP_TRANSPARENT before bind; that is the mechanism blueprint 9.1"
echo "  relies on, and it is being exercised here for real."
echo
found=0
for spec in "tcp -lntH" "udp -lunH"; do
	proto=${spec%% *}
	flags=${spec#* }
	# shellcheck disable=SC2086
	out=$(ss $flags 2>/dev/null | grep ":$PORT")
	echo "  --- $proto"
	[ -z "$out" ] && echo "      NONE" && continue
	echo "$out" | while read -r line; do
		echo "      $line"
	done
	n=$(echo "$out" | grep -c .)
	found=$((found + n))
done

echo
echo "  --- with process and inode, cross-checked against /proc/$sbpid/fd"
for flags in "-lntpe" "-lunpe"; do
	# shellcheck disable=SC2086
	ss $flags 2>/dev/null | grep ":$PORT" | while read -r line; do
		ino=$(echo "$line" | tr ' ' '\n' | grep '^ino:' | cut -d: -f2)
		owner="not found under the engine's fds"
		if [ -n "$ino" ]; then
			for fd in /proc/"$sbpid"/fd/*; do
				t=$(readlink "$fd" 2>/dev/null)
				case "$t" in
				"socket:[$ino]")
					owner="fd $(basename "$fd") of pid $sbpid"
					break
					;;
				esac
			done
		fi
		printf '      ino %-12s %s\n' "${ino:-?}" "$owner"
	done
done

echo
echo "  NOTE on SO_REUSEPORT: ss cannot show it. The authoritative runtime test"
echo "  is bpf_sk_assign() returning 0 in step 6 -- on this kernel a reuseport"
echo "  listener would make it return -ESOCKTNOSUPPORT (-524 is ENOTSUPP, this"
echo "  one is -94). That is why the assign result is the verdict, not ss."

echo
echo "########## 4. veth for the ingress probe"
# bpf_sk_assign() is legal only at TC ingress, and a dedicated veth means the
# probe sees nothing but the packets generated below.
ip link add "$V0" type veth peer name "$V1" 2>&1 | sed 's/^/  /'
[ -d "/sys/class/net/$V0" ] || fail "veth creation failed"
veth=1
# Addresses here are for the harness only. Production keeps the pair
# addressless (blueprint 8.4) because packets arrive by bpf_redirect carrying
# their original tuple, not by routing.
ip addr add 10.99.0.1/24 dev "$V0" 2>&1 | sed 's/^/  /'
ip addr add 10.99.0.2/24 dev "$V1" 2>&1 | sed 's/^/  /'
ip link set "$V0" up
ip link set "$V1" up
echo "0" >/proc/sys/net/ipv4/conf/"$V1"/rp_filter 2>/dev/null
echo "1" >/proc/sys/net/ipv4/conf/"$V1"/accept_local 2>/dev/null
tc qdisc add dev "$V1" clsact 2>&1 | sed 's/^/  /'
echo "  up, rp_filter=$(cat /proc/sys/net/ipv4/conf/$V1/rp_filter), accept_local=$(cat /proc/sys/net/ipv4/conf/$V1/accept_local)"

echo
echo "########## 5. load and attach the probe at $V1 ingress"
rm -f "$PIN" 2>/dev/null
bpftool prog load "$OBJ" "$PIN" 2>&1 | sed 's/^/  /'
[ -e "$PIN" ] || fail "probe did not load -- if the verifier rejected it, that is itself the Q2 answer"
pinned=1
bpftool prog show pinned "$PIN" 2>&1 | sed 's/^/  /'
tc filter add dev "$V1" parent ffff:fff2 pref 1 protocol all \
	bpf da pinned "$PIN" 2>&1 | sed 's/^/  /'
tc filter show dev "$V1" parent ffff:fff2 2>/dev/null | grep -q 'pref 1 ' ||
	fail "probe did not attach"
attached=1
echo "  attached"

mid=""
for m in $(bpftool prog show pinned "$PIN" 2>/dev/null |
	grep -oE 'map_ids [0-9,]+' | grep -oE '[0-9,]+' | tr ',' ' '); do
	bpftool map show id "$m" 2>/dev/null | grep -q q2_out && mid="$m"
done
[ -n "$mid" ] || fail "cannot find q2_out"

echo
echo "########## 6. drive one packet through $V1 ingress"
# Destination is irrelevant: the probe looks the listener up by an explicit
# tuple and assign does not inspect the packet. Any packet arriving at ingress
# is enough, and all of them are dropped by the probe.
ping -c 3 -i 0.3 -W 1 10.99.0.2 >/dev/null 2>&1
sleep 0.5

slot() {
	k=$(printf '%02x %02x 00 00' $(($1 % 256)) $(($1 / 256)))
	bpftool map lookup id "$mid" key hex $k 2>/dev/null |
		grep -oE '"value": *[0-9-]+' | grep -oE '[0-9-]+' | head -1
}

inv=$(slot 24)
echo "  probe invocations: ${inv:-0}"
[ "${inv:-0}" = 0 ] && fail "the probe never ran; no packet reached $V1 ingress"

echo
echo "########## 7. what the kernel returned"
i=0
for name in "v4 TCP" "v4 UDP" "v6 TCP" "v6 UDP"; do
	base=$((i * 6))
	f=$(slot $((base + 0)))
	echo
	echo "  --- $name"
	if [ "${f:-0}" != 1 ]; then
		echo "      lookup MISS"
		i=$((i + 1))
		continue
	fi
	fam=$(slot $((base + 1)))
	st=$(slot $((base + 2)))
	sp=$(slot $((base + 3)))
	s4=$(slot $((base + 4)))
	echo "      lookup HIT"
	printf '      %-14s %s   (2 = AF_INET, 10 = AF_INET6)\n' "family" "$fam"
	printf '      %-14s %s   (10 = BPF_TCP_LISTEN, 7 = BPF_TCP_CLOSE for UDP)\n' "state" "$st"
	printf '      %-14s %s   (host order; expected %s)\n' "src_port" "$sp" "$PORT"
	if [ "$i" -lt 2 ]; then
		# src_ip4 is network order; render it.
		a=$((s4 & 255))
		b=$(((s4 >> 8) & 255))
		c=$(((s4 >> 16) & 255))
		d=$(((s4 >> 24) & 255))
		printf '      %-14s %s.%s.%s.%s   (expected 198.51.100.1)\n' "src_ip4" "$a" "$b" "$c" "$d"
	fi
	i=$((i + 1))
done

echo
echo "########## 8. verdict"
# The map's value type is __s64, so bpftool renders a failure as a plain
# negative errno and no two's complement arithmetic is needed here.
rc=$(slot 5)
srcport=$(slot 3)
hit4t=$(slot 0)
hit4u=$(slot 6)
hit6t=$(slot 12)
hit6u=$(slot 18)
hits=$(((${hit4t:-0}) + (${hit4u:-0}) + (${hit6t:-0}) + (${hit6u:-0})))

echo "  lookups hit: $hits / 4"
echo "  bpf_sk_assign() returned: ${rc:-?}"
echo

ok=1
[ "$hits" = 4 ] || { echo "  FAIL: not all four listener sockets were reachable by sk_lookup."; ok=0; }
[ "${srcport:-0}" = "$PORT" ] || { echo "  NOTE: src_port ${srcport:-?} != $PORT -- check the host/network order assumption."; }
if [ "${rc:-1}" = 0 ]; then
	echo "  bpf_sk_assign() SUCCEEDED."
	echo "  On a kernel below 6.5 that is the runtime proof that sing-box's"
	echo "  tproxy listener carries no SO_REUSEPORT -- the helper would have"
	echo "  returned -ESOCKTNOSUPPORT (-94) otherwise. Blueprint 9.2 held only"
	echo "  by source reading until now; it is measured."
else
	echo "  bpf_sk_assign() FAILED with ${rc:-?}."
	echo "  -94  = ESOCKTNOSUPPORT: the listener HAS SO_REUSEPORT. Blueprint 9.2"
	echo "         is falsified and the architecture needs revisiting -- do NOT"
	echo "         work around it with a reuseport selector program."
	echo "  -22  = EINVAL: bad flags, or sk was NULL."
	echo "  -95  = EOPNOTSUPP: not at TC ingress."
	echo "  -101 = ENETUNREACH: socket is in a different netns."
	ok=0
fi

[ "$ok" = 1 ] && echo && echo "  Q2 PASSES on the baseline."
echo
echo "  engine log tail:"
tail -6 "$LOG" 2>/dev/null | sed 's/^/    /'
