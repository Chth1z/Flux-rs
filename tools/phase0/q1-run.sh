#!/usr/bin/env bash
# Phase 0 Q1 -- SK_STORAGE first-decision, run in a network namespace.
#
# MODIFIES HOST STATE, all of it removed by the cleanup trap on every exit
# path. Everything lives inside a dedicated netns plus one veth pair, so the
# blast radius is a namespace nothing else uses.
#
# REHEARSAL, NOT VERDICT if this host is not on the product baseline (5.15).
# A program the verifier here rejects is certainly rejected on 5.15, so a
# failure is conclusive; a pass is not. The authoritative run is on device.
#
# Usage: sudo tools/phase0/q1-run.sh [connections]

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

NS=fluxq1
HOST_IF=fq1a
NS_IF=fq1b
HOST_IP=10.99.0.1
NS_IP=10.99.0.2
CLOSED_PORT=59999
OPEN_PORT=59998
CONNS=${1:-100}
OBJ=/tmp/q1_probe.o
PIN=/sys/fs/bpf/q1_probe
SRV_PID=""

created_ns=0
created_link=0
pinned=0

cleanup() {
	echo
	echo "########## cleanup"
	[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null && echo "  stopped listener"
	if [ "$pinned" = 1 ]; then
		rm -f "$PIN" && echo "  unpinned $PIN"
	fi
	if [ "$created_link" = 1 ]; then
		ip link del "$HOST_IF" 2>/dev/null && echo "  removed veth $HOST_IF/$NS_IF"
	fi
	if [ "$created_ns" = 1 ]; then
		ip netns del "$NS" 2>/dev/null && echo "  removed netns $NS"
	fi
	echo "--- residue check"
	ip netns list 2>/dev/null | grep -q "$NS" && echo "  WARNING: netns $NS still present" || echo "  netns clean"
	ip link show "$HOST_IF" >/dev/null 2>&1 && echo "  WARNING: $HOST_IF still present" || echo "  links clean"
	[ -e "$PIN" ] && echo "  WARNING: $PIN still present" || echo "  pins clean"
}
trap cleanup EXIT INT TERM

fail() {
	echo "  ABORT: $*"
	exit 1
}

echo "########## 0. environment"
echo "  kernel: $(uname -r)"
[ "$(id -u)" = 0 ] || fail "must run as root"
case "$(uname -r)" in
5.15.*) echo "  on the product baseline -- results are authoritative for the kernel" ;;
*) echo "  NOT the 5.15 baseline -- REHEARSAL ONLY, a pass here proves nothing about 5.15" ;;
esac
[ -f "$OBJ" ] || fail "$OBJ missing; build it first (see the header of q1_probe.bpf.c)"
mount | grep -q ' /sys/fs/bpf ' || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
modprobe cls_bpf 2>/dev/null
modprobe sch_ingress 2>/dev/null

echo
echo "########## 1. topology"
ip netns add "$NS" || fail "cannot create netns"
created_ns=1
ip link add "$HOST_IF" type veth peer name "$NS_IF" || fail "cannot create veth"
created_link=1
ip link set "$NS_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" addr add "$NS_IP/24" dev "$NS_IF"
ip -n "$NS" link set "$NS_IF" up
ip -n "$NS" link set lo up
echo "  $HOST_IF $HOST_IP  <-->  $NS:$NS_IF $NS_IP"

echo
echo "########## 2. load and attach"
rm -f "$PIN"
bpftool prog load "$OBJ" "$PIN" || fail "verifier rejected the program (this IS conclusive)"
pinned=1
bpftool prog show pinned "$PIN" | sed 's/^/  /'
# nsenter --net rather than `ip netns exec`: the latter mounts a fresh /sys for
# the namespace, so the bpffs pin is invisible inside and tc fails with
# "Couldn't retrieve pinned program". nsenter changes only the network
# namespace, and tc reaches the interface over netlink anyway.
NSE="nsenter --net=/var/run/netns/$NS"
$NSE tc qdisc add dev "$NS_IF" clsact || fail "cannot add clsact"
$NSE tc filter add dev "$NS_IF" egress pref 2 protocol all \
	bpf da pinned "$PIN" || fail "cannot attach"
echo "  attached at $NS_IF egress pref 2"
$NSE tc filter show dev "$NS_IF" egress | sed 's/^/    /'

mapid_counters=$(bpftool prog show pinned "$PIN" |
	grep -oE 'map_ids [0-9,]+' | grep -oE '[0-9,]+' | tr ',' '\n' |
	while read -r m; do
		bpftool map show id "$m" 2>/dev/null | grep -q 'name q1_counters' && echo "$m"
	done | head -1)
[ -n "$mapid_counters" ] || fail "cannot find the counters map"
echo "  counters map id: $mapid_counters"

sum_slot() {
	bpftool map lookup id "$mapid_counters" key hex "$(printf '%02x %02x %02x %02x' "$1" 0 0 0)" 2>/dev/null |
		grep -oE '"value": *[0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END {print s+0}'
}

report() {
	printf '  %-14s %s\n' "$1" "$2"
}

echo
echo "########## 3. phase A: $CONNS concurrent connects to a closed port"
echo "  every connect() creates a socket and emits a SYN, so each one should"
echo "  produce exactly one storage creation"
for _ in $(seq 1 "$CONNS"); do
	(timeout 2 bash -c "exec 3<>/dev/tcp/$HOST_IP/$CLOSED_PORT" 2>/dev/null) &
done
wait 2>/dev/null
sleep 1

a_created=$(sum_slot 1)
a_loser=$(sum_slot 2)
a_fail=$(sum_slot 3)
a_corrupt=$(sum_slot 4)
report "CREATED" "$a_created"
report "RACE_LOSER" "$a_loser"
report "ALLOC_FAIL" "$a_fail"
report "CORRUPT" "$a_corrupt"
report "first decisions" "$((a_created + a_loser))  (expected about $CONNS)"

echo
echo "########## 4. phase B: established connections, multiple packets each"
if command -v python3 >/dev/null 2>&1; then
	python3 - "$HOST_IP" "$OPEN_PORT" <<'PY' &
import socket, sys, threading
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port)); s.listen(64)
def serve(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except OSError:
        pass
    finally:
        c.close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
	SRV_PID=$!
	sleep 1
	before_seen=$(sum_slot 0)
	ip netns exec "$NS" python3 - "$HOST_IP" "$OPEN_PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
socks = []
for _ in range(10):
    c = socket.create_connection((host, port), timeout=3)
    socks.append(c)
# Several round trips per socket: the first packet creates the decision, every
# later one must find the same one unchanged.
for _ in range(20):
    for c in socks:
        c.sendall(b'x' * 64)
        c.recv(4096)
for c in socks:
    c.close()
print("  10 sockets x 20 round trips done")
PY
	sleep 1
	b_seen=$(sum_slot 0)
	b_created=$(sum_slot 1)
	b_corrupt=$(sum_slot 4)
	report "SEEN delta" "$((b_seen - before_seen))"
	report "CREATED total" "$b_created"
	report "CORRUPT" "$b_corrupt"
else
	echo "  SKIPPED: no python3, cannot run a listener"
	b_seen=0
	b_corrupt=$a_corrupt
fi

echo
echo "########## 5. verdict"
ok=1
if [ "$a_corrupt" != 0 ] || [ "${b_corrupt:-0}" != 0 ]; then
	echo "  FAIL: stored value was mutated or corrupted"
	ok=0
fi
if [ "$a_fail" != 0 ]; then
	echo "  FAIL: F_CREATE returned NULL $a_fail times (capacity or allocation problem)"
	ok=0
fi
if [ "$((a_created + a_loser))" = 0 ]; then
	echo "  INCONCLUSIVE: no first decisions recorded -- did any traffic reach egress?"
	ok=0
fi
if [ "${b_seen:-0}" -gt 0 ] 2>/dev/null && [ "${b_corrupt:-0}" = 0 ]; then
	echo "  PASS: existing decisions were found unchanged on later packets"
fi
if [ "$ok" = 1 ]; then
	echo "  PASS: verifier accepted the real E1/E2/E3 shape; F_CREATE is"
	echo "        first-decision-wins; stored values stayed immutable."
	case "$(uname -r)" in
	5.15.*) : ;;
	*) echo "  NOTE: rehearsal only -- rerun on the 5.15 baseline for the record." ;;
	esac
fi
