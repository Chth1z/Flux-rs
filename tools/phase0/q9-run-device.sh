#!/system/bin/sh
# Phase 0 Q9 -- is DNS attributed to the app that asked, or to netd?
#
# Observation only. The program returns TC_ACT_UNSPEC everywhere, so no
# packet's fate changes. Footprint is one TC filter plus one pin, both removed
# by the cleanup trap on every exit path.
#
# Reads /data/system/packages.list to turn UIDs back into package names, so the
# evidence is "UID 10234 = com.example.app sent 3 plaintext DNS packets", not a
# bare number. That file is root-readable and is the same source fluxd will use
# (blueprint 6.2).

OBJ=/data/local/tmp/q9_probe.o
PIN=/sys/fs/bpf/q9_probe
WINDOW=${1:-60}
EGRESS=ffff:fff3

pinned=0
attached=0
IF=""

cleanup() {
	echo
	echo "########## cleanup"
	if [ "$attached" = 1 ]; then
		tc filter del dev "$IF" parent "$EGRESS" pref 2 2>&1 | sed 's/^/  /'
		echo "  detached pref 2 on $IF"
	fi
	if [ "$pinned" = 1 ]; then
		rm -f "$PIN" && echo "  unpinned $PIN"
	fi
}
trap cleanup EXIT INT TERM

fail() {
	echo "  ABORT: $*"
	exit 1
}

echo "########## 0. environment"
echo "  kernel: $(uname -r)"
echo "  private_dns_mode: $(settings get global private_dns_mode 2>/dev/null)"
[ -f "$OBJ" ] || fail "$OBJ not pushed"

# Attach where netd has actually put a clsact, which tracks "this interface is
# on a live network" -- not merely "it has an address".
for cand in $(tc qdisc show 2>/dev/null | grep clsact | sed 's/.*dev \([^ ]*\).*/\1/'); do
	case "$cand" in
	flxrs* | lo) continue ;;
	esac
	IF="$cand"
	break
done
[ -n "$IF" ] || fail "no interface carries a clsact right now"
echo "  attaching on: $IF ($(cat /sys/class/net/$IF/type) = $(
	case $(cat /sys/class/net/$IF/type) in
	1) echo ARPHRD_ETHER ;;
	519) echo ARPHRD_RAWIP ;;
	*) echo other ;;
	esac
))"

echo
echo "########## 1. load and attach"
rm -f "$PIN" 2>/dev/null
bpftool prog load "$OBJ" "$PIN" 2>&1 | sed 's/^/  /'
[ -e "$PIN" ] || fail "program did not load"
pinned=1
tc filter add dev "$IF" parent "$EGRESS" pref 2 protocol all \
	bpf da pinned "$PIN" 2>&1 | sed 's/^/  /'
tc filter show dev "$IF" parent "$EGRESS" 2>/dev/null | grep -q "pref 2 " ||
	fail "filter did not appear"
attached=1
echo "  attached"

ids=$(bpftool prog show pinned "$PIN" 2>/dev/null | grep -oE 'map_ids [0-9,]+' | grep -oE '[0-9,]+')
mid=""
did=""
for m in $(echo "$ids" | tr ',' ' '); do
	n=$(bpftool map show id "$m" 2>/dev/null)
	case "$n" in
	*q9_uid_port*) mid="$m" ;;
	*q9_diag*) did="$m" ;;
	esac
done
[ -n "$mid" ] || fail "cannot find q9_uid_port"

echo
echo "########## 2. observing for ${WINDOW}s"
echo "  Ambient DNS is what we want -- apps resolving on their own is exactly"
echo "  the case D18 is about. Use the phone normally if you like."
# A couple of nudges that make apps resolve without opening anything: asking
# the connectivity stack to re-evaluate triggers a fresh lookup.
cmd connectivity reevaluate 2>/dev/null >/dev/null
i=0
while [ "$i" -lt "$WINDOW" ]; do
	sleep 5
	i=$((i + 5))
	printf '\r  %ss elapsed' "$i"
done
echo

echo
echo "########## 3. diagnostics (did the program parse anything?)"
if [ -n "$did" ]; then
	j=0
	for nm in TOTAL NOT_IP V4 V6 NO_L4 READ_FAIL UID_OVF; do
		k=$(printf '%02x 00 00 00' "$j")
		v=$(bpftool map lookup id "$did" key hex $k 2>/dev/null |
			grep -oE '"value": *[0-9]+' | grep -oE '[0-9]+' |
			awk '{s+=$1} END {print s+0}')
		printf '  %-10s %s\n' "$nm" "$v"
		j=$((j + 1))
	done
fi

echo
echo "########## 4. UID x port"
bpftool map dump id "$mid" >/data/local/tmp/q9.raw 2>&1

# The device's bpftool prints BTF-typed maps as JSON with the struct's real
# field names rather than raw hex -- a free readability win that BTF map
# definitions buy us, and worth knowing about. Try that shape first.
awk '
  { gsub(/,/, "") }
  $1 == "\"uid\":"   { u = $2 + 0 }
  $1 == "\"kind\":"  { k = $2 + 0 }
  $1 == "\"value\":" { print u, k, $2 + 0 }
' /data/local/tmp/q9.raw | sort -k2,2n -k3,3rn >/data/local/tmp/q9.tsv

# Fall back to hex if this bpftool lacks BTF output. It wraps its dump onto
# continuation lines unpredictably, so flatten to a token stream and walk it
# rather than parsing line by line.
[ -s /data/local/tmp/q9.tsv ] || tr '\n' ' ' </data/local/tmp/q9.raw | awk '
{
  i = 1
  while (i <= NF) {
    if ($i != "key:") { i++; continue }
    # 8 key bytes, then the literal "value:", then 8 value bytes.
    for (j = 0; j < 8; j++) k[j] = $(i + 1 + j)
    vi = i + 9
    if ($vi != "value:") { i++; continue }
    for (j = 0; j < 8; j++) v[j] = $(vi + 1 + j)
    uid  = strtonum("0x" k[3] k[2] k[1] k[0])
    kind = strtonum("0x" k[7] k[6] k[5] k[4])
    val  = 0
    for (j = 7; j >= 0; j--) val = val * 256 + strtonum("0x" v[j])
    print uid, kind, val
    i = vi + 9
  }
}' | sort -k2,2n -k3,3rn >/data/local/tmp/q9.tsv

if [ ! -s /data/local/tmp/q9.tsv ]; then
	echo "  PARSE PRODUCED NOTHING. Raw dump, first 6 lines:"
	head -6 /data/local/tmp/q9.raw | sed 's/^/    /'
	exit 1
fi

kindname() {
	case "$1" in
	0) echo "UDP:53   plaintext DNS" ;;
	1) echo "TCP:53   plaintext DNS" ;;
	2) echo "TCP:853  DoT (netd)" ;;
	3) echo "UDP:443  QUIC/DoH3" ;;
	4) echo "TCP:443  HTTPS/DoH" ;;
	5) echo "other" ;;
	esac
}

# UID -> package name. packages.list column 1 is the package, column 2 the UID.
pkg() {
	if [ "$1" = 0 ]; then echo "root"; return; fi
	if [ "$1" = 1051 ]; then echo "netd  <-- DNS resolver itself"; return; fi
	if [ "$1" = 1000 ]; then echo "system"; return; fi
	if [ "$1" = 2000 ]; then echo "shell"; return; fi
	if [ "$1" = 4294967295 ]; then echo "(no socket)"; return; fi
	# Multi-user UIDs are userId*100000 + appId; packages.list stores appId.
	a=$(($1 % 100000))
	p=$(awk -v u="$a" '$2 == u {print $1; exit}' /data/system/packages.list 2>/dev/null)
	[ -n "$p" ] && echo "$p" || echo "uid $1 (not in packages.list)"
}

last=""
while read -r uid kind val; do
	if [ "$kind" != "$last" ]; then
		echo
		echo "  --- $(kindname "$kind")"
		last="$kind"
	fi
	printf '      %-10s %6s pkts  %s\n' "$uid" "$val" "$(pkg "$uid")"
done </data/local/tmp/q9.tsv

echo
echo "########## 5. verdict on D18"
dns_rows=$(awk '$2==0 || $2==1' /data/local/tmp/q9.tsv | wc -l)
dns_app=$(awk '($2==0 || $2==1) && $1 >= 10000 && $1 != 4294967295' /data/local/tmp/q9.tsv | wc -l)
dns_netd=$(awk '($2==0 || $2==1) && $1 == 1051' /data/local/tmp/q9.tsv | wc -l)
dot_rows=$(awk '$2==2' /data/local/tmp/q9.tsv | wc -l)

if [ "$dns_rows" = 0 ]; then
	echo "  NO PLAINTEXT DNS OBSERVED."
	if [ "$dot_rows" != 0 ]; then
		echo "  DoT on :853 was seen, so this network's resolver supports it and"
		echo "  opportunistic mode took that path. D18 is NOT contradicted -- it"
		echo "  simply had nothing to attribute. Retest on a network whose DNS"
		echo "  server refuses DoT, or set private_dns_mode=off."
	else
		echo "  No DNS of any kind. The window was probably too quiet."
	fi
	exit 1
fi

echo "  plaintext DNS rows: $dns_rows   (app-UID rows: $dns_app, netd rows: $dns_netd)"
if [ "$dns_app" -gt 0 ]; then
	echo
	echo "  D18 HOLDS on this device."
	echo "  Plaintext DNS carries app UIDs, so netd's fchown() does reach"
	echo "  sk->sk_uid and bpf_get_socket_uid() reads it. Per-app DNS needs no"
	echo "  extra mechanism: the ordinary uid_policy lookup already covers it."
	if [ "$dns_netd" -gt 0 ]; then
		echo "  Some rows are netd's own (1051) -- expected for its internal"
		echo "  lookups, which have no app to attribute to."
	fi
	exit 0
else
	echo
	echo "  D18 IS FALSIFIED on this device."
	echo "  Every plaintext DNS packet carries a system UID, so per-app DNS"
	echo "  attribution does not work here. Do NOT special-case port 53 to hide"
	echo "  this -- go back to the design (blueprint 1.3, and the Q9 note)."
fi
