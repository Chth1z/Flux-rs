#!/system/bin/sh
# Blast radius: temporary fluxd disable/enable (C9 file), finit_module of
# fluxrs, UDP sendto to the default IPv4 gateway. Cleanup unloads fluxrs
# and restores the switch found at start. Does not write sysctl, does not
# flush xtables, does not install a Magisk module.

FLUXD=/data/adb/modules/Flux-rs/bin/fluxd
KO=/data/local/tmp/fluxrs-android13-5.15.ko
HELPER=/data/local/tmp/fluxrs-finit
BENCH=/data/local/tmp/fluxrs-floor-bench
DISABLE=/data/adb/modules/Flux-rs/disable
COUNT=50000
REPEATS=5
PORT=9
WAS_DISABLED=0
LOADED=0

log() { echo "$1"; }

restore_switch() {
	if [ "$WAS_DISABLED" = 1 ]; then
		touch "$DISABLE" 2>/dev/null || true
		if [ -x "$FLUXD" ]; then
			"$FLUXD" disable >/dev/null 2>&1 || true
		fi
	else
		rm -f "$DISABLE"
		if [ -x "$FLUXD" ]; then
			"$FLUXD" enable >/dev/null 2>&1 || true
		fi
	fi
}

cleanup() {
	exec 3<&- 2>/dev/null || true
	if [ "$LOADED" = 1 ]; then
		"$HELPER" unload fluxrs >/dev/null 2>&1 || true
		LOADED=0
	fi
	restore_switch
}
trap cleanup EXIT INT TERM

if [ ! -x "$FLUXD" ]; then
	log "no_fluxd"
	exit 1
fi
if [ ! -x "$HELPER" ] || [ ! -x "$BENCH" ] || [ ! -f "$KO" ]; then
	log "missing_artifacts"
	exit 1
fi

if [ -e "$DISABLE" ]; then
	WAS_DISABLED=1
fi

# Android has no main-table default; uid 0 uses the wlan/rmnet table.
# `ip route get` still yields a via on the capture interface.
GW=""
prev=""
for w in $(ip route get 1.1.1.1 2>/dev/null); do
	if [ "$prev" = "via" ]; then
		GW=$w
		break
	fi
	prev=$w
done
if [ -z "$GW" ]; then
	log "no_route_via"
	exit 1
fi

log "UNAME $(uname -r)"
log "UID $(id -u)"
log "GW_PRESENT 1"
log "WAS_DISABLED $WAS_DISABLED"
log "STATUS_START"
"$FLUXD" status 2>/dev/null | head -n 20 || true

# Disable deletes the live engine generation. If the on-disk policy cannot
# rebuild (last_error already set), do not take that engine down.
if [ "${FLUX_FLOOR_FORCE-}" != 1 ]; then
	err=$("$FLUXD" status 2>/dev/null | sed -n 's/^last error:[[:space:]]*//p' | sed -n '1p')
	case "$err" in
	"" | "none") ;;
	*)
		log "REFUSE_DISABLE last_error=$err"
		log "set FLUX_FLOOR_FORCE=1 to override"
		exit 2
		;;
	esac
fi

run_arm() {
	name=$1
	i=1
	while [ "$i" -le "$REPEATS" ]; do
		out=$("$BENCH" "$GW" "$PORT" "$COUNT") || exit 1
		log "ARM $name $i $out"
		i=$((i + 1))
	done
}

wait_state() {
	want=$1
	n=0
	while [ "$n" -lt 20 ]; do
		st=$("$FLUXD" status 2>/dev/null | sed -n '1p')
		case "$st" in
		*"$want"*) return 0 ;;
		esac
		sleep 1
		n=$((n + 1))
	done
	log "WAIT_FAIL $want last=$st"
	return 1
}

wait_settle() { wait_state "$1" || true; }

# --- off: no Flux TC, no live LOCAL_OUT ---
"$FLUXD" disable >/dev/null 2>&1 || touch "$DISABLE"
wait_settle Disabled
log "STATUS_OFF"
"$FLUXD" status 2>/dev/null | head -n 12 || true
run_arm off

# --- tc: product TC E1, still no fluxrs ---
rm -f "$DISABLE"
"$FLUXD" enable >/dev/null 2>&1 || true
wait_settle Active
log "STATUS_TC"
"$FLUXD" status 2>/dev/null | head -n 12 || true
run_arm tc

# --- ko: TC down, floor module live ---
"$FLUXD" disable >/dev/null 2>&1 || touch "$DISABLE"
wait_settle Disabled
"$HELPER" load "$KO" || exit 1
LOADED=1
log "KO_LOADED"
ls -l /dev/fluxrs
exec 3</dev/fluxrs || exit 1
run_arm ko
exec 3<&-
"$HELPER" unload fluxrs
LOADED=0

log "DONE"
