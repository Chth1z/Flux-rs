#!/system/bin/sh
# Blast radius: finit_module of fluxrs, one UDP origdst probe as uid 2000,
# delete_module. Does not touch fluxd, sysctl, xtables, or Magisk.

KO=/data/local/tmp/fluxrs-android13-5.15.ko
HELPER=/data/local/tmp/fluxrs-finit
PROVE=/data/local/tmp/fluxrs-steal-prove
LISTEN4=198.51.100.1
LISTEN6=2001:db8:0:1::2
DEST4=203.0.113.1
DEST6=2001:db8:0:2::9
LPORT=61234
DPORT=53
UID=2000
LOADED=0
V4ROUTE=0
V6ROUTE=0

log() { echo "$1"; }

cleanup() {
	if [ "$V4ROUTE" = 1 ]; then
		ip route del "$DEST4"/32 dev lo 2>/dev/null || true
		V4ROUTE=0
	fi
	if [ "$V6ROUTE" = 1 ]; then
		ip -6 route del "$DEST6"/128 dev lo 2>/dev/null || true
		V6ROUTE=0
	fi
	if [ "$LOADED" = 1 ]; then
		"$HELPER" unload fluxrs >/dev/null 2>&1 || true
		LOADED=0
	fi
}
trap cleanup EXIT INT TERM

if [ ! -x "$HELPER" ] || [ ! -x "$PROVE" ] || [ ! -f "$KO" ]; then
	log "missing_artifacts"
	exit 1
fi

log "UNAME $(uname -r)"
lsmod | grep fluxrs && log "already_loaded" && exit 1

"$HELPER" load "$KO" || exit 1
LOADED=1
log "KO_LOADED"
ls -l /dev/fluxrs
dmesg -d | tail -n 8

# On-link lo destinations still hit LOCAL_OUT; nothing leaves the device.
if ip route add "$DEST4"/32 dev lo 2>/dev/null; then
	V4ROUTE=1
	log "V4ROUTE_LO 1"
else
	log "V4ROUTE_LO 0"
fi
if ip -6 route add "$DEST6"/128 dev lo 2>/dev/null; then
	V6ROUTE=1
	log "V6ROUTE_LO 1"
else
	log "V6ROUTE_LO 0"
fi

"$PROVE" "$UID" "$LISTEN4" "$LISTEN6" "$DEST4" "$DEST6" "$LPORT" "$DPORT"
rc=$?
log "PROVE_RC $rc"

"$HELPER" unload fluxrs
LOADED=0
log "UNLOADED"
dmesg -d | tail -n 12
lsmod | grep fluxrs && log "STILL_LOADED"
exit $rc
