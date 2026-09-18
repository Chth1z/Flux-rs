#!/system/bin/sh
# Blast radius: ksud insmod of a pre-pushed fluxrs.ko, one UDP sendto as
# uid 2000, delete_module. Does not touch fluxd, sysctl, xtables, SELinux,
# or Magisk. Does not nsenter.

KO=/data/local/tmp/fluxrs-android13-5.15.ko
PROVE=/data/local/tmp/fluxrs-stage-prove
KSUD=/data/adb/ksud
DEST4=203.0.113.1
DPORT=9
UID=2000
LOADED=0

log() { echo "$1"; }

cleanup() {
	if [ "$LOADED" = 1 ]; then
		rmmod fluxrs >/dev/null 2>&1 || true
		LOADED=0
	fi
}
trap cleanup EXIT INT TERM

if [ ! -x "$PROVE" ] || [ ! -f "$KO" ] || [ ! -x "$KSUD" ]; then
	log "missing_artifacts"
	exit 1
fi

log "UNAME $(uname -r)"
lsmod | grep fluxrs && log "already_loaded" && exit 1

"$KSUD" insmod "$KO" || exit 1
LOADED=1
log "KO_LOADED"
ls -l /dev/fluxrs

if [ "$#" -ge 5 ]; then
	"$PROVE" "$UID" "$DEST4" "$DPORT" "$1" "$2" "$3" "$4" "$5"
	rc=$?
elif [ "$#" -ge 4 ]; then
	"$PROVE" "$UID" "$DEST4" "$DPORT" "$1" "$2" "$3" "$4"
	rc=$?
else
	"$PROVE" "$UID" "$DEST4" "$DPORT"
	rc=$?
fi
log "PROVE_RC $rc"

rmmod fluxrs
LOADED=0
log "UNLOADED"
dmesg | grep fluxrs | tail -n 12
lsmod | grep fluxrs && log "STILL_LOADED"
exit $rc
