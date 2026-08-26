#!/system/bin/sh
# Flux-rs boot entry.
#
# service.sh is the ONLY boot script that runs on all three managers
# (docs/blueprint.md §13.2.0):
#   - post-fs-data.sh is skipped entirely by KernelSU in late-load mode
#   - boot-completed.sh does not exist on Magisk
#
# We therefore do everything here and never depend on sys.boot_completed:
# fluxd is event-driven and converges when rtnetlink tells it the network
# exists (§11.3, §25).

MODDIR=${0%/*}

# Manager detection. MAGISK_VER_CODE is NOT usable for this: KernelSU reports
# 25200 and APatch reports 27000, and KernelSU's own documentation says not to
# use it. Use the positive markers instead (§13.2.0).
if [ "$KSU" = "true" ]; then
	MANAGER=kernelsu
	MANAGER_VER="${KSU_VER:-unknown}"
	# built-in / lkm / late-load. Worth recording: lkm and late-load run on
	# stock vendor kernels, where BPF feature gaps are far more likely.
	MANAGER_MODE="${KSU_RUNTIME_MODE:-unknown}"
elif [ "$APATCH" = "true" ]; then
	MANAGER=apatch
	MANAGER_VER="${APATCH_VER:-unknown}"
	MANAGER_MODE=n/a
else
	MANAGER=magisk
	MANAGER_VER="${MAGISK_VER:-unknown}"
	MANAGER_MODE=n/a
fi

RUNTIME_ROOT=/data/adb/flux-rs
LOG="$RUNTIME_ROOT/service.log"

mkdir -p "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"
chown 0:0 "$RUNTIME_ROOT" "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"
chmod 0700 "$RUNTIME_ROOT" "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"

{
	echo "--- $(date '+%Y-%m-%d %H:%M:%S') boot"
	echo "manager=$MANAGER version=$MANAGER_VER mode=$MANAGER_MODE"
	echo "kernel=$(uname -r)"
} >>"$LOG" 2>&1
chown 0:0 "$LOG"
chmod 0600 "$LOG"

# Keep the manager's service process small: fluxd owns all convergence and
# engine backoff. This loop only handles an unexpected daemon-level failure;
# a clean `fluxd stop` exits zero and deliberately ends the boot service.
n=0
while :; do
	"$MODDIR/bin/fluxd" daemon >>"$LOG" 2>&1
	rc=$?
	[ "$rc" = 0 ] && break
	n=$((n + 1))
	[ "$n" -gt 4 ] && n=4
	case "$n" in
	1) s=1 ;;
	2) s=2 ;;
	3) s=4 ;;
	*) s=8 ;;
	esac
	echo "fluxd exited rc=$rc; restart in ${s}s" >>"$LOG"
	sleep "$s"
done

exit 0
