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

mkdir -p "$RUNTIME_ROOT"
chmod 0700 "$RUNTIME_ROOT"

{
	echo "--- $(date '+%Y-%m-%d %H:%M:%S') boot"
	echo "manager=$MANAGER version=$MANAGER_VER mode=$MANAGER_MODE"
	echo "kernel=$(uname -r)"
} >>"$LOG" 2>&1

# 0.9.0 skeleton: nothing is implemented, so do not attempt activation.
# Replace this block with the fluxd launch once Phase 6 lands (§17).
echo "skeleton build: $MODDIR/bin/fluxd not started" >>"$LOG"
exit 0
