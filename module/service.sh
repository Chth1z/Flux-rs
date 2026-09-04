#!/system/bin/sh
# Flux-rs boot entry.
#
# service.sh is the ONLY boot script that runs on all three managers
# (docs/spec/blueprint.md §13.2.0):
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

# Pass the positively identified manager into the daemon's structured status.
# These variables are process-local metadata; they are not another state file.
export FLUX_ROOT_MANAGER="$MANAGER"
export FLUX_ROOT_MANAGER_VERSION="$MANAGER_VER"
export FLUX_ROOT_MANAGER_MODE="$MANAGER_MODE"

# FLUX_RUNTIME_ROOT is the daemon's existing integration-test seam. Root
# managers never set it; production therefore always uses the fixed path.
RUNTIME_ROOT=${FLUX_RUNTIME_ROOT:-/data/adb/flux-rs}
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

exec "$MODDIR/bin/fluxd" daemon >>"$LOG" 2>&1
