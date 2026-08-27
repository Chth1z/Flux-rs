#!/system/bin/sh
# Flux-rs uninstaller.
#
# The manager removes the module directory. This script synchronously makes
# the runtime inactive, stops the child and daemon, then deletes only Flux's
# external state root (blueprint §13.2). It deliberately does not flush TC,
# RPDB, routes, qdiscs or lookalike paths; the non-persistent kernel objects
# disappear on the manager-required reboot (§8.8).

MODDIR=${0%/*}
FLUXD="$MODDIR/bin/fluxd"
RUNTIME_ROOT=/data/adb/flux-rs

# `disable` publishes active=0 before stopping the engine. `stop` then exits
# the daemon cleanly; neither command flushes system objects (§8.8).
if [ -x "$FLUXD" ]; then
	"$FLUXD" disable >/dev/null 2>&1
	"$FLUXD" stop >/dev/null 2>&1
fi

rm -rf "$RUNTIME_ROOT"

exit 0
