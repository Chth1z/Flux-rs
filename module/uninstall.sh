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

# `stop` publishes active=0, terminates the engine and exits the daemon
# cleanly, without flushing system objects (§8.8). It deliberately does not
# call `disable` first: the switch lives in this module directory, which the
# manager is about to delete, so writing it would be a no-op with a chance of
# leaving a stray file behind if removal is interrupted.
if [ -x "$FLUXD" ]; then
	"$FLUXD" stop >/dev/null 2>&1
fi

rm -rf "$RUNTIME_ROOT"

exit 0
