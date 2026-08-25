#!/system/bin/sh
# Flux-rs uninstall.
#
# This script is load-bearing, not a formality. Flux keeps state OUTSIDE the
# module directory — TC filters, an ip rule, a routing table entry, per-device
# sysctls and a veth pair — and the manager only deletes the module directory
# (docs/blueprint.md §13.2, §18.2).
#
# One rule that must not be relaxed: delete our FILTERS, never the clsact
# qdisc. netd creates clsact for tethering and CLAT, and removing it would
# break both (§8.5).

MODDIR=${0%/*}
FLUXD="$MODDIR/bin/fluxd"
RUNTIME_ROOT=/data/adb/flux-rs

# Ask the daemon to tear down its own objects: it is the only thing that knows
# the full ownership predicate, so it can avoid deleting a lookalike that
# belongs to someone else.
if [ -x "$FLUXD" ]; then
	"$FLUXD" disable >/dev/null 2>&1
	"$FLUXD" stop >/dev/null 2>&1
fi

rm -rf "$RUNTIME_ROOT"

exit 0
