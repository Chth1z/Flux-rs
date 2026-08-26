#!/system/bin/sh
# Toggle Flux-rs from the manager UI.
#
# Three hard constraints on this script (docs/blueprint.md §13.2.1):
#   1. STDOUT is shown in the manager UI; STDERR is DISCARDED. Never write
#      anything meaningful to stderr.
#   2. STDIN is unavailable. Never prompt.
#   3. The manager re-reads module.prop after this script exits, so the
#      description= line doubles as a live status readout. Use it.
#
# Requires Magisk >= v28.0 (canary 27008). KernelSU and APatch have always
# supported action.sh.

MODDIR=${0%/*}
FLUXD="$MODDIR/bin/fluxd"

# Rewrites description= in place, so the manager list shows current state.
set_description() {
	[ -f "$MODDIR/module.prop" ] || return 0
	sed -i "s|^description=.*|description=$1|" "$MODDIR/module.prop"
}

if [ ! -x "$FLUXD" ]; then
	echo "Flux-rs: fluxd binary is missing or not executable."
	set_description "[Error] fluxd binary missing."
	exit 0
fi

STATE=$("$FLUXD" status --json 2>/dev/null)

case "$STATE" in
*'"state":"Disabled"'*)
	echo "Flux-rs is disabled. Enabling."
	"$FLUXD" enable 2>&1
	set_description "[Enabled] Tap to disable; use fluxd status for details."
	;;
*'"state":"Inactive"'* | *'"state":"Active"'*)
	echo "Flux-rs is enabled. Disabling."
	"$FLUXD" disable 2>&1
	set_description "[Disabled] Tap to enable."
	;;
*)
	echo "Flux-rs daemon is not reachable; persisting the enabled switch."
	"$FLUXD" enable 2>&1
	set_description "[Enabled] Daemon not reachable; check service.log."
	;;
esac
