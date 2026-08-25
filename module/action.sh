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
	echo "Flux-rs 0.9.0 skeleton: no fluxd binary in this build."
	echo ""
	echo "This commit contains the design contract and crate structure only."
	echo "See docs/blueprint.md section 17 for the phase plan."
	set_description "[Skeleton] Not functional yet. See docs/blueprint.md."
	exit 0
fi

STATE=$("$FLUXD" status 2>/dev/null)

case "$STATE" in
*'"state":"Active"'*)
	echo "Flux-rs is active. Disabling."
	"$FLUXD" disable
	set_description "[Disabled] Tap to enable."
	;;
*)
	echo "Flux-rs is not active. Enabling."
	"$FLUXD" enable
	"$FLUXD" status
	set_description "[Enabled] Tap to disable."
	;;
esac
