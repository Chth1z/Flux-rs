#!/system/bin/sh
# Flux-rs install-time checks.
#
# Refuses obviously unsupported devices at install time rather than failing
# mysteriously at boot. Anything that needs a live kernel probe is deliberately
# NOT checked here — capability verification happens at activation by actually
# performing the operation, never by parsing version strings
# (docs/blueprint.md §4, §12.7).

# Read by the manager's installer after it sources this script, not by us.
# shellcheck disable=SC2034
SKIPUNZIP=0

# No system/ overlay, so skip the mount entirely. Belt and braces with the
# skip_mount file the ZIP ships (blueprint §13.1).
# shellcheck disable=SC2034
SKIPMOUNT=true

ui_print "- Flux-rs $(grep_prop version "$MODPATH/module.prop")"

# Architecture. The data plane is aarch64-only.
if [ "$ARCH" != "arm64" ]; then
	ui_print "! Unsupported architecture: $ARCH"
	ui_print "! Flux-rs requires arm64."
	abort "! Aborting."
fi

# Kernel floor is 5.15 (blueprint Q3). This is an install-time courtesy check
# on the version string; the real gate is the activation-time capability probe,
# because vendor kernels backport freely and a version string proves nothing.
KREL=$(uname -r)
KMAJ=${KREL%%.*}
KREST=${KREL#*.}
KMIN=${KREST%%.*}
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 15 ]; }; then
	ui_print "! Kernel $KREL is below the 5.15 floor."
	abort "! Aborting."
fi
ui_print "- Kernel $KREL"

# Manager. MAGISK_VER_CODE is not trustworthy here (§13.2.0).
if [ "$KSU" = "true" ]; then
	ui_print "- Manager: KernelSU ${KSU_VER:-} (${KSU_RUNTIME_MODE:-unknown})"
elif [ "$APATCH" = "true" ]; then
	ui_print "- Manager: APatch ${APATCH_VER:-}"
else
	ui_print "- Manager: Magisk ${MAGISK_VER:-}"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
[ -d "$MODPATH/bin" ] && set_perm_recursive "$MODPATH/bin" 0 0 0755 0755

ui_print "- This is a 0.9.0 skeleton build: no functionality yet."
ui_print "- See docs/blueprint.md for the design contract."
