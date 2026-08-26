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

# The archive is built from an allowlist, but interrupted extraction or a
# third-party repack can still leave a partial module. Refuse before touching
# persistent state; booting a half-installed control plane is worse than a
# loud install failure.
for payload in \
	bin/fluxd \
	bin/sing-box \
	bin/observe.sh \
	etc/default-flux.toml \
	etc/default-sing-box.json \
	engine.lock \
	LICENSE \
	THIRD_PARTY_NOTICES.md; do
	if [ ! -s "$MODPATH/$payload" ]; then
		abort "! Incomplete module payload: $payload is missing or empty."
	fi
done

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

RUNTIME_ROOT=/data/adb/flux-rs
FRESH_INSTALL=0
[ -d "$RUNTIME_ROOT" ] || FRESH_INSTALL=1

mkdir -p "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"
chown 0:0 "$RUNTIME_ROOT" "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"
chmod 0700 "$RUNTIME_ROOT" "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/config"

# Defaults are bootstrap inputs only. Reinstalling/upgrading must never replace
# either user authority file.
if [ ! -e "$RUNTIME_ROOT/config/flux.toml" ]; then
	cp "$MODPATH/etc/default-flux.toml" "$RUNTIME_ROOT/config/flux.toml"
	chown 0:0 "$RUNTIME_ROOT/config/flux.toml"
	chmod 0600 "$RUNTIME_ROOT/config/flux.toml"
fi
if [ ! -e "$RUNTIME_ROOT/config/sing-box.json" ]; then
	cp "$MODPATH/etc/default-sing-box.json" "$RUNTIME_ROOT/config/sing-box.json"
	chown 0:0 "$RUNTIME_ROOT/config/sing-box.json"
	chmod 0600 "$RUNTIME_ROOT/config/sing-box.json"
fi

# Installation itself must never start capturing traffic. Preserve the user's
# switch on upgrades; create it only for a genuinely fresh state root.
if [ "$FRESH_INSTALL" = 1 ]; then
	: >"$RUNTIME_ROOT/disable"
	chown 0:0 "$RUNTIME_ROOT/disable"
	chmod 0600 "$RUNTIME_ROOT/disable"
fi

ui_print "- Runtime files initialized; fresh installs start disabled."
ui_print "- Edit both configs, run 'fluxd check', then enable Flux-rs."
