#!/system/bin/sh
# Flux-rs install-time checks.
#
# Refuses obviously unsupported devices at install time rather than failing
# mysteriously at boot. Anything that needs a live kernel probe is deliberately
# NOT checked here — capability verification happens at activation by actually
# performing the operation, never by parsing version strings
# (docs/spec/blueprint.md §4, §12.7).

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
	module.prop \
	customize.sh \
	service.sh \
	uninstall.sh \
	webroot/index.html \
	bin/fluxd \
	bin/sing-box \
	etc/default-flux.toml \
	etc/default-template.json \
	engine.lock \
	LICENSE \
	THIRD_PARTY_NOTICES.md \
	licenses/sing-box-LICENSE \
	licenses/DEPENDENCIES.md; do
	if [ ! -s "$MODPATH/$payload" ]; then
		abort "! Incomplete module payload: $payload is missing or empty."
	fi
done
if [ ! -e "$MODPATH/skip_mount" ]; then
	abort "! Incomplete module payload: skip_mount is missing."
fi

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

# FLUX_RUNTIME_ROOT is the same test seam service.sh uses. Root managers never
# set it, so production always installs to the fixed path.
RUNTIME_ROOT=${FLUX_RUNTIME_ROOT:-/data/adb/flux-rs}
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
if [ ! -e "$RUNTIME_ROOT/config/template.json" ]; then
	cp "$MODPATH/etc/default-template.json" "$RUNTIME_ROOT/config/template.json"
	chown 0:0 "$RUNTIME_ROOT/config/template.json"
	chmod 0600 "$RUNTIME_ROOT/config/template.json"
fi

# Installation itself must never start capturing traffic. The switch is the
# manager's own module toggle, so a fresh install lands as a disabled module and
# the user turns it on in the manager UI after configuring. Upgrades must not
# touch it: whatever the user chose stays chosen.
if [ "$FRESH_INSTALL" = 1 ]; then
	: >"$MODPATH/disable"
fi

ui_print "- Runtime files initialized."
if [ "$FRESH_INSTALL" = 1 ]; then
	ui_print "- Flux-rs is installed, but disabled; nothing is proxied yet."
	ui_print "- 1. Edit /data/adb/flux-rs/config/flux.toml and /data/adb/flux-rs/config/template.json."
	ui_print "- 2. Run /data/adb/modules/flux_rs/bin/fluxd check."
	ui_print "- 3. Enable this module in your root manager."
	ui_print "- Reboot once after first enabling it; later toggles take effect immediately."
fi
