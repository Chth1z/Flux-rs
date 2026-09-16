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
SKIPUNZIP=1

# No system/ overlay, so skip the mount entirely. Belt and braces with the
# skip_mount file the ZIP ships (blueprint §13.1).
# shellcheck disable=SC2034
SKIPMOUNT=true

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
	build-info.toml; do
	unzip -o "$ZIPFILE" "$payload" -d "$MODPATH" >/dev/null || abort "! Cannot extract $payload."
	if [ ! -s "$MODPATH/$payload" ]; then
		abort "! Incomplete module payload: $payload is missing or empty."
	fi
done
unzip -o "$ZIPFILE" skip_mount -d "$MODPATH" >/dev/null || abort "! Cannot extract skip_mount."
if [ ! -e "$MODPATH/skip_mount" ]; then
	abort "! Incomplete module payload: skip_mount is missing."
fi
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

# FLUX_RUNTIME_ROOT is the same test seam service.sh uses. Root managers never
# set it, so production always installs to the fixed path.
RUNTIME_ROOT=${FLUX_RUNTIME_ROOT:-/data/adb/flux-rs}
MODULES_ROOT=${FLUX_MODULES_ROOT:-/data/adb/modules}
CURRENT_MODULE="$MODULES_ROOT/Flux-rs"
PREVIOUS_MODULE="$MODULES_ROOT/flux_rs"
FRESH_INSTALL=1
[ -f "$RUNTIME_ROOT/config/flux.toml" ] && FRESH_INSTALL=0
CURRENT_RUST=false
PREVIOUS_RUST=false
if [ "$(grep_prop id "$CURRENT_MODULE/module.prop")" = Flux-rs ] && \
    [ "$(grep_prop name "$CURRENT_MODULE/module.prop")" = Flux-rs ]; then
	CURRENT_RUST=true
fi
if [ "$(grep_prop id "$PREVIOUS_MODULE/module.prop")" = flux_rs ] && \
    [ "$(grep_prop name "$PREVIOUS_MODULE/module.prop")" = Flux-rs ]; then
	PREVIOUS_RUST=true
fi

# The Rust installer stops this Flux-rs daemon, prepares and validates the
# migration, and preserves existing user files before atomic publication.
DEFAULTS="$MODPATH/.install-defaults"
mkdir -p "$DEFAULTS" || abort "! Cannot prepare installation defaults."
for payload in default-flux.toml default-advanced.toml default-template.json; do
	unzip -jo "$ZIPFILE" "etc/$payload" -d "$DEFAULTS" >/dev/null || abort "! Cannot extract $payload."
	[ -s "$DEFAULTS/$payload" ] || abort "! Missing installation default: $payload."
done
# Only the positively identified previous Rust module establishes the old
# implicit app default. The current identity wins on upgrade/retry.
LEGACY_CONFIG=false
if [ "$PREVIOUS_RUST" = true ] && [ "$CURRENT_RUST" = false ]; then
	LEGACY_CONFIG=true
fi
if [ "$LEGACY_CONFIG" = true ]; then
	"$MODPATH/bin/fluxd" install --root "$RUNTIME_ROOT" --defaults "$DEFAULTS" --legacy-config || abort "! Configuration installation failed."
else
	"$MODPATH/bin/fluxd" install --root "$RUNTIME_ROOT" --defaults "$DEFAULTS" || abort "! Configuration installation failed."
fi
rm -f "$DEFAULTS/default-flux.toml" "$DEFAULTS/default-advanced.toml" "$DEFAULTS/default-template.json"
rmdir "$DEFAULTS"

# Installation itself must never start capturing traffic. The switch is the
# manager's own module toggle, so a fresh install lands as a disabled module and
# the user turns it on in the manager UI after configuring. Upgrades must not
# touch it: whatever the user chose stays chosen.
if [ "$FRESH_INSTALL" = 1 ]; then
	: >"$MODPATH/disable"
elif [ "$CURRENT_RUST" = true ]; then
	[ ! -e "$CURRENT_MODULE/disable" ] || : >"$MODPATH/disable"
elif [ "$PREVIOUS_RUST" = true ]; then
	[ ! -e "$PREVIOUS_MODULE/disable" ] || : >"$MODPATH/disable"
fi

# Changing the Rust module id transfers ownership of the same state root.
# Retire the old launch and uninstall entries before asking the manager to
# remove that envelope; its old uninstaller would delete the transferred data.
# Keep its switch unchanged so an interrupted installation can retry faithfully.
if [ "$PREVIOUS_RUST" = true ]; then
	rm -f "$PREVIOUS_MODULE/uninstall.sh" "$PREVIOUS_MODULE/service.sh" || abort "! Cannot retire the previous Rust module scripts."
	: >"$PREVIOUS_MODULE/remove" || abort "! Cannot mark the previous Rust module for removal."
fi

ui_print "- Runtime files initialized."
if [ "$FRESH_INSTALL" = 1 ]; then
	ui_print "- Flux-rs is installed, but disabled; nothing is proxied yet."
	ui_print "- 1. Edit /data/adb/flux-rs/config/flux.toml and /data/adb/flux-rs/config/template.json."
	ui_print "- 2. Enable this module in your root manager."
	ui_print "- Reboot once after first enabling it; later toggles take effect immediately."
	ui_print "- 3. Read the module status in your manager, or run /data/adb/modules/Flux-rs/bin/fluxd status."
	ui_print "- Flux validates the complete configuration before activation; use fluxd check for diagnostics."
fi
