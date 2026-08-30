#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

fail() {
	echo "module lifecycle test: $*" >&2
	exit 1
}

# service.sh must positively identify all three managers and export the result
# to fluxd. A fake foreground daemon records its environment and exits cleanly.
mkdir -p "$WORK/module/bin"
cp "$ROOT/module/service.sh" "$WORK/module/service.sh"
cat >"$WORK/module/bin/fluxd" <<'EOF'
#!/bin/sh
printf '%s|%s|%s\n' \
	"$FLUX_ROOT_MANAGER" \
	"$FLUX_ROOT_MANAGER_VERSION" \
	"$FLUX_ROOT_MANAGER_MODE" >"$FLUX_RUNTIME_ROOT/identity"
exit 0
EOF
chmod 0755 "$WORK/module/bin/fluxd"

run_service() {
	name=$1
	expected=$2
	shift 2
	runtime="$WORK/service-$name"
	env FLUX_RUNTIME_ROOT="$runtime" "$@" sh "$WORK/module/service.sh"
	actual=$(cat "$runtime/identity")
	[ "$actual" = "$expected" ] || fail "$name identity: $actual != $expected"
}

run_service kernelsu 'kernelsu|1.0.5|late-load' \
	KSU=true KSU_VER=1.0.5 KSU_RUNTIME_MODE=late-load
run_service apatch 'apatch|10800|n/a' \
	APATCH=true APATCH_VER=10800
run_service magisk 'magisk|28.1|n/a' \
	MAGISK_VER=28.1

# There is no action.sh: the manager's own module toggle is the switch, and
# fluxd reacts to it through inotify (C9).
[ ! -e "$ROOT/module/action.sh" ] || fail 'action.sh is forbidden; the switch is the manager toggle'

# customize.sh must land a fresh install DISABLED, and the switch it creates
# must be the manager's own module toggle rather than a second file under the
# runtime root. Stub the manager helpers customize.sh expects.
install_module() {
	dest=$1
	runtime=$2
	shift 2
	mkdir -p "$dest/bin" "$dest/etc" "$dest/licenses"
	for payload in module.prop customize.sh service.sh uninstall.sh \
		bin/fluxd bin/sing-box etc/default-flux.toml \
		etc/default-sing-box.json engine.lock LICENSE \
		THIRD_PARTY_NOTICES.md licenses/sing-box-LICENSE \
		licenses/DEPENDENCIES.md; do
		echo payload >"$dest/$payload"
	done
	: >"$dest/skip_mount"
	cp "$ROOT/module/customize.sh" "$dest/customize.sh"
	cp "$ROOT/module/flux.toml" "$dest/etc/default-flux.toml"
	cp "$ROOT/module/template.json" "$dest/etc/default-sing-box.json"

	env FLUX_RUNTIME_ROOT="$runtime" MODPATH="$dest" ARCH=arm64 MAGISK_VER=28.1 \
		sh -c '
			ui_print() { :; }
			abort() { echo "abort: $*" >&2; exit 1; }
			grep_prop() { echo 0.9.0; }
			set_perm_recursive() { :; }
			. "$MODPATH/customize.sh"
		'
}

FRESH="$WORK/fresh"
FRESH_RUNTIME="$WORK/fresh-runtime"
install_module "$FRESH" "$FRESH_RUNTIME"
[ -f "$FRESH/disable" ] || fail 'fresh install must land as a disabled module'
[ ! -e "$FRESH_RUNTIME/disable" ] || fail 'the runtime root must not hold a second switch'
[ -f "$FRESH_RUNTIME/config/flux.toml" ] || fail 'fresh install did not seed flux.toml'
[ -f "$FRESH_RUNTIME/config/sing-box.json" ] || fail 'fresh install did not seed sing-box.json'

# An upgrade must never re-disable a module the user turned on, and must never
# replace either authority file.
echo 'user edit' >"$FRESH_RUNTIME/config/flux.toml"
UPGRADE="$WORK/upgrade"
install_module "$UPGRADE" "$FRESH_RUNTIME"
[ ! -e "$UPGRADE/disable" ] || fail 'upgrade must preserve the user switch, not force disable'
[ "$(cat "$FRESH_RUNTIME/config/flux.toml")" = 'user edit' ] || fail 'upgrade overwrote flux.toml'

# Product scripts keep the narrow lifecycle boundaries from blueprint §13.
body=$(sed '/^[[:space:]]*#/d' "$ROOT/module/uninstall.sh")
printf '%s\n' "$body" | grep -q 'rm -rf "$RUNTIME_ROOT"' || fail 'uninstall root changed'
printf '%s\n' "$body" | grep -Eq '(^|[[:space:]])(ip|tc|bpftool)([[:space:]]|$)' && \
	fail 'uninstall contains a forbidden network flush command'
printf '%s\n' "$body" | grep -q '/data/adb/modules' && fail 'uninstall scans module roots'

[ ! -e "$ROOT/module/post-fs-data.sh" ] || fail 'post-fs-data.sh is forbidden'
[ ! -e "$ROOT/module/boot-completed.sh" ] || fail 'boot-completed.sh is forbidden'
[ ! -d "$ROOT/module/webroot" ] || fail 'WebUI/webroot is forbidden'

echo 'module lifecycle test: OK'
