#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
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

# Runtime supervision belongs to the Rust binary (PHIL-7), never this script.
service_body=$(sed '/^[[:space:]]*#/d' "$ROOT/module/service.sh")
printf '%s\n' "$service_body" | grep -Eq '(^|[[:space:]])(while|sleep)([[:space:]]|$)' && \
	fail 'service.sh contains a shell supervision loop'

# There is no action.sh: the manager's own module toggle is the switch, and
# fluxd reacts to it through inotify (C9).
[ ! -e "$ROOT/module/action.sh" ] || fail 'action.sh is forbidden; the switch is the manager toggle'

# Exercise selective extraction and the real Rust install operation. A host
# build embeds no BPF by default; installation never activates it or an engine.
if [ -n "${FLUX_TEST_FLUXD:-}" ]; then
	HOST_FLUXD=$FLUX_TEST_FLUXD
else
	TARGET_DIR=$(cd "$ROOT" && cargo metadata --no-deps --format-version 1 | \
		python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
	HOST_FLUXD="$TARGET_DIR/debug/fluxd"
	if [ ! -x "$HOST_FLUXD" ]; then
		(cd "$ROOT" && cargo build -p fluxd --bin fluxd --target-dir "$TARGET_DIR")
	fi
fi
[ -x "$HOST_FLUXD" ] || fail "host fluxd is not executable: $HOST_FLUXD"

ZIPFILE="$WORK/Flux-rs-host-test.zip"
MODULES_ROOT="$WORK/installed-modules"
mkdir -p "$MODULES_ROOT"
python3 - "$ROOT" "$HOST_FLUXD" "$ZIPFILE" <<'PY'
import pathlib
import sys
import zipfile

root, binary, target = map(pathlib.Path, sys.argv[1:])
with zipfile.ZipFile(target, "w") as archive:
    for path in ("customize.sh", "service.sh", "uninstall.sh", "webroot/index.html"):
        archive.write(root / "module" / path, path)
    archive.write(binary, "bin/fluxd")
    for source, destination in (
        ("flux.toml", "default-flux.toml"),
        ("advanced.toml", "default-advanced.toml"),
        ("template.json", "default-template.json"),
    ):
        archive.write(root / "module" / source, "etc/" + destination)
    archive.writestr("module.prop", "id=Flux-rs\nname=Flux-rs\nversion=host-test\n")
    archive.writestr("build-info.toml", 'kind = "host lifecycle fixture"\n')
    # An attempted engine invocation fails; install must not use it.
    archive.writestr("bin/sing-box", "#!/bin/sh\nexit 97\n")
    archive.writestr("skip_mount", "")
    # These belong to the ZIP only and must not become runtime prerequisites.
    archive.writestr("LICENSE", "host fixture licence\n")
    archive.writestr("THIRD_PARTY_NOTICES.md", "host fixture notices\n")
    archive.writestr("licenses/DEPENDENCIES.md", "host fixture inventory\n")
    archive.writestr("kmod/fluxrs-android13-5.15.ko", b"host fixture module\n")
PY

# Stub only root-manager helpers. No unzip, installer, or filesystem writes
# performed by fluxd are mocked. All products live in this test's temp directory.
install_module() {
	dest=$1
	runtime=$2
	mkdir -p "$dest"
	if [ "${3:-enabled}" = disabled ]; then
		: >"$dest/disable"
	fi
	cp "$ROOT/module/customize.sh" "$dest/customize.sh"

	env FLUX_RUNTIME_ROOT="$runtime" FLUX_MODULES_ROOT="$MODULES_ROOT" MODPATH="$dest" ZIPFILE="$ZIPFILE" ARCH=arm64 MAGISK_VER=28.1 \
		sh -c '
			ui_print() { :; }
			abort() { echo "abort: $*" >&2; exit 1; }
			grep_prop() {
				# Do not consult or mutate any installed host module.
				case "$2" in "$MODPATH"/*|"$FLUX_MODULES_ROOT"/*) ;; *) return 0 ;; esac
				[ -f "$2" ] && sed -n "s/^$1=//p" "$2"
			}
			set_perm_recursive() {
				find "$1" -type d -exec chmod "$4" {} +
				find "$1" -type f -exec chmod "$5" {} +
			}
			. "$MODPATH/customize.sh"
		' || return $?
	for absent in etc licenses LICENSE THIRD_PARTY_NOTICES.md .install-defaults; do
		[ ! -e "$dest/$absent" ] || fail "unexpected installed payload: $absent"
	done
}

FRESH="$WORK/fresh"
FRESH_RUNTIME="$WORK/fresh-runtime"
install_module "$FRESH" "$FRESH_RUNTIME"
[ -f "$FRESH/disable" ] || fail 'fresh install must land as a disabled module'
[ ! -e "$FRESH_RUNTIME/disable" ] || fail 'the runtime root must not hold a second switch'
[ -f "$FRESH_RUNTIME/config/flux.toml" ] || fail 'fresh install did not seed flux.toml'
[ -f "$FRESH_RUNTIME/config/template.json" ] || fail 'fresh install did not seed template.json'
[ -f "$FRESH_RUNTIME/config/advanced.toml" ] || fail 'fresh install did not seed advanced.toml'
cmp "$ROOT/module/template.json" "$FRESH_RUNTIME/config/template.json" || fail 'template bootstrap bytes changed'

# An upgrade must never re-disable a module the user turned on, and must never
# replace either authority file.
printf '# user formatting\n[apps]\nmode="whitelist"\nlist=[]\n[nodes]\nsources=[]\n' >"$FRESH_RUNTIME/config/flux.toml"
echo '{ "user": "template" }' >"$FRESH_RUNTIME/config/template.json"
cp "$FRESH_RUNTIME/config/flux.toml" "$WORK/expected-flux.toml"
cp "$FRESH_RUNTIME/config/advanced.toml" "$WORK/expected-advanced.toml"
UPGRADE="$WORK/upgrade"
install_module "$UPGRADE" "$FRESH_RUNTIME"
[ ! -e "$UPGRADE/disable" ] || fail 'upgrade must preserve the user switch, not force disable'
cmp "$WORK/expected-flux.toml" "$FRESH_RUNTIME/config/flux.toml" || fail 'upgrade overwrote flux.toml'
cmp "$WORK/expected-advanced.toml" "$FRESH_RUNTIME/config/advanced.toml" || fail 'upgrade overwrote advanced.toml'
[ "$(cat "$FRESH_RUNTIME/config/template.json")" = '{ "user": "template" }' ] || \
	fail 'upgrade overwrote template.json'

# A marker already carried by the manager must survive its staging install.
install_module "$WORK/disabled-upgrade" "$FRESH_RUNTIME" disabled
[ -f "$WORK/disabled-upgrade/disable" ] || fail 'upgrade removed the manager disable marker'

# A current config-only installation stays enabled; it receives its missing
# template but no unsolicited optional advanced file.
CONFIG_ONLY="$WORK/config-only-runtime"
mkdir -p "$CONFIG_ONLY/config"
cp "$WORK/expected-flux.toml" "$CONFIG_ONLY/config/flux.toml"
install_module "$WORK/config-only-module" "$CONFIG_ONLY"
[ ! -e "$WORK/config-only-module/disable" ] || fail 'config-only upgrade was treated as fresh'
[ ! -e "$CONFIG_ONLY/config/advanced.toml" ] || fail 'upgrade inserted optional advanced defaults'
cmp "$WORK/expected-flux.toml" "$CONFIG_ONLY/config/flux.toml" || fail 'config-only upgrade rewrote main'

# A leftover runtime directory is not an installed configuration. Bootstrap it
# disabled while retaining unrelated files and the existing run directory.
RESIDUE="$WORK/residue-runtime"
mkdir -p "$RESIDUE/run"
echo retain >"$RESIDUE/run/unrelated"
install_module "$WORK/residue-module" "$RESIDUE"
[ -f "$WORK/residue-module/disable" ] || fail 'configuration-free residue was treated as an upgrade'
[ "$(cat "$RESIDUE/run/unrelated")" = retain ] || fail 'installation cleared unrelated run data'
[ -f "$RESIDUE/config/advanced.toml" ] || fail 'residue bootstrap omitted advanced defaults'

# Invalid user input aborts without replacing it or seeding sibling files.
INVALID="$WORK/invalid-runtime"
mkdir -p "$INVALID/config"
printf 'not valid TOML\n' >"$INVALID/config/flux.toml"
if install_module "$WORK/invalid-module" "$INVALID"; then
	fail 'invalid user configuration unexpectedly installed'
fi
[ "$(cat "$INVALID/config/flux.toml")" = 'not valid TOML' ] || fail 'invalid input was replaced'
[ ! -e "$INVALID/config/template.json" ] || fail 'failed preparation published template'
[ ! -e "$INVALID/config/advanced.toml" ] || fail 'failed preparation published advanced config'

seed_old_module() {
	old="$MODULES_ROOT/flux_rs"
	mkdir -p "$old"
	printf 'id=%s\nname=%s\n' "$1" "$2" >"$old/module.prop"
	echo 'old boot entry' >"$old/service.sh"
	echo 'old shared-root deletion entry' >"$old/uninstall.sh"
}

# Positive old Rust identity is retired only after successful configuration
# publication. Its old uninstall hook must never delete the shared new root.
for switch in enabled disabled; do
	MODULES_ROOT="$WORK/legacy-$switch-modules"
	seed_old_module flux_rs Flux-rs
	[ "$switch" != disabled ] || : >"$MODULES_ROOT/flux_rs/disable"
	legacy_runtime="$WORK/legacy-$switch-runtime"
	mkdir -p "$legacy_runtime/config"
	printf '# old implicit app default\n' >"$legacy_runtime/config/flux.toml"
	install_module "$WORK/legacy-$switch-new" "$legacy_runtime"
	grep -q 'whitelist' "$legacy_runtime/config/flux.toml" || fail 'old implicit whitelist was lost'
	grep -q 'sources' "$legacy_runtime/config/flux.toml" || fail 'migration completion marker missing'
	[ -f "$MODULES_ROOT/flux_rs/remove" ] || fail 'old Rust module not marked for retirement'
	[ ! -e "$MODULES_ROOT/flux_rs/service.sh" ] || fail 'old Rust boot entry survives'
	[ ! -e "$MODULES_ROOT/flux_rs/uninstall.sh" ] || fail 'old Rust shared-root deletion survives'
	if [ "$switch" = disabled ]; then
		[ -e "$WORK/legacy-$switch-new/disable" ] || fail 'old disabled choice not inherited'
		[ -e "$MODULES_ROOT/flux_rs/disable" ] || fail 'old choice lost for interrupted retry'
	else
		[ ! -e "$WORK/legacy-$switch-new/disable" ] || fail 'old enabled choice not inherited'
		[ ! -e "$MODULES_ROOT/flux_rs/disable" ] || fail 'retirement changed old enabled choice'
	fi
	cp "$legacy_runtime/config/flux.toml" "$WORK/legacy-$switch-complete"
	install_module "$WORK/legacy-$switch-retry" "$legacy_runtime"
	cmp "$WORK/legacy-$switch-complete" "$legacy_runtime/config/flux.toml" || fail 'retirement retry rewrote completed main'
done

# Current identity wins, including absence of disable: stale old disabled state
# must not re-disable the user's current enabled module.
MODULES_ROOT="$WORK/current-wins-modules"
seed_old_module flux_rs Flux-rs
: >"$MODULES_ROOT/flux_rs/disable"
mkdir -p "$MODULES_ROOT/Flux-rs"
printf 'id=Flux-rs\nname=Flux-rs\n' >"$MODULES_ROOT/Flux-rs/module.prop"
install_module "$WORK/current-wins-new" "$FRESH_RUNTIME"
[ ! -e "$WORK/current-wins-new/disable" ] || fail 'old disabled state overrode current enabled state'

# A matching path or name alone is insufficient authority to retire a module.
for mismatch in id name; do
	MODULES_ROOT="$WORK/mismatch-$mismatch-modules"
	if [ "$mismatch" = id ]; then
		seed_old_module unrelated Flux-rs
	else
		seed_old_module flux_rs unrelated
	fi
	: >"$MODULES_ROOT/flux_rs/disable"
	install_module "$WORK/mismatch-$mismatch-new" "$FRESH_RUNTIME"
	[ -f "$MODULES_ROOT/flux_rs/service.sh" ] || fail 'unidentified module boot entry was removed'
	[ -f "$MODULES_ROOT/flux_rs/uninstall.sh" ] || fail 'unidentified module uninstall entry was removed'
	[ ! -e "$MODULES_ROOT/flux_rs/remove" ] || fail 'unidentified module was retired'
	[ ! -e "$WORK/mismatch-$mismatch-new/disable" ] || fail 'unidentified module supplied switch state'
done

# Product scripts keep the narrow lifecycle boundaries from blueprint §13.
body=$(sed '/^[[:space:]]*#/d' "$ROOT/module/uninstall.sh")
printf '%s\n' "$body" | grep -q 'rm -rf "$RUNTIME_ROOT"' || fail 'uninstall root changed'
printf '%s\n' "$body" | grep -Eq '(^|[[:space:]])(ip|tc|bpftool)([[:space:]]|$)' && \
	fail 'uninstall contains a forbidden network flush command'
printf '%s\n' "$body" | grep -q '/data/adb/modules' && fail 'uninstall scans module roots'

[ ! -e "$ROOT/module/post-fs-data.sh" ] || fail 'post-fs-data.sh is forbidden'
[ ! -e "$ROOT/module/boot-completed.sh" ] || fail 'boot-completed.sh is forbidden'
WEBROOT="$ROOT/module/webroot"
[ -d "$WEBROOT" ] || fail 'webroot redirect directory is missing'
[ -f "$WEBROOT/index.html" ] || fail 'webroot/index.html redirect is missing'
WEBROOT_ENTRY_COUNT=$(find "$WEBROOT" -mindepth 1 -maxdepth 1 -print | wc -l)
[ "$WEBROOT_ENTRY_COUNT" -eq 1 ] || fail 'webroot must contain only index.html'

echo 'module lifecycle test: OK'
