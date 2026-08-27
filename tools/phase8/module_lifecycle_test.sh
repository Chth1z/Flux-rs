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

# action.sh reads status before acting, calls an explicit enable/disable, never
# reads stdin, and refreshes module.prop from the post-action status.
ACTION="$WORK/action"
mkdir -p "$ACTION/bin"
cp "$ROOT/module/action.sh" "$ACTION/action.sh"
cat >"$ACTION/module.prop" <<'EOF'
id=flux_rs
description=initial
EOF
cat >"$ACTION/bin/fluxd" <<'EOF'
#!/bin/sh
ROOT=${0%/*}/..
case "$1" in
status) cat "$ROOT/status.json" ;;
enable)
	echo 'fluxd: enabled'
	printf '%s\n' '{"state":"Active","generation":7,"policy":{"selected":3},"counters":{"admit_tcp":41,"admit_udp":388}}' >"$ROOT/status.json"
	;;
disable)
	echo 'fluxd: disabled'
	printf '%s\n' '{"state":"Disabled","generation":7,"policy":{"selected":3},"counters":{"admit_tcp":41,"admit_udp":388}}' >"$ROOT/status.json"
	;;
*) exit 1 ;;
esac
EOF
chmod 0755 "$ACTION/bin/fluxd"
printf '%s\n' '{"state":"Disabled","generation":0,"policy":{"selected":3},"counters":{"admit_tcp":0,"admit_udp":0}}' >"$ACTION/status.json"

first=$(sh "$ACTION/action.sh" </dev/null)
printf '%s' "$first" | grep -q 'Enabling' || fail 'action did not explicitly enable'
grep -q '^description=\[Active\] gen 7 · 3 apps · 41 tcp / 388 udp$' \
	"$ACTION/module.prop" || fail 'active description does not reflect status'

second=$(sh "$ACTION/action.sh" </dev/null)
printf '%s' "$second" | grep -q 'Disabling' || fail 'action did not explicitly disable'
grep -q '^description=\[Disabled\] gen 7 · 3 apps · 41 tcp / 388 udp$' \
	"$ACTION/module.prop" || fail 'disabled description does not reflect status'

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
