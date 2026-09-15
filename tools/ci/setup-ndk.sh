#!/bin/sh
# Resolve the stable SDK channel once; every later step uses this installation.
set -eu

packages=$(sdkmanager --list --channel=0)
package=$(printf '%s\n' "$packages" | awk '
    /^Available Packages:/ { available = 1; next }
    /^[^[:space:]].*:/ { available = 0 }
    available && /^[[:space:]]*ndk;[0-9]/ { print $1 }
' | sort -Vu | tail -n 1)
[ -n "$package" ] || { echo "No stable NDK package in the official SDK channel" >&2; exit 1; }
yes | sdkmanager --channel=0 "$package"
revision=${package#ndk;}
ndk_path="$ANDROID_HOME/ndk/$revision"
test -x "$ndk_path/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang"
printf 'ndk-path=%s\n' "$ndk_path" >> "$GITHUB_OUTPUT"
printf 'NDK: %s\n' "$revision"
