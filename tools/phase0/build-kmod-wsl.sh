#!/bin/bash
# Build kmod + device helpers in WSL. ASCII only.
set -euo pipefail
ROOT="${1:-/mnt/d/Github/Flux-rs}"
KDIR="${KDIR:-/home/chth1z/ddk/kdir/android13-5.15}"
SRC="${SRC:-/home/chth1z/ddk/src/android13-5.15}"
CLANG="${CLANG:-/home/chth1z/ddk/clang/clang-r450784e/bin}"
NDK_CLANG="${NDK_CLANG:-}"
OUT=/tmp/fluxrs-kmod

if [[ -z "$NDK_CLANG" ]]; then
  for c in \
    "$HOME/Android/Sdk/ndk/27.3.13750724/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang" \
    "$HOME/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"; do
    if [[ -x "$c" ]]; then
      NDK_CLANG=$c
      break
    fi
  done
fi
if [[ -z "$NDK_CLANG" ]]; then
  NDK_CLANG=$(find "$HOME/Android/Sdk/ndk" -name 'aarch64-linux-android21-clang' 2>/dev/null | head -n 1 || true)
fi
if [[ -z "$NDK_CLANG" || ! -x "$NDK_CLANG" ]]; then
  echo "no NDK clang" >&2
  exit 1
fi

# DDK kdir Makefile points at /opt/ddk/src; rewrite to this machine's src.
if grep -q '/opt/ddk/src' "$KDIR/Makefile"; then
  sed -i "s|/opt/ddk/src/android13-5.15|$SRC|g" "$KDIR/Makefile"
fi

rm -rf "$OUT"
mkdir -p "$OUT"
cp -a "$ROOT/kmod/." "$OUT/"
export PATH="$CLANG:$PATH"
STAGE="${FLUXRS_STAGE:-6}"
NOCFI="${FLUXRS_NOCFI:-1}"
make -C "$OUT" KDIR="$KDIR" FLUXRS_STAGE="$STAGE" FLUXRS_NOCFI="$NOCFI" clean
make -C "$OUT" KDIR="$KDIR" FLUXRS_STAGE="$STAGE" FLUXRS_NOCFI="$NOCFI"

echo "STAGE $STAGE NOCFI $NOCFI"
echo "UNDEF"
llvm-nm -u "$OUT/fluxrs.ko" | grep -v '^$' | sort
echo "TPROXY_UNDEF"
llvm-nm -u "$OUT/fluxrs.ko" | grep tproxy || echo none

"$NDK_CLANG" -O2 -Wall -Werror -o /tmp/fluxrs-finit "$ROOT/tools/phase0/fluxrs-finit.c"
"$NDK_CLANG" -O2 -Wall -Werror -o /tmp/fluxrs-stage-prove "$ROOT/tools/phase0/local-out-stage-prove.c"
cp "$OUT/fluxrs.ko" /tmp/fluxrs-android13-5.15.ko
ls -l /tmp/fluxrs-android13-5.15.ko /tmp/fluxrs-finit /tmp/fluxrs-stage-prove
