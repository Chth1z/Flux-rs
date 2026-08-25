#!/usr/bin/env bash
# Rebuilds clone/ from tools/clone-manifest.md. Run in WSL or on Linux.
#
# clone/ is a development asset -- nearly every claim in the design cites it --
# but third-party source does not belong in git. This script plus the manifest
# is what makes it reproducible without carrying 80 MB of other people's code
# in the product tree.
#
# Commits are pinned deliberately: kernel and AOSP semantics change between
# versions, so a citation like "v6.1 net/core/filter.c:2144" only means
# something if the tree is pinned.
#
# Usage:
#   tools/reclone.sh              # everything missing
#   tools/reclone.sh dae honk     # only these
#   FLUX_RECLONE_DEPTH=full tools/reclone.sh   # full history instead of shallow

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
mkdir -p clone

depth_args=(--depth 1)
[ "${FLUX_RECLONE_DEPTH:-shallow}" = "full" ] && depth_args=()

# dir|url|commit
REPOS='
aosp-Connectivity|https://android.googlesource.com/platform/packages/modules/Connectivity|2519a78731
aosp-DnsResolver|https://android.googlesource.com/platform/packages/modules/DnsResolver|4d70e9efa5
aosp-netd|https://android.googlesource.com/platform/system/netd|e11b8688b1
sing-box-official-1.13.19|https://github.com/SagerNet/sing-box|b5ebaa1fc0
chizi-sing-box-ebpf-cilium|https://github.com/CHIZI-0618/sing-box|45a5bd8d6c
dae|https://github.com/daeuniverse/dae|caa6f5e917
honk|https://github.com/daeuniverse/honk|131e71b8db
asteriskd|https://github.com/Asterisk4Magisk/asteriskd|0e6705e424
bpf2socks|https://github.com/Asterisk4Magisk/bpf2socks|885a313abe
bpfmatcher|https://github.com/Asterisk4Magisk/bpfmatcher|b814407819
AndroidTProxyShell|https://github.com/CHIZI-0618/AndroidTProxyShell|4b6ddd8779
box4magisk|https://github.com/CHIZI-0618/box4magisk|1aabf31ad8
box_for_magisk|https://github.com/taamarin/box_for_magisk|a87244943a
mihomo|https://github.com/MetaCubeX/mihomo|f295ba6da4
tun2socks|https://github.com/xjasonlyu/tun2socks|d24a73449e
hev-socks5-tunnel|https://github.com/heiher/hev-socks5-tunnel|0428c4ebb0
Vector|https://github.com/JingMatrix/Vector|5e4dcb92a1
NeoZygisk|https://github.com/JingMatrix/NeoZygisk|ec29fb101d
Flux-original|https://github.com/Chth1z/Flux|c978b75d87
'

selected=("$@")
matches() {
	[ "${#selected[@]}" -eq 0 ] && return 0
	for s in "${selected[@]}"; do [ "$s" = "$1" ] && return 0; done
	return 1
}

# Fed by here-string rather than a pipe so the loop body runs in this shell.
while IFS='|' read -r dir url commit; do
	[ -z "$dir" ] && continue
	matches "$dir" || continue

	if [ -d "clone/$dir/.git" ]; then
		have=$(git -C "clone/$dir" rev-parse HEAD 2>/dev/null | cut -c1-10)
		if [ "$have" = "$commit" ]; then
			printf '  %-30s already at %s\n' "$dir" "$commit"
			continue
		fi
		printf '  %-30s at %s, want %s -- refetching\n' "$dir" "${have:-?}" "$commit"
		rm -rf "clone/$dir"
	fi

	printf '  %-30s cloning ...\n' "$dir"
	# Shallow clone then fetch the exact commit. Not every host allows
	# fetching an arbitrary SHA, so fall back to a full clone.
	if git clone "${depth_args[@]}" "$url" "clone/$dir" >/dev/null 2>&1 &&
		{ git -C "clone/$dir" fetch --depth 1 origin "$commit" >/dev/null 2>&1 ||
			git -C "clone/$dir" fetch origin >/dev/null 2>&1; } &&
		git -C "clone/$dir" checkout -q "$commit" 2>/dev/null; then
		printf '  %-30s OK at %s\n' "$dir" "$commit"
	else
		if [ -d "clone/$dir/.git" ]; then
			printf '  %-30s WARNING: cloned but could not check out %s\n' "$dir" "$commit"
			printf '  %-30s          citations may not line up\n' ""
		else
			printf '  %-30s FAILED\n' "$dir"
		fi
	fi
done <<<"$REPOS"

cat <<'NOTE'

Three directories are not git repositories and are not handled above:

  kernel-src/              per-version kernel sources, fetched from
                           raw.githubusercontent.com/torvalds/linux/<tag>/...
                           Subdirectories: v5.10 v6.1 v6.6 v6.12
  gki/                     arm64 gki_defconfig from the four GKI branches at
                           android.googlesource.com/kernel/common
  mihomo-ebpf-historical/  the eBPF component mihomo later removed, taken
                           from a historical commit

Fetch those on demand. Which files matter is recorded alongside each citation
in the design, so only pull what a claim actually needs -- the point is
verifiability, not a local mirror of the kernel.
NOTE
