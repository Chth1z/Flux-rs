#!/system/bin/sh
# Put the real product data plane in front of the baseline kernel's verifier.
#
# This is the strongest single check available before fluxd's own loader exists:
# if all four programs verify on 5.15, the hot paths in blueprint sections 7.2
# through 7.5 are proven implementable rather than merely argued for.
#
# bpftool creates maps from the BTF declarations, which is NOT how the product
# will do it -- crates/fluxd/src/bpf/maps.rs owns the authoritative parameters
# (blueprint 12.2). So a failure in map creation here says nothing about the
# product; a failure in VERIFICATION says a great deal. The output separates
# the two.

OBJ=/data/local/tmp/flux.o
DIR=/sys/fs/bpf/fluxtest

cleanup() {
	echo
	echo "--- cleanup"
	rm -rf "$DIR" 2>/dev/null && echo "    removed $DIR"
}
trap cleanup EXIT INT TERM

echo "kernel:  $(uname -r)"
echo "bpftool: $(bpftool version 2>&1 | head -1)"
[ -f "$OBJ" ] || { echo "ABORT: $OBJ not pushed"; exit 1; }
echo

rm -rf "$DIR" 2>/dev/null
out=$(bpftool prog loadall "$OBJ" "$DIR" 2>&1)
rc=$?

echo "$out" | tail -60
echo
echo "--- exit $rc"

if [ -d "$DIR" ]; then
	echo
	echo "PINNED PROGRAMS:"
	for p in "$DIR"/*; do
		[ -e "$p" ] || continue
		echo "  $(basename "$p")"
		bpftool prog show pinned "$p" 2>/dev/null | sed 's/^/      /'
	done
	echo
	echo "ALL FOUR PROGRAMS VERIFIED ON THE BASELINE."
	exit 0
fi

echo
if echo "$out" | grep -qiE 'map_create|failed to create map|BTF.*map|inner map|max_entries'; then
	echo "FAILED IN MAP CREATION, not verification."
	echo "Expected: bpftool builds maps from BTF, while the product builds them"
	echo "explicitly in maps.rs (blueprint 12.2). ARRAY_OF_MAPS in particular"
	echo "needs an inner-map template that bare BTF does not carry."
	echo "This says nothing about whether the programs verify."
elif echo "$out" | grep -qiE 'guess program type|section'; then
	echo "FAILED ON SECTION NAMING -- see flux_abi.h FLUX_SEC_* and phase0 16.7."
else
	echo "FAILED IN VERIFICATION. This one matters: read the log above."
fi
exit 1
