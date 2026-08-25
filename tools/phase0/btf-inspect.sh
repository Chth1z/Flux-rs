#!/usr/bin/env bash
# Why libbpf cannot build control_root from this object's BTF.
#
# The failure is "map 'control_root.inner': can't determine value size for
# type [N]". For an ARRAY_OF_MAPS, libbpf parses the __array element struct as
# an inner map definition and has to resolve the size of its value type. A
# struct that the program only ever touches through a pointer can end up in BTF
# as a forward declaration, which has no size -- that is the hypothesis this
# checks rather than assumes.
set -u
OBJ=${1:-/tmp/flux.o}

echo "=== object: $OBJ"
echo
echo "=== forward declarations in BTF (a FWD has no resolvable size)"
bpftool btf dump file "$OBJ" | grep -E '^\[[0-9]+\] FWD' || echo "  none"
echo
echo "=== how flux_control and control_leaf appear"
bpftool btf dump file "$OBJ" | grep -nE "'flux_control'|'control_leaf'" || echo "  neither found"
echo
echo "=== the type id libbpf named in the error, if given as argument 2"
if [ -n "${2:-}" ]; then
	bpftool btf dump file "$OBJ" | grep -E "^\[$2\]"
fi
