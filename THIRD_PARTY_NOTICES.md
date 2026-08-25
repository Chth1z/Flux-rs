# Third-party notices

## Shipped in the module ZIP

### sing-box

The module distributes the **unmodified** official release binary, pinned by
`engine.lock`. It is not linked into `fluxd` and is not modified in any way.

- Upstream: <https://github.com/SagerNet/sing-box>
- License: GPL-3.0-or-later

## Vendored at build time

### libbpf headers (header-only subset)

`bpf/flux.bpf.c` includes only the header-only macro and helper-prototype
subset of libbpf (`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_endian.h`). **The
libbpf library itself is not linked**, and neither are libelf or zlib: the BPF
loader in `crates/fluxd/src/bpf/` issues raw `bpf(2)` syscalls and builds its
BTF blob by hand (`docs/blueprint.md` D10).

- Upstream: <https://github.com/libbpf/libbpf>
- License: LGPL-2.1-only OR BSD-2-Clause

## Rust dependencies

Resolved by Cargo and audited in CI by `cargo deny` against `deny.toml`. Run
`cargo deny list` for the current set with licenses.

## Research sources

`docs/blueprint.md` cites AOSP, the Linux kernel, dae, honk, Cilium and several
Android proxy projects as **evidence**, with file and line references. No code
from any of them is present in this repository. Third-party sources used for
research are cloned into a git-ignored `clone/` directory that never enters the
product tree.
