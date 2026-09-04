# Third-party notices

## Shipped in the module ZIP

### sing-box

The module distributes the **unmodified** official release binary, pinned by
`engine.lock`. It is not linked into `fluxd` and is not modified in any way.

- Upstream: <https://github.com/SagerNet/sing-box>
- License: GPL-3.0-or-later

Every Flux-rs release publishes the exact upstream source tree pinned by
`engine.lock` beside the module ZIP. That archive includes sing-box's build
scripts, `go.mod`, and `go.sum`; its size and SHA-256 are verified before the
release is created. The source archive is intentionally not nested inside the
module ZIP.

## Vendored at build time

### libbpf headers (header-only subset)

`bpf/flux.bpf.c` includes only the header-only macro and helper-prototype
subset of libbpf (`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_endian.h`). **The
libbpf library itself is not linked**, and neither are libelf or zlib: the BPF
loader in `crates/fluxd/src/bpf/` issues raw `bpf(2)` syscalls and builds its
BTF blob by hand (`docs/spec/blueprint.md` D10).

- Upstream: <https://github.com/libbpf/libbpf>
- License: LGPL-2.1-only OR BSD-2-Clause

## Rust dependencies

Resolved by Cargo and audited in CI by `cargo deny` against `deny.toml`. Run
`cargo deny list` for the current set with licenses.

The subscription pipeline has five direct Rust dependencies:

- `ureq` 3 — blocking HTTP over rustls, built with `rustls-no-provider` so that
  no bundled root store is compiled in (Flux reads the device's own); upstream
  <https://github.com/algesten/ureq>; MIT OR Apache-2.0.
- `rustls` 0.23 — the TLS implementation ureq drives, with the `ring` crypto
  provider named explicitly; upstream <https://github.com/rustls/rustls>;
  Apache-2.0 OR ISC OR MIT. Its own tree brings `ring` (Apache-2.0 AND ISC),
  `rustls-webpki` and `untrusted` (ISC) and `subtle` (BSD-3-Clause), which is
  why `deny.toml` allows ISC and BSD-3-Clause.
- `base64` 0.22 — provider and URI payload decoding; upstream
  <https://github.com/marshallpierce/rust-base64>; MIT OR Apache-2.0.
- `url` 2 — standards-based URL and percent decoding; upstream
  <https://github.com/servo/rust-url>; MIT OR Apache-2.0.
- `regex-lite` 0.1 — node filtering, renaming, and region grouping; upstream
  <https://github.com/rust-lang/regex>; MIT OR Apache-2.0.

## Research sources

`docs/spec/blueprint.md` cites AOSP, the Linux kernel, dae, honk, Cilium and several
Android proxy projects as **evidence**, with file and line references. No code
from any of them is present in this repository. Third-party sources used for
research are cloned into a git-ignored `clone/` directory that never enters the
product tree.
