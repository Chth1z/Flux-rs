# Third-party notices

## Shipped in the module ZIP

### sing-box

The module distributes the **unmodified** official release binary. Each build
resolves the latest stable release and records the selected revision and asset
digests in `build-info.toml`. It is not linked into `fluxd`.

- Upstream: <https://github.com/SagerNet/sing-box>
- License: GPL-3.0-or-later

Every Flux-rs release publishes the upstream source tree corresponding to its
packaged engine beside the module ZIP. That archive includes sing-box's build
scripts, `go.mod`, and `go.sum`; its SHA-256 is published with the release. The
source archive is not nested inside the module ZIP.

## Used at build time

### libbpf headers (header-only subset)

`bpf/flux.bpf.c` includes only the header-only macro and helper-prototype
subset of libbpf (`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_endian.h`) supplied
by the build environment. No fixed header revision is vendored. **The
libbpf library itself is not linked**, and neither are libelf or zlib: the BPF
loader in `crates/fluxd/src/bpf/` issues raw `bpf(2)` syscalls and builds its
BTF blob by hand (`docs/spec/blueprint.md` D10).

- Upstream: <https://github.com/libbpf/libbpf>
- License: LGPL-2.1-only OR BSD-2-Clause

Flux uses this header subset under BSD-2-Clause. Its redistribution notice is
included here so it accompanies the module's compiled BPF object:

```text
Copyright (c) 2013-2015 Alexei Starovoitov
Copyright (c) 2015 Wang Nan and Huawei Inc.
Copyright (c) 2018, 2019, 2021 Facebook
Copyright (c) 2017 Nicira, Inc.
Copyright (c) 2019 Isovalent, Inc.
Copyright (c) 2019 Netronome Systems, Inc.
Copyright (c) 2003-2013 Thomas Graf
Copyright (c) 2018-2019 Intel Corporation
Copyright (c) 2022-2023 Meta Platforms, Inc. and affiliates
Copyright (c) 2024 Oracle and/or its affiliates

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Rust dependencies

Resolved by Cargo and audited in CI by `cargo deny` against `deny.toml`. Run
`cargo deny list` for the current set with licenses.

The subscription pipeline has five direct Rust dependencies:

- `ureq` — blocking HTTP over rustls, built with `rustls-no-provider` so that
  no bundled root store is compiled in (Flux reads the device's own); upstream
  <https://github.com/algesten/ureq>; MIT OR Apache-2.0.
- `rustls` — the TLS implementation ureq drives, with the `ring` crypto
  provider named explicitly; upstream <https://github.com/rustls/rustls>;
  Apache-2.0 OR ISC OR MIT. Its own tree brings `ring` (Apache-2.0 AND ISC),
  `rustls-webpki` and `untrusted` (ISC) and `subtle` (BSD-3-Clause), which is
  why `deny.toml` allows ISC and BSD-3-Clause.
- `base64` — provider and URI payload decoding; upstream
  <https://github.com/marshallpierce/rust-base64>; MIT OR Apache-2.0.
- `url` — standards-based URL and percent decoding; upstream
  <https://github.com/servo/rust-url>; MIT OR Apache-2.0.
- `regex-lite` — node filtering, renaming, and region grouping; upstream
  <https://github.com/rust-lang/regex>; MIT OR Apache-2.0.

## Research sources

`docs/spec/blueprint.md` cites AOSP, the Linux kernel, dae, honk, Cilium and several
Android proxy projects as **evidence**, with file and line references. No code
from any of them is present in this repository. Third-party sources used for
research are cloned into a git-ignored `clone/` directory that never enters the
product tree.
