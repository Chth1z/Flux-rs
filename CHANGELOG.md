# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Incremental 0.9.1 design contract (`docs/history/blueprint-0.9.1.md`) that leaves
  the 0.9.0 blueprint content unchanged, records every known cross-document
  conflict as a stable `R091-*` correction, and defines baseline-plus-delta
  precedence without changing the workspace version or release status.
- `ifaces[].pref` in the status response: the TC preference each interface's
  capture filter actually occupies, chosen per interface (R091-05). Additive
  optional field; no existing field is renamed or removed.
- Per-interface lines, traffic counters and the draining / self-address counts
  in human `status` output, which previously reported neither coverage nor
  data-plane activity (`docs/spec/interaction.md` §27.3.3).
- Live status in the manager's module list: `fluxd` rewrites the
  `description=` line of `module.prop` on every settled state change, so the
  current state is visible without a terminal. The rewrite is idempotent,
  skipped when the rendered line is unchanged, and atomic; a failure costs the
  readout and never the daemon.
- Design contract for 0.9.0 (`docs/spec/blueprint.md`), the data-plane ABI
  (`bpf/include/flux_abi.h`) and its compile-time-checked Rust mirror
  (`crates/flux-core/src/abi.rs`).
- Three-crate workspace skeleton: `flux-core` (pure logic, `unsafe` forbidden),
  `fluxd` (runtime), `xtask` (build and packaging).
- Magisk / KernelSU / APatch module envelope.
- Phase 1 (`docs/plan/implementation.md` §17.4): the complete `flux-core` pure
  logic layer — app selectors and `packages.list` resolution, CIDR
  canonicalisation with LPM key encoding and the fixed bypass set, strict
  `flux.toml` parsing, engine-config generation with tproxy
  inbound injection, the hand-written BTF blob for `tcp_decision`, the control
  wire protocol, and SemVer-derived packaging metadata — including all eight
  §15.2 logic tests.
- `cargo xtask abi-check`: clang verifies `flux_abi.h` sizes, alignments and
  field offsets against the compiled Rust mirror, field by field, for both the
  `bpf` and `aarch64` targets; string defines byte-compared; define name sets
  must match exactly. The CI escape hatch (`continue-on-error`) is gone.
- `cargo xtask package` / `verify-package`: allowlist staging (§13.1),
  automated `engine.lock` digest/size/`p_align` verification that refuses to
  package on any mismatch, `p_align >= 0x4000` enforcement for `fluxd`, and a
  deterministic ZIP — two clean builds hash identically, asserted in CI.
- `cargo xtask doc-check` (in CI), over `docs/`, `tools/` and the root markdown:
  chapter map, relative links, identifier resolution across the registered
  namespaces, decision status registries, `FLUX_SEC_*`/`SEC_*` identity within
  the measured-usable set, and overturn numbering consistency.
- Phase 2–7 runtime: root-only control socket and event-driven reactor;
  typed rtnetlink ownership/cleanup; embedded raw-syscall BPF loader; exact TC
  attachment and liveness admission; official sing-box check/readiness,
  generation switching and crash recovery; policy/config/topology convergence;
  per-UID statistics, status hints and privacy-preserving bug reports.
- Phase 8 module lifecycle: one `service.sh` boot path for Magisk, KernelSU and
  APatch; structured root-manager/runtime-mode status; the manager's module
  toggle as the single inotify-watched switch with a live module description;
  synchronous narrow uninstall; blueprint-minimal direct bootstrap config with
  no remote rule-set or WebUI downloads.
- Signed-tag release workflow with tag/workspace-version equality,
  reproducible package verification, git-commit provenance, SHA256SUMS, and the
  pinned official sing-box Corresponding Source archive beside the module ZIP.

### Changed

- The shipped bootstrap template now follows the original Flux module's
  template — DNS splitting with fakeip, `clash_mode` rules, remote rule-sets,
  `PROXY` / `GLOBAL` selectors — instead of a bare direct outbound, so both
  projects present users the same shape. It still ships no servers, no
  subscription and no credentials. `xtask` stopped enumerating allowed keys and
  now checks the four properties a default must actually have: no `inbounds`,
  no `clash_api`, no empty selector, and a fakeip IPv6 range outside `fc00::/7`.
  That last one is load-bearing: Flux bypasses all of ULA as private space, so
  the original's `fc00::/18` fakeip range would have been sent direct and every
  IPv6 fakeip connection would have failed silently.
- `parse_jsonc` skips a leading UTF-8 BOM. Editors on Windows add one routinely
  and the raw parser error points at a byte the user cannot see.
- The on/off switch is now the root manager's own module toggle
  (`/data/adb/modules/flux_rs/disable`), watched with the daemon's existing
  inotify source. Toggling the module in Magisk, KernelSU or APatch therefore
  takes effect immediately rather than at the next boot. `/data/adb/flux-rs/disable`
  is gone: there is one switch file, and `fluxd enable` / `fluxd disable` write
  that same one, so the CLI and the manager UI can never disagree.
- A fresh install now lands as a disabled *module*, which is what the manager
  shows in its list. `customize.sh` says so explicitly, because a greyed-out
  module is otherwise easy to mistake for a failed install. Upgrades leave the
  switch alone.
- `ifaces[].first_applicable` is now three-valued and no longer inferred from
  dump position. Admission publishes no verdict at all; only the `flx_verify`
  liveness probe (or an identity plus preceding-snapshot recheck of an existing
  owned filter) sets `true`, and a decided failure sets `false`. The previous
  computation asserted "lowest preference in chain 0", which is exactly the
  ordering claim R091-05 overturned — on the Q10 device it would have reported
  `false` for a path measured to work. An absent field must not be read as
  `false`.

### Removed

- `module/action.sh`, and with it the Magisk v28+ floor it implied. A dedicated
  action button existed only to work around the manager toggle needing a
  reboot; watching the manager's own switch removes the need for both the
  button and the second switch file. The packaging allowlist is now 15 files, the webroot redirect of §28.8 included.
- `module/module.prop`: generated by `cargo xtask package` from the workspace
  version; the checked-in copy was the second version file blueprint §13.4
  forbids and had already drifted (`updateJson`, `id`, `author`).

### Notes

The 0.9.1 work is primarily a documentation/design correction layer, plus the
status-surface changes above. It does not change SemVer, the ABI magic, the
config schema, or the control-socket encoding, and it is not a `v0.9.1` release.

Subscription conversion (C11) moved into scope by owner decision on 2026-08-30
and is specified in §28. A Flux-built WebUI (C8) and an out-of-the-box proxy
control panel (C10) remain deferred — deferred, not abandoned — and no seam is
pre-built for them. The twelve-line `webroot/index.html` that does ship is a
redirect to the user''s own controller, not a UI.

Fresh history. The repository previously implemented a different architecture;
`docs/spec/blueprint.md` §0 records what changed and why, and §19 lists the rejected
alternatives with reasons.

The previous 385 commits are preserved in an offline bundle outside this
repository and are not part of this history.
