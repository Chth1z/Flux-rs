# Flux-rs

Flux-rs is transparent per-app proxying for rooted Android, implemented with
eBPF and an **unmodified** official
[sing-box](https://github.com/SagerNet/sing-box) binary. It does not create a
VPN, alter packets' IP addresses or ports, or take over traffic from apps you
did not select.

> **Status:** the 0.9.0 implementation is in pre-release validation. A signed
> `v0.9.0` release tag is created only after every gate in
> `docs/blueprint.md` §20 passes. Do not treat an arbitrary Actions artifact or
> third-party repack as a release.

## What it does

For each packet leaving a supported physical interface, Flux reads the owning
socket UID. A selected app is redirected, without L3/L4 rewriting, to four
sing-box TProxy listeners. Unselected apps, fixed and user bypass destinations,
and unsupported interfaces continue through Android's normal classifier chain.

The failure boundary is deliberately exact:

- Before a TCP socket or UDP datagram is admitted, a missing capability,
  listener, interface attachment, valid snapshot, or supported packet layout
  means **Direct** (`TC_ACT_UNSPEC`). Android's CLAT and OEM filters still run.
- After a TCP socket has been admitted as captured, an internal failure drops
  that packet instead of silently leaking the connection to its real
  destination. Already-admitted TCP is therefore not promised fail-open.
- An engine event-loop livelock while its listeners remain present cannot be
  detected. There is no heartbeat or active connectivity probe.

Flux does not attach to VPN/TUN devices, bridge or tethering traffic, cgroup
hooks, or forwarded/LAN ingress. It does not modify netd fwmarks, replace AOSP
BPF programs, flush system qdiscs/rules, inject broad SELinux policy, or ship a
Flux WebUI. An OEM classifier that prevents Flux from being first-applicable
causes that interface to remain Direct with a specific reason in `status`.

## Requirements

| Item | 0.9.0 requirement |
|---|---|
| Root manager | Magisk, KernelSU, or APatch; Magisk v28+ for `action.sh` |
| CPU | arm64/aarch64 |
| Kernel floor | 5.15 |
| Base page | exactly 4096 bytes |
| Runtime | initial Android network namespace and the required BPF/TC/veth/RPDB capabilities |

The version and kernel floor are courtesy filters, not capability proof.
Activation performs the real operations and stays `Inactive`/Direct on the
first unsupported capability or ownership conflict. A 16 KiB base-page device
is unsupported in 0.9.0 because the pinned official sing-box ELF has 4 KiB
`PT_LOAD` alignment; `fluxd` itself is built with at least 16 KiB alignment so
it can report the refusal cleanly.

## Per-app DNS boundaries

Android normally `fchown()`s plaintext system-resolver sockets to the requesting
app. Flux therefore captures a selected app's UDP/TCP port-53 queries with the
same per-app boundary as its other traffic. Four qualifications are part of
the product contract:

1. System Private DNS (DoT/strict encrypted DNS) uses the system DNS UID and is
   not captured. Flux does not turn it off. sing-box cannot apply its domain
   rules to those resolutions.
2. On an OEM configuration with `enforce_dns_uid`, even plaintext system DNS is
   attributed to the system DNS UID. It remains Direct and `status` reports the
   degradation.
3. mDNS (`224.0.0.251:5353` and `[ff02::fb]:5353`) is in the fixed multicast
   bypass and remains Direct.
4. Capturing port 53 is not enough to activate sing-box domain routing. The
   user config needs a `sniff` rule and a `hijack-dns` rule. The shipped default
   contains both; `fluxd check` warns, but does not reject, if equivalent DNS
   handling is absent.

sing-box may additionally use `package_name`/`process_name` in its own route and
DNS rules. Flux decides **whether** a UID is captured; sing-box decides **how**
captured traffic is routed.

## Other published boundaries

- Android records both the selected app's leg and sing-box's outbound leg.
  Per-app/system traffic statistics can therefore be roughly doubled; Flux does
  not falsify those counters.
- Traffic sent on an app's behalf by `DownloadManager`, a media/system service,
  or another delegated process belongs to that process and is not captured for
  the requesting app. System DNS is the documented `fchown()` exception.
- A selected VPN provider's outer socket may itself be selected; Flux warns but
  does not try to infer intent. Traffic already routed through a VPN TUN is
  excluded.
- An app's explicit Android network identity is not inherited by sing-box's
  new root-owned outbound socket. Official sing-box outbound controls remain
  the user's responsibility.
- VLAN/QinQ, unknown link layouts, unverified CLAT ordering, and interfaces
  shadowed by an OEM filter remain Direct. Support is proven at runtime, not by
  a device-model whitelist.

## Install and first use

Install `Flux-rs-v0.9.0-arm64.zip` from the Magisk, KernelSU, or APatch manager
app, verify it against the adjacent `SHA256SUMS`, then reboot. A fresh install
creates `/data/adb/flux-rs/disable`, so installation alone does not capture
traffic and upgrades preserve the existing switch and user configs.

The two authority files are:

- `/data/adb/flux-rs/config/flux.toml` — selected `userId:packageName` apps and
  CIDR bypasses.
- `/data/adb/flux-rs/config/sing-box.json` — the complete user-owned official
  sing-box configuration. Flux only injects its two generated TProxy inbounds.

On first daemon start, the known Clash API bootstrap marker in the default
config is atomically replaced with a random 256-bit secret. Reinstalling does
not overwrite either config.

```sh
FLUXD=/data/adb/modules/flux_rs/bin/fluxd
$FLUXD check
$FLUXD enable
$FLUXD status
```

The manager's Action button performs one explicit operation: it reads current
status, enables a disabled module or disables an enabled one, and updates the
module description with state, generation, app count, and admitted TCP/UDP
counts. It never reads stdin or hides a toggle state elsewhere.

`fluxd bugreport` creates a redacted diagnostic ZIP. Raw config files are never
included and logcat is excluded by default; `--with-logcat` is explicit opt-in
and `--raw` disables address redaction with a warning.

## Build and verify

The Rust toolchain, Cargo lockfile, Android NDK revision, engine asset, and BPF
ABI are pinned. Packaging has one entry point and an exact 15-file allowlist.

```sh
cargo test --workspace
cargo xtask doc-check
cargo xtask template-check
cargo xtask verify-package
```

`verify-package` performs two clean Android release builds and requires
byte-identical module ZIPs. It verifies the official sing-box archive and
binary size/SHA-256, enforces its recorded ELF alignment, embeds the current git
commit as build provenance, and writes the ZIP plus `dist/SHA256SUMS`.

Only a signed annotated `v*` tag whose suffix exactly matches
`[workspace.package] version` can run the release workflow. The release also
publishes the exact sing-box Corresponding Source archive pinned by
`engine.lock`, including upstream build scripts and dependency manifests.

## Documentation and license

`docs/blueprint.md` is the normative implementation contract;
`docs/architecture.md` is the short engineering orientation. The data-plane ABI
source of truth is `bpf/include/flux_abi.h`, mirrored and layout-tested in Rust.

Flux-rs is GPL-3.0-only. The unmodified sing-box binary is
GPL-3.0-or-later; see `THIRD_PARTY_NOTICES.md` and the release's corresponding
source archive.
