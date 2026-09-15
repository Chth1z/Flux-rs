# Flux-rs

Flux-rs is transparent per-app proxying for rooted Android, implemented with
eBPF and an **unmodified** official
[sing-box](https://github.com/SagerNet/sing-box) binary. It does not create a
VPN, alter packets' IP addresses or ports, or take over traffic from apps you
did not select.

> **Status:** pre-release. The normative design is the 0.9.5 blueprint
> (`docs/spec/blueprint.md`); the implementation has caught up with it, and
> the workspace version stays at 0.9.0 until the device regression and every
> gate in §20 pass. A signed release tag is the only release channel — do not
> treat an Actions artifact or a third-party repack as one.

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
Flux WebUI. Flux does not need to be the first classifier in a dump: each
attachment must pass identity, ordering, and live reachability verification.
An OEM chain that makes the Flux filter unreachable leaves only that interface
Direct with a specific reason in `status`.

## Requirements

| Item | 0.9.0 requirement |
|---|---|
| Root manager | Magisk, KernelSU, or APatch (no minimum beyond module support) |
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

Verify the release's `Flux-rs-v<version>-arm64.zip` against the adjacent `SHA256SUMS`, then install
it from the Magisk, KernelSU, or APatch manager app. **A fresh install
lands as a disabled module on purpose**, so installation alone does not capture
traffic; upgrades preserve whatever you chose and never overwrite user configs.

The switch is your root manager's own module toggle. `fluxd` watches that file
with inotify, so toggling the module takes effect immediately instead of at the
next boot, and there is no separate switch file, no `action.sh` and no second
place to look. `fluxd enable` / `fluxd disable` write the same file. The
manager's module description doubles as a live status readout, for example
`🥰 [Active] gen 7 · 3 apps · rmnet_data0`.

The two authority files are:

- `/data/adb/flux-rs/config/flux.toml` — which apps, which destinations, which
  interfaces and which Wi-Fi networks, each as a mode plus a list, along with
  the subscription settings.
- `/data/adb/flux-rs/config/template.json` — the sing-box configuration
  template: DNS, routing rules, and the skeleton of the selector groups.

**You edit the template; Flux generates what the engine runs.** From the
template plus the subscription it produces `run/sing-box.<generation>.json`,
filling the selector groups that are still vacant and appending the refined
nodes. Everything else
passes through byte for byte, so what you wrote is what runs — and a
subscription update needs no manual merge.

The shipped bootstrap template is the original Flux module's, so both projects
present the same shape: DNS splitting with fakeip, `clash_mode` rules, remote
rule-sets, and `PROXY` as a menu over the regional groups `HK`/`TW`/`JP`/`SG`/
`US`. It contains no servers, no subscription and no credentials — those five
groups are empty, waiting for the subscription to fill them — and it declares no
inbound of its own, because Flux injects two tproxy inbounds. The original's
control panel is in the file too, commented out with its secret blank: a default
must not open a port that every app on the device can reach, but you should not
have to discover the panel exists either.

Until something fills those groups the template is not a runnable configuration,
and Flux says so instead of starting the engine on it: `check` and the module
description report which groups are waiting. A region your provider has no node
for becomes `DIRECT`, so one unused group never takes the configuration down.

**Flux never writes to anything under `config/`.** Reinstalling does not
overwrite it, and everything under `run/` can be deleted at any time and will be
rebuilt.

After editing the configuration, enable the module in the manager and reboot
once. Flux fetches the subscription and validates the complete configuration
before activation; the manager description reports the result. Later toggles
and saved configuration edits take effect without rebooting.

For details or diagnostics after that first reboot:

```sh
FLUXD=/data/adb/modules/flux_rs/bin/fluxd
$FLUXD status
$FLUXD check
```

`check` is optional diagnostics, not an activation prerequisite. It does not
fetch subscriptions, so a check before the initial fetch reports the empty
groups as `engine_config_unfilled`.

The manager's WebUI entry opens a redirect page for the external controller
configured in the template's optional `clash_api` block. When no controller is
configured, it explains how to enable one. The module toggle remains the only
switch.

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

The implementation contract is `docs/spec/blueprint.md`, one document, complete
on its own; **where it and the code disagree, the code is wrong.**
`docs/guide/architecture.md` is the short engineering orientation. The
data-plane ABI source of truth is `bpf/include/flux_abi.h`, mirrored and
layout-tested in Rust.

Flux-rs is GPL-3.0-only. The unmodified sing-box binary is
GPL-3.0-or-later; see `THIRD_PARTY_NOTICES.md` and the release's corresponding
source archive.
