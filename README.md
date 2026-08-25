# Flux-rs

Transparent per-app proxying for rooted Android, built on eBPF and an
**unmodified** official [sing-box](https://github.com/SagerNet/sing-box).

> **Status: 0.9.0 skeleton.** This commit contains the complete design contract
> and the crate structure. **No functionality is implemented yet.** Every
> command exits with `EX_UNAVAILABLE`. See [Roadmap](#roadmap).

## What it does

You pick apps. Their traffic — including the DNS queries they make through the
Android system resolver — is handed to sing-box with the **original destination
address and port intact**. Everything else on the device keeps using the normal
Android network path, untouched.

## How it works

```text
selected app socket
  └─ TC egress on the physical interface
     ├─ classify by socket UID + destination CIDR bypass
     └─ bpf_redirect() into a dedicated address-less veth
        └─ TC ingress on the veth peer
           └─ bpf_sk_assign() -> sing-box TProxy inbound
```

Three properties fall out of that shape:

- **The original destination survives.** Nothing rewrites L3 or L4, so
  `IP_RECVORIGDSTADDR` and the transparent listener's `LocalAddr` report the
  real destination. This is why no sing-box patch is needed.
- **Unselected traffic is cheap.** It costs one map lookup and one hash miss,
  then continues down its normal path via `TC_ACT_UNSPEC`.
- **Failure is explicit.** Before admission, failure means "go direct". After
  admission, failure means "drop" — never a silent fall back to the real
  destination.

### Per-app DNS

Plaintext DNS from a selected app is captured with its correct UID and no extra
machinery. Android's `DnsResolver` `fchown()`s the resolver socket to the
requesting app, and `bpf_get_socket_uid()` reads `sk->sk_uid`, which follows
`fchown`. This is also why the iptables ecosystem cannot do it: `xt_owner` reads
`f_cred->fsuid`, which `fchown` does not touch, so those projects are forced to
hijack port 53 device-wide. Details in `docs/blueprint.md` §1.3.

## Requirements

| | |
|---|---|
| Root | Magisk (≥ v28.0 for `action.sh`), KernelSU, or APatch |
| Kernel | 5.15 or newer, with `CONFIG_VETH`, `CONFIG_NET_CLS_BPF`, `CONFIG_NET_SCH_INGRESS`, `CONFIG_BPF_SYSCALL` |
| Arch | `aarch64` |

Every capability is verified by actually performing the operation at activation
time, never by parsing `uname -r`. If anything is missing, Flux stays inactive
and `fluxd status` says which check failed and why.

## Known boundaries

These are published because they cannot be eliminated, not because they are
unimportant:

- Traffic sent on an app's behalf by another process (`DownloadManager`, sockets
  passed across binder) is attributed to that process, not the app. DNS is the
  documented exception.
- No flow stickiness across an interface change: if Android re-routes an
  existing socket onto a VPN tun or an interface Flux has not attached to, that
  traffic takes the normal Android path.
- Both legs are counted: the app's leg and sing-box's outbound leg. Per-UID
  totals in Android's settings will not match physical link bytes.
- App-requested DSCP marking is lost for proxied flows, because AOSP's
  `dscpPolicy` filter sits at egress pref 5 and captured packets leave the chain
  at pref 1.
- A sing-box event-loop livelock is undetectable from the data plane. There is
  no heartbeat, by design.

Full list with mechanisms: `docs/blueprint.md` §2.2.3.

## Roadmap

Phases are defined in `docs/blueprint.md` §17. Phase 0 is a throwaway spike that
must falsify nine assumptions on real hardware **before** implementation starts;
none of it has been run yet.

| Phase | Content | State |
|---|---|---|
| 0 | Nine on-device assertions (spike, discarded afterwards) | not started |
| 1 | `flux-core`: config, selector, CIDR | skeleton |
| 2 | Layout, single-instance lock | skeleton |
| 3 | Control plane, reactor | skeleton |
| 4 | Network objects, netlink | skeleton |
| 5 | BPF loader, data plane | skeleton |
| 6 | Engine supervision | skeleton |
| 7 | Module packaging, release | skeleton |

## Building

```bash
cargo build --workspace          # host build, no BPF
cargo test --workspace           # ABI layout assertions and pure logic
cargo clippy --workspace --all-targets -- -D warnings

FLUX_BUILD_BPF=1 cargo build     # requires a bpf-capable clang
cargo xtask package              # module ZIP (not implemented yet)
```

Without `FLUX_BUILD_BPF=1` the build embeds an empty BPF object so that the
workspace compiles and tests anywhere, including Windows. The loader refuses a
zero-length object, so such a build can never silently appear to work.

## Documentation

`docs/blueprint.md` is the implementation contract, not an overview. It records
the reasoning, the primary sources, and the rejected alternatives with reasons.
`bpf/include/flux_abi.h` is the sole source of truth for the data-plane ABI;
`crates/flux-core/src/abi.rs` mirrors it and asserts every offset at compile
time.

## License

GPL-3.0-only. See `LICENSE`.
