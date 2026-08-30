# Architecture

A short orientation for implementers: why the system has this shape, not how to
operate it. The binding contract is [`../spec/blueprint.md`](../spec/blueprint.md),
and where this document disagrees with it, this one is wrong.

Until the 0.9.5 fold completes, two incremental layers still sit on top of the
baseline — [`../history/blueprint-0.9.1.md`](../history/blueprint-0.9.1.md) and
[`../history/blueprint-0.9.2.md`](../history/blueprint-0.9.2.md) — and the later layer
wins where it explicitly amends an earlier one. That arrangement is being
retired, not extended (`../authoring.md` AUTH-7.2).

## Shape

```text
┌──────────────────────────────────────────────────────────────┐
│ selected app                                                  │
└───────────────────────────┬──────────────────────────────────┘
                            │ connect() / sendmsg()
┌───────────────────────────▼──────────────────────────────────┐
│ physical interface, TC egress, chain 0, per-iface dynamic pref│
│   flx_cap_l2  (ARPHRD_ETHER)                                  │
│   flx_cap_l3  (ARPHRD_RAWIP, CLAT tun) + skb_change_head(14)   │
│                                                               │
│   not ours ─────────────────────────► TC_ACT_UNSPEC (direct)   │
│   admitted ─────────────────────────► bpf_redirect(flxrs0)     │
│   failed after admission ───────────► TC_ACT_SHOT              │
└───────────────────────────┬──────────────────────────────────┘
                            │ veth_xmit
┌───────────────────────────▼──────────────────────────────────┐
│ flxrs1, TC ingress: flx_in                                     │
│   bpf_skb_change_type(PACKET_HOST)                             │
│   TCP SYN  ─► lookup listener ─► bpf_sk_assign ─► TC_ACT_OK     │
│   TCP other ─────────────────────────────────► TC_ACT_OK        │
│   UDP      ─► lookup listener ─► bpf_sk_assign ─► TC_ACT_OK     │
└───────────────────────────┬──────────────────────────────────┘
                            │ ip rule pref 100 iif flxrs1 → table 20260
                            │ local default dev lo
┌───────────────────────────▼──────────────────────────────────┐
│ sing-box tproxy inbound (official binary, IP_TRANSPARENT)      │
└──────────────────────────────────────────────────────────────┘
```

## Why this shape and not another

Two facts, both established from primary sources and device evidence, remove
every alternative:

1. **UDP's original destination cannot be recovered from a cgroup hook.** The
   `IP_RECVORIGDSTADDR` cmsg is produced by the kernel in `udp*_recvmsg` by
   reading the packet's own IP header. A `BPF_CGROUP_UDP4_RECVMSG` program can
   only rewrite the sockaddr handed back to userspace. So any design that keeps
   the real destination *and* leaves the engine unmodified must let the real
   headers reach the listener.
2. **A one-time cgroup snapshot cannot establish a safe ownership seam.** The
   clean Phase 0 snapshot had no root-cgroup `SOCK_ADDR` attachments even
   though the AOSP programs were loaded; Android can attach them dynamically,
   and a `flags=0` ancestor then prevents descendant coexistence. Flux therefore
   never attaches cgroup BPF and never competes for these slots.

`bpf_sk_assign()` satisfies both: it associates a socket with an skb and lets
the kernel deliver locally, without touching a single L3 or L4 byte.

## Crates

| Crate | Contains | Constraint |
|---|---|---|
| `flux-core` | config, selector, CIDR, ABI mirror, wire types, version math | No `libc`, no syscalls, `unsafe` forbidden. Tests run on any host |
| `fluxd` | reactor, netlink, BPF loader, network objects, engine supervision | The only crate that touches the kernel |
| `xtask` | build, packaging, release | Development host only, never shipped |

`fluxd → flux-core` and `xtask → flux-core`. Never the reverse. No platform,
testkit or backend-registry crate, and no trait abstraction layer for a single
implementation.

Two internal seams are load-bearing, inherited from the previous
repository's over-design review: raw netlink message construction lives only in
`fluxd/src/netlink/`, and raw `bpf(2)` only in `fluxd/src/bpf/`. Callers see
`create_veth`, `add_rule`, `attach_filter`, `publish_control` — never an
`nlmsghdr`.

The four deep modules are policy, dataplane, engine, and reactor. Their
interfaces are defined in `../history/blueprint-0.9.1.md` R091-14; no public trait is
introduced for a single implementation.

## Failure semantics

The single most important rule in the system:

| When | On failure |
|---|---|
| Before a TCP socket has a CAPTURED decision, or before the current UDP datagram redirects | `TC_ACT_UNSPEC` — the flow/datagram goes direct |
| After a socket has a CAPTURED decision | `TC_ACT_SHOT` — the packet is dropped |

There is no third option. Falling back to the real destination after admission
would leak traffic the user asked to proxy, so it is forbidden everywhere,
including on snapshot corruption and generation mismatch.

`TC_ACT_UNSPEC` rather than `TC_ACT_OK` matters: `TC_ACT_OK` ends the classifier
chain and would skip AOSP's CLAT and OEM filters that must still run for direct
traffic.

## State

`fluxd` is a single-threaded epoll reactor with no periodic polling. Event
sources: rtnetlink, inotify, pidfd, signalfd, the BPF fault ring buffer, the
control socket, timerfd.

Three top-level states — `Disabled`, `Inactive`, `Active`. The only way into
`Active` is one `control_root` map-in-map pointer swap after engine readiness
and at least one physical capture interface have both closed; the first action
on leaving it is always publishing `active = 0`.

One distinction that is easy to get wrong and expensive when wrong:
**capture-side drift is routine, core drift is not.** netd deletes the physical
`clsact` qdisc when an interface leaves a network, taking our filters with it.
Flux removes only that interface from coverage and waits for netd to recreate
`clsact`; it then re-runs per-interface admission. While another capture
interface remains active, global `active` is untouched; if the last active
interface disappears, Flux publishes inactive but may keep the ready engine
waiting. Flux never creates a physical-interface `clsact`. Escalating every
single-interface drift to a global transaction would blip unrelated proxied
flows on every Wi-Fi reconnect. See `../spec/blueprint.md` §8.5.1 as amended by
R091-05 and R091-10.
