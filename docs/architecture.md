# Architecture

This is the short orientation. The binding document is
[`blueprint.md`](blueprint.md); where the two disagree, the blueprint wins.

## Shape

```text
┌──────────────────────────────────────────────────────────────┐
│ selected app                                                  │
└───────────────────────────┬──────────────────────────────────┘
                            │ connect() / sendmsg()
┌───────────────────────────▼──────────────────────────────────┐
│ physical interface, TC egress, chain 0 pref 1, direct-action  │
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

Two facts, both established from primary sources, remove every alternative:

1. **UDP's original destination cannot be recovered from a cgroup hook.** The
   `IP_RECVORIGDSTADDR` cmsg is produced by the kernel in `udp*_recvmsg` by
   reading the packet's own IP header. A `BPF_CGROUP_UDP4_RECVMSG` program can
   only rewrite the sockaddr handed back to userspace. So any design that keeps
   the real destination *and* leaves the engine unmodified must let the real
   headers reach the listener.
2. **Android already owns the cgroup `SOCK_ADDR` slots.** On Android 15/16 the
   root cgroup holds `inet4/6 connect`, `udp4/6 sendmsg` and `udp4/6 recvmsg`
   with `flags=0`, and the kernel refuses descendant attachment under a
   `flags=0` ancestor. Coexistence would mean displacing netd's hooks.

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

Two encapsulation boundaries are load-bearing, inherited from the previous
repository's over-design review: raw netlink message construction lives only in
`fluxd/src/netlink/`, and raw `bpf(2)` only in `fluxd/src/bpf/`. Callers see
`create_veth`, `add_rule`, `attach_filter`, `publish_control` — never an
`nlmsghdr`.

## Failure semantics

The single most important rule in the system:

| When | On failure |
|---|---|
| Before a socket has a CAPTURED decision | `TC_ACT_UNSPEC` — the flow goes direct |
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
`Active` is one `control_root` map-in-map pointer swap; the first action on
leaving it is always publishing `active = 0`.

One distinction that is easy to get wrong and expensive when wrong: **capture-side
drift is routine, core drift is not.** netd deletes the `clsact` qdisc every
time an interface joins or leaves a network, taking our filters with it. That
must be repaired per-interface without touching `active`. Escalating it to a
global transaction would blip every proxied flow on the device on every Wi-Fi
reconnect. See `blueprint.md` §8.5.1 and §26.
