# Flux-rs Design Blueprint

- Specifies: **1.0.0 candidate, pending owner review**. This is the single normative blueprint and it is edited
  in place; there are no incremental layers (`../authoring.md` AUTH-7.2).
- Nature: **the implementation contract.** Where this document and the code
  disagree, the code is wrong. Where this document and `../philosophy.md`
  disagree, this document is wrong.
- Audience: implementers, human or model. It assumes no knowledge of the
  previous repository and requires no earlier document.
- ABI source of truth: `bpf/include/flux_abi.h`, which defines `FLUX_ABI_MAGIC`
  and carries its change log — the value is not restated here, so this document
  cannot lag behind it; data-plane skeleton: `bpf/flux.bpf.c`.
- Section numbers are global and never reused. `§N → file` mapping and the
  identifier rules are in `../index.md`; current progress is in
  `../plan/implementation.md`, never here.

## How strong is each claim

Two independent dimensions. An assertion carries one word from each column, and
prose that carries neither does not belong in this document (`../authoring.md`
AUTH-2).

| Obligation | Meaning |
|---|---|
| **MUST / MUST NOT** | The contract. Violating it is an implementation defect. |
| **SHOULD** | The default engineering choice; replaceable once the reason is recorded. |

| Evidence | Meaning |
|---|---|
| **Verified** | Checked this round against first-party kernel source, official documentation or official configuration, with the citation given inline. |
| **Measured** | Observed on a real device; the device, kernel version and date are named, and the raw output is in `../../tools/phase0/results/`. |
| **Inferred** | Follows from stated premises, which are named. Never written as though measured. |

RFC 2119 supplies only the first column. The second exists because this project
has twice reached a correct conclusion through a wrong argument, and a reader
who cannot tell a verified claim from an inferred one cannot catch the next one.

The design overturned itself **8 times** — 5 before measurement, 3 during the
measurement round, two of those three against conclusions written by the same
author who then disproved them. Every one is recorded as
*claimed / actual / disposition* in `../history/review-log.md` §0.6. **A
conclusion that is right for the wrong reason is more dangerous than one that
is simply wrong**, because the next decision builds on the reason; that table
is worth more than the conclusions it corrects.

C and Rust in code blocks are signatures and algorithm skeletons meant to remove
ambiguity. Implementers supply bodies, error paths and tests.

## Where the previous revision numbers went

0.9.5 folds the 0.9.0 baseline and the `R091-*` / `R092-*` incremental layers
into this one document. **The section numbers did not move**; only the layering
did. This table maps each retired revision to the section that now carries it,
so that a commit message or comment naming an `R09x` number can still be
resolved.

`R09x` identifiers are retired: none will be issued again, and code cites `§`
instead, because a section number survives a re-issue and a version-scoped one
does not (`../governance.md` GOV-6.2).

| Retired | Now carried by |
|---|---|
| R091-01 failure semantics · R091-02 cost of unselected traffic | §2.2, §14.1 |
| R091-03 scope · R092-08 webroot | §1.2, §1.3, §13.1, §28 |
| R091-04 paths and schema · R092-02 allow/deny lists and `@file` | §11.1, §11.2 |
| R091-05 preference and reachability · R092-10 renamed `reachable` | §8.5, §8.6, §24 |
| R091-06 cgroup facts | §3.2 |
| R091-07 capacity and the 6.6 LPM defect · R092-11 RESERVED/POLICY split | §1.6, §6.1, §7.3 |
| R091-08 listener addresses and ports · R092-03 injected inbounds | §9.0, §9.1, §9.6 |
| R091-09 disable/stop/uninstall · R091-10 top-level state | §8.8, §10.1, §26 |
| R091-11 control interface and CLI · R092-06 event sources | §10.3, §10.4, §10.6 |
| R091-12 packaging and installation | §13.1, §13.2 |
| R091-13 status/plan/history layering | `../plan/implementation.md`, `../history/` |
| R091-14 deep modules and seams | §5 |
| R091-15 verification by platform · R092-04 hard and soft gates | §15.1, §23 |
| R092-01, R092-05 subscription and config generation | §28 |
| R092-07 SSID-conditional activation | §29 |
| R092-09 user-facing wording | §27, `../guide/` |

---

# Part 0: Independent review and the corrections it produced

> **Moved out of this document** → `../history/review-log.md`. The section number is unchanged. It holds every claimed / actual / disposition correction.
# Part 1: The product contract

## 1.1 Identity

| Item | Value |
|---|---|
| Product / repository | `Flux-rs` |
| Version | the workspace manifest is the only source; `versionCode` and the module artifact name are derived from it (§13.4). Never restate a literal version here |
| root module id | `flux_rs`, installed by the manager to `/data/adb/modules/flux_rs` |
| Product state root | `/data/adb/flux-rs`, `root:root 0700` |
| ABI / target | `arm64-v8a` / `aarch64-linux-android`, API 31 |
| Build API level | `aarch64-linux-android` API 31 — a compile target, not a runtime gate |
| Kernel baseline | **5.15** (owner, 2026-08-25). The real gate is a successful load, attach and behaviour at run time; admitting a device by version string is forbidden. Consequence: devices that shipped with Android 12 (GKI 5.10 at most) are out of scope, so the supportable set is roughly devices that shipped with Android 13 or later |
| Base page | `4096` only; any other value means Inactive/Direct |
| Root manager | one module envelope shared by Magisk, KernelSU and APatch |
| Engine | unmodified official sing-box; builds resolve the latest stable release (§9.7) |
| Licence | Flux-rs's own code is `GPL-3.0-only`; third parties keep theirs |
| Data-plane ABI | `FLUX_ABI_MAGIC` (`bpf/include/flux_abi.h`), unrelated to SemVer |

## 1.2 What Flux MUST do

1. Resolve `userId:packageName` to a UID exactly, and state the shared-UID
   merge semantics openly.
2. Capture IPv4/IPv6 TCP client flows **initiated by** a selected UID — one
   immutable decision on the first `SYN && !ACK` — and IPv4/IPv6 UDP datagrams
   sent by that UID.
3. Apply the fixed safety bypass, the device's own addresses, and the user's
   CIDR bypass inside eBPF. Resolve no domain names.
4. **Per-app DNS, precisely.** A selected app's plaintext DNS — including the
   part the system resolver sends on its behalf — enters the engine with the
   rest of its traffic, and an unselected app's DNS is untouched. Mechanism and
   boundaries in §1.3.
5. Preserve the original L3/L4 headers and hand the packet to the official
   sing-box TProxy inbound.
6. Manage the engine's `check`, start, candidate switch, exit and crash
   recovery.
7. Drive every state change from rtnetlink, inotify, pidfd, signalfd, the BPF
   ringbuf, the control socket and timerfd. **No periodic polling** (§29.3
   records the one deliberate exception and why it is not polling).
8. Stay Direct on unknown device layouts, missing capabilities, object
   conflicts and unsupported paths, and give the per-item reason in `status`.
9. Produce a single clean module ZIP that installs under all three managers.
10. Generate the engine configuration from a user-owned template and an
    optional subscription (§28), never by editing a user-owned file.

## 1.3 Non-goals

Hotspot, tethering, LAN ingress, bridging and forwarded traffic; inbound TCP
server proxying; ICMP, ICMPv6, ESP and IPv6 jumbograms; nesting inside,
taking over, or bypassing a VPN TUN; gateway, side-router, container and
multi-netns deployments; nftables, iptables, a TPROXY-mark backend or any
runtime backend selector; a TUN backend or a userspace TCP/IP stack; **any
cgroup BPF attach**, including the child `SETSOCKOPT` and `POST_BIND` slots;
SOCKMAP or `pidfd_getfd` listener handoff; domain, DNS, SNI, rule-set, node
selection or connection-quality learning inside eBPF; multiple proxy cores,
modes, plugins or a backend registry; a Flux-built WebUI or a Flux-owned Clash
proxy layer; policy invented from online learning or traffic statistics;
recovery-mode installation, 32-bit, x86 or riscv; a 16 KiB base page; broad
SELinux patches; replacing AOSP BPF programs or flushing system qdiscs and
rules; detecting, migrating, rejecting or cleaning up an older Flux
installation; pre-building a schema registry, migration framework or
compatibility matrix for a future version.

**Subscription is no longer on this list.** It was excluded from 0.9.1 by
R091-03 as a scope freeze rather than a permanent refusal, and the owner moved
C11 into scope on 2026-08-30; it is specified in §28. A Flux-built WebUI (C8)
and an out-of-the-box control plane (C10) remain excluded, and §28.8 draws the
line between those and the twelve-line redirect that does ship.

### 1.3.1 Per-app DNS works because AOSP already calls `fchown`

**Verified against `clone/aosp-DnsResolver`, line by line: Android already
changes the owner of a plaintext DNS socket to the app that asked for the
resolution.**

- `res_send.cpp:789` and `:1092` —
  `const uid_t uid = statp->enforce_dns_uid ? AID_DNS : statp->uid;`, where
  `statp->uid` is the requesting UID, taken by `DnsProxyListener` from the
  dnsproxyd peer credentials.
- `resolv_private.h:245-256` — `resolv_tag_socket()` calls netd's
  `tagSocket(sock, TAG_SYSTEM_DNS, uid, pid)` and then **immediately performs
  `fchown(sock, uid, -1)`**.
- `binder/android/net/ResolverOptionsParcel.aidl:48-57`, verbatim:

  > "The default behavior is that plaintext DNS queries are sent by **the
  > application's UID using `fchown()`**. DoT are sent with an UID of AID_DNS.
  > … **false: set application uid on DNS sockets (default)**"

On the kernel side, the definition of `sk->sk_uid` includes `fchown` by
construction. Linux commit `86741ec25462` ("net: core: Add a UID field to
struct sock") states that the UID is set when userspace calls **`socket()`,
`fchown()` or `accept()`**; the implementation is `sockfs_setattr()`
synchronising `sock->sk->sk_uid` on `ATTR_UID`. Its author, Lorenzo Colitti, is
an Android networking engineer, and the field exists for exactly this kind of
attribution. `bpf_get_socket_uid()` reads that same field
(`net/core/filter.c` → `sock_net_uid()`).

**Therefore `bpf_get_socket_uid(skb)` on TC egress returns the requesting app's
UID for a plaintext DNS packet sent by netd.** The `uid_policy` lookup of §7.3
covers system DNS **for free** — no port special case, no reading of a private
AOSP map, no change to the engine's UID, no device-wide `:53` hijack. That is
per-app DNS routing with zero additional mechanism.

Note what the last row of the table below means for self-capture: **the engine
excludes itself structurally.** sing-box runs as root, its own upstream DNS
queries carry uid 0, and §1.4 refuses `appId` 0 outright, so uid 0 can never be
in `uid_policy`. So Flux captures the app's system DNS without swallowing the
engine's. A device-wide `:53` hijack needs a dedicated non-root UID to reach the
same place; here it comes for nothing.

| Who sent the DNS | `sk_uid` seen at TC egress | Captured |
|---|---|---|
| Selected app's own socket (Cronet, QUIC-internal DNS, direct `sendto(:53)`) | that app | **yes** |
| Selected app calls `getaddrinfo()`, netd sends plaintext UDP/TCP :53 | **that app**, via netd's `fchown` | **yes** |
| An unselected app's DNS | that app, absent from `uid_policy` | no — which is the point |
| Private DNS (DoT/DoH) | `AID_DNS` (1051) | no, see §1.3.3 |
| sing-box's own upstream DNS | root (0) | no — self-capture is structurally impossible |

**Capturing system DNS device-wide instead** — option B of Q2 in
`../history/rejected-and-deferred.md` §21.1 — costs three things that must be
accepted together:

1. the engine would need a dedicated non-root UID, because capturing uid-0 `:53`
   would swallow the engine's own upstream DNS into a loop — the alternative
   being to force the user's `dns` to DoH/DoT only, plus a validator to enforce
   it;
2. DNS would become a device-wide behaviour, so **unselected** apps' DNS would
   also traverse the proxy, producing the inverted mismatch of "DNS proxied,
   traffic direct";
3. Private DNS would have to be dealt with. `clone/box4magisk/box/scripts/box.service:50-58`
   runs `settings put global private_dns_mode off` for the duration and restores
   it on stop, because DoT uses port 853 rather than :53 and hijacking 53 cannot
   see it. In other words the complete form of that option includes turning off
   the user's encrypted DNS on their behalf.

### 1.3.2 Why the iptables/TPROXY family cannot do this

The difference is not Android. **The two mechanisms read different fields of
`struct sock`:**

| Mechanism | Field read | Sees netd's `fchown`? |
|---|---|---|
| `iptables -m owner --uid-owner` (`xt_owner`) | `skb->sk->sk_socket->file->f_cred->fsuid` — **the credentials of the process that opened the socket** | **No.** `fchown` changes the inode owner and `sk_uid`, not `f_cred` |
| **`bpf_get_socket_uid()`** | **`sk->sk_uid`** | **Yes**, by the semantics of commit `86741ec25462` |

AOSP's own test comments state it outright
(`clone/aosp-DnsResolver/tests/resolv_test_utils.h:48-49`):

> "netd calls `fchown()` on the DNS query sockets, and **`iptables -m owner`
> matches the UID of the socket creator, not the UID set by `fchown()`**."

**That one sentence explains the whole ecosystem.** Those root modules did not
*choose* a device-wide `:53` hijack; `xt_owner` left them no choice, because
their per-app matching is structurally blind to DNS. Falling back to port
hijacking is what forces them to accept the inverted mismatch — unselected apps'
DNS proxied too — and to turn off the user's Private DNS. Read the table below
as **different compromises under one constraint**, not as designs to borrow:

| Project | per-app selection | DNS handling | Evidence (first-party source under `clone/`) |
|---|---|---|---|
| AndroidTProxyShell | `-m owner --uid-owner "$uid" -j ACCEPT/RETURN` in `APP_CHAIN` | `DNS_HIJACK_PRE` / `DNS_HIJACK_OUT` are **separate chains**; `redirect2` mode applies a global `--dport 53 -j REDIRECT` on `nat OUTPUT`, letting the core through first | `tproxy.sh:1226/1242`; `tproxy.sh:1342-1372` |
| box_for_magisk | `-m owner --uid-owner` / `--gid-owner`, **OUTPUT side only**; PREROUTING has no owner match at all. Its README says Android iptables cannot match PID, so process matching is done indirectly through GID — a **weaker** identity than ours | Port 53 handling at `box.iptables:458-464` sits **before** the app uid/gid block at 478+, making the rule order explicitly anti-per-app; `CLASH_DNS_LOCAL:568` REDIRECTs all UDP/53 after letting the core through; `box.iptables:177-178` additionally drops all IPv6 DNS unconditionally | `box/scripts/box.iptables` |
| box4magisk | `APP_PROXY_ENABLE` / `APP_PROXY_MODE` / `PROXY_APPS_LIST`, in the same `userID:packageName` form | A separate global switch `DNS_HIJACK_ENABLE` (0 off / 1 tproxy / 2 redirect) plus `DNS_PORT` | `box/scripts/tproxy.conf` |
| CHIZI sing-box eBPF | `uid_bypassed(config)` include/exclude inside the cgroup hook | Attaches at the cgroup2 **root**, so it can see netd's socket, and with `dns_mode: hijack` **skips the UID check entirely for `:53`** — abandoning per-app DNS semantics | `common/ebpf/native/cgroup.bpf.c:491-494` |
| dae / honk | Process identity from `sock_create` / `connect4/6` / `sendmsg4/6` on cgroupv2, maintaining `COOKIE_PID_MAP` | Domain association by intercepting the DNS port; the documentation concedes UDP state is hard to maintain and needs `must_direct` to exempt whole ports | `honk/crates/honk-ebpf/src/cgroup.rs`; dae `docs/en/how-it-works.md` |

**Neither dae's process identity nor CHIZI's view of netd ports to a TC data
plane on Android.** Both depend on the cgroup attach types Android already holds
exclusively with `flags=0` (§3.2, with the source review at
`../history/review-log.md` §0.5.2). CHIZI avoids self-capture using the
**TGID**, which requires the process context a cgroup hook has and TC egress,
running in softirq, does not (§0.5.3).

**netd does know the requesting UID internally** and uses it to pick a network:
`DnsProxyListener` reads `const uid_t uid = cli->getUid()` and
`NetworkController::getNetworkForDns(netId, uid)` decides between an explicitly
selected network, that UID's VPN if it provides DNS servers, and the default.
VpnService gets per-app DNS from the platform for free this way. **`fchown` puts
the same attribution into the packet's socket owner**, so an eBPF data plane can
reach it too — netfilter simply reads the wrong field.

### 1.3.3 Three residual DNS boundaries, to be stated plainly

**① Private DNS (DoT / DoH strict mode) is not captured, and Flux does not turn
it off.** AOSP deliberately attributes encrypted DNS to `AID_DNS` (1051) rather
than to the app: `DnsTlsSocket.cpp:82`, `DnsTlsTransport.cpp:107` and
`PrivateDnsConfiguration.cpp:593` all call
`resolv_tag_socket(fd, AID_DNS, NET_CONTEXT_INVALID_PID)`. It runs over :853 or
:443 on long-lived connections shared across apps, so it is inherently not
per-app attributable.

Consequence: with system Private DNS on, resolution leaves over DoT and does not
pass through Flux. That is **good for privacy** — it was already encrypted — but
it means sing-box cannot see the resolution and cannot use its own DNS to decide
the destination IP. `clone/box4magisk/box/scripts/box.service:50-58` handles this
by running `settings put global private_dns_mode off` for the duration.
**Flux MUST NOT do that.** Changing a user's system settings on their behalf is
not ours to do. The correct behaviour is to detect and report: when
`private_dns_mode` is not `off`, `status` says that system encrypted DNS is on
and that name resolution does not pass through Flux, and the user decides.

**② `enforce_dns_uid` destroys the attribution.**
`ResolverOptionsParcel.aidl:48-57` defines an option an OEM or a network
configuration may enable, after which plaintext DNS also uses `AID_DNS`. AOSP's
own comments argue against it ("decreases battery life", "data usage … attributed
to the OS instead of to the requesting app"), so it is rare. Detection is direct:
captured :53 traffic carrying `sk_uid == 1051` means the device has it on. System
DNS then degrades to not being per-app capturable — **the behaviour is
non-capture, which is not an error** — and `status` reports it.

**③ mDNS is not captured.** `.local` resolution goes to `224.0.0.251:5353` and
`[FF02::FB]:5353`, which fall inside the fixed bypass prefixes `224.0.0.0/4` and
`ff00::/8`, and is therefore direct. That is the correct behaviour.

One further `fchown` site, `getaddrinfo.cpp:1330`, is guarded by
`uid > 0 && uid != NET_CONTEXT_INVALID_UID`. Its semantics match the above and
it changes no conclusion.

### 1.3.4 The engine config must handle :53, and the shipped default does

Because a selected app's DNS arrives at the tproxy inbound, the configuration
MUST tell sing-box what to do with it. Otherwise sing-box forwards it as
ordinary UDP to the original DNS server — functional, but it gives up domain
routing entirely. The standard form is a `hijack-dns` action in `route.rules`,
which is what the sing-box example in `clone/AndroidTProxyShell/README.md` uses:

```jsonc
{
  "route": {
    "rules": [
      { "action": "sniff" },
      { "type": "logical", "mode": "or",
        "rules": [ { "port": 53 }, { "protocol": "dns" } ],
        "action": "hijack-dns" }
    ]
  }
}
```

`hijack-dns` hands the datagram to sing-box's `dns` module, so domain rules,
`dns.rules` and fakeip all take effect — **and only for the selected apps**.
This is the substantive advantage over a device-wide hijack: the scope of DNS
routing and the scope of traffic routing are **exactly the same set**.

Flux MUST NOT inject these rules. Routing and DNS are sing-box's authority
(§9.6). But:

- the shipped `etc/default-template.json` MUST contain both rules, as a working
  starting point (§27.2.3);
- `fluxd check` MUST warn, and MUST NOT refuse to start, when the user's config
  has no `hijack-dns` or equivalent :53 handling (§23);
- `../guide/` must explain what the two rules do.

### 1.3.5 The second layer of precision: `package_name` rules work in sing-box

**Verified against `clone/sing-box-official-1.13.19`, line by line:** the
official Android binary initialises a PackageManager of its own when running
**standalone**, with no GUI or library platform interface:

```go
// route/network.go:175-192
if C.IsAndroid && r.platformInterface == nil {
    packageManager, err := tun.NewPackageManager(...)   // reads /data/system/packages.xml
    ...
    r.packageManager = packageManager
}
```

`route/router.go:130-146` therefore builds a `process.NewSearcher{PackageManager: ...}`, which on Android resolves to `common/process/searcher_android.go`:

```go
_, uid, err := querySocketDiagOnce(family, protocol, source)   // NETLINK_SOCK_DIAG on the source socket
appID := uid % 100000
packageNames = s.packageManager.PackagesByID(appID)
```

Because **the source address is never rewritten**, the source the engine sees is
the app's real IP:port and SOCK_DIAG finds that socket. Therefore:

- users can write **`package_name`** and `process_name` in `route.rules` and
  `dns.rules`, choosing a different outbound or DNS per app;
- **this holds for system-resolver DNS as well.** inet_diag's `idiag_uid` comes
  from `sock_i_uid(sk)`, the inode owner, which is precisely the field `fchown`
  writes — the same chain as `sk_uid` in §1.3.1. So an app's system DNS is
  attributed to that app's package name inside the engine too.

The two layers of precision divide as follows:

| Layer | Decides | Basis |
|---|---|---|
| Flux, in-kernel at TC | **whether** to capture | `uid_policy` lookup on `bpf_get_socket_uid()` |
| sing-box, in userspace | **where it goes** once captured: outbound, DNS server, rule-set | SOCK_DIAG → appId → package name |

Flux MUST NOT inject any `package_name` rule and MUST NOT maintain a package
table on the user's behalf; that is sing-box's authority. `../guide/` should say
the capability exists, because it is the second half of precise routing.

**Unproven:** whether `tun.NewPackageManager` can read the package database on a
given device. On failure sing-box only warns and continues, and `package_name`
rules then silently match nothing.

**The user's CIDR bypass applies to :53 as well.** The previous cgroup
implementation had `should_bypass_v4/v6` return 0 whenever `dport == 53`, so a
user bypass could never exempt port 53
(`crates/flux-platform/src/bpf/prog/flx_sock_addr.c:261-292`); CHIZI's
`dns_mode: hijack` goes further and skips the UID check outright. **Flux adopts
neither.** Writing `192.168.0.0/16` into the bypass list is an explicit statement
that the LAN goes direct; forcing an app's query to its router at
`192.168.1.1:53` through the proxy anyway would break local name resolution, as
hidden behaviour the user cannot turn off. Let the explicit configuration speak.
A user who wants DNS never bypassed simply keeps the DNS server out of the
bypass list.

## 1.4 Unit of selection, and the limits of identity

- The configuration unit is `userId:packageName`; the kernel enforcement unit is
  `UID = userId * 100000 + appId`.
- **`appId` 0 is never accepted**, and that single refusal is what the loop
  argument of §7.4 rests on: the engine runs as root, so a uid it cannot be
  named by is a uid it cannot capture itself through.
- **Every other uid `packages.list` names is the user's to select**, including a
  platform one such as `android` (1000) or `com.android.shell` (2000). Ordinary
  apps occupy `[10000, 19999]`; selecting outside it is a deliberate act, so
  `check` and `status` warn, naming the entry and what it costs — for uid 1000,
  that Android's connectivity validation, DHCP and time sync run there and the
  device reports no internet whenever the proxy cannot carry their traffic.
  Flux does not refuse it: the user is root on their own device, and a proxy
  that silently drops the app it was asked to proxy is the failure mode this
  project exists to avoid (PHIL-6).
- **Blacklist mode expands only `[10000, 19999]`.** "Proxy everything except
  these apps" must never sweep the platform in; a platform uid enters the policy
  only by being written down.
- A shared UID selects every package and process under it, with no way to
  distinguish them per packet. `check` and `status` MUST list every package
  sharing the UID.
- Isolated UIDs (90000+), SDK sandbox UIDs and temporary child UIDs do not
  follow automatically.
- **Traffic sent on an app's behalf is attributed to the sender, not the
  requester.** DNS is the **exception**, because AOSP gives the attribution back
  with `fchown` (§1.3.1); nothing else gets that treatment. A `DownloadManager`
  download, `MediaProvider`, a socket passed across Binder, and connections made
  by system services on an app's behalf all appear at TC egress with the
  **sending process's UID**, and are therefore **not** captured. CHIZI lists the
  same boundary for its package policy. This is an inherent property of UID-level
  capture rather than a defect, and it MUST be stated to users.
- Selecting a VPN provider captures its outer socket, nested. `check` and
  `status` warn where they can, but do not refuse.

## 1.5 Trust and threat boundary

Trusted: device root, the three root managers, the module directory, the local
configuration administrator, and the user's sing-box JSON — treated as trusted
**code-level** configuration, since `sing-box check` validates syntax and
semantics rather than sandboxing anything.

**Not defended against:** a second hostile root, which can write the BPF maps,
change TC and the RPDB, or inject a veth; and a hostile local process that scans
the internal ports and wins a race with `IP_FREEBIND` on the same tuple while one
listener is briefly closed. Random ports and the SOCK_DIAG/PID/inode cross-check
at promotion only reduce the probability of a **non-adversarial** collision.
Presenting the current seam as security isolation against a hostile root or app
would be false assurance.

---

## 1.6 What eBPF can and cannot buy here

Three questions with one answer: how precise the routing is, whether eBPF can
accelerate anything, and whether it can carry a large CIDR set.

### 1.6.1 A large CIDR bypass is strictly better than ipset

`BPF_MAP_TYPE_LPM_TRIE` exists for this. Against the older Flux's
`BYPASS_SET_BACKEND=zone|ipset`:

| | iptables jump tree | ipset `hash:net` | **`LPM_TRIE`** |
|---|---|---|---|
| Cost of reaching the match | walk the chain | walk the chain to `-m set` | **none** — our program is already running; one helper call |
| Lookup complexity | O(rules) | O(1) hash, but retried per prefix-length bucket | O(prefix bits), far less in practice |
| Tens of thousands of CIDRs | not viable | viable | **viable** |
| Memory | one chain entry per rule | preallocated hash table | the kernel **forces `BPF_F_NO_PREALLOC`**; allocated on demand |

The last row is the one that matters: **`max_entries` is a ceiling for an
`LPM_TRIE`, not an allocation.** Setting it to 65536 costs nothing while unused.

For scale, the `chnroute` IPv4 list is roughly ten thousand entries, well inside
that. Bulk loading uses `BPF_MAP_UPDATE_BATCH` (5.6+, present on the 5.15
baseline), which admits thousands of entries per syscall.

### 1.6.2 This is not "move routing policy into Flux"

§1.4 confines Flux to coarse UID selection and leaves domains and rules to
sing-box. A large CIDR set looks like a breach of that, so the framing has to be
exact:

it is not routing policy, it is **avoiding a userspace round trip already known
to be useless**. If a destination would be judged direct by sing-box no matter
what, then capturing it, crossing the veth, copying it into userspace and having
sing-box send it again is pure waste. Bypassed in eBPF, those packets **never
leave their original path**.

The saving is concrete: a user who proxies a browser but whose traffic is mostly
domestic skips the veth hop, the userspace copy and a second TCP connection for
the majority of it.

**Two semantic boundaries MUST be stated:**

1. **Destination IP only, never domain.** It supplements sing-box's domain rules
   rather than replacing them.
2. **The bypass decision precedes sing-box and is final.** If a domain resolves
   to a bypassed IP, it is **not captured**, even when the user's sing-box
   configuration wants it proxied. This ordering must be visible in the
   documentation and in diagnostics, or it becomes the "why doesn't my rule
   work" question.

### 1.6.3 Capacity, corrected by measurement

Measured on SM-S9180: `packages.list` holds **429 apps** in the
`[10000, 19999]` range. The original constants were
`FLUX_UID_SELECTED_MAX = 128` and `FLUX_UID_POLICY_MAX_ENTRIES = 512`.

So **selecting every third-party app — the most natural thing a user might
ask for — was structurally impossible.** The 512 was worse than it looks: by the
ABI, a `FLUX_UID_DRAINING` entry is **never removed within a boot**, because
removing it would leak an already-captured socket's packets to the real
destination. Every change to the selection therefore accumulates draining
entries, and 429 selected plus a few edits exceeds 512.

The capacities are the ones below, and this table is the only place they are
stated in prose; `bpf/include/flux_abi.h` is the source of truth (§6.1).

| Object | Capacity | Basis |
|---|---:|---|
| `uid_policy` | 4096 | must hold selected plus a boot's accumulated draining. A preallocated HASH of 4096 × ~64 B ≈ 256 KB is acceptable |
| Simultaneously `SELECTED` | 1024 | covers selecting everything on a full device; 429 measured, with room to double |
| `bypass_v4` / `bypass_v6` | 65536 each | §1.6.1; `LPM_TRIE` with `NO_PREALLOC`, so unused capacity is free |
| `self_addr_v4` / `self_addr_v6` | 256 each | exact HASH, see §1.6.3a |
| `uid_stats` | 4096 | `PERCPU_HASH`, §1.6.6 |

Local addresses go only into the two self-address HASH maps and never into the
LPM. The desired policy set is therefore computed as three separate things:
`selected_uids`, the user and fixed LPM prefixes, and the dynamic self-address
set.

`uid_stats` is the second class of per-CPU state §7.1 permits. It updates only
on already-captured packets and does not touch the hot path of an unselected
UID.

### 1.6.3a The LPM trie crashes on 6.6.0–6.6.46

Before building a CIDR bypass on `LPM_TRIE`, a **kernel crash** has to be dealt
with. The source is CHIZI's sing-box eBPF branch documentation, which has long
field exposure on Android:

> Linux 6.6.0 through 6.6.46 carry a risk of an LPM trie UBSAN kernel crash.
> Where UID or package filtering, `bypass_rule_set` or shared-source CIDRs are
> involved, sing-box refuses to start the affected policy on a known-unfixed
> kernel. Upgrade to 6.6.47+, or use a vendor kernel carrying the upstream fix.

**This lands on us directly.** `android15-6.6` is one of the GKI branches inside
the supported range, and the failure is not degraded function — it is a **device
reboot**.

Three consequences:

1. **Local addresses use an exact HASH, not the LPM.** This holds independently
   of the defect and is the better design anyway: a local address is always a
   full-length prefix (`/32`, `/128`), so using LPM for an exact match was always
   waste. HASH is O(1) and deletes cleanly, which matters for the IPv6 privacy
   address rotation of §1.6.4. CHIZI avoids the crash the same way — "exact HASH
   maps for local addresses, avoiding some Linux 6.6 LPM trie crashes".

   The map set is therefore 12 rather than 9: `bypass_v4` / `bypass_v6` keep
   `LPM_TRIE` for **prefixes**, and `self_addr_v4` / `self_addr_v6` are added as
   `HASH` for local addresses. The two no longer share a capacity.

2. **A large CIDR set still needs the LPM, so a version gate is required.** When
   `uname -r` falls in 6.6.0–6.6.46, Flux MUST stay `Inactive` before creating or
   filling any LPM, MUST report `unsupported_lpm_trie_kernel:<release>`, and MUST
   NOT probe by performing a real LPM operation, because the probe itself can
   reboot the device.

   The BPF loader MUST enforce this gate itself, before creating any kernel
   object. The daemon, `fluxd check`, and device-test entry points all use the
   same loader; a check in the reactor alone cannot protect those other callers.
   Parse the leading release components only: a vendor suffix is not a patch
   version. The affected `6.6` series without a patch component is not evidence
   of the fix. The upstream change is
   [896880ff3086, backported in 6.6.47](https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/stable-queue/+/refs/tags/v6.12.41/releases/6.6.47/bpf-replace-bpf_lpm_trie_key-0-length-array-with-fle.patch).

   **The gate cannot be conditional on the user configuring a large list.** Every
   valid policy uses the fixed bypass LPM, so gating only on `bypass.files` would
   leave the default configuration exposed. This is the **only** place in the
   design where a kernel version string may deny activation, and the reason MUST
   be stated in the code comment; every other capability is decided by attempting
   the real operation (§1.1).

### 1.6.4 Local-address bypass MUST filter on the address flags

D7 requires every local unicast address to be injected into the bypass set
dynamically. **That requirement is incomplete**, and the older Flux's
`addrsyncd` shows the gap: its configuration carries an `ignore_addr_flags`
option accepting `temporary | optimistic | deprecated | tentative | dadfailed |
stable_privacy | managetempaddr`.

That was not over-engineering. It is necessary:

| Flag | Why it must be handled |
|---|---|
| `tentative` | DAD has not finished and the address is not usable yet; injecting it now is wrong |
| `dadfailed` | the address collided and will never be usable |
| `temporary` / `stable_privacy` | **IPv6 privacy addresses rotate**, commonly daily. Without filtering they accumulate until the self-address map is full |
| `deprecated` | still serving existing connections, so it **must be kept** — being deprecated is not a reason to withdraw the bypass |

The address observer of §10.4 therefore MUST read `IFA_FLAGS`; MUST NOT inject
`tentative` or `dadfailed`; MUST retain `deprecated`; and MUST inject
`temporary` and `stable_privacy` under **LRU eviction** bounded by the
self-address capacity of §1.6.3.

### 1.6.5 Every acceleration considered, and what came of it

| Technique | Conclusion |
|---|---|
| The older Flux's `PERFORMANCE_MODE` (`-m socket` plus a conntrack `--ctdir REPLY -j ACCEPT` fast path) | **Structurally superseded.** It existed to let established connections skip a chain walk; `tcp_decision` in `SK_STORAGE` is a per-socket O(1) lookup with no chain to walk (§7.3, E2 before E3). Nothing to port |
| The older Flux's `MSS_CLAMP_ENABLE` | **Structurally unnecessary here.** The app's TCP is **terminated** by a local transparent socket, so it travels app → veth → local socket where the path MTU is the veth's 65535; sing-box to the server is a **separate** connection with a normally negotiated MSS. The app's TCP never crosses the carrier path, so the problem cannot arise. This is an inherent advantage of a terminating proxy over a forwarding one |
| The older Flux's `BLOCK_QUIC` | **Unnecessary, and at the wrong layer.** UDP is captured correctly and QUIC reaches sing-box. Forcing a TCP fallback because an egress lacks UDP relay is **policy**, and belongs in a sing-box route rule (`{"network":"udp","port":443,"outbound":"block"}`), not a Flux switch |
| `SOCKMAP` / `sk_msg` in-kernel splice | **Rejected on two independent grounds.** It would require sing-box to put its own sockets into a sockmap, breaking the unmodified-official-binary rule (§9.7, and §3.8 on why the asset cannot simply be rebuilt); and splice only pays when the data is not transformed, whereas the point of a proxy is usually encryption. The only spliceable case is a `direct` outbound, and that traffic is already bypassed by §1.6.1. Zero benefit |
| XDP | Not applicable. XDP is ingress-only and runs before the stack, so it has **no socket context** and cannot see a UID |
| `BPF_PROG_TYPE_SOCK_OPS` | **Forbidden.** It is a cgroup attach type, and §1.3 forbids cgroup attach entirely |
| `bpf_redirect_peer` to save a hop | Structurally unavailable: it requires TC ingress and a netns crossing (§19) |
| GSO super-packets crossing the veth | **Already an acceleration, and free.** `__is_skb_forwardable()` exempts GSO skbs explicitly, so a large packet crosses whole and the number of traversals falls with the segment count (mechanism verified by Q4, §16) |
| per-UID byte and packet counters | **Recommended**, see §1.6.6 |

### 1.6.6 per-UID counters, the one data-plane addition worth making

The existing counters increment only at decision edges (§6.1), so they answer
"is it working" but not "which app used how much". The second question is one of
the most common a user has, and it is the direct compensation for the
double-counting boundary of §2.2.3(4).

A `PERCPU_HASH` keyed by `uid`, valued `{ tx_packets, tx_bytes }`, **updated
only on captured packets**.

The cost argument: a captured packet has already paid for a redirect, roughly a
`dev_queue_xmit`, so one more per-CPU hash update is marginal — and **unselected
traffic touches none of it**, so the performance floor of §14.1 is untouched.
That is the difference between this and a per-packet liveness counter, which is
why §8.5.4 uses a separate probe program instead.

Deliberately absent: no destination address, no port, no time series. Only "how
many bytes did this UID send through the proxy". **Nothing that could
reconstruct a browsing history is recorded.**

# Part 2: The data path and its failure semantics

## 2.1 The path

```
a selected app's socket
 └─(1) TC egress on a supported physical interface (chain 0, direct-action, preference selected per §8.5.3)
        flx_cap_l2 (ARPHRD_ETHER) or flx_cap_l3 (ARPHRD_RAWIP / a confirmed CLAT TUN)
        ├─ unselected / bypassed / pre-admission failure -> TC_ACT_UNSPEC (AOSP CLAT and OEM continue; Android's own path)
        ├─ failure past the admission boundary   -> TC_ACT_SHOT
        └─ admitted -> L2 rewrites nothing / L3 pushes a 14-byte header -> bpf_redirect(flxrs0, 0)
 └─(2) veth flxrs0 --kernel veth_xmit--> flxrs1 (eth_type_trans sets PACKET_OTHERHOST)
 └─(3) flxrs1 TC ingress: flx_in, which first corrects attribution with bpf_skb_change_type(PACKET_HOST)
        ├─ invalid snapshot / active=0 / not IP -> TC_ACT_SHOT
        ├─ TCP SYN && !ACK: fixed-tuple listener lookup -> guard -> bpf_sk_assign -> TC_ACT_OK
        ├─ other TCP, fragments included: TC_ACT_OK, leaving the kernel's request/established lookup to it
        └─ UDP: per-datagram lookup -> guard -> assign -> TC_ACT_OK
 └─(4) input routing: ip rule `iif flxrs1 lookup 20260` -> `local default dev lo` -> RTN_LOCAL
 └─(5) the official sing-box TProxy inbound (flux-in-v4/v6) accepts or recvmsgs, original destination intact
        - TCP destination = the accepted socket's LocalAddr()
        - UDP destination = the IP(V6)_RECVORIGDSTADDR cmsg
 └─(6) sing-box's ordinary outbound socket (root, uid 0, absent from uid_policy) -> Android netd routes it natively
```

Three properties hold along the whole path: **IP and port are never rewritten**;
the hot path for unselected traffic is one helper call plus one HASH miss; and
when the engine is gone, the next new SYN or datagram misses the listener lookup
*before* the redirect and goes Direct.

## 2.2 Failure is admission-bounded, not fail-open

"Fail-open" is the wrong word for what this design guarantees, and using it in
user-facing text was a real error rather than a simplification. The guarantee has
a boundary, and the boundary is admission.

| Moment | Failure semantics |
|---|---|
| A TCP flow has no immutable `CAPTURED` decision yet; the current UDP datagram has not been redirected | `TC_ACT_UNSPEC`, Direct along Android's own path |
| A TCP flow holds a valid `CAPTURED` decision | internal inconsistency, generation mismatch or a failed ingress handoff MUST drop or reset. Leaking to the real destination is forbidden |
| The packet has already been redirected to the veth | the redirect cannot be undone atomically, so later failures may drop |
| The engine's listener still exists but its event loop is wedged | not detectable here; there is no heartbeat (§2.2.3(3)) |

So `../guide/` may say "failures before admission stay direct". It MUST NOT say
"no failure can ever break your network". **That is a security boundary, not an
implementation shortfall:** once a flow is admitted, its packets carry a
destination the app believes is being proxied, and quietly sending them to the
real destination would defeat the reason the user selected that app.

**Egress "not taking over" is always `TC_ACT_UNSPEC`. Using `TC_ACT_OK` for
egress Direct is forbidden**, because it terminates the classifier chain and
skips CLAT and OEM programs. `TC_ACT_OK` is for ingress only. The Flux capture
filter MUST be reachable within chain 0 for that protocol, and a successful
attach does not establish reachability (§8.5).

### 2.2.1 Guaranteed Direct (`TC_ACT_UNSPEC`)

For the **first SYN of a TCP socket not yet admitted** and for the **current UDP
datagram**, every pre-redirect failure below is Direct:

- `skb->sk` is null, `bpf_sk_fullsock()` returns null, or
  `bpf_get_socket_uid()` returns the overflow uid;
- `uid_policy` misses, or the UID is `DRAINING` and this is a new connection;
- the family, protocol, header or L2 layout is unsupported — VLAN, an unknown
  ARPHRD, a non-IP EtherType;
- an unknown IPv6 extension header, or the parse bound is exceeded;
- a hit in the fixed safety bypass, the local-address bypass or the user's CIDR
  bypass — **fragments take this step too**;
- the control snapshot is invalid or `active == 0`;
- the actual listener lookup for that family and protocol misses, or the guard
  does not match;
- **both** the TCP decision storage `CREATE` and the concurrent read-only retry
  fail — this packet goes Direct with no stickiness, and a later SYN may decide
  again;
- the current interface has no successfully attached Flux filter, meaning no
  Flux program runs there at all.

### 2.2.2 MUST drop or reset (past the admission boundary)

- `bpf_sk_storage_get(...F_CREATE)` returned, or a concurrent read-only retry
  observed, an immutable `CAPTURED(gen)` — **this is the TCP admission
  boundary**, and a `DIRECT` storage entry is not admission. From here neither
  this packet nor any later parseable packet may go direct because of an internal
  Flux error;
- a selected, active UDP fragment that missed the bypass;
- any failure after `bpf_skb_change_head()` has added the internal Ethernet
  header on a raw-IP interface;
- any failure after the EtherType has been written at the L3 entry — the L2 entry
  writes nothing, so it has no such boundary;
- any enqueue, veth or routing failure after `bpf_redirect()` has returned;
- an admitted TCP flow meeting `active=0` or an expired `generation`;
- a parse, listener lookup, guard or `bpf_sk_assign()` failure on ingress;
- a TCP final ACK or data reaching the local stack with no request or established
  socket, which the kernel answers with RST or a drop.

### 2.2.3 Boundaries that cannot be removed, and are therefore published

1. **No stickiness across interfaces.** When Android reroutes an existing socket
   onto a VPN TUN, an unknown layout or an interface with no attachment, Flux has
   no global hook and the packet takes Android's own path. Absolute flow
   stickiness is not claimed.
2. **Late control packets.** A TIME_WAIT ACK or abortive RST after the socket has
   been destroyed may carry no full socket and no UID, and goes
   `TC_ACT_UNSPEC`. No tuple tombstone is kept.
3. **A wedged event loop is undetectable.** If the process is alive and the
   listener socket still exists but the event loop has stopped, this data plane
   cannot tell, and new flows are captured and stall. There is **no** heartbeat,
   periodic probe or watchdog packet. The official sing-box source also allows a
   fatal accept or read error to close one listener without exiting the process —
   that class **is** caught by the fault notification of §7.4 on the next
   relevant packet and heals; an internal failure with no traffic at all is not.
4. **Both legs are counted.** AOSP's per-UID and per-interface accounting sees
   the app's original leg, and sing-box's root outbound is a second leg. Flux does
   not falsify TrafficStats to cancel this out, so per-UID figures in Settings do
   not equal bytes on the physical link.
5. **The interface churn window.** Physical interfaces change constantly on
   Android: Wi-Fi to cellular handover, one `rmnet_data*` appearing and
   disappearing per PDN, netd creating and destroying `v4-*` CLAT on demand.
   Between "a new interface comes up and starts carrying traffic" and "fluxd
   receives the rtnetlink event and finishes attaching" there is an
   **irreducible window** in which traffic takes Android's own path. This is
   consistent with §2.2.1 and is not a defect, but it **MUST be published**: Flux
   does not claim to carry all traffic at all times. The window is bounded by
   rtnetlink delivery latency plus the debounce of §10.4, on the order of
   hundreds of milliseconds. **The same window reopens periodically because netd
   deletes `clsact`** — see §8.5.1, where that is routine rather than
   exceptional.
6. **Proxied traffic loses the app's DSCP marking.** AOSP's `dscpPolicy` attaches
   at **egress pref 5** on the physical interface
   (`DscpPolicyTracker.java:50-51`), and a captured packet returns
   `TC_ACT_REDIRECT`, ending the chain — so as long as our preference is below 5,
   dscpPolicy never sees those packets. sing-box's **outbound leg** still passes
   through it, but that is a root socket and cannot carry the per-UID DSCP policy
   the app requested through `ConnectivityManager`. **Net effect: app-level QoS
   marking is lost for proxied traffic.** The impact is confined to carrier
   networks that act on DSCP, and the measured Samsung device carries five
   further `tosMarker` egress programs, so more downstream consumers are affected
   than this entry alone names.
7. **conntrack counts twice.** Crossing the veth necessarily calls
   `skb_scrub_packet()`, which calls `nf_reset_ct()`, so every proxied flow is
   re-established in the veth peer's PREROUTING and netfilter sees it twice. This
   compounds with item 4. It is common to the whole TPROXY family and is not
   special-cased.

### 2.2.4 What unselected traffic actually costs

Unselected traffic is **not** untouched, and saying so to users was wrong.

The real cost per packet is one TC invocation, one `bpf_get_socket_uid()`, and
one `uid_policy` HASH miss, followed immediately by `TC_ACT_UNSPEC`. It performs
no packet parsing, reads no control snapshot, enters no userspace, and changes
nothing about the Android classifiers that run after it.

So the honest user-facing sentence is "not taken over, does not enter the
proxy". The sentence "the kernel program never even looks at it" is false, and
§14.1 budgets the cost that sentence would deny.

## 2.3 Self-capture is unconstructible, not mitigated

"Could the engine's own outbound traffic be captured again, looping forever?" is
the question every reviewer asks. Comparable projects genuinely need a
self-exclusion mechanism: `clone/bpf2socks/connect_prog.c:226-237` compares
**GIDs** (because app-side UIDs can be shared),
`clone/AndroidTProxyShell/tproxy.sh:1002` uses
`-m owner --uid-owner $CORE_USER --gid-owner $CORE_GROUP -j ACCEPT`, and
`clone/dae/control/kern/tproxy.c:2362-2391` combines a cookie→pid map with
`dae_socket_mark` in a three-way test.

**Flux needs none of them, because the policy is an allowlist rather than a
blocklist.** The argument:

1. `uid_policy` is a HASH containing **only selected app UIDs**. Step E1 of §7.3
   is "miss ⇒ `TC_ACT_UNSPEC`", not "hit an exclusion entry ⇒ let it through".
2. §1.4 refuses `appId` 0. sing-box runs as root, uid 0, so it is
   **structurally incapable of appearing in the table** — no spelling of any
   entry composes to it.
3. `bpf_get_socket_uid()` returns `overflowuid` (65534) when there is no
   `skb->sk`, which is also absent from the table ⇒ `TC_ACT_UNSPEC`. **A failure
   to resolve the UID therefore means no capture, not a wrong capture.** A
   blocklist inverts this: there, a failed resolution means "matched no exclusion"
   and the packet *is* captured, which is what creates the loop.
4. The engine's three kinds of outbound traffic, individually:
   - **upstream proxy connections** (sing-box to the remote server): a root
     socket on physical-interface egress, uid 0 ⇒ miss ⇒ Direct;
   - **upstream DNS**: the same, uid 0 ⇒ miss ⇒ Direct — this is also why §1.3.1
     can capture the app's system DNS without swallowing the engine's;
   - **UDP write-back** (return traffic on an accepted connection): destined for
     the app's local address, so output routing selects `lo` and it **never
     reaches any physical interface's TC egress**.
5. A packet delivered by `bpf_sk_assign` leaves the data plane on entering the
   engine, and what the engine opens afterwards is a **new socket** covered by
   item 4. There is no path from redirect or assign back to egress.

**Self-capture is not "mitigated"; it cannot be constructed.** Flux therefore has
no engine-specific mark, no GID bypass and no upstream-destination CIDR
exception. Adding any of them would add hot-path cost and configuration surface
against a threat that does not exist.

**One invariant carries the whole argument:** `uid_policy` MUST never contain
uid 0 (enforced by the parser, §11.2), and the engine MUST never run as a
selected app's UID (fixed root, §13.3). Breaking either one is what would open
the loop. A platform uid other than 0 — 1000 or 2000, say — is not part of this
argument: it is not the engine, capturing it loops nothing, and §1.4 leaves that
choice to the user with a warning.

---

# Part 3: Android platform facts every implementer needs

## 3.1 netd, fwmark and the RPDB

Android's socket fwmark is a packed 32-bit value encoding the netId,
`explicitlySelected`, `protectedFromVpn`, permission bits and vendor bits. netd
implements VPN, explicit network, implicit and default network, and
prohibit/unreachable behaviour with a set of rules keyed on UID ranges, fwmark
and `iif lo`, at priorities roughly 10000–32000. This is **not** desktop Linux's
three `local` / `main` / `default` rules.

Flux therefore MUST NOT read or write a packet's fwmark, MUST NOT guess a "free"
mark for itself, MUST NOT flush, reorder or reuse a netd rule, and MUST NOT
assume that the `main` table or the current default route is the app's real
network. Flux adds exactly one local-delivery rule, matched by the dedicated
`iif flxrs1` (§8.4).

## 3.2 The root cgroup's SOCK_ADDR slots

**Fact, as measured:** on a clean Phase 0 re-measurement the root cgroup's
`SOCK_ADDR` attach list was **empty**. **Inference, and the reason that fact
changes nothing:** an AOSP program being loaded is not the same as being
attached, the system may still attach dynamically depending on runtime
conditions, and an ancestor holding `flags=0` prevents safe coexistence
regardless.

State the two separately. An earlier draft compressed them into "the root cgroup
is currently full", which the measurement then contradicted — and a reader who
found the fact wrong had no way to see that the conclusion did not depend on it.
The honest form is: **observed empty at the time of measurement; neither
lifecycle nor coexistence can be guaranteed by one snapshot.**

**The product conclusion is unchanged, and is not derived from the snapshot:
Flux attaches no cgroup BPF program of any kind, and moves neither apps nor
sing-box into a cgroup of its own.** It observes packets only at physical
netdevice TC egress, after AOSP has finished applying socket and owner policy.
If Android's owner firewall has already dropped a packet, Flux never sees it and
does not circumvent the drop.

See `../history/review-log.md` §0.1(2) for the source review this rests on.

## 3.3 L2 layout differs: Wi-Fi vs rmnet vs CLAT

| Entry | Accepts | Packet handling |
|---|---|---|
| `flx_cap_l2` | `ARPHRD_ETHER`, `skb->vlan_present == 0`, `skb->protocol ∈ {IPv4, IPv6}`, not a bridge, VPN or Flux's own | **No byte is rewritten.** The original Ethernet header, EtherType included, travels as-is; `pkt_type` is corrected on ingress (D17) |
| `flx_cap_l3` | `ARPHRD_RAWIP` (Qualcomm rmnet), or a strictly identified CLAT `v4-*` TUN | `bpf_skb_change_head(skb, 14, 0)` — the helper zeroes the new room and calls `skb_reset_mac_header()` — then writes **only** the EtherType at offset 12, derived from `skb->protocol`. The destination and source MAC stay all zero; attribution is handled by `bpf_skb_change_type()` on ingress (D17) |

VLAN, QinQ and unknown ARPHRD values exclude the interface outright. Phones
almost never need VLAN, and a strip-and-rebuild branch for it is out of scope.

### 3.3.1 The L3 branch is **mandatory**, not an optimisation

Omit it and the product works perfectly over Wi-Fi while **every cellular packet
is silently dropped, with no counter recording it**. The mechanism is verified
line by line against kernel source:

```c
/* v6.1 net/core/filter.c:2144-2165 */
static int __bpf_redirect_common(struct sk_buff *skb, struct net_device *dev, u32 flags)
{
	/* Verify that a link layer header is carried */
	if (unlikely(skb->mac_header >= skb->network_header)) {
		kfree_skb(skb);
		return -ERANGE;
	}
	...
}
static int __bpf_redirect(struct sk_buff *skb, struct net_device *dev, u32 flags)
{
	if (dev_is_mac_header_xmit(dev))
		return __bpf_redirect_common(skb, dev, flags);
	else
		return __bpf_redirect_no_mac(skb, dev, flags);
}
```

Three facts, none of them dispensable, produce the conclusion:

1. **`dev_is_mac_header_xmit()` inspects the *target* device**
   (`include/linux/if_arp.h:44-60`). A veth is `ARPHRD_ETHER`, so **any redirect
   whose target is the veth always takes the path carrying the `-ERANGE`
   check.** The source device's type does not select the branch; it only decides
   whether the check passes.
2. **`skb_reset_mac_header()` runs immediately before TC egress.**
   `__dev_queue_xmit()` calls it at `net/core/dev.c:4170` and only then invokes
   the egress hook at `:4198`. On a device with no Ethernet header `skb->data`
   points at the IP header, so `mac_header == network_header` and the `>=` holds.
3. **On Android this is the entire cellular path.** `rmnet_data*` is
   `ARPHRD_RAWIP` and CLAT's `v4-*` is `ARPHRD_NONE`. AOSP states it directly in
   `ClatCoordinator.java:471` — "*This program will be attached to the v4-\*
   interface which is a TUN and thus always rawip*" — and
   `tcutils.cpp:478-512` classifies both as non-Ethernet.

The fix is one the kernel **documents explicitly**. The comment on
`__bpf_skb_change_head()` reads "*Intention for this helper is to be used by an
L3 skb that needs to push mac header for redirection into L2 device*"
(`net/core/filter.c:3729-3758`). It calls `skb_reset_mac_header()` internally,
which restores `mac_header < network_header`, and it exempts GSO skbs from the
length ceiling, so it is GSO-safe.

AOSP and honk both split this into two objects and two attach branches — AOSP's
`..._ether` and `..._rawip` at `clatd.c:248-270`, honk's at
`attach.rs:657-690` — matching the `flx_cap_l2` / `flx_cap_l3` split here.

> **Interface selection MUST NOT use `operstate`.** Measured (§16.9.5):
> `rmnet_data0` was carrying the default route, held global v4 and v6 addresses
> and was passing traffic, while `/sys/class/net/rmnet_data0/operstate` read
> **`unknown`** rather than `up`. RAWIP interfaces do not report carrier state.
> Any filter of the form `operstate == "up"` or `IF_OPER_UP` therefore **misses
> every cellular interface** — precisely the only interfaces `flx_cap_l3`
> applies to. Use the `IFF_UP` flag from `RTM_NEWLINK`'s `ifi_flags` plus the
> presence of a global-scope address.
>
> The same measurement produced a second criterion not to use: **having an
> address does not mean netd considers the interface part of a network.** At
> observation time `wlan0` held a `192.168.x.x` address but had **no `clsact`**,
> because Wi-Fi had just disconnected and the address had not yet been reclaimed.
> The presence of `clsact` is netd's view of the truth (§8.5.1), which is also
> why Flux reuses it rather than creating its own.

## 3.4 CLAT464

AOSP's `ClatCoordinator` creates a `v4-*` raw-IP TUN and translates IPv4 to IPv6
with a TC BPF program at a fixed low priority on its egress. An IPv4 packet at
`v4-*` egress still carries the originating app's socket UID; the translated
physical IPv6 usually belongs to `AID_CLAT` and can no longer be used to select
an app.

Flux supports CLAT only when **all** of these hold: ① the link is a TUN or
raw-IP device whose name matches `v4-*`; ② the characteristic CLAT address and
an associated underlay are present; ③ a recognisable AOSP CLAT egress filter
exists in the TC dump; ④ Flux can install in the same chain at **some available
preference below `FLUX_TC_PREF_CLAT_MAX` (4)** with IPv4 protocol and handle
`0x1` (§8.5.3; the condition fails if 1–3 are all taken); ⑤ Phase 0 has proven
UID, GSO, checksum, MTU and header conversion correct on that device. Any
condition in doubt means the interface stays Direct.

**Flux never deletes, moves or replaces an AOSP filter**, and never hardcodes
AOSP's priority numbers.

Note what condition ④ does and does not assert. It requires a numerically lower
preference than CLAT's, which is a necessary condition for running first — but
**dump order is not evidence that our program is reached** (R091-05 overturned
that claim; see §8.5.3). Reachability is established by the liveness
verification of §8.5.4, on this interface, and nowhere else.

## 3.5 VPN and TUN

- When an app uses a VPN, its original packet is on the VPN TUN. Flux excludes
  all generic TUN and TAP devices.
- What appears on the physical interface afterwards is the VPN provider's outer
  socket, usually no longer the original app's UID.
- Always-on and lockdown VPNs remain Android's business. Flux offers no hidden
  switch to "take precedence over the VPN".
- If a VPN coming up migrates an established Flux TCP flow onto an excluded TUN,
  that flow leaves the range over which Flux can enforce stickiness
  (§2.2.3(1)). Flux does not attach a drop-only program to the VPN TUN to
  compensate.

## 3.6 Explicit networks and outbound identity

When an app binds explicitly to Wi-Fi or cellular through the Android API, its
original packet may be captured on the corresponding underlay. But the sing-box
outbound is a new socket in a root process and **does not inherit** the app's
netId, VPN protection or per-flow network identity. Flux uses whatever network
Android selects for that root socket. Users who need control have the official
sing-box outbound options — `bind_interface`, `routing_mark`,
`network_strategy` — and own the consequences. **Flux does not claim to preserve
the app's Android network selection.**

## 3.7 GKI, OEM, SELinux and root managers

API level, kernel version string, GKI defconfig, OEM backports, SELinux domain
and root provider permissions are independent dimensions, none of which implies
another. Flux **maintains no device catalogue** and never infers a capability
from a string allowlist.

Normal activation at startup *is* the capability admission: create the real
maps, load the real programs, create and verify the real network objects,
attempt the exact attach. Any step failing leaves that interface — or the whole
data plane — Direct, with the **first concrete error** in `status`. Injecting
broad sepolicy to widen device compatibility is forbidden.

## 3.8 4 KiB and 16 KiB

Android 15 allows a 16 KiB base-page kernel, and the API level does not imply
the page size. All four `PT_LOAD` segments of the previously tested official
sing-box 1.13.19 arm64 asset have `p_align == 0x1000`, which does not satisfy AOSP's 16 KiB ELF
alignment requirement, and `zipalign` cannot modify a program header. Flux
therefore supports `sysconf(_SC_PAGESIZE) == 4096` only.

This is the current device-support boundary, not a dependency version pin.
Packaging measures the selected asset's actual load alignment. A newer engine
with better alignment does not by itself establish device evidence for Flux.

`fluxd` itself is still built 16 KiB aligned, for installation and diagnostic
hygiene: on a device with another page size it can then produce a definite
diagnosis instead of crashing.

## 3.9 netns

BPF socket lookup, TC, the veth, the RPDB and the sing-box listeners all live in
the current network namespace. `fluxd` and sing-box MUST be in the initial netns
where Android's apps run. At startup, compare the inodes of
`/proc/self/ns/net` and `/proc/1/ns/net`; a mismatch means Inactive with an
error. **Magisk's mount namespace is not a network namespace**, and confusing
the two is the likely cause of a mismatch here.

---

# Part 4: Kernel mechanisms this design depends on

Use this table to check a target device item by item. **Every entry MUST be
verified at activation by performing the real call successfully, never by
inspecting a version.** The "minimum kernel" column records only where each
mechanism first appeared; all of them predate the 5.15 baseline, and the column
exists to explain why they are available on it, not to be consulted at run time.

**GKI defconfigs verified item by item** across the arm64 `gki_defconfig` of
`android12-5.10`, `android13-5.15`, `android14-6.1` and `android15-6.6`, with
all four branches satisfying: `CONFIG_VETH=y`, `CONFIG_DUMMY=y`, `CONFIG_TUN=y`,
`CONFIG_NET_SCH_INGRESS=y` (clsact), `CONFIG_NET_CLS_BPF=y`,
`CONFIG_NET_CLS_ACT=y`, `CONFIG_NET_ACT_BPF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_JIT=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_IP_MULTIPLE_TABLES=y`,
`CONFIG_NF_CONNTRACK=y`. **`CONFIG_NETKIT` is absent from all four.**

| Mechanism | Min kernel | Purpose | Consequence of failure |
|---|---|---|---|
| `BPF_PROG_TYPE_SCHED_CLS` + direct-action | 4.4 / 4.5 | the four programs | Inactive overall |
| `bpf_get_socket_uid()` | 4.3 | coarse UID selection | Inactive overall |
| `__sk_buff->sk` + `bpf_sk_fullsock()` | 5.1 | reach the app's full socket | Inactive overall |
| `BPF_MAP_TYPE_SK_STORAGE` + `bpf_sk_storage_get(F_CREATE)` | 5.2 | the TCP first decision | Inactive overall |
| `bpf_sk_lookup_tcp/udp()` + `bpf_sk_release()` | 4.20 | listener liveness and the assign target | Inactive overall |
| `bpf_sk_assign()` on TC ingress | 5.7 | delivery to the TProxy listener | Inactive overall |
| `BPF_MAP_TYPE_ARRAY_OF_MAPS` | 4.12 | atomic publication of the control snapshot | Inactive overall |
| `BPF_MAP_FREEZE` | 5.2 | leaf immutability | degrade to not freezing; hygiene only |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 | fault-only notification | degrade to no self-healing notification |
| `BPF_MAP_TYPE_LPM_TRIE` | 4.11 | CIDR bypass | Inactive overall |
| `bpf_skb_change_head()` | 4.16 | push an Ethernet header on raw-IP | exclude that interface; L3 entry only |
| `bpf_skb_store_bytes()` / `bpf_skb_pull_data()` | 4.1 / 4.9 | safe packet writes | Inactive overall |
| `bpf_redirect()` | 4.4 | redirect into the veth | Inactive overall |
| `BPF_BTF_LOAD` | 5.1 | the BTF that SK_STORAGE requires | Inactive overall |
| `veth` (`CONFIG_VETH=y`, built into GKI) | — | the loopback topology | Inactive overall |
| `CONFIG_NETKIT` | — | **absent from all four GKI branches**, so dae's netkit L3 fast path is unavailable on Android and veth is the only option | — |
| `clsact` qdisc | 4.5 | the TC attach point | exclude that interface |
| RPDB `iif` selector + an `RTN_LOCAL` route | — | local delivery | Inactive overall |
| `NETLINK_SOCK_DIAG` (inet_diag) | — | verifying listener readiness | Inactive overall |
| `pidfd_open` + `PR_SET_PDEATHSIG` | 5.3 | engine lifecycle | Inactive overall |
| `signalfd` / `inotify` / `timerfd` / `epoll` | — | the reactor | Inactive overall |

**A known limitation before 6.5:** `bpf_sk_assign()` rejects a `SO_REUSEPORT` socket. This is the hard constraint of §9.2.

---

# Part 5: Crate and module structure

Three crates, one product binary, and no abstraction built for a single
implementation.

```text
Flux-rs/
├── Cargo.toml                     # [workspace] members = ["crates/flux-core","crates/fluxd","xtask"]
├── Cargo.lock                     # generated locally, not version-controlled
├── rust-toolchain.toml            # stable channel; targets = ["aarch64-linux-android"]
├── LICENSE / README.md / CHANGELOG.md / THIRD_PARTY_NOTICES.md
├── licenses/…
├── bpf/
│   ├── flux.bpf.c                 # the only BPF source file
│   └── include/flux_abi.h         # ABI source of truth, shared by C and Rust
├── crates/
│   ├── flux-core/                 # pure logic: no libc, no syscalls, testable anywhere
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs          # flux.toml parse, canonicalise, hard ceilings
│   │       ├── selector.rs        # "userId:package" parse, UID maths, appId range
│   │       ├── cidr.rs            # CIDR canonicalise, fixed bypass, LPM key encoding
│   │       ├── engine_config.rs   # template validation and generated-config assembly
│   │       ├── abi.rs             # Rust mirror of flux_abi.h, with layout assertions
│   │       ├── control_wire.rs    # control protocol request/response types
│   │       └── version.rs         # SemVer to versionCode and artifact name
│   └── fluxd/                     # the Linux/Android runtime: one product binary
│       ├── build.rs               # compiles bpf/flux.bpf.c with clang into OUT_DIR
│       └── src/
│           ├── main.rs            # CLI dispatch
│           ├── layout.rs          # directories, permissions, single-instance lock
│           ├── control.rs         # SOCK_SEQPACKET server and client
│           ├── reactor.rs         # single-threaded epoll loop, state machine, convergence
│           ├── packages.rs        # reads and parses /data/system/packages.list
│           ├── netlink/           # rtnetlink: link/addr/route/rule/tc codecs and operations
│           ├── bpf/               # minimal loader: syscalls, BTF blob, relocation, maps, ringbuf
│           ├── dataplane.rs       # object lifecycle, control leaf publication, admission
│           └── engine.rs          # config write-out, check, spawn, SOCK_DIAG readiness
├── module/                        # the Magisk/KernelSU/APatch envelope
└── xtask/                         # build, package, release; development host only
```

Dependency direction: `fluxd → flux-core`; `xtask → flux-core`. Pure parsing
and text-processing dependencies are declared in `crates/flux-core/Cargo.toml`;
`flux-core` MUST contain no I/O, syscalls or unsafe code and MUST NOT depend on
`fluxd`. No platform, testkit or backend-registry crate may be added,
and **no trait abstraction may be created for a single implementation.**

Module dependencies inside `fluxd`:
`main → reactor → {layout, control, packages, netlink, bpf, dataplane, engine}`,
with no reverse edge back to `reactor`. The `Reactor` owns mutable coordination
state and module-owned resources; the subscription worker owns only its request
and transport. There is no mutable global coordination state.

**One boundary inherited from the previous repository.** The old over-design
review found that writing raw rtnetlink messages directly in the daemon — the
sequence-number, ACK and timeout handling in `native_canary_facility.rs` —
violated the deep-module principle. Merging `flux-platform` away did not retire
that finding; it only moved the boundary from a crate to a module:

**Raw netlink message construction, sequence numbers, ACK and timeout handling
belong inside `fluxd/src/netlink/` and nowhere else. Raw `bpf(2)` belongs inside
`fluxd/src/bpf/` and nowhere else.** `reactor` and `dataplane` see typed
operations — `create_veth`, `add_rule`, `attach_filter`, `publish_control` — and
never an `nlmsghdr`.

The test is not module count but what a caller must know. A module is deep when
its interface is much smaller than the knowledge it holds; `attach_filter` is
deep because the caller needs to know nothing about netlink framing, and a
`Capture` trait with one implementation is shallow because it adds a name
without removing anything a caller must understand (PHIL-1).

---

# Part 6: The BPF ABI

`bpf/include/flux_abi.h` is the only source of truth. `flux-core/src/abi.rs` is a
hand-written mirror and MUST carry tests asserting every `size_of` and field
offset against it, with `cargo xtask abi-check` having clang compute the C side
in CI. **Changing any layout MUST change `FLUX_ABI_MAGIC` in the same commit.**

## 6.1 The map set — 12 kernel objects in steady state

| Name | Type | Key | Value | max_entries / flags |
|---|---|---|---|---|
| `uid_policy` | `HASH` | `__u32 uid` | `__u8` (`FLUX_UID_*`) | 4096 |
| `bypass_v4` | `LPM_TRIE` | `flux_lpm_v4_key` | `__u8` (`FLUX_BYPASS_*`) | 65536, `BPF_F_NO_PREALLOC` — kernel-forced, so `max_entries` is only a ceiling |
| `bypass_v6` | `LPM_TRIE` | `flux_lpm_v6_key` | `__u8` (`FLUX_BYPASS_*`) | 65536, as above |
| `self_addr_v4` | `HASH` | `__u8[4]` | `__u8` | 256 — D20: local addresses are full-length prefixes and never enter the LPM |
| `self_addr_v6` | `HASH` | `__u8[16]` | `__u8` | 256, as above |
| `uid_stats` | `PERCPU_HASH` | `__u32 uid` | `struct flux_uid_stats` (16 B) | 4096 — D23, updated only on captured packets |
| `tcp_decision` | `SK_STORAGE` | `int`, implicit | `struct flux_decision` (16 B) | 0, `BPF_F_NO_PREALLOC`, **requires BTF** |
| `control_root` | `ARRAY_OF_MAPS` | `__u32 0` | reference to the current leaf | 1 |
| `control_leaf` | `ARRAY`, inner | `__u32 0` | `struct flux_control` | 1, `BPF_MAP_FREEZE` once written |
| `fault_latch` | `HASH` | `struct flux_fault_key` | `__u8` | 64 |
| `fault_events` | `RINGBUF` | — | `struct flux_fault_event` (32 B) | 16384 bytes |
| `counters` | `PERCPU_ARRAY` | `__u32 idx` | `__u64` | 32 |

- During publication two `control_leaf` maps exist briefly; at every other moment
  there are 12 objects.
- `fault_events` is fixed at 16384 because that is the smallest value that is
  both a power of two and PAGE_SIZE-aligned under 4 KiB and 16 KiB alike, which
  keeps the ABI from forking on page size.
- Maps are **not pinned**.
- Forbidden: a `bpf_spin_lock` that would make selected packets contend
  globally; per-packet telemetry; a per-flow map; and any claim that an `ARRAY`
  update of a large struct is atomic. Adding a map requires stating its hot-path
  and lifecycle cost.

### 6.1.1 The bypass value distinguishes mechanism from policy

One LPM set was doing two unrelated jobs:

| | Internal: a mechanism invariant | External: user policy |
|---|---|---|
| Contents | loopback, link-local, multicast and broadcast, listener addresses | LAN, chnroute, a CGNAT gateway |
| Cost of violation | self-capture, contending with a local service for a port — the mechanism breaks | the user's own trade-off |
| Affected by `mode` | **never** | yes |

Mixing them had concrete costs: the allow-list semantics were ambiguous (does a
listener address belong in the user's allow list?), the fakeip check had to
reason about a union, and listener addresses had to be written in two places.

The value byte already exists and **has never been read**: the loader always
writes `1` and the BPF side only tests for a non-NULL pointer. Tagging it costs
no new map and no new lookup.

```c
#define FLUX_BYPASS_RESERVED 1   /* mechanism invariant; always direct */
#define FLUX_BYPASS_POLICY   2   /* user policy; subject to cidr.mode */
```

One lookup, plus one branch on a mode flag carried in `flux_control`:

| LPM result | blacklist | whitelist |
|---|---|---|
| hit `RESERVED` | direct | direct |
| hit `POLICY` | direct | **capture** |
| miss | capture | direct |

`cidr_mode` occupies `flux_control`'s existing `pad0[2]`, so the struct size and
every offset are unchanged — but the **contract** changed, so `FLUX_ABI_MAGIC`
MUST be bumped. That is the smallest possible ABI change carrying this meaning.

This split is PHIL-1 applied to a map. The reference implementations reach the
same shape by other means: `AndroidTProxyShell/tproxy.sh:980-1012` orders
mechanism before policy by chain position, and
`box4magisk/box/scripts/net.inotify:15-22` inserts local addresses as a separate
anti-loopback rule on a different path from the user's `cn.zone`. Flux had
already done half of it — D20 moved local addresses into their own `self_addr_*`
HASH, which is why `bypass_hit()` in `bpf/flux.bpf.c:420-439` is already
two-level. This finishes the second level.

What it buys: the allow-list semantics stop being ambiguous, because `RESERVED`
ignores the mode and listener addresses are simply not in the user's set, so the
question disappears; the fakeip check splits into two separately decidable
sentences, where intersecting `RESERVED` is a hard refusal on mechanism grounds
(PHIL-6) and the relation to `POLICY` follows the mode and is the user's
trade-off; and the `[cidr]` documentation shrinks to one sentence, because it
now describes user policy only.

## 6.2 `flux_decision`, the SK_STORAGE value

```c
struct flux_decision {
    __u32 magic;        /* == FLUX_DECISION_MAGIC; rejects uninitialised or foreign storage */
    __u8  mode;         /* FLUX_DEC_DIRECT | FLUX_DEC_CAPTURED */
    __u8  reserved[3];  /* MUST be zero */
    __u64 generation;   /* the admitting generation when CAPTURED; 0 when DIRECT */
};
```

**Invariant: never rewritten in place once created.** `DIRECT` is not admission;
admission begins at the instruction after a valid `CAPTURED` is observed. The
storage is released when the app's socket is destroyed, and there is no LRU
capacity eviction to race with.

## 6.3 `flux_control`, an immutable snapshot

Fields are in `bpf/include/flux_abi.h`. What matters here:

- `abi_magic`, `generation`, `active`;
- `flxrs0_ifindex`, the redirect target, and `flxrs1_ifindex`;
- **no MAC field** (D17). Egress rewrites no Ethernet header, and ingress covers
  the `PACKET_OTHERHOST` that `eth_type_trans()` derives by calling
  `bpf_skb_change_type(skb, PACKET_HOST)`;
- `listen_v4[4]` / `listen_v6[16]` / `listen_port_v4` / `listen_port_v6`, in
  network byte order;
- `probe_remote_v4[4]` / `probe_remote_v6[16]` / `probe_remote_port`, the fixed
  synthetic remote that makes the listener lookup deterministic;
- `cidr_mode`, in the former `pad0[2]` (§6.1.1);
- diagnostic counts: `selected_count`, `draining_count`, `bypass_v4_count`,
  `bypass_v6_count`.

## 6.4 Publishing a control snapshot atomically

**Verified:** updating an `ARRAY_OF_MAPS` takes a reference to the new inner map,
`xchg()`es the pointer, calls `synchronize_rcu()` before the syscall returns, and
frees the old inner map after a further RCU grace period. Therefore:

1. create a new `control_leaf`, an `ARRAY` of one element;
2. write the whole struct with a single
   `bpf_map_update_elem(leaf, 0, &full_control)`;
3. `BPF_MAP_FREEZE(leaf)`;
4. publish with `bpf_map_update_elem(control_root, 0, &leaf_fd)`;
5. close the old leaf fd.

**Mandatory on the BPF side:** look up `control_root[0]` exactly **once** per
invocation and use the returned inner pointer for the rest of that invocation.
The leaf is frozen before publication and never modified in place. A single
invocation therefore sees either the old or the new snapshot **whole**, and never
a struct torn mid-`memcpy`.

**When a new leaf is created:** an engine generation switch, an `active` flip
between 0 and 1, or a change to a topology field — an ifindex, a listener address
or port. **A policy change to UIDs or CIDRs creates no new leaf and does not
flip `active`** (D5), and the diagnostic counts above are refreshed only when the
next legitimate leaf is published. BPF programs MUST NOT treat those counts as
policy authority, and `status` computes live counts from the data plane's current
set rather than reading them.

## 6.5 generation

Monotonically increasing from 1 within a boot, **never reused and never reset**.
A cold daemon start begins at 1, which is safe because the old objects have been
deleted and rebuilt by then, so no cross-generation packet is in flight. It is a
`u64` and cannot wrap within the product's lifetime. Only the engine candidate
switch of §9.4 increments it.

---

# Part 7: Data-plane algorithms

## 7.1 Constraints common to every program

- Four entry points: `flx_cap_l2` and `flx_cap_l3` on egress, `flx_in` on
  ingress, and `flx_verify` for liveness (§8.5.4). They share
  `static __always_inline` helpers, so the logic exists once.
- Forbidden: tail calls, a BPF-to-BPF call graph, perf events, BPF timers,
  spinlocks, and per-CPU statistics other than `counters` and `uid_stats`
  (§6.1).
- Every reference returned by `bpf_sk_lookup_tcp/udp()` MUST be released by
  exactly one `bpf_sk_release()` on every branch. **`bpf_sk_assign()` does not
  release.** `bpf_sk_fullsock()` takes no reference and MUST NOT be released.
- A socket pointer MUST NOT be stored in a map or passed between programs.
- Every offset computation is preceded by a fixed bound and a `data_end` check
  the verifier can see.
- Writes to an skb MUST go through `bpf_skb_store_bytes()`. When `data_end` is
  insufficient before a deeper parse, call
  `bpf_skb_pull_data(skb, FLUX_MAX_PULL_BYTES)` once and re-read `data` and
  `data_end` (D15).

## 7.2 Parse bounds

- **IPv4:** minimum header present, `version == 4`, `ihl ∈ [5,15]`, a plausible
  `tot_len`. `MF` set or a non-zero fragment offset takes the fragment branch.
- **IPv6:** at most 4 extension headers totalling at most 256 bytes. A Fragment
  header takes the fragment branch; ESP, No-Next-Header, an unknown extension or
  a jumbogram is Direct.
- Only `IPPROTO_TCP` and `IPPROTO_UDP` are accepted. TCP must expose its fixed
  header and flags; UDP must have a complete 8-byte header.

## 7.3 The egress algorithm (`flx_cap_l2` / `flx_cap_l3`)

```
E0  if skb->protocol ∉ {ETH_P_IP, ETH_P_IPV6}            -> UNSPEC
    (l2 only) if skb->vlan_present                       -> UNSPEC
E1  skc = skb->sk;             if !skc                   -> UNSPEC
    sk  = bpf_sk_fullsock(skc);if !sk                    -> UNSPEC
    uid = bpf_get_socket_uid(skb)
    mode = uid_policy[uid];    if miss                   -> UNSPEC   <- the entire cost for unselected traffic
E2  /* a decision exists: no L4 parse, and fragments follow the decision */
    d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0)
    if d:
        if d->magic != FLUX_DECISION_MAGIC || d->reserved != 0 || d->mode unknown
                                                          -> cnt(CORRUPT); SHOT
        if d->mode == DIRECT                              -> UNSPEC
        c = ctrl();  if !c                                -> cnt; SHOT
        if !c->active                                     -> cnt(INACTIVE); SHOT
        if d->generation != c->generation                 -> cnt(STALE_GEN); SHOT
        goto HANDOFF(c)
E3  /* no decision yet */
    parse L3 (bounded);  if unsupported                  -> UNSPEC
    if fragment:
        if bypass_lookup(family, daddr)                   -> UNSPEC
        c = ctrl()
        if mode == SELECTED && c && c->active             -> cnt(UDP_FRAG_DROP); SHOT
        else                                              -> UNSPEC
    parse L4 (bounded);  if !TCP && !UDP                 -> UNSPEC
E4  if TCP:
        if !(SYN && !ACK)                                 -> UNSPEC   /* a connection established before capture pays no control cost */
        cand.magic = FLUX_DECISION_MAGIC
        c = ctrl()
        capture = (mode == SELECTED)
               && c && c->active
               && !bypass_lookup(family, daddr)
               && listener_alive(c, family, TCP)          /* emits one fault on a miss */
        cand.mode = capture ? CAPTURED : DIRECT
        cand.generation = capture ? c->generation : 0
        d = bpf_sk_storage_get(&tcp_decision, sk, &cand, BPF_SK_STORAGE_GET_F_CREATE)
        if !d: d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0)   /* a concurrent loser re-reads the winner */
        if !d:  cnt(ALLOC_FAIL);                          -> UNSPEC /* no stickiness; a later SYN may decide again */
        /* obey the winner unconditionally, even where it contradicts this cand */
        if d->mode == DIRECT: cnt(DIRECT_FIRST)           -> UNSPEC
        if !c || !c->active || d->generation != c->generation
                                                          -> cnt; SHOT
        cnt(ADMIT_TCP); goto HANDOFF(c)
E5  if UDP:
        if mode != SELECTED                               -> UNSPEC
        c = ctrl(); if !c || !c->active                   -> UNSPEC
        if bypass_lookup(family, daddr)                    -> UNSPEC
        if !listener_alive(c, family, UDP)                -> fault; UNSPEC
        cnt(ADMIT_UDP); goto HANDOFF(c)

HANDOFF(c):
    l2: /* writes no packet byte */
    l3: ok = bpf_skb_change_head(skb, ETH_HLEN, 0) == 0
          && bpf_skb_store_bytes(skb, 12, &ethertype, 2, 0) == 0   /* the kernel already zeroed the first 12 bytes */
        if !ok: cnt(HANDOFF_FAIL); SHOT      /* past admission, so dropping is the only option */
    return bpf_redirect(c->flxrs0_ifindex, 0)
```

Three properties this ordering buys:

- **E2 precedes E3.** A steady-state packet on a captured flow parses no IP and
  no TCP at all. The L2 path performs one storage lookup, two map lookups and one
  redirect, **writing zero bytes** (D17); the L3 path adds one
  `bpf_skb_change_head(14)` and one 2-byte EtherType write.
- **A retransmitted `SYN` meets the same immutable state.** `DIRECT` stays
  direct and `CAPTURED` keeps its generation. Only the allocation-failure edge,
  where no decision was ever installed, is decided again (the last item of
  §2.2.1).
- **The `DIRECT` state earns its keep.** Without it, retransmissions of one
  `connect()` could flip between direct and proxied as bypass, `active` or a
  brief fault changed underneath them. The cost is 16 bytes of storage per
  selected-but-direct socket and no per-packet write.

## 7.4 `listener_alive()` and fault notification

```
listener_alive(c, family, proto):
    tuple = { saddr = c->probe_remote_{v4,v6}, sport = c->probe_remote_port,
              daddr = c->listen_{v4,v6},       dport = c->listen_port_{v4,v6} }
    sk2 = proto == TCP ? bpf_sk_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0)
                       : bpf_sk_lookup_udp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0)
    if !sk2: fault_once(c, family, proto, LISTENER_MISS); return false
    ok = sk2->family == (family == 4 ? AF_INET : AF_INET6)
      && (proto == TCP ? sk2->state == BPF_TCP_LISTEN : 1)
      && bound_addr_matches(sk2, c)          /* src_ip4 / src_ip6 == the listen address */
      && sk2->src_port == host_order(listen_port)
    bpf_sk_release(sk2)
    if !ok: fault_once(c, family, proto, LISTENER_GUARD); 
    return ok
```

**The fixed synthetic remote** (`probe_remote_*`) makes the lookup key identical
every time: deterministic, cache-friendly, and incapable of accidentally matching
some established socket.

**Byte-order trap in `bpf_sock`:** `src_port` is in **host** order while
`dst_port` is in **network** order. This is a pre-existing inconsistency in the
kernel ABI, not a choice available here, and getting it backwards produces a
guard that fails for reasons no log will explain.

**Fault notification rules:**

- Only two classes of event are notified: ① a `listener_alive` failure on
  egress, where the packet is unmodified and returns `UNSPEC`; ② an ingress
  lookup, guard or assign failure after the earlier checks passed, where the flow
  is already admitted and the packet is dropped.
- Mechanism: insert `{generation, family, protocol, reason}` into `fault_latch`
  with `BPF_NOEXIST`; only the program that wins that insert writes one 32-byte
  event to `fault_events`. **If the ringbuf is full, delete the latch just
  inserted**, so a later packet retries rather than the fault being lost.
- No event is emitted for a parse error, a bypass hit, a UID miss, `active=0` or
  an ordinary Direct. An event carries only generation, family, protocol and
  reason — **no header, no UID, no address, no payload**.
- On a current-generation fault `fluxd` publishes `active=0` first, then restarts
  the whole engine generation. The handler is idempotent per generation and
  state; an old or duplicate event only clears the latch and is ignored. Latches
  are cleared before a new generation activates.
- The contract is **"no steady-state event storm"**, not exactly-once delivery.

## 7.5 The ingress algorithm, `flx_in` on `flxrs1`

```
I0  c = ctrl(); if !c                                     -> SHOT
    if !c->active                                         -> SHOT
    bpf_skb_change_type(skb, PACKET_HOST)                 /* see below; MUST precede ip_rcv */
I1  /* cls_bpf already did __skb_push(mac_len) on ingress, so the Ethernet header is readable */
    check eth readability; if fail                     -> cnt; SHOT
    if eth->h_proto ∉ {ETH_P_IP, ETH_P_IPV6}              -> cnt; SHOT
    /* no MAC comparison: the device itself is the provenance boundary (D3) */
I2  parse L3 (the same bounded implementation as egress)
    if fragment                                           -> cnt(PASS_FRAG); TC_ACT_OK
                                                             /* let the kernel ip_defrag reassemble, then the established lookup */
    parse L4; if !TCP && !UDP                             -> cnt; SHOT
I3  if TCP:
        if SYN && !ACK:                                   /* retransmissions and TFO included */
            sk = lookup_listener(c, family, TCP)
            if !sk: fault; cnt; SHOT
            if !guard(sk, c): release; fault; cnt; SHOT
            r = bpf_sk_assign(skb, sk, 0); bpf_sk_release(sk)
            if r != 0: fault; cnt(ASSIGN_FAIL); SHOT
            cnt(ASSIGN_TCP); return TC_ACT_OK
        else:
            cnt(PASS_ESTABLISHED); return TC_ACT_OK       /* relies on the kernel request/established lookup */
I4  if UDP:
        sk = lookup_listener(c, family, UDP)
        if !sk: fault; cnt; SHOT
        if !guard(sk, c): release; fault; cnt; SHOT
        r = bpf_sk_assign(skb, sk, 0); bpf_sk_release(sk)
        if r != 0: fault; cnt; SHOT
        cnt(ASSIGN_UDP); return TC_ACT_OK
```

**Boundary:** the `else` branch of I3 is not a promise that the packet will be
accepted. If no request or established socket exists the kernel may RST or drop.
A complete handshake, TFO, retransmission and an engine crash must all be covered
by Phase 0 (§16, Q3).

**Provenance boundary:** `flxrs1` is Flux's own device, has no address, and is
fed only by `flxrs0`'s xmit. Nothing but root can inject a packet into it. That
*is* the provenance boundary, and no custom EtherType, token map or skb metadata
is layered on top of it. (Note that a veth within one netns does **not** clear
`skb->mark` — see the correction in `../history/review-log.md` §0.5.8. Flux does
not use the mark because it does not need to, not because the mark would not
survive.)

**A kernel invariant that must be written down: why `TC_ACT_OK` on the
established branch delivers correctly.**

`bpf_sk_assign()` calls `skb_orphan()`, then sets `skb->sk` to our listener and
`skb->destructor` to `sock_pfree`. `ip_rcv_core()` and `ip6_rcv_core()` contain
this (v6.1 `net/ipv4/ip_input.c:538-540`, comment verbatim: "Must drop socket now
because of tproxy."):

```c
	if (!skb_sk_is_prefetched(skb))
		skb_orphan(skb);
```

`skb_sk_is_prefetched()` is exactly the test `destructor == sock_pfree`. So both
paths are correct, for different reasons:

| Path | `skb->sk` entering `ip_rcv_core` | Does `ip_rcv_core` orphan it? | Result of the later lookup |
|---|---|---|---|
| SYN, already assigned | our listener, destructor `sock_pfree` | **no**, it is prefetched | `skb_steal_sock()` returns the listener directly ✓ |
| established or fragment, not assigned | **still the app's own socket** — crossing a veth does not orphan | **yes** | `skb_steal_sock()` returns NULL, and the tuple lookup finds the engine's accepted child ✓ |

Why the second row cannot wrongly find the app's own socket: the established
lookup keys on local = `daddr:dport` and remote = `saddr:sport`. Our inbound
packet has `saddr=app_ip, sport=app_port, daddr=server_ip, dport=server_port`, so
the local side is `server_ip:server_port` — which is the engine's transparent
accepted child, whose `ir_loc_addr` came from the SYN's daddr. It is **not** the
app's socket, whose local side is `app_ip:app_port`.

**Two prohibitions follow.** ① `bpf_sk_assign()` MUST NOT be called on an
established or data packet: associating the listener with a data segment makes
`tcp_v4_rcv` use the wrong socket. ② `skb->destructor` MUST NOT be set to
`sock_pfree` anywhere as a convenience, because that skips the orphan in
`ip_rcv_core` and lets `skb_steal_sock` recover the app's own socket — handing
the app its own packet back. Together these are the entire reason the `else`
branch of I3 must be `TC_ACT_OK` rather than a second assign.

## 7.5.0 A trap that lies past the verifier: arm64 5.15 has no fetching atomics

**Measured 2026-08-25 on SM-S9180 / 5.15.211**, as a by-product of Phase 0 Q1
(§16.6).

Writing `__sync_fetch_and_add(p, 1)` in BPF **and using its return value**
generates a `BPF_ATOMIC` instruction carrying the `BPF_FETCH` flag. Loading such
a program on arm64 5.15 fails:

```
libbpf: prog 'q1_probe': BPF program load failed: Unknown error 524
processed 167 insns (limit 1000000) ... total_states 15 peak_states 15
libbpf: prog 'q1_probe': failed to load: -524
```

`524` is `-ENOTSUPP`. Note the shape of that log: **the verifier itself passed** —
167 instructions, no complaint — and the failure came afterwards, in the JIT. So
this is not a malformed program but an instruction the platform does not
implement, reported by an errno that points nowhere near the cause.

**Rule: the data plane MUST NOT use a fetching atomic.** A non-fetching atomic
add, the plain `BPF_XADD` form, is unaffected.

The design satisfies this **by construction rather than by discipline**:
`counters` is a `PERCPU_ARRAY` and per-CPU data cannot contend, so `cnt()` is an
ordinary `*v += 1`; `uid_stats` (D23) is a `PERCPU_HASH` for the same reason. The
generation number comes from `flux_control.generation`, published by userspace,
and the data plane increments no global counter at all.

**An implementer will walk into this while debugging**, wanting one global count
to see what is happening, reaching for `__sync_fetch_and_add`, and then staring
at `-524`. That is the reason to write it down rather than rely on the design not
needing it.

## 7.5.1 Verifier traps

Each of these makes the algorithms of §7.3–§7.5 **fail to load** rather than
behave wrongly. Every row states the correct form, because the verifier's message
usually does not point at the real cause.

| # | Trap | Correct form |
|---:|---|---|
| 1 | **Pointers die across a helper.** After `bpf_skb_pull_data()`, `bpf_skb_change_head()` or `bpf_skb_store_bytes()`, the `data` and `data_end` read earlier and every pointer derived from them are invalid | Re-read `skb->data` and `skb->data_end` after every such call and redo all bounds checks. Never reuse the earlier pointer "just once more" |
| 2 | **A flag is not tracked as related to a pointer.** `int ok = (c && ...); if (ok) c->field;` is rejected | Put the dereference of `c` inside the **same** condition chain as `if (c && ...)`. This is why step E4 of §7.3 is not written as a ternary, and the reference C carries an explicit comment saying so |
| 3 | **A variable offset has no visible bound.** In `data + ip->ihl * 4`, `ihl` came from the packet | Compute into a local and **clamp explicitly** — `if (ihl_bytes < 20 \|\| ihl_bytes > 60) return -1;` — before it takes part in address arithmetic |
| 4 | **A `bpf_sk_lookup_*` reference must be released exactly once on every path.** An early return that forgets is a reference leak and fails to load | Use a single-exit shape immediately after each lookup: guard, store a bool, release, then branch on the bool. Do not `return` from inside the `if` |
| 5 | `bpf_sk_fullsock()` **takes no reference**, so releasing it is rejected with "reference has never been acquired" | Release only pointers obtained from `bpf_sk_lookup_tcp/udp` |
| 6 | **The IPv6 extension header loop.** A `for` bound must be a compile-time constant, and the accumulated offset needs a visible ceiling | `#pragma unroll` with the two ceilings `FLUX_IPV6_MAX_EXT_HDRS` (4) and `FLUX_IPV6_MAX_EXT_BYTES` (256), **checking the bound before advancing the offset** |
| 7 | **A map value pointer's NULL check is never optional**, including a fixed index into a `PERCPU_ARRAY` | Even a `counters` increment must be wrapped in `if (v)`; see `cnt()` in the reference C |
| 8 | **The inner pointer of a map-in-map**: `bpf_map_lookup_elem(&control_root, &z)` returns a map pointer, and a second lookup is needed for the value. Both must be NULL-checked | See `ctrl()`, and look it up **once per invocation**, which §6.4's atomic snapshot requires |
| 9 | **`__builtin_memcmp` and `memcpy` lengths must be compile-time constants** | Use the fixed lengths 4, 6 and 16; never a variable length |
| 10 | **The 512-byte stack limit.** A `struct bpf_sock_tuple`, a `flux_pkt` and a `flux_decision` on the stack together come close to it | Keep `flux_pkt` to the fields actually needed, currently 32 bytes; build the tuple in place where it is used rather than passing it between functions; remember `static __always_inline` shares the caller's frame, so the sizes add up |
| 11 | **`skb->protocol` is a zero-extended `__be16`**, not host order | Compare against `bpf_htons(ETH_P_IP)`, never against `0x0800` |
| 12 | **`bpf_sock->src_port` is host order while `dst_port` is network order** — a pre-existing kernel ABI inconsistency | The guard in §7.4 compares `src_port` against `bpf_ntohs(listen_port)` |
| 13 | **An `-mcpu` newer than the kernel** produces unknown instructions | Pin `-mcpu=v3`, which 5.15 supports. Do not use `v4` |
| 14 | **Passing `BPF_PROG_LOAD` on 6.x does not mean passing on 5.15**; newer kernels relaxed many constraints | §15.1 states where the baseline evidence actually comes from, and why CI alone does not supply it |

**Debugging discipline:** when the verifier rejects a program, read the **last 20 lines** of the log — the point of failure — not the first. `log_level=1` is enough; the instruction-level dump of `log_level=2` is only for diagnosing a state explosion. The log-retry mechanism of §12.7 item 3 ensures the real error is never lost to an undersized log buffer.

## 7.6 How UID policy sticks to a flow

`uid_policy` holds exactly two values:

- `FLUX_UID_SELECTED` — a new TCP flow with no decision may be judged DIRECT or CAPTURED, and UDP may be admitted.
- `FLUX_UID_DRAINING` — an existing TCP decision continues to be honoured by its own mode and generation; a first SYN with no decision installs `DIRECT`; UDP goes direct.

Deselecting an app changes its UID from `SELECTED` to `DRAINING`; it is **not deleted**. Selecting an app affects only flows that have no decision yet. A bypass change behaves the same way.

**Hard invariant: within one boot, a UID entry that could ever have created a
TCP decision MUST NOT be deleted from `uid_policy`**; it may only remain
`SELECTED` or `DRAINING`.

This is what preserves the meaning of "UID miss ⇒ take the shortest Direct
path". Delete the entry instead, and packets belonging to an already-`CAPTURED`
socket hit `UNSPEC` at step E1 and **leak to the real destination** — the exact
outcome §2.2.2 forbids. `DRAINING` entries disappear no later than the next
reboot, and paying for them until then is the price of that guarantee.

Ceilings: at most 4096 UID entries in total, of which at most 1024 are SELECTED. A candidate configuration that would exceed either is rejected, and the current policy stays in force.

Both numbers come from measurement rather than estimation: a real device held
**429** apps in the `[10000, 19999]` range, so the original 512 and 128 made
"proxy every third-party app" structurally impossible — and the never-delete
invariant above means every change to the selection accumulates entries, so 429
selected plus a few edits exceeds 512 (§1.6.3).

---

# Part 8: Network objects and ownership

## 8.1 A dedicated veth

| Property | Value |
|---|---|
| Host end | `flxrs0`, `IFLA_IFALIAS = "flux-rs:managed:v1:host"` |
| Peer end | `flxrs1`, `IFLA_IFALIAS = "flux-rs:managed:v1:peer"` |
| Addresses | **none configured** on either end, IPv4 or IPv6 |
| Link state | both ends UP |
| MTU | 65535 on both ends (`ETH_MAX_MTU`). If the kernel refuses it the seam does not activate; **a smaller value is never guessed** |
| MAC | the kernel's random locally-administered pair, **neither read nor used by Flux** (D17: egress writes no MAC and ingress forces `PACKET_HOST` directly) |
| sysctls on `flxrs1` | `net.ipv4.conf.flxrs1.rp_filter = 0`, `accept_local = 1`; `net.ipv6.conf.flxrs1.accept_ra = 0`, `autoconf = 0` |
| TC | `clsact` + `flx_in` ingress filter |

An object with the same name whose alias or layout does not match exactly is a **conflict**: stay Direct and report it. **Never delete and recreate somebody else's object.** Objects that are ours — the alias matching exactly — are deleted and rebuilt at daemon cold start.

The 65535 MTU exists so that `is_skb_forwardable()` accepts any non-GSO skb; GSO skbs are exempt already.

## 8.2 Why `pkt_type` is corrected on ingress rather than writing a MAC on egress

`veth_xmit → __dev_forward_skb → eth_type_trans()` re-derives `pkt_type` from the destination MAC. When that MAC is not `flxrs1->dev_addr` it becomes `PACKET_OTHERHOST`, and `ip_rcv()` drops `PACKET_OTHERHOST` outright. **Verified** — and note that the `PACKET_HOST` set earlier by `skb_scrub_packet()` is overwritten by the later `eth_type_trans()`, so it does not help.

There are two solutions, and **D17 chose the second**:

| | Write the correct dst MAC on egress | **Call `bpf_skb_change_type(skb, PACKET_HOST)` on ingress** |
|---|---|---|
| control struct | needs `peer_mac` and `host_mac`, 12 bytes | no MAC field at all |
| L2 steady-state hot path | one `bpf_skb_store_bytes(12)` per packet, which triggers `skb_ensure_writable()` — and a retransmitted TCP skb is a clone, so it must be copied | **zero packet writes, zero copies** |
| L3 path | `change_head` plus 14 bytes written | `change_head` plus 2 bytes of EtherType, the first 12 having been zeroed by the helper |
| Correctness rests on | the MAC comparison being exactly right | TC ingress running before `ip_rcv()`, which `sch_handle_ingress` does |

**The L3 path MUST still write the EtherType.** `eth_type_trans()` derives `skb->protocol` from `h_proto`, and a packet with `h_proto == 0` never reaches `ip_rcv()`.

The single cost: packets injected into `flxrs1` carry a zero or stale destination MAC. Nothing on that link does L2 forwarding, so this is cosmetic.

**Upstream precedent:** dae does the same thing on its veth peer ingress — `tproxy_dae0peer_ingress` in `control/kern/tproxy.c` calls `bpf_skb_change_type` — although it also writes the MAC on egress.

## 8.3 The RPDB rule and the route

One rule per family:

```text
priority 100   iif flxrs1   lookup 20260
```

Table `20260` contains only:

```text
local 0.0.0.0/0  dev lo  proto 202
local ::/0       dev lo  proto 202
```

The safety of priority 100 and table 20260 now rests on first-party evidence rather than estimation:

- **netd's lowest `ip rule` priority is 10000** (`clone/aosp-netd/server/RouteController.h:34`; the full ladder from 10000 to 32000 is at `:34-85`). **The entire 1–9999 range is therefore empty**, and priority 100 sits after the kernel's `local` at 0 and before every netd rule.
- **netd's per-interface route tables are `ROUTE_TABLE_OFFSET_FROM_INDEX = 1000` plus the ifindex** (`RouteController.h:100`), occupying roughly `1001` to `1000 + max_ifindex`. Table **20260** is far outside that. Corroborating: `box_for_magisk` independently chose table 2024 and pref 100 (`box.iptables:12-13`).

The rule matches **only** Flux's dedicated ingress and consumes no fwmark. An unknown rule already at priority 100, or an unknown route already in table 20260, means staying Direct and reporting the conflict. **Flux MUST NOT pick a different value dynamically**, because cleanup has to be provable: an object at an address chosen at random cannot be shown to be ours later.

`proto 202` is a self-assigned `rtm_protocol` marker used to identify our own routes exactly.

## 8.4 rp_filter: an implementation-level hole in the two earlier blueprints

**Verified:** `IN_DEV_RPFILTER(idev) = max(net.ipv4.conf.all.rp_filter, net.ipv4.conf.<dev>.rp_filter)` via `IN_DEV_MAXCONF`, while `IN_DEV_ACCEPT_LOCAL` is an **or** via `IN_DEV_ORCONF`. **The asymmetry is the whole problem**: a per-device `rp_filter` of 0 cannot override a global 1, but a per-device `accept_local` of 1 does take effect.

A packet Flux injects into `flxrs1` carries a source address belonging to **the device itself** — wlan0's IP, say — and a remote destination. Input routing hits `RTN_LOCAL` and then reaches `fib_validate_source()`:

- **Effective rp_filter of 0:** because Flux added a custom local route, `net->ipv4.fib_has_custom_local_routes` is true and `__fib_validate_source()` is entered; `accept_local=1` lets `res.type == RTN_LOCAL` through; `dev_match` is false; `flxrs1` has no address so `no_addr` is true, reaching `last_resort:`, where `rpf == 0` means **accept**.
- **Effective rp_filter non-zero:** the same path ends at `goto e_rpf` and the packet is dropped as a **martian source**. `accept_local` cannot save it here, because it only applies on the early-return branch where `r == 0`.

**Implementation requirement:** read both `all.rp_filter` and `flxrs1.rp_filter` at activation.
- Flux sets `flxrs1.rp_filter` to 0. That interface is ours, so writing it is legitimate.
- When `all.rp_filter != 0`, Flux **MUST NOT** modify the global sysctl, which would weaken the device's overall security posture. The whole data plane stays Inactive, and `status` reports the conflict with instructions for the user to act on.
- AOSP does not set `rp_filter` by default, relying on its own RPDB, so 0 is expected on a real device — but this **MUST be checked rather than assumed**.

**There is no Android precedent, but dae hit and confirmed the same problem on Linux.**

`clone/AndroidTProxyShell/tproxy.sh` never writes `rp_filter` or `accept_local` anywhere — **not because Android does not need it**, but because its packets re-enter through **`lo`** and hit the early-return branch in `__fib_validate_source()`: `dev_match = dev_match || (res.type == RTN_LOCAL && dev == net->loopback_dev)`. Flux's packets arrive on `flxrs1` and never reach that branch.

**dae uses veth loopback exactly as Flux does, and it must write these sysctls** (`control/netns_utils.go:433-473`):

| sysctl | dae's value | Line |
|---|---|---|
| `net.ipv4.conf.dae0.rp_filter` | 0 | 437 |
| **`net.ipv4.conf.all.rp_filter`** | **0** | **440** |
| `net.ipv4.conf.dae0.arp_filter` / `all.arp_filter` | 0 | 443 / 446 |
| `net.ipv4.conf.dae0.accept_local` | 1 | 449 |
| peer-side `conf.dae0peer.accept_local` | 1 | 473, with a comment naming martian-source |

**This corroborates the kernel analysis above, and simultaneously exposes a trade-off Flux does not accept: dae writes the global `all.rp_filter=0` directly.** Flux **MUST NOT**, for two reasons. First, silently weakening a global security sysctl on a user's phone is not a networking module's decision to make. Second, after a crash there is no way to prove what value should be restored — a backup-and-restore is not reliable under `SIGKILL`, which is precisely the situation the honesty rule of §15.4(1) governs. So a non-zero effective `rp_filter` means staying Inactive and reporting, leaving the decision to the user.

`arp_filter` is **not needed**: `flxrs0` and `flxrs1` hold no IPv4 address and take no part in ARP. Phase 0 Q5 confirms this incidentally.

**Conclusion:** the mechanism is confirmed by dae, but whether the effective `all.rp_filter` is 0 on Android, and whether declining to write the global sysctl is workable, still **MUST be measured** (§16, Q5).

### 8.4.1 Two pieces of external evidence, and one sysctl that does not apply

**(1) dae has an empirical drop trace** (`daeuniverse/dae` PR #512, CHANGELOG `:403`). It occurred inside dae's **separate netns**, whereas Flux runs in the same netns with a source address that is genuinely local — so the outcome applies to Flux with more certainty, not less:

```
if=83(dae0peer) ... 10.0.8.9:35964 > 1.1.1.2:80 tcp_flags=S ... fib_validate_source
if=83(dae0peer) ... ip_handle_martian_source
if=83(dae0peer) ... kfree_skb_reason(SKB_DROP_REASON_NOT_SPECIFIED)
```

The fix was exactly `sysctl net.ipv4.conf.dae0peer.accept_local=1`. That raises §8.4 from reasoning over kernel source to something somebody hit and left a trace of. Worth noting separately: **`pwru` plus `kfree_skb_reason` is the only effective way to debug this class of problem**, and Phase 0 Q5 should reach for it directly on failure rather than guessing.

**(2) Cilium hit the same problem on an isomorphic topology** — an fwmark rule into a `local default dev lo` — in `cilium/cilium` PR #46312, and observed that it had long been setting only `rp_filter=0` while missing `accept_local`. The two belong **together**. This agrees with §8.4: `IN_DEV_ACCEPT_LOCAL` is an `or` and `IN_DEV_RPFILTER` is a `max`, so both have to be right.

**(3) `net.ipv4.conf.all.src_valid_mark` does not apply. Do not copy it.** Cilium sets it so that the reverse lookup in `fib_validate_source()` **carries the fwmark** and therefore matches a mark-based rule. Flux's rule keys on `iif flxrs1` rather than fwmark, and during the reverse lookup the `iif` is `lo`, so our rule cannot match whether a mark is carried or not — setting it achieves nothing. **Recorded here to stop an implementer copying an ineffective global sysctl out of Cilium.**

**(4) AOSP never sets any of these four.** Searching all of `clone/aosp-netd/server` and `clone/aosp-Connectivity` gives **zero hits** for `rp_filter`, `accept_local`, `route_localnet` and `src_valid_mark`. That cuts both ways: no AOSP component will contend with us or change a value back, **and the effective values are determined entirely by the vendor's defconfig and `init.rc`, so they cannot be inferred from AOSP at all.** This is what forces §8.4's implementation requirement to be "read at run time, fail loudly on conflict" with no assumed default.

**`ip_forward` is an inference and MUST be confirmed by measurement.** The analysis: the packet hits `RTN_LOCAL` for local delivery and travels `ip_local_deliver` rather than `ip_forward_finish`, so `ip_forward` does **not** need enabling. But both precedents enable it — AndroidTProxyShell sets `ip_forward=1` and `ipv6 conf/all/forwarding=1` for its forwarding and hotspot paths (`tproxy.sh:1414-1415`, `1433-1434`), and dae lists it as required (`clone/dae/docs/en/user-guide/kernel-parameters.md`). **Both have LAN and forwarding paths that Flux does not**, so their needing it does not imply we do.

**Phase 0 Q5 MUST establish the end-to-end path with `ip_forward=0`.** If measurement shows it is required, that is a **scope change rather than a small fix**: writing the global `ip_forward` shares its objection with §8.4's refusal to write `all.rp_filter` — both alter global network semantics on a user's phone — and it MUST go back to §21 for confirmation rather than being enabled quietly. dae additionally sets `arp_filter=0`, including `all.`; `flxrs0` and `flxrs1` hold no IPv4 address and take no part in ARP, so this is judged unnecessary and confirmed in Q5 as well.

IPv6 has no rp_filter, so none of this arises there.

## 8.5 TC identity and the ownership predicate

| Position | chain | pref | protocol | handle | program |
|---|---:|---|---|---:|---|
| Ordinary L2 egress | 0 | chosen per interface, §8.5.3 | all | `0x1` | `flx_cap_l2` |
| Ordinary L3 egress (rmnet) | 0 | chosen per interface, §8.5.3 | all | `0x1` | `flx_cap_l3` |
| Confirmed CLAT egress | 0 | chosen, `< FLUX_TC_PREF_CLAT_MAX` (4) | ip | `0x1` | `flx_cap_l3` |
| `flxrs1` ingress | 0 | 1, fixed — Flux owns this interface | all | `0x2` | `flx_in` |
| Liveness probe | 0 | same pref as that interface's capture filter | all | `0x3` | `flx_verify` |

The complete ownership predicate — **every** item must match before a filter may
be adopted or deleted: netns, ifindex, ifname, parent and direction, chain,
preference, protocol, handle, `kind == "bpf"`, the direct-action flag,
**`TCA_BPF_ID`** (the program id), **`TCA_BPF_TAG`** (the 8-byte hash of the
instruction stream), `TCA_BPF_NAME`, and the program's expected map set.

**Why the id and the tag are required.** A program name can be forged, and it
also survives the program being replaced underneath it. `TCA_BPF_TAG` is the
kernel's hash of the instruction stream and `TCA_BPF_ID` is unique to this load;
Flux obtains both from its own `BPF_OBJ_GET_INFO_BY_FD` and holds them as the
expected values. This is the five-way exact match of
`clone/asteriskd/asteriskd_tc_netlink.c:170-177` (`TCA_BPF_NAME`, `FLAGS`,
`FLAGS_GEN`, `TAG`, `ID`), and it is the single most directly reusable finding of
the whole source review.

**Dump parsing MUST use an allowlist.** Attribute types are accepted from a known
set, at the top level and inside `TCA_OPTIONS` alike; an unknown or duplicated
attribute fails the parse and marks the slot foreign
(`asteriskd_tc_netlink.c:141-157`). `NLMSG_OVERRUN` is fatal. **Every failure
path marks the slot foreign and fails closed** — "it looks like ours, adopt it"
is forbidden.

**A TOCTOU guard using two dumps.** Before deleting or adopting any filter, take
two consecutive dumps and compare `{id, tag, name, flags}` item by item. A
mismatch returns `ESTALE` and abandons this round; the next event tries again.
This mirrors `clone/bpf2socks/bpf_util.c:411-454`, which does the same for
`BPF_PROG_QUERY`.

**When a `clsact` is foreign.** If the dump shows the `clsact` carrying
`TCA_INGRESS_BLOCK` (13) or `TCA_EGRESS_BLOCK` (14), or a non-empty
`TCA_OPTIONS`, it is foreign and **the interface is excluded** — a shared block
means another controller is managing filters through indirection Flux cannot see
(`asteriskd_tc_netlink.c:333-341`). This is the concrete detection behind "block
or goto makes chain 0 unreachable".

### 8.5.0 Reachability, not first place in the dump

**Flux's filter does not have to be the first classifier in chain 0.** The
earlier requirement that it must be does not survive contact with real devices:
a vendor may already hold pref 1, and tc's lowest preference *is* 1 (§8.5.3).

The real requirement is that **no classifier ahead of Flux terminates the
chain**, and that condition **cannot be inferred from a dump**. A dump says who
is in front; it does not say what they return. AOSP's ingress accounting returns
`TC_ACT_UNSPEC` and CLAT translation returns `TC_ACT_PIPE`, but neither fact
vouches for an OEM program. The determination is therefore **measured, not
reasoned**: the liveness verification of §8.5.4.

Activation requires all four of:

1. identity and relative ordering satisfy the ownership predicate;
2. the CLAT position constraint holds where CLAT applies;
3. `flx_verify` observes packets inside a real tx-growth window;
4. re-verification happens whenever the identity of a numerically lower
   preference — that is, a filter ahead of us — changes.

Direct returns `TC_ACT_UNSPEC`, handing the packet to every later system
program. An interface MUST NOT be marked active if any of these hold: a `block`
or `goto` makes chain 0 unreachable; the post-attach dump does not satisfy the
ownership predicate; every preference below `FLUX_TC_PREF_CLAT_MAX` is taken on a
`v4-*`; **or liveness verification finds us shadowed**.

**`clsact` ownership.** A physical interface's `clsact` belongs to netd. Flux
**MUST NOT create, replace or delete it.**

- A physical interface with no `clsact` is excluded as `netd_clsact_missing`.
  Admission runs again when netd's `RTM_NEWQDISC` arrives.
- A physical `clsact` carrying a shared block, non-empty options, or unknown or
  duplicated attributes is foreign, and the interface is excluded.
- **Only `flxrs1`'s `clsact` is created by Flux**, and its lifetime is the veth
  pair's.

The temptation is to create the missing qdisc and proceed, and it has to be
refused for two independent reasons. After a crash there is no way to prove who
created it, so it can never be safely deleted again; and netd deletes and
recreates it as a matter of routine (§8.5.1), so racing to create it means
contending with the component that owns it. Waiting costs a window in which that
interface is Direct — which §2.2.3(5) already publishes.

Flux deletes only its own exactly-matched filters, and MUST NOT flush a qdisc or
a chain.

### 8.5.1 netd deletes `clsact` routinely — design for it, not around it

This is the operationally most consequential finding of the whole source review. It MUST be designed for as a frequent event, not handled as an exception.

`maybeModifyQdiscClsact()` at `clone/aosp-netd/server/RouteController.cpp:1201-1229` **creates the `clsact` when an interface joins a network and deletes it when the interface leaves** (call sites `:1347`, `:1374`, `:833`). More sweepingly, netd clears the clsact of every interface at startup:

```cpp
// clone/aosp-netd/server/NetworkController.cpp:152-164
// Clear all clsact stubs on all interfaces.
for (const std::string& iface : ifaces.value()) {
    if (int ifIndex = if_nametoindex(iface.c_str())) {
        tcQdiscDelDevClsact(ifIndex);
    }
}
```

AOSP documents the constraint itself at `ConnectivityService.java:12231-12240`: "*in case of a system server crash, the NetworkController constructor in netd (called when netd starts up) deletes the clsact qdisc of all interfaces*".

**Direct consequences for this design:**

1. **Every Wi-Fi reconnect, every cellular handover, and every netd restart after
   a system_server crash takes our filter with it.** This is not a rare fault; it
   is daily life.
2. The reactor MUST therefore subscribe to `RTM_NEWQDISC` and `RTM_DELQDISC` and
   treat a vanished qdisc as an **expected event**: exclude that interface as
   `netd_clsact_missing` and **wait for netd's `RTM_NEWQDISC`**, then redo step 9
   of §8.7 — the egress attach — for that one interface, **without reporting an
   error, without entering `Inactive`, and without touching `active`**. Flux does
   not create the qdisc itself (§8.5). §26 lists this separately as
   **capture-side drift**, distinct from **core drift** which does require
   `active=0`. Conflating the two is forbidden; invariant 4 of §26 explains what
   it costs.
3. **Do not expect to be the only creator.** AOSP uses
   `tcQdiscReplaceDevClsact` with `NLM_F_CREATE | NLM_F_REPLACE`
   (`aosp-netd/server/TcUtils.h:28-37`). Flux uses `NLM_F_EXCL` and reads
   `EEXIST` as "it exists and I did not create it" (§8.9.4) — equivalent in
   effect, and it additionally yields the information about who created it.
4. Between re-attachments there is a window in which traffic goes Direct, on the
   order of rtnetlink delivery plus the debounce of §10.4.1. See §2.2.3(5).

### 8.5.2 TC preferences AOSP already occupies on a physical interface

| pref | Direction | protocol | Held by | Evidence |
|---:|---|---|---|---|
| 1 | ingress | `ETH_P_ALL` | `tc police` inbound rate limiting | `ConnectivityService.java:974` (`TC_PRIO_POLICE = 1`), `:1730` |
| 2 | ingress | `ETH_P_IPV6` | tethering downstream6 | `Tethering/.../BpfUtils.java:57-61` |
| 3 | ingress | `ETH_P_IP` | tethering downstream4 | same |
| 4 | ingress | `ETH_P_IPV6` | CLAT ingress6, on the upstream | `ClatCoordinator.java:107-109`, `:499-505` |
| 4 | **egress** | `ETH_P_IP` | CLAT egress4, on the `v4-*` | `ClatCoordinator.java:473-479` |
| **5** | **egress** | `ETH_P_ALL` | **dscpPolicy** | `DscpPolicyTracker.java:50-51` (`PRIO_DSCP = 5`), `:338` |

Three conclusions:

1. **ingress pref 1 is contended on a physical interface**, by `tc police`. This
   does not affect Flux: our ingress filter lives only on our own `flxrs1`, where
   nobody else is.
2. ~~**egress pref 1 is uncontended**~~ — **overturned by the measurement in
   §8.5.3.** As far as *AOSP* goes, egress pref 1 is indeed free, with CLAT at 4
   and dscpPolicy at 5. But **this table covers AOSP and not OEMs**, and
   Samsung's `semUidBPF` holds egress pref 1. What survives of the constraint is
   "must precede CLAT at pref 4".
3. **`dscpPolicy` at egress pref 5 is skipped.** With our preference below 5, a
   captured packet returns `TC_ACT_REDIRECT` at our filter and the chain ends, so
   dscpPolicy never sees it. Consequences in §2.2.3(6).

### 8.5.3 A vendor already holds egress pref 1, so the preference cannot be fixed

> **Measured 2026-08-25, overturning an assumption implicit in §8.5.2.** The
> assumption was that AOSP uses only pref 1 on ingress (`tc police`), 4 and 5, so
> **egress** pref 1 belongs to us. On SM-S9180 running Android 16:

```
# tc filter show dev wlan0 parent ffff:fff3        (clsact egress)
filter protocol all pref 1 bpf chain 0 handle 0x1 \
    prog_semUidBPF_schedcls_egress_tsm_ether id 96 tag 2ef4ef809be2dd32 jited
```

Samsung's `semUidBPF` occupies **`chain 0` / `pref 1` / `handle 0x1` /
`protocol all`** — **the same four-tuple** that `flux_abi.h` named in
`FLUX_TC_CHAIN`, `FLUX_TC_PREF` and `FLUX_TC_HANDLE_EGRESS`. The ingress side is
likewise held by `..._ingress_tsm_ether`, which does not affect Flux because our
ingress filter is on our own veth.

**Three hard constraints follow:**

1. **Preference 1 cannot be reserved.** tc priorities run `1..0xFFFF` and 1 is
   already the minimum, so on an interface where a vendor holds pref 1 **there is
   no way to get in front of it**. The fixed constant `FLUX_TC_PREF` is deleted
   and replaced by three bounds — `FLUX_TC_PREF_PREFERRED` (2), `_MIN` (1),
   `_CLAT_MAX` (4) — plus **selection from the dump at attach time**, with the
   preference actually taken recorded in the ownership predicate and in `status`.
2. **On a CLAT `v4-*` it MUST still be below 4**, since AOSP's CLAT egress sits
   at pref 4 (§3.4). If 1, 2 and 3 are all taken on that interface, the ordering
   constraint cannot be satisfied and **the interface is excluded**. Do not fall
   back to a preference at or above 4.
3. **"Attach succeeded" no longer means "it works".** If a vendor program at a
   lower preference returns `TC_ACT_OK` or `TC_ACT_PIPE`, the classifier chain
   ends before us and our program **receives not one packet, while the attach
   itself succeeded completely**. Activation therefore gains a step of **positive
   liveness verification** (§8.5.4). A shadowed verdict **excludes only that
   interface** — not the whole data plane — and reports `tc_chain_shadowed`. It
   runs after step 9 of §8.7 and before step 10.

**There is also a race, harder to handle than any of the three.** When the probe
first ran, `wlan0` was connected, held a global address and had a `clsact`, but
**no filter yet**; Samsung attached its egress program minutes later. The program
itself had been loaded and pinned by bpfloader seven seconds after boot — being
loaded and being attached are two different events. Consequences:

- **A one-time conflict check misses this.** Pref 1 being free at activation does
  not mean it stays free.
- **If Flux takes pref 1 first**, the vendor's later attach either fails, meaning
  Flux has silently broken Samsung's traffic accounting, or uses `NLM_F_REPLACE`
  and evicts us, meaning capture silently stops. Neither is acceptable.
- **So pref 1 MUST NOT be taken even when it is free.** The selection policy is
  "the lowest preference that satisfies the ordering constraint, avoiding the
  vendor-conventional pref 1", backed by continuous monitoring through §10.4's
  `RTM_NEWTFILTER` events — both that our own filter is still there and that
  nothing new has been inserted ahead of it.

**This also changes the impact assessment of §2.2.3(6).** Beyond AOSP's
`dscpPolicy`, this device carries Samsung's `tosMarker` family of **five** egress
programs — `classify_ack`, `classify_uid`, `classify_queue_mapping`,
`set_queue_mapping`, `set_tos_mobile` — plus ether variants of `mnxbNetd`,
`semUidBPF_ape` and `tcpAccECN`. Far more downstream filters are bypassed by
captured traffic than the original blueprint assumed.

> **Measured 2026-08-25, additionally: occupancy is per interface, not per
> device.** "Samsung holds egress pref 1" reads like a device-level fact.
> **It is not.** On the same SM-S9180, with Wi-Fi disconnected and cellular as
> the primary network, `rmnet_data0`, `rmnet_data1` and `rmnet_data8` all had a
> `clsact` and **not one filter on either side** (§16.9.2).
>
> The name says so itself: the `..._tsm_ether` suffix is `ether`, so it is meant
> for `ARPHRD_ETHER`, and RAWIP cellular interfaces are out of its scope.
>
> **Direct consequence for the implementation:** the available preference MUST
> NOT be cached as one value for the device. Dump, select and run §8.5.4's
> liveness verification **per interface**. On one device cellular may be able to
> take pref 1 — though the reasoning above says still avoid it — while Wi-Fi can
> only take 2. Extrapolating an observation on `wlan0` to `rmnet` produces the
> wrong exclusion decision.

### 8.5.4 Positive liveness verification: the only vendor-independent test

Constraint 3 of §8.5.3 states the requirement; this section fixes the mechanism.
**This is the only health check in the entire design that depends on no vendor
knowledge**, so its implementation is specified rather than left to the
implementer.

**The problem.** A successful `attach` syscall proves the filter is installed. It
does not prove the filter will run. If a program at a lower preference in the
same chain returns `TC_ACT_OK` or `TC_ACT_PIPE`, `__tcf_classify` terminates
there and our program **receives no packet and produces no error code**. This is
the most likely "installed but nothing happens" failure mode in the design, and
on an unfamiliar OEM there is no way to know in advance who is ahead of us.

**Why the existing counters cannot answer it.** §6.1 increments counters only at
decision, drop and fault edges, precisely so that unselected traffic keeps its
steady-state cost of one helper plus one hash miss (§14.1). If no selected app
happens to be communicating, every counter stays still — which is
indistinguishable from the program never having run.

**Why kernel statistics cannot answer it either.** In direct-action mode
`cls_bpf` does not go through `tcf_exts_exec` and does not update `bstats`. And
measured on this device, `iproute2-ss171113` returns nothing at all for
`tc -s filter show`, so that route is unreliable in practice as well as in
theory.

**A rejected design, stated because it is the natural first idea.** Add a
`verify` flag to `flux_control` and have `flx_cap_l2/l3` count when it picks up
the snapshot. **This does not work.** Look at step E1 of §7.3: unselected traffic
returns `TC_ACT_UNSPEC` on the `uid_policy` miss and **never reaches `ctrl()`**,
which is only called on the E2 branch where a decision already exists. Making the
flag effective would mean hoisting the snapshot lookup to the very top of the hot
path, paying two extra map lookups on **every outbound packet on the device** —
destroying the performance floor of §14.1 permanently to serve a check that runs
for two seconds at activation.

**The mechanism: a separate probe program, `flx_verify`.**

```c
SEC("tc/verify")
int flx_verify(struct __sk_buff *skb) {
	cnt(FLUX_CNT_SAW_PACKET);
	return TC_ACT_UNSPEC;   /* changes no packet's fate */
}
```

The procedure, run per interface between steps 9 and 10 of §8.7:

1. Dump that parent per §8.5.3 and select the target preference **P**.
2. Attach `flx_verify` at
   `(parent, protocol all, pref P, handle FLUX_TC_HANDLE_VERIFY)`.
3. Read `counters[FLUX_CNT_SAW_PACKET]` as a baseline, wait one timerfd window —
   2 s is the recommended value — and read it again.
4. **Decide:**
   - **Difference > 0 ⇒ preference P is reachable.** Detach the probe and attach
     the real capture program at the same preference P with handle `0x1`. Both
     are direct-action `cls_bpf` filters on the same parent, protocol and
     preference, so their positions are exactly equivalent: if the probe runs,
     the capture program runs.
   - **Difference == 0 ⇒ the two possible causes MUST be distinguished**, or
     "no traffic right now" gets misreported as "shadowed". Read whether that
     interface's `/sys/class/net/<if>/statistics/tx_packets` grew over the same
     window.
     - **tx grew while the count did not ⇒ shadowing confirmed.** Record
       `tc_chain_shadowed`, remove the interface from the active set, and **name**
       in `status` the filters in that chain at a preference below P. On an
       unfamiliar device that naming is how a user substantiates the diagnosis.
     - **tx did not grow either ⇒ no conclusion.** Retry after a backoff, reusing
       the timerfd of §10.4. If the backoff ceiling is reached with still no
       traffic, mark the interface unverified and **allow activation anyway** —
       refusing to work because the user happened not to be online is worse than
       an unverified attach.
5. Only after every interface has been processed does step 10 perform the single
   pointer swap publishing `active = 1`.

**Five hard constraints:**

- **`active` MUST be 0 throughout verification.** Capturing traffic in a state
  not yet confirmed to work is experimenting on the user's connections.
  Conversely, *because* `active == 0`, the microsecond gap between detaching the
  probe and attaching the capture program is harmless.
- **`flx_verify` MUST return only `TC_ACT_UNSPEC`.** It is an observer, not a
  policy.
- **`FLUX_CNT_SAW_PACKET` MUST be touched only by `flx_verify`.** The capture and
  ingress programs MUST NOT write it. This is the only way the zero-hot-path-cost
  property stays true rather than merely intended.
- **Use the distinct handle `0x3`**, not the capture handle `0x1`. The ownership
  predicate then can never confuse the two, and residue left by a crash during
  verification remains exactly identifiable and deletable — the cleanup in step 3
  of §8.7 must recognise this handle.
- **A failed verdict excludes only that interface** and does not enter
  `Inactive`, consistent with §26 invariant 4 on capture-side handling.

**Other failures this covers incidentally:** attaching to the wrong parent; the
interface having gone down while the filter remains; and a new vendor filter
appearing at a lower preference. All three present as "tx grew, count did not".

**Re-verification.** In steady state, if the reactor sees an `RTM_NEWTFILTER`
whose preference is below ours, it can attach a probe at **P+1**: if P+1 is
reachable then P necessarily is, so we confirm we are still working **without
touching our own filter**. This is a benefit the rejected control-bit design does
not have.

**There is no precedent for this; do not expect to copy one.**
`../history/review-log.md` §0.5.10 read every project in the corpus that attaches
a TC filter: **not one verifies that its program actually executes.** The closest
is asteriskd, which dumps with `RTM_GETTFILTER` after attaching and compares
object id, program tag, bpf name and the `da` flag. That verifies **identity** —
is my filter still there, and is it mine — not **execution**. When shadowed by a
filter in front, an identity check **passes**. They are different failures and
both need covering: identity by the ownership predicate of §8.5 plus
`RTM_NEWTFILTER` monitoring, execution by this section.

**One contrast asteriskd does teach.** When it finds its own slot occupied by a
stranger it **refuses to start**, reporting `"foreign TC resource collision"`.
That is fail-closed, simple and safe — and it would make Flux entirely unusable
on a Samsung device. Choosing "pick another preference and measure whether we are
reached" is strictly more capable, and the price is having to implement this
section rather than borrow it.

## 8.6 Interface admission

Interfaces that might carry this host's output are collected from live
rtnetlink link, address and route events. **Names are never hardcoded.**
Excluded:

- `lo`, `flxrs0`, `flxrs1`;
- generic TUN and TAP, an active Android VPN, bridge, bond, veth, dummy, team;
- tether, downstream and LAN-only interfaces;
- VLAN, unknown ARPHRD, unknown layout;
- any interface whose existing TC filters occupy Flux's exact identity;
- any interface where the ordering constraint of §8.5.0 cannot be satisfied,
  including a `v4-*` whose conditions do not hold.

One interface failing excludes only that interface; the rest continue. The
candidate set is hard-limited to 64; exceeding it means the whole new topology
candidate is not promoted and the current state or Direct is kept — **the list is
never truncated by name**. `status` MUST list every candidate as either `active`
or `excluded(reason)`.

## 8.7 Ordered activation on a cold start with a valid configuration

Strictly in order. A step that fails does not proceed to the next, and any
control snapshot that already exists stays at `active=0`:

1. Take the daemon lock. Check `sysconf(_SC_PAGESIZE) == 4096`, netns identity
   and the runtime directory permissions. An unsupported page size means
   Inactive and Direct immediately, with no engine started and no object
   created.
2. **Clean up.** Enumerate by the ownership predicate and delete every residual
   object of our own — TC filters, RPDB rules, route table entries, the veth.
   An object matching by name but not by predicate is a conflict: Inactive, and
   report it.
3. Check `all.rp_filter`. Create the veth, set MTU and sysctls, bring it up. **No
   MAC is read**, because since D17 the control struct has no MAC field.
4. Create the route table 20260 entries and the two RPDB rules.
5. Load the BTF, the 12 maps and the 4 programs, `flx_verify` (§8.5.4) among
   them. Register the ringbuf with epoll. Publish the initial frozen leaf with
   `active=0`.
6. Parse `packages.list` and the configuration; fill `uid_policy`, the two
   bypass LPM tries (fixed prefixes tagged `RESERVED`, user prefixes tagged
   `POLICY`, §6.1.1) and the two `self_addr` HASH maps (D20).
7. Generate the engine configuration (§28.2), run `sing-box check`, start the
   child, and wait for its 4 sockets to pass SOCK_DIAG plus the PID and inode
   cross-check.
8. Create the `clsact` on `flxrs1` and attach `flx_in` — **before** any egress
   attach, so the return path is ready first.
9. Process each supportable interface independently, one failure excluding only
   that interface: dump the parent and select an available preference (§8.5.3),
   attach `flx_verify` and run liveness verification (§8.5.4), then on success
   detach the probe and attach `flx_cap_l2` or `flx_cap_l3` at the same
   preference.
10. One final `control_root` pointer swap publishes the complete generation
    snapshot with `active=1`.

**`active` is 0 throughout steps 1 to 9**, which is what makes step 9's
verification safe: no traffic changes course while Flux is still establishing
whether it can be reached.

Normal shutdown reverses only the first half: publish an `active=0` leaf, then
stop the engine.

## 8.8 What a crash leaves behind

If `fluxd` dies abnormally its TC programs and maps may survive, but its direct
child is killed by the kernel through `PR_SET_PDEATHSIG=SIGKILL`, so the
listeners close with the process. The consequences follow from that asymmetry:

- unadmitted TCP and UDP go Direct because `listener_alive()` misses — **this is
  the mechanism that delivers the pre-admission guarantee of §2.2.1**, not a
  separate safety net;
- packets on a flow that already holds a TCP decision are still redirected, and
  then dropped when the ingress lookup misses — which is §2.2.2 behaving as
  specified rather than a residual defect;
- once the supervisor restarts the reactor (§13.2.2), §8.7's delete-and-rebuild
  returns everything to a known state.

A manual `disable` or `stop` follows the same order: publish `active=0` first,
then stop the engine. Objects remain until the daemon restarts or the device
does. After an uninstall and a reboot, every non-persistent kernel object is gone
on its own.

## 8.9 netlink messages, field by field

§12.8 rules out shelling out to `ip` and `tc`, so these messages are encoded
here. This section fixes the **exact fields** so that no implementer has to
guess.

Every attribute is a standard `nlattr` TLV on a 4-byte alignment. Every request
carries `NLM_F_REQUEST | NLM_F_ACK` and **MUST wait for and check
`NLMSG_ERROR`**: success is `error == 0`, and ignoring the ACK is the single most
common way for one of these operations to fail silently.

### 8.9.1 Creating the veth pair

`RTM_NEWLINK` with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. `EXCL`
turns "already exists" into an explicit `EEXIST` rather than a silent overwrite:

```text
ifinfomsg { ifi_family = AF_UNSPEC, ifi_type = 0, ifi_index = 0, ifi_flags = 0, ifi_change = 0 }
  IFLA_IFNAME    = "flxrs0"
  IFLA_MTU       = 65535
  IFLA_LINKINFO (nested)
    IFLA_INFO_KIND = "veth"
    IFLA_INFO_DATA (nested)
      VETH_INFO_PEER (nested)          /* = 1 */
        ifinfomsg { all zero }         /* this embedded header is required; its length counts inside the attr */
        IFLA_IFNAME = "flxrs1"
        IFLA_MTU    = 65535
```

**The trap:** the `VETH_INFO_PEER` payload **begins with a complete `struct ifinfomsg`**, and only then carries the peer's attributes. Omitting it yields `EINVAL`.

The alias and the up transition are two further messages — `RTM_NEWLINK` without `CREATE|EXCL`, addressed by `ifi_index`:

```text
/* set the alias, used for ownership identification in §8.5 */
ifinfomsg { ifi_index = <idx> }   IFLA_IFALIAS = "flux-rs:managed:v1:host"
/* bring it up */
ifinfomsg { ifi_index = <idx>, ifi_flags = IFF_UP, ifi_change = IFF_UP }
```

`ifi_change` is a mask and **MUST set only the bits being changed**. Passing `~0` writes every other flag to 0 as a side effect.

### 8.9.2 The two local routes in table 20260

`RTM_NEWROUTE` with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`:

```text
rtmsg {
  rtm_family   = AF_INET (or AF_INET6)
  rtm_dst_len  = 0                     /* default */
  rtm_src_len  = 0
  rtm_tos      = 0
  rtm_table    = RT_TABLE_UNSPEC       /* 0; a table id > 255 MUST travel in RTA_TABLE */
  rtm_protocol = 202                   /* FLUX_ROUTE_PROTO, our own marker */
  rtm_scope    = RT_SCOPE_HOST         /* RTN_LOCAL requires HOST */
  rtm_type     = RTN_LOCAL
  rtm_flags    = 0
}
  RTA_TABLE = 20260
  RTA_OIF   = <ifindex of lo: usually 1, but look it up>
```

**Three traps.** ① The table id 20260 does not fit the 8 bits of `rtm_table`, so it MUST go in `RTA_TABLE` with `rtm_table` set to `RT_TABLE_UNSPEC`. ② With `rtm_type = RTN_LOCAL`, `rtm_scope` MUST be `RT_SCOPE_HOST`; `UNIVERSE` returns `EINVAL`. ③ Look up the ifindex of `lo` rather than hardcoding 1.

### 8.9.3 The two RPDB rules

`RTM_NEWRULE` — the rule variant of `RTM_NEWROUTE`, whose body is a `struct fib_rule_hdr` — with the same flags:

```text
fib_rule_hdr {
  family   = AF_INET (or AF_INET6)
  dst_len  = 0, src_len = 0, tos = 0
  table    = RT_TABLE_UNSPEC           /* likewise travels in FRA_TABLE */
  action   = FR_ACT_TO_TBL             /* = 1 */
  flags    = 0
}
  FRA_PRIORITY = 100                   /* FLUX_RULE_PRIORITY */
  FRA_TABLE    = 20260
  FRA_IIFNAME  = "flxrs1"              /* IIFNAME, not OIFNAME */
```

**`FRA_IIFNAME` is what makes the whole design safe.** It confines the rule to the one input device only Flux-injected packets can arrive on. `FRA_FWMARK` would consume Android fwmark space (§3.1), and `iif lo` would catastrophically match **every locally generated packet on the device** — `iif lo` is precisely how netd expresses "locally generated".

Deletion uses `RTM_DELRULE` and **MUST carry the identical `FRA_PRIORITY`, `FRA_TABLE` and `FRA_IIFNAME`**. Priority alone would delete somebody else's rule.

### 8.9.4 `clsact` qdisc

`RTM_NEWQDISC`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`：

```text
tcmsg {
  tcm_family = AF_UNSPEC
  tcm_ifindex = <idx>                  /* re-resolve with if_nametoindex immediately before use, §10.4.1 */
  tcm_handle  = 0xFFFF0000             /* TC_H_MAKE(TC_H_CLSACT, 0) */
  tcm_parent  = 0xFFFFFFF1             /* TC_H_CLSACT */
  tcm_info    = 0
}
  TCA_KIND = "clsact"
```

**This message is issued for `flxrs1` only.** A physical interface's `clsact` is
netd's, and Flux never creates it (§8.5); there, the same `tcmsg` is used with
`RTM_GETQDISC` to inspect rather than with `RTM_NEWQDISC` to create.

On `flxrs1`, `EEXIST` means residue from a previous run, which the cold-start
rebuild of §8.7 step 2 removes.

On a physical interface the dump MUST confirm the `clsact` carries neither
`TCA_INGRESS_BLOCK` (13) nor `TCA_EGRESS_BLOCK` (14) and that `TCA_OPTIONS` is
empty; otherwise it is foreign and the interface is excluded. Absence of the
qdisc is not a failure to repair but `netd_clsact_missing`, and the interface
waits for netd.

### 8.9.5 BPF filter

`RTM_NEWTFILTER`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`：

```text
tcmsg {
  tcm_family  = AF_UNSPEC
  tcm_ifindex = <idx>
  tcm_handle  = 0x1                    /* egress capture; 0x2 = ingress, 0x3 = flx_verify */
  tcm_parent  = 0xFFFFFFF3             /* egress: TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) */
                                       /* ingress: 0xFFFFFFF2 (TC_H_MIN_INGRESS) */
  tcm_info    = TC_H_MAKE(prio << 16, htons(protocol))
                                       /* prio: selected per interface, §8.5.3 — never a constant */
                                       /* protocol = ETH_P_ALL(0x0003) or ETH_P_IP(0x0800) */
}
  TCA_KIND = "bpf"
  TCA_OPTIONS (nested)
    TCA_BPF_FD    = <program fd>       /* = 6 */
    TCA_BPF_NAME  = "flx_cap_l2"       /* = 7; diagnostic only, never proof of ownership */
    TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT (=1)   /* = 8; this is `da` */
```

**The byte-order trap in `tcm_info`:** the high 16 bits are the priority in host
order, and the low 16 bits are the protocol in **network** order. Writing the
protocol in host order produces a filter that matches no packet **and reports no
error** — the hardest class of bug to find here.

Dumping uses `RTM_GETTFILTER` with `NLM_F_DUMP` and
`tcmsg{ tcm_ifindex, tcm_parent }`. The kernel additionally returns
`TCA_BPF_ID` (11), `TCA_BPF_TAG` (10) and `TCA_BPF_FLAGS_GEN` (9), which are the
three the ownership predicate of §8.5 rests on.

**Dump order is execution order, and that is not the same as being reached.**
The dump tells you who runs before you; it does not tell you whether they
terminate the chain, so it cannot establish reachability. Use it for the ordering
constraint and for selecting a preference (§8.5.3), and use `flx_verify`
(§8.5.4) for whether Flux actually runs.

Deletion uses `RTM_DELTFILTER` and **MUST carry the identical `tcm_handle`,
`tcm_parent`, `tcm_info` and `TCA_KIND`**. Omitting any one of them risks
deleting somebody else's filter, or the entire chain.

### 8.9.6 sysctl

`rp_filter` and `accept_local` are ordinary file writes under `/proc/sys/net/ipv4/conf/<if>/`, not netlink. Read the prior value into memory first, for the diagnostics of §23, but **do not restore it on exit**: `flxrs0` and `flxrs1` are rebuilt by us on every start, so there is no prior value worth protecting. `all.rp_filter` is read and never written (§8.4).

---

# Part 9: sing-box integration

## 9.0 An address-range collision that silently disables fakeip entirely

Found while porting the older Flux's `conf/template.json`. **It is a design
defect rather than a misconfiguration**, because it arose from two choices that
were each individually reasonable.

> **Resolved by D21 on 2026-08-25.** The section is kept as a record: the symptom
> is "DNS works, the app connects, nothing loads", which is close to impossible
> to diagnose by guesswork.

sing-box's default fakeip ranges are `198.18.0.0/15` for v4 and `fc00::/18` for
v6. Flux's fixed bypass set **at the time** (§11.2, D16) contained:

- `198.18.0.0/15`, because the listener was bound at `198.18.0.2` and the whole
  range was bypassed to prevent self-capture;
- `fc00::/7`, as ULA private space.

**The two overlap exactly.** The consequence is fatal, because the entire point
of fakeip is that the app connects to the fake address and the proxy intercepts
it — and being in Flux's bypass set means **those packets are never captured**.
fakeip fails silently and completely: DNS returns the fake address, the app
connects to it, the packets go direct, and nothing works.

### 9.0.1 Resolution

**First, narrow the listener bypass from a whole prefix to the exact address.**
Bypassing an entire `/15` was excessive: preventing self-capture only requires
that a selected app cannot reach the listener itself. This holds independently of
fakeip.

**Second, move the listener out of the range fakeip conventionally uses.**
fakeip's use of `198.18.0.0/15` is the older, established convention in this
ecosystem and users have muscle memory for it; Flux's original `198.18.0.2` was
merely "some unroutable address" and far more arbitrary. **Flux is the one that
should move.** Now:

| | Was | Is |
|---|---|---|
| v4 listener | `198.18.0.2` | **`198.51.100.1`** (RFC 5737 TEST-NET-2) |
| v4 bypass | `198.18.0.0/15` | **`198.51.100.1/32`** |
| v6 listener | `2001:db8::2` | **`2001:db8:0:1::2`** |
| v6 bypass | `2001:db8::/32` | **`2001:db8:0:1::2/128`** |

The v6 fakeip range instead **MUST avoid ULA in the template**: bypassing
`fc00::/7` as private space is legitimate and should not yield to fakeip.
`2001:db8:f::/48` is the recommended value, and §27.2.3 makes it a checked
property of the shipped default.

**Third, and most important: `fluxd check` MUST cross-validate the fakeip ranges
against the bypass set and report an error when they intersect.** The first two
points only make the defaults correct. Users change these ranges, and the symptom
of the collision — "DNS works, the app connects, nothing loads" — is not
diagnosable by inspection. **The automatic check is the actual fix**; the new
defaults merely stop shipping the collision.

That cross-validation applies against `RESERVED` entries only (§6.1.1). A fakeip
range intersecting a `POLICY` entry is the user's own trade-off; intersecting a
mechanism invariant is a hard refusal (PHIL-6).

Related cross-checks that belong in the same place: fakeip against a `tun` range
if the user added one; whether `clash_api`'s listen address is loopback; and
whether a large list loaded through a `@file` reference accidentally contains the
fakeip range.

> **Status: fully landed (2026-08-25).** `FLUX_LISTEN_V4_STR` and
> `FLUX_LISTEN_V6_STR` in `bpf/include/flux_abi.h`, their mirrors in
> `crates/flux-core/src/abi.rs`, the fixed bypass list in
> `crates/flux-core/src/cidr.rs` and the fakeip range in `module/template.json`
> were all changed, and `FLUX_ABI_MAGIC` was raised to `0xF10C0903`. The
> cross-validation of the third point belongs to `fluxd check`.

## 9.1 The injected inbounds: two per generation, four kernel sockets

| tag | family | listen | listen_port | Notes |
|---|---|---|---|---|
| `flux-in-v4` | IPv4 | `198.51.100.1` | random `actual4` | `type: "tproxy"`, TCP and UDP |
| `flux-in-v6` | IPv6 | `2001:db8:0:1::2` | random `actual6` | `type: "tproxy"`, TCP and UDP |

**Flux injects these; the template MUST NOT declare them.** Generation deep-copies
the user's value, asserts that `inbounds` is absent or an empty array, and writes
the two objects above. It MUST NOT inject `route.rules` and MUST NOT modify the
user's DNS, outbounds or log configuration.

The reason injection wins over prefilling is worth stating, because prefilling
looks more transparent. A prefilled listener address and port would be a fact
living in two places — the template and `flux_control` — with no mechanism
keeping them equal, so it needs a validator to confirm the template still says
what the data plane believes. Injection makes the question unrepresentable
instead: there is one writer, and the template that could disagree does not exist
(PHIL-2, PHIL-4). Transparency is served by `run/sing-box.<gen>.json` being a
readable file the user can inspect at any time (§28.1).

Only these keys may appear in the injected JSON: `type`, `tag`, `listen`,
`listen_port`. `sniff*`, `domain_strategy`, `udp_disable_domain_unmapping`
(removed in 1.13.0), `bind_interface`, `routing_mark` and `reuse_addr` MUST NOT
appear — see §9.2 and §9.3 for why the last three would break delivery.

**Ports:** two distinct random values from `61000..=65535`, generated with
`getrandom()` and fixed for the generation. Android's `ip_local_port_range` is
typically `32768..60999`, so this range does not collide with ephemeral
allocation. **A port is not a credential**; it exists only to avoid collisions,
and §1.5 states what that does and does not defend against.

**Binding a non-local address** works because sing-box's tproxy inbound sets
`IP_TRANSPARENT` or `IPV6_TRANSPARENT` before binding, and
`inet_can_nonlocal_bind()` permits a transparent socket to bind a non-local
address when the process holds `CAP_NET_RAW`, which root does. The documentation
ranges `198.18.0.0/15` (RFC 2544) and `2001:db8::/32` (RFC 3849) were chosen
because they are not routed; the exact listener addresses within them enter the
fixed bypass as `RESERVED` (D16, §6.1.1).

## 9.2 Hard constraint: no `SO_REUSEPORT`

**Verified:** before 6.5, `bpf_sk_assign()` returns `-ESOCKTNOSUPPORT` for a socket whose `sk->sk_reuseport` is set.

- **`SO_REUSEPORT` has zero hits across the whole `SagerNet/sing-box@v1.13.19` tree**, re-checked with `rg` inside `clone/` (`../history/review-log.md` §0.5.1). The constraint holds.
- The exact kernel boundary was checked: v6.1's `bpf_sk_assign()` contains `if (unlikely(sk_fullsock(sk) && sk->sk_reuseport)) return -ESOCKTNOSUPPORT;` (`net/core/filter.c:7167-7186`), and v6.6 and v6.12 replace that line with `if (sk_unhashed(sk)) return -EOPNOTSUPP;`. **GKI 5.10, 5.15 and 6.1 all fall on the older side.**
- **Before 6.5 there is also no rejection of an unhashed socket**, so an assign
  landing in the instant a listener has just been unhashed **leaks a socket
  reference permanently**. The design closes this by ordering rather than by
  detection (§9.4): a candidate switch **publishes `active=0` first**, after
  which `flx_in` returns SHOT at step I0 and performs no lookup or assign, and
  **only then** terminates the old child. The residual window is the few hundred
  microseconds between an unplanned engine crash and pidfd waking fluxd, and its
  consequence is a very small number of unreclaimed socket objects. **Known and
  accepted**; no mechanism is added for it.
- `redir.TProxy()` sets `SO_REUSEADDR` unconditionally (`common/redir/tproxy_linux.go:16`), which has nothing to do with `bpf_sk_assign`. Not injecting `reuse_addr` therefore keeps the generated JSON minimal without changing socket behaviour.
- User JSON MUST NOT be allowed to influence these two internal inbounds.
- Phase 0 still takes an actually successful assign as the final proof (§16, Q2), and **the zero-hit finding MUST be re-checked whenever the engine version is raised** — it is a property of a specific release, not of sing-box.

## 9.3 Hard constraint: the listener carries no mark and no bind_interface

- `routing_mark` is inherited by the accepted child socket (`ireq->ir_mark = inet_request_mark(sk, skb)`), so the SYN-ACK is interpreted under Android's fwmark semantics as belonging to some netId — most likely `unreachable`, and the handshake fails.
- `bind_interface`, which is `SO_BINDTODEVICE`, propagates to the TCP child and to the UDP write-back socket, destroying the return path that delivers to the app through `lo`.

## 9.4 The engine candidate switch is the only commit point

1. Allocate a new `generation`, monotonic and never reused within the boot, and two random ports. Write `run/sing-box.<generation>.json` with `O_CREAT|O_EXCL|O_NOFOLLOW`, `fsync` it, mode `0600`, and run `sing-box check -c` against that exact immutable path. A write or check failure deletes only the candidate file; **the running engine is not touched at all**.
2. Keep the current control leaf and the current generation's file. Publish an `active=0` leaf for the *same* generation.
3. Terminate the old child normally: `SIGTERM`, a short deadline, then `SIGKILL`, with pidfd confirming exit. **At most one sing-box runs at any instant.**
4. While inactive, clear `fault_latch`. Start the candidate child and wait for the four sockets of the two inbounds to pass the PID and inode cross-check.
5. Once ready, create and freeze the new generation's `active=1` leaf and perform **one** `control_root` pointer swap. **That swap is the only commit point.** From it, TCP decisions carrying the old generation are dropped or reset and new flows enter the new generation. Then mark the candidate current in memory and delete the old generation's file best-effort — a failed delete is a control-plane error only and MUST NOT roll back a data plane that has already committed.
6. If the candidate fails to start or the swap fails, stop it and restart the old generation from its file — which was **never renamed and never overwritten** — then re-verify its four sockets. Only a successful recovery re-publishes the old `active=1`; a failed one stays at `active=0` and reports the error.

Flux does not use sing-box's `SIGHUP`, whose success cannot be confirmed synchronously, and does not run two complete engines in parallel, which would contend over ports, cache, logs and the API. During the brief inactive window new flows take Android's own path and packets on admitted TCP flows are dropped and left to retransmission. Configuration reload is an infrequent control operation, and this deterministic window fits the module's complexity budget better than a dual-child platform would.

## 9.5 Listener readiness without sleeping or parsing logs

Enumerate the four exact sockets — two families by two protocols — through `NETLINK_SOCK_DIAG` (`SOCK_DIAG_BY_FAMILY`, `inet_diag`), and cross-check each socket's inode against `/proc/<candidate-pid>/fd/*`. This establishes control-plane evidence that the four sockets are held by the candidate **at the moment of promotion**, and nothing more. Admission during operation remains per-packet through BPF's `listener_alive()`; there is **no periodic diag polling**.

A timerfd MAY re-check with a bounded backoff while the candidate starts — 10, 20, 40 ms rising to a 250 ms cap, with a total deadline of 5 s — cancelled the moment readiness or failure is decided. It is not steady-state polling and MUST NOT be extended into a health probe.

## 9.6 The boundary around the user's engine configuration

The JSONC reader treats comments as whitespace, retaining line and byte
positions for parser errors. It MUST reject an unterminated block comment and
MUST NOT join tokens across a comment: `1/* note */2` is invalid, never `12`.

At most 8 MiB, and a complete official configuration satisfying:

- `inbounds` absent or an empty array, since the two tproxy inbounds are injected by fluxd alone;
- no tag equal to either injected inbound's tag, `flux-in-v4` or `flux-in-v6`. Only those two are reserved: the mechanism needs its inbounds to be unambiguous and nothing wider. An earlier draft reserved the whole `flux-` prefix, which let a provider naming a node `flux-hk` invalidate the entire generated configuration — external data deciding whether the user's proxy runs (PHIL-1);
- Flux MUST NOT modify the user's `dns`, `outbounds`, `route`, `log` or `experimental`;
- the Android consequences of a user's own outbound `routing_mark` or `bind_interface` are the user's to own. Flux warns in `status` and does not build a large, brittle policy validator (PHIL-6).

The shipped default template carries the official direct outbound and a `final`,
no inbound, **and MUST carry the `sniff` and `hijack-dns` route rules of
§1.3.4** — without them a captured `:53` datagram is forwarded as ordinary UDP
and the domain-routing capability is thrown away for nothing. Combined with a
fresh install being disabled, the installation itself takes over no traffic. The
default is a bootstrap starting point, **not a second authoritative copy**: the
user owns it from first edit onward, and §28.1 defines that ownership.

`fluxd check` performs one additional **non-blocking** check: if the user's
`route.rules` contains no action able to handle `:53` — `hijack-dns` or an
equivalent the user wrote — it warns that selected apps' DNS will be forwarded
verbatim and domain rules will not apply. **Warn, never refuse.** A user may
genuinely want DNS to pass through untouched, and §23 keeps the line between a
diagnosable difference of intent and an undiagnosable failure.

## 9.7 Upstream resolution and build evidence

Flux does not pin sing-box or other dependency versions. A top-level package,
template-check or release operation resolves the latest stable official
sing-box release once. Its Android asset, host validation asset and upstream
source revision all come from that result. The build verifies the official
archive's published size and digest and extracts the binary unchanged:
**no strip, no patch, no re-sign.**

`build-info.toml` is generated for the artifact, recording the resolved engine
version, source revision, asset digests and actual build tools. It describes
what was built; it does not select a version for the next build. The source
tree contains no `engine.lock`. Cached downloads are addressed by the resolved
release; an old cached release is not a substitute for resolving the current
one.

Compatibility is a behaviour contract: the real engine checks the generated
configuration, ELF inspection establishes load alignment for the supported
page size, and the existing listener and data-plane tests establish the
TProxy/original-destination requirements. No version allowlist substitutes for
these properties. The source findings in §9.2 remain evidence for the stated
revision, not a claim about every future release.

Each release page offers the source archive for the same resolved upstream
revision beside the module ZIP, with its build scripts and dependency
manifests. Source identity must follow the packaged engine, even if upstream
publishes a newer release during the build. The archive is not packed into the
module ZIP.

---

# Part 10: The control plane

## 10.1 The state machine

There are exactly three top-level states:

| State | Meaning |
|---|---|
| `Disabled` | the `disable` file exists — the only switch, C9, §27.1. No engine is started and no data plane is created or activated. |
| `Inactive` | the `disable` file is absent, but Flux is starting or restarting, is blocked by a definite error, or is paused by the `[ssid]` dimension (§29.5). control `active == 0`. |
| `Active` | control `active == 1`, **and at least one interface has passed the liveness verification of §8.5.4**. An `active` flag with no reachable capture interface is not Active; it is Inactive with a reason. |

An invalid hot candidate **keeps the current `Active` generation** and attaches the candidate error to it. It MUST NOT create a fourth persistent state — a state that exists only to describe a failed attempt is a state every transition afterwards has to account for. A daemon restart re-evaluates from the authority files alone.

## 10.2 Interfaces and state ownership

The interface is the operation and its guarantees, not a second copy of Rust
struct fields. Exact signatures live in the source files named below; changing
a field there must not leave a contradictory pseudo-definition here (PHIL-4).

| Module | Input and ownership | Guarantee visible to its caller |
|---|---|---|
| `flux-core/config.rs`, `selector.rs`, `cidr.rs` | User configuration and package text become validated selections and prefix sets | Pure computation; root appId is excluded; the configured modes, shared UIDs and hard capacities retain the semantics of §1.4 and §11.2 |
| `flux-core/subscription.rs`, `engine_config.rs` | Raw provider bytes and a user template become refined nodes and a generated candidate | No I/O; generation changes only the permitted fields (§28.2); inbound injection owns the two listener tuples (§9.1) |
| `fluxd/bpf/` | Owns loaded map/program FDs and the verified object identity | Kernel preflight precedes object creation; callers cannot bypass the LPM exclusion; control publication is one frozen-leaf pointer swap (§6.4, §12) |
| `fluxd/dataplane/` | Owns observed topology, admitted interfaces, kernel identities and desired policy | Typed operations; capture drift remains local, core drift publishes inactive first, and deletion requires current identity evidence (§8, §26) |
| `fluxd/engine.rs` | Owns an immutable candidate file and each child/pidfd | Check the exact file that will run; readiness verifies all four sockets; child exit is confirmed before a replacement starts (§9.4) |
| `fluxd/subscription.rs` | One immutable fetch request in a blocking worker; one result returned by channel/eventfd | The worker cannot mutate reactor state, cache files or a generation; the reactor validates the current authority when consuming completion (§28.6) |
| `fluxd/reactor.rs` | Owns top-level state, pending events and engine transactions | One coordinator and no re-entry; policy and engine are separate transaction domains; later events remain serviceable and are consumed after the current transaction (§10.5, §26) |
| `fluxd/time.rs` | A timestamp supplied by the caller | Pure formatting shared by logs and diagnostics; neither consumer depends on the reactor to format dates |

No module outside the reactor may write its mutable state. Immutable request
and completion values cross the subscription seam; kernel and child resources
stay owned by their corresponding modules. A helper shared by diagnostics and
the reactor belongs below both, not behind a reverse dependency into the event
loop.

## 10.3 Single instance and the control protocol

- The daemon holds `flock(LOCK_EX|LOCK_NB)` on `/data/adb/flux-rs/run/daemon.lock`. A second instance exits immediately **with code 3**, which its supervisor recognises as "do not restart" (§13.2.2): it MUST NOT unlink the control socket, MUST NOT start a second engine, and MUST NOT touch the first instance's objects. **Only the lock owner may inspect or delete a stale control socket** — the alternative is a losing instance destroying a working one's socket on the way out.
- The control socket is `/data/adb/flux-rs/run/control.sock`: `AF_UNIX` with `SOCK_SEQPACKET`, mode `0600`, and every request additionally checks `SO_PEERCRED.uid == 0`.
- Encoding is **one single-line JSON document per SEQPACKET datagram**. SEQPACKET preserves message boundaries by construction, so no length prefix is needed. A datagram is at most 64 KiB. The types live in `flux-core/src/control_wire.rs`, so serialisation is unit-testable on any host.
- **No request_id deduplication cache is needed.** The old v9 protocol maintained a 128-entry `(peer, request_id)` table plus a 30-second duplicate wait for mutating commands. All six commands here are idempotent by construction — `enable` writes the file and reconverges, `reload` recomputes the desired state, `stop` converges to stopped — so replaying one produces the same result as executing it once, and the entire mechanism was deleted. **A new command MUST preserve this property**; if it cannot be made idempotent, deduplication has to come back with it.

```jsonc
// Request — the whole grammar
{ "op": "status" | "check" | "enable" | "disable" | "reload" | "stop" }
```

**The response schema is specified once, in §24.1**, and is not repeated here.
An earlier draft carried an abbreviated copy in this section; it drifted, naming
a `counts` object where the implementation has `policy`, and omitting fields
added later. A schema with two homes acquires two meanings (PHIL-4), and the one
in a section about the *transport* is the copy nobody updates.

What belongs here is the transport property that §24.1 cannot state: the
response is a single JSON document in one SEQPACKET datagram, so a reader never
has to reassemble it and a truncated response is a delivery failure rather than a
parse ambiguity.

## 10.4 Reactor event sources

One thread, one epoll. The sources:

| Source | What it delivers |
|---|---|
| rtnetlink (`RTMGRP_LINK|IPV4_IFADDR|IPV6_IFADDR|IPV4_ROUTE|IPV6_ROUTE|IPV4_RULE|IPV6_RULE` plus TC) | interface admission; **capture-side drift** when netd deletes a qdisc or filter (§8.5.1); **core drift** of the veth, rule, route or ingress filter; self-address bypass updates. **The two kinds of drift are handled differently** — see §26 invariant 4 |
| inotify | the `disable` switch in the **module** directory (C9, §27.1.1); atomic replacement of `config/` and the files in it; `/data/system/packages.list` |
| pidfd | sing-box exiting |
| BPF ringbuf | deduplicated listener and assign faults |
| signalfd | `SIGTERM` and `SIGINT` to stop, `SIGHUP` to reload |
| control socket | CLI requests |
| timerfd | configuration debounce, readiness backoff, the 1/2/4/8/30 s crash backoff, and the subscription refresh of §29.3 |
| child stdout pipe | output of `sing-box check`, **non-blocking**, with a deadline |
| eventfd | completion of a subscription fetch on its worker thread (§28.3); the reactor never blocks on the network |
| generic netlink (`nl80211`, multicast group `mlme`) | Wi-Fi connect, roam and disconnect for the SSID dimension of §29. Each event is a trigger to re-read `NL80211_CMD_GET_INTERFACE` through the debounce, never a value acted on directly (§29.2). Opened only while `[ssid]` has entries |

**No per-second polling, no busy loop, no BPF timer, no periodic counter sampling, no heartbeat.** §29.3 records the one deliberate exception and why a one-shot timer is not polling. Backoff resets once a child has been stable for 60 s, and recovery continues at a low rate for as long as the switch is on: there is **no "failed N times, locked out permanently"** state, because a user who fixes the cause deserves the next attempt to succeed.

**Every external command — `sing-box check` is the only one — MUST run as a child process read through an epoll pipe with a deadline. Blocking on `wait()` inside the reactor is forbidden**: one hung child would otherwise freeze every other event source, including the switch.

### 10.4.1 Three hard rules for rtnetlink

Android produces event storms on a network change, and incrementally processing a truncated batch is the standard way to arrive at inconsistent state. These three rules come from the practice in `clone/asteriskd/asteriskd_network.c:147-164`:

1. **A 1500 ms trailing debounce.** Every **new, post-deduplication distinct** event **re-arms** the deadline — trailing, not leading. The batch has a capacity ceiling, and exceeding it sets `truncated`. The 1500 ms matches asteriskd (`asteriskd.h:35`), which tuned it against real Wi-Fi to cellular handovers.
2. **`ENOBUFS` or `NLMSG_OVERRUN` means abandon the increment and re-dump everything.** When the netlink socket overflows or reports an overrun, the events already received **MUST NOT** be trusted: set `integrity_loss`, discard the batch, take a fresh full snapshot with `RTM_GETLINK`, `GETADDR`, `GETROUTE`, `GETRULE` and `GETTFILTER`, and converge from that. This matches the snapshot-replacement semantics of `flux-core`'s inventory: **recompute rather than splice.**
3. **Re-resolve `if_nametoindex()` immediately before every TC operation.** Interfaces being renamed and ifindexes being reassigned is routine on Android. The ifindex seen in a dump and the ifindex a few milliseconds later at `RTM_NEWTFILTER` may no longer be the same device (`asteriskd_runtime.c:3806`, `:3818`). **Both** the name and the ifindex MUST be re-checked for agreement in the instant before the operation; a mismatch abandons this round and waits for the next event.

The socket is `NETLINK_ROUTE | SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC`, and it **subscribes before taking the initial snapshot**, then drains to `EAGAIN`. Reversing that order loses every change occurring between the snapshot and the first delivered event.

## 10.5 Two independent transaction domains

`flux.toml` (policy) and `config/template.json` with its generated output (engine) are two independent authority domains, and Flux **does not attempt a distributed transaction across them**. Changing one triggers only that flow. `reload` processes both in turn, promoting each independently and reporting both in `status`. One succeeding while the other keeps its old state is allowed; **half-writing a map or half-starting a generation is not.**

**A policy update (D5) touches neither `active` nor the generation:**

1. Parse, canonicalise, resolve UIDs and check the hard ceilings entirely in memory. Any failure keeps the current policy and reports a candidate error.
2. Compute the desired sets separately: `selected_uids`, the `RESERVED` and `POLICY` LPM prefixes, and the dynamic self-address set (§6.1.1).
3. **Add first:** write the new `SELECTED` entries and insert the new LPM prefixes.
4. **Subtract second:** change UIDs that were `SELECTED` and no longer are to `DRAINING` — **never delete them** (§7.6) — and remove LPM prefixes no longer needed.
5. Leave the diagnostic counts in the control leaf alone. They refresh when the next legitimate leaf is published (§6.4); a frozen leaf is not rewritten, and `status` computes live counts from the data plane instead.
6. If any map operation fails, record the error and **re-queue one complete convergence**. The reactor is level-triggered, so recomputing the desired state is both simpler and safer than unwinding a snapshot.

Why the window is safe: adding before subtracting means that during it the policy either keeps the old behaviour more permissively or applies the new behaviour early. Both affect **only flows that have no decision yet**, because an existing `DIRECT` or `CAPTURED` decision is immutable (§6.2).

## 10.6 CLI

| Command | Behaviour |
|---|---|
| `fluxd daemon` | invoked by `service.sh`; supervises the reactor, restarting it after a crash (§13.2.2) |
| `fluxd status` | prints the response of §24.1, human-readable or `--json` |
| `fluxd check` | read-only validation of both configurations, package resolution and the engine `check`; changes no state |
| `fluxd enable` | deletes the `disable` file and requests activation. **A front end to the switch file** (C9), never a second source of truth |
| `fluxd disable` | creates the `disable` file, publishes `active=0`, stops the engine; the daemon keeps waiting for commands |
| `fluxd reload` | triggers the policy and engine candidate flows |
| `fluxd stop` | for service and uninstall paths: publish `active=0`, stop the child, exit cleanly with 0 |

**There is no `toggle`.** A toggle hides the current state from the caller, so two clients racing on it can each invert the other's intent; `enable` and `disable` are idempotent statements of a desired state, which is what §10.3 relies on to need no deduplication. There is also no `action.sh` (§27.1.3).

---

# Part 11: Configuration and persistent state

## 11.1 The authority for each fact

| Path | What it is authoritative for | On failure |
|---|---|---|
| `/data/adb/modules/flux_rs/disable` | The only persistent switch: **present means disabled, absent means enabled** (C9, §27.1.1). It lives in the **module** directory, owned by the manager, and is watched by the existing inotify source so a toggle takes effect during the current boot | Existence is the whole signal; the contents are never read |
| `config/flux.toml` | app selection, CIDR policy, interface and SSID dimensions, subscription parameters | invalid at cold start means Direct; invalid on reload keeps the current policy |
| `config/template.json` | the user-owned engine template (§28.1) | invalid at cold start means Direct; invalid on reload keeps the current generation |
| `run/sing-box.<generation>.json` | the immutable generated artifact for one child; at most current plus candidate exist during a transaction | Not authoritative for anything. A daemon restart deletes them precisely and rebuilds from the template |
| `run/daemon.lock`, `run/control.sock` | single-instance enforcement and IPC | — |

**No last-known-good persistent copy is kept**, `enabled` is not duplicated into the TOML, and runtime state is never inferred from `module.prop` — that file is an output of the daemon, not an input to it (§27.1.3). **Flux never writes back to a user-owned file.** A fresh install is disabled by default, with the installer creating the `disable` file (§13.2).

After a cold start confirms it has no surviving child of its own, the daemon enumerates and deletes only the regular, root-owned files in `run/` matching exactly the `sing-box.<u64>.json` form. Anything else in that directory is left alone, because a pattern loose enough to catch a stranger's file is loose enough to delete one.

Permissions: the state root and its subdirectories are `root:root 0700`; user configuration and generated engine configs are `0600`; the control socket is `0600`.

## 11.2 The `flux.toml` schema

Three dimensions, **one idiom**: a mode and a list.

```toml
[apps]
# whitelist = proxy only what is listed; blacklist = proxy everything except
mode = "whitelist"
list = ["0:com.twitter.android", "@apps.txt"]

[cidr]
# blacklist = listed destinations go direct (the ordinary use)
# whitelist = capture only the listed destinations
mode = "blacklist"
list = ["100.64.0.0/10", "@chnroute.txt"]

[interfaces]
# blacklist with an empty list = take over every supported physical interface
mode = "blacklist"
list = []
```

§29.1 adds `[ssid]` as a fourth dimension in the same shape.

Node inputs use `[nodes] list` (§28.2.2), without a mode: the list contributes
nodes rather than matching traffic. `[subscription]` controls remote acquisition;
`[subscription.refine]` controls provider-name cleanup (§28.2.1).

### 11.2.1 Why one idiom rather than several switches

The shape is taken from `box_for_magisk`'s `package.list.cfg`, which is **one
list plus one mode line** rather than two lists, and which reuses the same idiom
for package names, Wi-Fi SSIDs and interface toggles. **Uniformity is itself a
user-facing property:** learn it once, apply it everywhere.

**`mode = "blacklist"` with an empty list is the automatic mode**, and it needs
no third enum value. Every third-party app is proxied, and a newly installed one
joins automatically because the inotify watch on `packages.list` already exists
(§29.6). An explicit `auto` would be a second way to express a state the two
existing values already reach, and states reachable two ways drift.

**`bypass` was renamed `[cidr]`** because once a mode exists, "bypass" names only
one of the two directions. The new name also blocks a known misreading head-on:
**this dimension sees destination IPs and never domain names.** Domain routing is
sing-box's job (§1.4).

The whitelist direction costs the data plane one branch — whether to invert after
an LPM hit — which is cheap for three consistent shapes. But **a single mistyped
entry in whitelist mode sends everything direct, silently**, so `status` MUST
print the mode in force and not merely the entry count.

### 11.2.2 `@file` references

Any list entry beginning with `@` is a file reference: one entry per line, `#`
starting a comment.

Neither a CIDR nor an Android package name can begin with `@`, so no guessing is
involved. **Determining whether an entry is a path by testing whether it parses
as a CIDR is forbidden** — that turns one mistyped CIDR into a silent filename.

Three constraints:

- **No recursion.** A referenced file MUST NOT itself contain `@`. This bounds
  the failure modes and removes cycles and unbounded expansion outright.
- **Paths resolve inside `config/`** and nowhere else. The inotify watch on the
  configuration directory then covers list files for free, with no dynamic watch
  set to maintain.
- **A missing file is a `check` error.** At run time the new policy is refused,
  the current one is kept, and the existing level-triggered convergence retries.

This replaces the `[bypass] files` key of earlier drafts, which split one concept
into two knobs and gave the CIDR dimension a capability the others lacked.

### 11.2.3 Limits

The file is at most 256 KiB. At most 1024 apps may be simultaneously selected;
total UID entries after resolution are at most 4096; each of the IPv4 and IPv6
LPM tries holds at most 65536 (**local addresses do not consume LPM capacity**,
D20). Package strings and CIDRs MUST be canonical and free of duplicates.

Exceeding a limit is a plain configuration error. Flux **MUST NOT truncate and
MUST NOT partially apply**: a silently truncated selection is a policy the user
never wrote and cannot see.

**The fixed safety bypass**, injected regardless of configuration and tagged `RESERVED` (§6.1.1). The authoritative list is `crates/flux-core/src/cidr.rs`:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `198.51.100.1/32` (the listener itself), `224.0.0.0/4`, `255.255.255.255/32`
- IPv6: `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`, `ff00::/8`, `2001:db8:0:1::2/128` (the listener itself)

Two notes:

- **The listener bypasses its exact address, never a whole prefix** (D21). Reserving the entire `/15` was more than self-capture prevention required — that needs only "a selected app cannot reach the listener itself" — and the excess overlapped exactly with sing-box's conventional fakeip range, silently disabling fakeip altogether (§9.0).
- **RFC 1918 and ULA are bypassed unconditionally.** They are private addresses, proxying them is meaningless, and an `ip_is_private` rule on the sing-box side would judge them direct anyway — releasing them in the kernel saves a userspace round trip already known to be useless (§1.6.2).

**Dynamic local-address bypass:** the reactor injects every live local unicast address into the dedicated `self_addr_v4` and `self_addr_v6` HASH maps, never into the LPM (D20). A local address is always a full-length prefix, so a trie would be waste; a HASH deletes cleanly, which matters for IPv6 privacy rotation; and it avoids the 6.6.0–6.6.46 LPM trie crash entirely (§1.6.3a). Capacity is 256 per family, filtered by `IFA_FLAGS` with least-recently-seen eviction for IPv6 privacy addresses (§1.6.4).

## 11.3 Resolving packages without binder

Each line of `/data/system/packages.list` looks like:

```text
com.example.browser 10231 0 /data/user/0/com.example.browser default:targetSdkVersion=34 none 0
```

The second column is the uid under user 0, and `app_id = uid % 100000`. The rules:

1. Read the whole file, at most 8 MiB, and parse both directions: `package -> app_id` and `app_id -> [package]`.
2. For each `userId:package` in the configuration, look up the `app_id`, refuse `app_id` 0 (§1.4), and compute `uid = userId * 100000 + app_id`. An `app_id` outside `[10000, 19999]` resolves, and is reported as a platform uid rather than an app.
3. A package that does not exist fails the candidate configuration with an explicit error. **Silently ignoring it is forbidden**: the user asked for an app to be proxied and would otherwise believe it is.
4. Other packages sharing the same `app_id` are listed in the shared-UID note in `status` (§1.4).
5. inotify watches the file **and its parent**, because Android rewrites it by atomic replacement and a watch on the inode alone would follow the file that was replaced. Event, debounce, reconverge.
6. If the file is unreadable or malformed, keep the current policy and report the error. **Do not poll for it to come back**; the inotify watch already covers its return.

The VPN provider warning is best-effort: `check` MAY run one `cmd package` query, and a failure MUST NOT affect any gate. D8 rejected `cmd package` as a *dependency* for the same reason §29.2 rejects binder — it may not be up when needed — and using it for an advisory warning that degrades to silence does not reintroduce that dependency.

---

# Part 12: Building the BPF object and the minimal loader

## 12.1 Compilation

`crates/fluxd/build.rs`：

```text
clang -target bpf -O2 -g -Wall -Wextra -Werror \
      -mcpu=v3 -D__TARGET_ARCH_arm64 \
      -Ibpf/include -Ibpf/vendor/libbpf/include \
      -c bpf/flux.bpf.c -o $OUT_DIR/flux.bpf.o
```

**What "no libbpf" precisely means.** The libbpf *library* is not linked, so libelf and zlib are not needed and `fluxd` is a single binary of Rust plus libc. The BPF **side** still vendors three **header-only** libbpf files — `bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_endian.h`, BSD-2 — for the `SEC`, `__uint` and `__type` macros and the helper prototypes. They are used only while compiling the BPF object and are not a runtime dependency. Hand-writing those macros is possible, roughly 60 lines, and buys nothing.

- `-g` is required: it produces the `.BTF` section, which is used **only** to cross-check the hand-written BTF blob (§12.3), never loaded.
- No `vmlinux.h`, no access to private kernel structs, no CO-RE relocation. Only the `linux/bpf.h` UAPI and fixed helper prototypes.
- The object is embedded with `include_bytes!(concat!(env!("OUT_DIR"), "/flux.bpf.o"))`. The shipped module contains **one** `fluxd` binary and no loose `.o` file.
- CI compiles the real embedded object and tests its ABI, program sections and map references through the loader. Exact instruction counts are compiler output, not ABI. Package reproducibility is checked under the same toolchain (§13.4); the current workflow installs the runner's distro clang and does not pin a separate clang version or compare a standalone object hash.

## 12.2 Map creation

**Maps are created explicitly from Rust and never inferred from the ELF.** `fluxd/src/bpf/maps.rs` holds a constant table describing all 12 maps — the list and its order are `flux-core::abi::MAP_NAMES` — with `map_type`, `key_size`, `value_size`, `max_entries`, `map_flags` and `name`, and issues one `BPF_MAP_CREATE` each. The map definitions in the C file are therefore symbol placeholders, and the single source of truth for the parameters is Rust, with `flux_abi.h` constraining the value layouts.

The `control_leaf` inner map is created first, and its fd becomes the `inner_map_fd` used to create `control_root`.

## 12.3 The BTF that SK_STORAGE requires

**Verified:** `bpf_sk_storage_map_alloc_check()` requires both `btf_key_type_id` and `btf_value_type_id` to be non-zero.

The approach — **SHOULD**, because it reduces the compatibility surface to nothing — is to **construct a minimal BTF blob by hand** in Rust and `BPF_BTF_LOAD` it:

```text
BTF header (magic 0xeb9f, version 1, hdr_len 24, type_off/len, str_off/len)
types:
  [1] BTF_KIND_INT  "int"                size=4  bits=32 signed
  [2] BTF_KIND_INT  "unsigned int"       size=4  bits=32
  [3] BTF_KIND_INT  "unsigned long long" size=8 bits=64
  [4] BTF_KIND_ARRAY (elem=[2], index=[1], nelems=3)      /* reserved[3] */
  [5] BTF_KIND_STRUCT "flux_decision" size=16
        members: magic:[2]@0, mode:[u8]@32, reserved:[4]@40, generation:[3]@64
```

(`u8` needs a `BTF_KIND_INT` of its own; the real implementation generates this from the final layout in `bpf/include/flux_abi.h`.)

`tcp_decision` is then created with `btf_fd` set to that blob, `btf_key_type_id = 1` and `btf_value_type_id = 5`.

Why not simply load clang's `.BTF`: it would work today, but 5.15's BTF validation is strict about unknown kinds, and a clang upgrade can introduce new ones such as `DECL_TAG`, `FLOAT` or `ENUM64` — sanitizing exactly this is why libbpf carries that code. Flux needs two type IDs, and hand-building a hundred-odd bytes is smaller and more stable than adopting a sanitizer. `cargo xtask btf-check` compares the hand-written blob against clang's `.BTF` in CI, so the two cannot drift apart silently.

## 12.4 Program loading and relocation

1. Parse the embedded ELF — the `object` crate, or roughly 200 lines by hand — taking the instruction bytes of `.text` and each `SEC("tc")` program section, the `.symtab`, and the matching `.rel<section>`.
2. For each relocation landing on a `BPF_LD | BPF_DW | BPF_IMM` wide instruction, resolve the symbol name against the map table of §12.2 to obtain an fd, then set `insn.src_reg = BPF_PSEUDO_MAP_FD` and `insn.imm = map_fd`.
3. `BPF_PROG_LOAD` with `prog_type = BPF_PROG_TYPE_SCHED_CLS`, `license = "GPL"`, `prog_name` set to the program's name, `log_level = 1` and a `log_buf` of at least 256 KiB. **On failure the first lines of the verifier log MUST reach `status` and the log** — on an unfamiliar device that output is the only thing that makes the failure diagnosable at all.
4. Do not load `func_info`, `line_info` or `.BTF.ext`.
5. After a successful load, record the program's **id and 8-byte tag** through `BPF_OBJ_GET_INFO_BY_FD`, for the ownership predicate of §8.5 and for `status`.

## 12.7 Loader hardening

Every item below comes from a failure `clone/bpf2socks` hit on a real Android device (`bpf_util.c`, `bpf_object.c`). These are not best practices; they are **required**, because each corresponds to a class of outright failure on some device.

| # | Measure | Why | Source |
|---:|---|---|---|
| 1 | Hardcode `__NR_bpf` per architecture as a fallback — aarch64 is **280** | Android NDK UAPI headers sometimes do not define `__NR_bpf`, breaking the build outright | `bpf_util.c:26-36` |
| 2 | `#define` fallbacks for `BPF_F_NO_PREALLOC`, `BPF_OBJ_NAME_LEN` and `BPF_F_MARK_MANGLED_0` | Same cause: older NDK headers lack the constants | `bpf_util.c:16-24`, `tc_checksum_flags.h:11-13` |
| 3 | **Verifier log retry:** when `BPF_PROG_LOAD` returns `EAGAIN` or `ENOSPC` because of the log buffer, reload once with `log_level = 0`; if it still fails, **report the original errno**, not the second one | A large program's verifier log exceeds the buffer, and the real load error is then masked by `ENOSPC`. Skipping this step produces a diagnosis that points at the wrong thing | `bpf_util.c:177-189` |
| 4 | A sanity gate before ELF parsing: `ELFCLASS64`, `ELFDATA2LSB`, `e_machine == EM_BPF` | Stops any other file being parsed as a BPF object | `bpf_object.c:250-257` |
| 5 | Handle only `R_BPF_64_64` relocations, patching from a **map symbol name to fd table** with bounds checks on each | This is the concrete form of §12.4. bpf2socks loads successfully on Android this way with no libbpf | `bpf_object.c:23-172`, binding table `:78-96` |
| 6 | **Re-verify the id** after `BPF_PROG_GET_FD_BY_ID`: the id from `BPF_OBJ_GET_INFO_BY_FD` must equal the one requested | Program ids are reused. Without the re-check you may be operating on a different program entirely | `bpf_util.c:352-370` |
| 7 | Treat a truncated enumeration as a failure, never as a shorter list: `ENOSPC` and `NLMSG_OVERRUN` on a TC dump abandon the round (§8.5), and any bounded query **re-checks `count > capacity`** after the call returns. bpf2socks needed this for `BPF_PROG_QUERY`; Flux attaches to no cgroup and makes that call nowhere, so its enumerations are the TC dumps | The kernel returns the true entry count when the buffer is too small; not re-checking truncates silently | `bpf_util.c:306-315` |
| 8 | Identify our own objects by the **program name prefix** `flx_`, but **as a filter only, never as proof of ownership** — ownership still requires the id and tag of §8.5 | A prefix can be forged. Its job is to narrow the candidate set | `bpf_util.c:384-386` |
| 9 | If pinning is ever used — it is not — `mkdir -p` the parent at mode `0700` and `unlink` any old pin before `BPF_OBJ_PIN` | — | `bpf_util.c:89-122` |
| 10 | **Admit nothing by version.** Every capability decision is "attempt the real operation, report the errno"; the sole exclusion is the crash defect in §1.6.3a, for which a real probe is unsafe | BPF feature switches in vendor Android kernels are highly scattered, and a version string does not prove capability. Same reasoning as §3.7 | `bpf2socks` has no version gate anywhere; §1.6.3a records Flux's exception |

**Item 11 is ours rather than inherited:** on a load failure the **first lines of the verifier log MUST reach `status` and the log** (§12.4 step 3). It is the only diagnosable artefact a device failure produces, and swallowing it discards the scene.

## 12.8 Why nothing shells out to `tc` or `ip`

`clone/asteriskd` splits the work: verify through netlink, mutate through the `tc` binary (`asteriskd_runtime.c:3587`, `3605` against `:3824`, `:3834`). Flux uses **netlink for both**, and the reason is a concrete chain of consequences rather than a preference:

On Android, `tc` and `ip` run in the `netutils_wrapper` and `netd` SELinux domains, and stock sepolicy **does not let those domains touch another party's BPF objects**. So asteriskd has to inject policy first:

```text
allow netd * bpf { prog_run map_read map_write }
allow netutils_wrapper * bpf { prog_run map_read map_write }
```

— then search six candidate paths for `magiskpolicy`, `supolicy` or `ksud` (`asteriskd_capability.c:9-12`, `:97-154`), and degrade to a warning when that fails (`:181-206`). **This is exactly the "broad SELinux patch" that §1.3 lists as a non-goal.**

Issuing netlink and `bpf(2)` from `fluxd`'s own process sidesteps the `netutils_wrapper` domain entirely: the only domain needing `bpf` permission is **our own**, and the root domains of Magisk and KernelSU already have it. The price is encoding the `TCA_BPF_*` attributes of `RTM_NEWTFILTER` ourselves (§8.9), roughly two hundred lines — far cheaper than injecting sepolicy, and **it leaves the device's security posture unchanged**, which the alternative does not.

**Phase 0 MUST verify this separately on Magisk and on KernelSU.** Their policy paths differ — asteriskd carries two discovery implementations for exactly this reason — and "root implies the ability to load BPF" is an assumption, not a fact.

## 12.5 TC attach

Through rtnetlink, never the `tc` binary:

- **`clsact`, on `flxrs1` only:** `RTM_NEWQDISC` with `NLM_F_EXCL|NLM_F_CREATE`, `tcm_parent = TC_H_CLSACT`, `tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0)`, `TCA_KIND = "clsact"`. A physical interface's `clsact` is never created (§8.5); on `flxrs1`, `EEXIST` means residue from a previous run and is handled by the cold-start rebuild of §8.7 step 2.
- **Filter:** `RTM_NEWTFILTER` with `NLM_F_EXCL|NLM_F_CREATE`, `tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS|TC_H_MIN_INGRESS)`, `tcm_info = TC_H_MAKE(prio << 16, protocol)` where the preference is selected per interface (§8.5.3), `tcm_handle` of `0x1`, `0x2` or `0x3`, `TCA_KIND = "bpf"`, and `TCA_BPF_FD`, `TCA_BPF_NAME` and `TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT` inside the options.
- **Ownership check:** dump with `RTM_GETTFILTER` and compare every item of the §8.5 predicate. **Dump order establishes the ordering constraint, not reachability** — reachability comes from `flx_verify` (§8.5.4), and treating dump position as proof was the claim R091-05 overturned.
- **Deletion:** `RTM_DELTFILTER`, carrying the exact `prio`, `protocol`, `handle` and `kind` (§8.9.5).

## 12.6 Consuming the ringbuf

The `fault_events` map fd registers directly with `epoll`, because a ringbuf map
fd supports `EPOLLIN`. Consumption is the `mmap`ed consumer and producer pages
plus record-header parsing, roughly 80 lines, with no libbpf. Events are a fixed
32 bytes, so the parsing is trivial and the fault path adds no dependency to a
binary whose whole point is not having one.

---

# Part 13: Module packaging and the build

## 13.1 One minimal ZIP

```text
module.prop
skip_mount                  # empty file; no system overlay
customize.sh
service.sh
uninstall.sh
webroot/index.html          # the redirect shell of §28.8, not a WebUI
bin/fluxd
bin/sing-box
etc/default-flux.toml
etc/default-template.json
build-info.toml             # generated evidence of this build's inputs
LICENSE
THIRD_PARTY_NOTICES.md
licenses/{sing-box-LICENSE, DEPENDENCIES.md}
```

**The list is an allowlist, and packaging is built from it rather than by
excluding paths from the working tree.** An exclusion list fails open: a file
added to the tree ships unless someone remembers to exclude it. `xtask` holds
this list as a constant and stages exactly these entries; §13.4 makes two
consecutive runs byte-identical so the property is checkable rather than
asserted.

**There is no `action.sh`** (§27.1.3). The switch is the manager's own module
toggle, so a second button would be a second way to express one state — and it
would additionally impose a Magisk v28+ floor for no gain.

`module.prop` is generated by xtask: `id=flux_rs`, `name=Flux-rs`,
`author=Flux-rs contributors`, with the version and `versionCode` derived from
the single version source (§13.4). Its `description` is one sentence that **MUST
NOT overstate the failure semantics** — §2.2 is the contract it has to be
consistent with — and `fluxd` rewrites that line at runtime to carry live status
(§27.1.3). No `updateJson` is shipped.

**Forbidden:** `post-fs-data.sh`, a recovery `META-INF`, `service.d`, a WebUI,
an APK, SEPolicy, multi-ABI directories, compiled `.o` files, and a per-file
installation hash manifest.

Since libbpf, libelf and zlib were removed (D10), `licenses/` needs only the
sing-box licence and the Rust dependency licences.

## 13.2 Scripts stay thin

Every script locates itself with `MODDIR=${0%/*}` and MUST NOT hardcode a
manager's temporary directory.

### 13.2.0 The three managers really do differ

| Item | Magisk | KernelSU | APatch |
|---|---|---|---|
| `service.sh` | ✓ | ✓ | ✓ |
| `post-fs-data.sh` | ✓, blocking, 40 s ceiling | **skipped entirely in late-load mode** | ✓ |
| `boot-completed.sh` | **absent** | ✓ | ✓ |

**All startup logic lives in `service.sh` alone.** Flux ships no
`post-fs-data.sh`, which turns out to be exactly right rather than merely
minimal: KernelSU's late-load mode skips it silently, so a module depending on
it fails invisibly on those devices. Magisk has no `boot-completed.sh`, and §11.3
removed the dependency on `sys.boot_completed`, so there is nothing to wait for.

**Manager detection MUST NOT use `MAGISK_VER_CODE`.** KernelSU reports `25200` and `v25.2`, APatch reports `27000` and `v27.0`, and KernelSU's own documentation states plainly that these two variables must not be used to decide whether you are running under KernelSU. Use the positive markers:

```sh
if   [ "$KSU"    = "true" ]; then MANAGER=kernelsu
elif [ "$APATCH" = "true" ]; then MANAGER=apatch
else                              MANAGER=magisk; fi
```

KernelSU additionally exports `KSU_RUNTIME_MODE` as `built-in`, `lkm` or `late-load`. **This value belongs in `status`**: LKM and late-load run on the **vendor's own kernel**, where missing BPF features are substantially more likely, so it is the first thing worth knowing when something fails.

**The BusyBox path differs** — `/data/adb/magisk/busybox` against `/data/adb/ksu/bin/busybox` — and **MUST NOT be hardcoded**. All three managers use BusyBox `ash` in Standalone Mode, so relying on `PATH` to select tools is equally unreliable. `module.prop` MUST use LF line endings, and `id` MUST match `^[a-zA-Z][a-zA-Z0-9._-]+$`.

### 13.2.1 The status display does not depend on a button

`module.prop`'s `description=` is the only graphical status surface this product
has under the no-WebUI constraint, and it MUST be used fully.

An earlier design had `action.sh` write that line when the user pressed the
manager's Action button, exploiting the fact that Magisk re-reads `module.prop`
after the script exits. **That is the wrong writer.** A status line refreshed
only when a button is pressed shows a stale value at every other moment, which
is worse than no status at all — it looks current.

`fluxd` writes it instead, after each pass of the event loop, with three
properties the button-driven version could not have: it compares before writing
and skips an unchanged render; it replaces the file atomically through a
temporary file in the same directory plus `rename`, so the manager never reads a
half-written file; and the render is idempotent, so repeated writes cannot make
`description=` grow without bound. A write failure loses only the status display
and MUST NOT affect the daemon — the file belongs to the manager.

The reference implementation reached the same conclusion: `Flux-original` has its
daemon call `sync_prop` on every state transition (`scripts/log:104-152`), with
the same deduplication, idempotent stripping and atomic replacement.

The formats are specified in §27.1.3, and the split lives in
`flux-core::version` so it can be unit-tested on any host.

```sh
# service.sh (late_start; all logic lives in fluxd)
MODDIR=${0%/*}
exec "$MODDIR/bin/fluxd" daemon
```

The script starts one process and is gone. It does not loop, does not sleep and
does not read an exit code: every one of those depends on the state of the
running system, which is PHIL-7's test for what belongs in the binary.

### 13.2.2 The daemon supervises itself

`fluxd daemon` is two processes. The one `service.sh` starts is the
**supervisor**; it re-executes its own binary — `/proc/self/exe`, so a module
replaced on disk cannot change which image restarts — as the **reactor**, with
`FLUX_SUPERVISOR=<pid>` in the environment as the only marker. The reactor is
the daemon this document describes everywhere else: it takes `run/daemon.lock`,
opens the control socket, owns every kernel object and runs the state machine of
§26. The supervisor owns nothing and knows two things — exit codes and signals.

| Reactor outcome | Supervisor action |
|---|---|
| exit `0` — a requested stop (`fluxd stop`, `SIGTERM`, `SIGINT`) | exit `0`. The boot service ends, as it did before |
| exit `3` — another instance already holds `run/daemon.lock` (§10.3) | exit `3`. Restarting would contend with the instance that is working |
| any other exit code, or death by signal | wait out the backoff, then re-execute. Same schedule as the engine's: 1/2/4/8/30 s, reset once the reactor has lived 60 s (§25) |

Signals to the supervisor are forwarded: `SIGTERM` and `SIGINT` start a stop
(`SIGKILL` follows if the reactor has not exited within 10 s, the same deadline
discipline §13.3 applies to the engine), `SIGHUP` is a reload. After a forwarded
stop the supervisor exits with the reactor's status and does not restart.

Constraints, because the supervisor's only virtue is that it cannot fail:

- It MUST NOT open the lock, the socket, netlink, BPF or any file under the state
  root; its whole interface to the reactor is `waitpid` and `kill`.
- It MUST NOT poll. It blocks in `sigwaitinfo` on `SIGCHLD`, `SIGTERM`,
  `SIGINT` and `SIGHUP`; the backoff is one `sigtimedwait`, so a stop arriving
  during backoff is honoured immediately rather than after the sleep.
- The reactor starts with default signal dispositions and an empty signal mask;
  the supervisor's blocked set MUST NOT leak through `execve`.
- It writes one line per event to stderr, which `service.sh` has pointed at
  `service.log`. It has no other output.

**The reactor does not die with the supervisor.** No `PR_SET_PDEATHSIG` is set on
it: a supervisor killed by hand leaves a working proxy in place, merely
unsupervised, and a later `fluxd daemon` is rejected by the lock exactly as any
second instance is. This is the opposite of the engine's rule in §13.3, for the
opposite reason — the engine owns nothing and an orphan of it only contends for
ports; the reactor owns everything and *is* the instance.

Why not the shell loop this section used to show. Its behaviour depended on the
exit code and on time, so PHIL-7 already placed it in the binary; and it had a
defect the move fixes: it restarted on **every** non-zero exit, including "another
instance is already running", so a second `service.sh` invocation looped
forever at eight-second intervals against the instance that was working.

In `ps`, both processes read `fluxd daemon`; the parent is the supervisor.

- **`customize.sh`** checks arm64 and payload integrity, creates directories and
  sets modes and owners; copies a default configuration **only when the file is
  absent**, so an ordinary reinstall never overwrites a user's configuration;
  and runs no BPF capability test at install time — capability is decided by
  activation actually working (§3.7), and an install-time test would report a
  verdict that may not hold at boot.
- **`uninstall.sh`** requests `fluxd stop` synchronously and, on success, deletes
  only `/data/adb/flux-rs`. It MUST NOT scan for, read or delete any older Flux
  path, and MUST NOT flush network objects: the manager requires a reboot, after
  which non-persistent kernel objects are gone by themselves (§8.8).

## 13.3 The child process and orphan prevention

`fluxd` `fork`s and `exec`s the official sing-box directly, never daemonized. The pre-`exec` order is fixed (compare `clone/asteriskd/asteriskd_process.c:332-344`): restore signal dispositions, skipping `SIGKILL` and `SIGSTOP`; `setsid()`; clear supplementary groups; `PR_SET_PDEATHSIG`; **re-check the parent PID**, closing the window where the parent died before PDEATHSIG took effect; prepare fds; `execve`. `setsid()` makes the child a process group leader so the whole group can be signalled.

While the parent is alive, normal termination is `SIGTERM`, a short deadline, then `SIGKILL`, with pidfd confirming the exit.

**PDEATHSIG is `SIGKILL`, not `SIGTERM`** — asteriskd chose the latter. Once the parent has died abnormally nobody is left to enforce a graceful deadline, so a `SIGTERM` the engine ignores or handles slowly leaves an orphan contending for the same ports with whatever engine a supervisor starts next. And this engine **owns no kernel state at all** — no TUN, no BPF, no iptables, only listener sockets — so there is nothing to clean up gracefully and `SIGKILL` is strictly stronger. It also closes the listeners immediately, which is exactly what §2.2.1 wants: the next new flow misses the listener lookup and goes Direct.

**The child's identity MUST be verified rather than assumed.** Beyond the pid, read `starttime` from `/proc/<pid>/stat` and `/proc/<pid>/exe` to form a composite `(pid, starttime)` identity. When parsing `stat`, **locate fields from the last `)`**, because a comm may contain parentheses, and reject `Z` and `X` states. pid reuse is real on a device that runs for weeks (`asteriskd_process.c:370-390`).

**The engine's stdout and stderr MUST be captured** — piped to fluxd, written to the log, with the last lines retained in `status.last_error`. Discarding them abandons the only engine-side diagnostic other than `sing-box check`, and the hints of §24.4 depend on it.

## 13.4 One version source, and reproducible packaging

```toml
[workspace.package]
version = "0.9.0"
```

Everything else is derived by xtask: `module.prop`'s version line, `versionCode = major*1_000_000 + minor*1_000 + patch`, the ZIP name, and the CLI and build metadata. The VCS revision hash is provenance only and never enters `versionCode`. Only a signed `v*` tag triggers the release workflow, which verifies that the tag with its `v` removed equals the workspace version. **No second version file is maintained** — a version in two places is a version that disagrees with itself at exactly the wrong moment (PHIL-4).

`cargo xtask package` is the only packaging entry point, locally and in CI:

1. Start from an empty staging directory.
2. Resolve dependencies without repository version pins. Rust follows `stable`; Cargo dependency requirements are open and its local `Cargo.lock` is generated, not committed. `cargo update` refreshes an existing development resolution. Use the configured NDK and a host LLVM/clang with the BPF backend, targeting `aarch64-linux-android` API 31. Keep the resolved dependencies and tools unchanged within a reproducibility run. `fluxd` carries `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384`, and every `PT_LOAD` is then statically checked for `p_align >= 0x4000`. It is dynamically linked against Bionic so `getaddrinfo` reaches netd. The ZIP ships one `fluxd` file and does not bundle a libc. Remap the workspace path to `/flux-rs`; embed no wall-clock value.
3. Obtain the official engine resolved in §9.7, verify its archive and measure its ELF load alignment. Generate `build-info.toml` from these actual inputs; derive the dependency inventory from the local Cargo resolution.
4. Generate `module.prop`.
5. Copy files by the allowlist, normalising line endings to LF and fixing modes.
6. Build the ZIP with a fixed entry order, `SOURCE_DATE_EPOCH`, and no extra attributes.
7. Emit the ZIP and `SHA256SUMS`.

Build, artifact reads, staging and clean-build verification MUST agree on
Cargo's resolved target directory, including `CARGO_TARGET_DIR` and Cargo
configuration. Resolve it through `cargo metadata` and pass it explicitly to
the nested build. A binary left in the workspace's default `target/` is never
a fallback. Each reproducibility run uses a fresh, exclusively created target
directory; cleanup is confined to that run's directory. Cargo documents
`target_directory` as an absolute output path in
[`cargo metadata`](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).

`verify-package` resolves upstream once and reuses those inputs for both clean
builds. Reproducibility means equal inputs produce equal bytes; two builds that
resolve different upstream releases need not be identical. `release` retains
that same result when obtaining the engine's source archive.

No SBOM, signature, per-file hash or layered manifest is produced unless a real distribution channel actually requires one.

---

# Part 14: Performance and power budget

## 14.1 Static hot-path cost

| Path | Work performed |
|---|---|
| Unselected UID — the overwhelming majority of traffic | one TC invocation, `bpf_get_socket_uid`, one HASH miss. **No packet parsing, no control read** (§2.2.4) |
| TCP holding a `DIRECT` decision | the above plus `bpf_sk_fullsock` and one SK_STORAGE lookup. **No parsing, no control read** |
| First SYN of a selected-but-direct TCP flow | the above plus one control read (two map lookups), one LPM lookup, one listener lookup, one storage create. Nothing is written afterwards |
| First SYN of a captured TCP flow | the above plus `bpf_redirect` — zero writes on L2, two bytes on L3 — then on ingress one `change_type`, one control read, one listener lookup and `bpf_sk_assign` |
| Captured TCP, steady state, L2 | `bpf_sk_fullsock`, one storage lookup, one control read, `bpf_redirect`. **Zero packet writes, zero clone copies, zero parsing** |
| Captured TCP, steady state, L3 or rmnet | the above plus `bpf_skb_change_head(14)` and a two-byte EtherType write |
| Selected UDP, per datagram | UID lookup, bounded parse, one control read, one LPM lookup, one listener lookup, redirect; on ingress one `change_type`, one control read, one lookup and assign |

Against the two earlier blueprints, the L2 steady state for a captured TCP flow lost: one socket hash lookup (D1), one sentinel lookup (D2), one 6-byte MAC comparison (D3), and one 12-byte `bpf_skb_store_bytes` together with the `skb_ensure_writable()` copy it forced on a cloned skb (D17) — and it parses no L3 or L4 at all, as a by-product of D6. **On that path Flux does not touch a single byte of the packet.**

`bpf_redirect()` transfers ownership of the skb to the veth rather than copying it and continuing along the original path. The kernel may still unshare or segment for a shared skb, insufficient headroom or GSO, and **this document does not claim absolute zero-copy** — a claim that would be false in exactly the cases hardest to observe.

## 14.2 Userspace budget

- The reactor is single-threaded, with at most one blocking subscription worker and a steady-state target RSS of 8 MiB. **This is a target, not a measurement**, and must not be reported as one.
- Without a configured subscription refresh there is no periodic idle action: an epoll wait, plus the supervisor process blocked in `sigwaitinfo` (§13.2.2). A configured refresh uses the one-shot deadline of §29.3.
- Interface, package, configuration, child and fault events, control requests, and explicitly configured subscription deadlines/completions wake the control plane (§10.4).
- Production carries no per-packet logging or telemetry. The one ringbuf wakes only on a deduplicated fault, and `counters` is read only when `status` asks.
- sing-box's memory and CPU are dominated by the user's own configuration and MUST be reported separately. **`fluxd`'s small RSS MUST NOT be used to present the engine's cost as smaller than it is.**

## 14.3 What counts as evidence of efficiency

The evidence is static path counts, algorithmic complexity, allocation lifetimes, copy and wakeup boundaries, and BPF verifier output. Phase 0 and pre-release each run **one** short sanity check: unselected traffic does not enter userspace, idle produces no periodic wakeups, and the selection path contains no obvious loop or upload. No multi-day A/B, no per-device performance catalogue, and **no advertised percentage improvement that was never measured.**

---

# Part 15: Verification strategy

## 15.1 Static checks, and which platform proves what

- `cargo fmt --check`; the high-value `cargo clippy` lints; `cargo build --target aarch64-linux-android`.
- `cargo test -p flux-core`, which **MUST run on a Windows host**. That constraint is what keeps the pure logic free of libc and syscalls (§5).
- BPF: compiles clean under `-Wall -Wextra -Werror`, and a real `BPF_PROG_LOAD` passes the verifier on the Linux CI runner.

  **Passing on a newer kernel does not mean passing on 5.15.** CI runs `ubuntu-latest`, whose kernel is far newer than the baseline, so this gate proves only that the programs hold under some modern verifier. **The baseline verifier evidence comes from the device**: the Phase 3-8 device suites load the same programs on SM-S9180 running 5.15.211, and that is the first-hand result for 5.15. The CI gate exists to fail early, not to be the verdict; both must pass (GOV-4.1).

- Shell: CI runs `shellcheck --shell=sh --severity=warning` over `module/*.sh`. **The target runtime is BusyBox `ash` and shellcheck is not `ash`**, so it checks portability rather than what the target interpreter accepts. Scripts under `tools/**` are outside that scope and are executed by hand on a development host or a device.
- ELF checks: every `LOAD` segment of `fluxd` has `p_align >= 0x4000`; the official engine's measured alignment supports the product's page size and its asset digest matches the selected upstream release.
- Clean staging from the allowlist, version consistency, and two packaging runs hashing identically.

## 15.2 Eight logic tests that MUST exist, all in `flux-core`

1. Canonical `userId:package` parsing, `appId` range rejection, shared-UID enumeration, hard ceilings.
2. IPv4 and IPv6 CIDR canonicalisation, fixed bypass injection with its `RESERVED` tag, LPM key encoding, ceilings.
3. The template MUST NOT declare an inbound; the generated config injects exactly two tproxy inbounds and contains **none** of the removed or forbidden keys (§9.1).
4. The shipped `etc/default-template.json` has the shape §27.2.3 requires — no inbound, no `clash_api` once parsed (the original's block ships commented out), a fakeip range clear of the fixed bypass — and **carries the `sniff` and `hijack-dns` route rules**; a missing `:53` handler produces a warning rather than an error. **The real `sing-box check` against that file is `cargo xtask template-check`, not this test**: a flux-core test cannot run the engine binary, and conflating the two overstates what the host suite proves.
5. `size_of` and every field offset agree between `flux_abi.h` and the Rust mirror. **The cross-language comparison is `cargo xtask abi-check`, which has clang compute the C side**; this test guards the mirror.
6. The hand-written BTF blob's byte layout matches the struct definition, cross-checked against clang's `.BTF` by `cargo xtask btf-check`.
7. Control protocol request and response round-trip.
8. SemVer to `versionCode`, `module.prop` and the artifact name.

## 15.3 Deliberately not done

Multi-day soaks; a qualification catalogue across dozens of OEMs; a three-manager device matrix on every commit; a mock kernel or platform framework; a production canary or proof daemon with packet-token self-consistency proofs; unused tests written for a future backend or compatibility layer; and performance thresholds turned into hard gates CI cannot reproduce stably.

These are a **floor, not a ceiling.** Adding a focused test for an invariant after a real regression is encouraged; what is forbidden is piling tests onto every wrapper, getter and enum, which produces a suite that is expensive to run and proves nothing anyone doubted.

## 15.4 Four rules inherited from the old audits

Four classes of defect from the earlier audits are independent of any particular architecture and will recur under this one. They are **implementation contract**, not advice.

1. **Status reporting MUST be honest.** The old code swallowed every error on the rollback path and then published `attached=false` to the control plane (F-05), and deleted the promote journal even when the restore had failed (F-03). The rule: **`status` MUST NOT report a state cleaner than the one it has proven.** Before claiming "cleaned", "Inactive" or "no residue" there MUST be a fresh actual enumeration — a TC dump, `ip rule`, `ip route`, BPF program info — showing the objects are absent. When that cannot be shown, report `unknown(cleanup_required)` with the first concrete error attached.
2. **ABI tests assert against artefacts, never against source strings.** The old repository had a token-map test asserting a literal in a C source file (`token_map.rs:907` against `flx_sock_addr.c:409`), which turned red when a helper was renamed (F-10). The rule: `flux_abi.h` consistency, the BTF blob and map parameters are asserted against **compiled artefacts** — an ELF section, `.BTF`, `BPF_OBJ_GET_INFO_BY_FD` — and grepping C source is forbidden.
3. **CI, documentation and the real command set MUST agree mechanically.** The old CI invoked two deleted xtask subcommands while `development.md` and the README still listed retired commands and an obsolete protocol version (F-09, F-13, design audit P0 #4). The rule: a self-check walks every `cargo xtask <sub>` appearing in a workflow or a document and asserts that xtask can resolve it, and the version has exactly one source in the workspace. **This is implemented** as the commands check of `cargo xtask doc-check`.
4. **One authoritative architecture document.** The old design corpus specified three mutually incompatible attach strategies in a single file — PromoteThenAppend, forbidden DETACH, KD 35 fail-open — so an implementer following any one passage was wrong (design audit P0 #1), and eighteen ADRs had YAML statuses contradicting their own bodies (P1 #20). The rule: **there is no ADR directory.** There is one blueprint, edited in place, with `../guide/architecture.md` as its reader-facing projection. A second document that conflicts with it is deleted, **not annotated with "the later one wins"** — the same reasoning that retired the incremental blueprints (`../authoring.md` AUTH-7.2).

---

# Part 16: Phase 0

> **Moved out of this document** → `../history/phase0.md`. The section number is unchanged; the tools are in `tools/phase0/`.
# Part 17: Implementation phases

> **Moved out of this document** → `../plan/implementation.md`. The section number is unchanged.
>
> Moving it also **fixed a circular dependency**: the old Phase 0 exit condition required "every critical seam in §16 passes", while §16's Q5, Q7 and Q8 can only be tested by code that phases 5 to 7 produce. §17.2 now assigns each remaining question to **the phase that can actually run it**, so every phase's exit condition is satisfiable by that phase.

---

# Part 18: Transition from the previous repository

> **Moved out of this document** → `../history/migration.md`. The section number is unchanged.
>
> The migration was executed on 2026-08-25 and is a record rather than a plan. This document keeps only what constrains current code.
---

# Part 19: Rejected alternatives

> **Moved out of this document** → `../history/rejected-and-deferred.md`. The section number is unchanged.
# Part 20: Pre-release acceptance

Tagging a release requires **all** of the following simultaneously. The list is
a conjunction: a release blocked by one unmet item is blocked, and the remedy is
to meet it rather than to argue it is minor.

1. Phase 0 records prove the core seam through **an original destination
   observed by the real engine**, not through a map agreeing with itself.
2. The repository contains only the structure §5 permits, with no old code or
   artefacts.
3. The official sing-box asset is verified against the selected upstream
   release; `build-info.toml` describes the actual binary, source revision and
   tools, and measured ELF alignment supports the product's page size.
4. The release notes and the runtime both state `base page == 4096` as a product
   boundary; `fluxd`'s own LOAD segments are 16 KiB aligned; a device with any
   other page size stays Inactive and Direct and starts no engine.
5. The static hot path for an unselected UID is exactly the UID helper plus one
   HASH miss — no parsing, no userspace (§2.2.4).
6. Dual-stack TCP and UDP original destinations agree with what the official
   sing-box actually observes.
7. After the engine exits, a new SYN or datagram goes Direct at the next
   listener lookup, and a parseable packet on an admitted TCP flow does **not**
   go direct because Flux lost internal state while still passing through a
   managed hook (§2.2.2).
8. No Android VPN or TUN has been attached; an unconfirmed CLAT is Direct; netd
   fwmark, rules and sysctls are unmodified.
9. `stop` and `uninstall` flush no system object, and a reboot leaves no Flux
   kernel residue.
10. Magisk, KernelSU and APatch have each completed one
    `install → boot → status → disable → uninstall/reboot` smoke run.
11. The module ZIP and `SHA256SUMS` come from the same xtask invocation and two
    clean builds agree byte for byte.
12. **DNS precision is measured**: a selected app's system-resolver DNS is
    captured and an unselected app's is not (§16, Q9 items 1 and 3).
13. `../guide/` adopts the boundaries of §1.3, §2.2 and §3 verbatim, **stating
    the three residual DNS boundaries of §1.3.3 explicitly** — Private DNS does
    not pass through Flux, `enforce_dns_uid` devices degrade, mDNS is direct —
    together with §1.3.4's requirement that `hijack-dns` is what makes domain
    rules take effect. Phrases such as "any failure falls back invisibly" or
    "works on all of Android" MUST NOT appear.
14. The gap table of `../plan/implementation.md` §17.0.2 is empty. The blueprint
    is a target contract, so a release while it is non-empty would ship
    something the contract does not describe.

---

# Part 21, 22: Owner confirmations and deferred items

> **Moved out of this document** → `../history/rejected-and-deferred.md`. The section number is unchanged.
# Part 23, 24: Failure matrix and the status specification

> **Moved out of this document** → `failures.md`. The section number is unchanged.
# Part 25: Startup timing and boundary conditions

`service.sh` fires at late_start, when Android is not yet ready. This section enumerates every "too early" condition, because **all of them are hit on a real device's first boot** — they are the normal case, not edge cases.

| Timing problem | How it presents | Handling |
|---|---|---|
| `/data` not yet decrypted — FBE, user has not unlocked | `/data/adb/flux-rs` is reachable because `/data/adb` is device-encrypted, but **configuration in the credential-encrypted area would be unreadable** | The state root is fixed at `/data/adb/flux-rs`, in the DE area, so this cannot arise. Placing configuration under `/data/user/0/...` is **forbidden** |
| Network not up yet | no candidate interface at all | Enter `Inactive` normally and wait for rtnetlink. **This is not an error**: `last_error` stays null and `ifaces` is an empty array |
| `packages.list` not yet written | may be absent very early on a first boot | Stay `Inactive` with the reason recorded; inotify watches its **parent directory**, because the file is replaced atomically and a watch on the file alone would miss the event |
| `sys.boot_completed` not set | irrelevant here — §11.3 removed the dependency on binder and `cmd package` | Nothing to wait for. **This is D8's principal benefit**, and it is why no retry state machine exists for startup ordering |
| SELinux still moving permissive to enforcing | a BPF load may succeed then fail, or the reverse | No special handling. A failure means `Inactive`, and the next rtnetlink or inotify event retries |
| The engine binary's `PT_LOAD` check | not performed at runtime; xtask verified it at packaging time | At runtime only the page size is checked |
| Clock not synchronised | affects log timestamps only | **No decision uses wall-clock time.** The generation is a monotonic counter, not a timestamp |
| Repeated restarts, a crash loop — of the engine under the reactor, or of the reactor under its supervisor (§13.2.2) | backoff of 1/2/4/8/30 s, reset after the child is stable for 60 s; one schedule for both | **There is no "failed N times, locked out permanently".** Recovery continues at a low rate for as long as the switch is on, and `status` exposes `backoff_seconds` so a human can tell the difference between waiting and stuck |

**The correct posture at cold start is to do what can be done and wait for events for the rest.** Only the page size and netns checks are terminal, because retrying them cannot change the answer. Every other failure is merely the outcome of the current convergence round, and the next rtnetlink, inotify or timerfd event converges again. This is what makes the daemon level-triggered rather than a startup sequence with error handling bolted on.

---

# Part 26: The reactor state machine

Three top-level states (§10.1) by event, giving the action. This table is the direct basis for implementing `reactor.rs`. **A combination absent from the table is a combination that should not occur**: log it and ignore it, and MUST NOT invent handling for it.

| Event | `Disabled` | `Inactive` | `Active` |
|---|---|---|---|
| Bootstrap complete | stay Disabled | attempt the full activation sequence (§8.7) | — |
| `enable`, deleting the `disable` file | attempt activation | idempotent, no action | idempotent, no action |
| `disable`, creating the `disable` file | idempotent | stop the engine, go Disabled | publish `active=0`, stop the engine, go Disabled |
| `reload` | re-validate the configuration and report; change nothing | attempt activation again | policy domain: the add-then-subtract of §10.5, **leaving `active` untouched**; engine domain: the candidate switch of §9.4 |
| `stop` | exit cleanly with 0 | publish `active=0`, stop the engine, exit 0 | as Inactive |
| `status`, `check` | read-only | read-only | read-only |
| rtnetlink: new interface | ignore | re-evaluate admission and activate if otherwise ready | debounce, admit, attach; a failure excludes only that interface |
| rtnetlink: interface gone | ignore | update the candidate set | remove from the active set; if it becomes empty, go Inactive |
| rtnetlink: address change | ignore | update the desired self-address set | update the self-address maps additively, **leaving `active` untouched** |
| rtnetlink: **capture-side** drift — a physical interface's `clsact` or our egress filter was deleted | ignore | reconverge | **leave `active` untouched**: debounce, then re-attach the egress filter. If the `clsact` is gone, exclude the interface as `netd_clsact_missing` and wait for netd's `RTM_NEWQDISC` — Flux does not create it (§8.5). A failure removes only that interface from the active set |
| rtnetlink: **core** drift — `flxrs0`/`flxrs1`, the ingress filter, the rule or the local route was deleted or altered | ignore | reconverge | **publish `active=0` first**, reconverge by the predicate, and set `active=1` only on success |
| rtnetlink: `ENOBUFS` or overrun | ignore | full re-dump | full re-dump (§10.4.1 rule 2) |
| inotify: `flux.toml` changed | update the validation result only | attempt activation again | policy transaction, add then subtract |
| inotify: `template.json` or a `@file` list changed | update the validation result only | attempt activation again | regenerate (§28.2), then the engine candidate switch |
| inotify: `packages.list` changed | ignore | re-parse | re-parse, then a policy transaction |
| nl80211: connect, roam or disconnect | ignore | re-read the SSID set (§29.2); if it no longer pauses, attempt activation | re-read the SSID set; if it now pauses, publish `active=0`, stop the engine, go Inactive (§29.5); otherwise no action |
| pidfd: engine exited | should not occur | record, restart with backoff | publish `active=0`, restart with backoff, new generation |
| ringbuf: current-generation fault | should not occur | clear the latch | publish `active=0`, restart the generation |
| ringbuf: old-generation or duplicate fault | ignore | ignore | **clear the latch and ignore** — the handler is idempotent per generation |
| timerfd: debounce expired | — | run the pending convergence | same |
| timerfd: backoff expired | — | retry activation | retry starting the engine |
| timerfd: readiness backoff | — | re-check SOCK_DIAG | same |
| `SIGHUP` | equivalent to `reload` | equivalent to `reload` | equivalent to `reload` |
| `SIGTERM`, `SIGINT` | exit 0 | publish `active=0`, stop the engine, exit 0 | same |

**Four invariants:**

1. **The only way into `Active`** is the single `control_root` pointer swap of §8.7 step 10, and **the first action on leaving `Active`** is always publishing `active=0`. There is no other path in either direction, which is what lets every other rule reason about `active` without enumerating cases.
2. **A policy transaction never changes the top-level state** (§10.5, D5). Only an engine generation switch, **core** topology drift, or the engine exiting leaves `Active`.
3. **Events arriving during a transaction are neither dropped nor recursed into.** Record them in a pending set and consume them in one convergence after the current transaction ends. Re-entering the reactor from inside a transaction is forbidden.
4. **Capture-side drift MUST be handled locally and MUST NOT escalate into a
   global transaction.** The table gives capture-side and core drift separate
   rows for the reason in §8.5.1: netd deletes the `clsact` every time an
   interface joins or leaves a network, and a netd restart after a
   system_server crash clears the clsact of **every** interface.

   Routing those events through "publish `active=0`, reconverge, `active=1`"
   would mean **every Wi-Fi reconnection briefly cuts proxied traffic across the
   whole device**. The correct handling re-attaches the filter on that one
   interface with `active` untouched throughout, leaving every other interface
   unaffected.

   **This is the easiest thing in the state machine to get wrong, and the
   consequence is the most visible** — which is why the distinction is a row in
   the table rather than a note under it.

---

# Part 28: Subscription and configuration generation

> **New numbering in 0.9.5**, folding R092-01, R092-05 and R092-08. C11
> (subscription) moved from deferred into scope with the owner's confirmation on
> 2026-08-30. C8 (a Flux-built WebUI) and C10 (an out-of-the-box control plane)
> **remain deferred** — see `../history/rejected-and-deferred.md` §21.0.

## 28.1 Who owns which file

The engine config is **generated**, not owned. The user edits a template; Flux
produces the file sing-box actually runs, and rebuilds it whenever an input
changes.

| Path | Owner | Notes |
|---|---|---|
| `config/flux.toml` | user | Flux's own behaviour: who is selected, what bypasses, which interfaces, subscription parameters |
| `config/template.json` | user | sing-box config template: DNS, route rules, selector skeleton |
| `config/*.txt` | user | list files referenced by `@` (§11.2) |
| `run/subscription.raw` | machine | the **raw** subscription response, the only network artifact |
| `run/sing-box.<gen>.json` | machine | one per generation, read-only, deleted on rotation |

Flux MUST NOT write to any user-owned path. It MUST NOT edit `template.json` in
place, and it MUST NOT treat a generated file as an input on the next run.

`config/template.json` carries the same name and meaning as `Flux-original`'s
`conf/template.json`, so a cross-reference between the two projects needs no
explanation. **`Flux-original`'s `config.json` is a machine artifact**, and this
project deliberately does not reuse that name for a user-owned file: one name
meaning opposite things across two closely related projects is worse than a
slightly longer one.

The 0.9.0 name `effective-sing-box.<gen>.json` becomes `sing-box.<gen>.json`.
The file lives in `run/`, so "effective" carried no information.

### 28.1.1 Why the user does not own the engine config

0.9.1 had this relationship backwards: it copied the template once at install
time and handed ownership of the result to the user. The consequence only became
visible on a real device — applying a subscription update meant merging it into
the user's file **by hand with `jq`**. A step that must happen on every
subscription refresh, performed manually, is a missing product feature rather
than a workflow.

The reference implementation resolves it the other way and has for years:
`Flux-original`'s `scripts/updater.sh:139-149` (Phase C) takes the template,
fills each empty selector with the matching regional group, appends the refined
nodes, and writes the runtime config. The user edits only the template.

## 28.2 Generation is a pure function

```
template.json + configured manual nodes + available subscription snapshot
  → sing-box.<gen>.json
```

Manual nodes and a remote subscription are independent inputs to one node pool.
Either may be absent. The cached remote response contributes only when it is
bound to the currently configured URL. A missing response contributes no nodes;
it does not prevent a valid configuration built from manual nodes from running.
All inputs converge through this same generation function and the existing
engine transaction, without a separate manual-node activation path.

Generation MUST do exactly two things, matching `updater.sh` Phase C:

1. **Fill.** Every `selector` or `urltest` in the template whose `outbounds` is
   an empty array is filled with the regional group its tag matches. Tags
   `PROXY`, `GLOBAL` and `AUTO` are filled with every node.
2. **Append.** The refined nodes are appended to `outbounds`.

Two consequences follow from one measured fact: **the engine rejects an empty
group outright** — `initialize outbound[N]: missing tags` at both `check` and
`run`, measured against official 1.13.19, whether or not anything references
the group.

- **A group with no matching node becomes `DIRECT`.** An Asia-only plan leaves
  the template's `US` empty, and shipping that to the engine would take the
  whole configuration down over one unused group. `DIRECT` keeps it selectable
  and visibly not a proxy.
- **With no nodes at all the candidate is refused**, naming the empty groups:
  `engine_config_unfilled`. A template is not a configuration. The reference
  implementation can leave its regional groups empty because `updater.sh` fills
  them before the engine ever sees the file; Flux reaches the same place by
  refusing to hand sing-box a file it will reject, and saying which groups are
  waiting and that `[subscription] url` or the user's own nodes fill them.
  Cold start therefore stays `Inactive` and Direct, with the reason stated,
  rather than entering a crash-restart loop (§23.1).

**Nodes that no group selects are a warning, not an error** (`nodes_unreferenced`).
The configuration is valid and the user may mean it, but every selected app
still egresses direct, so `status` and `check` say so instead of reporting a
clean Active (§17.1).

Everything else MUST retain the same JSON value. Comments and formatting are
not part of that value and are not copied into generated JSON.

That last sentence is a testable claim, not a statement of intent: **substitute
the template's `outbounds` back into the generated file and the result MUST be
deeply equal to the template.** An implementation that reorders keys, drops a
comment-stripped field, or normalises a number fails it. This test is required
(§15.2).

### 28.2.1 Subscription parameters

These live in `flux.toml` and belong to its schema (§11.2); their meaning is
defined here, where it is used, so that neither section restates the other.

```toml
[subscription]
url = ""
interval = 86400          # seconds; 0 = manual refresh only
timeout = 10
retries = 2

[subscription.refine]
exclude_pattern = "(expire|traffic|官网|到期|流量|剩余|套餐|重置|联系|群组|通知|平台|网站|时间|建议|反馈|版本|更新)"
rename = [
  { match = "【(亚洲|北美洲|欧洲|南美洲|非洲|大洋洲|南极洲)】", replace = "" },
]
strip_emoji = true
max_tag_length = 32
```

An empty `url` disables subscription entirely: no fetch, no timer, and
`run/subscription.raw` is never created. That is the default, so a fresh install
makes no network request of its own.

Acquisition settings belong to `[subscription]`; provider-specific name cleanup
belongs to `[subscription.refine]`. These are responsibilities, not beginner
and expert modes. Both tables have defaults and may be omitted. The former
flat refinement keys move into the nested table for the 1.0.0 candidate schema;
Flux never rewrites an existing user configuration to migrate it.

### 28.2.2 Manual node inputs

```toml
[nodes]
list = ["@nodes.txt"]
```

Each list entry is a sharing URI or an `@file` reference using the existing
direct-child, non-recursive list-file rules of §11.2.2. A file contains one URI
per line; only whole lines starting with `#` are comments, because a URI's
fragment is its node name. Inline URIs and list files may be mixed without a
second configuration format. An empty or absent list means no manual nodes.

The parser preserves the manual node's name and protocol settings. Provider
announcement filters, renaming and truncation MUST NOT alter a node the user
entered explicitly. Region membership may be derived from its name for an
optional regional selector, but no region match is required to use the node.
Manual nodes appear first in the pool, followed by the accepted remote nodes.
Neither source silently replaces nodes from the other. The complete candidate
still goes through official engine validation, including tag collisions.

The original outbound menus remain intact. A matching name places a manual
node in a regional group; otherwise the user can reference its tag in an
existing menu or add an empty `AUTO` selector to receive the entire pool.
Generation never makes that policy choice. The existing `nodes_unreferenced`
warning identifies an appended node that no group selects. A complete template
with its own populated outbounds also remains valid without either external
input.

On cold start, manual nodes can form a generation while the optional remote
fetch is pending or unavailable. The fetch failure remains visible. A later
valid response enters the same candidate transaction. An invalid manual URI
invalidates that candidate; it is never skipped or replaced by a guessed node.
Diagnostics identify the source entry and unsupported field, not the URI or
its credentials.

## 28.3 Subscription input formats

Two, distinguished **by content**, never by file extension, URL suffix or the
`Content-Type` header:

- **Already sing-box JSON** — take `.outbounds`. Measured: providers return a
  complete config when the request carries a `sing-box` user agent.
- **Base64-encoded URI list** — decode, then parse each line as `vmess`,
  `vless`, `trojan`, `hysteria`, `hysteria2`, `tuic`, `ss`, `socks` or `http`.

Manual list entries use the same URI parser directly. `hy2` is an alias of
`hysteria2`. A URI conversion MUST preserve protocol semantics: unsupported
transports or VLESS encryption other than absent/`none` are errors in the
current converter, never silently converted into ordinary TCP or unencrypted
VLESS. Hysteria2 authentication is the entire percent-decoded URI userinfo,
including an encoded username/password separator.

URI support is the intersection of an exact conversion and the installed
official engine's capabilities. Engine upgrades need no Flux version allowlist;
the actual engine checks the generated configuration. Native sing-box JSON in
the template or subscription can express features beyond the URI converter.
`snell` was listed here through 0.9.5 and is not: it is Surge-proprietary and
appears nowhere in sing-box, so under §1.1's unmodified official binary a snell
node could never connect. Parsing one would have produced a candidate that fails
`sing-box check` — safe, because §28.6 keeps the current generation, but the user
would be left with a subscription that never applies and no statement of why.

A line whose scheme is not in this list **fails the parse, naming the line
number and the scheme**. It is not skipped: a silently dropped node is a node
the user paid for and cannot see is missing. The failure costs nothing
operationally, because §28.6 keeps the running generation either way.

URI parsing MUST live in `flux-core`: pure logic, no libc, no syscalls.
It therefore has unit tests that run on any development host with no device and
no network. This is a direct improvement on the reference implementation, which
hand-writes a base64 decoder, a URL decoder and a JSON field extractor in awk
(`updater.sh:175-245`) — in Rust all three are library calls, and every
hand-rolled version of them is a source of defects.

## 28.4 Node refinement

This pipeline handles provider output only, using `[subscription.refine]`.
Manual nodes preserve their user-authored names (§28.2.2). Fixed order,
matching `updater.sh` Phase A/B:

1. drop infrastructure types (`selector`, `urltest`, `direct`, `block`, `dns`);
2. discard entries matching `exclude_pattern`;
3. rewrite tags by the `rename` rules;
4. optionally strip emoji;
5. normalise multiplier notation (`$2.0`, `2.0倍率`, `2.0X` all become `2.0x`)
   and collapse runs of whitespace;
6. truncate to `max_tag_length`;
7. group by region regex, for the fill step of §28.2.

**Step 2 is the one that earns its place.** Providers put announcements —
expiry dates, traffic quotas, contact links — into the node list as fake
outbounds. Without this step the user's selector fills up with entries that can
never connect, and every one of them looks like a node.

Generation MUST fail when the refined non-infrastructure outbound count is zero.
A fetch that returned an error page can still be syntactically valid JSON and
can still pass `sing-box check`, while containing no node at all; the count is
what distinguishes the two.

## 28.5 The cache holds the raw response

`run/subscription.raw` stores the response exactly as received, **before**
refinement.

The refinement rules (`exclude_pattern`, `rename`, `strip_emoji`,
`max_tag_length`) live in `flux.toml` under `[subscription.refine]`, so editing them is a purely local
operation. Caching the refined output would force a network round trip to see
the effect of a local edit, which fails offline and is slow when it does not.
Keeping the raw copy also keeps the network artifact single-purpose: exactly one
file in the tree came from the network, which matters for both diagnosis and
trust.

## 28.6 A subscription update must never take the network down

The transaction is the three-stage form of `updater.sh:421-450`, joined to the
existing engine candidate switch (§9.4):

1. the merged result MUST pass the official `sing-box check` before anything is
   deployed; on failure the current generation is kept and the error reported;
2. deployment is a backup plus an atomic `rename`;
3. if the new content is identical to the current generation, skip the rotation
   entirely rather than restarting the engine for no reason.

This is not a new guarantee. §9.4 already requires it of every candidate switch;
subscription refresh is simply routed through the same transaction rather than
being given a path of its own.

## 28.7 `fluxd subscribe`

Triggers one fetch and, if it produces a different result, one rotation.

It is the first CLI command added since R091-11 froze the set, and it is added
for the reason that freeze allowed: there is now an implementation behind it.
Refresh is otherwise driven by the timer of §29.3 and by network recovery,
never by polling.

## 28.8 `webroot` is a redirect, not a UI

`Flux-original`'s `webroot/index.html` is 12 lines that redirect to
`http://127.0.0.1:9090/ui/`. **It is not a WebUI.** It is the target of the
button the root manager shows next to a module, and it lands on sing-box's own
`clash_api` interface.

C8 defers *a Flux-built WebUI*. A redirect shell is not that, and its cost is
close to zero, so it ships while C8 stays deferred. Two improvements over the
reference:

- the redirect URL carries the controller address and secret the user
  configured, so neither has to be typed;
- when no `clash_api` is configured, the page says so instead of redirecting
  into a connection failure, and points at the commented block in the template
  that turns it on (§27.2.4) rather than describing keys to invent.

**Where the page gets that information.** Not from a file Flux writes: §27.1.2
allows Flux exactly two writes in the module directory, and §27.2.3 ships no
controller, so there is no install-time secret to bake in. The page asks at the
moment it is opened. Every manager that opens a `webroot` — KernelSU, APatch,
and the standalone WebUI launchers used with Magisk, which itself has no module
WebUI — exposes the same JavaScript bridge, `ksu.exec(command, options,
callback)`, which runs a command in a root shell and returns `errno`, `stdout`
and `stderr` (Verified: `kernelsu.org/guide/module-webui.html`; APatch's FAQ
states its implementation is identical). The page runs `fluxd status --json`,
reads `engine.effective_config`, reads that generation's `experimental.clash_api`
through the same bridge, and then either navigates to the controller or explains
which precondition is missing: the bridge, a running daemon, a running engine, or
a configured controller. `fluxd` gains no new command and writes nothing for it.

`webroot/index.html` joins the packaging allowlist (§13.1). It is one file with
no assets, and it stays one file: anything beyond the redirect is the WebUI C8
defers. Flux still enables no control port by default (§27.2.3), so on a
default install this page explains rather than redirects.

---

# Part 29: Conditional activation

> **New numbering in 0.9.5**, folding R092-07 and the automation half of
> R092-06.

## 29.1 The SSID dimension

Some networks do not want proxying: the home or office network the user already
trusts. `box_for_magisk` covers this with `use_ssid_matching`,
`use_wifi_list_mode` and `wifi_ssids_list` (`settings.ini:204-212`).

```toml
[ssid]
mode = "blacklist"        # blacklist = do not activate on a listed SSID
list = ["MyHome", "@ssid.txt"]
```

This is the fourth dimension to reuse the same allow/deny idiom of §11.2, with
the same `@file` reference and the same meaning for an empty list. A user who
has understood one of them has understood all four, which is the point of
spending a fourth dimension on the same shape rather than inventing a switch.

An entry matches a connected station interface's SSID **byte for byte**, the
entry taken as UTF-8 — no wildcards, no case folding. A Wi-Fi name is an
identifier the user copies from the phone's own settings, not a pattern, and a
pattern language would turn one stray character into a silent non-match. Only
`NL80211_IFTYPE_STATION` interfaces count: a P2P client or an access point the
phone is hosting is not "the network the user is on". With several connected
station interfaces, the dimension considers the set of their SSIDs.

| `mode` | Flux pauses when |
|---|---|
| `blacklist` | some connected SSID is in the list |
| `whitelist` | Wi-Fi is connected and no connected SSID is in the list |

Neither mode pauses when no Wi-Fi is connected (§29.5): the dimension speaks
only about Wi-Fi networks, so on cellular it has nothing to say.

## 29.2 SSID comes from nl80211, never from binder

Flux MUST read the SSID over generic netlink (`NL80211_CMD_GET_INTERFACE`). It
MUST NOT call into binder and MUST NOT shell out to `dumpsys`.

The reasoning is the same one that rejected `cmd package` in D8: binder may not
be up during `late_start`, so depending on it introduces a start-ordering
dependency and a retry state machine — two mechanisms bought for one field.
Flux already speaks netlink, so another generic netlink family is the capability
it has, not a new one. This is a case where the design can be **cleaner than the
reference implementation** rather than merely equivalent to it.

SSID changes are themselves events: the `NL80211_CMD_CONNECT` and
`NL80211_CMD_DISCONNECT` multicast groups. Nothing here polls.

**How the family is reached.** Generic netlink families have no fixed id, so
Flux resolves `nl80211` once at start through the controller family
(`GENL_ID_CTRL`, `CTRL_CMD_GETFAMILY` with `CTRL_ATTR_FAMILY_NAME`), whose reply
carries the family id and, under `CTRL_ATTR_MCAST_GROUPS`, the id of the `mlme`
multicast group (Verified: `clone/kernel-src/v5.15/include/uapi/linux/genetlink.h`;
`NL80211_MULTICAST_GROUP_MLME` in `nl80211.h:50`). Flux joins that group
**before** the first dump, for the reason §10.4.1 gives for rtnetlink. A kernel
without cfg80211 answers the resolution with `ENOENT`, and the dimension is then
inert (§29.5).

**What the dump says.** `NL80211_CMD_GET_INTERFACE` with `NLM_F_DUMP` answers
one `NL80211_CMD_NEW_INTERFACE` per wireless interface, carrying
`NL80211_ATTR_IFINDEX`, `NL80211_ATTR_IFTYPE` and — for a station, P2P-client or
ad-hoc interface that has a current BSS — `NL80211_ATTR_SSID`, taken from that
BSS's SSID element (Verified: `clone/kernel-src/v5.15/net/wireless/nl80211.c:3612-3633`,
`nl80211_send_iface`). An interface without the attribute is not associated.
Attribute parsing follows the allowlist discipline of §8.5: an unknown attribute
is skipped, a malformed message fails the dump, and a failed dump is
`ssid_unreadable`, never "no Wi-Fi".

**Events are triggers, not values.** `NL80211_CMD_CONNECT`, `ROAM`,
`DISCONNECT`, `DEAUTHENTICATE` and `DISASSOCIATE` arrive on `mlme`. Each one
schedules a fresh dump through the existing debounce, exactly as an rtnetlink
event does (§10.4.1); the SSID is never read out of the event itself, which
would mean two parsers for one fact and a decision taken on a message that may
already be stale.

## 29.3 A one-shot timer is not polling

§10.1 forbids periodic polling. Subscription refresh (§28.7) arms a timerfd for
`interval` seconds and re-arms it on expiry, which needs to be reconciled with
that rule explicitly rather than left to the reader.

The prohibition targets health probes: waking every N seconds to ask whether
something is still true. A refresh timer asks nothing. It performs an action the
user configured, at a time the user chose, and with `interval = 0` no timer is
armed at all. **Recorded as an explicit exception**, on those grounds.

`cron` is not used. Android ships no `crond`; relying on busybox would add an
external dependency and a second process, whereas a timerfd is already part of
the reactor's event loop and costs nothing new.

## 29.4 Network recovery and configured refresh are independent

A failed fetch MUST NOT create a second retry schedule. A usable default route
returning may trigger one earlier attempt through the existing rtnetlink event.
The user's configured refresh interval (§29.3) continues independently after
success or failure. `interval = 0` still means no scheduled refresh.

Route presence is not proof of Internet access or completion of a captive
portal login. HTTP/TLS failures MUST NOT disable future configured refreshes
until the route disappears and returns. A user can request an immediate fetch
with `fluxd subscribe`; Flux does not invent a connectivity watchdog to discover
when an external service or authentication session has recovered.

## 29.5 Boundaries

- SSID affects **whether Flux activates**, never what the policy contains. It is
  an input to the top-level state of §26, not to the maps of §6.
- When no Wi-Fi is connected, the dimension does not participate in the
  decision. It is not treated as an empty SSID.
- When the SSID cannot be read, Flux MUST treat it as matching no list entry,
  MUST warn, and MUST NOT block activation. An unreadable SSID is a diagnosable
  failure, not a reason to refuse to run (§23, PHIL-6).

**What "does not activate" is.** A paused Flux does exactly what the module
switch does when it is turned off (§26, `disable` row): publish `active=0`, stop
the engine, keep every kernel object, keep waiting for events. It differs in one
thing only — the switch is on, so the top-level state is `Inactive`, and `status`
says why through the `ssid` object of §24.1. The moment the SSID set stops
matching, the ordinary activation of §8.7 runs again from the authority files;
nothing is remembered across a pause. This reuses one transition rather than
adding a fourth state, which §26 forbids.

**The SSID never leaves the daemon.** It appears in no `status` field, no
`module.prop` line, no log line and therefore no bug report. `status` reports
`ssid.connected`, `ssid.paused` and, when a pause is caused by one list entry,
that entry's position in the expanded list — enough to diagnose, because the
user can see the network name on the phone itself. A network name is location
history, and no diagnostic here needs it.

When `[ssid]` is empty the dimension does nothing, reads nothing and subscribes
to nothing; an empty list MUST cost no generic netlink traffic.

## 29.6 What the existing event sources already cover

Flux's event sources all sit on one epoll: signalfd, inotify, rtnetlink, generic
netlink for `nl80211`, pidfd, ringbuf, timerfd, the control socket and the
subscription worker's eventfd (§10.4). The automation below adds **no new
mechanism** — each item connects an event already being watched to a behaviour
the user can observe.

| Automation | Event source |
|---|---|
| A newly installed app is picked up when `mode = "blacklist"` | inotify on `packages.list` |
| Editing the template or a list file regenerates, validates and rotates | inotify on `config/` |
| A failed fetch retries when the network returns | rtnetlink (§29.4) |
| Scheduled subscription refresh | timerfd (§29.3) |
| Interfaces appearing or disappearing are taken over or dropped | rtnetlink |
| Local address changes are injected into the bypass set | rtnetlink |
| Pausing on a listed Wi-Fi network, resuming when it is left | generic netlink `mlme` events (§29.2) |

### 29.6.1 Two automations that are deliberately absent

**Automatic latency-based node selection.** sing-box's `urltest` already does
it. A second implementation would mean a second copy of "which node is usable"
and a synchronisation problem between Flux and the engine.

**A network watchdog that rolls back automatically.** §8.3 rejected this and the
reasoning is unchanged: deciding whether the network is healthy requires active
probing, which misjudges an offline or captive network, and **a rollback that
misjudges turns the proxy off while the user is using it normally** — strictly
worse than having none.

---

- The language a document is written in, and the names of its fields, do not change what it binds.
- ABI source of truth: `bpf/include/flux_abi.h`; data-plane skeleton: `bpf/flux.bpf.c`.
- For terminology, see `../README.md`.
