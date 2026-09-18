# clone 项目设计哲学与技术边界重估

**研究日期：2026-09-17。结论：clone 里真正可迁移的不是某一种挂钩方式，而是同一套分层——内核只回答身份与交付，政策留在用户态，热路径不得连累未选中流量，对象所有权必须能从内核现证。Flux 现行哲学（PHIL-0–8）在这张图上仍然成立。值得重新打开的不是「要不要变成代理内核」，而是「在不改官方 sing-box、不抢 cgroup、不占 fwmark 的前提下，交付路径能不能比 veth 更短」。`.ko` 是这条问题的一种答案，不是唯一答案，也不是最便宜的答案。**

本文是当日证据记录，不新增产品合同。与 `spec/` 冲突时，错的是本文。第三方源码不进 git，路径相对于 `clone/`；重建见 `tools/clone-manifest.md`。`clone/Re-Kernel` 是 2026-09-17 另浅克隆的，当时尚未写入清单，HEAD `e67cd94`。

证据等级按 AUTH-2：源码给 `clone/<dir>/file:line`；内核源带版本；没有设备新测的百分比一律标「推断」。先前会话「Re:Kernel 学习」（conversation `9e1a710f-2da7-4981-9294-7aafbdbe0075`）的 `.ko` 讨论并入第 4 节，不以聊天记录当出处。

## 0 读法与当日版本

先读第 1 节的问题分类，再读第 2 节技术目录（本文的主体），第 3 节是各项目笔记，第 4 节才是对 Flux 边界的压力测试。不要从第 3 节抄实现。

| 目录 | 当日 HEAD | 它回答的问题 |
|---|---|---|
| `dae` | `caa6f5e` | Linux 网关上，如何在 TC 里按规则把包交给本进程的 TPROXY |
| `honk` | `131e71b` | 把 dae 的数据面用 Rust 重写，并补 LAN UDP 的 NFQUEUE 暂扣 |
| `chizi-sing-box-ebpf-cilium` | `45a5bd8` | 给 sing-box 打补丁：cgroup 改写目的 + 可选 TC/TCX |
| `bpf2socks` | `885a313` | cgroup 改写到 token，用户态 bridge 再出 SOCKS5 |
| `bpfmatcher` | `b814407` | 给 iptables `xt_bpf` 提供可 pin 的 socket-filter |
| `asteriskd` | `0e6705e` | 一个监督进程管多种核心、多种模式、一份 effect journal |
| `AndroidTProxyShell` | `4b6ddd8` | 模块化 shell：TPROXY/REDIRECT + owner + mark + ipset |
| `box4magisk` | `1aabf31` | Magisk 里跑 box 核心；inotify 近似 netlink |
| `box_for_magisk` | `a872449` | 另一份 box 封装；iptables 更激进 |
| `Flux-original` | `c978b75` | 本仓库前身：iptables TPROXY + 订阅转换 + 管理器开关 |
| `mihomo` | `f295ba6` | 用户态规则引擎；网关上 netfilter TCP redirect |
| `mihomo-ebpf-historical` | 历史摘录 | 后来移除的 TC redirect-to-TUN |
| `tun2socks` | `d24a734` | TUN + gVisor 用户态栈 + 上游代理 |
| `hev-socks5-tunnel` | `0428c4e` | 轻量 TUN→SOCKS5（自研协程栈，不是 gVisor） |
| `aosp-netd` / `Connectivity` / `DnsResolver` | 清单固定 commit | 平台先占的对象：fwmark、clsact、`fchown` |
| `Vector` | `5e4dcb9` | 特权守护拥有真相；畸形第三方输入不得让整模块消失 |
| `NeoZygisk` | `ec29fb1` | 单线程 epoll 监视器；注入痕迹可拆干净 |
| `Re-Kernel` | `e67cd94` | 冻住之后的内核传感器；LKM / eBPF / 刷内核三代接入 |
| `sing-box-official-1.13.19` | `b5ebaa1` | 未修改 TPROXY inbound 合同 |
| `gki/` | 四个 defconfig | GKI 上 `.ko` / BPF / TPROXY 是否存在 |

清单里写「不必在 mihomo / tun2socks / hev 上花时间」指的是**不要去它们的用户态栈里找 eBPF 数据面**。作为反例，它们仍然规定了 Flux 拒绝 TUN 的理由。

## 1 一张图：这些项目在回答哪一类问题

**源码事实：分流产品不是一种技术，是四种交付哲学。** 它们对「包还在不在原来的 skb 里」「身份读哪一层 sock 字段」「失败时对象还在不在」给出了互斥答案。

| 族 | 产品句子 | 代表 | 身份 | 交付 | 失败后内核对象 |
|---|---|---|---|---|---|
| A. 分类后把原包交给透明 listener | 这包属不属于要代理的主体；属则 `sk_assign` / TPROXY，地址不改 | Flux、dae/honk 的 WAN 路径、chizi 的 TC `socket_assign` | Flux：`sk_uid`；dae：cgroup cookie→pid | 原 skb | BPF 随 fd；TC filter 不随 fd |
| B. 改写 connect 目的，用户态再转发 | 把 socket 骗到本地 token/端口，再自己当栈 | bpf2socks、chizi cgroup 路径 | cgroup 上的 current uid/tgid | 新字节流 | pin 的 map/prog 不随进程 |
| C. netfilter 打标 + 策略路由 + TPROXY 目标 | 用 iptables 模拟透明代理 | AndroidTProxyShell、box 系、Flux-original、asteriskd `tproxy` 模式 | `xt_owner` 的 `f_cred` | 原 skb，经 `lo` 重入 | iptables/ip rule **不随 fd** |
| D. 全流量进 TUN，用户态协议栈终止 | 设备是一台虚拟网关 | mihomo TUN、tun2socks、hev、asteriskd `tun*` | 通常不再有 per-app UID（除非再套规则） | 拷贝进用户态 | TUN 设备、路由 |

AOSP 不是第五族。它是另外三族必须绕开或租用的房东：netd 的 `ip rule` 从 10000 起跳（`aosp-netd/server/RouteController.h:34`），物理口 `clsact` 由 netd 增删（`RouteController.cpp:1201-1223`，启动时清所有口：`NetworkController.cpp:152-164`），明文 DNS 的归属靠 `fchown` 写进 `sk_uid` 而不是 `f_cred`（`aosp-DnsResolver/tests/resolv_test_utils.h:48-49`）。

Re-Kernel 也不是第五族分流。它回答的是「冻住的目标此刻被谁碰了」。把它放进对照，是因为它把 **`.ko` 当作能力阶梯** 而不是当作代理实现。

PHIL-8 在这里的用法：shell 项目的 inotify 是「不会 netlink 时的近似」；dae 的 cgroup cookie 是「Linux 路由器上能占 cgroup 时的身份」；box 的 `settings put private_dns_mode off` 是「`xt_owner` 看不见 `fchown` 之后的妥协」。原则留下，工作区路径丢掉。

## 2 技术目录：每项展开与权衡

每一小节的第一句是结论。对 Flux 的状态用四个词：**现行**、**已延期**、**已拒绝**、**可重开（须改合同）**。可重开不是建议做，是「若要扩展边界，讨论应从这里开始」。

### 2.1 `xt_owner`（`f_cred`）对 `bpf_get_socket_uid`（`sk_uid`）

**结论：Android 上 per-app DNS 的分叉点是 sock 的哪一个 UID 字段，不是「会不会写 iptables」。**

`xt_owner` 读打开该 socket 的进程凭证。netd 对明文 DNS 做 `fchown(sock, requesting_uid, -1)` 之后，inode 与 `sk_uid` 变成 app，`f_cred` 仍是 netd。AOSP 自己的测试把这句话写死了（`resolv_test_utils.h:48-49`）。

| | 买到 | 付出 |
|---|---|---|
| `xt_owner` | 不需要 BPF；GKI 四个分支都有 `CONFIG_NETFILTER_XT_MATCH_OWNER` | 系统代发的 DNS 永远是错的 UID；于是几乎所有 C 族项目再加全机 `:53` 劫持 |
| `bpf_get_socket_uid` | 看见 `fchown` 后的归属；D18 的整条链 | 需要 TC/cgroup 等能拿到 `skb->sk` 的挂钩；`skb->sk == NULL` 时退回 overflowuid |

Re-Kernel 内部并不统一：LKM netfilter 走 inode `i_uid`，eBPF 走 `sk->sk_uid`。这是反例：**能读到一个 uid 和「这是哪一种 uid」是两件事。** Flux 合同钉死后者（§1.3.1）。

**Flux：现行。** 重开 `xt_owner` 等于放弃 per-app DNS，并被迫关 Private DNS。那是退回 C 族。

### 2.2 全机 `:53` 劫持与关掉 Private DNS

**结论：这不是功能，是 C 族在 2.1 上的补偿；补偿会制造反向错配。**

box4magisk 把当前 `private_dns_mode` 写入文件再 `settings put global private_dns_mode off`（`box/scripts/box.service:50-58`）。chizi 在 cgroup 路径上 `dns_mode: hijack` 时对端口 53 **跳过 UID 判定**（复核见 `history/review-log.md` §0.5.3）。box_for_magisk 的 `:53` 规则排在 app uid 块之前，并无条件丢掉 IPv6 DNS。

买到：DoT 被关掉之后，明文 DNS 终于能进核心。付出：未选中 app 的 DNS 也被代理；用户的加密 DNS 偏好被模块改写；崩溃后要靠自己写过的文件恢复——PHIL-4/PHIL-5 都不喜欢这份小本本。

**Flux：已拒绝**（§1.3.3、§19）。D18 之后这条补偿没有存在理由。

### 2.3 iptables TPROXY + fwmark + `ip rule` + `local default dev lo`

**结论：这是 Android 上验证最多的透明代理，也是对象生命周期最差的透明代理。**

AndroidTProxyShell 的生产形态（`tproxy.sh:1401-1418`）：`fwmark → table → local 0.0.0.0/0 dev lo`。包从 OUTPUT 打标，策略路由送进 `lo`，再从 PREROUTING 的 TPROXY 进 listener。它从不写 `rp_filter`，因为 `lo` 命中 `__fib_validate_source()` 的 loopback 早退。Flux 的包从 `flxrs1` 进，走不到这条早退，所以才有 §8.4。

链的顺序是机制先于政策（`tproxy.sh:980-1012`）：conntrack REPLY 放行（保住 netd 的 mark、过 strict RPF）→ 核心自身 bypass → 用户 bypass/名单。核心 bypass 配不上时只打一行 `"Core traffic bypass not configured, may cause traffic loop"` 然后继续——PHIL-6 的反例：无声环路不可诊断，应当拒绝。

`save_runtime_config()` 把本次用过的 mark/table 写进 `runtime_tproxy.conf`（`:250-277`），stop 时读它。快照丢失就按**当前**配置删规则。这是 PHIL-5 点名的书本所有权。

买到：任意 TPROXY 核心都能用；不依赖 BPF verifier；热点/USB 共用同一套 mark。付出：占用 Android packed fwmark；对象不随 `SIGKILL` 消失；`xt_owner` 的 DNS 盲区；OEM `filter` 链可能直接丢掉这条路径（box4magisk 因此 flush OnePlus `fw_*`，`box.service:72-79`，Flux 拒绝）。

**Flux：已拒绝作为数据面**（§19）。`local default dev lo` 这条**交付技巧**被 Flux 用在自有 `flxrs1` 的 table 20260 上，那是租用技巧，不是租用整张表。

### 2.4 `xt_bpf` matcher（bpfmatcher）

**结论：把 UID/CIDR 判定塞进 iptables 能看见的 BPF，所有权却可以按 pin 路径精确拆掉。**

`--stop` 只 unlink 策略里的四条路径（`bpf-matcher.c:628-637`，README:61）。这是 PHIL-5 的好例子：删除集合是合同里的四个名字，不是「看起来像我们的 prog」。

它仍然寄生在 C 族上：没有 iptables TPROXY/REDIRECT，matcher 只是更准的 `-m bpf`。不能单独拯救 `f_cred`。

**Flux：不采用。** 可学的是 stop 的精确集合，不是 xt_bpf。

### 2.5 cgroup `SOCK_ADDR` 改写目的 / token 地址

**结论：它能看见 netd 的 socket，也能用 TGID 排除自身；它付不起的是原目的与槽位所有权。**

UDP 的 `IP_RECVORIGDSTADDR` 在 `recvmsg` **之后**从 skb 头生成。cgroup 钩子改的是交还用户态的 sockaddr，不是包头。所以「不改引擎、又保留真目的」在这条路上是伪证明（§19）。chizi 因此必须改 sing-box：listener 用 token 反查原目的。bpf2socks 把目的改写成 `127.128.0.0/9` / `fd7a:7374:6572:6973::/64` 的 token（README:73-74、124-125），再在用户态恢复。

槽位：Android 可在 root cgroup 动态 `flags=0` attach。chizi 的 `attachProgramRaw` 失败后回落到 `flags=0`，会盖掉 netd 的 connect/sendmsg/recvmsg，清理却只 detach `sb_ebpf_` 前缀（§0.5.2）。这不是疏忽，是「占住才能工作」的产品选择。

自排除：cgroup 有进程上下文，`bpf_get_current_pid_tgid()` 可用；TC egress 跑在 softirq，不可用。所以 C 族/B 族用 uid/gid/tgid 排除核心，Flux 用「引擎 uid 0 永不进 `uid_policy`」。

**Flux：已拒绝**（§1.3、§19）。不是因为 eBPF 不好，是因为官方未修改二进制 + 不抢 netd 槽位这两条同时成立时，这条路不存在。

### 2.6 用户态 packet pump（bpf2socks bridge）

**结论：把「透明」从内核挪到用户态，换来 SOCKS5 通用性，付两次拷贝、一个自研栈、以及与 `bpf_sk_assign` 互斥的 `SO_REUSEPORT`。**

`bridge_tcp.c` + `bridge_udp.c` 合计四千余行。bridge socket 设 `SO_REUSEPORT`（`bridge.c:95/125/152/189`）。5.15 的 `bpf_sk_assign` 对 reuseport socket 返回 `-ESOCKTNOSUPPORT`。全树没有 `bpf_sk_assign` / `bpf_redirect`——它选择了另一条分岔。

自排除用 GID（`connect_prog.c` 的 `self_bypass_gid`），因为挂钩点有 current。DNS 有单独的 transaction tracking。这是完整的用户态 L4 网关，不是「一小段 glue」。

**Flux：已拒绝**（§19）。官方 sing-box 已经是终止代理；再插一个 pump 是第二个栈。

### 2.7 TC clsact + `bpf_redirect` + 同 netns veth + `bpf_sk_assign`

**结论：这是目前唯一同时满足「原包头到达官方 TPROXY」「不 attach cgroup」「不占 fwmark」的交付。它的税是每条捕获流一次完整 `dev_queue_xmit` + NAPI，外加 `rp_filter`/`accept_local` 门。**

dae 的 WAN：egress `bpf_redirect(dae0)`，peer ingress `bpf_sk_assign`，注释写明不能改目的（`tproxy.c:2456`），egress 不能 `redirect_peer`（`:1520-1522`）。established TCP 不 assign，交给内核按 tuple 查（与 Flux §7.5 同构）。`bpf_skb_change_type(PACKET_HOST)` 是 D17 的先例。

Flux 比 dae 少一整截：engine 与 app 同 netns，回程是普通本机路由，不需要 `redirect_track`、不需要跨 netns 的 MAC 恢复。dae 把 listener 放进 `daens` 是为了在 Linux 路由器上躲开主机 netfilter；手机上那笔税没有对应收益。

未选中流量必须在 **egress 第一次** 用 `TC_ACT_UNSPEC` 离开。把策略收进 ingress、egress 无条件 redirect，技术上可行（`skb->sk` 活到 peer），但要把未选中流量也送去再送回——放弃 §14.1 的地板。已评估拒绝（§19）。

`TC_ACT_OK` 在 Linux 路由器上无害；在 Android 上会截断 AOSP CLAT 与 OEM filter。dae 仍大量 `TC_ACT_OK`。chizi 为此把继续值写成 `TC_ACT_UNSPEC`，并注明 TCX 上 `TC_ACT_PIPE` 同样截断（`shared_network.bpf.c:22-25`）。

**Flux：现行。** 第 4 节问的是能不能在**不放弃这三条满足条件**的前提下换掉 veth 这一跳。

### 2.8 `bpf_redirect_peer`

**结论：对本拓扑结构上不存在，不是延期优化。**

内核要求 TC ingress **且** 目标设备在不同 netns。Flux 是 egress + 同 netns。dae 自己也写了 egress 不支持；另外因 CVE-2025-37959 gate 在 ≥6.8。

**Flux：已拒绝，且不是选择问题**（§19、§22.3）。

### 2.9 独立 netns（`daens`）/ netkit

**结论：跨 netns 能躲开主机栈，但强制第二次 redirect，且 GKI 没有 netkit。**

四个 GKI defconfig 均无 `CONFIG_NETKIT`（当日 `rg` 零命中）。同 netns 时 `skb_scrub_packet` **不清** `skb->mark`（`xnet==false`）；dae 需要 netkit `scrub=NONE` 是因为它跨 netns。Flux 不用 mark 传信息，理由是不需要 + 不占 fwmark，不是「传不过去」（§0.5.8 更正）。

**Flux：刻意同 netns。** 重开独立 netns 会把已经删掉的 return leg 请回来。

### 2.10 TCX（`BPF_LINK_CREATE` + `BPF_F_BEFORE`）

**结论：这是现行合同里唯一已经写好 seam、且能消灭两整类失败的扩展。**

clsact 挂在 qdisc 上，netd 删 qdisc 就删 filter；pref 最小是 1，被 OEM 占了无法插到前面。TCX 是独立 attach 点，相对定位可以排到 legacy clsact 之前。chizi 是语料里唯一用了 TCX 的，但它的 `AttachTCX` **不带 anchor**，等于放弃相对定位。

不能替代 5.15：本机 Android 16 跑 5.15（§16.3.5）。所以 clsact 仍是主路径，TCX 是探测后的优选，探测方式是尝试 `BPF_LINK_CREATE` 成功与否，不是 `uname`。

**Flux：已延期，优先级最高**（§22.2.1）。扩展边界应从这里开始，而不是从 `.ko` 开始——它不改产品句子，不引入第二后端身份。

### 2.11 SOCKMAP / `sk_msg` / `pidfd_getfd`

**结论：零拷贝 splice 要引擎把自己的 socket 放进 map；未修改的官方二进制没有这个 ABI。**

chizi 的 `socket_assign` 路径用 SOCKMAP 把新流交给 listener，失败则回落到改写目的。即便 Flux 去用 SOCKMAP，官方 sing-box 也不会登记自己的 fd。加密出站本来就不能 splice；能 splice 的 direct 已被 CIDR bypass 挡在内核里。

**Flux：已拒绝**（§1.6.5、§19）。

### 2.12 XDP / AF_XDP

**结论：太早，看不见 socket，没有 UID。**

XDP 在协议栈之前、ingress-only。honk 的 TODO 仍列 AF_XDP。对 per-app 手机模块没有身份。

**Flux：不适用**（§1.6.5）。

### 2.13 `BPF_PROG_TYPE_SOCK_OPS` 与任何 cgroup attach

**结论：能力存在，槽位不属于我们。**

GKI 全系 `CONFIG_CGROUP_BPF=y`。那是给 Android 用的。子 cgroup `SETSOCKOPT`/`POST_BIND` 会被祖先 `flags=0` 挡住（§19）。

**Flux：已拒绝。** 与「eBPF 好不好」无关。

### 2.14 TUN + 用户态协议栈

**结论：最强的覆盖（所有包、所有协议、可做网关），最贵的热路径（每包拷贝 + 用户态 TCP）。**

tun2socks 明确用 gVisor。hev 用自研协程栈，主打低内存/低 CPU 的 TUN→SOCKS5。mihomo 是规则引擎，TUN 只是它的一种入口。asteriskd 把 `tun` / `tun2socks` / `hev-socks5-tunnel` 列成可切换模式（README:87-93）。

买到：不依赖 `skb->sk`、不依赖 TC pref、可做热点下游。付出：未选中流量也无法保持「1 helper + 1 hash miss」；手机上等于常开 VPN；和系统 VpnService 争路由。

**Flux：已拒绝**（§1.3、§19）。PHIL-0 的「不创建 VPN」不是口号，是这条税。

### 2.15 多后端 / 运行时选模式（asteriskd）

**结论：这是「扩展边界」最容易滑进去的形状，也是 §19 拒绝双实现的现场标本。**

asteriskd 一个监督进程，可跑 xray/sing-box/mihomo，模式包括 tproxy、tun、tun2socks、bpf2socks、ebpf。matcher 是 tproxy/tun 上的必选 overlay，失败 abort，不静默降级（README:101-105）。生命周期却很干净：不 daemonize，子进程失败 fail-stop，先撤流量入口再反向清 effect journal；状态文件只做遥测，启动从不靠它决定删什么（README:8-12、108-128）。抽象 Unix socket `@asteriskd.control` 是单实例权威。

学：effect journal、fail-stop 顺序、状态文件不是所有权、精确目录清单、netlink 1500 ms trailing debounce。不学：把 seam 失败变成用户可选的五种数据面。

**Flux：已拒绝多后端。** 下面第 4.3 节区分「用户可见的 mode」和「探测后的 attach 优选」——后者 TCX 已经开了先例。

### 2.16 LPM trie / ipset / 有界 goto 树

**结论：CIDR bypass 的价值是避免已知无用的用户态往返，不是把 sing-box 的规则搬进 Flux。**

C 族用 ipset 或 Flux-original 的 Bounded Goto Skeleton（README:18-19）在 iptables 里走完大表。eBPF 的 `LPM_TRIE` 已经在程序里，一次 helper。6.6.0–6.6.46 的 LPM UBSAN 崩溃迫使本机地址改 HASH，并在该版本窗口拒绝激活（§1.6.3a）。

**Flux：现行。** 语义边界仍是「只按目的 IP、先于引擎、最终」。

### 2.17 `SK_STORAGE` 对 LRU flow map 对 conntrack

**结论：TCP 一次准入后的粘性，用每 socket 存储比用会驱逐的 LRU 安全。**

TCP cookie LRU 满了会踢掉仍活着的流，已入场连接可能中途 Direct（§19）。conntrack 是 C 族 PERFORMANCE_MODE 的快路径，被 `SK_STORAGE` 结构上取代（§1.6.5）。UDP 无连接，仍是每包判定。

**Flux：现行。** 取消勾选不拆已有 TCP，是这条粘性的用户可见面。要拆，见 2.22 / 2.23，不必先上 `.ko`。

### 2.18 honk NFQUEUE：暂扣「还没想好」的 LAN UDP

**结论：这是路由器产品在 eBPF 复杂度上限上的逃逸舱，不是手机 per-app 的需求。**

只对 **LAN 转发的、路由结果仍可能被用户态改写的** 首包 UDP 暂扣；主机 WAN 出站仍走 TPROXY；`:53`、`must`、`block` 从不进队列（`honk/doc/en/design/nfqueue.md:17-27`）。队列 `320`、nftables `inet honk_nfqueue` 是它独占的对象。

手机上 Flux 不转发 LAN，也没有「eBPF 里做域名/QUIC 再决定」的产品句子。把 NFQUEUE 搬来等于引入 nftables 对象 + 用户态 hold，和 PHIL-3/§14 的唤醒预算冲突。

**Flux：不适用。** 原则是「内核里做不完的决策不要假装做完」——Flux 的对应物是把域名留给 sing-box，CIDR bypass 只处理已确定无用的 IP。

### 2.19 可加载内核模块（`.ko`）与 vendor hook / kprobe

**结论：GKI 上的 `.ko` 不是完整内核；它买到的是「C 里能做、BPF helper 做不到的事」，主要是挂钩点与对象生命周期，不是更快的分类。**

GKI 事实（四个 `gki_defconfig`）：

| 项 | 12-5.10 | 13-5.15 | 14-6.1 | 15-6.6 |
|---|---|---|---|---|
| `CONFIG_MODULES` | y | y | y | y |
| `CONFIG_MODULE_SIG` / `SIG_PROTECT` | 无 SIG 行 | y / y | y / y | y / y |
| `CONFIG_MODULE_SIG_FORCE` | 无 | 无 | 无 | 无 |
| `CONFIG_BPF_SYSCALL` + `BPF_JIT_ALWAYS_ON` | y | y | y | y |
| `CONFIG_KPROBES` | y | y | y | y |
| `CONFIG_DEBUG_INFO_BTF` | 无（本份摘录） | y | y | y |
| `CONFIG_NETFILTER_XT_TARGET_TPROXY` | y | y | y | y |
| `CONFIG_NETKIT` | 无 | 无 | 无 | 无 |

推断（须标）：厂商内核可以关 `CONFIG_MODULES`、开 `MODULE_SIG_FORCE`、砍 BTF，GKI defconfig 不能代表装机内核。KernelSU LKM 跑在厂商内核上时，BPF 能力与模块能力是两条独立的骰子。

Re-Kernel 展示的能力阶梯：

| 代 | 附着 | 用户态信封 | 为什么存在 |
|---|---|---|---|
| ≤5.4 Integrate | 改 `binder.c` 编进 boot | raw netlink unit 22–26 | 不能 `insmod` |
| GKI LKM 11.7 | `android_vh_*` vendor hook + `NF_INET_LOCAL_IN` | genl family 名 `rekernel` | GKI 不许改 binder，但 vendor hook 是公开缝 |
| eBPF 10.0 | kprobe + ringbuf | `rekerneld` → `@rekernel` | 不装 `.ko`，绑 BTF |

Magisk 加载：`post-fs-data.sh` 写 `.boot` 哨兵，再次进入则 `touch disable`（`template/post-fs-data.sh:4-18`）。失败模式是开机循环，不是 status 里一行 Direct。README 仍写「内核模块无法被检测到」——与 PHIL-0 相反，也不真。

网络钩子纪律：LOCAL_IN 每包都进，hashmap 未命中立刻 `NF_ACCEPT`（`rekernel_netfilter.c:4-7` 文件头注释，`:35-43` 查找）。冻住谓词每次从 task/cgroup/jobctl 现读（`rekernel_internal.h:27-36`），不维护「我们冻过谁」。genl 命令只有增删监视 uid 和查版本；`REKERNEL_A_PID` 留了位，`destroySocket` 文档超前于代码（`rekernel.h:47-66`）。

对 Flux 若引入 `.ko`，能买到的与买不到的，见第 4.2 节。这里只钉技术事实：**vendor hook 是观测 Binder/信号的稳定缝；netfilter 钩子是每包都付的全局税；`insmod` 的失败域是开机。**

**Flux：合同未写「禁止 `.ko`」的字样，但产品身份是 eBPF-only（§19「保留 iptables 兜底」那一行把身份说死了），且 §1.3 禁止 nftables/iptables/TPROXY-mark 后端。引入 `.ko` 做 in-kernel TPROXY 须走 GOV-1.2。**

### 2.20 Generic Netlink 用名字，不用魔法编号

**结论：自己当 family 提供者时，名字是合同；unit 22–26 是债。**

Re-Kernel 从 raw netlink + `/proc/rekernel` + `REMOVE_PROC` 藏 proc，进化到 `CTRL_CMD_GETFAMILY` 解析 `rekernel` / `events`。Flux 的 nl80211 已经走名字。值得学的是边界，不是 ASCII `type=Binder,...;`——那种 ABI 适合每秒几十次通知，不适合每包。

**Flux：控制面现行（netlink）；数据面保持冻结二进制 ABI。**

### 2.21 事件驱动对轮询

**结论：独立项目把同一句话写进了注释，因为 shell 没有 netlink。**

box4magisk：`#Use inotifyd to monitor write events in the /data/misc/net directory ... cyclic polling is a bad solution`（`box4_service.sh:27`）。Flux-original 用 inotifyd 监视管理器自己的 `disable`（`flux_service.sh:50-57`），当场启停，没有 `action.sh`。NeoZygisk：单线程 event-driven，`epoll` + `signalfd`（`monitor.hpp:21-22`）。asteriskd：一个 reactor 收信号、pidfd、route-netlink、debounce。

原则：订阅，不轮询。工作区：`/data/misc/net` 是近似；Flux 已经有 rtnetlink。

**Flux：现行（PHIL-3）。**

### 2.22 `inet_diag` 与 `SOCK_DESTROY`（不必 `.ko`）

**结论：拆掉某 UID 的活连接是控制面能力，Linux 已经通过 netlink 提供；Re-Kernel 文档里的 `destroySocket` 并不是唯一入口。**

Flux 已经用 `NETLINK_SOCK_DIAG` 做 listener 就绪核验（§9.5），并且禁止把它变成周期健康检查。`SOCK_DESTROY` 是同族命令：对匹配的 socket 发销毁，应用看到连接复位后会重连。推断：取消勾选时按 uid dump 再 destroy，能补上 2.17 的用户可见缺口，而不把数据面换成 `.ko`。

代价：要证明只拆选中 uid、不拆引擎、不拆系统 socket；dump 不完整（`NLM_F_DUMP_INTR`）必须当失败；UDP 无连接，收益主要在 TCP。这仍是推断，没有本仓库实测。

**Flux：未写入合同。可重开，且比 `.ko` 便宜一个数量级。**

### 2.23 自研 `.ko` 做 in-kernel TPROXY / 注册 kfunc

**结论：这是 2.7 的替代交付，不是 2.7 的加速器。分类不会更快；未选中路径若变成全局 nf_hook，地板可能上升。**

能做的：

1. 在 `NF_INET_LOCAL_OUT`（或更早仍握着 `struct sock` 的点）按 uid 拿走 skb，填 TPROXY orig-dst，交给已 `IP_TRANSPARENT` 的官方 inbound。删掉 `flxrs0/1`、L2/L3 分叉、`rp_filter` 门、物理口 TC pref 冲突。
2. 没有 `skb->sk` 的 TC egress 漏包，在 `sendmsg` 时尚握着 sock。
3. 模块里直接 `sock_destroy`（仍可用 2.22 代替）。
4. 向 BPF 暴露 kfunc：数据面仍是 verifier 程序，只把「helper 没有的那一两个动作」放进模块。这比把整个分类器写成 C 更接近现在的形状。

不能做的：给未修改 sing-box 加协议；SOCKMAP；让未选中流量比现在的 JIT 路径更便宜。

必须一起付的：KMI 矩阵（一份 `.ko` 对一个 `androidN-x.y`）；`post-fs-data` 变砖面；`fluxd` 死后模块仍按旧表偷包（无声劫持，PHIL-6 最贵的那种）——必须做成「没有用户态心跳就 `NF_ACCEPT`」，而心跳本身又像轮询；装不了模块的设备仍要 2.7，产品变成双后端，正是 2.15。

性能与能耗（推断，路径计数，不是焦耳）：捕获路径少一次 veth xmit/NAPI 和第二次 conntrack，高吞吐时 CPU 可感；无线电和 sing-box 加密仍是选中流量的耗电大头；未选中若改全局钩子，待机基数可能变差。§14.3 禁止把未测百分比写进合同。

**Flux：可重开（须 GOV-1.2）。** 若重开，优先讨论「kfunc 小模块 + 现有 BPF」和「探测成功才切换、失败保持 2.7」，不要讨论「用户选 lkm 或 bpf」。

### 2.24 OEM 防火墙、全局 sysctl、flush 别人的链

**结论：能让某一台机器「工作」的操作，常常是把房东的对象当成自己的。**

box4magisk flush `fw_*`。dae 写 `all.rp_filter=0`。两者在真机上可能是对的。Flux 的选择是：冲突则该口或整机 Direct，并报告。崩溃后无法证明该恢复成什么值。

**Flux：已拒绝**（§15.4(1)、§19）。`.ko` 若把钩子挂在 iptables 够不到的优先级，是同一问题的内核版：更可能「工作」，更难证明没把系统防火墙旁路成无声漏洞。

### 2.25 Magisk 模块信封：开关、脚本、监督

**结论：开关只有一个家；脚本只安装；运行时在二进制。**

Vector：`service.sh` 极短，daemon 拥有真相（`manager/README.md:54-55`）。畸形 `module.prop` 不得让整个 APK 不可加载（`FileSystem.kt:255-257`）——那是第三方输入，PHIL-2 的另一面。NeoZygisk：最小实现、痕迹可拆。Flux-original：监视管理器自己的 `disable`。asteriskd：监督进程不重启失败的子进程，先撤入口。Re-Kernel：`.boot` 防循环。

**Flux：现行（PHIL-4、PHIL-7、C9）。** 从 asteriskd 可继续挖的是 fail-stop 顺序与 effect 的反向撤销，不是多模式。

### 2.26 官方 sing-box TPROXY 合同

**结论：官方二进制已经是合格的透明 inbound；Flux 的工作是把原包送进去。**

`IP_TRANSPARENT` / `RECVORIGDSTADDR`、全树无 `SO_REUSEPORT`、UDP 回写 bind 原目的——§0.5.1 逐行核对。UDP bind 原目的迫使 D7 本机地址 bypass。禁止对注入 inbound 设 `bind_interface` / `routing_mark`。

打补丁路线（chizi、D19）能做 cgroup 自排除、SOCKMAP、自己管 TC。付出是永久 fork 引擎、跟随上游 ABI、以及「官方发布」四个字不再成立。

**Flux：现行未修改引擎（C7/D19）。** 扩展边界若要求改 sing-box，直接结束讨论。

## 3 各项目笔记

每条只记哲学句子、技术选型、对 Flux 的态度。展开在第 2 节。

### 3.1 dae / honk

**哲学：尽可能早分流；确定直连的流量不要进用户态。** 文档承认域名靠劫持 DNS 关联，有误判；eBPF 不能做真正的嗅探循环，于是用户态补 sniff，`dial_mode: domain` 让代理重解析（`docs/en/how-it-works.md:19-30`）。**该文档关于 WAN 改写目的、关 checksum 的说法与 `caa6f5e` 的 C 矛盾，引用只引 `control/kern/*.c`。**

honk 的产品句子是「dae 数据面 + sing-box 风格出站」，并额外用 NFQUEUE 处理 LAN UDP 的不确定一跳。Score 组策略只在进程内存学习，导出的 `/stats` 不含目标键——控制面可观测性的克制。

对 Flux：学 TC→veth→assign、fail-closed、`change_type`；不学 cgroup 进程名、独立 netns、`TC_ACT_OK`、写全局 `rp_filter`、NFQUEUE。

### 3.2 chizi sing-box eBPF

**哲学：引擎拥有数据面。** 一份进程既是代理又是 BPF 加载器，所以可以用 TGID 排除自己，可以用 SOCKMAP 登记自己的 listener。这是 D19 反面的完整形态。TC/TCX 共享路径给下游接口做源/MAC 策略，是热点产品，不是 per-app 手机产品。

对 Flux：学 `TC_ACT_UNSPEC` 在 TCX 上仍是唯一继续值、LPM 崩溃窗口、本机地址用 HASH；不学抢 cgroup、hijack DNS、无 anchor 的 TCX、改引擎。

### 3.3 bpf2socks / bpfmatcher / asteriskd

**哲学（asteriskd）：一个监督者拥有全部副作用；核心只是子进程；模式可以换，目录清单不能换。** bpf2socks 是 B 族的极致工程（手写 BPF 汇编器、token、full-cone UDP）。bpfmatcher 是 C 族的精确 pin。

对 Flux：加载器加固清单已进 §12.7；所有权五元组已进 §8.5；debounce 已进 §10.4.1。其余（token、pump、shell out `tc`、SELinux 广补、多模式）明确不搬。

### 3.4 AndroidTProxyShell / box4magisk / box_for_magisk / Flux-original

**哲学：机制链先于政策链；核心流量必须先活着；用户名单只是后面一截。** 四份材料在 PHIL-1 上独立一致。DNS 与 Private DNS、OnePlus flush、GID 近似 PID，是工作区。Flux-original 另有订阅转换与「管理器 disable 即真相」，这两件已经进 0.9.5。

SRI / Bounded Goto 是 iptables 时代对大 CIDR 的认真工程；eBPF LPM 结构上取代它，不要把 AWK 搬回来。

### 3.5 mihomo / tun2socks / hev / mihomo-ebpf-historical

**哲学：用户态是规则的家；内核只提供入口。** 历史 eBPF 组件是 TC redirect 进 TUN，不是 `sk_assign`。移除本身说明：在已经拥有 TUN 栈的产品里，eBPF 只是加速进 TUN，不是身份方案。

对 Flux：反证 TUN 族与「eBPF 重定向到 TUN」都不是 per-app 透明代理。

### 3.6 AOSP netd / Connectivity / DnsResolver

**哲学：设备上的网络对象有一个先到的主人。** clsact、fwmark、UID 路由、CLAT 的 `v4-*` tun 都不是空地。DnsResolver 用 `fchown` 把「替谁问」写进 socket，却不把同一信息写进 `xt_owner` 能读的字段——这不是给 root 模块的 API，是给流量统计和 VPN 的。Flux 借到了 `sk_uid`，没有借到 cgroup 槽位。

### 3.7 Vector / NeoZygisk

**哲学：特权与 UI 分开；守护拥有真相；第三方输入防御性解析；监视器只靠事件。** 隐身/DenyList 是它们的产品，不是 Flux 的。可迁的是「写和读争的时候，读来自异步缓存」这条诊断，以及「脚本不决定运行时」。

### 3.8 Re-Kernel

**哲学：冻住的进程无法自报；内核报事实，墓碑做政策；热路径只观测；跨锁只留身份再发现；ABI 用名字。** 异步 Binder 队列清理是「停掉消费者就要管它排不空的队列」。对 Flux 的类比是包的生命周期，不是去 hook Binder。

不迁：隐身、文档超前、`insmod` 当主交付、字符串数据面 ABI、LKM/eBPF UID 读法分裂。

### 3.9 官方 sing-box

见 2.26。它不是分流方案。它是 Flux 唯一允许的政策引擎。

## 4 对 Flux 哲学与技术边界的压力测试

### 4.1 哪些原则仍然是物理，哪些只是选择

| 条款 | 压力 | 判定 |
|---|---|---|
| PHIL-0 产品句子 | `.ko`、TCX、LAN、TUN 都想挤进来 | **句子仍对。** 可变的是交付，不是「变成路由器/规则引擎/墓碑」 |
| PHIL-1 机制/政策 | asteriskd 的 mode 把机制暴露成政策 | **仍对。** TCX/可能的 `.ko` 必须是探测，不能是用户开关 |
| PHIL-2 不可表示 | 双后端几乎无法做成不可表示 | **仍对。** 这是拒绝用户可见双后端的深层理由 |
| PHIL-3 订阅 | 模块心跳防无声劫持看起来像轮询 | **边界要写清。** 若 `.ko` 需要心跳，必须是「deadline 内未刷新则 NF_ACCEPT」的安全阀，并计入唤醒预算 |
| PHIL-4 单一真相 | Re-Kernel 文档/头文件/Java 三份 ABI | **仍对。** 新路径若存在，能力探测结果是派生，不是第二份政策 |
| PHIL-5 现证所有权 | `.ko` 与 iptables 一样不随 fd 消失 | **这是 `.ko` 的决定性代价。** 删模块必须能从内核认出自己的 hook，心跳失败必须自动变成旁路 |
| PHIL-6 无声才硬拒绝 | `insmod` 失败是开机循环 | **与现行 Direct 报告相反。** 除非加载移出 `post-fs-data`、失败只导致不用该路径 |
| PHIL-7 脚本只安装 | Re-Kernel 的 `insmod` 在 post-fs-data | **若做 `.ko`，加载应在 `fluxd` 里，脚本只负责把文件放到位** |
| PHIL-8 原则不是工作区 | 整份第 2 节 | **仍是阅读纪律** |

§14.1 的地板——未选中流量 1 helper + 1 hash miss——**不是哲学装饰，是产品能在手机上常开的原因。** 任何扩展若把未选中流量送进全局 C 钩子或 TUN，先在这里失败。

### 4.2 `.ko` 收益再陈述（并入 9e1a710f 会话）

只谈对产品句子有用的：

1. **架构：** 删 veth。这是唯一能改形状的收益。连带放松 `rp_filter`、物理口 TC 槽位、L2/L3 分叉。
2. **覆盖：** 无 `skb->sk` 的漏；OEM clsact 冲突机型；厂商砍了 JIT/BTF 但仍能 `insmod` 的内核（推断，且与「GKI 有 BPF」相反的那批机器）。
3. **行为：** 策略变更拆活连接（2.22 也能做）。
4. **性能/能耗：** 只减捕获路径那一跳 CPU；不是整机功耗卖点；未选中路径默认不省电。
5. **零收益：** 官方引擎能力、分类本身、Binder/墓碑。

会话里「基线下探 5.10」是覆盖面想像，与现行 C3（基线 5.15）冲突；即使有 `.ko` 也不自动改变「Admit by successful load」——5.10 仍要真机证明 sk_storage/assign 或证明不再需要它们。

### 4.3 「扩展边界」的合法形状

asteriskd 证明：用户可见的多模式会变成永久双实现。TCX 条款证明：Flux **已经接受**「同一批 BPF 程序，attach 层探测优选」。

因此，若扩展交付，合法形状只有一种：

> 机制探测到更短的手交路径则用；否则保持 2.7。用户看不见 mode。所有权谓词随 attach 种类切换。失败则整条候选作废，回到现行路径或 Direct，不得半套。

非法形状：`backend = bpf | lkm | iptables`、装不上 `.ko` 就「暂时 TPROXY」、文档写 eBPF-only 代码里却有第二条热路径却不共享 ABI 测试。

### 4.4 比 `.ko` 更便宜、仍能让产品更强的扩展（按价格排序）

推断优先级，供讨论，不是计划：

| 顺序 | 项 | 买到什么 | 相对价格 | 合同现状 |
|---|---|---|---|---|
| 1 | TCX + `BPF_F_BEFORE` | 消灭 netd 删 qdisc、OEM pref 遮挡 | 已有 seam，只动 attach | 已延期 §22.2.1 |
| 2 | `SOCK_DESTROY` 按 uid | 取消勾选立即离开代理 | 控制面，数据面不动 | 未写 |
| 3 | LAN/热点第三入口 | 下游设备按源 IP/MAC | 新入口，复用 veth+assign | 已延期 §22.2 |
| 4 | kfunc 小模块 | 给 BPF 一个 helper 做不到的动作，分类器仍是 C BPF | 中：KMI 矩阵但热路径仍 verifier | 未写，须 GOV-1.2 |
| 5 | `.ko` nf_hook TPROXY | 删 veth | 高：生命周期 + 双路径 + 变砖 | 未写，须 GOV-1.2 |
| 6 | `BPF_PROG_TYPE_NETFILTER`（6.4+） | 可能不用 `.ko` 挂 nf 钩子 | 中高：基线 5.15 仍要 2.7；需核实能否 `sk_assign` | 未写；**6.4 helper 能力未在本次逐行核对，标推断** |
| 7 | 改 sing-box / TUN / cgroup / iptables 后端 | 各种「更强」 | 改产品身份 | 已拒绝 |

第 6 项特别容易在讨论里被说成「有 BPF 就不用 `.ko`」。在未核对 5.15/6.1/6.6 的 `BPF_PROG_TYPE_NETFILTER` 是否存在、以及该上下文有没有 `bpf_sk_assign` 之前，不能把它写成比 `.ko` 更干净的替代。

### 4.5 什么叫「更优雅」

优雅不是挂钩更底层。clone 给出的优雅几乎都是**收窄**：

- dae：确定直连的包不要进用户态。
- Re-Kernel：内核不当墓碑。
- asteriskd：副作用有一份 journal，失败先撤入口。
- bpfmatcher：stop 只 unlink 四个名字。
- Vector：第三方畸形输入不能让整模块消失；自己产生的状态则不可表示非法。
- Flux 自己：未选中付地板税；捕获稳态 L2 零写包；引擎未修改。

若 `.ko` 让热路径变成「全机进 C、再哈希」，那是更强的挂钩、更丑的地板。若 `.ko`（或 kfunc）只在**已经判定捕获**之后缩短手交，分类器仍是现在这份 BPF，那才和现行优雅同向。

## 5 明确不从 clone 带走的

- 用户可见多数据面（asteriskd modes）。
- 抢 netd cgroup（chizi、bpf2socks）。
- flush OEM 链、关 Private DNS、写全局 `rp_filter`。
- 文档当愿望清单（Re-Kernel `destroySocket`、dae how-it-works 的 WAN 改写）。
- 「模块检测不到」当安全模型。
- 把字符串或 iptables 当数据面 ABI。
- 为对称而做的 UDP 用户态 hold、XDP、SOCKMAP。

## 6 本文不决定什么

不修改 `philosophy.md`、不修改蓝图、不把 `.ko` 或 `SOCK_DESTROY` 写进 §22。若所有者选定某一行重开，走 GOV-1.2，新条款进 `spec/`，理由进 `history/review-log.md`。

## 7 当日补录：并行源码对照补上的事实

正文写完后，对同一批 `clone/` 树又做了一轮逐项核对。下面只追加正文没钉死、或需要收窄措辞的条目，不改上面的结论。

### 7.1 `CONFIG_INET_DIAG_DESTROY=y` 在四个 GKI 分支都在

**源码事实：** `clone/gki/android12-5.10.config:144`、`android13-5.15.config:153`、`android14-6.1.config:161`、`android15-6.6.config:157` 均为 `CONFIG_INET_DIAG_DESTROY=y`。

这把第 2.22 节从「Linux 有这条 netlink 命令」收紧为：**GKI 文本承诺了销毁路径**。装机内核仍可能被厂商关掉，因此合同写法仍应是运行时探测，不能靠 `uname`。它不改变「比 `.ko` 便宜一个数量级」的排序，只是去掉了「内核里也许没有这条命令」的疑虑。

### 7.2 这四份 GKI 片段没有单独列出 `SK_STORAGE`

当日对 `CONFIG_BPF_SK_STORAGE` / `SK_STORAGE` 的 `rg` 在四个 `.config` 上零命中。这**不能**写成「GKI 没有 SK_STORAGE」：片段不是完整 `allmodconfig`，且 Flux 在 SM-S9180 / 5.15.211 上已加载带 `SK_STORAGE` 的程序（§16.8）。正确读法与 §1.1 一致：能力以一次真实 load/attach 为准，不把 defconfig 缺行当否定。

`CONFIG_NETKIT` 的零命中仍然有效——四个片段都没有，和 dae/honk 对 netkit 的依赖对照得上。

### 7.3 dae 文档的内核下限是 5.17，Flux 的基线是测过的 5.15

`clone/dae/docs/en/README.md` 把 LAN/WAN bind 写成 **≥5.17**（另要 BTF）。Flux 的 C3 是 5.15，且 Phase 0 已在 5.15.211 上验证 `sk_assign` / `skb_change_head`。这不是矛盾：dae 的下限绑的是它自己的 CO-RE + netkit 偏好；Flux 用手写 loader、不依赖 netkit。原则仍是 PHIL-8：不要把别人的版本门当自己的能力门。

### 7.4 fwmark 占用是 C 族和网关族的共同税，数值已经撞车

正文 2.3 / 2.24 说「不要占 Android packed fwmark」。补一组第一方常量，说明「找一个空位」不是办法——别人已经各自挑了看起来很空的值：

| 项目 | 标记 | 源 |
|---|---|---|
| dae | `TPROXY_MARK = 0x8000000` | `dae/control/kern/tproxy.c:70` |
| honk | 保留位 `0xc0000000`，另有 `DAE_BYPASS_MARK = 0x100` | `honk/honk-ebpf-common/src/lib.rs:28-61`、`:87-89` |
| chizi shared `socket_assign` | 默认 `routing_mark` `0x53420001` | `chizi-sing-box-ebpf-cilium/docs/configuration/inbound/ebpf.md`（与 `shared_network` 路径） |
| asteriskd | 主标记 `0x20000000`，掩码 `0x60000000` | `asteriskd/asteriskd.h:79-80` |
| mihomo iptables helper | 固定 `0x2d0` | `mihomo/listener/tproxy/tproxy_iptables.go:21-24` |
| box_for_magisk | `16777216`（即 `0x1000000`），table 2024，pref 100 | `box_for_magisk/box/scripts/box.iptables:11-13` |
| Flux-original | `MARK_MASK 0xff`，刻意躲开厂商 QoS 高位 | `Flux-original/conf/settings.ini:117-118` |

AOSP 的 fwmark 是 packed bitfield（`aosp-netd/include/Fwmark.h:24-48`）：16-bit netId、VPN/permission/billing/vendor。第三方「自选一个常数」无论避开 netd 的 ip rule 数字，都还可能撞 connmark 的 20-bit 截断或厂商 vendor 位。Flux 不用 mark 跨 hook 传信息，这条对照把它从偏好升级为**和这些常数共存时的必要形状**。

### 7.5 Flux-original 把厂商破坏做成 opt-in；box4 做成开机必做

box4magisk 的 `oneplus_a16_fix()` 在 start 路径上无条件 flush（`box/scripts/box.service:72-79`，调用点约 `:361`）。Flux-original 把 `VENDOR_FIX_PROFILE=oneplus` 做成保留配置，且 **oneplus 分支当时没有通用动作**（`scripts/tproxy:233-234`）。这是同一作者线上的一次收窄：破坏房东对象必须显式，不能当默认润滑剂。现行 Flux 比这更严——连 opt-in flush 也不做，冲突则 Direct。

### 7.6 mihomo 历史 eBPF 是 fail-open 的 TUN 加速器

`clone/mihomo-ebpf-historical/component__ebpf__bpf__tc.c`：缺 map / ARP / LAN / ICMP 时 `TC_ACT_OK`；用 skb mark 相等识别自身流量；没有 UID。它回答「怎么更快进自己的 TUN」，不回答「哪些 App」。这加固正文 3.5：从 mihomo 族学不到 per-app 身份，只能学到「eBPF 重定向到 TUN」与 Flux 的产品句子正交，以及 **fail-open 在不确定时放行**——与 dae/Flux 的 fail-closed 相反。

### 7.7 hev-socks5-tunnel 的栈是 lwIP + hev-task

正文 2.14 写成「自研协程栈」过粗。第一方是 TUN fd → lwIP → SOCKS5（`hev-socks5-tunnel/src/hev-socks5-tunnel.c`，README:5-13），文档要求操作者自己设 `rp_filter=0` 与 fwmark 回 main。嵌入形态提供 `tun_fd`（VpnService）。对 Flux 仍是 D 族反例；精确的技术名是 lwIP，不是 gVisor。

### 7.8 bpf2socks 的 token 吃掉环回地址空间

token 前缀 `127.128.0.0/9`（README:124-125）。TC 路径上若目的已在 `127.0.0.0/8` 则 `TC_ACT_SHOT`（`tc_redirect.bpf.c` 约 408 行一带）。这是 B 族用地址当 cookie 的税：环回不再是「本机服务的完整空间」。Flux 用 `sk_assign` 正是为了不付这笔税。

## 8 当日补录：交付路径在 SM-S9180 / 5.15.211-Qkernel 上的加深

设备：`SM-S9180`（`dm3q`），`5.15.211-Qkernel`，KernelSU，Flux 当时已在跑（`flxrs0/1` UP，`flx_cap_l2` 挂在 `wlan0` egress，`flx_cap_l3` 挂在 `rmnet_data1/8`，`flx_in` 挂在 `flxrs1` ingress）。本节只追加证据，不改第 4 节的产品结论，也不改合同。

### 8.1 `BPF_PROG_TYPE_NETFILTER` 在这台 5.15 上不是交付手段

**设备事实：** `bpftool feature` 报告 `program_type netfilter is available`，但该类型的 helper 表只有四条：`bpf_map_lookup_elem`、`bpf_map_update_elem`、`bpf_get_current_pid_tgid`、`bpf_get_current_uid_gid`。没有 `bpf_sk_assign`、没有 `bpf_redirect`、没有 `bpf_get_socket_uid`。`bpftool net` 的 `netfilter:` 段为空。

上游把 netfilter BPF 程序类型并进主线是 6.4 一带的事。这里能 load 类型名，只说明厂商枚举/验器表里有这个槽；**能挂上且只能 ACCEPT/DROP 加读 current cred，并不能把原包交给 TPROXY listener**。`bpf_get_current_uid_gid` 在 `LOCAL_OUT` 或许能看见进程，但 Flux 的身份合同是 `sk_uid`（§1.3.1 / 本文 2.1），而且没有偷包 helper。

因此第 4.4 表第 6 行从「未核对、标推断」收紧为：**在本测试机上，它不是比 `.ko` 更干净的替代，也不是 5.15 基线的交付候选。** 别的 6.x GKI 要另测 helper 表，不得用这份四行表外推。

### 8.2 veth 这一跳到底买的是什么：`skb_scrub`，不是「多一块网卡」

现行手交（`bpf/flux.bpf.c` 的 `handoff`）：`bpf_redirect(flxrs0_ifindex, 0)`。flags 0 走 TX：`__bpf_tx_skb` → `dev_queue_xmit(flxrs0)` → `veth_xmit` → `__dev_forward_skb(flxrs1)` → `skb_scrub_packet`（同 netns 不 orphan）→ `eth_type_trans` → `netif_rx` / 可选 NAPI。§8.2 的 `PACKET_OTHERHOST` 和 §8.4 的 martian/`rp_filter` 都发生在这条 scrub 之后的第二次 `ip_rcv`。

对照 5.15 源码（`torvalds/linux` tag `v5.15`，与本机 `5.15.211` 同主线）：

| 注入办法 | 实际内核路径 | 掉 `skb_dst`？ | 专用 `iif`？ | 对 Flux 的含义 |
|---|---|---|---|---|
| 现行：TX 到 `flxrs0` | `veth_xmit` → `____dev_forward_skb` | 是 | `flxrs1` | 已验证 |
| `bpf_redirect(flxrs1, BPF_F_INGRESS)` | `__bpf_rx_skb` → `dev_forward_skb_nomtu` → 同一个 `____dev_forward_skb` | **是** | `flxrs1` | **源码上等于跳过 `flxrs0` 的 `dev_queue_xmit`/`veth_xmit`，scrub 不丢** |
| `bpf_redirect(dummy, BPF_F_INGRESS)` | 同上 | 是 | dummy | 少一对 veth；见下 |
| TX 到 dummy | `dummy_xmit` 直接 `kfree_skb` | — | — | 黑洞，不能当回送 |
| TX 到 ifb | `netif_keep_dst`；无 `skb_iif` 则丢；tasklet 把包弹回原 `skb_iif` | **故意保留 dst** | 弹回原口 | **与 TPROXY 回送目标相反** |
| `tc mirred ingress redirect` | `nf_reset_ct` 后 `netif_receive_skb`，**不**走 `____dev_forward_skb` | **否** | 目标设备 | 不能当 `bpf_redirect INGRESS` 的实验替身 |
| TX/`INGRESS` 到 `lo` | `loopback_xmit` 的 `skb_dst_force`，或 `iif lo` 规则命中全部本机流量 | 见 §19 | 非法 | 已拒绝 |

`dummy` / `ifb` 在本机都是 `=y`，当场 `ip link add` + `clsact` 成功；dummy 接受 `mtu 65535`（`gso_max_size 65536`）。ifb 的 bounce + `keep_dst` 把它从候选里剔除。dummy 的 TX 是黑洞，所以 **dummy 只可能作为 `BPF_F_INGRESS` 的接收端**，不能替换现行的 flags-0 TX 目标。

veth 在 5.15 的库存设备里几乎是唯一「TX 就会 scrub 并注入 peer RX」的种类。这不是历史包袱，是 dummy/ifb/lo 都做不到的那一件事。真正能删掉的是 **TX 那一半**（`flxrs0`），不是 scrub 本身。

**生产先例：** dae 已经按方向选择 flags——`from_wan` 时 `BPF_F_INGRESS`，否则 0（`clone/dae/control/kern/tproxy.c:2975-2980`）。egress 方向同样不用 `bpf_redirect_peer`（同文件 `:1518-1522`），与 §19 一致。Flux 若改 `bpf_redirect(flxrs1, BPF_F_INGRESS)` 或改 dummy 接收端，形状仍是「同一批分类器，探测优选手交」，符合第 4.3 节的合法扩展，**但本开机没有改 Flux BPF 做通包证明**（当时数据面在服务真实流量）。源码等价 ≠ 已测。

代价要写清楚：INGRESS 注入走 `netif_rx`，不再走 `veth_xmit` 里那条可选 NAPI/GRO。捕获路径可能更快（少一次 xmit），也可能在大流量 GRO 上更差。未选中路径不变。`rp_filter` / `accept_local` / `change_type` **不会**因为跳过 `flxrs0` 而消失——第二次 `ip_rcv` 还在。只有 in-kernel TPROXY（下面 8.6）才删得掉这一次。

### 8.3 `SOCK_DESTROY`：内核有，`ss` 不能当实现

`CONFIG_INET_DIAG_DESTROY=y`（本机 `/proc/config.gz`，与 7.1 的四份 GKI 一致）。`ss` 是 `iproute2-ss171113`，帮助文本有 `-K`。对自建 `127.0.0.1:19991` 连接实测：过滤器要么 bison 报错，要么打印表头后 **Segmentation fault**，socket 仍停在 `CLOSE-WAIT` / `FIN-WAIT-2`。

结论：能力在内核 netlink 上，不在厂商 `ss` 上。Flux 已有只读的 `NETLINK_SOCK_DIAG`（`crates/fluxd/src/netlink/sock_diag.rs`，模块注释写明 *never mutates*）。若重开 2.22，实现必须是 fluxd 发 `SOCK_DESTROY`（type 21），禁止 `ss -K`。dump 不全则宁可漏拆，也不能误杀。本开机没有用自写 netlink 做通一次销毁（避免动正在代理的连接）。

### 8.4 物理口上已经有别人的 clsact

`bpftool net`：`wlan0` ingress/egress 各有一条 Samsung `prog_semUidBPF_schedcls_*_tsm_ether`，Flux 的 `flx_cap_l2` 与 OEM egress 程序 **共用同一个 clsact**。这是 TCX + `BPF_F_BEFORE` 仍被列为最便宜扩展的现场理由——但本机 5.15 没有 TCX，§22.2.1 继续搁置。

### 8.5 比 `.ko` 便宜的顺序（被 8.1–8.3 改写之后）

只把第 4.4 表里被今晚证据移动的格子写出来：

| 顺序 | 项 | 相对第 4.4 的变化 |
|---|---|---|
| 1 | TCX + `BPF_F_BEFORE` | 不变；本机仍不可用 |
| 2 | `SOCK_DESTROY` 按 uid（fluxd netlink） | 从「GKI 文本承诺」再加「厂商 ss 不能用」 |
| 3 | **`BPF_F_INGRESS` 注入 `flxrs1` 或 dummy** | **新：5.15 上唯一不改挂钩、可能缩短手交的路径**；须通包 + 对比 GRO |
| 4 | LAN/热点第三入口 | 不变；问题不同 |
| 5 | kfunc 小模块 | 见 8.6；比「换设备」贵，比「C 数据面 `.ko`」便宜 |
| 6 | `.ko` `nf_hook` TPROXY | 仍是唯一能删第二次 `ip_rcv` / `rp_filter` 的架构收益 |
| — | `BPF_PROG_TYPE_NETFILTER` | **本机降为死路** |

### 8.6 `.ko` 若要做，只该是分类之后的一个动作

Re-Kernel 的课还在：内核不当墓碑；对象必须在消费者消失后变成无害。全机 C 钩子里做 UID 哈希会破坏 §14.1 地板。

本机 `CONFIG_NF_TPROXY_IPV4/IPv6=y`、`CONFIG_MODULES=y`、`CONFIG_DEBUG_INFO_BTF_MODULES=y`。合法形状仍是第 4.3 节那句：分类器还是现在这份 C BPF；**只有已经判定捕获之后**才调用一个 kfunc，例如「`skb_dst_drop` + 绑到已核验的 listener + 本机投递」。失败则整条候选作废，回到 8.2 的 veth/`INGRESS`。用户看不见 mode。

这比「自己实现一份 nf_hook 分类器」便宜，因为热路径仍过 verifier。它仍然贵：GKI KMI、`nf_tproxy_get_sock_*` 未必是可链符号、fluxd 死后 kfunc 必须变成 no-op/`TC_ACT_UNSPEC`、post-fs-data `insmod` 仍有变砖面。没有 8.2 的通包数据和 8.3 的控制面之前，不值得付这笔税。

### 8.7 刻意没做的实验

- 没有改正在服务的 `flux.bpf.c` 去切 `BPF_F_INGRESS`。
- 没有用 `tc mirred` 冒充 BPF 注入（8.2：路径不同）。
- 没有对真实 app 连接发 `SOCK_DESTROY`。
- 没有 load 四 helper 的 netfilter 程序往 INPUT/OUTPUT 上挂。

下一步若做，应是隔离对象上的通包（自建 dummy/`flxrs*` 测试对，或一次可回滚的 probe-and-prefer），以及 fluxd 对自建 TCP 的 netlink `SOCK_DESTROY`。两者都不必先碰哲学合同。

