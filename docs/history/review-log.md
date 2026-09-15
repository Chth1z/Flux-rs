# 独立复核记录与更正对照

> 原 blueprint.md 第 0 部分。**章节编号未变**：本文里的 §N.x 就是全仓库引用的那个 §N.x（见 AUTH-1.1）。
>
> 谁读这份：有人质疑某条断言的依据时，来查它是源码、实测还是推理。本文是历史证据与更正记录，不单独创造当前产品要求；0.9.1 规范性合同是冻结的 `docs/spec/blueprint.md` 加 `docs/history/blueprint-0.9.1.md`。

---

# 第 0 部分：独立复核与本文的修正

## 0.1 我采纳前两版蓝图的什么

**采纳核心数据路径**：

> 受支持的 Android 物理 egress TC 按 socket UID + 目的 CIDR 做粗分流 → 命中 packet 经无地址专用 veth 回送 → veth peer TC ingress 用 `bpf_sk_assign()` 交给**官方未修改** sing-box 的 TProxy inbound。

这是硬约束下唯一可行的组合，理由不是"eBPF 越多越好"，而是三条互相咬合的事实：

1. **UDP 原目的无法用 cgroup SOCK_ADDR 恢复。** `IP_RECVORIGDSTADDR` 的 cmsg 由内核在 `udp*_recvmsg` 中**从 skb 的 IP 头**生成（`ip_cmsg_recv_offset` 读 `ip_hdr(skb)->daddr`），而 `BPF_CGROUP_UDP4_RECVMSG` hook 只能改写返回给用户态的 peer sockaddr。旧仓库的 token 方案因此对 UDP 是**伪证明**：map 自洽，engine 读到的 cmsg 仍是 token。任何"保留真实原目的且不改 engine"的方案都必须让**真实 IP/port header 抵达 TProxy listener**。
2. **cgroup SOCK_ADDR 槽位是一个"随时可能被占、且占用时机不可预测"的共享资源。**

   > **2026-08-25 实测更正。** 这一条我原先写的是"Android 15/16 已用 flags-0 **永久独占** root cgroup 的 SOCK_ADDR 槽位"，依据是归档的 `sm-s9180-sock-addr-occupancy-2026-08.md`。**在同一台设备上复测，该表述不成立**：`bpftool cgroup show` 对 `/sys/fs/cgroup`、`/sys/fs/cgroup/apps`、`/sys/fs/cgroup/system` 以及 `bpftool cgroup tree` 全树遍历，**返回的 attach 列表全部为空**；同时 `bpftool prog show` 显示 **8 个 `cgroup_sock_addr`、2 个 `cgroup_skb`、2 个 `cgroup_sockopt`、2 个 `cgroup_sock` 程序确实已加载**。参见 §16.2。
   >
   > 真实机制是：AOSP 的 bpfloader 在开机时**只 load + pin，不 attach**；attach 发生在对应功能被激活的时刻。所以槽位占用是**动态的**，不是常驻的。

   这**削弱**了"槽位被占死"的说法，但**不改变结论**，理由反而更强了一层：一个只在 netd 激活某功能时才出现的冲突，比常驻冲突**更难处理**——它意味着产品可能在安装时工作正常，几小时后因为系统启用了某个特性而**静默失效**，且失效时机不可预测、不可复现。`hierarchy_allows_attach()` 对 flags-0 祖先拒绝后代同类型 attach 这条内核规则依然成立，只是触发时刻不确定。

   可行的替代只剩"抢占 netd 槽位"（CHIZI/bpf2socks 的做法，会静默关掉 Android 自己的 connect hook）或"detach-promote-append"（无人实现，且 netd 重启即打架）。**产品不能建立在抢系统槽位、或建立在一个随时可能被系统收回的共享资源上。** 因此 0.9.0 **禁止任何 cgroup attach**。

   注意第 1 条**不依赖**本条。即使槽位永远空着，UDP 原目的仍然无法用 cgroup 方案恢复——那是内核机制问题，与占用无关。**第 1 条单独就足以否决 cgroup 路线。**
3. **TC + `bpf_sk_assign` 不改写 IP/port**，只把 socket 关联到 skb，由内核 local-route 交付。这正是官方 sing-box 能读到真实目的的机制根源。

**采纳失败语义框架**：admission-bounded fail-open。未入场的新 TCP 首 SYN / 当前 UDP datagram 在**可检测的 redirect 前**失败走 Direct；越过 admission boundary 后的内部失败只能 drop/reset，绝不中途 direct 泄漏。这是可实现且诚实的合同。

**采纳产品身份与范围收缩**：单一 `fluxd` + 官方零 patch sing-box；不做 nftables/TUN/SOCKMAP/多后端/远程订阅/WebUI/机型 catalog。

## 0.2 我独立核验的地基事实

| 断言 | 结论 | 依据 |
|---|---|---|
| `bpf_sk_assign()` 只在 TC ingress 合法，且在 6.5 之前**拒绝 `SO_REUSEPORT` socket**（`-ESOCKTNOSUPPORT`） | **已核验** | uapi 文档 + `net/core/filter.c`；SO_REUSEPORT 支持由 Lorenz Bauer 2023 系列（6.5）加入，**5.10/5.15 没有**。→ 注入的 inbound 必须不带 `SO_REUSEPORT`（见 §9.2）。 |
| `bpf_sk_storage_get/delete` 与 `bpf_sk_fullsock` 在 `BPF_PROG_TYPE_SCHED_CLS/ACT` 可用 | **已核验** | `tc_cls_act_func_proto` 与 ebpf-docs 的 SCHED_ACT/SCHED_CLS helper 列表。 |
| `skb->sk` 在 TC 是 `PTR_TO_SOCK_COMMON_OR_NULL`；`bpf_sk_fullsock()` 返回 `PTR_TO_SOCKET` 且**不取引用计数**；`bpf_sk_storage_get` 的 `arg2` 接受它 | **已核验** | Linux commit `46f8bc92758c`（引入 `__sk_buff->sk` + `bpf_sk_fullsock`，明示不 acquire reference）；`bpf_sk_storage_get_proto.arg2_type = ARG_PTR_TO_SOCKET`。 |
| `BPF_MAP_TYPE_SK_STORAGE` 创建**强制要求 BTF**（`btf_key_type_id`/`btf_value_type_id` 非零、`max_entries==0`、`BPF_F_NO_PREALLOC`、`key_size==sizeof(int)`） | **已核验** | `bpf_sk_storage_map_alloc_check()`。→ 决定了加载器必须提供 BTF（见 §12.3）。 |
| `CONFIG_VETH=y` 在 arm64 GKI `gki_defconfig`（android12-5.10 与 android13-5.15 均为 built-in） | **已核验** | `kernel/common` arm64 `gki_defconfig`。veth 不是可选模块，无需 `system_dlkm` 赌运气。 |
| sing-box listen 字段**确实**支持 `bind_interface`/`routing_mark`/`reuse_addr`（1.12.0 起） | **已核验**（推翻我最初的怀疑） | 官方 `configuration/shared/listen` 文档。→ sentinel 方案技术上可行，我出于简化而删除，不是因为不可行（§0.3 D2）。 |
| sing-box 1.13.0 **移除**了 inbound 上已弃用的 `sniff`/`sniff_override_destination`/`domain_strategy`/`udp_disable_domain_unmapping` | **已核验** | 同上文档的 deprecation 说明。→ 注入的 inbound **禁止**包含这些键。 |
| sing-box TProxy 的 UDP 回写会**新建一个 socket、以 `IP_TRANSPARENT` 绑定原目的地址**再发给客户端 | **已核验** | 官方 issue #3646 明确描述该行为并记录"原目的端口被本机其他进程占用 → `address already in use`"。→ 必须把**本机自有地址**纳入 bypass（§0.3 D7）。 |
| `cls_bpf` direct-action 返回 `TC_ACT_UNSPEC` 会**继续**同一 chain 的后续 classifier；`TC_ACT_OK` 会**终止** classifier chain | **已核验** | `cls_bpf_classify()` 对 `TC_ACT_UNSPEC` 执行 `continue`；`__tcf_classify()` 只在 `err >= 0` 时返回。→ egress"不接管"必须用 `TC_ACT_UNSPEC`，否则跳过 AOSP CLAT/OEM 后续程序。 |
| `cls_bpf` 在 **ingress** 会 `__skb_push(skb, skb->mac_len)` 后再运行程序 | **已核验** | `cls_bpf_classify()`。→ ingress 程序看得到完整以太头。 |
| `bpf_skb_change_head()` 的设计用途正是"L3 skb 补 MAC 头以便 redirect 进 L2 设备"，且**不需要重置 GSO** | **已核验** | 该 helper 源码注释原文。→ rmnet raw-IP / CLAT TUN 的处理方式被上游背书。 |
| `eth_type_trans()` 会按目的 MAC 重新判定 `pkt_type`；不等于设备 MAC 即 `PACKET_OTHERHOST`，而 `ip_rcv()` 直接丢弃 `PACKET_OTHERHOST` | **已核验** | `eth_type_trans()` / `ip_rcv_core()`。→ 必须处理 `pkt_type`；**D17 选择在 ingress 用 `bpf_skb_change_type(PACKET_HOST)` 修正，而不是在 egress 改写 MAC**（§8.2）。 |
| `IN_DEV_RPFILTER` 取 `max(all.rp_filter, dev.rp_filter)`，而 `IN_DEV_ACCEPT_LOCAL` 取 `or(all, dev)` | **已核验** | `include/linux/inetdevice.h` 的 `IN_DEV_MAXCONF` / `IN_DEV_ORCONF`。→ **只在 `flxrs1` 设 `rp_filter=0` 不够**；见 §8.4，这是前两版蓝图的实现级漏洞。 |

## 0.3 我对前两版蓝图的修正（D1–D23）

以下每条都是**本文与旧蓝图的实质差异**，实现者必须按本文执行。

### 0.3.0 D 条目状态登记

引用一条 D 之前先看这张表。**没有它，一条已被取代的决定和一条现行决定在文档里长得一模一样**——这正是 agent 会反复重新推导已经辩论完的问题的原因。`doc-check` 校验：每个定义过的 D 都在表里、状态取自固定词表、`superseded` 必须指出被谁取代。

状态词表：`current`（仍然生效）、`superseded`（已被取代，必须写明取代者）、`deferred`（决定推迟）、`executed`（一次性动作，已完成）。

| # | 状态 | 取代者 |
|---|---|---|
| D1–D6 | current | — |
| D7 | superseded | D20、D21（地址前缀方案作废；防自环结论保留） |
| D8 | current | — |
| D9 | superseded | §1.4（经 §0.6.5 第 30 条放宽：只拒绝 uid 0，平台 uid 显式写名字可选并告警；黑名单展开仍限 `[10000, 19999]`） |
| D10–D12 | current | — |
| D13 | executed | 清库重建已完成（C1），是一次性动作而非持续约束 |
| D14–D15 | current | — |
| D16 | superseded | D21（收窄为 listener 精确 /32 与 /128） |
| D17–D21 | current | — |
| D22 | superseded | §11.2（容量结论保留；`.srs` 输入方案未进入 schema） |
| D23 | current | — |

### 0.3.1 D1–D18：与旧蓝图的实质差异

| # | 旧蓝图做法 | 本文做法 | 理由 |
|---|---|---|---|
| **D1** | egress 对每个 packet 做 `bpf_sk_lookup_tcp()` 反向查找 app full socket，再取 SK_STORAGE | 直接 `bpf_sk_fullsock(skb->sk)` 取 full socket | 省掉每包一次 socket hash 查找；并消除"反查到错误 socket / `sk_bound_dev_if` 不匹配导致查不到"的正确性风险。已核验 helper 可用且不需 release。 |
| **D2** | 每 generation 注入 **4 个** inbound（actual v4/v6 + sentinel v4/v6，8 个 kernel socket），sentinel 带随机 `routing_mark` 作特权守卫 | 只注入 **2 个** inbound（`flux-in-v4` / `flux-in-v6`，4 个 kernel socket），删除 sentinel、mark、reject rule 与 egress 的第二次 lookup | sentinel 防御的是"恶意本地 app 抢绑"，而两版蓝图都在威胁模型里**明确声明不抵抗**该攻击。它保护的性质（liveness / 换代 fail-open）由 actual listener 的 lookup 已经完全提供。删掉去掉 2 个 inbound、4 个 socket、1 个 mark、1 条 route rule、1 次热路径 lookup 和整套 mark 语义。 |
| **D3** | 内部以太头 source MAC 由 generation 一一编码（46 bit），boot 内禁止复用，ingress 逐包比对 | **不做 generation 编码**，不比对 MAC；来源边界就是设备本身。（本条最初还保留了"写固定 MAC pair"，后被 **D17 进一步取消**——egress 完全不写 MAC） | 该编码只防"换代瞬间 in-flight 的旧 packet 被错送给新 engine"。其后果是无害的：旧 SYN 被新 engine 当作一条新连接；旧 established 数据包在 ingress 不 assign、内核查不到 socket 直接 RST。用 46-bit 编码方案 + 逐包 6 字节比对换这个，是负收益。 |
| **D4** | `flx_in` 内置由 `anchor_probe` 控制的 dead branch，使 program 持有全部 map 引用；crash 后从 TC program ID "reclaim" root maps，不可核验时禁止 detach | **删除 anchor 分支与 reclaim 机制**。daemon 启动时删除全部精确自有残留对象并重建 | reclaim 保护的是"已入场 TCP 的 SK_STORAGE 不丢失"，但 fluxd 死亡时 engine 因 `PDEATHSIG=SIGKILL` 必然一起死，那些 flow 已经无处可去。真正承担 fail-open 的是 **redirect 前的 listener lookup**（engine 没了 → lookup miss → 新流 Direct），它与 reclaim 无关。且 anchor 方案依赖"编译器不消除 dead branch"，还要用 `BPF_OBJ_GET_INFO_BY_FD` 事后验证——这是脆弱且不必要的复杂度。 |
| **D5** | policy 热更新流程：publish `active=0` → 改 map → publish `active=1`；失败用内存快照回滚 | policy 热更新**不动 `active`**：先加（新 SELECTED / 新 bypass），后减（旧 UID 降级 DRAINING / 删旧 bypass）；失败不回滚，由 level-triggered reconcile 重算收敛 | 旧做法让"用户增删一个 app"这种低风险操作把**所有在场 TCP 连接的 packet 打成 drop**（`active=0` 期间 CAPTURED 必须 SHOT）。而 map 非原子更新的唯一后果是"窗口内的**新**连接看到混合策略"——新连接无论走 direct 还是 proxy 都是良性的。同时删掉快照/回滚代码，改用幂等收敛。 |
| **D6** | 所有 IPv4 fragment / IPv6 Fragment Header 一律 Direct | ① 已有决策的 socket **不解析 L4** 直接按决策处理，因此已入场 TCP 的 fragment 跟随决策进入代理；② selected+active 的 UDP fragment 先按目的做 LPM bypass，未命中则 **drop**，绝不 direct | 旧规则是**数据泄漏**：一条已被代理的 TCP 流一旦发生 IP 分片，分片会被送到真实目的地。UDP 同理（首片进代理、后续片直连，既泄漏又破流）。修正后既无泄漏，又顺带让 CAPTURED 快路径省掉 L4 解析。 |
| **D7** | 固定 bypass 只有回环/链路本地/多播 | 当时追加 `198.18.0.0/15`、`2001:db8::/32` 并把本机地址写进 bypass；**地址前缀方案随后被 D20/D21 与 R091-07/R091-08 覆盖**：listener 只保留精确地址，本机地址进入独立 HASH | 已核验 sing-box TProxy 回写会 `IP_TRANSPARENT` 绑定原目的；若 app 访问本机自有地址上的服务而被捕获，回写 bind 会与真实本地服务**端口冲突**（官方 issue #3646）。捕获本机地址本身也毫无意义。 |
| **D8** | package→UID 用 Android PackageManager 命令接口（`cmd package`），并解析 manifest 拒绝声明 `BIND_VPN_SERVICE` 的包 | 只读 `/data/system/packages.list` + `uid = user_id*100000 + app_id`；VPN provider 只在 `status`/`check` 里**告警**，不做硬门禁 | `cmd package` 走 binder，`service.sh` 在 late-start 运行时 `system_server` 可能未就绪，会引入启动顺序依赖与重试状态机。`packages.list` 是纯文件读取、可 inotify、无 binder。manifest 权限门禁需要 binder + 权限模型，而它防的只是"用户主动选了 VPN app"这一配置误用。 |
| **D9** | 未限制可选 UID 范围 | **硬性只接受 app_id ∈ [10000, 19999]**（Android `FIRST_APPLICATION_UID..LAST_APPLICATION_UID`）；拒绝 root/system/isolated/sdk-sandbox | 结构性保证 engine（root，uid 0）永远不在 `uid_policy` 中，无需任何"自排除"逻辑；同时防止用户误选 `system_server` 这类会把设备打死的 UID。**已被 §0.6.5 第 30 条放宽**：结构性那半只需要拒绝 uid 0，后半是替 root 用户做决定，改为告警。 |
| **D10** | `build.rs` 用锁定版 `libbpf-rs`/`libbpf`，为 Android 静态构建 libbpf/libelf/zlib | **不链接 libbpf**（只 vendor 它的 header-only 宏，见 §12.1）。BPF 由 clang 编译，object 内嵌；加载器是 in-tree 的最小 Rust 实现（裸 `bpf(2)` + 自建 BTF blob + 按 map 符号名重定位） | ① 为 `aarch64-linux-android` 交叉构建 elfutils/libelf 是已知痛点；② 我们自著全部 ABI，不用 CO-RE，libbpf 的 99% 功能是负担；③ 本仓库现有 `crates/flux-platform/src/bpf/sys.rs`（661 行）已在同类设备上证明裸 syscall 路径可行；④ 交付物变成"纯 Rust + libc 单二进制"。 |
| **D11** | 只有一个 product crate `fluxd` | 三个 crate：`flux-core`（纯逻辑、无 libc、可在 Windows 上 `cargo test`）+ `fluxd`（Linux/Android 运行时）+ `xtask`（构建打包） | 开发主机是 Windows。单 crate 意味着**本地一条单元测试都跑不了**（整个 crate 会拉进 Linux 专有代码）。`flux-core` 承载配置解析、CIDR canonicalize、UID 计算、effective JSON 生成、版本推导等全部纯决策逻辑，这些恰好是最值得单测的部分。删除旧 `flux-platform`/`flux-testkit`。 |
| **D12** | 生产环境零 counter，只有 fault ringbuf | 增加 1 张 `PERCPU_ARRAY`（32 × u64），**只在决策/丢弃/故障事件上**自增，不在稳态每包上自增；`fluxd status` 读出 | "完全无可观测性"是真实的可用性缺陷：用户报"不生效"时无任何定位手段。per-CPU 自增在事件边上的成本是纳秒级且无锁。禁止 per-flow / PII / 地址级记录。 |
| **D13** | 删除工作树与 `.git`，`git init` 全新历史 | ~~保留仓库与历史~~ → **所有者 2026-08-25 决定：按旧蓝图执行，删除 `.git` 后重新 `git init`** | 我原本建议保留历史（删 `.git` 不可逆且对产品零收益：历史不进 ZIP、不影响 fresh-install 语义）。所有者选择干净重建。技术设计完全不受影响；唯一后果是旧实现与审计出处只能从 §18.1 的仓库外归档目录查证，**因此归档步骤从"建议"升级为"必须"**。 |
| **D14** | "新代码不得复制旧生产实现" | 数据面、策略/generation 机制**必须重写**；但 §18.3 列出的低层平台原语（rtnetlink 编解码、TC filter netlink、`bpf(2)` 封装、SEQPACKET、pidfd/进程、inotify、epoll）**应当移植并复审** | "全部从零"会把几千行已经调通的机械正确代码重写一遍，重新引入同类 bug。审计发现的缺陷集中在策略/抽象层，不在这些原语。 |
| **D15** | egress 直接写包 / 原位覆盖以太头 | 对 skb 的任何写入**必须**先经 `bpf_skb_store_bytes()` 或 `bpf_skb_pull_data()`，禁止对可能 clone 的 skb 做裸直写 | TCP 重传路径的 skb 是 `skb_clone()` 的，共享数据缓冲区；裸直写会**破坏仍在写队列里的原始 skb**。两个 helper 都会经 `skb_ensure_writable()`/`bpf_try_make_writable()` 解共享。 |
| **D16** | listener 绑定非本地地址但未把该地址纳入 bypass | 当时把 `198.18.0.0/15` 与 `2001:db8::/32` 放进固定 bypass；**D21/R091-08 已收窄为当前 listener 的精确 `/32` 与 `/128`** | 防自环结论保留，整段前缀方案作废。 |
| **D17** | egress 改写内部以太头的 dst/src MAC 以满足 `eth_type_trans()` | **egress 不改写 MAC**；ingress 调 `bpf_skb_change_type(skb, PACKET_HOST)`。control 结构删掉 `peer_mac`/`host_mac` | 见 §8.2 的对照表。结果：**L2 捕获稳态零 packet 写入、零 clone 复制**（TCP 重传 skb 是 clone，写它必然触发 `skb_ensure_writable()` 复制一份）；L3 只写 2 字节 EtherType；control 结构 104 → 96 字节。上游先例见 dae 的 `tproxy_dae0peer_ingress`。 |
| **D18** | 系统 DNS 不在捕获范围（前两版蓝图与我前几轮的结论都错） | **系统 DNS 精准 per-app 捕获，零额外机制。** 因为 AOSP 用 `fchown()` 把明文 DNS socket 的 owner 改成发起解析的 app，而 `bpf_get_socket_uid()` 读的 `sk->sk_uid` 跟随 `fchown` | 见 §1.3.1–§1.3.4。这是本轮最重要的发现：`xt_owner` 读 `f_cred->fsuid` 所以看不到，eBPF 读 `sk_uid` 所以看得到——**整个 iptables 生态被迫全设备劫持 :53 的根因就在这里**。连带作废了前几轮设想的 `cookie_tag_map` 路线（不再需要读 AOSP 私有 map）与"engine 换专用 UID"的前提。 |

## 0.3a 定稿轮新增的决定（D19–D23，2026-08-25 所有者拍板）

D1–D23 是对**前两版蓝图**的修正。以下五条是本轮实测与调研之后新增或改变的决定，全部已由项目所有者确认。

| # | 决定 | 依据 |
|---|---|---|
| **D19** | **不给 sing-box 打补丁。** 永久使用官方未修改的二进制 | 打补丁确实会让若干问题**结构性变简单**——cgroup hook 可以绕开 TC pref 冲突、`rp_filter`、raw-IP 补头三个难点，token 地址方案也随之可行（CHIZI 的分支正是如此）。**但那不是"更容易"，是"另一种难"**：他们自己的文档里有内核崩溃规避、按版本拒启动、mode × ipv6_mode 矩阵，且仍标注为实验性。决定性的权衡是：**厂商 TC 冲突是可检测、可按接口降级的局部问题，而维护一个 sing-box fork 是永久且无界的承诺**；加上用户信任面应当落在官方签名二进制上。代价也要诚实记下：拿不到他们 `testing-observability` 分支的指标（§1.5.6 的 per-UID 计数是我们这一半的对称补偿），且不能直接复用 `bypass_rule_set`——**但后者有解**，见 D22 |
| **D20** | 本机地址从 bypass 的 `LPM_TRIE` **移出**，改用专用的精确 `HASH` map（`self_addr_v4/v6`）；CIDR 仍用 LPM，**任何有效策略**在 6.6.0–6.6.46 上都拒绝激活（R091-07），不是只 gate “大列表” | 两条理由叠加。① **更好的设计**：本机地址永远是全长前缀，用 trie 做精确匹配本就是浪费，而 `HASH` 删除干净，对 IPv6 隐私地址轮换尤其重要。② **规避内核崩溃**：CHIZI 的文档记录了 LPM trie 在 6.6.0–6.6.46 的 UBSAN 崩溃，而 `android15-6.6` 就在支持范围内——**症状是设备重启，不是功能失效**。这是全设计里唯一允许按内核版本 gate 的地方，因为崩溃无法安全探测 |
| **D21** | listener 地址移出 sing-box 的 fakeip 惯用段：`198.18.0.2` → **`198.51.100.1`**，`2001:db8::2` → **`2001:db8:0:1::2`**；固定 bypass 只收**确切地址**，不再收整个前缀 | 移植旧版模板时发现的**设计缺陷**。fakeip 默认用 `198.18.0.0/15`，而旧的 listener 保留把整个 `/15` 放进了 bypass —— 于是**每个 fakeip 地址都不会被捕获，fakeip 静默完全失效**（DNS 正常、应用连得上、什么都打不开）。惯例是他们的且更早，所以该让的是 Flux。同时认识到"防自环只需 bypass listener 本身"，收窄前缀这一条独立成立。**真正的解法是第三条**：`fluxd check` 必须交叉校验 fakeip 段与 bypass 集是否相交（§9.0.1） |
| **D22** | 支持**大规模 CIDR bypass**（`FLUX_LPM_MAX_ENTRIES` 128 → 65536）。当时曾提议用 `rule-set decompile` 从 `.srs` 展开 CIDR；**该输入方案未进入当前 schema，已由 R091-04 覆盖**，0.9.1 只接受 `bypass_cidrs` | `LPM_TRIE` 被内核强制 `NO_PREALLOC`，所以 `max_entries` 只是上限、未用不占内存；容量结论保留，但 `.srs` 转换会制造第二配置来源与额外生命周期，当前不实现 |
| **D23** | 新增 **per-UID 字节/包计数**（`uid_stats`，`PERCPU_HASH`），只在已捕获的包上更新 | 现有 counters 只在决策边沿递增，能回答"有没有在工作"但不能回答"哪个应用走了多少"，而后者是用户最常问的问题之一，也是"系统统计翻倍"（§2.2.3(4)）的直接补偿。成本可控：被捕获的包已付了一次 redirect，再加一次 per-CPU hash 是边际的，**未选中流量一行都不碰**。明确不记目的地址、端口、时间序列——**不保存任何能重建访问历史的东西**。导出为 Prometheus 文本格式，但**不开 HTTP 端口**（Android loopback 不按应用隔离，指标会暴露"哪些应用在被代理"） |

### 容量与 map 集的连带变化

D20 与 D23 把 map 集从 9 张变成 12 张，容量也随实测调整（§1.5.3）：

| 常量 | 原 | 现 | 依据 |
|---|---:|---:|---|
| `FLUX_UID_SELECTED_MAX` | 128 | 1024 | 实测一台真机 `[10000,19999]` 内有 **429** 个 app，原值让"全选"结构上不可能 |
| `FLUX_UID_POLICY_MAX_ENTRIES` | 512 | 4096 | 必须容纳 selected + 一个 boot 内累积的 draining（后者永不删除） |
| `FLUX_LPM_MAX_ENTRIES` | 128 | 65536 | D22 |
| ~~`FLUX_LPM_SELF_ADDR_RESERVE`~~ | 32 | **取消** | D20：本机地址不再与 LPM 共用容量 |
| `FLUX_SELF_ADDR_MAX_ENTRIES` | — | 256 | D20 新增 |
| `FLUX_UID_STATS_MAX_ENTRIES` | — | 4096 | D23 新增，与 `uid_policy` 对齐 |

`FLUX_ABI_MAGIC` 因此从 `0xF10C0902` 提到 **`0xF10C0903`**。

## 0.4 我保留的旧蓝图关键结论

- **4 KiB base page only**。官方 `sing-box-1.13.19-android-arm64` 资产四个 `PT_LOAD` 的 `p_align` 全为 `0x1000`，不满足 AOSP 16 KiB ELF 要求。0.9.0 在 `sysconf(_SC_PAGESIZE) != 4096` 时保持 Inactive/Direct，不启动 engine、不建数据面。不重编上游、不用 app 兼容模式冒充原生支持。
- **`TC_ACT_UNSPEC` / capture filter 可达性**合同；“必须是枚举首位”的旧表述已由 R091-05 覆盖。
- **map-in-map + freeze 的不可变 control snapshot 发布协议**（§6.4）。
- **generation 单调、pointer swap 是唯一 commit point**（§9.4）。
- **不 attach cgroup、不写 Android fwmark、不动 netd RPDB、永不删除物理接口的 `clsact`**；自有 `flxrs1` 随 veth 生命周期管理（R091-05）。
- **Phase 0 先于清库与编码**。

## 0.5 克隆源码复核（2026-08-25）

七个同类/上游项目已浅克隆到仓库外可丢弃目录 `clone/`（已加入 `.gitignore`，**永不进入产品树**）：`CHIZI-0618/AndroidTProxyShell`、`CHIZI-0618/box4magisk`、`taamarin/box_for_magisk`、`CHIZI-0618/sing-box@testing-ebpf-cilium`（commit `45a5bd8`）、`SagerNet/sing-box@v1.13.19`、`daeuniverse/dae`、`daeuniverse/honk`。下表是**逐行读源码**得到的事实，取代前几节里基于文档/搜索的间接引用。

### 0.5.1 官方 sing-box `v1.13.19`：本设计依赖的四点全部成立

| 断言 | 源码位置 | 结论 |
|---|---|---|
| tproxy listener 设置 `IP_TRANSPARENT`（v6 时另设 `IPV6_TRANSPARENT`），UDP 另设 `IP_RECVORIGDSTADDR`（v6 时另设 `IPV6_RECVORIGDSTADDR`） | `common/redir/tproxy_linux.go:15-32` | 成立 |
| **整个代码树没有任何 `SO_REUSEPORT` / `ReusePort`** | 全树 `rg` 零命中 | **§9.2 的硬约束成立**：5.15 的 `bpf_sk_assign()` 不会返回 `-ESOCKTNOSUPPORT` |
| TCP 原目的 = accepted conn 的 `LocalAddr()` | `protocol/redirect/tproxy.go:77` | 成立 |
| UDP 原目的 = `IP(V6)_RECVORIGDSTADDR` cmsg | `protocol/redirect/tproxy.go:95` → `common/redir/tproxy_linux.go:46-59` | 成立 |
| UDP 回写新建 socket 并 **bind 原目的地址** + `IP_TRANSPARENT` | `protocol/redirect/tproxy.go:136-149`（`ListenPacket(..., destination.String())` + `redir.TProxyWriteBack()`） | 成立 → **D7 的本机地址 bypass 是必需的**，否则原目的落在本机地址上时 bind 会与真实本地服务撞端口 |
| `ListenOptions` 含 `BindInterface` / `RoutingMark` / `ReuseAddr` / `NetNs` | `option/inbound.go:66-88` | 成立（§9.3 禁止对注入 inbound 使用前两者的理由不变） |

**一处需要修正的细节**：`redir.TProxy()` 第 16 行**无条件**设置 `SO_REUSEADDR`。所以 §9.1 里"禁止设置 `reuse_addr`"在效果上是多余的——sing-box 自己一定会设。真正重要的只有"不得有 `SO_REUSEPORT`"，而这一条由全树零命中保证。保留"不注入该键"是为了让 effective JSON 最小，不是为了改变 socket 行为。

### 0.5.2 CHIZI sing-box eBPF 分支：确认它在 Android 上是"抢占 netd 槽位"

这是对 §0.1(2) 最重要的一手验证。`common/ebpf/loader.go:207-218`：

```go
func attachProgramRaw(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
    const allowMulti = 2
    err := rawAttachProgram(target, program, attachType, allowMulti)   // 先试 BPF_F_ALLOW_MULTI
    if err == nil { return nil }
    if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EPERM) &&
        !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
        return err
    }
    return rawAttachProgram(target, program, attachType, 0)            // 回落 flags=0
}
```

当 Android 在 root cgroup **动态 attach 了 netd 的 `flags=0` 程序时**，这条路径必然走完全程：`link.AttachRawLink` 失败 → MULTI 因 flags 不匹配返回 `EPERM` → **`flags=0` 覆盖掉 netd 的程序**。Phase 0 干净快照为空，不能把这个条件写成常驻占用（R091-06）。`common/ebpf/cgroup_attachment.go:42` 的清理只 detach 名字前缀为 `sb_ebpf_` 的程序：

```go
if strings.HasPrefix(info.Name, "sb_ebpf_") { ... rawDetachProgram(...) }
```

**netd 的 `connect4/6`、`sendmsg4/6`、`recvmsg4/6` 被替换后不会被恢复，直到 netd 自己重启。** 这不是旧版本遗留——上面是 cilium 重构后的当前 commit。他们的 `common/ebpf/README.md` 全文没有出现 `netd`、`occupancy conflict`、`replace existing program` 之类的说明，即该行为未在文档中披露。

**这条证据把"抢占槽位"从二手笔记升级为一手源码事实，是 0.9.0 禁止任何 cgroup attach 的直接依据（§3.2、§19）。**

### 0.5.3 CHIZI 如何拿到系统 DNS：cgroup root + 端口 53 越过 UID 策略

`common/ebpf/native/cgroup.bpf.c:491-494`（`sendmsg`/`connect` 三处同构）：

```c
bool force_dns     = port == 53U && config->dns_mode == SB_EBPF_DNS_MODE_HIJACK;
bool intercept_dns = port == 53U && config->dns_mode != SB_EBPF_DNS_MODE_OFF;
if (port == 53U && config->dns_mode == SB_EBPF_DNS_MODE_OFF) return 1;
if (!force_dns && uid_bypassed(config)) return 1;      /* hijack 模式下 :53 跳过 UID 判定 */
```

组合起来是：**在 cgroup2 root 上 attach（因此看得见包括 netd 在内的所有 socket）+ `dns_mode: hijack` 时让端口 53 完全跳过 UID include/exclude**。这正是 §21.1 的选项 B（全设备 DNS 劫持），只是实现在 cgroup 层而不是 iptables 层。它**没有**做到 per-app DNS——它是放弃了 DNS 的 per-app 语义。

自环防护上他们用的是 **TGID/PID**（`cgroup_program.go` 的 `selfTGID`，配 `config->engine_pid`），因为 cgroup hook 有进程上下文。**TC egress 没有这个上下文**（packet 可能在 softirq 中发出，`bpf_get_current_pid_tgid()` 不可用），所以我们若要做选项 B，只能靠专用非 root UID——这是 cgroup hook 相对 TC 的一项真实优势，也是 §21.1 里选项 B 代价的根源。

他们自己的发布说明同样承认 per-app 边界：「包名策略只保证由目标 UID 直接创建的 socket。系统 DNS、DownloadManager、isolated process、SDK sandbox 等代发流量可能属于其他 UID」。

### 0.5.4 AndroidTProxyShell：`local default dev lo` 在 Android 上是生产验证过的

`tproxy.sh:1401-1418` / `1420-1435`：

```sh
ip  rule  add fwmark "$MARK_VALUE"  table "$TABLE_ID" pref "$TABLE_ID"
ip  route replace local 0.0.0.0/0 dev lo table "$TABLE_ID"
ip -6 rule  add fwmark "$MARK_VALUE6" table "$TABLE_ID" pref "$TABLE_ID"
ip -6 route replace local ::/0 dev lo table "$TABLE_ID"
```

三点可迁移结论：

1. **`local <default> dev lo` 的本地交付技巧在 rooted Android 上是生产做法**，不是纸面推断。§8.3 因此风险很低。
2. **他们创建的链全部挂在 `mangle PREROUTING` 与 `mangle OUTPUT`，从不碰 `filter INPUT`**（链清单见 `tproxy.sh:968`）。他们的本机流量路径是 OUTPUT 打 mark → 策略路由送到 `lo` → 从 `lo` 重新入栈 → PREROUTING 的 TPROXY → **INPUT**。既然无需在 INPUT 开口就能工作，说明 **Android 默认的 `filter INPUT` 不会丢弃这类本地交付流量**。这实质性降低了 §16 Q6 的风险，但**不是完全证明**：他们的包 `iif = lo`，我们的包 `iif = flxrs1`，Android 可能有 `-i lo` 的快捷放行。Q6 仍要在设备上核。
3. **他们从不设置 `rp_filter` 或 `accept_local`**（全脚本只写 `ip_forward` / `ipv6 forwarding`）。原因在内核里：`__fib_validate_source()` 有一条 `dev_match = dev_match || (res.type == RTN_LOCAL && dev == net->loopback_dev)` 的早退分支——**包从 `lo` 进来就直接过关**。我们的包从 `flxrs1` 进来，走不到这条分支，所以 §8.4 的 `rp_filter` 依赖是**本设计独有的新风险，没有任何现有项目替我们验证过**。Phase 0 Q5 必须实测。

另外两点对照：

- `tproxy.sh:1045-1046` 的 `BYPASS_IP` 链有 `-m addrtype --dst-type LOCAL -p udp ! --dport 53 -j ACCEPT`，即**显式绕过发往本机地址的流量**——独立印证了 D7。
- `tproxy.sh:1002` 用 `-m owner --uid-owner "$CORE_USER" --gid-owner "$CORE_GROUP" -j ACCEPT` 排除内核自身，并在 `xt_owner` 不可用时回落到 `ROUTING_MARK`；`1370-1371` 在全局 DNS 劫持前先按 uid/gid 放行 core。**全设备 DNS 劫持必须配 core 自排除**，再次印证 §21.1 选项 B 的代价。
- `tproxy.sh:1272-1279` 用 `CONNMARK --mark "$mark/0xff"` 并注释「PREROUTING 阶段加上 /$mark 掩码识别被 MIUI 染色的连接」——OEM 会往连接上盖自己的 mark。这是"不占用 Android fwmark"（§3.1）的又一条现实依据。

### 0.5.5 dae / honk：进程身份来自 cgroup hook，Android 上不可移植

`honk/crates/honk-ebpf/src/cgroup.rs`（dae `tproxy.c` 的 Rust 移植）里 `cgroup_sock(sock_create)`、`cgroup_sock_addr(connect4/6)`、`cgroup_sock_addr(sendmsg4/6)` 五个程序**只做一件事**：`update_map_elem_by_cookie(cookie)` 后返回 `CGROUP_ALLOW`，用来维护 `COOKIE_PID_MAP`。dae 的 `docs/en/how-it-works.md` 也写明进程名靠"在 cgroupv2 挂载点监控 socket/connect/sendmsg 系统调用"获得。

**结论**：dae 的 per-process 能力依赖的正是 Android 会动态占用、且无法建立稳定生命周期所有权的那些 attach type。它的 TC 数据面原语（TC → veth → `bpf_sk_assign`）可以借鉴，它的进程身份机制不能。

### 0.5.6 AOSP DnsResolver / netd：per-app DNS 的源码链（D18 的依据）

克隆了 `platform/packages/modules/DnsResolver`、`platform/packages/modules/Connectivity`、`platform/system/netd`。完整论证在 §1.3.1–§1.3.4，此处只列证据位置：

| 事实 | 位置 |
|---|---|
| 明文 DNS 用**请求者 UID**，除非 `enforce_dns_uid` | `aosp-DnsResolver/res_send.cpp:789`、`:1092` |
| `resolv_tag_socket()` 在 tag 之后**执行 `fchown(sock, uid, -1)`** | `aosp-DnsResolver/resolv_private.h:245-256` |
| 官方文档口径："plaintext DNS queries are sent by the application's UID using `fchown()`"，默认 `false: set application uid on DNS sockets` | `aosp-DnsResolver/binder/android/net/ResolverOptionsParcel.aidl:48-57` |
| **`iptables -m owner` 看不到 `fchown` 后的 UID** | `aosp-DnsResolver/tests/resolv_test_utils.h:48-49` |
| DoT/DoH 刻意归属 `AID_DNS` | `aosp-DnsResolver/DnsTlsSocket.cpp:82`、`DnsTlsTransport.cpp:107`、`PrivateDnsConfiguration.cpp:593` |
| netd 侧 tag 回调（`TAG_SYSTEM_DNS`） | `aosp-netd/server/main.cpp:92-95`、`FwmarkServer.cpp:297` |
| 内核语义：`sk_uid` 随 `socket()` / `fchown()` / `accept()` 更新 | Linux commit `86741ec25462`（`sockfs_setattr()`） |

### 0.5.7 bpf2socks / asteriskd：另一条路，以及从中直接照搬的工程细节

`clone/bpf2socks` 的架构是 cgroup connect 改写到 token/本地地址 → **用户态 bridge**（`bridge_tcp.c` 1161 行 + `bridge_udp.c` 3282 行）→ SOCKS5。两点直接相关：

- 它的 bridge socket **设置了 `SO_REUSEPORT`**（`bridge.c:95`、`:125`、`:152`、`:189`），并配一个 `SEC("sk_reuseport")` 程序（`tc_redirect.bpf.c:660`）在 reuseport 组内选 socket。**这条路与 `bpf_sk_assign` 互斥**：6.5 之前 assign 对 reuseport socket 直接返回 `-ESOCKTNOSUPPORT`（§0.2）。所以"engine listener 不得有 SO_REUSEPORT"不是我们的偏好，而是两种架构的分岔点。
- 全树**没有** `bpf_sk_assign` / `bpf_redirect` / `bpf_sk_lookup`（`rg` 零命中）。它选择了在用户态复制字节，我们选择把 skb 直接交给内核 socket。前者多两次拷贝加一次上下文切换。
- 它用**legacy `struct bpf_map_def SEC("maps")`**（`tc_redirect.bpf.c:113-137`）在 Android 上加载成功——独立印证了 §12.2「C 只声明 map 符号、参数真相源在 Rust 侧」这条路可行，不必依赖 BTF map 定义。

**从这两个项目直接照搬进本蓝图的具体条目**（每条都已落到相应章节）：

| 来源 | 照搬到 |
|---|---|
| TC filter 所有权按 `{TCA_BPF_ID, TCA_BPF_TAG, TCA_BPF_NAME, FLAGS, FLAGS_GEN}` 五路精确匹配（`asteriskd_tc_netlink.c:170-177`） | §8.5 的 ownership 谓词 |
| netlink dump 属性 allowlist + 未知/重复即 foreign（`:141-157`） | §8.5 |
| 双次 dump 比对的 TOCTOU 守卫（`bpf_util.c:411-454`） | §8.5 |
| `clsact` 带 `TCA_INGRESS_BLOCK`/`EGRESS_BLOCK` 判 foreign（`asteriskd_tc_netlink.c:333-341`） | §8.5 |
| 只在独占创建时才删 `clsact`（`asteriskd_tc_plan.c:36-46`） | §8.5（我们更严：**永不删**） |
| 1500 ms 尾随 debounce + overrun 触发全量重 dump（`asteriskd_network.c:147-164`） | §10.4.1 |
| 每次 TC 操作前重新 `if_nametoindex`（`asteriskd_runtime.c:3806`） | §10.4.1 |
| verifier log 因缓冲不足重试并恢复原 errno（`bpf_util.c:177-189`） | §12.7 第 3 条 |
| `__NR_bpf` / 常量的按架构兜底（`bpf_util.c:16-36`） | §12.7 第 1–2 条 |
| ELF sanity gate + `R_BPF_64_64` + map 名绑定表（`bpf_object.c:23-172`、`:250-257`） | §12.7 第 4–5 条 |
| `BPF_PROG_GET_FD_BY_ID` 后复核 id（`bpf_util.c:352-370`） | §12.7 第 6 条 |
| 能力判定=真实 attach 再 detach，绝不查版本（`connect_prog.c:1980-2013`） | §3.7、§12.7 第 10 条 |
| child exec 前的固定顺序 + parent PID 复查 + `(pid, starttime)` 复合身份（`asteriskd_process.c:332-390`） | §13.3 |
| readiness = "已验证的进程拥有那个特定端口"，不是"进程活着"（`asteriskd_process.c:572-666`） | §9.5 |
| effect journal 的 `probe_original`/`apply`/`verify`/`undo` 与**重入时复用原始基线**（`asteriskd_effect_journal.c:84-109`、`:157-184`） | §15.4(1)；我们因为每次重建 veth 而不需要基线，但规则同源 |
| 抽象 unix socket 作为自清理的单实例锁（`asteriskd_control.c:56`） | §10.3 记为**已评估的替代方案**：我们用 `flock` 是为了让 socket 路径可被 `uninstall.sh` 检查；抽象 socket 的自清理优点已由 §8.7 步骤 2 的"启动即删残留"覆盖 |

**明确不照搬的**：shell out 到 `tc`（§12.8）、token 地址改写、`SO_REUSEPORT` 分片、用户态 pump、`IPPROTO_RAW` 兜底、丢弃 IPv6 DNS、":53 覆盖一切 bypass"、删除 Android tethering offload filter、手写 BPF 汇编器、"永不重启"策略。理由见 §19。

### 0.5.8 dae 的 TC 数据面逐项对照（revision `caa6f5e`）

**与本设计一致的部分（可作为先例引用）**：

| 项 | dae 源码 | 与本设计的关系 |
|---|---|---|
| 不改写目的地址 | `tproxy.c:2455-2456` 注释原文："We cannot modify the dest address here." | 一致。**注意 dae 的英文文档 `docs/en/how-it-works.md:36` 仍写着 WAN egress 会改写目的并关闭 checksum，与当前 C 代码矛盾。引用 dae 时只引 C，不引该文档。** |
| WAN（本机流量）在 **TC egress** 捕获，`bpf_redirect(dae0, 0)` 后在 **peer ingress** `bpf_sk_assign` | `tproxy.c:1518-1522`、`2822-2845` | 与 §2.1 完全同构 |
| `bpf_sk_assign` **只对 UDP 与 TCP `SYN && !ACK`**，established TCP 直接回栈 | `tproxy.c:551-555`；`2836-2839` 注释："Established TCP can return to the stack without bpf_sk_assign." | 与 §7.5 的 I3 else 分支完全一致——这是一次独立印证，不是巧合 |
| `bpf_skb_change_type(skb, PACKET_HOST)` 在 peer ingress | `tproxy.c:2833` | **D17 的直接先例** |
| L3 链路用 `bpf_skb_change_head` 补 14 字节以太头，`h_proto` 取自 `skb->protocol` | `tproxy.c:1628-1644` | 与 §3.3 的 `flx_cap_l3` 一致 |
| L2/L3 由链路 `EncapType` 决定，不猜 | `control_plane_core.go:348-363`（`none/ipip/ppp/tun` → L3，`ether` → L2） | 与 §8.6 按 ARPHRD 分类一致 |
| TC 程序里**没有任何** checksum helper | 全 `control/kern/` 无 `bpf_csum_diff` / `bpf_l3_csum_replace` / `bpf_l4_csum_replace` | 印证 §0.2 的推理：不改 L3/L4 就不需要动 checksum，`CHECKSUM_PARTIAL` 能穿过 veth |
| map 满时 fail-closed（宁可 drop 也不泄漏） | `tproxy.c:2287-2302` | 与 §2.2.2 同一取向 |

**本设计比 dae 简单的地方（读者对照时会问"return leg 去哪了"）**：

dae 把 listener 放在**独立 netns `daens`** 里，所以回程必须再穿一次 veth——它为此维护 `redirect_track` map（`tproxy.c:120-127`）保存原接口与 MAC，并在 `tproxy_dae0_ingress` 里恢复 MAC、按 `from_wan` 决定 `BPF_F_INGRESS`（`tproxy.c:2952-2980`）。**0.9.0 把 engine 放在与 app 相同的初始 netns（§3.9），回程就是普通本地路由经 `lo`**，因此不需要 `redirect_track`、不需要 MAC 恢复、不需要第二个 redirect 方向。这是"同 netns"这个决定换来的实质简化。

**两条硬教训**：

- **`bpf_redirect_peer` 不要用**，而且**比我原先以为的更彻底**。我此前只把它记成"因 CVE-2025-37959 被 dae 禁用（`netns_utils.go:220`、`bpf_utils.go:496-514`）的待评估优化"。逐行读内核后它其实**结构上就不适用**：`BPF_F_PEER` 分支要求 ① `skb_at_tc_ingress(skb)` 且 ② 目标设备在**不同** netns（v6.1 `net/core/filter.c:2458-2471`），我们是 egress 侧 + 同 netns，两条都不满足。dae 源码自己也写了"NOT supported in egress direction"（`tproxy.c:1518-1523`）。**结论：这不是延期项，是不存在的选项**，必须为每个捕获包预算一次完整 `dev_queue_xmit` + backlog/NAPI 跳（已计入 §14.1）。
- **关于 `skb->mark` 的一处更正。** 我此前（D3、§7.5）写过"veth 会 scrub 掉 mark"，**这对本设计的拓扑是错的**。`____dev_forward_skb()` 调 `skb_scrub_packet(skb, xnet)`，而 `skb_scrub_packet` 只在 `xnet == true` 时清 `skb->mark`（v6.1 `net/core/skbuff.c:5518-5523`）；`xnet` 由 `!net_eq(dev_net(dev), dev_net(skb->dev))` 算出。**同 netns 的 veth ⇒ `xnet == false` ⇒ mark 保留。** dae 需要 netkit 的 `scrub=NONE`（`netns_utils.go:219`）是因为它**跨 netns**，我们不跨。

  结论不变但理由要换：我们**不用** mark 跨 hook 传信息，原因是 ① 根本不需要传（设备本身就是 provenance 边界）；② 用 mark 就要占 Android 的 fwmark 位空间（§3.1）。**不是因为传不过去。** 这一条必须写清楚，否则实现者会基于错误前提做决策。

- **`nf_reset_ct()` 与 `skb_dst_drop()` 无条件执行**（同一函数内）。后果：conntrack 在 veth peer 的 PREROUTING **重新建立**，因此 netfilter 对每条被代理的流会看到两次，Android 的流量统计除了 §2.2.3(4) 的双 leg 之外还有一层 conntrack 重复计数。这是 TPROXY 类方案的共性，不特殊处理。

### 0.5.9 内核源码逐行核对轮：三处推翻、一处升级为日常事件

最后一轮把 v5.10 / v6.1 / v6.6 / v6.12 的相关源文件与四个 GKI 分支的 `gki_defconfig` 拉下来逐行读，另外读了 `aosp-netd` 与 `aosp-Connectivity` 的路由/TC/CLAT 侧。产出分四类：

**(a) 推翻了我此前写下的三处论证**（结论都还成立，但理由是错的，已就地更正）：

| 我原来的说法 | 实际 | 处理 |
|---|---|---|
| "veth 会 scrub 掉 `skb->mark`"（D3、§7.5） | 只在**跨 netns** 时清；同 netns 保留 | 上一节已更正。结论保留，理由换成"不需要 + 不占 fwmark 位" |
| "`bpf_redirect_peer` 是被 CVE 挡住的待评估优化" | egress + 同 netns，**结构上不可用** | 已从 §22.2 延期表移出，改写进 §19 与 §22.3 |
| "重定向到 `lo` 的问题是 blast radius" | `loopback_xmit()` 调 `skb_dst_force()`，`ip_route_input()` 被跳过，包按 output rtable 的 `dst->input` **直接丢弃**——机制上根本不成立 | §19 已换成决定性理由 |

**(b) 一条从"异常"升级为"日常"的运维事实**：netd 在每次 interface 加入/离开网络时删 `clsact`，netd 重启还会清空所有 interface 的 clsact（§8.5.1）。这改变了 §26 状态机的形状——必须把捕获侧漂移与核心漂移分成两条路径，否则每次 Wi-Fi 重连都会让全设备代理流量瞬断。

**(c) 把若干"估计"换成一手依据**：netd 的 `ip rule` 最低 priority 是 10000 且路由表偏移 1000（⇒ 我们的 pref 100 / table 20260 安全，§8.3）；AOSP 的 TC 优先级占用表（§8.5.2）；四个 GKI 分支的 config 逐项核对且 `CONFIG_NETKIT` 全部缺失（§4）；`bpf_sk_assign` 的 reuseport 拒绝行为在 6.5 前后的确切差异（§9.2）。

**(d) 一条明确评估后拒绝的重构提议**：因为 `skb->sk` 确实活到 veth peer ingress，理论上可以"egress 无条件 redirect、全部策略收进 ingress"。拒绝理由见 §19——那要求把未选中流量也 redirect 一遍再原路送回，等于放弃"未选流量只付 1 helper + 1 hash miss"这条性能地基。

同一轮还确认了两件已有设计的正确性：`flx_cap_l2`/`flx_cap_l3` 的拆分是**强制**的（§3.3.1，否则蜂窝数据全丢且无计数器），以及 rp_filter / accept_local 的马丁源丢包在本拓扑下是**必然**而非概率事件（§8.4）。

### 0.5.10 TC attach 策略的同类实现对照：我的核心问题没有先例

针对 §8.5.3 发现的 pref 冲突，把语料里**所有真正 attach TC filter 的项目**逐个读了 attach 层。

| 项目 | pref 怎么定 | 冲突怎么处理 | attach 后验证什么 | TCX | 不接管时返回 |
|---|---|---|---|---|---|
| **dae** | 硬编码（LAN egress 1 / ingress 2、WAN egress 2 / ingress 1，`control_plane_core.go:474-724`） | 先 `FilterDel` 再 `FilterAdd`，`EEXIST` 当成功 | **不验证** | 无 | **`TC_ACT_OK` 23 处** / `TC_ACT_PIPE` 4 处 |
| **honk** | 不自己设，交给 aya | 交给 aya | 只记 link id | 无 | `TC_ACT_PIPE` 为主 |
| **chizi**（Android） | 默认常量 **1**，可配置（`shared_network_tc.go:27`） | 先 `FilterList`，**只**在 handle 相同时报错 | 重新 `FilterList` 确认可见 | **有，TCX 优先 + clsact 回落** | **`TC_ACT_UNSPEC`** |
| **asteriskd**（Android） | 硬编码 `pref 1 / handle 1`（`asteriskd.h:2567`） | **探测到该槽位被外人占用就拒绝启动**（`asteriskd_tc_plan.c:129-135`，`"foreign TC resource collision"`） | **netlink dump 复核自有 filter 的身份**（object id / tag / name / da 标志） | 无 | `TC_ACT_PIPE`（bpf2socks） |
| **mihomo**（已移除的历史组件） | 硬编码 0 / 1 | 不检查，`FilterAdd` 失败即启动失败 | 不验证 | 无 | `TC_ACT_OK` 几乎所有分支 |
| **AOSP** | 跨子系统协调的固定值 1–5 | `NLM_F_EXCL｜NLM_F_CREATE`，且 `tcm_handle = TC_H_UNSPEC`（**让内核分配 handle**） | 不验证执行 | 无 | — |

**四条"无先例"的结论**（宁可知道没人解决过，也不要假定有人解决过）：

1. **动态选 pref：没有任何项目做。** 全部硬编码或交给用户配置。
2. **验证程序是否真的执行：没有任何项目做。** asteriskd 最接近，但它复核的是**身份**（"我装的那条还在不在、是不是我的"），不是**执行**（"包有没有真的进来"）。这两者在被前面的 filter 遮挡时给出完全相反的答案——身份检查会通过。
3. **检测"同 pref、不同 handle 的外来 filter 在我们之前跑"：没有先例。** chizi 只比 handle，asteriskd 只比一个精确的 `(pref, handle)` 元组。
4. **TCX 的相对定位：没有先例。** chizi 是唯一用 TCX 的，但它的 `link.AttachTCX` **不带任何 `BPF_F_BEFORE`/`BPF_F_AFTER`**（`shared_network_tcx.go:91-95` 实测无 anchor 参数）。

**三条可以直接拿来用的：**

**(a) chizi 给了 `TC_ACT_UNSPEC` 一个我没记录过的独立理由。** 我原先的理由只有"`TC_ACT_OK` 会终止 chain，跳过 AOSP CLAT 与 OEM filter"。chizi 的注释补上了 TCX 侧：

```c
// TCX only continues with later TCX programs and the legacy clsact chain for
// TC_ACT_UNSPEC. TC_ACT_PIPE stops the TCX program array before being mapped
// to "next", which can skip tethering programs attached after sing-box.
#define SB_SHARED_ACT_CONTINUE TC_ACT_UNSPEC
```

也就是说在 TCX 上 **`TC_ACT_PIPE` 同样会截断**，只有 `TC_ACT_UNSPEC` 会继续走到后续 TCX 程序与 legacy clsact 链。这条让 §7 的"不接管一律 `TC_ACT_UNSPEC`"从"clsact 时代的正确选择"升级为"clsact 与 TCX 两条路径下都唯一正确"，因此 §22.2.1 的 TCX 分支**不需要改任何返回值**。

**(b) dae 在 Android 上会遮挡系统 filter，我们的分歧是对的。** `dae/control/kern/tproxy.c` 里 `return TC_ACT_OK` 出现 **23 次**、`TC_ACT_PIPE` 4 次。在 Linux 路由器上无害；搬到 Android 就会跳过 AOSP CLAT 与全部 OEM 程序。这是 §0.5.8"只引 dae 的 `control/kern/*.c` 当机制参考、不照搬其策略"的又一个具体例证。

**(c) asteriskd 的身份复核值得叠加，但不能替代存活验证。** 它在 attach 之后用 `RTM_GETTFILTER` dump 比对 object id、program tag、bpf name 与 `da` 标志（`asteriskd_tc_netlink.c:119-177`）。这抓的是"我们的 filter 被人替换/删除"，与 §8.5.4 抓的"我们的 filter 在但跑不到"是**两类不同故障**，两者都要有。前者本设计已由 §8.5 的所有权谓词 + `RTM_NEWTFILTER` 监视覆盖。

**(d) 一处刻意与 AOSP 不同**：AOSP 用 `tcm_handle = TC_H_UNSPEC` 让内核分配 handle，代价是**它无法凭 handle 认出自己的 filter**。我们固定 `handle 0x1`（探测用 `0x3`），正是为了让所有权谓词能精确自证（§8.5、§8.9.5）。这个分歧是有意的。

**唯一没能核实的**：`accept_local` / `rp_filter` 在各厂商内核上的实际默认值（AOSP 自己从不设置这四个 sysctl，值完全来自厂商 defconfig 与 `init.rc`），以及模块 SELinux 域能否写 `/proc/sys/net/ipv4/conf/*/accept_local`。两者都已在 Phase 0 有对应条目，处置方式是运行时读取 + 失败即响亮报错。

---


---

## 0.6 2026-08-25 下半场：实测又推翻了三条，其中两条是我自己写的

实测前的五条分布在：§0.2 一条（"推翻我最初的怀疑"，sing-box `listen` 字段确实支持那三个键）、§0.5 开头一条（cgroup `SOCK_ADDR` 槽位"永久独占"的表述不成立）、§0.5.9(a) 三条。**给出位置而不只给数字，是为了让这个计数能被对着文档数出来**——它此前写成"七次"，而按标注实际只有五条。

这一轮由 Phase 0 的 Q1 / Q9 / Q6 实测引出，同样按"原说法 / 实际 / 处置"记，编号接着上面的五条。

| # | 原说法 | 实际 | 处置 |
|---|---|---|---|
| 6 | §16.1 Q6：AOSP 默认 `filter INPUT` 应当放行本地交付流量，**但残余风险是 Android 可能有 `-i lo` 的快捷放行**，使得 `iif = flxrs1` 的包待遇不同 | `filter INPUT` 的七条 target **全部是 `in *`**，且七条计数与 policy 计数逐字相同。没有任何接口维度的分支 | 残余风险**消除**（§16.9.1）。`iif = lo` 与 `iif = flxrs1` 走同一条路径。Q6 剩下的问题收窄为"OEM 是否整体丢弃"，需数据面在位 |
| 7 | §8.5.3：三星的 `semUidBPF` 占据 egress pref 1 —— 行文让人读成**设备级**事实 | 同一台设备上，三个 `rmnet_data*` 的 egress 与 ingress **一个 filter 都没有**。占位是**按接口**的；程序名后缀 `_tsm_ether` 本身就说明它只服务 `ARPHRD_ETHER` | §8.5.3 加了实测追加段。硬性要求：**逐接口 dump、逐接口选 pref、逐接口做 §8.5.4 存活验证**，禁止把可用 pref 缓存为设备级的一个值 |
| 8 | §7.x 数据面被描述为"论证上可实现"，其中 `sk_storage` / `sk_assign` 引用配平 / `skb_change_head` 等难点只有推理支撑 | **四个程序全部在基线 5.15.211 上通过验证器并 JIT 成功**（§16.8.5）。同时发现四个程序的 ELF 段名 libbpf 一律拒绝，**根本加载不了** | 段名缺陷已修（§16.8）。数据面从"论证"升级为"实测可验证"。`bpftool prog loadall` 进 CI 作为最便宜的验证器门 |

### 0.6.1 0.9.1 文档一致性更正（2026-08-29）

0.9.0 蓝图保持冻结。以下更正的完整覆盖范围与验收条件见 `../history/blueprint-0.9.1.md` 的冲突裁决登记表；这里仅保留“原说法 / 实际 / 处置”的历史索引。

| # | 原说法 | 实际 | 处置 |
|---|---|---|---|
| 9 | capture filter 必须是 dump 中 first-applicable | 前置 OEM filter 返回 `TC_ACT_UNSPEC` 时，后续 Flux filter 仍可达；Q10 已实证 | R091-05 改为身份/排序 + 正向存活验证，兼容字段只表示“已验证可达” |
| 10 | 物理 `clsact` 缺失或被删后由 Flux 重建 | 物理 `clsact` 属于 netd；抢建会破坏所有权边界 | R091-05 改为 `netd_clsact_missing` 排除并等待 `RTM_NEWQDISC` |
| 11 | disable/stop/uninstall 会同步拆除全部对象 | 当前实现先 inactive 并停 engine，同 boot 可保留精确自有对象；卸载后由重启清除非持久对象 | R091-09 明确同步承诺与不承诺事项 |
| 12 | 0.9.x 有 subscription、默认 zashboard | 默认配置无远程内容；订阅命令不存在 | R091-03 冻结产品范围，不预建未来 seam。（本行原本还断言"当前包含 `action.sh`"，已由下方第 19 行推翻） |
| 13 | 配置存在多套路径、`bypass_v4/v6`、`bypass.files` 或 `.srs` 输入 | 当前 authority file 与 parser 只有 R091-04 的路径和 `apps`/`bypass_cidrs` schema | R091-04 统一路径、schema 与 fresh-install 状态 |
| 14 | 逐文件 sidecar hash 与管理器版本资格矩阵是当前安装合同 | 当前发布路径是精确文件 allowlist + 归档级 `SHA256SUMS`，安装器只做最小检查 | R091-12 对齐实际供应链边界；文件数随第 19 行的 `action.sh` 移除变为 14 |
| 15 | Phase 0 后的 Q3–Q8 仍待实现 | Phase 1–8 与对应设备测试均已进入仓库 | R091-13 以 `plan/implementation.md` §17.0 作为当前进度真相 |
| 16 | 本地 socket 已独立版本化，CLI 含 `explain/watch/subscribe` | 现有 wire 无独立版本字段，当前 CLI 不含后三个命令 | R091-11 不为唯一 adapter 预建协议框架 |
| 17 | 每个开发平台都无条件运行 `cargo test --workspace` | Windows 会编译到 Linux/Android-only device binaries，并在 `std::os::fd`/`libc` 处失败；CI 的完整 workspace 门在 Linux | R091-15 把 host-safe、Linux CI 与 Android device suite 分层，三层互不冒充 |
| 18 | R091-03 初稿把 C8/C10/C11 写成 0.9.1 的范围结论，读起来像 agent 自行取消了这三项能力 | 这三项是 0.9.0 §21 的**所有者确认项**，移出交付范围属 GOV-1.2 的产品能力边界变化，不在 §1.1 的自决授权内 | 所有者 2026-08-29 确认：**WebUI、代理控制面默认体验、订阅转换三项都在后续版本做，0.9.1 不做**。R091-03 与 §21.1/§22.2 改写为"已确认的延期项"而非范围永久收缩；仍禁止现在预建 seam |
| 19 | 运行时开关是 `/data/adb/flux-rs/disable`，与管理器的模块开关"互不相干"；管理器开关只能下次启动生效，于是需要 `action.sh` 提供一个即时按钮 | 参考实现 `Flux-original` 用 `inotifyd` 直接监听**管理器自己的**模块目录（`flux_service.sh:57`、`dispatcher:187-190` 的 `disable:d`→start / `disable:n`→stop），管理器开关因此当场生效，整个项目没有 `action.sh`。两个 disable 文件是自造的解释负担，而 `action.sh` 是为绕开它引入的第三个入口，还额外背上 Magisk v28+ 的依赖 | 所有者 2026-08-29 确认改用原版模型：**开关合并为 `/data/adb/modules/flux_rs/disable`**，`fluxd` 的既有 inotify 改watch 模块目录；删除 `action.sh`（allowlist 15→14）；`fluxd enable/disable` 写同一个文件；fresh install 由 `customize.sh` 在 `$MODPATH` 建 `disable`，装完即在管理器里显示为禁用。见 R091-03、R091-04 |
| 20 | `module.prop` 的 `description=` 由 `action.sh` 在按钮被按下时刷新 | 状态显示不该依赖用户按按钮：不按就永远是旧值。原版由守护进程在每次状态转移时 `sync_prop`（`scripts/log:104-152`），并且做了去重、幂等剥离和 mktemp+`mv` 原子替换三件事 | `fluxd` 每次事件循环唤醒后重写，渲染结果不变则不写；剥离与合成逻辑放在 `flux-core::version` 以便任意主机测试（R091-15）。写失败只丢状态显示，不影响 daemon |
| 21 | 默认 `sing-box.json` 必须是"只有 direct outbound + final + 两条规则"的极简形状 | 所有者要求与原版 Flux 对齐。极简形状本身没有保护任何不变量；真正必须成立的是"不抢 inbound、不开控制端口、每个 selector 能解析、fakeip 不落在固定 bypass 里"四条 | 模板改用原版形状，`xtask` 的校验从枚举允许的键改为检查这四条性质加两条路由规则（R091-03） |
| 22 | 原版模板的 fakeip `inet6_range: fc00::/18` 可以直接用 | `FIXED_BYPASS_V6` 含 `fc00::/7`（ULA 属私网，必须直连），`fc00::/18` 整个落在里面。IPv6 fakeip 会被判 bypass 走直连，DNS 正常、应用连得上、什么都打不开——D21 的 v6 翻版 | 模板改用 `2001:db8:f::/48`，与 `checks.rs` 既有测试用的已知良好值一致；`fluxd check` 的 `fakeip_bypass_overlap` 本来就会拒绝原值 |

首次真机端到端验证的完整记录见 §0.6.4。

### 0.6.2 三条附带的平台事实

这些不是推翻，是原先根本没写、而实现者一定会踩的。

| 事实 | 依据 | 为什么会踩 |
|---|---|---|
| **arm64 5.15 不实现带返回值的 BPF 原子操作** | §16.6.3。`__sync_fetch_and_add` 取返回值 → `BPF_ATOMIC \| BPF_FETCH` → 加载失败 `-ENOTSUPP(524)`，**而 verifier 已经通过**（167 条指令零抱怨） | errno 毫无指向性，日志形状会让人以为是逻辑问题。调试时随手加一个全局计数器就中招。已写成 §7.5.0 的硬规则 |
| **`operstate` 对 RAWIP 接口读出 `unknown`** | §16.9.5。`rmnet_data0` 承载默认路由、流量在跑，`operstate` 仍是 `unknown` | 任何 `operstate == "up"` 的过滤会漏掉**全部蜂窝接口**，而那是 `flx_cap_l3` 唯一的适用对象。已写进 §3.3 |
| **`SEC("action")` 会骗过"加载成功"** | §16.8.2。它选中 `BPF_PROG_TYPE_SCHED_ACT`，加载成功但 `tc filter ... bpf da` 直接 `EINVAL` | 只看加载结果会误判为可用段名 |

### 0.6.3 一条被实测**加强**而非推翻的论断

D18（per-app DNS 零额外机制）此前只有源码链支撑（§1.3.1 的 `netd` → `fchown()` → `sk->sk_uid` → `bpf_get_socket_uid()`）。§16.7 的实测结果：明文 :53 上出现的是 `com.android.vending`（UID 10265）这样的 **app UID**，而 netd 自己的 **1051 出现零次**。

值得单独说的是**为什么这条证据强**：同一次测量的对照组（:443）显示各 app 逐一正确归属，所以 :53 的结果不是孤立巧合，而是整条 UID 归属路径在这台设备上都准。源码分析预测了什么，实测就看到了什么。

同时实测暴露了一个源码分析**没有覆盖**的边界：`private_dns_mode` 的**默认值是 `opportunistic`**，语义是"先试 DoT，上游拒绝才回落明文"。所以可捕获的 DNS 量**取决于对端 DNS 服务器**，不取决于我们。这不是缺陷而是边界（§1.3.3 边界①），但它意味着**同一份配置在两个网络上的 DNS 行为可以完全不同**，`status` 必须让用户看得出来。

### 0.6.4 首次真机端到端验证（2026-08-29，SM-S9180 / 5.15.211 / KernelSU 3.2.5）

0.9.1 合同第一次在真实设备上跑通完整数据路径，用的是产品本身而不是探针：模块 ZIP 安装 → 真实机场订阅转成 authority file → 五个选中 app 的流量经官方未修改 sing-box 出网。

| 断言 | 实测结果 |
|---|---|
| 动态 per-interface pref，避开 1 | `rmnet_data0/1/8` 与 `wlan0` **全部取 pref 2** |
| Q10：三星 `semUidBPF` 占 pref 1 不遮挡后续 filter | `wlan0` 在 Samsung pref 1 之后取 pref 2，`flx_verify` 判定 **reachable**。**这是产品自身而非探针的首次实证** |
| `ifaces[].pref` 与三态 `first_applicable`（R091-05） | status 逐接口输出 `pref 2` 与 `reachable` / `reachability unverified` |
| 两个不同随机 listener 端口（R091-08） | 每代候选各抽一对，如 `62909/61793`、`61786/65467` |
| 动态 self-address 注入 | 收敛过程中 9 → 12 条，随接口地址变化 |
| `bpf_sk_assign` 无泄漏 | `tcp 36 captured / assigned 36`、`udp 40 captured / assigned 40`，**捕获数与 assign 数逐一相等** |
| engine 候选失败不改变顶层承诺 | 配置有误时连续 14 代候选失败，顶层稳定 `Inactive` + 精确 `engine_exited:code=1`，backoff 正常，从未谎报 Active |
| `module.prop` 实时状态（R091-04） | 依次显示 `🤯 [Inactive] engine_exited:code=1` → `🥰 [Active] gen 18 · 5 apps · rmnet_data0, rmnet_data1, rmnet_data8, wlan0` |
| 官方 engine 收到原始目的 | engine 日志 `inbound/tproxy[flux-in-v4]: inbound connection from 192.168.128.135:51072`，随后 `outbound/hysteria2[香港01]` |

**暴露的一个真实缺口**：`fluxd check` 通过不代表 engine 能启动。`sing-box check` 接受了 `detour` 指向裸 direct outbound 的 DNS server，`start` 阶段却拒绝（`detour to an empty direct outbound makes no sense`）。Flux 的处置是正确的——候选失败、保持 `Inactive`、报出精确原因、按 backoff 重试——但文档不能把 `check` 说成"通过就一定能跑"，`check` 是**配置合法性**门，不是启动保证。

**第二个缺口**：fresh install 落地为"管理器里已禁用"，而被禁用的模块不会执行 `service.sh`，所以没有 daemon 在监听开关。**首次启用因此仍需重启一次**；此后的开关才即时生效。`customize.sh` 必须说清这一点。

### 0.6.5 0.9.5 实现期更正（2026-08-31 起）

合同折叠完成后，实现批次对照合同时发现的更正。编号接 §0.6.1。

| # | 原说法 | 实际 | 处置 |
|---|---|---|---|
| 23 | §28.3 把 `snell` 列入订阅 URI 的可解析协议集 | Snell 是 Surge 私有协议，`clone/sing-box-official-1.13.19/` 全树零引用；按 §1.1 的"官方未修改二进制"，一个 snell 节点永远连不上，解析它只会造出一个必然过不了 `sing-box check` 的候选。批次 C 的实现者（codex）发现并拒绝自行改合同，是对的 | 2026-08-31 从 §28.3 与解析器移除。不支持的 scheme **让整份解析失败并报行号与 scheme**，不静默跳过——静默丢掉的节点是用户付了钱却看不见的缺失；操作上零成本，因为 §28.6 无论如何保留当前代 |
| 24 | §28.8 说 webroot 跳转 URL"带上安装时生成的 secret"，在 `check` 发现未配置 `clash_api` 时显示说明 | 0.9.5 的 §27.2.3 默认模板不含 `clash_api`，安装时**不存在任何 secret**；§27.1.2 又只允许 Flux 在模块目录写 `disable` 与 `description=` 两处，静态页面无处可读。这句是 R092 时期"模板可带默认密码"设想的残留，折叠时被原样带过来了 | 2026-09-04 就地改 §28.8：页面在被打开时通过管理器的 WebUI 桥接（KernelSU、APatch 与 Magisk 侧的独立启动器都暴露同一个 `ksu.exec`）运行 `fluxd status --json` 并读取当前代的 `experimental.clash_api`，据此跳转或说明缺了哪个前提。`fluxd` 不加命令、不为它写文件 |
| 25 | §13.2 的 `service.sh` 用一个 shell 循环监督 `fluxd daemon`：非零退出就按 1/2/4/8 s 退避重启；§14.2 把它写成"a supervisor shell blocked in `wait`" | 这个循环的行为取决于退出码和时间，按 PHIL-7 的判据本就属于二进制（§17.0.1 第 5 项）。而且它有缺陷：对**任何**非零退出都重启，包括"另一个实例已在运行"——第二次执行 `service.sh` 会以 8 秒间隔永远重试，对着正在工作的实例撞 | 所有者 2026-09-05 在三个选项里选定"收进二进制"。§13.2.2：`fluxd daemon` 成为监督进程，重新执行 `/proc/self/exe` 作为 reactor；reactor 持锁、开 socket、拥有全部内核对象；监督进程只认退出码与信号——`0` 退出、`3`（锁已被持有）退出不重启、其余按引擎同一张 1/2/4/8/30 s 表重启并在稳定 60 s 后重置。不给 reactor 设 PDEATHSIG：监督进程被杀只是失去监督，代理继续工作。§23.1 第二实例的退出码从 1 改为 3，`service.sh` 变成一行 `exec` |
| 26 | §23.1：状态根、`run/`、`config/` 的模式不是 0700 时 daemon 拒绝激活（`runtime_dir_mode`），"不自动 chmod，用户可能是故意改的" | 这三个目录是 Flux 自己创建、自己拥有的对象（§11.1），不是用户的文件；`/data/adb` 本身就是 root 专属，这个模式几乎不保护任何东西；而 `service.sh` 每次开机本来就 `chmod 0700` 一遍——开机静默改正、运行中却拒绝，两头矛盾，且 shell 在做本该由二进制做的事（PHIL-7） | 所有者 2026-09-05 在三个选项里选定"Flux 拥有自己的状态根"。`Layout::ensure()` 在每次启动与收敛时恢复 `root:0700` 并记一行日志；`service.sh` 只保证目录存在；唯一仍拒绝的是路径上是符号链接或非目录（`runtime_dir_type`）——那是外来对象，Flux 不替换不跟随（PHIL-5）。§23.1 两行改写 |
| 27 | §9.6：模板里任何 `flux-` 前缀的 tag 都被拒绝 | 机制真正需要的只是两个注入 inbound 的 tag 不被撞。前缀保留把外部数据也卷进来：订阅提供方把一个节点命名为 `flux-hk`，整份生成配置就失效——外部数据决定用户的代理能不能跑（PHIL-1） | 所有者 2026-09-05 选定收窄为精确匹配：只有 `flux-in-v4` / `flux-in-v6` 两个 tag 被拒绝，其余归用户与提供方。§9.6 改写，`RESERVED_TAG_PREFIX` 变为 `RESERVED_TAGS` |
| 28 | §28.2：只填 `outbounds` 为空数组的 selector/urltest；出厂 `PROXY=["DIRECT"]` 是为了让未订阅的 `check` 能过 | 原版 Flux 的 `PROXY` 指向空的地区组（HK/TW/JP/SG/US），填充发生在那些空组上，所以从来不会「Active 却全直连」。0.9.5 把模板简化成 `PROXY`/`GLOBAL` 两个组之后，占位 `DIRECT` 让填充规则看不见空位。2026-09-06 真机：29 个节点已追加、`route.final` 仍是 PROXY、状态已是 Active，流量全部 DIRECT，没有警告 | 2026-09-06 所有者定「模板按旧版来」。出厂模板换回原版形状（五个地区组 + `PROXY` 作为它们的菜单），另加一个 `AUTO` urltest 兜住命名不含地区的机场。旧版的地区组是空的，它能这样是因为 `updater.sh` 保证引擎先看到填好的配置；Flux 未订阅时把模板原样交给引擎，而**空组对引擎是致命的**——实测 1.13.19 的 `check` 与 `run` 都报 `initialize outbound[N]: missing tags`。所以各组出厂带 `DIRECT` 占位，§28.2 把「只有 `DIRECT`」视为空位，且**填不出成员就原样保留**（否则会把配置整份打死）。**同日被第 29 条取代** |
| 30 | D9 与 §1.4：硬性只接受 `app_id ∈ [10000, 19999]`，理由写的是「结构性保证 engine（root，uid 0）永远不在 `uid_policy` 中」外加「防止用户误选 system_server 把设备打死」 | 前半句真正需要的只是**拒绝 uid 0**——引擎固定以 root 运行，1000/2000 都不是它，选中它们不会造成回环。后半句是替用户做决定：他本来就是 root，而「用户点名要代理的东西被静默丢掉」正是本项目要避免的失败模式（PHIL-6）。2026-09-06 实测：所有者往清单里写了 `com.android.shell`（uid 2000），整份策略被拒、生效的仍是上一份，浏览器因此不走代理，而报错既没点名条目也没说清原因。另外数据面并不检查这个范围（`flux.bpf.c` 只用 `OVERFLOWUID`），`flux_abi.h` 的常量是给黑名单展开用的 | 所有者 2026-09-06 选定放宽：只永久拒绝 `app_id == 0`（以及会跨用户的 `app_id >= 100000`）；`packages.list` 里的其它 uid 显式写名字即可选中，`check` 与 `status` 点名警告，uid 1000 额外说明「代理不可用时 Android 会判定无网络」。黑名单展开仍只覆盖 `[10000, 19999]`，平台 uid 只能靠写名字进来。§1.4、§1.3.1、§7.4、§11.3 与 `flux_abi.h` 注释同步改写：承重的不变量从「范围」收窄为「uid 0」 |
| 29 | 第 28 条的处置：靠 `DIRECT` 占位与 `AUTO`，让未订阅的模板仍能交给引擎跑起来 | 所有者当日指出：「未订阅时把模板原样交给 sing-box」这条逻辑本身不对。占位与 `AUTO` 都是为了迁就它才存在的——**模板不是配置**。承认这一点之后，出厂文件就能与原版逐字一致（只留四处被迫的差异），不需要占位，也不需要 `AUTO` | 2026-09-06：§28.2 增加两条，都从同一个实测事实推出（空组对引擎致命）：① 某地区一个节点都没匹配上时该组变 `DIRECT`——不能让一个用不上的组把整份配置打死；② **一个节点都没有时整份候选被拒**（`engine_config_unfilled`，点名等待中的组与两种填法），冷启动停在 Inactive + Direct 并说明原因，而不是进入崩溃重启循环。另加告警 `nodes_unreferenced`：配置里有节点但没有任何组引用它们时，`check` 与 `status` 明说「被选中的应用仍然直连」。`xtask template-check` 随之改成两段：未填必须被拒，填上每个地区一个合成节点后官方 sing-box 必须接受 |

### 0.6.6 0.9.5 真机回归（2026-09-06，SM-S9180 / 5.15.211 / KernelSU 3.3.0 lkm）

从 `b4f367b` 打的 `Flux-rs-v0.9.0-arm64.zip`（sha256 `b129b812bedd47dedf4737a103b99f6f8271b937b3ca69a6e58a9fd7cf4b0a35`）卸载 0.9.1 形态后重装。卸载后重启：`/data/adb/flux-rs` 不在，`ip`/`tc` 无 `flxrs*`、无 pref 100、无 table 20260（§20 第 9 条，KernelSU 这一台）。安装日志打印新的三步引导，落地为禁用；`config/flux.toml` 是五个顶层表且带 `[ssid]`。

**订阅抓取在设备上结构性失败，下列「精修 / 填组」行用的是宿主机抓到的 `subscription.raw` 加 `subscription.url` 归属文件，其余都是设备上的守护自己做的。** 原因见本节末。

| 断言 | 实测结果 |
|---|---|
| 监督进程 + reactor 父子关系；锁在子进程 | `ps`：监督 2456（后为 2592）ppid 1、`fluxd daemon`；reactor 2549 / 2729 为其子。`run/daemon.lock` 写的是子进程 pid |
| `service.log` 开机三行、无循环 | boot 三行之后是事件行；无 `while`/`sleep` 痕迹 |
| 三个接口 `pref 2`、`reachable` | 蜂窝：`rmnet_data0/1/9`；重启后含 Wi-Fi：`rmnet_data1`、`rmnet_data8`、`wlan0`（`flx_cap_l2`）皆 `pref 2` / `reachable` |
| 捕获数 = assign 数 | `tcp 36 captured / 0 direct, udp 46 captured; assigned 36 tcp / 46 udp`（后 `status --json`：`admit_*` 与 `in_assign_*` 相等） |
| 真流量走节点 | 引擎日志 47 条 `outbound/hysteria2[香港01丨直连]: outbound connection to api.twitter.com:443` |
| `module.prop` 状态行 | `🥰 [Active] gen 3 · 5 apps · rmnet_data0, rmnet_data1, rmnet_data9` |
| 改模板无关字段换代；再 reload 不换代 | `log.level` error→info：generation 2→3，引擎 pid 变；不变模板再 `reload`：仍 generation 3、同一引擎 pid |
| 精修 + 填组（缓存喂入后） | 默认模板的 `PROXY=["DIRECT"]` **不会被填**（见缺口 2）。把 `PROXY` 置空后再 reload：generation 2，`PROXY` 29 成员，垃圾标签（流量/到期/官网）为零，注入 inbound `flux-in-v4`/`flux-in-v6` |
| 第二次 `fluxd daemon` 立刻以 3 退出并点名持锁 pid | 退出码 3，文案 `another fluxd instance holds the lock; not restarting`，点名 `run/daemon.lock` 里的 reactor |
| `kill -9` reactor：监督 pid 不变、1 s 后新 reactor | `service.log`：`reactor killed by signal 9; restarting in 1 s`；监督仍 2456；新 reactor 22313；引擎重启。代号从 1 重开（§10.6：守护重启删除产物、从权威文件重建） |
| `kill -9` 监督：reactor 与代理继续；再起被拒 | 监督死后 reactor 挂到 pid 1；`status` 仍 Active；再 `fluxd daemon` 以 3 退出并点名新锁持有者 |
| 管理器开关不重启 | `ksud module disable`：6 s 内 `Disabled`、引擎停、`😴 [Disabled]`；`enable`：新一代 Active，三接口就绪 |
| `clash_api` 空 secret 只告警 | `fluxd check` 退出 0，警告 `clash_api_secret_missing`；`status.warnings` 同一条 |
| `[ssid]` 为空时 `status.ssid` 为 null，reactor 无 `NETLINK_GENERIC` | `status --json` 的 `ssid` 空；`/proc/<reactor>/net/netlink` 协议 16 无该 pid |
| `[ssid]` blacklist 命中当前 Wi-Fi：暂停；删掉该项：恢复 | 干净 reactor 上：`wifi: connected · paused by [ssid] blacklist (entry 1)`，引擎停，`module.prop`：`😴 [Inactive] paused on this Wi-Fi network`。清空 list 后 generation 2、Active，三接口含 `wlan0` 再达 `reachable` |
| SSID 字节不进 `status` / `module.prop` / `fluxd.log` | 三处零命中当前 SSID 字符串；日志只写「1 associated station interface(s); [ssid] blacklist matched entry 1; paused」 |
| `bugreport` 不含权威文件与订阅 token | 默认写当前目录失败（见缺口 3）。`-o /data/local/tmp` 的 zip：无 `template.json` / `flux.toml` / `sing-box.<gen>.json`，无订阅 token/主机，目的域名为 `[domain-redacted]`。**引擎日志里的节点名未抹**（58 处 `outbound/hysteria2[…]`） |

未跑：批次 C 的设备侧 `fluxd subscribe`（抓取本身失败）；KernelSU WebUI 按钮（需人手）；Phase 3–7 设备套件；Magisk / APatch smoke（§20 第 10 条）。

**缺口 1 — 静态链接下订阅抓取永远解析不出域名。** `.cargo/config.toml` 给 `aarch64-linux-android` 加了 `+crt-static`；`llvm-readelf` 看产物是 `EXEC`、无 `INTERP`、无 `NEEDED`。Android 的 `getaddrinfo` 靠动态链接器注入 `libnetd_client` 才能问 netd；静态二进制没有这条注入，也没有 `/etc/resolv.conf`。root 下 `ping` 同一主机能解析，`fluxd` 报 `subscription_fetch_failed:io` / `failed to lookup address information: No address associated with hostname`（`failures.md` 承诺的类别是 `:dns`）。**处置（2026-09-06，所有者授权自行抉择）：去掉 `+crt-static`，动态链接 Bionic。** 自己实现 `dnsproxyd` 会把未文档化的 netd 协议变成产品依赖；写成发布边界等于 0.9.5 的订阅在唯一目标 OS 上不可用。§13.4 写明这一点。

**缺口 2 — 出厂模板的 `PROXY=["DIRECT"]` 挡住填组。** 见 §0.6.5 第 28、29 条。原版 Flux 没遇到，是因为它的 `PROXY` 指向空的地区组，不是 `DIRECT`。**处置：模板与原版逐字一致；没有节点可填时整份候选被拒，不再把模板交给引擎。**

**缺口 3 — `fluxd bugreport` 默认写 `.`。** root shell 的 cwd 是只读的 `/`，无 `-o` 时 `Read-only file system`。**处置：默认写到状态根。**

**附带观察（未升格为合同更正）。** reactor 经 `/proc/self/exe` 再执行后 `ps` 显示 `exe daemon`，不是第二个 `fluxd daemon`。`kill -9` reactor 之后立刻切默认路由到 `wlan0`，同一进程内收敛卡在 `tc_filter:ESTALE`（`recorded filter is no longer exact-owned`），`disable`/`enable` 清不掉，重启后消失——像进程内记录与内核对象对不上，不是设备上的永久残留。

**2026-09-06 补测（`eed47c6`，同一台设备）。** 动态链接后的 zip（sha256 `84adaede…ddb39dc`，`NEEDED`: `libdl.so`、`libc.so`）重装并重启：冷缓存 `fluxd subscribe` 在设备上抓取成功（`subscription cache committed atomically`，18665 字节），`last error: none`。出厂 `PROXY=["DIRECT"]` 的模板生成 32 个 outbound、`PROXY` 29 成员。内容不变的第二次 `subscribe` 不换代。`ps` 现为两个 `fluxd daemon`。无 `-o` 的 `bugreport` 写到 `/data/adb/flux-rs/`。

**2026-09-07 原版模板逐字复测（第 29 条之后，同一台设备）。** 出厂模板与原版逐字一致（五个空地区组、无 `AUTO`、无占位）。① 未订阅（`url = ""`）：`fluxd check` 以 `engine_config_unfilled` 失败并点名 `groups HK, TW, JP, SG, US`；重启后停在 `Inactive` / `generation 0`，`module.prop` 显示 `🤯 [Inactive] engine_config_unfilled`，**设备上零个 `sing-box` 进程**，日志里只有 `engine candidate rejected: engine_config_unfilled` 逐事件重试，没有崩溃重启循环。② 填回订阅 URL 后 `reload`：Active、generation 1、37 个 outbound，`HK` 7、`JP` 8、`SG` 8、`US` 6、**`TW` 因为该机场没有台湾节点变成 `DIRECT`**，`PROXY`/`GLOBAL` 原样；真流量 `tcp 25/25`、`udp 30/30`，无 `nodes_unreferenced` 告警。

顺带（非本次改动引入）：冷启动候选被拒时 `status` 的 `policy` 行显示 `0 selected`，因为 §8.7 规定这种情况只做残留清理、不建 BPF 运行时——策略确实没进内核。任何冷启动配置错误都是这个表现。

**2026-09-07 dashboard 注释块实测（同一台设备）。** 出厂状态：`fluxd check: ok`，不再有 `clash_api_secret_missing`——注释块对解析器完全惰性。取消注释并填入一个测试 secret 后：`check: ok`、`reload` 换代、引擎带 `clash_api` 起来；`/version` 带正确 secret 返回 `{"meta":true,"premium":true,"version":"sing-box 1.13.19"}`，不带或带错 secret 均 401；`/ui/` 返回 200，zashboard 按 `external_ui_download_detour: PROXY` 经代理下载到 `/data/adb/flux-rs/zashboard`（引擎 cwd 就是状态根）。换回出厂模板并 `reload` 后端口关闭（curl 得 `000`），说明前置逗号写法取消注释即为合法 JSON，且开与关都可逆。

**2026-09-07 放宽 appId 范围后实测（第 30 条，同一台设备）。** 所有者的 18 项清单（含 `com.android.shell`，uid 2000）应用成功：`policy: apps whitelist (18 selected)`，`last error: none`，并带一条点名警告 `0:com.android.shell is uid 2000, a platform uid rather than an app: …`。端到端判别：`curl http://icanhazip.com` 以 root（uid 0，永不可选）执行返回本地出口 `123.151.200.37`，以 shell（uid 2000，已选中）执行返回节点出口 `8.216.47.244`，同时 `admit_tcp`/`in_assign_tcp` 从 149 同步涨到 150。清单里两个本机未安装的包（`com.openai.chatgpt`、`proton.android.pass`）仍按 §11.3 第 3 条整份拒绝，报错各自点名——修复前它只报「app id 2000 is out of range」，既不点名也不说原因，用户改完配置只会看到「浏览器还是不走代理」。同一条 `cn`/`cnip` 规则让 `ifconfig.me` 在两侧都返回本地出口，那是模板的设计行为而不是失效。

**2026-09-06 旧版形状首测（模板换回原版 + `AUTO` + `DIRECT` 占位，已被上一段取代）。** 清掉订阅缓存、装回出厂模板后重启：开机自行抓取订阅并 Active（generation 1，38 个 outbound）。填充结果：`AUTO` 29 个节点，`HK` 7、`JP` 8、`SG` 8、`US` 6，**`TW` 保留 `DIRECT`**——这个机场没有台湾节点，填不出成员就原样保留；`PROXY`（`AUTO, HK, TW, JP, SG, US`）与 `GLOBAL` 是写好的菜单，未被改动。真流量：`tcp 35 captured / assigned 35`、`udp 41 / 41`，引擎日志新增 `outbound/hysteria2[香港01丨直连]`，即 `route.final` → `PROXY` → 首成员 `AUTO` 走到了真节点，不再是静默直连。

### 0.6.7 一次 Wi-Fi 切蜂窝打死整个代理（2026-09-07，SM-S9180 / 5.15.211 / KernelSU 3.3.0 lkm）

§0.6.6 末尾那条「附带观察（未升格为合同更正）」不是残留，是 bug。所有者报「手机使用流量时 flux 报错」，现场就是它：`state: Inactive`、`engine: not running`、`last error: tc_filter:ESTALE`、`warning: recorded filter is no longer exact-owned`、`ifaces` 为空数组，自当日 07:34 起持续四小时；`fluxd reload` 每次复现同一条；`rmnet_data0` 的 egress 上一条 filter 都没有，clsact 还在。

**根因。** `admit_interfaces` 在接纳接口之前，先删掉自己记录在「已不在候选集里」的接口上的 egress filter，走 `detach_identity`。后者把「两次 dump 里都找不到自己记录的那条 filter」判为 `tc_filter:ESTALE` 并抛出，`?` 让它穿过 `converge_inner` 成为 `status.error`，reactor 于是打出 `data-plane convergence blocked`、停引擎、进 Inactive。但接口离网时 netd 会删掉它的 clsact（§8.5.1），filter 随之消失——所以这条错误**不会自行清除**：记录指向的对象已经不存在，此后每次收敛都在同一处失败，`ifaces` 因此连一条都产不出来。这正是 §26 不变量 4 禁止的「把 capture-side drift 升格为全局事务」，代价也正是那条不变量预告的那一个：一次 Wi-Fi 切换掐断全设备的代理流量。

**复现（修复前二进制，蜂窝 → Wi-Fi → 蜂窝）。**

| 步骤 | 实测 |
|---|---|
| 蜂窝下 Active，`svc wifi enable` | 四接口，`wlan0 active (flx_cap_l2, pref 2, reachable)` |
| `svc wifi disable`（切回流量） | 15 秒内 `Inactive` / `engine: not running` / `last error: tc_filter:ESTALE`，`ifaces` 空 |
| `fluxd reload` | 日志再打一条 `data-plane convergence blocked: tc_filter:ESTALE`，状态不变 |
| `kill -9 <reactor pid>` | 新 reactor 立即 Active、三个 rmnet `reachable`——**唯一坏掉的是进程内那条记录** |

**处置（代码改，合同不改；§8.5.1 与 §26 早已写明该怎么做）。** `detach_identity` 不再把「记录对不上」当失败：dump 里没有自己那条 filter，就是没有可删的东西——被 netd 带走，或槽位已被别人占据，两种情况下要删的对象都不在，而 Flux 只删逐项精确匹配的自有对象；接口本身已经消失（dump 报 `ENODEV`/`ENOENT`）同理。仍然报错的只剩三种，它们都意味着那条 filter **还在**：两次 dump 之间身份变了、程序 map 集变了、删除本身失败。另外给这三条 ESTALE 文案补上接口名——修复前那句 `recorded filter is no longer exact-owned` 不带任何接口信息，是这次定位里最慢的一段。

**验证（修复后二进制，同一台设备，替换 `bin/fluxd` 后重启走真实开机路径）。**

| 断言 | 实测 |
|---|---|
| 开机在蜂窝上 Active | `generation 1`、引擎 pid 2773、`rmnet_data0/1/9` 皆 `reachable` |
| 开 Wi-Fi | `wlan0 active`，`rmnet_data0` 因默认路由归 Wi-Fi 退出候选集，`last error: none` |
| 关 Wi-Fi（即复现步骤） | **`Active` 不变、`generation 1` 不变、引擎 pid 2773 不变**，`last error: none`，三个 rmnet 重新 `active` |
| 连续三轮开关 | 同上；`admit_tcp` 81→88、`admit_udp` 111→113 持续增长，`drop_inactive` / `drop_stale_gen` / `egress_listener_miss` 全为 0 |
| 日志 | 修复后 113 行里 `ESTALE` 与 `data-plane convergence blocked` 各 0 条（最后一条 `04:08:23Z` 属修复前的复现） |

门禁：`cargo fmt --check`、`fluxd` + `flux-core` 181 项测试、aarch64 与宿主 `clippy -D warnings`、`template-check`、`doc-check` 全过。

**打包安装复验（`c6a3c6a`，同一台设备）。** `cargo xtask package` 产物 `Flux-rs-v0.9.0-arm64.zip`（sha256 `566f10c89de5…c58504fa`，provenance 干净、无 `-dirty`，`NEEDED`: `libdl.so`/`libc.so`）经 `ksud module install` 装入 `modules_update`、重启后落到 `modules/flux_rs`。`bin/fluxd` sha256 `1d99dec31946…25812c19` 与 ZIP 内一致。开机 Active；两轮 `svc wifi disable` 切回蜂窝：`Active` / `generation 1` / 引擎 pid 2766 全程不变，`admit_*` 与 `in_assign_*` 相等，`last_error` 空，日志里自本次开机起零条 `ESTALE` 与 `convergence blocked`（最后一条仍是修复前复现的 `04:08:23Z`）。

**附带观察。** 卡死那四个小时里，日志被 652 条 `BPF fault: generation=6 … reason=1` 加同样多的 `ignored stale/repeated BPF fault` 刷到 600 KB。这不是第二个 bug：代 6 被冻结后，属于它的旧 TCP 流仍在发包，而 §7.4 规定旧代事件「只清 latch 然后忽略」，清掉的 latch 让下一个包再报一次。§7.4 承诺的是「稳态无事件风暴」，而这个状态本不该稳态存在——修复后 113 行日志里 `BPF fault` 为 0。

### 0.6.8 1.0.0 候选设计与实现复核（2026-09-15，Windows / WSL）

**范围与判断。** 从 `aa4715d09af0a45e68ce40123b54a6971f267ebf` 的干净工作树开始，在 `codex/v1.0.0-review` 准备本地审核改动。读取哲学、治理、作者规则、蓝图、交互合同、架构和使用指南、实施计划与历史记录，再核对纯逻辑、BPF loader、数据面收敛、引擎事务、订阅 worker、检查命令、打包和 CI 的对应实现。结论是保留 UID/TC + 官方引擎、一个 reactor 协调两个事务域的主路线；改进集中在减少重复真相和错误的职责归属。所有者在审阅过程中重申：**优雅、简洁高效，尽可能从根本上避免问题，不做层层兜底和门禁。** 这是本轮取舍依据，符合 PHIL-1、PHIL-2、PHIL-4、PHIL-6。

**原说法 / 实际 / 处置。**

| 项目 | 原说法或实现；实际证据 | 处置与根因 |
|---|---|---|
| 首次使用 | 指引要求先 `check` 通过再启用；但默认模板需要首次订阅才能填满，且 `check` 是只读命令。保存配置后要求手工 `check → reload` 也与现有 inotify 自动处理重复 | §27.5、README、指南和安装提示统一为填写配置 → 管理器启用并首次重启 → 查看状态。完整候选由已有启动事务验证；`check` 是诊断工具。消除人工前置条件，激活事务的失败语义保持不变 |
| JSONC | 删除注释会把 `1/* comment */2` 拼成 `12`，接受 `{} /* unfinished`，并把跨行注释后的错误从第 4 行报成第 3 行；两个聚焦测试在旧实现上均失败 | 注释按原字节跨度替换为空白，保留 CR/LF 和字符串内容；未闭合块注释由 JSON 解析器拒绝。错误状态在词法转换处消除，§9.6 记录语义 |
| 构建目录 | Cargo 按环境或配置选择输出目录，xtask 却从仓库 `target/` 取二进制并清理该目录；两次“干净构建”可能读取同一旧文件 | 由 `cargo metadata` 提供产物根，显式传给编译并从该目录读取；复现运行各用新建目录。删除旧的清理仓库交叉编译目录函数，避免猜路径和复用旧产物。真实 Cargo fixture 验证配置及环境变量两条路径；§13.4 对齐 |
| 内核兼容性归属 | §1.6.3a 已要求避开 LPM 崩溃窗口，代码却只在 reactor 解析策略时检查；`check` 和直接调用 loader 的设备测试能绕过它。旧版本解析还会把 vendor 后缀中的数字当作补丁号 | 将既有排除规则收归 BPF loader，调用方无需记住先检查；解析版本主段，不增加型号列表或额外检查层。受影响 release 搭配空 ELF 的测试在解析/系统调用前返回原稳定错误 token；修复版本仍进入正常 ELF 解析 |
| BPF 产物测试 | 开启 `FLUX_BUILD_BPF=1` 后，原测试断言 `flx_cap_l2` 为 992 条指令，实际为 1235；数字源自 `a648cd4` 的 Phase 4。普通测试用空占位物，BPF CI 又只 build，断言一直未执行 | 用程序名、段名、ABI 与 map 引用集合替换精确指令数；现有 BPF CI 编译步骤改为运行同一组真实产物测试。算法或编译器变化不再要求维护第二组数字；真实装载/挂载仍由相应验证器及设备测试证明 |
| 架构文档和依赖 | §10.2 的伪 Rust 定义已经与实际字段、UID 范围和接口不同；§5 的依赖清单、单 `Runtime` 描述与订阅实现不符；bugreport 为格式化时间反向依赖 reactor | §10.2 改为模块输入、所有权和对调用方的保证，确切类型回到源文件。时间算法及原测试移到两方共用的 `time`；不引入公开 trait 或框架。§5、§14.2 按真实所有权和 worker 模型说明 |
| 其它文档事实 | README 仍描述已不存在的 Action 开关；指南把 `clash_api` 告警写成硬要求；治理文档宣称 Windows fluxd 没有测试；§12.1 宣称 CI 锁定 clang 并比对独立 BPF 哈希，§13.4 又称不重映射路径 | 修正为实际 WebUI 跳转、告警和平台测试范围；复现限定于同一工具链，路径按既有仓库映射和新的目标映射处理。未增加跨编译器一致性承诺或测试层 |

**PHIL-10 复核。** 机制仍由内部生成和拥有，用户只决定策略；新增逻辑处理外部文本和 Cargo 输出，没有把内部值交给用户维护。构建路径和类型定义各归唯一来源，日志与诊断没有反向依赖。生产侧没有新增预检阶段、周期探针或兜底重试；既有内核排除规则只有一处。清理只涉及本次独占创建的构建工作目录，内核对象删除仍依赖当前身份。没有新增运行期硬失败类别，也没有从参考项目搬入兼容层。xtask 复用工作区已有的 `serde_json`，锁文件只新增这一依赖边，没有引入新第三方包。BPF 源码与热路径未改，未把设计预算或指令数当作实测吞吐提升。

**验证环境。** Windows 宿主；WSL 内核 `6.18.33.2-microsoft-standard-WSL2`，Rust/Cargo `1.93.0`，系统 clang `21.1.8`，NDK `27.3.13750724`。WSL 构建目录均在 `/tmp`；Android 构建使用 NDK linker，BPF 使用系统 clang。

| 验证 | 当次结果与范围 |
|---|---|
| `cargo fmt --all -- --check`、`git diff --check`、UTF-8/LF/no BOM | 通过；仅规范化本轮改动文件 |
| Windows `cargo test -p flux-core` / `-p xtask` / `-p fluxd --bin fluxd` | 104 / 34 / 8 项通过；只代表 host-safe 范围 |
| WSL `cargo clippy --workspace --all-targets -- -D warnings` | 通过，嵌入真实 BPF 对象 |
| WSL `cargo test --workspace` | 104 + 79 + 34 = 217 项单元测试通过；daemon_e2e 和 engine_lifecycle 全场景通过；Phase 3–7 设备用例按预期跳过 |
| WSL `FLUX_BUILD_BPF=1 cargo test -p fluxd --bin fluxd bpf::` | 14 项通过，包含真实 ELF、map 重定位、内核排除规则与 ABI 拒绝路径 |
| Android `cargo clippy -p fluxd --target aarch64-linux-android --all-targets -- -D warnings` | 通过，嵌入真实 BPF 对象；不是 Android 执行结果 |
| `cargo xtask abi-check` / `btf-check` | 7 个结构、40 个字段偏移、34 个数值定义、28 个枚举成员、28 个字符串定义通过；`flux_decision` BTF size 16 与各字段偏移一致 |
| `cargo xtask template-check` | 官方 sing-box 1.13.19 接受填充后的默认模板；未填充模板不进入引擎 |
| shellcheck / `tools/phase8/module_lifecycle_test.sh` | 通过；以非 root WSL 用户执行时 fixture 的 `chown root` 报权限不足，因此不将此结果计作设备 root 权限或管理器安装验收 |
| `cargo xtask doc-check` | 通过：章节、链接、引用、ABI section 名、历史编号、xtask 命令及文档路由检查 |
| `cargo xtask verify-package` | 最终安装提示修改后重跑，两次独立完整交叉构建 ZIP 字节一致；15 个 allowlist 文件，包内安装脚本与默认配置逐字节匹配工作树 |

**本地审核产物。** `dist/Flux-rs-v0.9.0-arm64.zip`，SHA-256 **`b6b1a50b29149b5d9a3c32a45d5fab5e8a32c5d11dbd14590eab16f95da4ded8`**，与 `dist/SHA256SUMS` 一致。最终两次构建目录为 `/tmp/flux-rs-v1-review/xtask/verify-package-533-0/run1` 和 `run2`，成功后由打包工具清理。官方 engine 的 archive/binary 大小和 SHA-256 均符合 `engine.lock`；4 个 LOAD 段为 `0x1000`；fluxd 的 4 个 LOAD 段均 ≥ `0x4000`。

产物版本仍取现有 workspace 的 `0.9.0`；构建标识为 `aa4715d09af0a45e68ce40123b54a6971f267ebf-dirty`，代表本地待审工作树，**不是正式 1.0.0 发布物**。本轮没有运行远端 CI、设备装载/转发或三管理器真机验收，也没有重新生成对应源码发布物；旧设备记录不替代候选证据。审核与发布的剩余动作统一在 §17.0.3。
