# Flux-rs 0.9.0 终极设计蓝图与开发指南

- 文档编号：`FLUX-BP-0.9.0-FINAL`
- 日期：2026-08-25（Asia/Hong_Kong）
- 性质：**唯一实现合同**。取代 `audit/2026-08-24-final-ebpf-blueprint/final-blueprint.md`（`FLUX-BP-0.9.0`）与 `audit/2026-08-25-flux-rs-0.9.0-impl-blueprint/implementation-blueprint.md`（`FLUX-BP-0.9.0-IMPL`）。二者冲突处一律以本文为准。
- 读者：实现者（人或模型）。本文假设读者不了解旧仓库，也不需要读旧文档。
- 配套文件：`reference/flux_abi.h`（BPF/用户态共享 ABI 真相源）、`reference/flux.bpf.c`（数据面骨架）。

## 术语强度

| 词 | 含义 |
|---|---|
| **必须 / 禁止** | 实现合同。违反即实现错误。 |
| **建议** | 默认工程选择，可在记录理由后更换。 |
| **已核验** | 我在本轮独立核对过一手内核源码 / 官方文档 / 官方配置，并在文中给出依据。 |
| **待证** | 单项机制有依据，但**组合**必须由 Phase 0 在真机闭环证明。不得写成"已支持"。 |

代码块中的 C/Rust 是签名与算法骨架，用于消除歧义；实现者补全函数体、错误路径与测试。

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

## 0.3 我对前两版蓝图的修正（D1–D18）

以下每条都是**本文与旧蓝图的实质差异**，实现者必须按本文执行。

| # | 旧蓝图做法 | 本文做法 | 理由 |
|---|---|---|---|
| **D1** | egress 对每个 packet 做 `bpf_sk_lookup_tcp()` 反向查找 app full socket，再取 SK_STORAGE | 直接 `bpf_sk_fullsock(skb->sk)` 取 full socket | 省掉每包一次 socket hash 查找；并消除"反查到错误 socket / `sk_bound_dev_if` 不匹配导致查不到"的正确性风险。已核验 helper 可用且不需 release。 |
| **D2** | 每 generation 注入 **4 个** inbound（actual v4/v6 + sentinel v4/v6，8 个 kernel socket），sentinel 带随机 `routing_mark` 作特权守卫 | 只注入 **2 个** inbound（`flux-in-v4` / `flux-in-v6`，4 个 kernel socket），删除 sentinel、mark、reject rule 与 egress 的第二次 lookup | sentinel 防御的是"恶意本地 app 抢绑"，而两版蓝图都在威胁模型里**明确声明不抵抗**该攻击。它保护的性质（liveness / 换代 fail-open）由 actual listener 的 lookup 已经完全提供。删掉去掉 2 个 inbound、4 个 socket、1 个 mark、1 条 route rule、1 次热路径 lookup 和整套 mark 语义。 |
| **D3** | 内部以太头 source MAC 由 generation 一一编码（46 bit），boot 内禁止复用，ingress 逐包比对 | **不做 generation 编码**，不比对 MAC；来源边界就是设备本身。（本条最初还保留了"写固定 MAC pair"，后被 **D17 进一步取消**——egress 完全不写 MAC） | 该编码只防"换代瞬间 in-flight 的旧 packet 被错送给新 engine"。其后果是无害的：旧 SYN 被新 engine 当作一条新连接；旧 established 数据包在 ingress 不 assign、内核查不到 socket 直接 RST。用 46-bit 编码方案 + 逐包 6 字节比对换这个，是负收益。 |
| **D4** | `flx_in` 内置由 `anchor_probe` 控制的 dead branch，使 program 持有全部 map 引用；crash 后从 TC program ID "reclaim" root maps，不可核验时禁止 detach | **删除 anchor 分支与 reclaim 机制**。daemon 启动时删除全部精确自有残留对象并重建 | reclaim 保护的是"已入场 TCP 的 SK_STORAGE 不丢失"，但 fluxd 死亡时 engine 因 `PDEATHSIG=SIGKILL` 必然一起死，那些 flow 已经无处可去。真正承担 fail-open 的是 **redirect 前的 listener lookup**（engine 没了 → lookup miss → 新流 Direct），它与 reclaim 无关。且 anchor 方案依赖"编译器不消除 dead branch"，还要用 `BPF_OBJ_GET_INFO_BY_FD` 事后验证——这是脆弱且不必要的复杂度。 |
| **D5** | policy 热更新流程：publish `active=0` → 改 map → publish `active=1`；失败用内存快照回滚 | policy 热更新**不动 `active`**：先加（新 SELECTED / 新 bypass），后减（旧 UID 降级 DRAINING / 删旧 bypass）；失败不回滚，由 level-triggered reconcile 重算收敛 | 旧做法让"用户增删一个 app"这种低风险操作把**所有在场 TCP 连接的 packet 打成 drop**（`active=0` 期间 CAPTURED 必须 SHOT）。而 map 非原子更新的唯一后果是"窗口内的**新**连接看到混合策略"——新连接无论走 direct 还是 proxy 都是良性的。同时删掉快照/回滚代码，改用幂等收敛。 |
| **D6** | 所有 IPv4 fragment / IPv6 Fragment Header 一律 Direct | ① 已有决策的 socket **不解析 L4** 直接按决策处理，因此已入场 TCP 的 fragment 跟随决策进入代理；② selected+active 的 UDP fragment 先按目的做 LPM bypass，未命中则 **drop**，绝不 direct | 旧规则是**数据泄漏**：一条已被代理的 TCP 流一旦发生 IP 分片，分片会被送到真实目的地。UDP 同理（首片进代理、后续片直连，既泄漏又破流）。修正后既无泄漏，又顺带让 CAPTURED 快路径省掉 L4 解析。 |
| **D7** | 固定 bypass 只有回环/链路本地/多播 | 固定 bypass 追加 `198.18.0.0/15`、`2001:db8::/32`（listener 保留地址）；并由 reactor 从 rtnetlink 把**本机所有已配置单播地址**作为 `/32`、`/128` 动态注入 bypass | 已核验 sing-box TProxy 回写会 `IP_TRANSPARENT` 绑定原目的；若 app 访问本机自有地址上的服务而被捕获，回写 bind 会与真实本地服务**端口冲突**（官方 issue #3646）。捕获本机地址本身也毫无意义。 |
| **D8** | package→UID 用 Android PackageManager 命令接口（`cmd package`），并解析 manifest 拒绝声明 `BIND_VPN_SERVICE` 的包 | 只读 `/data/system/packages.list` + `uid = user_id*100000 + app_id`；VPN provider 只在 `status`/`check` 里**告警**，不做硬门禁 | `cmd package` 走 binder，`service.sh` 在 late-start 运行时 `system_server` 可能未就绪，会引入启动顺序依赖与重试状态机。`packages.list` 是纯文件读取、可 inotify、无 binder。manifest 权限门禁需要 binder + 权限模型，而它防的只是"用户主动选了 VPN app"这一配置误用。 |
| **D9** | 未限制可选 UID 范围 | **硬性只接受 app_id ∈ [10000, 19999]**（Android `FIRST_APPLICATION_UID..LAST_APPLICATION_UID`）；拒绝 root/system/isolated/sdk-sandbox | 结构性保证 engine（root，uid 0）永远不在 `uid_policy` 中，无需任何"自排除"逻辑；同时防止用户误选 `system_server` 这类会把设备打死的 UID。 |
| **D10** | `build.rs` 用锁定版 `libbpf-rs`/`libbpf`，为 Android 静态构建 libbpf/libelf/zlib | **不链接 libbpf**（只 vendor 它的 header-only 宏，见 §12.1）。BPF 由 clang 编译，object 内嵌；加载器是 in-tree 的最小 Rust 实现（裸 `bpf(2)` + 自建 BTF blob + 按 map 符号名重定位） | ① 为 `aarch64-linux-android` 交叉构建 elfutils/libelf 是已知痛点；② 我们自著全部 ABI，不用 CO-RE，libbpf 的 99% 功能是负担；③ 本仓库现有 `crates/flux-platform/src/bpf/sys.rs`（661 行）已在同类设备上证明裸 syscall 路径可行；④ 交付物变成"纯 Rust + libc 单二进制"。 |
| **D11** | 只有一个 product crate `fluxd` | 三个 crate：`flux-core`（纯逻辑、无 libc、可在 Windows 上 `cargo test`）+ `fluxd`（Linux/Android 运行时）+ `xtask`（构建打包） | 开发主机是 Windows。单 crate 意味着**本地一条单元测试都跑不了**（整个 crate 会拉进 Linux 专有代码）。`flux-core` 承载配置解析、CIDR canonicalize、UID 计算、effective JSON 生成、版本推导等全部纯决策逻辑，这些恰好是最值得单测的部分。删除旧 `flux-platform`/`flux-testkit`。 |
| **D12** | 生产环境零 counter，只有 fault ringbuf | 增加 1 张 `PERCPU_ARRAY`（32 × u64），**只在决策/丢弃/故障事件上**自增，不在稳态每包上自增；`fluxd status` 读出 | "完全无可观测性"是真实的可用性缺陷：用户报"不生效"时无任何定位手段。per-CPU 自增在事件边上的成本是纳秒级且无锁。禁止 per-flow / PII / 地址级记录。 |
| **D13** | 删除工作树与 `.git`，`git init` 全新历史 | ~~保留仓库与历史~~ → **所有者 2026-08-25 决定：按旧蓝图执行，删除 `.git` 后重新 `git init`** | 我原本建议保留历史（删 `.git` 不可逆且对产品零收益：历史不进 ZIP、不影响 fresh-install 语义）。所有者选择干净重建。技术设计完全不受影响；唯一后果是旧实现与审计出处只能从 §18.1 的仓库外归档目录查证，**因此归档步骤从"建议"升级为"必须"**。 |
| **D14** | "新代码不得复制旧生产实现" | 数据面、策略/generation 机制**必须重写**；但 §18.3 列出的低层平台原语（rtnetlink 编解码、TC filter netlink、`bpf(2)` 封装、SEQPACKET、pidfd/进程、inotify、epoll）**应当移植并复审** | "全部从零"会把几千行已经调通的机械正确代码重写一遍，重新引入同类 bug。审计发现的缺陷集中在策略/抽象层，不在这些原语。 |
| **D15** | egress 直接写包 / 原位覆盖以太头 | 对 skb 的任何写入**必须**先经 `bpf_skb_store_bytes()` 或 `bpf_skb_pull_data()`，禁止对可能 clone 的 skb 做裸直写 | TCP 重传路径的 skb 是 `skb_clone()` 的，共享数据缓冲区；裸直写会**破坏仍在写队列里的原始 skb**。两个 helper 都会经 `skb_ensure_writable()`/`bpf_try_make_writable()` 解共享。 |
| **D16** | listener 绑定非本地地址但未把该地址纳入 bypass | `198.18.0.0/15` 与 `2001:db8::/32` 进固定 bypass | 否则 app 主动访问该地址段会被捕获并送进 listener，构成自环。 |
| **D17** | egress 改写内部以太头的 dst/src MAC 以满足 `eth_type_trans()` | **egress 不改写 MAC**；ingress 调 `bpf_skb_change_type(skb, PACKET_HOST)`。control 结构删掉 `peer_mac`/`host_mac` | 见 §8.2 的对照表。结果：**L2 捕获稳态零 packet 写入、零 clone 复制**（TCP 重传 skb 是 clone，写它必然触发 `skb_ensure_writable()` 复制一份）；L3 只写 2 字节 EtherType；control 结构 104 → 96 字节。上游先例见 dae 的 `tproxy_dae0peer_ingress`。 |
| **D18** | 系统 DNS 不在捕获范围（前两版蓝图与我前几轮的结论都错） | **系统 DNS 精准 per-app 捕获，零额外机制。** 因为 AOSP 用 `fchown()` 把明文 DNS socket 的 owner 改成发起解析的 app，而 `bpf_get_socket_uid()` 读的 `sk->sk_uid` 跟随 `fchown` | 见 §1.3.1–§1.3.4。这是本轮最重要的发现：`xt_owner` 读 `f_cred->fsuid` 所以看不到，eBPF 读 `sk_uid` 所以看得到——**整个 iptables 生态被迫全设备劫持 :53 的根因就在这里**。连带作废了前几轮设想的 `cookie_tag_map` 路线（不再需要读 AOSP 私有 map）与"engine 换专用 UID"的前提。 |

## 0.4 我保留的旧蓝图关键结论

- **4 KiB base page only**。官方 `sing-box-1.13.19-android-arm64` 资产四个 `PT_LOAD` 的 `p_align` 全为 `0x1000`，不满足 AOSP 16 KiB ELF 要求。0.9.0 在 `sysconf(_SC_PAGESIZE) != 4096` 时保持 Inactive/Direct，不启动 engine、不建数据面。不重编上游、不用 app 兼容模式冒充原生支持。
- **`TC_ACT_UNSPEC` / first-applicable classifier** 合同（§8.5）。
- **map-in-map + freeze 的不可变 control snapshot 发布协议**（§6.4）。
- **generation 单调、pointer swap 是唯一 commit point**（§9.4）。
- **不 attach cgroup、不写 Android fwmark、不动 netd RPDB、永不删除 `clsact`**。
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

在 Android 15/16 的 root cgroup（`flags=0` 被 netd 独占）上，这条路径必然走完全程：`link.AttachRawLink` 失败 → MULTI 因 flags 不匹配返回 `EPERM` → **`flags=0` 覆盖掉 netd 的程序**。而 `common/ebpf/cgroup_attachment.go:42` 的清理只 detach 名字前缀为 `sb_ebpf_` 的程序：

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

**结论**：dae 的 per-process 能力依赖的正是 Android 已独占的那几个 attach type。它的 TC 数据面原语（TC → veth → `bpf_sk_assign`）可以借鉴，它的进程身份机制不能。

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

**唯一没能核实的**：`accept_local` / `rp_filter` 在各厂商内核上的实际默认值（AOSP 自己从不设置这四个 sysctl，值完全来自厂商 defconfig 与 `init.rc`），以及模块 SELinux 域能否写 `/proc/sys/net/ipv4/conf/*/accept_local`。两者都已在 Phase 0 有对应条目，处置方式是运行时读取 + 失败即响亮报错。

---

# 第 1 部分：产品合同

## 1.1 身份（唯一值）

| 项 | 值 |
|---|---|
| 产品 / 仓库 | `Flux-rs` |
| 首发版本 | `0.9.0`；git tag `v0.9.0`；`versionCode=9000` |
| root module id | `flux_rs`（管理器安装到 `/data/adb/modules/flux_rs`） |
| 产品状态根 | `/data/adb/flux-rs`，`root:root 0700` |
| ABI / target | `arm64-v8a` / `aarch64-linux-android`，API 31 |
| 构建 API level | `aarch64-linux-android` API 31（编译目标，非运行门禁） |
| 内核基线 | **5.15**（所有者 2026-08-25 决定）。真实门禁是运行时 load/attach/行为成功，禁止按版本字符串放行。实际后果：首发 Android 12 设备（GKI 最高 5.10）不在支持范围，可支持设备基本等于 Android 13 及更新的首发机型 |
| base page | 只支持 `4096`；其它值 Inactive/Direct |
| root 管理器 | Magisk / KernelSU / APatch 共同模块信封 |
| 引擎 | 官方 sing-box，版本由 `engine.lock` 权威（首发 `1.13.19`），零 patch |
| 许可证 | Flux-rs 自有代码 `GPL-3.0-only`；第三方按原许可证 |
| 数据面 ABI | `FLUX_ABI_MAGIC`（见 `reference/flux_abi.h`），与 SemVer 无关 |

## 1.2 0.9.0 必须做

1. 把 `userId:packageName` 精确解析为 UID，公开 shared UID 合并语义。
2. 捕获选中 UID **主动发起**的本机 IPv4/IPv6 TCP client flow（在首个 `SYN && !ACK` 上做一次不可变决策）与该 UID 发出的 IPv4/IPv6 UDP datagram。
3. 在 eBPF 内执行固定安全 bypass、本机自有地址 bypass 与用户 CIDR bypass。不解析域名。
4. **精准 per-app DNS**：被选中 app 的明文 DNS（含经系统解析器发出的那部分）随其它流量一起进入 engine，未选中 app 的 DNS 不受影响。机制与边界见 §1.3。
5. 保留原始 L3/L4 header，把 packet 交给官方 sing-box TProxy inbound。
6. 管理 sing-box 的 `check`、启动、候选切换、退出与崩溃恢复。
7. 由 rtnetlink / inotify / pidfd / signalfd / BPF ringbuf / 控制 socket / timerfd 驱动状态变化，**无周期轮询**。
8. 对未知设备布局、能力不足、对象冲突、未支持路径保持 Direct，并在 `status` 给出逐项原因。
9. 生成单一干净 module ZIP，供三管理器安装。

## 1.3 0.9.0 禁止做（非目标）

热点 / tethering / LAN ingress / bridge / forwarded traffic；被动入站 TCP 服务端代理；ICMP/ICMPv6/ESP/IPv6 jumbogram；VPN TUN 嵌套 / 接管 / 绕过；网关 / 旁路由 / 容器 / 多 netns；nftables / iptables / TPROXY mark 后端 / 运行时后端选择器；TUN 后端 / 用户态 TCP-IP 栈；**任何 cgroup BPF attach**（含 child `SETSOCKOPT`/`POST_BIND`）；SOCKMAP / `pidfd_getfd` listener handoff；eBPF 内域名/DNS/SNI/规则集/节点选择/连接质量学习；多代理核心 / 多模式 / 插件 / backend registry；WebUI / Flux 自有 Clash 代理层；远程 subscription；在线学习与统计驱动的策略自创；recovery 安装 / 32 位 / x86 / riscv；16 KiB base page；宽泛 SELinux patch；替换 AOSP BPF 程序 / 清空系统 qdisc/rule；旧 Flux 安装的检测/迁移/拒绝/清理；为未来版本预建 schema registry / migration framework / 兼容矩阵。

### 1.3.1 DNS：精准 per-app，机制是 AOSP 自己的 `fchown`

**关键事实（`clone/aosp-DnsResolver` 逐行核对）：Android 默认就把明文 DNS socket 的 owner 改成发起解析的那个 app。**

- `res_send.cpp:789` 与 `:1092`：`const uid_t uid = statp->enforce_dns_uid ? AID_DNS : statp->uid;`——`statp->uid` 是请求者 UID（由 `DnsProxyListener` 从 dnsproxyd 的 peer 凭据取得）。
- `resolv_private.h:245-256`：`resolv_tag_socket()` 先调 netd 的 `tagSocket(sock, TAG_SYSTEM_DNS, uid, pid)`，**紧接着执行 `fchown(sock, uid, -1)`**。
- `binder/android/net/ResolverOptionsParcel.aidl:48-57` 原文：

  > "The default behavior is that plaintext DNS queries are sent by **the application's UID using `fchown()`**. DoT are sent with an UID of AID_DNS. … **false: set application uid on DNS sockets (default)**"

内核侧，`sk->sk_uid` 的定义本身就包含 `fchown`。Linux commit `86741ec25462`（"net: core: Add a UID field to struct sock"，作者 Lorenzo Colitti 是 Android 网络工程师，这个字段就是为这类归属需求加的）写明：the UID is set when userspace calls **`socket()`、`fchown()` 或 `accept()`**；实现是 `sockfs_setattr()` 在 `ATTR_UID` 时同步 `sock->sk->sk_uid`。而 `bpf_get_socket_uid()` 读的正是 `sk->sk_uid`（`net/core/filter.c` → `sock_net_uid()`）。

**结论：TC egress 上 `bpf_get_socket_uid(skb)` 对 netd 发出的明文 DNS 包返回的是发起解析的那个 app 的 UID。** 于是 §7.3 的 `uid_policy` 查表**天然**覆盖系统 DNS——不需要端口特判、不需要读 AOSP 私有 map、不需要改 engine UID、不需要全设备劫持 :53。**这就是精准 per-app DNS 分流，零额外机制。**

注意最后一行的自环问题：**engine 自排除依然成立**。sing-box 以 root 运行，它自己的上游 DNS 查询是 uid 0，永远不在 `uid_policy`（§1.4 只接受 appId 10000–19999）。所以我们既捕获了 app 的系统 DNS，又不会吞掉 engine 的 DNS。全设备劫持 :53 的方案必须靠专用非 root UID 才能达到这个效果，我们免费获得。

原先的判断表因此**整体作废**，正确的表是：

| 谁发出的 DNS | TC egress 看到的 `sk_uid` | 是否被捕获 |
|---|---|---|
| 选中 app 自己开 socket（Cronet、QUIC 内 DNS、直接 `sendto(:53)`） | 该 app | **是** |
| 选中 app 调 `getaddrinfo()` → netd 发明文 UDP/TCP:53 | **该 app**（netd `fchown` 过） | **是** |
| 未选中 app 的 DNS | 该 app（不在 `uid_policy`） | 否——这正是我们要的 |
| Private DNS（DoT/DoH） | `AID_DNS`(1051) | 否，见 §1.3.3 |
| sing-box 自己的上游 DNS | root(0) | 否——自环天然避免 |

**若改为全设备捕获系统 DNS**（§21.1 Q2 选项 B），代价是：① engine 必须换成专用非 root UID，否则捕获 uid-0 的 :53 会把 engine 自己的上游 DNS 也吞进去形成死循环（或者必须强制用户的 `dns` 只用 DoH/DoT 并加一个校验器）；② DNS 变成全设备行为，**未被选中**的 app 的 DNS 也会走代理，于是出现"DNS 走代理、流量走直连"的反向错配；③ 还得处理 **Private DNS**——`clone/box4magisk/box/scripts/box.service:50-58` 在运行期间直接 `settings put global private_dns_mode off` 并在停止时恢复，因为 DoT 走 853 端口、不是 :53，劫持 53 根本抓不到它。也就是说选项 B 的完整形态包含"替用户关掉系统的加密 DNS"。这三点必须一起接受，不能只要好处。

### 1.3.2 为什么 iptables/TPROXY 派做不到，而我们做得到

差别不在 Android，而在**两个机制读的是 `struct sock` 的不同字段**：

| 机制 | 读的字段 | 看得到 netd 的 `fchown` 吗 |
|---|---|---|
| `iptables -m owner --uid-owner`（`xt_owner`） | `skb->sk->sk_socket->file->f_cred->fsuid`——**打开该 socket 的进程的凭据** | **看不到**。`fchown` 改的是 inode owner 与 `sk_uid`，不改 `f_cred` |
| **`bpf_get_socket_uid()`** | **`sk->sk_uid`** | **看得到**（commit `86741ec25462` 的语义） |

AOSP 自己的测试注释把这件事写死了（`clone/aosp-DnsResolver/tests/resolv_test_utils.h:48-49`）：

> "netd calls `fchown()` on the DNS query sockets, and **`iptables -m owner` matches the UID of the socket creator, not the UID set by `fchown()`**."

**这一句解释了整个生态的行为。** 那些 root 模块不是"选择"了全设备劫持 :53，而是被 `xt_owner` 逼的——它们的 per-app 匹配对 DNS 天生失效，只能退回端口劫持，于是不得不承担"未选中 app 的 DNS 也走代理"的反向错配，以及"必须替用户关掉 Private DNS"。下表是它们的实际做法；现在应当理解为**同一个约束下的不同妥协**，而不是可借鉴的设计：

| 项目 | per-app 选择 | DNS 处理 | 证据（`clone/` 内一手源码） |
|---|---|---|---|
| AndroidTProxyShell | `APP_CHAIN` 里 `-m owner --uid-owner "$uid" -j ACCEPT/RETURN` | `DNS_HIJACK_PRE` / `DNS_HIJACK_OUT` 是**独立的链**；`redirect2` 模式对 `nat OUTPUT` 全局 `--dport 53 -j REDIRECT`，只在前面按 uid/gid 放行 core | `tproxy.sh:1226/1242`；`tproxy.sh:1342-1372` |
| box_for_magisk（BFR） | `-m owner --uid-owner` / `--gid-owner`，**只在 OUTPUT 侧**；PREROUTING 完全无 owner 匹配。README 明说"Android iptables 不支持 PID 匹配，所以进程匹配靠 GID 间接实现"——身份能力比我们**更弱** | 端口 53 的处理在 `box.iptables:458-464`，**排在 app uid/gid 块（478+）之前**，即规则顺序上明确 **anti**-per-app；`CLASH_DNS_LOCAL:568` 只放行 core 后 REDIRECT 全部 UDP/53；`box.iptables:177-178` 还无条件 `ip6tables -A OUTPUT -p udp --dport 53 -j DROP` 封掉全部 IPv6 DNS | `box/scripts/box.iptables` |
| box4magisk | `APP_PROXY_ENABLE` / `APP_PROXY_MODE` / `PROXY_APPS_LIST`，格式恰好也是 `userID:packageName` | 独立的全局开关 `DNS_HIJACK_ENABLE`（0 关 / 1 tproxy / 2 redirect）+ `DNS_PORT` | `box/scripts/tproxy.conf` |
| CHIZI sing-box eBPF | cgroup hook 内 `uid_bypassed(config)` 做 include/exclude | 在 cgroup2 **root** attach（因此看得见 netd 的 socket）+ `dns_mode: hijack` 时 **`:53` 完全跳过 UID 判定**。等于放弃 DNS 的 per-app 语义 | `common/ebpf/native/cgroup.bpf.c:491-494` |
| dae / honk | 进程名靠 cgroupv2 上的 `sock_create` / `connect4/6` / `sendmsg4/6` 维护 `COOKIE_PID_MAP` | 靠拦截 DNS 端口做域名关联；文档承认 UDP 状态难维护，需 `must_direct` 按端口整体放行 | `honk/crates/honk-ebpf/src/cgroup.rs`；dae `docs/en/how-it-works.md` |

**dae 与 CHIZI 的进程/系统-DNS 能力在 Android 上都不可移植到 TC 数据面**：前者拿进程身份、后者看见 netd 的 socket，都依赖 Android 已用 `flags=0` 独占的那几个 cgroup attach type（§0.1(2)、§0.5.2）。而 CHIZI 为避免自环用的是 **TGID**，那需要 cgroup hook 的进程上下文——TC egress 在 softirq 里没有这个上下文（§0.5.3）。

**netd 内部也确实知道请求者 UID**，并用它选网络：`DnsProxyListener` 取 `const uid_t uid = cli->getUid()`，`NetworkController::getNetworkForDns(netId, uid)` 按「显式选定网络 → 该 UID 的 VPN（若 VPN 提供 DNS server）→ 默认网络」决策。VpnService 因此从平台白拿 per-app DNS。**而 `fchown` 把同一份归属信息也放进了 packet 的 socket owner**，所以 eBPF 数据面同样拿得到——只是 netfilter 因为读错字段而拿不到。

### 1.3.3 DNS 的三条残余边界（必须写进 README，不得含糊）

**① Private DNS（DoT / DoH strict mode）不被捕获，Flux 也不去关它。**
AOSP 刻意把加密 DNS 归属给 `AID_DNS`(1051) 而不是 app：`DnsTlsSocket.cpp:82`、`DnsTlsTransport.cpp:107`、`PrivateDnsConfiguration.cpp:593` 三处都是 `resolv_tag_socket(fd, AID_DNS, NET_CONTEXT_INVALID_PID)`。它走 :853/:443、跨 app 复用长连接，天生不可 per-app 归属。

后果：用户若开启系统 Private DNS，域名解析走 DoT 出去，不经过 Flux。这在**隐私上是好的**（本来就是加密的），但意味着 sing-box 看不到该解析、无法用自己的 DNS 决定目的 IP。`clone/box4magisk/box/scripts/box.service:50-58` 的做法是运行期间 `settings put global private_dns_mode off`；**0.9.0 拒绝这么做**——不擅自改用户的系统设置。正确做法是在 `status` 里检测并提示：若 `private_dns_mode` 非 `off`，告知"系统加密 DNS 已启用，域名解析不经过 Flux"，由用户自己决定。

**② `enforce_dns_uid` 会毁掉归属。**
`ResolverOptionsParcel.aidl:48-57` 定义了一个可由 OEM / 网络配置打开的选项，打开后明文 DNS 也用 `AID_DNS`。AOSP 自己在注释里劝退它（"decreases battery life"、"data usage … attributed to the OS instead of to the requesting app"），所以罕见。检测方式很直接：捕获到的 :53 流量若 `sk_uid == 1051`，说明该设备开了这个开关。此时该设备的系统 DNS 退化为不可 per-app 捕获——**行为等于不捕获，不是错误**，`status` 报告即可。

**③ mDNS 不捕获。** `.local` 解析走 `224.0.0.251:5353` / `[FF02::FB]:5353`，落在固定 bypass 的 `224.0.0.0/4` 与 `ff00::/8` 里，直连。这是正确行为。

另有一处 `fchown` 站点 `getaddrinfo.cpp:1330` 带 `uid > 0 && uid != NET_CONTEXT_INVALID_UID` 的守卫；语义与上文一致，不改变结论。

### 1.3.4 用户 sing-box 配置必须处理 :53（默认配置要带）

既然被选中 app 的 DNS 会进入 tproxy inbound，用户的 `sing-box.json` **必须**告诉 sing-box 如何处理它，否则 sing-box 会把它当普通 UDP 转发到原始 DNS 服务器——功能上能用，但等于放弃了域名分流。标准做法是 `route.rules` 里的 `hijack-dns` action（`clone/AndroidTProxyShell/README.md` 的 sing-box 样例就是这个）：

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

`hijack-dns` 把该 datagram 交给 sing-box 的 `dns` 模块，于是域名规则、`dns.rules`、fakeip（若用户配置）全部生效，**且只对被选中的 app 生效**。这是本设计相对全设备劫持方案的实质优势：DNS 分流范围与流量分流范围**严格一致**。

Flux **不注入**这段——路由与 DNS 属 sing-box 的权威域（§9.6）。但：

- 随模块分发的 `etc/default-sing-box.json` **必须**包含上面这两条 rule，作为可工作的起点；
- `fluxd check` 在用户 JSON 缺少 `hijack-dns`（或等价的 :53 处理）时**给出警告**，不阻止启动；
- README 必须说明这两条 rule 的作用。

### 1.3.5 分流精度的第二层：sing-box 侧的 `package_name` 规则可用

**观察（`clone/sing-box-official-1.13.19` 逐行核对）**：官方 Android 二进制**独立运行**（无 GUI/library platform interface）时会自己初始化 PackageManager：

```go
// route/network.go:175-192
if C.IsAndroid && r.platformInterface == nil {
    packageManager, err := tun.NewPackageManager(...)   // 读 /data/system/packages.xml
    ...
    r.packageManager = packageManager
}
```

于是 `route/router.go:130-146` 会构建 `process.NewSearcher{PackageManager: ...}`，在 Android 上落到 `common/process/searcher_android.go`：

```go
_, uid, err := querySocketDiagOnce(family, protocol, source)   // NETLINK_SOCK_DIAG 查源 socket
appID := uid % 100000
packageNames = s.packageManager.PackagesByID(appID)
```

因为我们**不改写源地址**，engine 看到的 source 就是 app 的真实 IP:port，SOCK_DIAG 查得到那个 socket。因此：

- 用户可以在 `route.rules` / `dns.rules` 里写 **`package_name`** 与 `process_name`，按 app 选不同 outbound、不同 DNS。
- **对系统解析器发出的 DNS 同样成立**：inet_diag 的 `idiag_uid` 取自 `sock_i_uid(sk)`（inode owner），而 `fchown` 正是改这个字段——与 §1.3.1 的 `sk_uid` 链路同源。所以 app 的系统 DNS 在 engine 里也会被正确归属到该 app 的包名。

**两层精度因此是这样分工的**：

| 层 | 决定什么 | 依据 |
|---|---|---|
| Flux（内核，TC） | **是否**捕获 | `uid_policy` 查 `bpf_get_socket_uid()` |
| sing-box（用户态） | 捕获之后**怎么走**（outbound、DNS server、规则集） | SOCK_DIAG → appId → package name |

Flux 不注入任何 `package_name` 规则，也不替用户维护包名表——这属 sing-box 的权威域。但 README 应当说明这条能力存在，因为它是"精准分流"的第二半。

**待证**：`tun.NewPackageManager` 在目标设备上能否成功读取包数据库（失败时 sing-box 只 warn 并继续，届时 `package_name` 规则静默不匹配）。Phase 0 Q9 顺带验证。

**用户 CIDR bypass 对 :53 同样生效。** 旧 cgroup 实现里有一段 `should_bypass_v4/v6` 在 `dport == 53` 时直接返回 0，即用户 bypass 永远豁免不了 53 端口（`crates/flux-platform/src/bpf/prog/flx_sock_addr.c:261-292`）；CHIZI 的 `dns_mode: hijack` 更进一步，连 UID 判定都跳过（§0.5.3）。**0.9.0 都不采用。** 用户把 `192.168.0.0/16` 写进 `bypass_cidrs` 是在明确表达"局域网直连"，此时强行把 app 对路由器 `192.168.1.1:53` 的查询送进代理会打断本地名称解析，而且是用户无法关掉的隐藏行为。让显式配置说话；需要"DNS 永不 bypass"的用户不要把 DNS 服务器写进 bypass 即可。

## 1.4 选择单位与身份边界

- 配置单位 `userId:packageName`；内核执行单位 UID = `userId * 100000 + appId`。
- **只接受 `appId ∈ [10000, 19999]`。** 其它一律配置错误。
- shared UID 下所有 package/process 一并命中，无法逐包区分；`check`/`status` 必须显示同 UID 的全部 package。
- isolated UID（90000+）、SDK sandbox UID、临时子 UID 不自动跟随。
- **代发流量按代发者的 UID 归属，不按请求者。** DNS 是**例外**（AOSP 用 `fchown` 把归属还给了 app，见 §1.3.1），但其它代发路径没有这个待遇：`DownloadManager` 代下载、`MediaProvider`、跨 Binder 传递的 socket、以及系统服务代发的连接，都以**代发进程的 UID** 出现在 TC egress，因此**不会**被捕获。CHIZI 在自己的 README 里也把这条列为包名策略的边界。这是 UID 级捕获的固有属性，不是缺陷，但必须写进 README。
- 用户若选中一个 VPN provider，其 outer socket 会被嵌套捕获。`check`/`status` 尽力告警，但不阻止。

## 1.5 信任与威胁边界

信任：设备 root、三个 root 管理器、模块目录、本地配置管理员、用户提供的 sing-box JSON（视为受信**代码级**配置；`sing-box check` 只验语法语义，不是沙箱）。

**不抵抗**：另一个恶意 root（可写 BPF map、改 TC/RPDB、注入 veth）；恶意本地进程扫描内部端口并在某个 listener 单独关闭的竞态里用 `IP_FREEBIND` 抢绑同 tuple。随机端口与 promote 时的 SOCK_DIAG/PID/inode 交叉核验只降低**非对抗**碰撞概率。把当前 seam 包装成对 hostile root/app 的安全隔离是伪安全。

---

# 第 2 部分：数据路径与失败语义

## 2.1 路径

```
选中 app 的 socket
 └─(1) 受支持物理接口 TC egress（chain 0 / pref 1 / direct-action）
        flx_cap_l2（ARPHRD_ETHER）或 flx_cap_l3（ARPHRD_RAWIP / 已确认 CLAT TUN）
        ├─ 未选 / bypass / 未入场失败 → TC_ACT_UNSPEC（继续 AOSP CLAT/OEM，走 Android 原路径）
        ├─ 越过 admission 后失败      → TC_ACT_SHOT
        └─ 入场 → L2 零改写 / L3 补 14 字节头 → bpf_redirect(flxrs0, 0)
 └─(2) veth flxrs0 ──内核 veth_xmit──> flxrs1（eth_type_trans 置 PACKET_OTHERHOST）
 └─(3) flxrs1 TC ingress：flx_in（首先 bpf_skb_change_type(PACKET_HOST) 纠正归属）
        ├─ snapshot 无效 / active=0 / 非 IP → TC_ACT_SHOT
        ├─ TCP SYN&&!ACK：固定 tuple lookup actual listener → guard → bpf_sk_assign → TC_ACT_OK
        ├─ TCP 其它（含 fragment）：TC_ACT_OK，交内核 request/established 查找
        └─ UDP：逐 datagram lookup → guard → assign → TC_ACT_OK
 └─(4) 输入路由：ip rule `iif flxrs1 lookup 20260` → `local default dev lo` → RTN_LOCAL
 └─(5) 官方 sing-box TProxy inbound（flux-in-v4/v6）accept / recvmsg，原始目的完好
        · TCP 目的 = accepted socket 的 LocalAddr()
        · UDP 目的 = IP(V6)_RECVORIGDSTADDR cmsg
 └─(6) sing-box 普通 outbound socket（root，uid 0，不在 uid_policy）→ Android netd 原生出网
```

关键性质：**IP/port 从不改写**；未选流量的热路径是"1 次 helper + 1 次 HASH miss"；engine 消失时下一个新 SYN/datagram 在 redirect 前就 lookup miss → Direct。

## 2.2 fail-open 精确合同

**egress"不接管"一律返回 `TC_ACT_UNSPEC`。禁止用 `TC_ACT_OK` 表示 egress Direct**（会终止 classifier chain，跳过 CLAT/OEM）。`TC_ACT_OK` 只用于 ingress。Flux capture **必须**是 chain 0 中该 protocol 的首个适用 classifier；仅 attach 成功不等于程序可达（§8.5）。

### 2.2.1 保证 Direct（`TC_ACT_UNSPEC`）

对**尚未入场的 TCP socket 首 SYN** 与**当前 UDP datagram**，下列 redirect 前失败一律 Direct：

- `skb->sk` 为空、`bpf_sk_fullsock()` 返回空、`bpf_get_socket_uid()` 返回 overflow uid；
- `uid_policy` miss；UID 为 `DRAINING` 且是新连接；
- family / protocol / header / L2 layout 不支持（VLAN、未知 ARPHRD、非 IP EtherType）；
- IPv6 未知 extension header、超出解析上界；
- 命中固定安全 bypass、本机地址 bypass 或用户 CIDR bypass（**fragment 也做这一步**）；
- control snapshot 无效或 `active == 0`；
- 对应 family/protocol 的 actual listener lookup miss 或 guard 不符；
- TCP decision storage `CREATE` 与并发只读重查**均**失败（当前包 Direct，无粘性，后续 SYN 可重判）；
- 当前 interface 未成功 attach 精确 Flux filter（该 interface 上根本没有 Flux 程序运行）。

### 2.2.2 必须 drop/reset（越过 admission boundary）

- `bpf_sk_storage_get(...F_CREATE)` 返回、或并发只读重查得到不可变 `CAPTURED(gen)` —— **这就是 TCP admission boundary**（`DIRECT` storage 不是 admission）。此后当前包与后续可解析包不得因 Flux 内部错误中途 direct；
- selected + active 的 UDP fragment 未命中 bypass；
- raw-IP 已 `bpf_skb_change_head()` 加内部以太头后的任何失败；
- L3 入口的 EtherType 写入成功后的任何失败（L2 入口不写包，故无此边界）；
- `bpf_redirect()` 已返回 redirect 之后的 enqueue/veth/route 失败；
- 已入场 TCP 遇到 `active=0` 或 `generation` 过期；
- ingress 的 parse / listener lookup / guard / `bpf_sk_assign()` 失败；
- TCP final ACK/data 进入本地栈但 request/established socket 不存在（内核 RST/drop）。

### 2.2.3 公开的不可消除边界

1. **跨 interface 无粘性**：Android 把已有 socket 改路由到 VPN TUN、未知 layout 或未 attach 的 interface 时，Flux 没有全局 hook，该 packet 走 Android 原路径。不宣称绝对流粘性。
2. **late control packet**：socket 析构后的 TIME_WAIT ACK、abortive RST 等可能没有 full socket/UID，走 `TC_ACT_UNSPEC`。不建 tuple tombstone。
3. **event-loop 活锁不可检测**：进程活着、listener socket 仍在、但 event loop 停止工作时，本数据面看不出来，该期间新流仍会被捕获并卡住。0.9.0 **不设** heartbeat / 周期探测 / watchdog packet。官方 sing-box 源码也允许个别 accept/read 致命错误关闭单个 listener 而不退出进程——这一类**会**被 §7.4 的 fault 通知在下一个相关 packet 上发现并自愈；"完全无流量时的内部故障"不会。
4. **双 leg 统计**：AOSP 的 UID/interface accounting 会看到 app 原 leg，sing-box 另建 root outbound 又是第二 leg。Flux 不篡改 TrafficStats 去"抵消"，系统设置里的按 UID 流量因此不等于物理链路字节。
5. **interface churn 窗口**：物理 interface 在 Android 上频繁变动——Wi-Fi↔蜂窝切换、每个 PDN 一个 `rmnet_data*` 的出现与消失、netd 按需创建销毁 `v4-*` CLAT。从"新 interface 变为 up 并开始承载流量"到"fluxd 收到 rtnetlink 事件并 attach 完 filter"之间存在一个**无法消除的窗口**，该窗口内的流量走 Android 原路径（即 Direct）。这与 §2.2.1 的 fail-open 语义一致，不是缺陷，但**必须公开**：0.9.0 不宣称"接管所有时刻的所有流量"。窗口大小取决于 rtnetlink 送达延迟与 §10.4 的 debounce，量级为百毫秒。**同一个窗口还会因 netd 删 `clsact` 而周期性重开**——见 §8.5.1，那不是异常而是日常。
6. **被代理流量失去 app 请求的 DSCP 标记**。AOSP 的 `dscpPolicy` 装在物理 interface 的 **egress pref 5**（`DscpPolicyTracker.java:50-51`），而我们在 pref 1 对捕获包返回 `TC_ACT_REDIRECT`，chain 就此终止——dscpPolicy 看不到这些包。sing-box 随后发出的**出站 leg** 仍会经过 dscpPolicy，但那是 root 的 socket，带不上 app 通过 `ConnectivityManager` 申请的 per-UID DSCP 策略。**净效果：被代理流量的 app 级 QoS 标记丢失。** 影响面限于依赖 DSCP 的运营商网络。改到 pref ≥ 6 不能解决（见 §8.5.2 结论 3）。
7. **conntrack 双计**。veth 跨越时 `skb_scrub_packet()` 必然 `nf_reset_ct()`，所以每条被代理的流会在 veth peer 的 PREROUTING 重新建立 conntrack，netfilter 因此看到两次。这与本节第 4 条的双 leg 统计叠加。TPROXY 类方案共性，不特殊处理。

## 2.3 为什么不可能自环（结构性论证，不是缓解措施）

"engine 自己的出站流量会不会被再次捕获，形成无限循环"是每个审阅者都会问的问题。同类项目确实需要专门的自排除机制：`clone/bpf2socks/connect_prog.c:226-237` 用 **GID** 比对做 bypass（因为 app 侧 UID 可能共享），`clone/AndroidTProxyShell/tproxy.sh:1002` 用 `-m owner --uid-owner $CORE_USER --gid-owner $CORE_GROUP -j ACCEPT`，`clone/dae/control/kern/tproxy.c:2362-2391` 用 cookie→pid 映射加 `dae_socket_mark` 三重判定。

**0.9.0 一个机制都不需要，因为策略是 allowlist 而不是 blacklist。** 论证：

1. `uid_policy` 是一张**只包含被选中 app UID 的 HASH**。§7.3 的 E1 步是"查表 miss 即 `TC_ACT_UNSPEC`"，不是"查表命中排除项才放行"。
2. §1.4 硬性只接受 `appId ∈ [10000, 19999]`。sing-box 以 root(uid 0) 运行，**结构上不可能出现在表里**。
3. `bpf_get_socket_uid()` 在无 `skb->sk` 时返回 `overflowuid`(65534)，同样不在表里 → `TC_ACT_UNSPEC`。**所以"UID 解析失败"的后果是不捕获，而不是误捕获。** 这一点与 blacklist 设计相反：blacklist 下解析失败意味着"没命中排除项"，会被捕获，才会形成循环。
4. engine 的三类出站流量逐一检查：
   - **上游代理连接**（sing-box → 远端服务器）：root socket，物理 interface egress，uid 0 → miss → Direct。
   - **上游 DNS**：同上，uid 0 → miss → Direct（这也是 §1.3.1 里"既捕获 app 的系统 DNS 又不吞 engine 的 DNS"成立的原因）。
   - **UDP 回写**（accepted 连接的返回流量）：目的是 app 的本机地址 → 输出路由走 `lo`，**根本不经过任何物理 interface 的 TC egress**。
5. 被 `bpf_sk_assign` 交付的 packet 进入 engine 后就离开了数据面；engine 之后建立的是**新 socket**，走第 4 条。redirect 与 assign 之间没有任何回到 egress 的路径。

**结论：自环不是"已缓解"，是"不可构造"。** 因此 0.9.0 **不设** engine 专用 mark、不设 GID bypass、不设上游目的 CIDR 例外。这些机制若被加入，反而会在没有对应威胁的情况下增加热路径成本与配置面。

**唯一需要保持的不变量**：`uid_policy` 永远不得包含 `appId < 10000` 的条目（§11.2 的解析器强制），且 engine 永远不以选中 app 的 UID 运行（§13.3 固定 root）。破坏其中任一条才会打开循环的可能性。

---

# 第 3 部分：Android 平台事实（实现者必读）

## 3.1 netd、fwmark 与 RPDB

Android socket fwmark 是 packed 32-bit，编码 netId、explicitlySelected、protectedFromVpn、permission 与 vendor 位；netd 用 UID range、fwmark、`iif lo` 和 priority ≈10000–32000 的一组规则实现 VPN、explicit network、implicit/default network 与 prohibit/unreachable。它不是桌面 Linux 的 `local/main/default` 三条规则。

因此 Flux **必须**：不读写 packet fwmark、不为自己猜"空闲 mark"、不清空/重排/复用 netd rule、不假定 `main` 表或当前 default route 是 app 的真实网络。Flux 只增加一条由专用 `iif flxrs1` 命中的本地交付规则（§8.4）。

## 3.2 AOSP 已独占 root cgroup 的 SOCK_ADDR 槽位

见 §0.1(2)。**结论：0.9.0 不 attach 任何 cgroup 程序，也不把 app 或 sing-box 移进自建 cgroup。** Flux 只在 AOSP 完成 socket/owner policy 之后的物理 netdevice TC egress 观察 packet；若 Android owner firewall 已 drop，Flux 看不到也不会绕过该包。

## 3.3 L2 布局差异：Wi-Fi vs rmnet vs CLAT

| 入口 | 接受条件 | packet 处理 |
|---|---|---|
| `flx_cap_l2` | `ARPHRD_ETHER`、`skb->vlan_present == 0`、`skb->protocol ∈ {IPv4, IPv6}`、非 bridge/VPN/Flux 自有 | **不改写任何字节**，原以太头（含 EtherType）原样带走；`pkt_type` 由 ingress 修正（D17） |
| `flx_cap_l3` | `ARPHRD_RAWIP`（Qualcomm rmnet）或被严格识别的 CLAT `v4-*` TUN | `bpf_skb_change_head(skb, 14, 0)`（该 helper 会 `memset` 清零并 `skb_reset_mac_header()`），随后**只**在 offset 12 写入按 `skb->protocol` 得到的 EtherType；dst/src MAC 留全零，由 ingress 的 `bpf_skb_change_type()` 处理归属（D17） |

VLAN、QinQ、未知 ARPHRD 在 0.9.0 直接排除该 interface。手机上几乎不需要 VLAN，为它加 strip/rebuild 分支不属首发范围。

### 3.3.1 为什么 L3 分支是**强制**的，不是优化

这条如果漏掉，产品在 Wi-Fi 下完全正常，而**全部蜂窝数据被静默丢弃且没有任何计数器**。机制已从内核源码逐行核对：

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

三个关键点，缺一不可地推出结论：

1. **`dev_is_mac_header_xmit()` 看的是 *目标* 设备**（`include/linux/if_arp.h:44-60`）。veth 是 `ARPHRD_ETHER`，所以**只要目标是 veth，就永远走带 `-ERANGE` 检查的那条路径**——源设备是什么类型不影响分支选择，只影响检查是否通过。
2. **TC egress 之前刚做过 `skb_reset_mac_header()`**：`__dev_queue_xmit()` 在 `net/core/dev.c:4170` 调它，紧接着 `:4198` 才调 egress hook。在不带以太头的设备上 `skb->data` 指向 IP 头，于是 `mac_header == network_header`，`>=` 成立。
3. **Android 上命中这条的就是全部蜂窝路径**：`rmnet_data*` 是 `ARPHRD_RAWIP`，CLAT 的 `v4-*` 是 `ARPHRD_NONE`——AOSP 自己在 `ClatCoordinator.java:471` 写明"*This program will be attached to the v4-\* interface which is a TUN and thus always rawip*"，`tcutils.cpp:478-512` 也把两者一并归为非以太。

修复手段是内核**明文认可**的：`__bpf_skb_change_head()` 的注释原文就是"*Intention for this helper is to be used by an L3 skb that needs to push mac header for redirection into L2 device*"（`net/core/filter.c:3729-3758`）。它内部调 `skb_reset_mac_header()`，正好让 `mac_header < network_header` 重新成立；且它对 GSO skb 豁免长度上限，因此 GSO 安全。

顺带一提，AOSP 与 honk 都把这件事做成两个 object / 两个 attach 分支（AOSP 的 `..._ether` 与 `..._rawip`，`clatd.c:248-270`；honk `attach.rs:657-690`），与本设计的 `flx_cap_l2` / `flx_cap_l3` 分法一致。

## 3.4 CLAT464

AOSP `ClatCoordinator` 创建 `v4-*` raw-IP TUN，并在其 egress 用固定低 priority 的 TC BPF 做 IPv4→IPv6 翻译。IPv4 packet 在 `v4-*` egress 仍带原 app socket UID；翻译后的物理 IPv6 通常已属 `AID_CLAT`，不能再作为 app 选择依据。

Flux 支持 CLAT 的**全部**条件：① link 是 TUN/raw-IP 且名字匹配 `v4-*`；② 存在 CLAT 特征地址与关联 underlay；③ TC dump 中存在可识别的 AOSP CLAT egress filter；④ Flux 能在同 chain 以 pref 1 + IPv4 protocol + 固定 handle 安装且**位于其之前**；⑤ Phase 0 已在该设备证明 UID/GSO/checksum/MTU/header 转换正确。任一条件不明 → 该 interface Direct。**Flux 不删除、不移动、不替换 AOSP 的 filter。** 不硬编码 AOSP 的 priority 数值，只要求 dump 顺序满足 first-applicable 谓词。

## 3.5 VPN / TUN

- app 走 VPN 时原 packet 在 VPN TUN 上，Flux 排除所有 generic TUN/TAP。
- 物理接口上随后出现的是 VPN provider 的 outer socket，通常已不是原 app UID。
- always-on / lockdown VPN 继续由 Android 处理；Flux 不提供"优先于 VPN"的隐藏开关。
- VPN 上线导致已有 Flux TCP 迁移到被排除的 TUN 时，该流离开 Flux 可执行粘性的范围（§2.2.3(1)）。Flux 不为此再向 VPN TUN 挂 drop-only 程序。

## 3.6 显式 network 与 outbound 身份

app 通过 Android API 显式绑定 Wi-Fi/蜂窝后，原 packet 可能在对应 underlay 被捕获；但 sing-box outbound 是新的 root 进程 socket，**不继承** app 的 netId、VPN protection 或 per-flow network identity。0.9.0 使用 Android 为 root socket 选择的网络，用户可用官方 sing-box outbound 选项（`bind_interface` / `routing_mark` / `network_strategy`）自行控制，后果自负。Flux 不声称"完全保持原 app 的 Android network 选择"。

## 3.7 GKI / OEM / SELinux / root 管理器

API level、内核版本字符串、GKI defconfig、OEM backport、SELinux domain、root provider 权限是互不等价的维度。Flux **不维护机型 catalog**，不按字符串白名单猜能力。启动时的正常 activation 本身就是最小 capability admission：创建真实 map、加载真实 program、创建/核验真实网络对象、尝试精确 attach。任一步失败 → 该 interface 或整个数据面保持 Direct，并在 `status` 给出**第一个具体错误**。禁止为"兼容更多机型"动态注入宽泛 sepolicy。

## 3.8 4 KiB / 16 KiB

Android 15 起允许 16 KiB base-page 内核，但 API level 推不出 page size。固定的官方 sing-box arm64 资产四个 `PT_LOAD` 的 `p_align` 均为 `0x1000`，不满足 AOSP 16 KiB ELF 对齐要求；`zipalign` 不能修改 program header。因此 0.9.0 只支持 `sysconf(_SC_PAGESIZE) == 4096`。`fluxd` 自身仍按 16 KiB 对齐构建（安装/诊断卫生），使它在其它 page size 设备上能给出确定诊断而不是崩溃。

## 3.9 netns

BPF socket lookup、TC、veth、RPDB、sing-box listener 全部在当前 netns。`fluxd` 与 sing-box **必须**位于 Android app 所在的初始 netns；启动时比较 `/proc/self/ns/net` 与 `/proc/1/ns/net` 的 inode，不一致则 Inactive 并报错。Magisk 的 mount namespace 不等于 network namespace。

---

# 第 4 部分：内核机制依赖清单

实现者可用此表逐项核对目标设备。**表中每一项都必须在 activation 时以"实际调用成功"验证，而不是查版本。** "最低内核"列只记录该机制首次出现的版本；全部早于产品基线 5.15，列出它是为了说明为什么这些机制在基线上可用，不是运行时判定依据。

**GKI defconfig 已逐项核对**（`android12-5.10` / `android13-5.15` / `android14-6.1` / `android15-6.6` 的 arm64 `gki_defconfig`，四个分支全部满足）：`CONFIG_VETH=y`、`CONFIG_DUMMY=y`、`CONFIG_TUN=y`、`CONFIG_NET_SCH_INGRESS=y`（clsact）、`CONFIG_NET_CLS_BPF=y`、`CONFIG_NET_CLS_ACT=y`、`CONFIG_NET_ACT_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_CGROUP_BPF=y`、`CONFIG_IP_MULTIPLE_TABLES=y`、`CONFIG_NF_CONNTRACK=y`。**`CONFIG_NETKIT` 四个分支全部缺失。**

| 机制 | 最低内核 | 用途 | 失败后果 |
|---|---|---|---|
| `BPF_PROG_TYPE_SCHED_CLS` + direct-action | 4.4 / 4.5 | 三个程序 | 整体 Inactive |
| `bpf_get_socket_uid()` | 4.3 | UID 粗分流 | 整体 Inactive |
| `__sk_buff->sk` + `bpf_sk_fullsock()` | 5.1 | 取 app full socket | 整体 Inactive |
| `BPF_MAP_TYPE_SK_STORAGE` + `bpf_sk_storage_get(F_CREATE)` | 5.2 | TCP first-decision | 整体 Inactive |
| `bpf_sk_lookup_tcp/udp()` + `bpf_sk_release()` | 4.20 | listener liveness / assign 目标 | 整体 Inactive |
| `bpf_sk_assign()`（TC ingress） | 5.7 | 交付给 TProxy listener | 整体 Inactive |
| `BPF_MAP_TYPE_ARRAY_OF_MAPS` | 4.12 | control snapshot 原子发布 | 整体 Inactive |
| `BPF_MAP_FREEZE` | 5.2 | leaf 不可变 | 可降级为不 freeze（仅卫生） |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 | fault-only 通知 | 可降级为无自愈通知 |
| `BPF_MAP_TYPE_LPM_TRIE` | 4.11 | CIDR bypass | 整体 Inactive |
| `bpf_skb_change_head()` | 4.16 | raw-IP 补以太头 | 该 interface 排除（仅 L3 入口） |
| `bpf_skb_store_bytes()` / `bpf_skb_pull_data()` | 4.1 / 4.9 | 安全写包 | 整体 Inactive |
| `bpf_redirect()` | 4.4 | 回送 veth | 整体 Inactive |
| `BPF_BTF_LOAD` | 5.1 | SK_STORAGE 必需的 BTF | 整体 Inactive |
| `veth`（`CONFIG_VETH=y`，GKI built-in） | — | 回送拓扑 | 整体 Inactive |
| `CONFIG_NETKIT` | — | **GKI 四个分支全部缺失** → dae 的 netkit L3 快路径在 Android 不可用，veth 是唯一选项 | — |
| `clsact` qdisc | 4.5 | TC 挂载点 | 该 interface 排除 |
| RPDB `iif` selector + `RTN_LOCAL` 路由 | — | 本地交付 | 整体 Inactive |
| `NETLINK_SOCK_DIAG`（inet_diag） | — | listener readiness 核验 | 整体 Inactive |
| `pidfd_open` + `PR_SET_PDEATHSIG` | 5.3 | engine 生命周期 | 整体 Inactive |
| `signalfd` / `inotify` / `timerfd` / `epoll` | — | reactor | 整体 Inactive |

**已知的 6.5 之前限制**：`bpf_sk_assign()` 拒绝 `SO_REUSEPORT` socket。见 §9.2 的硬约束。

---

# 第 5 部分：crate 与模块结构

```text
Flux-rs/
├── Cargo.toml                     # [workspace] members = ["crates/flux-core","crates/fluxd","xtask"]
├── Cargo.lock
├── rust-toolchain.toml            # stable，pin 精确版本；targets = ["aarch64-linux-android"]
├── engine.lock                    # 官方 sing-box pin
├── LICENSE / README.md / CHANGELOG.md / THIRD_PARTY_NOTICES.md
├── licenses/…
├── bpf/
│   ├── flux.bpf.c                 # 唯一 BPF 源文件（见 reference/flux.bpf.c）
│   └── include/flux_abi.h         # C 与 Rust 共享 ABI 真相源（见 reference/flux_abi.h）
├── crates/
│   ├── flux-core/                 # 纯逻辑，无 libc / 无 syscall / 跨平台可测
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs          # flux.toml 解析 + canonicalize + 硬上限
│   │       ├── selector.rs        # "userId:package" 解析、UID 计算、appId 范围校验
│   │       ├── cidr.rs            # v4/v6 CIDR canonicalize、固定 bypass、LPM key 编码
│   │       ├── engine_config.rs   # 用户 sing-box.json 校验 + effective JSON 生成
│   │       ├── abi.rs             # flux_abi.h 的 Rust 镜像 + size/offset 断言
│   │       ├── control_wire.rs    # 控制协议请求/响应类型（serde）
│   │       └── version.rs         # SemVer → versionCode / artifact 名
│   └── fluxd/                     # Linux/Android 运行时（单一产品二进制）
│       ├── build.rs               # clang 编译 bpf/flux.bpf.c，OUT_DIR 产出 object
│       └── src/
│           ├── main.rs            # CLI dispatch
│           ├── layout.rs          # /data/adb/flux-rs 目录、权限、单实例锁
│           ├── control.rs         # SOCK_SEQPACKET 服务端 + 客户端
│           ├── reactor.rs         # 单线程 epoll 事件循环 + 状态机 + 收敛
│           ├── packages.rs        # /data/system/packages.list 读取与解析
│           ├── netlink/           # rtnetlink：link/addr/route/rule/tc 的编解码与操作
│           ├── bpf/               # 最小加载器：syscall、BTF blob、relocation、map、ringbuf
│           ├── dataplane.rs       # 对象生命周期、control leaf 发布、interface admission
│           └── engine.rs          # effective JSON 落盘、check、spawn、SOCK_DIAG readiness
├── module/                        # Magisk/KernelSU/APatch 信封源
└── xtask/                         # 构建 / 打包 / release，只在开发机运行
```

依赖方向：`flux-core` 不依赖任何 crate（除 serde/toml/serde_json）；`fluxd → flux-core`；`xtask → flux-core`。**禁止** `flux-core` 依赖 `fluxd`，**禁止**新增 platform/testkit/backend registry crate，**禁止**为单一实现创建 trait 抽象层。

`fluxd` 内部模块依赖：`main → reactor → {layout, control, packages, netlink, bpf, dataplane, engine}`；后者不反向依赖 `reactor`。全部运行时状态在 `reactor` 拥有的单个 `Runtime` 结构里，无可变全局。

**一条从旧仓库继承的边界要求**：旧的过度设计复审判定"在 daemon 里直接写裸 rtnetlink 消息（`native_canary_facility.rs` 里的 ACK/超时/序列号处理）违反深模块原则"。合并 `flux-platform` 之后这条依然成立，只是边界从 crate 变成模块：**裸 netlink 消息构造、序列号、ACK 与超时处理只允许出现在 `fluxd/src/netlink/` 内部；裸 `bpf(2)` 只允许出现在 `fluxd/src/bpf/` 内部。** `reactor` 与 `dataplane` 只看到类型化操作（`create_veth`、`add_rule`、`attach_filter`、`publish_control`），看不到 `nlmsghdr`。

---

# 第 6 部分：BPF ABI

`bpf/include/flux_abi.h` 是唯一真相源，见 `reference/flux_abi.h`。`flux-core/src/abi.rs` 是手写镜像，并**必须**带 `#[test]` 断言每个 `size_of` / 字段 offset 与 C 一致（`xtask` 在 CI 里用 clang 打印 offset 对照）。改动任何布局**必须**同时改 `FLUX_ABI_MAGIC`。

## 6.1 map 集合（稳态 9 个 kernel object）

| 名称 | 类型 | key | value | max_entries / flags |
|---|---|---|---|---|
| `uid_policy` | `HASH` | `__u32 uid` | `__u8` (`FLUX_UID_*`) | 512 |
| `bypass_v4` | `LPM_TRIE` | `flux_lpm_v4_key` | `__u8` | 128，`BPF_F_NO_PREALLOC` |
| `bypass_v6` | `LPM_TRIE` | `flux_lpm_v6_key` | `__u8` | 128，`BPF_F_NO_PREALLOC` |
| `tcp_decision` | `SK_STORAGE` | `int`（隐式） | `struct flux_decision`（16 B） | 0，`BPF_F_NO_PREALLOC`，**需 BTF** |
| `control_root` | `ARRAY_OF_MAPS` | `__u32 0` | 当前 leaf 引用 | 1 |
| `control_leaf` | `ARRAY`（inner） | `__u32 0` | `struct flux_control` | 1，写满后 `BPF_MAP_FREEZE` |
| `fault_latch` | `HASH` | `struct flux_fault_key` | `__u8` | 64 |
| `fault_events` | `RINGBUF` | — | `struct flux_fault_event`（32 B） | 16384 bytes |
| `counters` | `PERCPU_ARRAY` | `__u32 idx` | `__u64` | 32 |

- 发布期短暂同时存在 old/new 两个 `control_leaf`，其它时刻共 9 个。
- `fault_events` 固定 16384 是同时满足"2 的幂且 PAGE_SIZE 对齐"在 4 KiB 与 16 KiB 下的最小通用值，避免 ABI 分叉。
- map 默认**不 pin**。
- **禁止**引入会让 selected packet 全局争用的 `bpf_spin_lock`、per-packet telemetry、per-flow map，或声称大 struct 的 `ARRAY` update 是原子的。新增任何 map 必须写明热路径与生命周期成本。

## 6.2 `flux_decision`（SK_STORAGE value）

```c
struct flux_decision {
    __u32 magic;        /* == FLUX_DECISION_MAGIC，防止误读未初始化/他方 storage */
    __u8  mode;         /* FLUX_DEC_DIRECT | FLUX_DEC_CAPTURED */
    __u8  reserved[3];  /* 必须为 0 */
    __u64 generation;   /* CAPTURED 时为入场 generation；DIRECT 时为 0 */
};
```

**不变量**：创建后**绝不原地改写**。`DIRECT` 不是 admission；观察到合法 `CAPTURED` 的下一条指令起就是 admission。storage 随 app socket 析构释放，不存在 LRU 容量驱逐。

## 6.3 `flux_control`（不可变 snapshot）

字段见 `reference/flux_abi.h`。要点：

- `abi_magic`、`generation`、`active`；
- `flxrs0_ifindex`（redirect 目标）、`flxrs1_ifindex`；
- **没有 MAC 字段**（D17）。egress 不改写以太头，由 ingress 的 `bpf_skb_change_type(skb, PACKET_HOST)` 兜住 `eth_type_trans()` 判出的 `PACKET_OTHERHOST`；
- `listen_v4[4]` / `listen_v6[16]` / `listen_port_v4` / `listen_port_v6`（网络字节序）；
- `probe_remote_v4[4]` / `probe_remote_v6[16]` / `probe_remote_port`（固定 synthetic 远端，用于确定性 listener lookup）；
- 诊断计数：`selected_count` / `draining_count` / `bypass_v4_count` / `bypass_v6_count`。

## 6.4 control snapshot 的原子发布协议

**已核验**：`ARRAY_OF_MAPS` 的 update 取新 inner map 引用后 `xchg()` 指针，syscall 返回前 `synchronize_rcu()`，旧 inner map 在再一个 RCU grace period 后释放。因此：

1. 创建新 `control_leaf`（`ARRAY`，1 元素）；
2. 一次 `bpf_map_update_elem(leaf, 0, &full_control)` 写满整个 struct；
3. `BPF_MAP_FREEZE(leaf)`；
4. `bpf_map_update_elem(control_root, 0, &leaf_fd)` 发布；
5. 关闭旧 leaf fd。

**BPF 侧强制约束**：每次 invocation **只** lookup `control_root[0]` 一次，把返回的 inner value 指针一直用到本次结束。leaf 先 freeze 后 publish、永不原地改。这样单次 invocation 只会看到旧或新的**完整** snapshot，不会看到 `memcpy` 中途撕裂的字段。

**何时创建新 leaf**：engine generation 切换、`active` 0/1 翻转、拓扑字段（ifindex / listener 地址与端口）变化。（**没有 MAC 字段**——D17 之后 `flux_control` 里不存在 MAC。）**policy 变化（UID/CIDR）不创建新 leaf、不翻转 `active`**（D5）。

## 6.5 generation

同一 boot 内从 1 单调递增，**不复用、不重置**。daemon 冷启动时从 1 开始（此时旧对象已被删除重建，不存在跨代 in-flight 包）。`u64` 计数，产品生命周期内不可能 wrap。generation 只在 §9.4 的 engine 候选切换中递增。

---

# 第 7 部分：数据面算法

## 7.1 公共约束

- 三个 entry：`flx_cap_l2`、`flx_cap_l3`（egress）、`flx_in`（ingress）。共享 `static __always_inline` 辅助函数，实际逻辑只有一份。
- **禁止** tail call、BPF-to-BPF 调用图、perf event、BPF timer、spinlock、per-CPU 统计（除 §6.1 的 `counters`）。
- 每个 `bpf_sk_lookup_tcp/udp()` 返回的引用**必须**在每条分支上恰好 `bpf_sk_release()` 一次。`bpf_sk_assign()` **不**代替 release。`bpf_sk_fullsock()` 不取引用，**不得** release。
- 禁止把 socket 指针存进 map 或跨程序传递。
- 所有 offset 运算先做 verifier 可见的固定上界与 `data_end` 检查。
- 对 skb 的写入**必须**经 `bpf_skb_store_bytes()`；深层解析前若 `data_end` 不足，调用一次 `bpf_skb_pull_data(skb, FLUX_MAX_PULL_BYTES)` 并重读 `data`/`data_end`（D15）。

## 7.2 解析上界

- IPv4：最小 header、`version == 4`、`ihl ∈ [5,15]`、`tot_len` 合理；`MF` 或非零 fragment offset → 走 fragment 分支。
- IPv6：最多 4 个 extension header、累计 ≤ 256 bytes；遇 Fragment header → fragment 分支；遇 ESP / No-Next-Header / 未知 ext / jumbogram → Direct。
- 只接受 `IPPROTO_TCP` / `IPPROTO_UDP`；TCP 必须能读到固定 header 与 flags；UDP 必须有完整 8 字节 header。

## 7.3 egress 算法（`flx_cap_l2` / `flx_cap_l3`）

```
E0  if skb->protocol ∉ {ETH_P_IP, ETH_P_IPV6}            -> UNSPEC
    (l2 only) if skb->vlan_present                       -> UNSPEC
E1  skc = skb->sk;             if !skc                   -> UNSPEC
    sk  = bpf_sk_fullsock(skc);if !sk                    -> UNSPEC
    uid = bpf_get_socket_uid(skb)
    mode = uid_policy[uid];    if miss                   -> UNSPEC   ← 未选流量的全部代价
E2  /* 已有决策：不解析 L4，fragment 亦跟随决策 */
    d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0)
    if d:
        if d->magic != FLUX_DECISION_MAGIC || d->reserved != 0 || d->mode unknown
                                                          -> cnt(CORRUPT); SHOT
        if d->mode == DIRECT                              -> UNSPEC
        c = ctrl();  if !c                                -> cnt; SHOT
        if !c->active                                     -> cnt(INACTIVE); SHOT
        if d->generation != c->generation                 -> cnt(STALE_GEN); SHOT
        goto HANDOFF(c)
E3  /* 无决策 */
    parse L3（有界）;  if unsupported                      -> UNSPEC
    if fragment:
        if bypass_lookup(family, daddr)                   -> UNSPEC
        c = ctrl()
        if mode == SELECTED && c && c->active             -> cnt(UDP_FRAG_DROP); SHOT
        else                                              -> UNSPEC
    parse L4（有界）;  if !TCP && !UDP                     -> UNSPEC
E4  if TCP:
        if !(SYN && !ACK)                                 -> UNSPEC   /* 捕获前已建立的连接不付 control 代价 */
        cand.magic = FLUX_DECISION_MAGIC
        c = ctrl()
        capture = (mode == SELECTED)
               && c && c->active
               && !bypass_lookup(family, daddr)
               && listener_alive(c, family, TCP)          /* miss 时发一次 fault */
        cand.mode = capture ? CAPTURED : DIRECT
        cand.generation = capture ? c->generation : 0
        d = bpf_sk_storage_get(&tcp_decision, sk, &cand, BPF_SK_STORAGE_GET_F_CREATE)
        if !d: d = bpf_sk_storage_get(&tcp_decision, sk, NULL, 0)   /* 并发 loser 只读重查 winner */
        if !d:  cnt(ALLOC_FAIL);                          -> UNSPEC /* 无粘性，后续 SYN 可重判 */
        /* 无条件服从 winner，即使与本次 cand 相反 */
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
    l2: /* 不写任何 packet 字节 */
    l3: ok = bpf_skb_change_head(skb, ETH_HLEN, 0) == 0
          && bpf_skb_store_bytes(skb, 12, &ethertype, 2, 0) == 0   /* 头 12 字节已被内核置零 */
        if !ok: cnt(HANDOFF_FAIL); SHOT      /* 已越过 admission，只能 drop */
    return bpf_redirect(c->flxrs0_ifindex, 0)
```

要点：

- **E2 在 E3 之前**：CAPTURED 的稳态包完全不解析 IP/TCP。L2 路径只做 1 次 storage 查、2 次 map 查、1 次 redirect——**零字节写入**（D17）；L3 路径额外一次 `bpf_skb_change_head(14)` 加一次 2 字节 EtherType 写。
- `SYN` 重传命中同一不可变 state：`DIRECT` 永远 direct，`CAPTURED` 保持同 generation。只有"从未成功安装 decision"的分配失败边界会重判（§2.2.1 最后一条）。
- `DIRECT` state 存在的价值：避免同一 `connect()` 在 bypass/active/短故障期间的重传因策略变化而在 direct/proxy 间翻转。代价只是每个 selected-direct socket 一个 16 字节 storage，无每包写入。

## 7.4 `listener_alive()` 与 fault 通知

```
listener_alive(c, family, proto):
    tuple = { saddr = c->probe_remote_{v4,v6}, sport = c->probe_remote_port,
              daddr = c->listen_{v4,v6},       dport = c->listen_port_{v4,v6} }
    sk2 = proto == TCP ? bpf_sk_lookup_tcp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0)
                       : bpf_sk_lookup_udp(skb, &tuple, len, BPF_F_CURRENT_NETNS, 0)
    if !sk2: fault_once(c, family, proto, LISTENER_MISS); return false
    ok = sk2->family == (family == 4 ? AF_INET : AF_INET6)
      && (proto == TCP ? sk2->state == BPF_TCP_LISTEN : 1)
      && bound_addr_matches(sk2, c)          /* src_ip4 / src_ip6 == listen 地址 */
      && sk2->src_port == host_order(listen_port)
    bpf_sk_release(sk2)
    if !ok: fault_once(c, family, proto, LISTENER_GUARD); 
    return ok
```

**固定 synthetic 远端**（`probe_remote_*`）使 lookup key 每次相同：确定性、cache 友好，且排除了偶然命中某条 established socket 的可能。

`bpf_sock` 字节序注意：`src_port` 是**主机序**，`dst_port` 是**网络序**（内核 ABI 的既有不一致）。

**fault 通知规则**：

- 只对两类事件通知：① egress 的 `listener_alive` 失败（包未修改，返回 `UNSPEC`）；② ingress 已通过前置检查但 lookup/guard/assign 失败（已入场，drop）。
- 机制：以 `{generation, family, protocol, reason}` 对 `fault_latch` 做 `BPF_NOEXIST` 插入；只有首次成功插入者向 `fault_events` 写一条 32 字节事件。ringbuf 满则**删除刚插入的 latch**，让后续包重试。
- **不为** parse 错误、bypass、UID miss、`active=0`、正常 Direct 发事件。事件只含 `generation/family/protocol/reason`，**不含** header、UID、地址、payload。
- `fluxd` 收到 current-generation fault → 先 publish `active=0`，再重启整个 engine generation。handler 按 generation/state 幂等；旧/重复事件只清 latch 并忽略。新 generation 激活前清空 latch。
- 合同是"不会形成稳态 event storm"，**不是** exactly-once。

## 7.5 `flx_in` 算法（`flxrs1` ingress）

```
I0  c = ctrl(); if !c                                     -> SHOT
    if !c->active                                         -> SHOT
    bpf_skb_change_type(skb, PACKET_HOST)                 /* 见下方说明，必须在 ip_rcv 之前 */
I1  /* cls_bpf 在 ingress 已 __skb_push(mac_len)，可直接读以太头 */
    eth 可读性检查; if fail                                -> cnt; SHOT
    if eth->h_proto ∉ {ETH_P_IP, ETH_P_IPV6}              -> cnt; SHOT
    /* 不做 MAC 比对：设备本身就是来源边界（D3） */
I2  parse L3（与 egress 同一有界实现）
    if fragment                                           -> cnt(PASS_FRAG); TC_ACT_OK
                                                             /* 交内核 ip_defrag 重组后走 established 查找 */
    parse L4; if !TCP && !UDP                             -> cnt; SHOT
I3  if TCP:
        if SYN && !ACK:                                   /* 含重传与 TFO */
            sk = lookup_listener(c, family, TCP)
            if !sk: fault; cnt; SHOT
            if !guard(sk, c): release; fault; cnt; SHOT
            r = bpf_sk_assign(skb, sk, 0); bpf_sk_release(sk)
            if r != 0: fault; cnt(ASSIGN_FAIL); SHOT
            cnt(ASSIGN_TCP); return TC_ACT_OK
        else:
            cnt(PASS_ESTABLISHED); return TC_ACT_OK       /* 依赖内核 request/established 查找 */
I4  if UDP:
        sk = lookup_listener(c, family, UDP)
        if !sk: fault; cnt; SHOT
        if !guard(sk, c): release; fault; cnt; SHOT
        r = bpf_sk_assign(skb, sk, 0); bpf_sk_release(sk)
        if r != 0: fault; cnt; SHOT
        cnt(ASSIGN_UDP); return TC_ACT_OK
```

**边界**：I3 的 else 分支不是"必定 accepted"的承诺；若 request/established socket 不存在，内核可能 RST/drop。完整握手、TFO、重传、engine crash 必须在 Phase 0 覆盖（§16 Q3）。

**来源边界**：`flxrs1` 是 Flux 专有、无地址、只由 `flxrs0` 的 xmit 喂入的设备。除 root 外无人能向其注入 packet。这就是 provenance 边界；不再叠加 custom EtherType、token map 或 skb metadata。（注意：同 netns 的 veth **不会**清掉 `skb->mark`，见 §0.5.8 的更正——我们不用它是因为不需要，不是因为传不过去。）

**一条必须写下来的内核不变量：为什么 established 分支的 `TC_ACT_OK` 能正确交付。**

`bpf_sk_assign()` 会 `skb_orphan()` 后设 `skb->sk = 我们的 listener` 且 `skb->destructor = sock_pfree`。而 `ip_rcv_core()` / `ip6_rcv_core()` 有这一段（v6.1 `net/ipv4/ip_input.c:538-540`，注释原文 "Must drop socket now because of tproxy."）：

```c
	if (!skb_sk_is_prefetched(skb))
		skb_orphan(skb);
```

`skb_sk_is_prefetched()` 就是判 `destructor == sock_pfree`。于是两条路径各自正确：

| 路径 | 进 `ip_rcv_core` 时的 `skb->sk` | `ip_rcv_core` 是否 orphan | 后续查找结果 |
|---|---|---|---|
| SYN（已 assign） | 我们的 listener，destructor = `sock_pfree` | **否**（prefetched） | `skb_steal_sock()` 直接拿到 listener ✓ |
| established / fragment（未 assign） | **仍是 app 自己的 socket**（veth 跨越不 orphan） | **是** | `skb_steal_sock()` 得 NULL → 按 tuple 查到 engine 的 accepted child ✓ |

第二行为什么不会错查到 app 自己的 socket：established 查找的 key 是「local = daddr:dport，remote = saddr:sport」。我们的入向包是 `saddr=app_ip, sport=app_port, daddr=server_ip, dport=server_port`，所以 local 侧是 `server_ip:server_port`——那是 engine 的 transparent accepted child（`ir_loc_addr` 取自 SYN 的 daddr），**不是** app 的 socket（它的 local 是 `app_ip:app_port`）。

**由此得到两条禁令**：① **禁止**对 established/data 包调 `bpf_sk_assign`——把 listener 关联到数据段会让 `tcp_v4_rcv` 用错 socket；② **禁止**在任何地方"顺手"把 `skb->destructor` 设成 `sock_pfree`，那会跳过 `ip_rcv_core` 的 orphan，让 app 自己的 socket 有机会被 `skb_steal_sock` 取回，等于把 app 的报文交还给 app。这两条是 §7.5 的 I3 else 分支为什么必须是 `TC_ACT_OK` 而不是"再 assign 一次"的全部理由。

## 7.5.1 BPF verifier 陷阱清单

这些都是会让 §7.3–§7.5 的算法**无法加载**（而不是行为错误）的具体形态。每一条都写出正确写法，因为 verifier 的报错信息通常指不到真正的原因。

| # | 陷阱 | 正确写法 |
|---:|---|---|
| 1 | **helper 之后指针失效**。`bpf_skb_pull_data()`、`bpf_skb_change_head()`、`bpf_skb_store_bytes()` 之后，之前读到的 `data` / `data_end` 与所有派生指针全部失效 | 每次调用后**重新**从 `skb->data` / `skb->data_end` 读，并重做全部边界检查。不要把旧指针"顺手再用一次" |
| 2 | **标志与指针的关联不被跟踪**。`int ok = (c && ...); if (ok) c->field;` 会被拒 | 把 `c` 的解引用放进 `if (c && ...)` 的**同一个**条件链内。这正是 §7.3 E4 步不写成三元表达式的原因（reference C 里有显式注释） |
| 3 | **变长偏移的上界不可见**。`data + ip->ihl * 4` 中 `ihl` 来自包 | 先算进局部变量并**显式 clamp**（`if (ihl_bytes < 20 \|\| ihl_bytes > 60) return -1;`），再参与地址运算 |
| 4 | **`bpf_sk_lookup_*` 的引用必须在每条路径恰好 release 一次**。早退分支忘记 release 即"reference leak"，加载失败 | 每个 lookup 后立刻用单一出口结构（先 `guard`→存 bool→`release`→再按 bool 分支），不要在 `if` 内直接 `return` |
| 5 | `bpf_sk_fullsock()` **不取引用**，对它 `bpf_sk_release()` 会被拒（"reference has never been acquired"） | 只 release 来自 `bpf_sk_lookup_tcp/udp` 的指针 |
| 6 | **IPv6 扩展头循环**。`for` 循环上界必须是编译期常量，且累计偏移要有可见上界 | `#pragma unroll` + `FLUX_IPV6_MAX_EXT_HDRS`(4) + 累计字节 `FLUX_IPV6_MAX_EXT_BYTES`(256) 双上界，**先判上界再推进偏移** |
| 7 | **map value 指针的 NULL 检查不可省**，包括 `PERCPU_ARRAY` 的固定下标 | `counters` 的自增也必须 `if (v)`；见 reference C 的 `cnt()` |
| 8 | **map-in-map 的 inner 指针**：`bpf_map_lookup_elem(&control_root, &z)` 返回的是 map 指针，必须再 lookup 一次才是 value；两次都要判 NULL | 见 `ctrl()`；并且**整个 invocation 只 lookup 一次**（§6.4 的原子快照要求） |
| 9 | **`__builtin_memcmp` / `memcpy` 的长度必须是编译期常量** | 全部用固定长度（4/6/16），不要用变量长度 |
| 10 | **栈超限（512 字节）**。`struct bpf_sock_tuple` + `flux_pkt` + `flux_decision` 同时在栈上很容易接近上限 | `flux_pkt` 只存必要字段（当前 32 字节）；tuple 在使用处就地构造、不跨函数传递；`static __always_inline` 会共享调用者栈帧，注意累加 |
| 11 | **`skb->protocol` 是 `__be16` 零扩展**，不是主机序 | 与 `bpf_htons(ETH_P_IP)` 比较，不要与 `0x0800` 比 |
| 12 | **`bpf_sock->src_port` 是主机序，`dst_port` 是网络序**（内核 ABI 的既有不一致） | §7.4 的 guard 里对 `src_port` 用 `bpf_ntohs(listen_port)` 转换后比较 |
| 13 | **`-mcpu` 与内核不匹配**导致未知指令 | 固定 `-mcpu=v3`（5.15 支持），不要用 `v4` |
| 14 | **CI 必须在 5.15 内核上真实 `BPF_PROG_LOAD`**。在 6.x 上通过不代表 5.15 verifier 通过（新内核放宽了很多约束） | §15.1 已列为硬门禁 |

**调试纪律**：verifier 拒绝时，先看 log 的**最后 20 行**（失败点）而不是开头；`log_level=1` 足够，`log_level=2` 的指令级 dump 只在定位状态爆炸时用。§12.7 第 3 条的 log 重试机制保证不会因为 log buffer 太小而丢掉真正的错误。

## 7.6 UID policy 的流粘性

`uid_policy` 只有两个值：

- `FLUX_UID_SELECTED`：无决策的新 TCP 可判 DIRECT/CAPTURED；UDP 可入场。
- `FLUX_UID_DRAINING`：已有 TCP decision 继续按其 mode/generation 处理；无 decision 的首 SYN 安装 `DIRECT`；UDP direct。

移除 app 时把旧 UID 从 `SELECTED` 改为 `DRAINING`，**不删除**。增加 app 只影响尚无决策的连接。bypass 变化同理。

**硬不变量：同一 boot 内任何曾可能创建过 TCP decision 的 UID entry 都不得从 `uid_policy` 删除**，只能保留为 `SELECTED` 或 `DRAINING`。这维持了"UID miss ⇒ 走最短 Direct 路径"的语义（否则删除后旧 CAPTURED socket 的包会在 E1 就 `UNSPEC`，泄漏到真实目的）。`DRAINING` entry 最晚在设备重启后消失。

上限：总 UID entry ≤ 512，其中 SELECTED ≤ 128。候选配置若会超限，热更新被拒绝并保持当前策略。

---

# 第 8 部分：网络对象与所有权

## 8.1 专用 veth

| 属性 | 值 |
|---|---|
| host end | `flxrs0`，`IFLA_IFALIAS = "flux-rs:managed:v1:host"` |
| peer end | `flxrs1`，`IFLA_IFALIAS = "flux-rs:managed:v1:peer"` |
| 地址 | 两端均**不配置** IPv4/IPv6 |
| link state | 两端 UP |
| MTU | 两端 65535（`ETH_MAX_MTU`）；内核拒绝则整个 seam 不激活，不猜较小值 |
| MAC | 内核生成的随机 locally-administered pair，**Flux 不读取也不使用**（D17：egress 不写 MAC，ingress 直接强制 `PACKET_HOST`） |
| sysctl（`flxrs1`） | `net.ipv4.conf.flxrs1.rp_filter = 0`、`accept_local = 1`；`net.ipv6.conf.flxrs1.accept_ra = 0`、`autoconf = 0` |
| TC | `clsact` + `flx_in` ingress filter |

同名对象存在但 alias/layout 不完全匹配 → 视为**冲突**，保持 Direct 并报告；**绝不删除后重建**他人的对象。自有对象（alias 完全匹配）在 daemon 冷启动时删除后重建。

MTU 65535 的作用：让 `is_skb_forwardable()` 对任何非 GSO skb 都通过（GSO skb 本来就豁免）。

## 8.2 pkt_type：为什么在 ingress 修，而不是在 egress 写 MAC

`veth_xmit → __dev_forward_skb → eth_type_trans()` 会按目的 MAC 重新判定 `pkt_type`。目的 MAC 不等于 `flxrs1->dev_addr` 时置 `PACKET_OTHERHOST`，而 `ip_rcv()` 对 `PACKET_OTHERHOST` 直接丢弃。（已核验；注意 `skb_scrub_packet()` 先设的 `PACKET_HOST` 会被随后的 `eth_type_trans()` 覆盖，所以那条不算。）

有两种解法。**0.9.0 选后者（D17）**：

| | egress 写正确的 dst MAC | **ingress 调 `bpf_skb_change_type(skb, PACKET_HOST)`** |
|---|---|---|
| control 结构 | 需要 `peer_mac` + `host_mac` 共 12 字节 | 无 MAC 字段 |
| L2 捕获稳态热路径 | 每包一次 `bpf_skb_store_bytes(12)`，且会触发 `skb_ensure_writable()` —— TCP 重传 skb 是 clone，必须复制一份 | **零 packet 写入、零复制** |
| L3 路径 | `change_head` + 写 14 字节 | `change_head` + 只写 2 字节 EtherType（前 12 字节已被 helper 置零） |
| 正确性依赖 | 依赖 MAC 比对完全正确 | 依赖 TC ingress 在 `ip_rcv()` 之前运行（`sch_handle_ingress` 确实如此） |

**L3 路径仍必须写 EtherType**：`eth_type_trans()` 由 h_proto 推导 `skb->protocol`，`h_proto == 0` 的包永远到不了 `ip_rcv()`。

代价只有一条：注入到 `flxrs1` 的包带着零或过期的目的 MAC。那条链路上没有任何 L2 转发，属纯观感问题。

**上游先例**：dae 在它的 veth peer ingress 做的是同一件事（`control/kern/tproxy.c` 的 `tproxy_dae0peer_ingress` 调 `bpf_skb_change_type`），尽管它同时也在 egress 写了 MAC。

## 8.3 RPDB 与路由

双栈各一条：

```text
priority 100   iif flxrs1   lookup 20260
```

table `20260` 只含：

```text
local 0.0.0.0/0  dev lo  proto 202
local ::/0       dev lo  proto 202
```

priority 100 与 table 20260 的安全性现在有一手依据，不再是估计：

- **netd 的最低 `ip rule` priority 是 10000**（`clone/aosp-netd/server/RouteController.h:34`，完整阶梯 10000→32000 见 `:34-85`）。因此 **1–9999 整段是空的**，priority 100 落在内核 `local`(0) 之后、netd 全部规则之前。
- **netd 的 per-interface 路由表是 `ROUTE_TABLE_OFFSET_FROM_INDEX = 1000` 加 ifindex**（`RouteController.h:100`），即它占用大致 `1001 .. 1000+max_ifindex`。table **20260** 远在其外。（旁证：`box_for_magisk` 独立选了 table 2024 / pref 100，`box.iptables:12-13`。）

这条规则**只**匹配 Flux 专用 ingress，不占用任何 fwmark。若 live RPDB 已有 priority 100 的未知规则，或 table 20260 已有未知路由 → 保持 Direct 并报告冲突。**不动态挑另一个值**，因为 cleanup 必须可证明。

`proto 202` 是自选的 `rtm_protocol` 标记，用于精确识别自有路由。

## 8.4 rp_filter：前两版蓝图的实现级漏洞

**已核验**：`IN_DEV_RPFILTER(idev) = max(net.ipv4.conf.all.rp_filter, net.ipv4.conf.<dev>.rp_filter)`（`IN_DEV_MAXCONF`），而 `IN_DEV_ACCEPT_LOCAL` 是 **or**（`IN_DEV_ORCONF`）。

我们注入到 `flxrs1` 的包，源地址是设备**自己的**地址（例如 wlan0 的 IP），目的是远端服务器。输入路由命中 `RTN_LOCAL` 后走 `fib_validate_source()`：

- 若有效 rp_filter 为 0：因为我们添加了自定义 local 路由，`net->ipv4.fib_has_custom_local_routes` 为真，会进 `__fib_validate_source()`；`accept_local=1` 让 `res.type == RTN_LOCAL` 通过；`dev_match` 为假；`flxrs1` 无地址故 `no_addr` 为真 → `last_resort:` → `rpf == 0` → **接受**。
- 若有效 rp_filter 非 0：同一路径最终 `goto e_rpf` → **martian source 丢包**。此时 `accept_local` 救不了（它只在 `r == 0` 的早退分支起作用）。

**实现要求**：activation 时读取 `all.rp_filter` 与 `flxrs1.rp_filter`。
- `flxrs1.rp_filter` 由 Flux 设为 0（自有对象，允许写）。
- `all.rp_filter != 0` 时**不得**擅自修改全局 sysctl（会降低系统整体安全姿态）。此时整个数据面保持 Inactive，`status` 报告 `rp_filter_conflict` 并给出人工处置说明。
- AOSP 默认不设置 `rp_filter`（依赖自己的 RPDB），因此实际设备上预期为 0；但**必须检查**而不是假设。

**Android 上没有先例，但 dae 在 Linux 上遇到并证实了同一个问题。**

`clone/AndroidTProxyShell/tproxy.sh` 全脚本从不写 `rp_filter` 或 `accept_local`，原因不是 Android 不需要，而是它的包从 **`lo`** 重新入栈，命中了 `__fib_validate_source()` 里 `dev_match = dev_match || (res.type == RTN_LOCAL && dev == net->loopback_dev)` 的早退分支。我们的包从 `flxrs1` 进来，走不到那条分支。

而 **dae 走的正是 veth 回送，它必须写这些 sysctl**（`control/netns_utils.go:433-473`）：

| sysctl | dae 的值 | 行 |
|---|---|---|
| `net.ipv4.conf.dae0.rp_filter` | 0 | 437 |
| **`net.ipv4.conf.all.rp_filter`** | **0** | **440** |
| `net.ipv4.conf.dae0.arp_filter` / `all.arp_filter` | 0 | 443 / 446 |
| `net.ipv4.conf.dae0.accept_local` | 1 | 449 |
| peer 侧 `conf.dae0peer.accept_local` | 1 | 473（注释明写 martian-source） |

**这印证了 §8.4 的内核分析是对的，同时暴露出一个我们不接受的取舍：dae 直接写全局 `all.rp_filter=0`。** 0.9.0 **禁止**这么做，理由有两条：① 在用户手机上静默削弱一个全局安全 sysctl，不是一个网络模块该做的事；② 崩溃后无法证明该恢复成什么值，"备份-恢复"在 `SIGKILL` 下不可靠（这正是 §15.4(1) 状态诚实性规则的适用场景）。因此有效 `rp_filter != 0` 时我们保持 Inactive 并报告，把决定权交给用户。

`arp_filter` 我们**不需要**：`flxrs0/1` 无 IPv4 地址，不参与 ARP。Phase 0 Q5 顺带确认。

**结论**：机制被 dae 证实，但"Android 上有效 `all.rp_filter` 是否为 0"以及"不写全局 sysctl 是否可行"仍必须实测（§16 Q5）。

### 8.4.1 两条外部证据，以及一条明确不适用的 sysctl

**(1) dae 有一份带 drop trace 的实证**（`daeuniverse/dae` PR #512，CHANGELOG `:403`）。它甚至发生在 dae 的**独立 netns** 里，而我们是同 netns、源地址就是本机地址，所以对我们只会更确定：

```
if=83(dae0peer) ... 10.0.8.9:35964 > 1.1.1.2:80 tcp_flags=S ... fib_validate_source
if=83(dae0peer) ... ip_handle_martian_source
if=83(dae0peer) ... kfree_skb_reason(SKB_DROP_REASON_NOT_SPECIFIED)
```

修复正是 `sysctl net.ipv4.conf.dae0peer.accept_local=1`。这把 §8.4 的推理从"内核源码推导"升级为"有人踩过并留下了 trace"。顺带记下：**这一串 `pwru` + `kfree_skb_reason` 是本类问题唯一有效的调试手段**，Phase 0 Q5 若失败应当直接用它，而不是猜。

**(2) Cilium 在同构拓扑上（fwmark 规则 → `local default dev lo`）遇到同一问题**（`cilium/cilium` PR #46312），并指出它一直漏了 `accept_local`、只设了 `rp_filter=0`——两者应当**成对**设置。这与 §8.4 的结论一致（`IN_DEV_ACCEPT_LOCAL` 是 `or`、`IN_DEV_RPFILTER` 是 `max`，两个都得对）。

**(3) `net.ipv4.conf.all.src_valid_mark` 明确不适用，不要照抄。** Cilium 设它，作用是让 `fib_validate_source()` 的反查**带上 fwmark**，从而命中基于 mark 的规则。我们的规则是 `iif flxrs1` 而非 `fwmark`，而反查时 `iif` 是 `lo`，所以带不带 mark 都不会命中我们那条规则——设了没用。**记录在此，防止实现者从 Cilium 抄一个无效的全局 sysctl。**

**(4) AOSP 自己从不设置这四个 sysctl。** 遍历 `clone/aosp-netd/server` 与 `clone/aosp-Connectivity` 全树，`rp_filter` / `accept_local` / `route_localnet` / `src_valid_mark` **零命中**。含义是双向的：好消息是没有 AOSP 组件会跟我们抢或把值改回去；坏消息是**有效值完全由厂商 defconfig 与 `init.rc` 决定，无法从 AOSP 推断**。这直接决定了 §8.4 的实现要求必须是"运行时读取 + 冲突则响亮失败"，不能有任何默认值假设。

**`ip_forward` 是一条推断，必须被实测确认。** 我的分析是：包命中 `RTN_LOCAL` 本地交付、走 `ip_local_deliver` 而非 `ip_forward_finish`，因此**不需要**打开 `ip_forward`。但两个先例都打开了它——AndroidTProxyShell 为其转发/热点路径设 `ip_forward=1` 与 `ipv6 conf/all/forwarding=1`（`tproxy.sh:1414-1415`、`1433-1434`），dae 也在文档里列为必需（`clone/dae/docs/en/user-guide/kernel-parameters.md`）。两者都有 LAN/转发路径，所以它们需要不代表我们需要。

**Phase 0 Q5 必须以 `ip_forward=0` 跑通端到端**。若实测发现必需，那是一次**范围变更**而非小修：写全局 `ip_forward` 与 §8.4 拒绝写 `all.rp_filter` 的理由同源（在用户手机上改全局网络语义），届时必须回到 §21 重新征求确认，不得默默打开。dae 另外还设了 `arp_filter=0`（含 `all.`）；我们的 `flxrs0/1` 无 IPv4 地址、不参与 ARP，判断为不需要，同样在 Q5 确认。

IPv6 没有 rp_filter，无此问题。

## 8.5 TC identity 与 ownership 谓词

| 位置 | chain | pref | protocol | handle | program |
|---|---:|---:|---|---:|---|
| 普通 L2 egress | 0 | 1 | all | `0x1` | `flx_cap_l2` |
| 普通 L3 egress（rmnet） | 0 | 1 | all | `0x1` | `flx_cap_l3` |
| 已确认 CLAT egress | 0 | 1 | ip | `0x1` | `flx_cap_l3` |
| `flxrs1` ingress | 0 | 1 | all | `0x2` | `flx_in` |

完整 ownership 谓词（**全部**匹配才可接管或删除该 filter）：netns、ifindex、ifname、parent/direction、chain、preference、protocol、handle、`kind == "bpf"`、direct-action 标志、**`TCA_BPF_ID`（program id）**、**`TCA_BPF_TAG`（8 字节指令流哈希）**、`TCA_BPF_NAME`、program 的预期 map 集合。

**为什么必须带 id 与 tag**：program name 可被伪造，也会在 program 被替换后保持不变；`TCA_BPF_TAG` 是内核对指令流算的哈希，`TCA_BPF_ID` 是本次加载的唯一 id。两者都由我们自己 `BPF_OBJ_GET_INFO_BY_FD` 得到并作为期望值。这条来自 `clone/asteriskd/asteriskd_tc_netlink.c:170-177` 的五路精确匹配（`TCA_BPF_NAME`/`FLAGS`/`FLAGS_GEN`/`TAG`/`ID`），是本轮调研里最值得直接照搬的一条。

**netlink dump 解析必须 allowlist**：顶层与 `TCA_OPTIONS` 内的属性类型都只接受已知集合，出现未知/重复属性即解析失败并把该 slot 判为 foreign（`asteriskd_tc_netlink.c:141-157`）。`NLMSG_OVERRUN` 视为致命。**一切失败路径都判 foreign 并 fail closed**，不得"看起来像我们的就接管"。

**双次 dump 的 TOCTOU 守卫**：删除或接管任何 filter 之前，连续取两次 dump，逐项比对 `{id, tag, name, flags}`；不一致则返回 `ESTALE` 并放弃本轮，下个事件重来。这条来自 `clone/bpf2socks/bpf_util.c:411-454` 对 `BPF_PROG_QUERY` 的同样处理。

**`clsact` 的 foreign 判定**：若 dump 显示该 `clsact` 携带 `TCA_INGRESS_BLOCK`(13) 或 `TCA_EGRESS_BLOCK`(14)，或 `TCA_OPTIONS` 非空，则判为 foreign 并**排除该 interface**——共享 block 意味着另一个控制器在通过我们看不见的间接层管理 filter（`asteriskd_tc_netlink.c:333-341`）。这是 §8.5 "block/goto 使 chain 0 不可达"的具体检测手段。

**first-applicable 要求**：三个 filter 必须是各自 protocol 在 chain 0 的首个适用 classifier。Direct 用 `TC_ACT_UNSPEC` 交给全部后续系统程序。pref 1 被未知 filter 占用、存在更早适用 classifier、`block`/`goto` 使 chain 0 不可达、或 attach 后 dump 顺序不满足谓词 → 该 interface **不得**标为 active。已知 AOSP ingress accounting 返回 `TC_ACT_UNSPEC`、CLAT translation 返回 `TC_ACT_PIPE`，但这不能替 OEM 程序背书；固定 first-applicable 顺序比维护 program-name 白名单更小、更可证明。

**`clsact` 规则**：Flux 可在不存在时创建，但**永不删除** `clsact`（crash 后无法证明是谁最初创建；而且删掉它会连带破坏 tethering 与 CLAT）。只删除精确自有 filter；**禁止** flush qdisc 或 chain。

### 8.5.1 netd 会删掉 `clsact`——这是常态事件，不是异常

这是本轮调研里**运维上最重要的一条**，必须按"频繁发生"来设计，而不是按"异常处理"。

`clone/aosp-netd/server/RouteController.cpp:1201-1229` 的 `maybeModifyQdiscClsact()` 在 **interface 加入网络时创建、离开网络时删除** `clsact`（调用点 `:1347` / `:1374` / `:833`）。更彻底的是 netd 启动时会清空所有 interface 的 clsact：

```cpp
// clone/aosp-netd/server/NetworkController.cpp:152-164
// Clear all clsact stubs on all interfaces.
for (const std::string& iface : ifaces.value()) {
    if (int ifIndex = if_nametoindex(iface.c_str())) {
        tcQdiscDelDevClsact(ifIndex);
    }
}
```

AOSP 自己在 `ConnectivityService.java:12231-12240` 记录了这个约束："*in case of a system server crash, the NetworkController constructor in netd (called when netd starts up) deletes the clsact qdisc of all interfaces*"。

**对本设计的直接后果**：

1. **每一次 Wi-Fi 重连、蜂窝切换、system_server 崩溃后的 netd 重启，都会把我们的 filter 连带删掉。** 这不是罕见故障，是日常。
2. 因此 reactor **必须**订阅 `RTM_NEWQDISC` / `RTM_DELQDISC` 并把"qdisc 消失"当作**预期事件**处理：只对受影响的那个 interface 重走 §8.7 步骤 9 的 egress attach（必要时先重建 clsact），**不报错、不进 `Inactive`、不动 `active`**。§26 把它单列为**捕获侧漂移**，与需要 `active=0` 的**核心漂移**分开——两者绝不能混为一谈，理由见 §26 不变量 4。
3. **创建时不要期望自己是唯一创建者。** AOSP 用 `tcQdiscReplaceDevClsact`（`NLM_F_CREATE | NLM_F_REPLACE`，`aosp-netd/server/TcUtils.h:28-37`）。我们用 `NLM_F_EXCL` 并把 `EEXIST` 当成"存在且非我创建"（§8.9.4），效果等价且额外获得了"是谁创建的"这一信息。
4. 每次重新 attach 之间存在流量走 Direct 的窗口，量级为 rtnetlink 送达 + §10.4.1 debounce，见 §2.2.3(5)。

### 8.5.2 AOSP 在物理 interface 上已占用的 TC 优先级

| pref | 方向 | protocol | 占用者 | 依据 |
|---:|---|---|---|---|
| 1 | ingress | `ETH_P_ALL` | `tc police` 入向限速 | `ConnectivityService.java:974`（`TC_PRIO_POLICE = 1`）、`:1730` |
| 2 | ingress | `ETH_P_IPV6` | tethering downstream6 | `Tethering/.../BpfUtils.java:57-61` |
| 3 | ingress | `ETH_P_IP` | tethering downstream4 | 同上 |
| 4 | ingress | `ETH_P_IPV6` | CLAT ingress6（upstream 上） | `ClatCoordinator.java:107-109`、`:499-505` |
| 4 | **egress** | `ETH_P_IP` | CLAT egress4（`v4-*` 上） | `ClatCoordinator.java:473-479` |
| **5** | **egress** | `ETH_P_ALL` | **dscpPolicy** | `DscpPolicyTracker.java:50-51`（`PRIO_DSCP = 5`）、`:338` |

**三条结论**：

1. **ingress pref 1 在物理 interface 上是冲突的**（`tc police`）。这不影响我们——我们的 ingress filter 只装在自有的 `flxrs1` 上，那里没有别人。
2. **egress pref 1 无硬冲突**，`v4-*` 上的 CLAT egress 在 pref 4，我们在 pref 1 先跑，正是 §3.4 要求的顺序。
3. **但 egress pref 5 的 `dscpPolicy` 会被跳过**：被捕获的包在 pref 1 返回 `TC_ACT_REDIRECT`，chain 终止，dscpPolicy 看不到它。后果见 §2.2.3(6)。**不要因此改到 pref ≥ 6**——那样一旦 pref < 6 的某个 filter 返回 `TC_ACT_PIPE`/`TC_ACT_OK`，chain 就在我们之前终止，我们**完全不会运行**。留在 pref 1 + `TC_ACT_UNSPEC` 是唯一自洽的选择。

## 8.6 interface admission

由 rtnetlink 的 live link/address/route 事件收集"可能承载本机输出"的 interface，**不按名字硬编码**。排除：

- `lo`、`flxrs0`、`flxrs1`；
- generic TUN/TAP、活跃 Android VPN、bridge、bond、veth、dummy、team；
- tether / downstream / LAN-only interface；
- VLAN、未知 ARPHRD、未知 layout；
- 已有 TC filter 占用 Flux 精确 identity 的 interface；
- 无法确认 first-applicable 顺序的 interface（含条件不满足的 `v4-*`）。

一个 interface 失败只排除该 interface，其余继续。候选总数硬限 64；超限时整个新 topology 候选不 promote，保持当前/Direct，**不按名字截断**。`status` 必须逐个列出 `active` 或 `excluded(reason)`。

## 8.7 有序激活（冷启动，配置有效）

严格按序，任一步失败不进入后续；已存在的 control snapshot 保持 `active=0`：

1. 取 daemon lock；检查 `sysconf(_SC_PAGESIZE) == 4096`、netns 一致、运行目录权限；page size 不支持则立即 Inactive/Direct，不启动 engine、不建任何对象。
2. **清理**：按 ownership 谓词枚举并删除全部残留自有对象（TC filter、RPDB rule、route table 条目、veth）。发现"同名但不匹配"的对象 → 冲突，Inactive 并报告。
3. 检查 `all.rp_filter`；创建 veth、设置 MTU/sysctl/UP。（**不需要读 MAC**——D17 之后 control 结构里没有 MAC 字段。）
4. 创建 route table 20260 条目与两条 RPDB 规则。
5. 加载 BTF 与 9 个 map、3 个 program；注册 ringbuf 到 epoll；publish 初始 frozen `active=0` leaf。
6. 解析 `packages.list` 与配置，填充 `uid_policy` 与两张 LPM（含固定 + 本机地址 bypass）。
7. 生成 effective JSON → `sing-box check` → 启动 child → 等待 4 个 socket 通过 SOCK_DIAG + PID/inode 核验。
8. 在 `flxrs1` 创建 `clsact` 并 attach `flx_in`（**先于** egress，保证回送侧就绪）。
9. 逐个 attach 可支持的 egress filter（每个独立，失败只排除该 interface）。
10. 最后一次 `control_root` pointer swap，发布完整 generation snapshot 与 `active=1`。

正常停止：先 publish `active=0` leaf，再关 engine。

## 8.8 崩溃残留

`fluxd` 异常死亡后 TC program/map 可能续存，但其直接 child 因 `PR_SET_PDEATHSIG=SIGKILL` 被内核终止，listener 随进程关闭。后果：

- 未入场 TCP/UDP 因 `listener_alive()` miss 而 Direct（**这是承担 fail-open 的机制**）；
- 已有 TCP decision 的包仍会 redirect，随后 ingress lookup miss 而 drop；
- `service.sh` 重启 fluxd 后走 §8.7 的删除-重建，一切归零。

手工 `disable`/`stop` 同样先 publish `active=0` 再停 engine；对象保留到 daemon 重启或设备重启。卸载后重启，全部非持久内核对象自然消失。

## 8.9 netlink 消息级规格

因为 §12.8 决定不 shell out 到 `ip`/`tc`，这些消息必须自己编码。这一节把每条消息的**精确字段**写死，避免实现者靠猜。所有属性用标准 `nlattr` TLV（4 字节对齐），所有请求带 `NLM_F_REQUEST | NLM_F_ACK` 并**必须等待并检查 `NLMSG_ERROR`**（`error == 0` 才是成功；忽略 ACK 是最常见的静默失败）。

### 8.9.1 创建 veth 对

`RTM_NEWLINK`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`（`EXCL` 让"已存在"变成显式 `EEXIST` 而不是静默改写）：

```text
ifinfomsg { ifi_family = AF_UNSPEC, ifi_type = 0, ifi_index = 0, ifi_flags = 0, ifi_change = 0 }
  IFLA_IFNAME    = "flxrs0"
  IFLA_MTU       = 65535
  IFLA_LINKINFO (nested)
    IFLA_INFO_KIND = "veth"
    IFLA_INFO_DATA (nested)
      VETH_INFO_PEER (nested)          /* = 1 */
        ifinfomsg { 全零 }             /* 必须有这个内嵌头，长度算在 attr 内 */
        IFLA_IFNAME = "flxrs1"
        IFLA_MTU    = 65535
```

**易错点**：`VETH_INFO_PEER` 的 payload **以一个完整的 `struct ifinfomsg` 开头**，之后才是 peer 的属性。漏掉它会得到 `EINVAL`。

alias 与 up 分两条消息（`RTM_NEWLINK`，不带 `CREATE|EXCL`，按 `ifi_index` 定位）：

```text
/* 打 alias，用于 §8.5 的所有权识别 */
ifinfomsg { ifi_index = <idx> }   IFLA_IFALIAS = "flux-rs:managed:v1:host"
/* 置 UP */
ifinfomsg { ifi_index = <idx>, ifi_flags = IFF_UP, ifi_change = IFF_UP }
```

`ifi_change` 是掩码，**必须只置要改的位**；置 `~0` 会把其它 flag 一起写成 0。

### 8.9.2 route table 20260 的两条 local 路由

`RTM_NEWROUTE`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`：

```text
rtmsg {
  rtm_family   = AF_INET (或 AF_INET6)
  rtm_dst_len  = 0                     /* default */
  rtm_src_len  = 0
  rtm_tos      = 0
  rtm_table    = RT_TABLE_UNSPEC       /* 0；表号 > 255 必须走 RTA_TABLE */
  rtm_protocol = 202                   /* FLUX_ROUTE_PROTO，自有标记 */
  rtm_scope    = RT_SCOPE_HOST         /* RTN_LOCAL 必须是 HOST */
  rtm_type     = RTN_LOCAL
  rtm_flags    = 0
}
  RTA_TABLE = 20260
  RTA_OIF   = <lo 的 ifindex，通常 1，但必须查>
```

**三个易错点**：① 表号 20260 超过 `rtm_table` 的 8 位，必须用 `RTA_TABLE` 且 `rtm_table` 置 `RT_TABLE_UNSPEC`；② `rtm_type = RTN_LOCAL` 时 `rtm_scope` 必须是 `RT_SCOPE_HOST`，写 `UNIVERSE` 会 `EINVAL`；③ `lo` 的 ifindex **要查不要写死 1**。

### 8.9.3 两条 RPDB 规则

`RTM_NEWRULE`（=`RTM_NEWROUTE` 的 rule 变体，消息体是 `struct fib_rule_hdr`），flags 同上：

```text
fib_rule_hdr {
  family   = AF_INET (或 AF_INET6)
  dst_len  = 0, src_len = 0, tos = 0
  table    = RT_TABLE_UNSPEC           /* 同样走 FRA_TABLE */
  action   = FR_ACT_TO_TBL             /* = 1 */
  flags    = 0
}
  FRA_PRIORITY = 100                   /* FLUX_RULE_PRIORITY */
  FRA_TABLE    = 20260
  FRA_IIFNAME  = "flxrs1"              /* 注意是 IIFNAME，不是 OIFNAME */
```

**`FRA_IIFNAME` 是整个设计的关键**：它把这条规则的作用域限制到只有 Flux 注入的包会命中的入口设备。用 `FRA_FWMARK` 会占用 Android fwmark 空间（§3.1）；用 `iif lo` 会灾难性地命中**全部本机发出的流量**（netd 正是用 `iif lo` 表示"本机产生"）。

删除用 `RTM_DELRULE`，**必须带上完全相同的 `FRA_PRIORITY` + `FRA_TABLE` + `FRA_IIFNAME`**；只带 priority 会删掉别人的规则。

### 8.9.4 `clsact` qdisc

`RTM_NEWQDISC`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`：

```text
tcmsg {
  tcm_family = AF_UNSPEC
  tcm_ifindex = <idx>                  /* 操作前一刻重新 if_nametoindex，见 §10.4.1 */
  tcm_handle  = 0xFFFF0000             /* TC_H_MAKE(TC_H_CLSACT, 0) */
  tcm_parent  = 0xFFFFFFF1             /* TC_H_CLSACT */
  tcm_info    = 0
}
  TCA_KIND = "clsact"
```

`EEXIST` **不是错误**：记录"该 clsact 非我创建"，此后**永不删除它**（§8.5）。同时必须 dump 一次确认它没带 `TCA_INGRESS_BLOCK`(13) / `TCA_EGRESS_BLOCK`(14) 且 `TCA_OPTIONS` 为空，否则判 foreign 并排除该 interface。

### 8.9.5 BPF filter

`RTM_NEWTFILTER`，flags `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`：

```text
tcmsg {
  tcm_family  = AF_UNSPEC
  tcm_ifindex = <idx>
  tcm_handle  = 0x1                    /* egress；ingress 用 0x2 */
  tcm_parent  = 0xFFFFFFF3             /* egress: TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) */
                                       /* ingress: 0xFFFFFFF2 (TC_H_MIN_INGRESS) */
  tcm_info    = TC_H_MAKE(prio << 16, htons(protocol))
                                       /* prio = 1；protocol = ETH_P_ALL(0x0003) 或 ETH_P_IP(0x0800) */
}
  TCA_KIND = "bpf"
  TCA_OPTIONS (nested)
    TCA_BPF_FD    = <program fd>       /* = 6 */
    TCA_BPF_NAME  = "flx_cap_l2"       /* = 7；仅诊断用，不是所有权证明 */
    TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT (=1)   /* = 8；即 `da` */
```

**`tcm_info` 的字节序陷阱**：高 16 位是 priority（主机序），低 16 位是 protocol 且必须是**网络字节序**。写成主机序会得到一个匹配不到任何包的 filter，而且不报错——这是最难查的一类错误。

dump 用 `RTM_GETTFILTER` + `NLM_F_DUMP`，`tcmsg{ tcm_ifindex, tcm_parent }`。内核在响应里额外返回 `TCA_BPF_ID`(11)、`TCA_BPF_TAG`(10)、`TCA_BPF_FLAGS_GEN`(9)，§8.5 的所有权谓词就靠这三个。**dump 顺序即执行顺序**，first-applicable 判定直接读顺序。

删除用 `RTM_DELTFILTER`，**必须带完全相同的 `tcm_handle` + `tcm_parent` + `tcm_info` + `TCA_KIND`**。少任何一项都可能删到别人的 filter，或者删掉整条 chain。

### 8.9.6 sysctl

`rp_filter` / `accept_local` 走 `/proc/sys/net/ipv4/conf/<if>/...` 的普通文件写，不走 netlink。写入前先读原值并记入内存（用于 §23 的诊断），但**不做"恢复原值"**——`flxrs0/1` 是我们每次启动重建的对象，没有需要保护的原值。`all.rp_filter` 只读不写（§8.4）。

---

# 第 9 部分：sing-box 集成

## 9.1 注入的 inbound（每 generation 两个，4 个 kernel socket）

| tag | family | listen | listen_port | 说明 |
|---|---|---|---|---|
| `flux-in-v4` | IPv4 | `198.18.0.2` | 随机 `actual4` | `type: "tproxy"`，TCP+UDP |
| `flux-in-v6` | IPv6 | `2001:db8::2` | 随机 `actual6` | `type: "tproxy"`，TCP+UDP |

生成方式：深拷贝用户 `Value`；断言 `inbounds` 缺失或为空数组；写入上述两个对象。**不注入** `route.rules`、不改用户 DNS/outbounds/log。

注入的 JSON 只允许出现这些键：`type`、`tag`、`listen`、`listen_port`。**禁止**出现 `sniff*`、`domain_strategy`、`udp_disable_domain_unmapping`（1.13.0 已移除）、`bind_interface`、`routing_mark`、`reuse_addr`（见 §9.2 与 §9.3）。

端口：两个不同的随机值，取自 `61000..=65535`（Android 的 `ip_local_port_range` 通常是 `32768..60999`，因此不与 ephemeral 分配冲突），由 `getrandom()` 生成，在本 generation 内固定。**端口不是身份凭据**，只用于避免碰撞。

非本地绑定地址：sing-box 的 tproxy inbound 会在 bind 前设置 `IP_TRANSPARENT`/`IPV6_TRANSPARENT`，而 `inet_can_nonlocal_bind()` 允许 transparent socket 绑定非本地地址（root 有 `CAP_NET_RAW`）。选 `198.18.0.0/15`（RFC 2544）与 `2001:db8::/32`（RFC 3849）是因为它们不会被路由；两个前缀同时进固定 bypass（D16）。

## 9.2 硬约束：不得有 `SO_REUSEPORT`

**已核验**：6.5 之前 `bpf_sk_assign()` 对 `sk->sk_reuseport` 为真的 socket 返回 `-ESOCKTNOSUPPORT`。

- **`SO_REUSEPORT` 在 `SagerNet/sing-box@v1.13.19` 全代码树零命中**（`clone/` 内 `rg` 复核，§0.5.1）。约束成立。
- 内核侧的精确边界已核对：v6.1 的 `bpf_sk_assign()` 含 `if (unlikely(sk_fullsock(sk) && sk->sk_reuseport)) return -ESOCKTNOSUPPORT;`（`net/core/filter.c:7167-7186`）；该行在 v6.6 / v6.12 已被替换为 `if (sk_unhashed(sk)) return -EOPNOTSUPP;`。**GKI 5.10 / 5.15 / 6.1 全部落在旧行为一侧。**
- **6.5 之前还缺少 unhashed socket 的拒绝**，因此在"listener 刚被 unhash"的瞬间 assign 会**永久泄漏一次 socket 引用**。本设计靠 §9.4 的顺序把它关掉：候选切换时**先 publish `active=0`**（`flx_in` 在 I0 就 SHOT，不再 lookup/assign），**再**终止旧 child。残余窗口只剩"engine 意外崩溃到 pidfd 唤醒 fluxd 之间"的数百微秒，后果是极少量 socket 对象不被回收。**已知并接受**，不为此增加机制。
- `redir.TProxy()` 无条件设置 `SO_REUSEADDR`（`common/redir/tproxy_linux.go:16`），这与 `bpf_sk_assign` 无关。因此"不注入 `reuse_addr`"只是为了 effective JSON 最小，不改变 socket 行为。
- 仍然**禁止**让用户 JSON 影响这两个内部 inbound。
- Phase 0 仍必须以"assign 实际成功"作为最终证明（§16 Q2）：升级 engine 版本时该零命中结论必须重新核验。

## 9.3 硬约束：actual listener 不得带 mark 或 bind_interface

- `routing_mark` 会被 accepted child socket 继承（`ireq->ir_mark = inet_request_mark(sk, skb)`），使 SYN-ACK 按 Android fwmark 语义被解读为某个 netId → 大概率 `unreachable`，握手失败。
- `bind_interface`（`SO_BINDTODEVICE`）会传播到 TCP child 与 UDP 回写 socket，破坏"回程经 `lo` 送达 app"的路径。

## 9.4 engine 候选切换（唯一 commit point）

1. 生成 boot 内单调且不复用的新 `generation` 与两个随机端口；以 `O_CREAT|O_EXCL|O_NOFOLLOW` 写入并 `fsync` 权限 `0600` 的 `run/effective-sing-box.<generation>.json`；从该 exact immutable 路径执行 `sing-box check -c`。写入或 check 失败 → 只删除 candidate 文件，**当前 engine 完全不动**。
2. 保留 current control leaf 与 current generation 文件；publish 同 generation 的 `active=0` leaf。
3. 正常终止旧 child（`SIGTERM` → 短 deadline → `SIGKILL`，pidfd 确认退出）。**同一时刻最多一个运行中的 sing-box。**
4. 在 inactive 状态清空 `fault_latch`；启动 candidate child；等待两个 inbound 对应的 4 个 socket 通过 PID/inode 核验。
5. ready 后创建/freeze 新 generation 的 `active=1` leaf 并执行**单次** `control_root` pointer swap —— **这是唯一 commit point**。旧 generation 的 TCP decision 从此 drop/reset，新连接进入新 generation。随后内存里把 candidate 设为 current，旧 generation 文件 best-effort 删除（删除失败只记控制面错误，不回滚已提交的数据面）。
6. candidate 启动或 swap 失败 → 停止它，用**始终未改名、未覆盖**的 current generation 文件重启旧 generation 并核验 4 个 socket；恢复成功才重新 publish 旧 `active=1`；恢复失败则保持 `active=0` 并报错。

不依赖无法同步确认成功的 sing-box `SIGHUP`；不并行运行两个完整 engine（避免端口/cache/log/API 资源冲突）。短暂 inactive 期间新流走 Android 原路径、已入场 TCP 的包 drop 并依赖重传；配置 reload 是低频控制操作，这个确定性窗口比双 child 平台更符合模块复杂度预算。

## 9.5 listener readiness（不 sleep、不解析日志）

按 `2 family × 2 protocol` 通过 `NETLINK_SOCK_DIAG`（`SOCK_DIAG_BY_FAMILY`，`inet_diag`）枚举 4 个 exact socket，并把每个 socket 的 inode 与 `/proc/<candidate-pid>/fd/*` 交叉核验。该检查只建立"promote 时这 4 个 socket 确由 candidate 持有"的控制面证据；运行中仍以 BPF 的 `listener_alive()` 逐包准入，**不做周期 diag 轮询**。

candidate 启动期间允许 timerfd 做有截止时间的短退避重查（10/20/40 ms 递增，封顶 250 ms，总 deadline 5 s）；ready 或失败后立即取消。它不是稳态 polling，也不得被扩展成健康探针。

## 9.6 用户 sing-box.json 边界

上限 8 MiB；必须是完整官方配置，并满足：

- `inbounds` 缺失或为空数组（两个 tproxy inbound 只由 fluxd 注入）；
- 不得使用 `flux-` 前缀的 tag；
- Flux **不改**用户的 `dns` / `outbounds` / `route` / `log` / `experimental`；
- 用户自设 outbound `routing_mark` / `bind_interface` 的 Android 后果由用户承担，Flux 只在 `status` 告警，不建大而脆弱的 policy validator。

随 module 提供的默认 `sing-box.json` 只有官方 direct outbound 与 `final`、无 inbound，**但必须带上 §1.3.4 的 `sniff` + `hijack-dns` 两条 route rule**，否则被捕获的 :53 会被当普通 UDP 转发、白白丢掉域名分流能力。加上 fresh install 默认 disabled，安装动作本身不会接管任何流量。默认文件是 bootstrap 样例，不是第二权威副本。

`fluxd check` 额外做一项**非阻塞**检查：用户 JSON 的 `route.rules` 里若找不到能处理 :53 的 action（`hijack-dns`，或用户自己写的等价规则），输出警告"selected apps' DNS will be forwarded verbatim; domain rules will not apply"。**只警告，不拒绝**——用户可能就是想让 DNS 原样穿透。

## 9.7 engine.lock

```toml
version         = "1.13.19"
upstream_commit = "b5ebaa1fc0f2b94256180b95468e73ef53caa27d"
asset           = "sing-box-1.13.19-android-arm64.tar.gz"
asset_size      = 18106459
sha256          = "e737ac40187563673e1fc282aebf1774e09f3b2057203872798968a2126fab53"
pt_load_align   = "0x1000"   # 四段均为 0x1000 → 0.9.0 只支持 4 KiB base page
```

构建只下载该官方 asset，校验 size + SHA-256，抽取原 binary；**不 strip、不 patch、不重签**。`xtask` 同时解析 ELF program headers，要求四个 `PT_LOAD` 仍精确为 `0x1000`，防止上游同名资产静默变化。

升级 engine 是显式设计变更：先重核 TProxy listener 选项与 orig-dst 合同、ELF alignment，再更新 lock。0.9.0 release 页必须与 ZIP 同处提供该官方 binary 的 exact Corresponding Source bundle 及构建脚本/依赖来源（GPL 合规），source bundle 不塞进 module ZIP。

---

# 第 10 部分：控制面

## 10.1 状态机

只有三个顶层状态：

| 状态 | 含义 |
|---|---|
| `Disabled` | `state/enabled == 0`。不启动 engine、不新建或激活数据面。 |
| `Inactive` | `enabled == 1` 但正在启动/重启，或被明确错误阻断。control `active == 0`。 |
| `Active` | control `active == 1`。 |

hot candidate 无效时**保持当前 `Active` generation**并附带 candidate error，不创造第四种持久状态。daemon 重启后只从权威文件重新求值。

## 10.2 类型骨架

```rust
// ---------- flux-core/src/config.rs ----------
pub struct FluxConfig {
    pub apps: Vec<AppSelector>,     // canonical、去重、<= 128
    pub bypass_v4: Vec<Ipv4Cidr>,   // 不含固定项
    pub bypass_v6: Vec<Ipv6Cidr>,
}
pub struct AppSelector { pub user_id: u32, pub package: String }   // "10:com.x"

pub enum ConfigError {
    TooLarge, TooManyApps, TooManyCidrs, NotCanonical, Duplicate,
    AppIdOutOfRange { app_id: u32 },   // 只接受 10000..=19999
    Parse(String),
}
impl FluxConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError>;             // <= 256 KiB
    /// 固定安全 bypass + listener 前缀；不含本机动态地址（那是 runtime 输入）
    pub fn fixed_bypass() -> (&'static [Ipv4Cidr], &'static [Ipv6Cidr]);
}

// ---------- flux-core/src/selector.rs ----------
pub struct PackageIndex { /* 由 /data/system/packages.list 解析 */ }
impl PackageIndex {
    pub fn parse(text: &str) -> Self;
    pub fn app_id(&self, package: &str) -> Option<u32>;
    pub fn shared_with(&self, app_id: u32) -> Vec<&str>;   // 同 UID 的全部 package
}
pub fn uid_of(user_id: u32, app_id: u32) -> Result<u32, ConfigError>;   // user*100000 + app_id

// ---------- flux-core/src/engine_config.rs ----------
pub struct EngineParams { pub generation: u64, pub port_v4: u16, pub port_v6: u16 }
pub fn build_effective(user: &serde_json::Value, p: &EngineParams)
    -> Result<serde_json::Value, ConfigError>;   // 纯函数，可在 Windows 上单测

// ---------- fluxd/src/dataplane.rs ----------
pub struct Dataplane {
    objs: LoadedObjects,          // 9 个 map + 3 个 prog 的 OwnedFd
    control_root: MapFd,
    leaf: Option<OwnedFd>,        // 当前 frozen leaf
    veth: VethOwned,              // 两端 ifindex + alias（不含 MAC，见 D17）
    rpdb: RpdbOwned,
    tc: Vec<TcFilterOwned>,
}
pub struct ControlSnapshot { /* flux_control 的 Rust 镜像 */ }

impl Dataplane {
    /// §8.7 步骤 2-5：清理残留、建 veth/RPDB、加载 BPF、publish active=0
    pub fn bring_up(layout: &Layout) -> Result<Self, DpError>;
    pub fn publish(&mut self, s: &ControlSnapshot) -> Result<(), DpError>;  // §6.4
    /// §10.5：additive-then-subtractive，不触碰 active
    pub fn apply_policy(&mut self, desired: &DesiredPolicy) -> Result<(), DpError>;
    pub fn attach_capture(&mut self, iface: &AdmittedIface) -> Result<(), DpError>;
    pub fn detach_capture(&mut self, ifindex: u32) -> Result<(), DpError>;
    pub fn drain_faults(&mut self) -> Vec<FaultEvent>;
    pub fn read_counters(&self) -> Counters;
    pub fn tear_down(self) -> Result<(), DpError>;    // 删除全部自有对象（clsact 除外）
}

// ---------- fluxd/src/engine.rs ----------
pub struct EngineChild { pidfd: OwnedFd, pid: u32, params: EngineParams, effective: PathBuf }
impl EngineChild {
    pub fn write_effective(cfg: &serde_json::Value, p: &EngineParams, dir: &Path)
        -> Result<PathBuf, EngineError>;                       // O_CREAT|O_EXCL|O_NOFOLLOW + fsync
    pub fn check(bin: &Path, effective: &Path) -> Result<(), EngineError>;
    pub fn spawn(bin: &Path, effective: &Path) -> Result<Self, EngineError>;   // PDEATHSIG
    pub fn wait_ready(&self, deadline: Instant) -> Result<(), EngineError>;    // SOCK_DIAG × 4
    pub fn terminate(self, grace: Duration) -> Result<(), EngineError>;
}
```

## 10.3 单实例与控制协议

- daemon 持有 `/data/adb/flux-rs/run/daemon.lock` 的 `flock(LOCK_EX|LOCK_NB)`。第二实例立即退出，**不** unlink 控制 socket、**不**启动第二个 engine、**不**碰第一实例的对象。只有 lock owner 能检查并删除 stale 控制 socket。
- 控制 socket：`/data/adb/flux-rs/run/control.sock`，`AF_UNIX` + `SOCK_SEQPACKET`，mode `0600`，每个请求额外检查 `SO_PEERCRED.uid == 0`。
- 编码：**每个 SEQPACKET 报文一条单行 JSON**（SEQPACKET 天然保留消息边界，不需要长度前缀）。单报文上限 64 KiB。类型定义在 `flux-core/src/control_wire.rs`，因此 Windows 上可单测序列化。
- **不需要 request_id 去重缓存。** 旧协议 v9 为可变命令维护了 128 条 `(peer, request_id)` 去重表加 30 秒重复等待。0.9.0 的六个命令全部按构造幂等（`enable` 写 1 后重新收敛、`reload` 重算期望状态、`stop` 收敛到停机），重放一次与执行一次结果相同，整套去重机制因此删除。**新增命令时必须保持这一性质**，否则要么改成幂等，要么才重新引入去重。

```jsonc
// Request
{ "op": "status" | "check" | "enable" | "disable" | "reload" | "stop" }

// Response
{
  "ok": true,
  "version": "0.9.0",
  "state": "Disabled" | "Inactive" | "Active",
  "generation": 7,
  "engine": { "running": true, "pid": 1234 },
  "counts": { "selected": 3, "draining": 1, "bypass_v4": 12, "bypass_v6": 6 },
  "ifaces": [ { "name": "wlan0", "ifindex": 24, "status": "active" },
              { "name": "v4-rmnet_data0", "ifindex": 31,
                "status": "excluded", "reason": "clat_order_unverified" } ],
  "counters": { "admit_tcp": 41, "admit_udp": 388, "drop_handoff": 0, "…": 0 },
  "warnings": [ "0:com.foo declares BIND_VPN_SERVICE" ],
  "last_error": null
}
```

## 10.4 reactor 事件源

单线程 epoll。事件源：

| 源 | 触发内容 |
|---|---|
| rtnetlink（`RTMGRP_LINK|IPV4_IFADDR|IPV6_IFADDR|IPV4_ROUTE|IPV6_ROUTE|IPV4_RULE|IPV6_RULE` + TC） | interface admission、**捕获侧漂移**（qdisc/filter 被 netd 删，§8.5.1）、**核心漂移**（veth/rule/route/ingress filter）、本机地址 bypass 更新。两类漂移的处置**不同**，见 §26 不变量 4 |
| inotify | `config/` 目录与两个配置文件的原子替换；`/data/system/packages.list` |
| pidfd | sing-box 退出 |
| BPF ringbuf | 已去重的 listener/assign fault |
| signalfd | `SIGTERM`/`SIGINT`（停机）、`SIGHUP`（reload） |
| 控制 socket | CLI 请求 |
| timerfd | 配置 debounce、readiness 退避、1/2/4/8/30 s crash backoff |
| 子进程 stdout pipe | `sing-box check` 的输出（**非阻塞**，带 deadline） |

**无每秒轮询、无 busy loop、无 BPF timer、无周期 counter 采集、无 heartbeat。** backoff 在 child 稳定 60 s 后复位；只要 `enabled` 为真就持续低频恢复，不设"失败 N 次永久锁死"。

**所有外部命令（`sing-box check`）必须以子进程 + epoll 管道 + deadline 的方式执行，禁止在 reactor 里阻塞 `wait()`。**

### 10.4.1 rtnetlink 的三条硬规则

Android 在网络切换时会产生事件风暴，增量处理一个被截断的批次是产生不一致状态的标准方式。三条规则来自 `clone/asteriskd/asteriskd_network.c:147-164` 的实践：

1. **1500 ms 尾随 debounce。** 每一条**新的、去重后不同**的事件都**重新武装**截止时间（trailing，不是 leading）。批次容量有上限；超限置 `truncated`。数值取 1500 ms 与 asteriskd 一致（`asteriskd.h:35`），它是在真机 Wi-Fi↔蜂窝切换上调出来的。
2. **`ENOBUFS` / `NLMSG_OVERRUN` ⇒ 放弃增量，做全量重新 dump。** netlink socket 溢出或收到 overrun 消息时，**不得**相信已收到的部分事件；置 `integrity_loss`，丢弃批次，重新 `RTM_GETLINK`/`GETADDR`/`GETROUTE`/`GETRULE`/`GETTFILTER` 全量快照后再收敛。这与 `flux-core` 的 inventory 快照替换语义一致：**宁可重算，不可拼接。**
3. **每次 TC 操作前重新 `if_nametoindex()`。** Android 上 interface 被改名与重新分配 ifindex 是常态。dump 里看到的 ifindex 与几毫秒后执行 `RTM_NEWTFILTER` 时的 ifindex 可能已不是同一个设备（`asteriskd_runtime.c:3806`、`:3818`）。名字与 ifindex **两者都必须**在操作前一刻复核一致，不一致则放弃本轮，等下一个事件。

socket 用 `NETLINK_ROUTE | SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC`，并且**先订阅再取初始快照**，然后把 socket 读到 `EAGAIN`——顺序反了会丢掉快照与首个事件之间的变化。

## 10.5 两个独立事务域

`flux.toml`（policy）与 `sing-box.json`（engine）是两个独立权威域，**不做跨文件分布式事务**。只改一个就只触发对应流程；`reload` 依次处理二者，各自独立 promote 并在 `status` 报告。允许一个成功另一个保持旧状态；禁止半写一张 map 或半启动一个 generation。

**policy 更新（D5，不触碰 `active`、不换 generation）**：

1. 在内存中完整解析、canonicalize、算 UID、检查硬上限；任一失败 → 保持当前策略，报 candidate error。
2. 计算 desired 集合：`selected_uids`、`bypass_v4/v6`（固定项 + 本机地址 + 用户项）。
3. **先加**：写入新的 `SELECTED` entry；插入新增 LPM 前缀。
4. **后减**：把"曾 SELECTED 但不再选中"的 UID 改为 `DRAINING`（**不删除**）；删除不再需要的 LPM 前缀。
5. 更新 control leaf 里的诊断计数（这**不**需要新 leaf；诊断字段允许滞后一个周期，或在下次 leaf 发布时顺带更新）。
6. 任一 map 操作失败：记录错误并**重新入队一次完整收敛**（level-triggered），不做快照回滚。

窗口内后果的正确性论证：先加后减意味着窗口内策略只会"更宽松地保持旧行为"或"提前生效新行为"，两者都只影响**尚无决策的新连接**；已有 `DIRECT`/`CAPTURED` decision 不可变，不受影响。

## 10.6 CLI

| 命令 | 行为 |
|---|---|
| `fluxd daemon` | `service.sh` 调用；进入 reactor |
| `fluxd status` | 输出 §10.3 的 Response（人类可读 + `--json`） |
| `fluxd check` | 只读校验两份配置、package 解析、engine `check`；不改任何状态 |
| `fluxd enable` | 原子写 `state/enabled=1` 并请求激活 |
| `fluxd disable` | 写 0、publish `active=0`、停 engine；daemon 继续等待命令 |
| `fluxd reload` | 触发 policy 与 engine 候选流程 |
| `fluxd stop` | service/uninstall 用：publish `active=0`、停 child、daemon 正常退出（exit 0） |

无 `toggle` 隐藏状态；`action.sh` 先读 `status` 再明确调用 `enable` 或 `disable`。

---

# 第 11 部分：配置与持久状态

## 11.1 唯一权威源

| 路径 | 权威内容 | 失败行为 |
|---|---|---|
| `state/enabled` | 唯一持久 enable 位，内容仅 `0\n` 或 `1\n` | 缺失/非法视为 0 |
| `config/flux.toml` | package 选择与 CIDR bypass | cold 无效 → Direct；hot 无效 → 保留当前 |
| `config/sing-box.json` | 唯一用户 engine 配置 | cold 无效 → Direct；hot 无效 → 保留当前 |
| `run/effective-sing-box.<generation>.json` | 对应 child 的一次性 immutable 生成物；事务中最多 current + candidate 两份 | 非权威源；daemon 重启后精确清理并从用户配置重建 |
| `run/daemon.lock` / `run/control.sock` | 单实例与 IPC | — |

不使用 last-known-good 持久副本；不在 TOML 里重复 `enabled`；不从 `module.prop` 推断运行状态；**Flux 从不反写用户配置**。fresh install 默认 disabled。

daemon 冷启动确认没有自己的存活 child 后，只枚举并删除 `run/` 中严格匹配 `effective-sing-box.<u64>.json` 格式且属 root 的普通文件。

权限：状态根与子目录 `root:root 0700`；用户 config、`state/enabled`、generation effective 文件 `0600`；控制 socket `0600`。

## 11.2 `flux.toml` 唯一 schema

```toml
apps = [
  "0:com.example.browser",
  "10:com.example.chat",
]

bypass_cidrs = [
  "192.168.0.0/16",
  "fd00::/8",
]
```

硬限：文件 256 KiB；`apps` ≤ 128；解析后总 UID entry ≤ 512；IPv4/IPv6 LPM 各 ≤ 128（含固定项与本机地址项）；package 字符串与 CIDR 必须 canonical 且无重复。超限是清晰的配置错误，**不截断、不部分应用**。

**固定安全 bypass（硬编码注入）**：

- IPv4：`0.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`224.0.0.0/4`、`255.255.255.255/32`、`198.18.0.0/15`
- IPv6：`::/128`、`::1/128`、`fe80::/10`、`ff00::/8`、`2001:db8::/32`

**动态本机地址 bypass**：reactor 把每个 live 的本机单播地址作为 `/32`（IPv4）或 `/128`（IPv6）注入，地址增删时同步。预留 32 个 LPM 槽位给它们；超出则拒绝激活并报告（不静默丢弃）。

RFC1918、CGNAT、ULA **不是**硬编码 bypass；是否 direct 由用户 CIDR 或 sing-box 规则决定。

## 11.3 package 解析（无 binder）

`/data/system/packages.list` 每行形如：

```text
com.example.browser 10231 0 /data/user/0/com.example.browser default:targetSdkVersion=34 none 0
```

第 2 列是 user 0 下的 uid，`app_id = uid % 100000`。解析规则：

1. 读整文件（上限 8 MiB），按行解析出 `package -> app_id` 与 `app_id -> [package]`。
2. 对配置里的每个 `userId:package`：查 `app_id`；校验 `app_id ∈ [10000, 19999]`；`uid = userId * 100000 + app_id`。
3. package 不存在 → 候选配置失败（明确报错，不静默忽略）。
4. 同 `app_id` 的其它 package 一并列入 `status` 的 shared-UID 提示。
5. inotify 监视该文件及其 parent（Android 以原子替换方式重写它）；事件 → debounce → 重新收敛。
6. 该文件不可读或格式异常 → 保持当前策略并报错，**不轮询**。

VPN provider 告警是 best-effort：可选地在 `check` 时执行一次 `cmd package` 查询，失败不影响任何门禁。

---

# 第 12 部分：BPF 构建与最小加载器

## 12.1 编译

`crates/fluxd/build.rs`：

```text
clang -target bpf -O2 -g -Wall -Wextra -Werror \
      -mcpu=v3 -D__TARGET_ARCH_arm64 \
      -Ibpf/include -Ibpf/vendor/libbpf/include \
      -c bpf/flux.bpf.c -o $OUT_DIR/flux.bpf.o
```

**关于"不用 libbpf"的精确含义**：不链接 libbpf 库，因此不需要 libelf/zlib，`fluxd` 是纯 Rust + libc 的单二进制。但 BPF **侧**仍 vendor libbpf 的三个 **header-only** 文件（`bpf_helpers.h`、`bpf_helper_defs.h`、`bpf_endian.h`，BSD-2）以获得 `SEC`/`__uint`/`__type` 宏与 helper 原型。这些头文件只在编译 BPF object 时使用，不进入运行时依赖。手写这些宏也可行（约 60 行），但没有收益。

- `-g` 必需（产生 `.BTF`，我们只用它与手写 BTF blob 做交叉核对，见 §12.3）。
- 不使用 `vmlinux.h`、不访问内核私有 struct、不使用 CO-RE relocation。只用 `linux/bpf.h` UAPI 与固定 helper 原型。
- `include_bytes!(concat!(env!("OUT_DIR"), "/flux.bpf.o"))` 内嵌进 `fluxd`。最终 module **只有一个** `fluxd` binary，不散放 `.o`。
- CI 用固定 clang 版本确定性重建并比对 object 的 SHA-256。

## 12.2 map 创建

**由 Rust 侧显式创建，不从 ELF 推断。** `fluxd/src/bpf/maps.rs` 用一张常量表描述 9 个 map 的 `map_type`、`key_size`、`value_size`、`max_entries`、`map_flags`、`name`，逐个 `BPF_MAP_CREATE`。这样 C 文件里的 map 定义只是符号占位，参数的唯一真相源在 Rust（并由 `flux_abi.h` 约束 value 布局）。

`control_leaf` 的 inner map 先创建，再以其 fd 作为 `inner_map_fd` 创建 `control_root`。

## 12.3 SK_STORAGE 需要的 BTF

**已核验**：`bpf_sk_storage_map_alloc_check()` 要求 `btf_key_type_id` 与 `btf_value_type_id` 均非零。

实现方式（**建议**，因为它把兼容性风险降到零）：在 Rust 里**手工构造**一个最小 BTF blob 并 `BPF_BTF_LOAD`：

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

（`u8` 需要一条自己的 `BTF_KIND_INT`；实际实现按 `reference/flux_abi.h` 的最终布局生成。）

然后以 `btf_fd = <该 blob>`、`btf_key_type_id = 1`、`btf_value_type_id = 5` 创建 `tcp_decision`。

理由：只用 clang 产出的 `.BTF` 也可行，但 5.15 的 BTF 校验对未知 kind 严格，而 clang 版本升级可能引入 `DECL_TAG`/`FLOAT`/`ENUM64` 等新 kind（libbpf 正是为此做 sanitization）。我们只需要两个类型 ID，手工构造 100 余字节比引入 sanitizer 更小更稳。`xtask` 在 CI 里用 `bpftool btf dump`（或直接比对 clang 的 `.BTF`）核对手写 blob 与 C 结构一致。

## 12.4 program 加载与重定位

1. 解析内嵌 ELF（用 `object` crate 或约 200 行手写解析）：取 `.text`/各 `SEC("tc")` 程序节的指令字节、`.symtab`、以及对应的 `.rel<section>`。
2. 对每条 `BPF_LD | BPF_DW | BPF_IMM` 双字指令上的重定位：按符号名在 §12.2 的 map 表里查到 fd，把 `insn.src_reg = BPF_PSEUDO_MAP_FD`、`insn.imm = map_fd`。
3. `BPF_PROG_LOAD`：`prog_type = BPF_PROG_TYPE_SCHED_CLS`、`license = "GPL"`、`prog_name` 为程序名、`log_level = 1` 且 `log_buf` ≥ 256 KiB。**加载失败必须把 verifier log 的前 N 行写进 `status`/日志**——这是唯一能让实机问题可诊断的东西。
4. 不加载 `func_info`/`line_info`/`.BTF.ext`。
5. 加载成功后用 `BPF_OBJ_GET_INFO_BY_FD` 记录 program **id 与 8 字节 tag**，供 §8.5 的 ownership 谓词与 `status` 使用。

## 12.7 加载器加固清单

以下每一条都来自 `clone/bpf2socks` 在真机 Android 上踩出来的坑（`bpf_util.c`、`bpf_object.c`）。它们不是"最佳实践"，是**必须实现的项**——每一条对应一类会在特定设备上直接失败的情况。

| # | 措施 | 为什么 | 来源 |
|---:|---|---|---|
| 1 | `__NR_bpf` 按架构硬编码兜底（aarch64 **280**） | Android NDK 的 UAPI 头有时不定义 `__NR_bpf`，编译期就断 | `bpf_util.c:26-36` |
| 2 | `BPF_F_NO_PREALLOC`、`BPF_OBJ_NAME_LEN`、`BPF_F_MARK_MANGLED_0` 全部 `#define` 兜底 | 同上，旧 NDK 头缺常量 | `bpf_util.c:16-24`、`tc_checksum_flags.h:11-13` |
| 3 | **verifier log 重试**：`BPF_PROG_LOAD` 因 log buffer 返回 `EAGAIN`/`ENOSPC` 时，用 `log_level = 0` 重载一次；若仍失败，**恢复原始 errno 再报告** | 大程序的 verifier log 会超出缓冲区，此时真正的加载错误会被 `ENOSPC` 掩盖。不做这一步会得到误导性的诊断 | `bpf_util.c:177-189` |
| 4 | ELF 解析前先做 sanity gate：`ELFCLASS64` + `ELFDATA2LSB` + `e_machine == EM_BPF` | 防止把任何别的文件当 BPF object 解析 | `bpf_object.c:250-257` |
| 5 | 只处理 `R_BPF_64_64` 重定位；按 **map 符号名 → fd 绑定表**打补丁，逐项做边界检查 | 这是 §12.4 的具体形态。bpf2socks 用同样方式在 Android 上加载成功，无需 libbpf | `bpf_object.c:23-172`，绑定表 `:78-96` |
| 6 | `BPF_PROG_GET_FD_BY_ID` 之后**重新核对 id**（`BPF_OBJ_GET_INFO_BY_FD` 得到的 id 必须等于请求的 id） | program id 会被复用。不复核就可能操作到另一个程序 | `bpf_util.c:352-370` |
| 7 | `BPF_PROG_QUERY` / TC dump 的 `ENOSPC` 规范化为 `E2BIG`，并在返回后**重新检查 count > capacity** | 内核会在缓冲区不足时返回真实条目数；不复检会静默截断 | `bpf_util.c:306-315` |
| 8 | 自有对象按 **program name 前缀**识别（我们用 `flx_`），但**只作为筛选，不作为所有权证明**——所有权仍需 §8.5 的 id + tag | 前缀可伪造；它的作用是把候选集缩小 | `bpf_util.c:384-386` |
| 9 | 若使用 pin（0.9.0 不用），`BPF_OBJ_PIN` 前先 `mkdir -p` 父目录（mode `0700`）并 `unlink` 旧 pin | — | `bpf_util.c:89-122` |
| 10 | **不维护"已知损坏内核"表，不按版本放行。** 一切能力判定都是"尝试真实操作、报告 errno" | Android 厂商内核的 BPF 特性开关高度分散，版本字符串没有预测力。这与 §3.7 同源 | `bpf2socks` 全树无版本门禁 |

**第 11 条是我们自己加的**：加载失败时，**verifier log 的前 N 行必须进入 `status` 与日志**（§12.4 第 3 步）。这是实机问题唯一可诊断的东西；把它吞掉等于放弃现场。

## 12.8 为什么不 shell out 到 `tc` / `ip`

`clone/asteriskd` 的分工是"netlink 验证 + `tc` 二进制变更"（`asteriskd_runtime.c:3587`/`3605` 对 `:3824`/`3834`）。0.9.0 **全部走 netlink**，理由是一条具体的连锁后果：

Android 上 `tc` / `ip` 运行在 `netutils_wrapper` / `netd` 的 SELinux 域，而 stock sepolicy **不允许这些域碰别人的 BPF 对象**。所以 asteriskd 必须先注入策略：

```text
allow netd * bpf { prog_run map_read map_write }
allow netutils_wrapper * bpf { prog_run map_read map_write }
```

并跨六个候选路径去找 `magiskpolicy` / `supolicy` / `ksud`（`asteriskd_capability.c:9-12`、`:97-154`），失败还只能降级为警告（`:181-206`）。**这正是 §1.3 非目标里"宽泛 SELinux patch"要避免的东西。**

从 `fluxd` 自己的进程发 netlink 与 `bpf(2)`，绕开整个 `netutils_wrapper` 域问题：我们只需要**自己所在的域**有 `bpf` 权限，而 Magisk 与 KernelSU 的 root 域本来就有。代价是要自己写 `RTM_NEWTFILTER` 的 `TCA_BPF_*` 属性编码（§8.9），大约两百行——比注入 sepolicy 便宜得多，且不改变系统安全姿态。

**Phase 0 必须在 Magisk 与 KernelSU 上分别验证**：两者的策略路径不同（asteriskd 为此写了两套发现逻辑），"root 就一定能 load BPF"不能假设。

## 12.5 TC attach

用 rtnetlink，不调用 `tc` 二进制：

- `clsact`：`RTM_NEWQDISC`，`NLM_F_EXCL|NLM_F_CREATE`，`tcm_parent = TC_H_CLSACT`，`tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0)`，`TCA_KIND = "clsact"`。已存在（`EEXIST`）视为成功且记录"非我创建"。
- filter：`RTM_NEWTFILTER`，`NLM_F_EXCL|NLM_F_CREATE`，`tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS|TC_H_MIN_INGRESS)`，`tcm_info = TC_H_MAKE(prio << 16, protocol)`，`tcm_handle = 0x1 / 0x2`，`TCA_KIND = "bpf"`，options 内 `TCA_BPF_FD`、`TCA_BPF_NAME`、`TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT`。
- ownership 校验：`RTM_GETTFILTER` dump 后逐项比对 §8.5 的完整谓词，**包括 dump 顺序**（first-applicable）。
- 删除：`RTM_DELTFILTER` 且必须带精确 `prio`/`protocol`/`handle`/`kind`。

## 12.6 ringbuf 消费

`fault_events` 的 map fd 可直接 `epoll` 注册（ringbuf map fd 支持 `EPOLLIN`）。消费用 `mmap` 的 consumer/producer 页 + 记录头解析（约 80 行），不引入 libbpf。事件固定 32 字节，解析平凡。

---

# 第 13 部分：模块封装与构建

## 13.1 同一个最小 ZIP

```text
module.prop
skip_mount                  # 空文件，不做 system overlay
customize.sh
service.sh
action.sh
uninstall.sh
bin/fluxd
bin/sing-box
etc/default-flux.toml
etc/default-sing-box.json
engine.lock
LICENSE
THIRD_PARTY_NOTICES.md
licenses/{sing-box-LICENSE, DEPENDENCIES.md}
```

`module.prop` 由 xtask 生成：`id=flux_rs`、`name=Flux-rs`、`author=Flux-rs contributors`、`version=v0.9.0`、`versionCode=9000`，description 一句话且**不夸大 fail-open**。0.9.0 不放 `updateJson`。

**禁止**：`post-fs-data.sh`、recovery `META-INF`、`service.d`、WebUI、APK、SEPolicy、multi-ABI 目录、已编译 `.o`、逐文件安装 hash 清单。

注意：由于删掉了 libbpf/libelf/zlib（D10），`licenses/` 只需 sing-box 与 Rust 依赖的许可证。

## 13.2 脚本职责（薄）

全部脚本以 `MODDIR=${0%/*}` 定位自身，不硬编码管理器临时目录。

### 13.2.0 三管理器的实际差异（会改变脚本内容，不是理论问题）

| 项 | Magisk | KernelSU | APatch |
|---|---|---|---|
| `service.sh` | ✓ | ✓ | ✓ |
| `post-fs-data.sh` | ✓（阻塞，40 s 上限） | **late-load 模式完全跳过** | ✓ |
| `boot-completed.sh` | **无** | ✓ | ✓ |
| `action.sh` | ≥ v28.0 / canary 27008 | ✓ | ✓ |

**全部启动逻辑只放 `service.sh`。** 我们本来就不出 `post-fs-data.sh`——这条恰好是对的，因为 KernelSU 的 late-load 模式会静默跳过它，依赖它的模块在那种设备上无声失效。Magisk 没有 `boot-completed.sh`；不过 §11.3 已消除对 `sys.boot_completed` 的依赖，我们不需要等它。

**管理器识别禁止用 `MAGISK_VER_CODE`**——KernelSU 报 `25200`/`v25.2`，APatch 报 `27000`/`v27.0`，KernelSU 文档明确写了"请不要用这两个变量判断是否运行在 KernelSU"。用正向标记：

```sh
if   [ "$KSU"    = "true" ]; then MANAGER=kernelsu
elif [ "$APATCH" = "true" ]; then MANAGER=apatch
else                              MANAGER=magisk; fi
```

KernelSU 另外导出 `KSU_RUNTIME_MODE`（`built-in` / `lkm` / `late-load`）。**这个值应当进 `status`**：LKM 与 late-load 跑在**厂商原版内核**上，BPF 特性缺失的概率显著更高，出问题时它是第一条排查线索。

**BusyBox 路径不同**（`/data/adb/magisk/busybox` vs `/data/adb/ksu/bin/busybox`），**禁止硬编码**；三者都用 BusyBox `ash` + Standalone Mode，靠 PATH 选工具同样不可靠。`module.prop` 必须 LF 行尾，`id` 匹配 `^[a-zA-Z][a-zA-Z0-9._-]+$`。

### 13.2.1 `action.sh` 的三条硬约束

Magisk 自 canary 27008 / v28.0 起支持 `action.sh`。它的行为约束是：**STDOUT 显示在管理器 UI 里，STDERR 被丢弃，STDIN 不可用**，并且**脚本结束后管理器会重新读取 `module.prop`**。

因此：① 所有输出走 STDOUT，**禁止**把任何信息放 STDERR；② **禁止**设计需要交互输入的动作；③ **利用 `module.prop` 的重读**——`action.sh` 在结束前把一行状态写进 `description=`（例如 `description=[Active] gen 7 · 3 apps · 41 tcp / 388 udp`），用户在管理器列表里就能直接看到运行状态，不必进终端。这是本产品在"无 WebUI"约束下唯一的图形化状态出口，应当用满。

```sh
# service.sh（late_start；业务全在 fluxd）
MODDIR=${0%/*}
n=0
while :; do
  "$MODDIR/bin/fluxd" daemon
  rc=$?
  [ "$rc" = 0 ] && break
  n=$(( n + 1 )); [ "$n" -gt 4 ] && n=4
  case "$n" in 1) s=1;; 2) s=2;; 3) s=4;; *) s=8;; esac
  sleep "$s"
done
```

- `customize.sh`：只检查 arm64 与 payload 完整性、创建目录、设置 mode/owner；**只在文件缺失时**复制默认配置（普通重装不覆盖用户配置）；不在安装时跑 BPF 资格测试。
- `action.sh`：先读 `status`，再明确调用 `enable`/`disable`，输出简短结果。
- `uninstall.sh`：同步请求 `fluxd stop`，成功后只删除 `/data/adb/flux-rs`；不扫描/读取/删除任何旧 Flux 路径，也不 flush 网络对象（管理器要求重启后非持久内核对象自然消失）。

## 13.3 child 进程与 orphan 防护

`fluxd` 只直接 `fork/exec` 不 daemonize 的官方 sing-box。`exec` 前的顺序是固定的（参照 `clone/asteriskd/asteriskd_process.c:332-344`）：恢复信号处置（`SIGKILL`/`SIGSTOP` 跳过）→ `setsid()` → 清空 supplementary groups → `PR_SET_PDEATHSIG` → **复查 parent PID**（关闭"父进程在 PDEATHSIG 生效前就已死"的窗口）→ 准备 fd → `execve`。`setsid()` 让 child 成为进程组 leader，从而可以对整组发信号。

父进程存活时的正常停止用 `SIGTERM` → 短 deadline → `SIGKILL`，并用 pidfd 确认退出。

**PDEATHSIG 取 `SIGKILL` 而不是 `SIGTERM`**（asteriskd 选后者）。理由：父进程异常死亡后已无人能执行 graceful deadline，`SIGTERM` 若被 engine 忽略或处理缓慢就会留下 orphan，与 supervisor 拉起的新 engine 争抢同一批端口。而本设计里 engine **不拥有任何内核状态**——没有 TUN、没有 BPF、没有 iptables，只有 listener socket——所以没有需要 graceful 清理的东西，`SIGKILL` 严格更强。附带好处：listener 立即关闭，正是 §2.2.1 fail-open 想要的效果。

**child 身份必须验证而不是假设**：记录 pid 之外，还要读 `/proc/<pid>/stat` 的 `starttime` 与 `/proc/<pid>/exe`，构成 `(pid, starttime)` 复合身份。解析 `stat` 时**以最后一个 `)` 定位**（comm 里可能含括号），并拒绝 `Z`/`X` 状态。pid 复用在长时间运行的设备上是真实的（`asteriskd_process.c:370-390`）。

**engine 的 stdout/stderr 必须被捕获**（pipe 到 fluxd，写入 §11.1 的日志，并保留最后若干行进 `status.last_error`）。丢弃它等于放弃 `sing-box check` 之外唯一的 engine 侧诊断，而 §24.4 的 hint 依赖它。

## 13.4 单一版本源与可复现打包

```toml
[workspace.package]
version = "0.9.0"
```

xtask 由它生成：`module.prop version=v0.9.0`；`versionCode = major*1_000_000 + minor*1_000 + patch = 9000`；ZIP 名 `Flux-rs-v0.9.0-arm64.zip`；CLI/build metadata。Git commit hash 只做 provenance，不参与 versionCode。只有签出的 `v*` tag 触发 release workflow，workflow 只校验 tag 去掉 `v` 后等于 workspace version，**不维护第二份版本文件**。

`cargo xtask package` 是本地与 CI 的唯一打包入口：

1. 从空 staging 目录开始。
2. 用 `rust-toolchain.toml`、`Cargo.lock`、固定 NDK 与固定 LLVM/clang 交叉构建 `fluxd` 与 BPF object；target 固定 `aarch64-linux-android` API 31；`fluxd` 链接 `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` 并静态检查每个 `PT_LOAD` 的 `p_align >= 0x4000`；构建路径 remap、不嵌 wall-clock。
3. 下载并校验 engine.lock（size + SHA-256 + 四个 `PT_LOAD` 仍精确 `0x1000`）。
4. 生成 `module.prop`。
5. 按 allowlist 复制文件、统一 LF 与 mode。
6. 固定排序 + `SOURCE_DATE_EPOCH` + 无额外属性地打 ZIP。
7. 输出 ZIP 与 `SHA256SUMS`。

不生成 SBOM、签名、逐文件 hash 或多层 manifest，除非未来真实分发渠道明确要求。

---

# 第 14 部分：性能与能效预算

## 14.1 热路径静态成本

| 路径 | 主要工作 |
|---|---|
| UID 未选（绝大多数流量） | 1 次 TC invocation + `bpf_get_socket_uid` + 1 次 HASH miss。**不解析 packet、不读 control** |
| 已有 `DIRECT` TCP | 上述 + `bpf_sk_fullsock` + 1 次 SK_STORAGE 查。**不解析、不读 control** |
| 新 selected direct TCP 首 SYN | 上述 + 1 次 control（2 map 查）+ 1 次 LPM + 1 次 listener lookup + 1 次 storage create。此后零写入 |
| 新 captured TCP 首 SYN | 同上 + `bpf_redirect`（L2 零写入 / L3 写 2 字节）；ingress 再 1 次 `change_type` + 1 次 control + 1 次 listener lookup + `bpf_sk_assign` |
| captured TCP 稳态（L2） | `bpf_sk_fullsock` + 1 次 storage 查 + 1 次 control + `bpf_redirect`。**零 packet 写入、零 clone 复制、零解析** |
| captured TCP 稳态（L3/rmnet） | 同上 + `bpf_skb_change_head(14)` + 写 2 字节 EtherType |
| selected UDP 每 datagram | UID 查 + 有界解析 + 1 次 control + 1 次 LPM + 1 次 listener lookup + redirect；ingress 1 次 change_type + 1 次 control + 1 次 lookup/assign |

与前两版蓝图相比，captured TCP 的 L2 稳态少了：一次 socket hash 查找（D1）、一次 sentinel lookup（D2）、一次 6 字节 MAC 比对（D3）、一次 12 字节 `bpf_skb_store_bytes` 及其对 clone 的 `skb_ensure_writable()` 复制（D17），并且完全不解析 L3/L4（D6 的副产品）。**结果是该路径上 Flux 一个字节都不碰 packet。**

`bpf_redirect()` 把 skb 所有权转交 veth，不复制一份继续走原路径；内核仍可能因 shared skb、headroom 或 GSO 做 unshare/segment，本文**不**虚构"绝对零拷贝"。

## 14.2 用户态预算

- `fluxd` 单线程，steady target RSS ≤ 8 MiB（**实现目标，不是既测事实**）。
- idle 时无周期 timer，只有 epoll 等待 + 一个阻塞在 `wait` 上的 supervisor shell。
- 只有 interface / package / config / child / fault 变化才唤醒控制面。
- 生产环境无 per-packet log/telemetry；唯一 ringbuf 只在已去重的 fault 上唤醒；`counters` 只被 `status` 主动读取。
- sing-box 的内存/CPU 由用户完整配置主导，单列报告，不用 fluxd 的小 RSS 掩盖 engine 成本。

## 14.3 如何证明"高性能/高能效"

0.9.0 以静态路径计数、算法复杂度、分配生命周期、copy/wakeup 边界与 BPF verifier 输出为主要证据。Phase 0 与发布前只做**一次**短 sanity：确认未选流量不进用户态、idle 无周期唤醒、选择路径无明显循环或上报。不做数日 A/B、不建机型性能 catalog、不宣传未测得的百分比提升。

---

# 第 15 部分：验证策略

## 15.1 日常静态检查

- `cargo fmt --check`；`cargo clippy` 高价值 lint；`cargo build --target aarch64-linux-android`。
- `cargo test -p flux-core`（**必须能在 Windows 主机上跑**）。
- BPF：`-Wall -Wextra -Werror` 编译通过；在 CI 的 Linux runner 上实际 `BPF_PROG_LOAD` 到 verifier 通过（**必须**用 5.15 内核的 runner 或 VM；在更新内核上通过不代表 5.15 verifier 通过）。
- shell 用目标 BusyBox `ash -n` 语法检查。
- ELF 静态检查：`fluxd` 每个 LOAD `p_align >= 0x4000`；官方 engine 精确匹配 engine.lock 且仍是 `0x1000`。
- clean staging allowlist、版本一致性、两次打包 hash 一致。

## 15.2 必须保留的八个逻辑测试（全部在 `flux-core`）

1. `userId:package` canonical 解析、`appId` 范围拒绝、shared UID 列举、硬上限。
2. IPv4/IPv6 CIDR canonicalize、固定 bypass 注入、LPM key 编码、上限。
3. 用户 JSON 禁止自带 inbound；effective JSON 恰好注入两个 tproxy inbound 且**不含**任何被移除/禁止的键。
4. 随模块分发的 `etc/default-sing-box.json` 通过 `sing-box check`，且**含 `sniff` 与 `hijack-dns` 两条 route rule**；缺失 :53 处理时 `check` 产生警告而非错误。
5. `flux_abi.h` 与 Rust 镜像的 `size_of` / 字段 offset 逐项一致。
6. 手写 BTF blob 的字节布局与结构定义一致（与 clang `.BTF` 交叉核对）。
7. 控制协议请求/响应的 round-trip。
8. SemVer → `versionCode` / `module.prop` / artifact 名。

## 15.3 明确不做

多日 soak；跨几十台 OEM 的资格 catalog；每 commit 的三 root-manager 真机矩阵；mock kernel/platform framework；production canary/proof daemon 与 packet token 自洽证明；为未来 backend/兼容层写未使用的测试；把性能阈值写成 CI 无法稳定复现的硬门禁。

这些是**最低基线**，不禁止在出现真实回归后为该不变量加一个聚焦测试；禁止的是为每个 wrapper/getter/枚举堆测试。

## 15.4 从旧审计继承的四条硬规则

前几轮审计里有四类缺陷与具体架构无关、换成新架构照样会复发。它们在 0.9.0 是**实现合同**，不是建议。

1. **状态报告诚实性。** 旧代码在 rollback 路径吞掉全部错误，然后向控制面发布 `attached=false`（F-05）；promote journal 在 restore 失败时仍被删除（F-03）。规则：`status` **禁止**报告比已证明状态更干净的结果。宣布"已清理 / Inactive / 无残留"之前必须有一次新的实际枚举（TC dump、`ip rule`、`ip route`、BPF program info）证明对象确实不在。无法证明时报告 `unknown(cleanup_required)` 并附第一个具体错误。
2. **ABI 测试对着产物，不对着源码字符串。** 旧仓库有一个 token-map 测试断言 C 源文件里的字面量（`token_map.rs:907` vs `flx_sock_addr.c:409`），helper 改名就红（F-10）。规则：`flux_abi.h` 一致性、BTF blob、map 参数一律对编译产物（ELF section / `.BTF` / `BPF_OBJ_GET_INFO_BY_FD`）断言，禁止 grep C 源。
3. **CI、文档与实际命令必须机械一致。** 旧 CI 调用两个已删除的 xtask 子命令，`development.md` 与 README 还在列退役命令与旧协议版本（F-09、F-13、设计审计 P0 #4）。规则：CI 加一条自检，遍历 workflow 与 docs 中出现的每个 `cargo xtask <sub>`，断言它能被 xtask 解析；版本号只有 workspace 一个来源。
4. **只有一份权威架构文档。** 旧设计语料里同一份文件同时规定了三种互不兼容的 attach 策略（PromoteThenAppend / 禁止 DETACH / KD 35 fail-open），实现者照着任一段写都会错（设计审计 P0 #1）；18 个 ADR 的 YAML 状态与正文互相矛盾（P1 #20）。规则：0.9.0 **没有 ADR 目录**，只有一份 `docs/architecture.md`（本蓝图的落地版）。任何第二份文档若与它冲突，删掉第二份，而不是加一句"以后者为准"。

---

# 第 16 部分：Phase 0 —— 编码与清库之前的最小证伪

Phase 0 在临时目录（`/tmp` 或独立 worktree）完成，只含一个最小 BPF C、一个小 loader、一份 netns 脚本与官方 sing-box。**不预建 Flux 框架，产物不进最终仓库。**

先在 Linux 主机的 network namespace 里跑 Q1–Q5（**必须是 5.15 内核**，与产品基线一致），再在一台可恢复的目标 Android 设备上跑 Q6–Q9。

## 16.1 九个必答问题

**Q1 — SK_STORAGE first-decision**
在 TC egress 中对 `bpf_sk_fullsock(skb->sk)` 执行 `bpf_sk_storage_get(..., &initial, F_CREATE)`：verifier 是否接受？并发 SYN 是否由 `BPF_NOEXIST` 语义产生唯一 winner、loser 在 `CREATE` 返回 NULL 后能用只读重查稳定读回同一 winner？两种 state 是否在后续 egress 保持不变、并随 socket 关闭释放（无容量驱逐）？
*断言*：并发 100 条 connect，每个 socket 的 decision 恒定；`grep` 内核内存不增长；socket close 后 storage 计数回落。

**Q2 — listener 身份、assign 与共绑**
官方 sing-box `1.13.19` 以 `type:tproxy`、`listen:198.18.0.2`/`2001:db8::2` 启动后：4 个 socket 是否出现且 `SOCK_DIAG` inode 能与 `/proc/<pid>/fd` 交叉核验？`bpf_sk_lookup_tcp/udp` 返回的 `src_ip4/src_ip6/src_port/state/family` 是否与配置一致？`bpf_sk_assign()` 是否**成功**（即 sing-box 的 listener 确实没有 `SO_REUSEPORT`，否则会 `-ESOCKTNOSUPPORT`）？
*断言*：4/4 socket 核验通过；assign 返回 0；`ss -lntpe`/diag 显示无 reuseport。

**Q3 — TCP 生命周期**
v4/v6 完整握手、SYN 重传、final ACK、data、FIN/RST、TFO 在"只对 SYN assign"策略下是否工作？sing-box 侧 `accept()` 后 `getsockname()` 是否**逐字节**等于原始目的？client 的 `getpeername()` 是否一致？TIME_WAIT 重传 ACK、abortive RST、无 `skb->sk` 的内核 RST 是否如合同走 Android 原路径？engine 退出后仍可查到 full socket 的旧 flow 是否只 drop/reset 而**不** direct？
*断言*：目的地址逐字节相等；旧 flow 无一个字节到达真实目的（用真实目的侧 tcpdump 证明）。

**Q4 — UDP 原目的**
v4/v6、connected 与 unconnected UDP 经 assign 后，sing-box 收到的 `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` cmsg 是否与原目的完全一致？回写路径（sing-box 新建 `IP_TRANSPARENT` socket 绑定原目的）是否能到达 app？
*断言*：4 组（family × connected）全部逐字节一致；app 收到的源地址等于原目的。

**Q5 — skb 回送闭环与路由前置条件**（D17 之后 L2 不再写包，本项相应调整）

1. **L2 零改写**：`flx_cap_l2` 不写任何字节即 `bpf_redirect`，配 ingress 的 `bpf_skb_change_type(PACKET_HOST)`，包能否被 `ip_rcv` 接受？（若 `PACKET_OTHERHOST` 仍被丢，说明 TC ingress 晚于 `ip_rcv`，D17 被证伪，回退到写 dst MAC。）
2. **L3 补头**：`bpf_skb_change_head(14)` + 只写 2 字节 EtherType，在 rmnet 上能否闭环？headroom 不足时 helper 是否返回 `-ENOMEM`（应当自行 `skb_cow`）？
3. **clone 安全**：TCP 重传的 skb 是 `skb_clone`。L2 路径现在完全不写包，因此**本条只对 L3 有效**：确认 `bpf_skb_change_head` 后原始写队列 skb 未被破坏（大文件上传 + 人为丢包触发重传，校验对端收到的数据完整）。
4. **GSO**：确认 TCP GSO 超级包（大文件上传，TSO 开启）能穿过 veth 并被本地栈正确处理；`CHECKSUM_PARTIAL` 在接收侧应被 `skb_csum_unnecessary` 跳过校验。依据：`__is_skb_forwardable()` 对 GSO skb 有显式豁免（v6.1 `include/linux/netdevice.h:3913-3917`），所以超级包会原样到达 peer。
5. **UDP GSO（`UDP_SEGMENT`）**：QUIC 客户端（Cronet）会用 `UDP_SEGMENT` 发超级包。接收侧应由 `udp_queue_rcv_skb()` 的 `udp_unexpected_gso()` → `udp_rcv_segment()` 分段后再入 socket 队列。**必须实测**：让一个选中的 app 跑 QUIC 大流量，确认 engine 收到的是正确的一个个 datagram 而不是一个巨包。dae 曾因此在自己的客户端里默认关掉 UDP GSO（PR #391）——我们不能关 app 的，只能确认内核路径成立。
6. **路由前置条件的最小集**：分别以 `all.rp_filter = 0/1`、`flxrs1.accept_local = 0/1`、**`ip_forward = 0/1`**、`arp_filter` 默认值跑矩阵，确定**真正必需的最小集**。§8.4 的预测是「需要 `flxrs1.rp_filter=0` + `accept_local=1` + `all.rp_filter=0`，不需要 `ip_forward`、不需要 `arp_filter`」；dae 三者都设了（`netns_utils.go:437-450`）。失败时**直接上 `pwru` + `kfree_skb_reason`**，不要猜（§8.4.1 有 dae 的原始 trace 可对照）。
7. **first-applicable**：Flux 的 pref 1 是否确在最前；`TC_ACT_UNSPEC` 之后后续 filter 的计数器是否增长。

*断言*：大文件双向传输 checksum 正确；`all.rp_filter=1` 时确实 martian-source 丢包（证明 §8.4 的检查是必要的，不是多余的保守）；`ip_forward=0` 下端到端成功（否则触发 §21 的范围变更）；后续 filter 计数器有增长。

**Q6 — 真机网络分支**
一台目标 Android（内核 ≥ 5.15）上：Wi-Fi（ARPHRD_ETHER）、rmnet（ARPHRD_RAWIP）、可用时的 CLAT `v4-*` 是否都保留 UID 与原目的？VPN TUN 是否确实被排除？`/data/system/packages.list` 是否能精确解析 user/package/UID？**Android 的 `filter INPUT`（`bw_INPUT`/`fw_INPUT`）与 `nat/mangle PREROUTING` 是否放行我们注入到 `flxrs1` 的包？**
*断言*：三类接口各至少一条 TCP + 一条 UDP 端到端成功；`iptables -L -v -n` 显示无异常 drop 计数增长。

**AOSP 默认路径的风险已下调，但 OEM 路径的风险被新证据抬高了。**

下调依据：`clone/AndroidTProxyShell/tproxy.sh` 创建的链全部挂在 `mangle PREROUTING` / `mangle OUTPUT`，**从不碰 `filter INPUT`**（`tproxy.sh:968`），而它的本机路径确实要经过 INPUT（OUTPUT 打 mark → 策略路由送 `lo` → 重新入栈 → PREROUTING TPROXY → INPUT）。既然它无需在 INPUT 开口就能工作，**AOSP 默认的 `filter INPUT` 不会丢弃这类本地交付流量**。残余风险是接口差异：它的包 `iif = lo`，我们的包 `iif = flxrs1`，Android 可能存在 `-i lo` 的快捷放行。

抬高依据：`clone/box4magisk/box/scripts/box.service:72-79` 有一个专门的 `oneplus_a16_fix()`，内容是 **flush OEM 的 `fw_INPUT` / `fw_OUTPUT` / `fw_OUTPUT_oplus_dns` 链**，注释写"OnePlus Android 16 filter rules cleaned for TProxy fix"。**这说明至少一个 OEM 的 `filter` 链确实会干掉 TPROXY 流量。**

因此本项的实测清单是：

0. **枚举 egress filter 基线**（本条是新增的，因为整个生态没人查过）：`tc filter show dev wlan0 egress`、`tc filter show dev rmnet_data0 egress`、以及 `v4-*` 存在时同样操作。`asteriskd` 只检查过 hotspot interface 的 **ingress**（`asteriskd_runtime.c:4994-4995`），所以"物理 interface 的 egress 上有什么"没有任何先例数据。记录已有 filter 的 pref / protocol / kind / program name。**这直接决定 §8.5 的 first-applicable 判定在真机上能否满足**；已知会出现 CLAT 翻译程序与 OEM 的 QoS/DSCP 程序。
1. `iptables -t filter -L -v -n` / `ip6tables` 全量抓一次基线；
2. 跑一条捕获流量，再抓一次，逐链比对 drop/reject 计数增长；
3. **单列 OEM 自有链**（`fw_*`、`oem_*`、`oplus_*`、`miui_*` 之类）的计数。

**若 OEM 链丢我们的包，0.9.0 的答案是"该设备不受支持，保持 Direct 并在 `status` 报告"，绝不是"flush OEM 的防火墙链"。** box4magisk 选了后者；那与 §1.3 的非目标（不清空系统对象）和 §15.4(1) 直接冲突，我们不跟。

**Q7 — 换代与故障自愈**
engine 在 egress 的 `listener_alive()` 与 ingress 的 lookup 之间退出时，是否只影响已 redirect 的包，而下一个新 SYN/datagram 恢复 Direct？跨 generation 的 in-flight 旧包被送进新 listener 时行为是否如 D3 所述无害（旧 SYN 变新连接、旧 established 数据被 RST）？fault latch 是否抑制 storm、重复/旧事件是否幂等、current fault 是否让 fluxd 先 inactive 再重启 generation？
*断言*：`kill -9` engine 后新连接 100% direct；fault 事件数为 O(1) 而非 O(packets)。

**Q8 — 清理与重建**
`kill -9 fluxd` 后：残留 TC filter 是否只造成"新流 direct、已入场流 drop"？重启 fluxd 后 §8.7 的删除-重建是否把所有对象恢复到确定状态？`stop` + `uninstall` + reboot 后是否零 Flux 内核残留？系统 TC/RPDB/VPN 对象是否**完全未被修改**？
*断言*：重启前后 `ip rule`/`ip route`/`tc filter show`（系统 interface）逐行 diff 为空。

**Q9 — per-app DNS（阻塞项，D18 的实机确认）**
源码链已完整（§1.3.1），但"这台设备上 `bpf_get_socket_uid()` 对 netd 的 DNS 包确实返回 app UID"必须实测：

1. 选中一个已知 UID 的 app，让它做一次 `getaddrinfo()`（不要用自带 DNS 的浏览器，用普通 app）。断言：该次明文 :53 流量被捕获，且 engine 侧看到的源是我们的 tproxy inbound。
2. 用 `counters` 的 `admit_udp` 与 engine 日志交叉确认该 datagram 确实进了 engine，而不是直连出去。
3. **未选中**的 app 做同样操作，断言其 DNS **不**被捕获（`uid_policy` miss）。这一条同样重要——它证明归属是精准的而不是"全抓"。
4. 关闭 Private DNS 与开启 Private DNS 各跑一次，确认后者的解析走 :853 且不经过 Flux（§1.3.3 边界①）。
5. 抓一次被捕获 :53 流量的 `sk_uid`，确认不是 `1051`（若是，该设备开了 `enforce_dns_uid`，属边界②，记录后按"不捕获"处理）。

6. 顺带验证 §1.3.5：在用户 JSON 里加一条 `{"package_name": ["<选中的包名>"], "outbound": "<某个出口>"}` 规则，确认它命中（`sing-box` debug 日志会打印匹配的 rule）。若 `tun.NewPackageManager` 在该设备失败，日志会有 warn，则 `package_name` 规则静默不匹配——记录为已知边界，不阻塞。

**若第 1 或 3 条不成立，D18 被证伪**：那说明该内核的 `sockfs_setattr` → `sk_uid` 链路或 AOSP 的 `fchown` 行为与源码不符。此时必须回到设计，重新在旧的"不捕获系统 DNS"与"全设备劫持 :53"之间选择，**不得**靠特判 :53 端口蒙过去。

## 16.2 观测半场的实测结果（SM-S9180 / Android 16 / 5.15.211-Qkernel，2026-08-25）

Phase 0 分两半：**观测半场**（只读，回答"设备实际是什么样"）与**证伪半场**（Q1–Q9，需要加载 BPF）。下表是观测半场的结果,全部通过 `adb shell su -c` 只读采集,未加载任何程序、未修改任何对象。

设备:SM-S9180 / SM8550(kalama) / Android 16 / SDK 36 / 安全补丁 2026-04-05 / **kernel 5.15.211-Qkernel**(恰为产品基线) / page size **4096** / root 为 KernelSU(`u:r:ksu:s0`)。

### 16.2.1 与蓝图预测一致的（可以停止怀疑的）

| 项 | 蓝图预测 | 实测 |
|---|---|---|
| `all.rp_filter` / `default.rp_filter` | 预期 0,但"必须检查而非假设"(§8.4) | **全部 0**,49 个 interface 无一例外 |
| `accept_local` | 预期 0,需我们在 `flxrs1` 上设 1 | **全部 0** —— 确认必须设 |
| `ip_forward` / `ipv6 forwarding` | 预期不需要打开(§8.4 推断) | **都是 0**,即 Q5 的测试条件就是设备原生状态 |
| `ip_local_port_range` | listener 端口取 61000–65535 须在其上 | **32768–60999**,不重叠 |
| `rmnet_data0` 链路类型 | ARPHRD_RAWIP ⇒ L3 分支强制(§3.3.1) | **ARPHRD_RAWIP(519)**,15 个 rmnet 全是 |
| `wlan0` 链路类型 | ARPHRD_ETHER ⇒ L2 分支 | **ARPHRD_ETHER(1)** |
| netd `ip rule` 最低 priority | 10000,故 1–9999 空闲(§8.3) | **最低 10000**,1–9999 **整段为空**,pref 100 可用 |
| 路由表 20260 | 应在 netd 的 `1000+ifindex` 之外 | v4/v6 **均为空** |
| fwmark 位占用 | 0–20 被 netd 用,21–28 空,31 是 wakeup(§3.1) | 实际用到 `0x7fefffff` 掩码 + **`0x80000000`(bit 31,`wakeupctrl` NFLOG)**。21–30 未见占用 |
| GKI config | §4 的整张表 | **逐项命中**,含 `CONFIG_VETH/DUMMY/TUN/NET_SCH_INGRESS/NET_CLS_BPF/NET_ACT_BPF/BPF_SYSCALL/BPF_JIT/CGROUP_BPF/DEBUG_INFO_BTF/IP_MULTIPLE_TABLES/NF_CONNTRACK` |
| `CONFIG_NETKIT` | 四个 GKI 分支全缺 | **缺失**,netkit 不可用 |
| BTF | `SK_STORAGE` 需要 | `/sys/kernel/btf/vmlinux` **存在,5,779,111 字节** |
| `clsact` 生命周期 | netd 随 interface 加入/离开网络创建与删除(§8.5.1) | **只有 3 个 UP 的蜂窝口(`rmnet_data0/1/8`)有 clsact;`wlan0` 没有**(当前未连接)。直接印证 |
| `packages.list` | 10 字段,`uid = userId*100000 + appId` | **10 字段**,561 行,UID 范围 1000–10425 |

### 16.2.2 与蓝图不一致、已据此改文档的

**(a) cgroup 槽位不是常驻占用。** 见 §0.1 第 2 条的更正框。`bpftool cgroup show` 对根、`/apps`、`/system` 与全树遍历**全部返回空**,但 8 个 `cgroup_sock_addr` 程序确实已加载。结论:bpfloader 开机只 load+pin,按需 attach。

**(b) AOSP 的 TC 优先级表描述的是"潜在冲突",不是当前状态。** §8.5.2 那张表来自 AOSP 源码常量,是对的;但**本机当前 `tc filter show` 在所有 interface 上都是空的**,`bpftool net show` 的 xdp/tc/flow_dissector/netfilter **四项全空**,而同时有 **29 个 `sched_cls` 程序已加载**。也就是说 tethering / CLAT / `tc police` / `dscpPolicy` 的程序都躺在那里等激活。实际含义:egress pref 1 在常态下是空闲的,§8.5.2 的共存设计仍然必要,但触发条件比预想的稀疏。

### 16.2.3 蓝图完全没有预料到的

| 发现 | 影响 |
|---|---|
| **14 个 `epdg0..13` 接口,全部 `ARPHRD_NONE`**(VoWiFi/ePDG 隧道) | §3.3 的 admission 会逐个遍历并排除它们(既非 ETHER 也非 RAWIP,且不叫 `v4-*`)。行为正确,但**接口清单比预期长得多**(49 个),admission 的日志与 `status` 输出要能承受这个规模而不刷屏 |
| **`tun0` 处于 UP 且有 `uidrange 0-99999` 的 netd 规则**(netId 0x76) | 设备上**当前有 VPN 在跑**。按 §3.5,此时物理口上看到的是 VPN 的 outer socket,不是 app 的。**任何捕获测试在关掉 VPN 之前都不可信** |
| **Samsung 自有 BPF 规模远超 AOSP**:86 个 prog pin / 115 个 map pin,含 `mnxbNetd`、`netlog`(5 个 ringbuf)、`semSmartHS`、`semUidBPF`、`tcpAccECN`、**`tosMarker`(`tos_policy_mobile_map`)** | `tosMarker` 与 §2.2.3(6) 的 DSCP 边界直接相关:除 AOSP 的 `dscpPolicy` 外,三星还有自己的 ToS 标记路径。被代理流量丢失 app 级标记这条**影响面比蓝图写的更大** |
| **`qcom_qos_reset_POSTROUTING` 对本机源地址出向流量 `--set-xmark 0x0/0xffffffff`** | 高通 QoS 在 POSTROUTING **清空整个 fwmark**。我们不用 mark,所以无影响;但这条独立地证明了 §19 拒绝 mark 方案是对的——**在这台设备上 mark 根本活不到出口** |
| **`memlock` rlimit 仅 64 KB** | kernel ≥ 5.11 用 memcg 而非 memlock 记账 BPF 内存,所以 5.15 上不受限。但若将来回落到更老内核,16 KiB ringbuf + 9 张 map 会撞上这个上限。记录备查 |
| **`/system/bin/bpftool` 已存在**(v5.16.0 / libbpf v1.4) | Phase 0 证伪半场可以直接用它做 attach 验证与 map dump,不必自带工具 |
| **旧架构残留仍在设备上**:`/data/adb/flux`、`/sys/fs/bpf/flux/`(空目录)、以及**仍然安装着的 `flux` 模块** | 在 0.9.0 上机测试前**必须清理**,否则新旧模块会争同一批对象与目录 |
| `private_dns_mode = opportunistic` | D18 依赖的明文 DNS 路径在此模式下**确实存在**(机会性 DoT,失败回落明文)。但上游支持 DoT 时查询走 853 加密,那部分不在捕获范围内——与 §1.3 的残余边界一致 |

## 16.3 通过标准

- `2 family × 2 protocol` 的 TCP/UDP 原目的**逐字节**一致，4 个 socket 全部完成 readiness 核验。
- 任何 pre-redirect 的未入场失败保留原 skb（真实目的侧能看到该连接直连成功）；任何 post-boundary 失败明确 drop（真实目的侧看不到任何字节）。
- 活跃 TCP decision 不被容量驱逐、first-decision-wins、不原地翻转、socket 关闭后释放。
- 所有 capture filter 是 first applicable；egress "不接管" 全部用 `TC_ACT_UNSPEC`；AOSP CLAT 与后续 OEM filter 仍被执行。
- frozen control leaf 经 pointer swap 只出现完整 old/new snapshot。
- Android 系统 TC/RPDB/VPN/sysctl 对象无修改或覆盖（`all.rp_filter` 亦未被 Flux 写过）。
- 全程无需 cgroup attach、sing-box patch、SOCKMAP、heartbeat 或第二后端。

**任何一项不成立：停止进入清库与编码阶段**，修订本蓝图并重新请所有者确认。不得把 Phase 0 变成长期实验平台。

---

# 第 17 部分：实施阶段

| 阶段 | 交付物 | 退出条件 |
|---:|---|---|
| 0 | 可丢弃的 vertical spike | §16 全部关键 seam 通过 |
| 1 | 仓库骨架、`flux-core` 全部纯逻辑 + 单测、xtask、module staging、版本与 engine pin | Windows 上 `cargo test -p flux-core` 全绿；`cargo xtask package` 两次 clean build hash 一致 |
| 2 | `fluxd` layout/单实例/控制协议/CLI/reactor 骨架/engine 候选生命周期 | 冷启动与热更新事务在设备上闭环（尚无数据面） |
| 3 | netlink：veth、route/RPDB、clsact/filter、interface admission、ownership 谓词、rp_filter 检查 | Direct / Active / 冲突 / 恢复四条路径闭环，`status` 逐 interface 有原因 |
| 4 | 最小加载器（map/BTF/relocation/ringbuf）+ 三个 BPF entry + counters + fault 自愈 | 单台目标 Android 上双栈 TCP/UDP 短功能 smoke 通过 |
| 5 | 三管理器 module lifecycle + release | 0.9.0 artifact / checksum / 文档一致 |

每阶段保持可 build；**不为下一阶段预建抽象**。阶段 4 发现真实回归时只为该不变量加一个聚焦测试。

---

# 第 18 部分：从当前仓库过渡

## 18.1 我的建议（与旧蓝图不同）

**所有者已决定：删除工作树与 `.git`，重新 `git init`**（D13）。因为历史将不可恢复，归档是**强制前置步骤**，不是建议。

两次确认门（清理不可逆，必须拆成两次授权）：

1. **确认本蓝图并授权 Phase 0**：只在临时目录验证 seam，**不删除任何东西**。
2. **Phase 0 全部通过后，第二次显式确认**：才执行下面的归档与清库。

第二次确认后的执行顺序：

0. **先匿名化再归档。** 逐行审计（F-07）发现 `docs/research/sm-s9180-dualstack-soak-evidence-2026-08.md:15` 提交了**真实设备序列号**，违反当时 `docs/development.md:135-136` 自己的规定。文档治理阶段（2026-08-25）已把该文件移入 `archive/2026-08-25-superseded/`，但**内容未修改**。删库重建是彻底消除它的唯一机会：复制到仓库外之前，必须把序列号 / IMEI / Android-ID 替换成稳定匿名 ID（例如 `DEV-A`），映射表另存于归档目录之外。新仓库的 CI 必须加一条 grep 检查拒绝此类标识再次进入。**注意 `git bundle` 会完整保留旧历史里的原值**，所以 bundle 属于私有归档，不得公开分发。
1. **归档（必须完成并校验后才允许删除任何文件）**：把以下内容复制到仓库外目录（建议同级 `Flux-rs-design-archive-2026-08-25/`）并生成 SHA-256 manifest：
   - 本目录 `audit/2026-08-25-flux-rs-0.9.0-final/` 全部文件；
   - `audit/2026-08-24-final-ebpf-blueprint/`（含 `primary-source-research.md`、`source-manifest.md`）；
   - `audit/2026-08-25-flux-rs-0.9.0-impl-blueprint/`；
   - `audit/2026-08-24-full-repository-line-audit/`、`audit/2026-08-24-design-and-code-audit/`；
   - `archive/2026-08-25-superseded/`（2026-08-25 文档治理已把旧 `docs/**`、`CONTEXT.md`、`README*`、`CHANGELOG.md`、`notes.md`、`task_plan.md` 全部移入，含**不可复现的真机证据**；该目录被 `.gitignore` 排除，因此不在 git 里，必须显式复制）；
   - **`audit/2026-08-25-flux-rs-0.9.0-final/`（本设计包本身）。这是本清单里最容易致命的一条**：`.gitignore:27` 的 `/audit/` 规则意味着**本蓝图、`reference/flux_abi.h`、`reference/flux.bpf.c` 全都不在 git 里**，因此 `git bundle --all` **不会**包含它们。一旦先删工作树再想起来，唯一的设计合同就永久丢失，`git reflog` 也救不回来——它从未被 git 跟踪过。**执行第 3 步之前，必须先把这个目录复制到仓库之外并核对 SHA-256。**
   - **§18.3 列出的、计划移植的全部源文件**（因为 `git init` 之后再也 `git show` 不到它们）；
   - 一份 `git bundle create ../Flux-rs-legacy.bundle --all`（**强烈建议**：一个文件，离线可读，是"删历史"与"能查证"的唯一交集）。
     > **`--all` 不包含 stash。** 本仓库现有 **18 个 stash**，其中只有 `stash@{0}` 是真 ref（`refs/stash`），`stash@{1..17}` 存在于 `refs/stash` 的 **reflog** 里，而 bundle **不携带 reflog**。要保留就必须先把每个 stash 变成真 ref：`git tag archive/stash-<N> stash@{<N>}`（逐个），再 bundle。否则 17 个 stash 静默消失。
   - **确认没有其它工作树引用本 `.git`。** 现有两个位于 `C:/Users/Chth1z/.grok/worktrees/github-flux-rs/` 的 detached-HEAD 工作树（子代理遗留）会在删除 `.git` 后损坏；先 `git worktree list` 核对再 `git worktree remove`（或确认可弃）。
2. 逐项核对 manifest 的 SHA-256 与文件数量。
3. 删除工作树内容与 `.git`，`git init`，按 §5 骨架从空目录新建，首个提交为 `chore: Flux-rs 0.9.0 initial import`。
4. 远端 force-push、删仓或改 GitHub repository 设置**另行单独授权**；本蓝图只规划本地重建。

## 18.2 清理矩阵

| 当前内容 | 动作 |
|---|---|
| `audit/**`、`archive/**` | 先归档到仓库外，再从产品库删除 |
| 旧 `README`/`README_zh`/`CONTEXT.md`/18 个 ADR/`docs/**`/`notes.md`/`task_plan.md` | **2026-08-25 已归档至 `archive/2026-08-25-superseded/`**（见该目录 `MANIFEST.md` 的取代关系表）；产品树只按 §5 重写 `README.md`、`CHANGELOG.md`、`docs/architecture.md` |
| `crates/flux-platform`、`crates/flux-testkit` | 删除（部分文件按 §18.3 移植） |
| `crates/flux-core`、`crates/fluxd` | 清空后按 §5 重建（部分文件按 §18.3 移植） |
| 旧 BPF C 与已提交 `.o`（`flx_sock_addr.c`、`connect4_token.c`、`trial_prog.c`、token/cookie/proof/canary） | 删除，重写单一 `bpf/flux.bpf.c` |
| `engine/sing-box/manifest.toml`、`xtask/src/sing_box_producer.rs`、任何 patch | 删除；只从 `engine.lock` 取官方 asset |
| `META-INF/`、`webroot/`、`conf/`、`flux_service.sh`、`customize.sh`、`uninstall.sh` | 删除；从 §13.1 的 allowlist 重建 |
| `tests/shell/**`、`xtask` 的资格/canary/preflight 子命令 | 删除 |
| 旧版本号/schema/protocol/manifest 数字（module `v0.1.0-dev`、config schema 5、control protocol v9、capability schema 3、package manifest schema 4） | 删除；只保留 `0.9.0` 与 `FLUX_ABI_MAGIC` |
| `clone/`（第三方研究源码） | **直接删除，不进归档**。它可随时按 §0.5 的清单与 commit 重新克隆；把第三方源码放进归档反而增加"新代码抄了旧第三方实现"的风险 |
| `target/`、缓存、临时下载 | 删除，由 `.gitignore` + clean staging 隔离 |

执行原则是"清空后按 allowlist 新建"，不是逐文件修补。

## 18.3 应当移植（而非重写）的低层原语

审计发现的缺陷集中在策略/generation/抽象层，不在这些机械正确的原语。**移植时必须逐行复审并去掉对旧类型的依赖**，但不要从零重写。

### 18.3.0 规模现实：可移植的是个位数百分比

2026-08-25 对现有树做了逐 crate 实测（`Measure-Object -Line` 全量 `*.rs` + 逐文件读）：

| 类别 | 行数 | 占比 |
|---|---:|---:|
| Rust 总量（含测试与 xtask） | ~144,600 | 100% |
| **明确属于旧架构、必须删除** | ~64,400 | 44.5% |
| 旧架构的测试 | ~15,700 | 10.9% |
| 乐观口径的"可移植文件"（整文件计） | ~26,000 | 17.9% |
| **剥掉纠缠部分后真正能落地的** | **~8,000–12,000** | **~6–8%** |

**有效可移植 : 待删除 ≈ 1 : 8。** 这不是在评价旧代码的质量——它是**另一个系统**的成熟实现（cgroup SOCK_ADDR + token 地址 + RPDB/nftables 调和 + 资格 oracle）。

### 18.3.1 决定性事实：0.9.0 的数据面在现有树里**完全不存在**

对现有 `crates/` 与 `xtask/` 全树 grep，以下符号**零命中**：

`bpf_sk_assign` · `SCHED_CLS` · `bpf_redirect` · `RTM_NEWQDISC` · `RTM_NEWTFILTER` · `TCA_KIND` · `TCA_BPF` · `clsact` · `sk_storage` / `SK_STORAGE` · `BPF_MAP_TYPE_RINGBUF` · `btf_fd` · `BPF_BTF_LOAD` · `timerfd` · `IFLA_INFO_DATA` · `VETH_INFO_PEER`

`veth` 一词只在 `canary_facility_policy.rs` 与 `android_platform_profile_catalog.rs`（都属删除清单）里作为**名字字符串**出现；`IFLA_INFO_KIND` 只出现在**解码**路径。**因此没有任何 veth 创建代码。**

**必须从零写的清单**（无任何可移植前身）：三个 BPF 程序与全部 map、手写 BTF blob 与带 `btf_fd` 的 prog load、TC qdisc/filter 的 netlink 消息（§8.9.4–8.9.5）、veth pair 创建（`RTM_NEWLINK` + `IFLA_LINKINFO`/`IFLA_INFO_DATA`/`VETH_INFO_PEER`，§8.9.1）、ringbuf 消费者、reactor 的 timerfd 源。

### 18.3.2 移植清单（已按实测修订）

| 来源 | 行数 | 用途 | 纠缠度 | 移植去向 |
|---|---:|---|---|---|
| `flux-platform/src/bpf/sys.rs` | 661 | 裸 `bpf(2)`：prog load / map CRUD / pin / obj info / query，含 EINTR 重试与 deadline | **低**（自足） | `fluxd/src/bpf/sys.rs`。**必须扩展**：`btf_fd`、`BPF_BTF_LOAD`、TC attach |
| `flux-platform/src/seqpacket.rs` | 2,476 | `SOCK_SEQPACKET` + `SO_PEERCRED` + `SCM_CREDENTIALS` + 路径/inode 校验 | **低** | `fluxd/src/control.rs` |
| `flux-platform/src/netlink.rs` | 412 | netlink 头/属性迭代、`NLMSG_DONE`/`NLMSG_ERROR` | **低** | `fluxd/src/netlink/mod.rs` |
| `flux-platform/src/netlink/socket.rs` | 1,458 | `AF_NETLINK` socket、多播组、dump 时序、批量 recv | **中** | `fluxd/src/netlink/socket.rs` |
| `flux-platform/src/netlink/policy_routing.rs` | 1,639 | **唯一存在的 netlink 变更构造器**：`RTM_NEWROUTE`/`NEWRULE` 及其删除、`mutation_flags` | **中**（只取构造/应答处理，弃 RPDB 语义） | `fluxd/src/netlink/route.rs`——0.9.0 只需一条 rule + 一条 local 路由（§8.3） |
| `flux-platform/src/netlink/{link,route,rule}.rs` | 600 / 1,212 / 1,175 | 消息**解码**（admission、冲突检测、本机地址 bypass 都要用） | **中**（依赖 flux-core 域类型） | `fluxd/src/netlink/*` |
| `flux-platform/src/socket_diagnostics{,/implementation}.rs` | 2,414 | `NETLINK_SOCK_DIAG` 枚举、listener 冲突定位 | **中**（自足，测试重） | `fluxd/src/engine.rs`（§9.3 就绪核验） |
| `flux-platform/src/{process,child_process}.rs` | 2,182 / 718 | pidfd、fdinfo/procfs、fork/exec、`PR_SET_PDEATHSIG`、关 fd、capability set | **低–中** | `fluxd/src/engine.rs` |
| `flux-platform/src/shutdown.rs` | 186 | signalfd + `pthread_sigmask` | **低** | `fluxd/src/reactor.rs` |
| `flux-platform/src/file_observer.rs` | 862 | `inotify_init1`、watch 增删、事件解析 | **中**（`FileObservationPaths` 写死了旧文件名） | `fluxd/src/reactor.rs` |
| `flux-core/src/packages_list.rs` + `flux-platform/src/bpf/packages.rs` | 116 + 40 | `packages.list` 解析、`ANDROID_PER_USER_RANGE = 100_000` | **低** | `flux-core/src/selector.rs` |
| `flux-core/src/network_inventory.rs` | 739 | link/addr 快照域模型（interface admission + 本机地址 bypass） | **中** | `flux-core/src/inventory.rs` |
| `flux-core/src/capture_program.rs` | 671 | `CaptureIpPrefix`、canonicalize、强制 bypass 前缀（**只取 ~300–400 行**） | **中** | `flux-core/src/cidr.rs` |
| `flux-platform/src/android_kernel_capabilities.rs` | 985 | `/proc/config.gz` 解析与 CONFIG 名常量（`NET_SCH_INGRESS`/`NET_CLS_BPF`/`DEBUG_INFO_BTF`…） | **中**（弃 nftables 门禁） | `fluxd/src/probe.rs` |
| `flux-platform/src/android_identity{,_properties}.rs` | 781 + 206 | getprop/procfs 设备指纹 | **低** | `fluxd/src/status.rs` |
| `xtask/src/main.rs` 的 staging / `verify-package` / ELF 检查 / zip；`android_profile.rs` 的 NDK 与 linker 命名 | ~1,200 | 可复现打包与 aarch64 交叉编译 | **低** | `xtask/src/main.rs` |

**只当参考实现、不要整体搬**（读它们学做法，代码重写）：

- `reactor.rs`（1,166）——**不是**通用 epoll 循环，它直接绑死 `NetworkInventorySource` / `RouteNetworkInventoryDriver` / `FileObserverDriver`，且缺 timerfd 与 ringbuf 源。
- `sing_box.rs`（2,315）——内含 `POLL_INTERVAL = 10ms` **轮询**就绪，与 §10.1"无周期轮询"直接冲突。就绪判定必须改成 SOCK_DIAG + pidfd 事件驱动（§9.3）。
- `control.rs`（722）——后台线程 + mpsc 派发，与单线程 reactor 冲突。
- `bpf/sock_addr_object.rs`（354）——真实的最小 ELF 解析，但**写死了 11 个 cgroup 程序与 token map**，只有约 150 行是通用的。
- `network_observer/driver.rs`（3,233）——旧版蓝图曾把它列为"直接就是 §10.4 需要的 inventory 引擎"，**这条已撤销**：它是 generation 作用域的调和用 observer，与 §10.4.1 的三条硬规则（全量重 dump、debounce、ifindex 一致性）不同构。

**明确不得移植**：`capture_path*`、`intercept_policy`、`android_mark_authority`、`android_rpdb`、`android_tproxy_topology`、`rpdb_placement`、`address_bypass`、`fwmark_*`、`planning_residual/*`、`android_platform_profile_catalog`、`canary_facility_policy`、`statistics`、`config`、`generation_engine_config/*`、`runtime_coordinator/*`、`native_*`、`subscription/*`、`protocol`、`clash_control`、`inspection`、`offline_cleanup`（其中只有约 80 行 `flock` 租约值得看一眼）、`address_sync`、`netlink/policy_routing_session`、`bpf/{sock_addr*,token_map,occupancy,proof,throwaway,capture_journal,intercept,vpn_proc}`。这些是旧架构的产物，或被审计判为缺陷源。

### 18.3.3 顺带保住的低成本资产

| 资产 | 位置 | 为什么值钱 |
|---|---|---|
| 模块脚本 | `customize.sh`、`flux_service.sh`、`uninstall.sh`、`module.prop` | 安装模式判定与 `/data/adb/flux` 载荷布局已经调通；按 §13.2.0 补三管理器差异即可 |
| CI workflow | `.github/workflows/ci.yml` | Rust 1.93.0 + NDK r27d + `cargo deny` + shell 语法检查的组合 |
| `deny.toml` | 仓库根 | 许可证/公告策略（GPL-3.0-only） |
| `rust-toolchain.toml`、`.cargo/config.toml` | 仓库根 | 工具链固定 + `aarch64-linux-android` 目标与 linker 配置 |
| NDK 版本钉 | `xtask/src/{main,android_profile}.rs` | NDK **27.3.13750724**、API 31 的 linker 命名规则 |
| GKI CONFIG 清单 | `android_kernel_capabilities.rs` | 与 §4 的 defconfig 表互为交叉验证 |

**仓库内没有任何 `.te` / SELinux 策略文件**，§12.8 若最终需要 `sepolicy.rule` 属于新增。

## 18.4 旧审计发现的关闭方式

三份审计（`2026-08-24-full-repository-line-audit`、`2026-08-24-design-and-code-audit`、`2026-08-11-overdesign-review`）的全部结论在新设计里的归宿。**"架构性关闭"意味着该缺陷所依附的机制在 0.9.0 不存在，不是"以后再修"。**

| 旧问题族 | 代表 ID | 关闭方式 |
|---|---|---|
| `fluxd` 不编译（缺 import） | F-01 | 架构性关闭：相关模块整体删除；CI 的 `cargo build --target` 是硬门禁 |
| Generation → Capture seam 丢失完整 Intercept Policy，family/protocol 被静默放大 | F-02、设计 P1 #6 | 架构性关闭：不再有"策略编译 → 写入器重建策略"两段式。策略就是 `uid_policy` + 两张 LPM，由同一次收敛直接写入 |
| promote journal 在 restore 失败时仍删除记录 | F-03 | 架构性关闭：无 journal、无 promote。对象由 level-triggered 收敛管理（§10.5） |
| UDP Proof 用 token map 反查冒充 orig-dst cmsg | F-04 | 架构性关闭：删除 token 路径；原目的由真实 header + 官方 engine 的 `IP(V6)_RECVORIGDSTADDR` 提供，Phase 0 Q4 直接读 engine 侧的值 |
| rollback 错误被吞、状态谎报 `attached=false` | F-05 | 规则化关闭：§15.4(1) 状态报告诚实性 |
| sing-box ELF 16 KiB 门禁被特判弱化成 4 KiB | F-06 | 架构性关闭：`engine.lock` 要求四个 `PT_LOAD` **精确等于** `0x1000`，并把 4 KiB 写成产品边界；`fluxd` 自身单独要求 ≥ 16 KiB（§9.7、§13.4） |
| 真机序列号进仓库 | F-07 | §18.1 第 0 步匿名化 + 新仓库 CI grep 检查 |
| Proof 与活跃 engine 共享 socket queue | F-08 | 架构性关闭：无 production Proof daemon、不复制 engine 的 fd。readiness 用 SOCK_DIAG 只读枚举（§9.5） |
| CI 调用已删除的 xtask 命令、文档列退役命令 | F-09、F-13 | 规则化关闭：§15.4(3) 命令一致性自检 |
| fmt/clippy 红、ABI 测试断言 C 源字符串 | F-10 | 规则化关闭：§15.4(2)；`cargo xtask ci` 是硬门禁 |
| Clash / Generation 互斥只实现单向 | F-11 | 架构性关闭：0.9.0 无 Clash 控制面（§1.3） |
| 真机资格证据未闭环 | F-12 | §16 Phase 0 + §20 发布验收；证据字段从 catalog 改为一次性 smoke 记录 |
| 迁移残留 + 单次巨型提交 | F-14 | §17 分阶段交付，每阶段可 build；§18.2 清理矩阵按 allowlist 重建 |
| 设计语料同时规定三种互不兼容的 attach 策略；ADR YAML/正文互相矛盾；README 停留在旧协议与已删命令 | 设计 P0 #1–#4、P1 #20 | 规则化关闭：§15.4(4) 单一权威文档，无 ADR 目录 |
| 双 Capture 外部接口（`Capture` vs `NativeCaptureConvergence`） | 设计 P1 #5 | 架构性关闭：不为单一实现创建 trait（§5） |
| Capture Path 选择器骨架、`CapturePathId::ALL`、租约、digest、wire 残留 | 设计 P1 #7–#8、过度设计 P1 #5 | 架构性关闭：只有一条数据路径，代码里没有"路径"这个概念 |
| ~12k 行 fwmark / TPROXY topology / canary facility / Passed catalog 仍在 `flux-core` 公开 API | 设计 P1 #9–#10 | 架构性关闭：不写 fwmark、不做 topology 规划、无 catalog（§3.1、§8.3） |
| `forwarded_ingress` / `forwarded_proxy` 等已删配置键仍在类型与 digest 里 | 设计 P1 #11 | 架构性关闭：`flux.toml` 只有 `apps` 与 `bypass_cidrs`（§11.2） |
| Geek IPv4-only TCP 切片是第二条写入路径 | 设计 P1 #12 | 架构性关闭：一个数据面、两个 entry（按 L2/L3 布局，不按协议族分叉） |
| god object（coordinator / engine_supervisor / generation_source 各数千行） | 设计 P1 #13、过度设计 P0 #1 | 架构性关闭：§5 的模块划分 + §10.5 的幂等收敛取代事务编排 |
| `cidr4`/`cidr6` map 创建但未 pin | 设计 P1 #13b | 架构性关闭：不 pin 任何 map（§6.1） |
| VPN RPDB singleton 确认是空实现 | 设计 P1 #13d | 架构性关闭：VPN 处理改为"排除全部 TUN + 选中 VPN app 时告警"（§3.5、§11.3） |
| 生产 crate 里残留 TPROXY 双 inbound 编译器 / SO_MARK credential probe | 设计 P1 #13e–f、#19 | 架构性关闭：只注入两个 tproxy inbound，无 mark、无 credential probe（§9.1、§9.3） |
| ~30k–49k 行 `functional_canary` 靠 `cfg(test)` 留在树里 | 设计 P1 #14、过度设计 P0 #1 | 架构性关闭：无 canary 概念；验证靠 Phase 0 一次性 spike + §15.2 的八个逻辑测试 |
| `engine/sing-box/manifest.toml` 仍构建 patch 0002 | 设计 P1 #15 | 架构性关闭：`engine.lock` 只接受官方 asset digest，零 patch（§9.7） |
| xtask 暴露 xtables 时代资格命令、四个 Android runner 重复 session 逻辑 | 设计 P1 #16、过度设计 P1 #7 | 架构性关闭：xtask 只做 build/package/release（§13.4） |
| `statistics.rs` + `traffic_observation.rs` ~2.6k 行无消费者 | 设计 P1 #17、过度设计 §9 | 架构性关闭：换成 18 个事件级 per-CPU counter，唯一消费者是 `fluxd status`（§6.1、D12） |
| canary 状态在 6+ 个类型里重复投影、三重 deadline 检查、trust 分层无威胁表 | 过度设计 P0 #2、P1 #6、§10 | 架构性关闭：只有三个顶层状态（§10.1）、一处 admission 判定（§8.7）、一份威胁边界声明（§1.5） |
| daemon 里写裸 rtnetlink（错误 seam） | 过度设计 P0 #3 | 规则化关闭：§5 的 netlink/bpf 模块边界要求 |
| 24+ 无人居住的脚手架、先铺横向权限再做纵向闭环 | 过度设计 P0 #4 | 规则化关闭：§17"每阶段保持可 build，不为下一阶段预建抽象" |

审计里被判为"**不是缺陷**"的两项也保留：默认打包配置只读（pre-release 边界，非缺陷）；Clash 的同 UID 控制 socket 边界设计正确——后者在 0.9.0 因删除 Clash 而不适用。

---

# 第 19 部分：被拒绝的替代方案

| 方案 | 否决依据 |
|---|---|
| cgroup SOCK_ADDR + token 地址（旧仓库路线） | UDP 原目的的 cmsg 由内核在 recvmsg **之后**从 skb 生成，SOCK_ADDR hook 无法恢复 → 对官方 engine 是伪证明；且 Android 15/16 已 flags-0 独占 root cgroup 的 connect/sendmsg/recvmsg 槽位，后代 attach 被内核拒绝 |
| child cgroup `SETSOCKOPT`/`POST_BIND` provenance | 同一 flags-0 祖先规则阻止；且引入 Android 版本分叉与 SELinux/OEM cgroup 权限不确定性 |
| 抢占 netd 的 cgroup 槽位（CHIZI / bpf2socks 做法） | 会静默关掉 Android 自己的 connect hook；netd 重启即互相替换。产品不能建立在此之上 |
| eBPF 分类 + iptables/nftables TPROXY | 静态 netfilter/mark/RPDB 对象不随 fd 消失，daemon `SIGKILL`/掉电后形成不可证明的黑洞窗口；且必须占用 Android packed fwmark |
| 在 ingress 用 `skb->mark` + `fwmark` 规则代替专用设备 | 需要占用 Android fwmark 位；且 Android 的 `tcp_fwmark_accept` 会把 mark 传播到 request sock，行为难以论证 |
| 重定向到 `lo` ingress + `iif lo` 规则 | **机制上根本不成立**：`loopback_xmit()` 会调 `skb_dst_force()`（v6.1 `drivers/net/loopback.c:84`），于是 `skb_valid_dst()` 为真、`ip_rcv_finish_core()` **跳过** `ip_route_input()`，包会按一个 *output* rtable 的 `dst->input` 被丢弃。veth 之所以可行，恰恰是因为 `skb_scrub_packet()` 会 `skb_dst_drop()`。次要理由：`iif lo` 在 netd 的语义里表示"本机产生"，那条规则会命中**全部**出向流量 |
| 把策略全部收进 ingress、egress 做无条件 redirect | 技术上可行（`skb->sk` 确实活到 veth peer ingress，见 §7.5 的不变量表），但它要求**把未选中的流量也 redirect 一遍**再判断，然后还得原路送回去——那就需要 dae 的 `redirect_track` + 反向 redirect + MAC 恢复。代价是彻底放弃"未选流量只付 1 helper + 1 hash miss"这条性能地基（§14.1），换来的只是少一个 hook。**明确评估后拒绝** |
| ingress 先 `bpf_skc_lookup_tcp` 找 established 再 assign（CHIZI 的形态） | 自包含性更好，但**每个已建立连接的包都要多一次 socket 查找 + 一次 assign**；而 §7.5 的不变量表已证明"不 assign、交给内核按 tuple 查"是正确的，且 dae 在生产上依赖同一条路径。稳态热路径的成本差异是决定性的 |
| 保留 iptables TPROXY 作为兜底后端 | 被重新提议过，理由是"多一条代码路径换任何设备都能用"。仍然拒绝：兜底后端要用 fwmark + iptables，正是 §3.1 与 §19 其它行要避免的东西；且它把一次 seam 失败变成长期双实现维护。产品身份就是 eBPF-only |
| `BPF_PROG_TYPE_SK_LOOKUP` | netns 级 hook，会介入设备上**所有**入站 socket 查找；风险面远大于设备级 TC filter |
| TUN 后端 | 全部流量进用户态栈，copy/wakeup/协议复杂度更高 |
| SOCKMAP / `pidfd_getfd` listener handoff | 需要 fd 发现、reload ABI、跨进程权限，把官方 engine 的生命周期变成 Flux 私有 ABI |
| sentinel listener + 随机 `SO_MARK`（前两版蓝图） | 技术上可行（listen 字段确实支持 `routing_mark`），但它防的是文档自己声明不抵抗的威胁；liveness/换代性质由 actual listener lookup 已完全提供 |
| generation 编码的 handoff MAC | 只防换代瞬间 in-flight 包的无害错送，代价是 46-bit 编码方案 + 每包比对 |
| anchor dead-branch + TC program ID reclaim | 依赖"编译器不消除 dead branch"，且保护的状态在 engine 已死时无价值 |
| TCP cookie `LRU_HASH` flow map | 容量满会驱逐仍活跃的 flow，可能让已入场连接中途 direct |
| heartbeat / 周期 counter / packet telemetry ringbuf | 增加周期唤醒与热路径状态，且不解决 post-redirect 的原子回退问题 |
| libbpf / libbpf-rs 作为加载器 | 需为 Android 交叉构建 elfutils/libelf/zlib；我们不用 CO-RE，其 99% 功能是负担 |
| aya-ebpf 写 BPF | 需要 nightly Rust；且其 `SkStorage` API 目前只覆盖 sock_addr context，不覆盖 TC |
| 多后端 fallback | 把一次 seam 失败变成长期双实现维护 |
| 首发做远程 subscription | 额外引入 TLS/重试/信任/promotion 面，不属 eBPF 核心闭环 |
| `bpf_redirect_peer` 省一跳 | **对本设计结构上不可用**，不只是 CVE 问题。`bpf_redirect` 的 `BPF_F_PEER` 分支要求 ① `skb_at_tc_ingress(skb)` 且 ② 目标设备在**不同** netns（v6.1 `net/core/filter.c:2458-2471`）。我们是 egress 侧 + 同 netns，两条都不满足。dae 自己的注释也写了"NOT supported in egress direction"（`tproxy.c:1518-1523`），并额外因 **CVE-2025-37959** 把它 gate 在 kernel ≥ 6.8。**因此必须为每个被捕获的包预算一次完整的 `dev_queue_xmit` + backlog/NAPI 跳**，不要规划这项优化 |
| flush OEM 的 `fw_*` / `oplus_*` filter 链让 TPROXY 工作 | box4magisk 的 `oneplus_a16_fix()`（`box.service:72-79`）就是这么做的。清空系统防火墙链违反 §1.3 非目标与 §15.4(1)。遇到这种设备保持 Direct 并报告 |
| 写全局 `net.ipv4.conf.all.rp_filter=0` | dae 这么做（`netns_utils.go:440`）。在用户手机上静默削弱全局安全 sysctl 不可接受，且崩溃后无法证明该恢复成什么值（§8.4） |
| 运行期关闭系统 Private DNS | box4magisk 这么做（`box.service:50-58`）。0.9.0 不替用户关掉加密 DNS |
| 引用 dae 的 `how-it-works.md` 作为 WAN 行为依据 | 该文档说 WAN egress 改写目的并关闭 checksum，与 `caa6f5e` 的 C 代码矛盾（§0.5.8）。只引 C |
| 全设备劫持 :53（box 系 / CHIZI `dns_mode: hijack`） | D18 之后完全不必要，且会让未选中 app 的 DNS 也走代理（反向错配），还要替用户关掉 Private DNS |
| 读 netd 的 `cookie_tag_map` 拿 DNS 归属 | D18 之后不必要。`fchown` 已把同一信息放进 `sk_uid`，无需碰 AOSP 私有 map、无需过 `fs_bpf_netd_*` SELinux、无跨版本 pin 名漂移 |
| 在 BPF 里特判 `dport == 53`（旧实现 `dport_is_dns`、CHIZI `force_dns`） | D18 之后 DNS 就是普通 UDP，没有任何理由特判端口。特判反而会覆盖用户显式 bypass（§1.3.4） |
| 运行期 `settings put global private_dns_mode off` | 见 §1.3.3 边界①。改用 `status` 检测并提示 |
| 用户态 packet pump（bpf2socks 的 bridge 架构） | `clone/bpf2socks` 的 `bridge_tcp.c` + `bridge_udp.c` 合计 4400+ 行用户态转发，且其 bridge socket 设了 `SO_REUSEPORT`（`bridge.c:95/125/152/189`）——那会让 6.5 之前的 `bpf_sk_assign` 直接返回 `-ESOCKTNOSUPPORT`。我们把 skb 直接 assign 给官方 engine，不引入第二个用户态栈 |

---

# 第 20 部分：发布前最终验收

打 `v0.9.0` tag 需以下条件**同时**成立：

1. Phase 0 记录证明核心 seam（真实 engine 观察到的原目的），而非 map 自洽。
2. 仓库只含 §5 允许的结构，无旧 code/artifact。
3. 官方 sing-box version/commit/asset digest 完全匹配 `engine.lock`，且四个 `PT_LOAD` 仍为 `0x1000`。
4. 发行说明与 runtime 都把 `base page == 4096` 写成 0.9.0 边界；`fluxd` 自身 LOAD ≥ 16 KiB 对齐；非 4096 设备保持 Inactive/Direct 且不启动 engine。
5. 未选 UID 的静态热路径确为"UID helper + 1 次 HASH miss"，无解析、无用户态。
6. 双栈 TCP/UDP 原目的由官方 sing-box 实际观察一致。
7. engine 退出后新 SYN/datagram 在下一次 listener lookup 就 Direct；已入场 TCP 的可解析包在仍经过 managed hook 时不因 Flux 内部状态丢失而直连。
8. Android VPN/TUN 未被 attach；CLAT 未确认时 Direct；netd fwmark/rules/sysctl 未被修改。
9. `stop`/`uninstall` 不 flush 系统对象；重启后无 Flux 内核残留。
10. Magisk、KernelSU、APatch 各完成一次 `install → boot → action/status → disable → uninstall/reboot` smoke。
11. `Flux-rs-v0.9.0-arm64.zip` 与 `SHA256SUMS` 由同一 xtask 生成，两次 clean build 一致。
12. **DNS 精准性已实测**：选中 app 的系统解析器 DNS 被捕获，未选中 app 的不被捕获（§16 Q9 第 1、3 条）。
13. `README.md` 逐字采用 §1.3、§2.2、§3 的边界；**明确写出 §1.3.3 的三条 DNS 残余边界（Private DNS 不经过 Flux、`enforce_dns_uid` 设备退化、mDNS 直连）**，以及 §1.3.4 需要 `hijack-dns` 才能生效域名规则；不使用"任何故障都无感直连""全 Android 通用"等夸张表述。

---

# 第 21 部分：需要项目所有者确认的事项

确认本蓝图等于确认以下六条：

1. 0.9.0 采用 **TC egress → 专用 veth → TC ingress `bpf_sk_assign` → 官方 sing-box TProxy** 作为唯一候选，并先做非破坏性 Phase 0。
2. fail-open 仅覆盖可检测的 redirect 前、未入场的新 TCP / 当前 UDP；越过 admission 后的内部失败允许 drop/reset；engine event-loop 活锁不自动识别；fragment / 未知 layout / Android 改路由到未 attach 的 interface 完全回到 Android 路径。
3. actual listener 的 synthetic tuple **不是** owner proof；0.9.0 不抵抗恶意本地进程在 listener 关闭竞态中用 `IP_FREEBIND` 抢绑；随机端口与 PID/inode 核验只降低非对抗碰撞。
4. 自动恢复是 event-driven 且无周期探测：进程退出、network/config/package 变化立即处理，部分 listener 故障在下一个相关 packet 触发自愈；完全无流量时的内部故障与 event-loop 活锁不可见。
5. 官方 sing-box 资产只有 4 KiB LOAD 对齐，因此 0.9.0 只支持 4 KiB base-page 设备；不重编上游，不以 app 兼容模式冒充原生 16 KiB 支持。
6. Phase 0 通过后**仍需第二次明确授权**才执行 §18 的清理重建。

## 21.1 我给出默认值、但需要你拍板的开放项

| # | 问题 | 我的默认 | 若你选另一个的影响 |
|---|---|---|---|
| **Q1** | 仓库策略 | **已决定（2026-08-25）**：删除 `.git` 并重新 `git init`。归档因此升级为强制前置步骤，见 §18.1 | — |
| **Q2** | 系统 DNS 处理 | **已解决（2026-08-25，D18）**：精准 per-app 捕获，零额外机制。不需要选 A/B/C——`fchown` 已经把归属放进 `sk_uid`。详见 §1.3.1–§1.3.4，残余边界只有 Private DNS / `enforce_dns_uid` / mDNS 三条 | — |
| **Q3** | 内核基线 | **已决定（2026-08-25）**：`5.15`。首发 Android 12 设备不在支持范围 | — |
| **Q4** | Phase 0 设备 | 假设可用 SM-S9180（Android 16 / 5.15.211 / KernelSU）。它同时是基线设备，故 Q6 可在同一台机上完成 | 若无法取得带 rmnet + CLAT 的蜂窝环境，Q6 的 CLAT 结论只能标"未证"，对应 interface 出厂即 Direct |
| **Q5** | 控制协议编码 | SEQPACKET 上的单行 JSON（人可读、易测） | 改紧凑二进制帧只影响 `control_wire.rs` 与 CLI |
| **Q6** | 文档语言 | 中文散文 + 英文标识符，单一主文档 + 两个参考代码文件 | 需要英文版或进一步拆分即可提出 |

在收到确认之前：**不执行 Phase 0，不清理旧库，不改动产品代码，不提交，不推送。**

---

# 第 22 部分：延期项与它们的 seam（"一次做到位"的自检）

要求是"这次设计就尽量做到完美，而不是后续再升级"。这一节把每个不在 0.9.0 里的东西逐项过一遍，只允许两种结论：**收进 0.9.0**，或者 **给出它插入哪个已存在 seam、为什么现在不做不会导致返工**。凡是"以后再想"的都不合格。

## 22.1 已因本轮调研收进 0.9.0

| 项 | 原本状态 | 现在 |
|---|---|---|
| 系统 DNS 精准 per-app 捕获 | 判为不可能 → 延期 | **收进**（D18，§1.3.1）。零额外机制 |
| `package_name` 级路由与 DNS 规则 | 未考虑 | **收进为文档能力**（§1.3.5）。不需要 Flux 写代码 |
| L2 捕获稳态零 packet 写入 | 每包一次 12 字节写 | **收进**（D17，§8.2） |
| 事件级 per-CPU counters | 无可观测性 | **收进**（D12，§6.1） |
| fragment 不再泄漏已捕获流 | 全部 direct（泄漏） | **收进**（D6，§7.3） |
| 本机地址动态 bypass | 未考虑 | **收进**（D7，§11.2） |

## 22.2 明确不做，且不会导致返工（附 seam）

| 项 | 为什么现在不做 | 将来插进哪个 seam（不改动其它模块） |
|---|---|---|
| 远程 subscription | 它是**纯附加**的产品功能，不在数据面也不在任何 seam 上。引入它需要 HTTP/TLS 信任面、重试与节点合并，与 0.9.0 要证明的东西（数据面正确性）无关 | 新增 `fluxd subscribe` 子命令：抓取 → 校验 → **原子替换 `config/sing-box.json`** → 走既有的 §10.5 engine 候选事务。`fluxd` 其它模块一行不改 |
| 热点 / tethering / LAN 下游代理 | 分类依据从"socket UID"变成"源 IP/MAC"，是一条**新的捕获入口**，但复用同一套 veth + assign 机制 | 新增第三个 entry `flx_cap_lan`，attach 在下游 interface 的 **ingress**（不是 egress），按源 CIDR/MAC 判定后走同一个 `handoff()`。`flux_control` 加一张源 LPM map。ABI magic 随之 bump |
| 被动入站 TCP（把手机当服务端） | 需要反向的 listener 归属与 NAT 语义，且不是"透明代理"这个产品的问题 | 无既有 seam。若真要做，属新产品线，不是升级 |
| 分片 UDP 的续传 | 极罕见（QUIC 置 DF 并做 PMTU；DNS 超 MTU 会退 TCP）。0.9.0 的处置是 **drop 而非泄漏**（§7.3），语义已经正确，只是可用性差一点 | 在 `flux_decision` 之外加一张 `{sk, ip_id} → 决策` 的小 map，只在首片命中时写入。热路径不受影响 |
| 多代理核心 / 多后端 | 一次 seam 失败换来长期双实现维护（§19） | 无 seam，且刻意如此 |
| WebUI / 自有 Clash 代理层 | sing-box 自带 Clash API 与 `observability`，重复造一层只增加攻击面 | 用户直接连 sing-box 的 `clash_api` |
| 管理器 App | 控制协议已是版本化 JSON over SEQPACKET（§10.3），且命令幂等 | 加命令即可，协议不需要改造 |
| 16 KiB base page | 由固定 engine 资产的 `p_align` 决定，不是我们能选的（§3.8） | 官方资产达到 `p_align >= 0x4000` 后改 `engine.lock` 与一处 page-size 判定 |
| **TCX attach（6.6+）** | **基线内核 5.15 根本没有这个 API**，不是"以后再优化"。它能消除 §8.5.1 整类失败（netd 删 clsact 连带删我们的 filter），但只对 6.6+ 设备有效 | 在 §12.5 的 attach 层加一个分支：探测到 `BPF_LINK_CREATE` 支持 `BPF_TCX_INGRESS`/`BPF_TCX_EGRESS` 就用 link，否则回落 clsact filter。所有权谓词相应换成 link id。三个 BPF 程序与全部 map **一行不改** |

## 22.3 刻意不做，且将来也不做

nftables/iptables 后端、TUN 后端、cgroup attach、SOCKMAP/FD handoff、机型 catalog、eBPF 内域名/规则集、在线学习、flush 系统防火墙链、写全局安全 sysctl、替用户关 Private DNS。理由分散在 §1.3、§3、§19，都不是"暂时不做"。

**`bpf_redirect_peer` 也属于这一类，且更彻底：它不是"我们选择不做"，而是不存在的选项。** 它要求 TC ingress **且**目标设备在不同 netns，本设计是 egress 侧 + 同 netns，两条都不满足（§19）。它一度被我记为延期优化，那是错的。

## 22.4 这一节的判据

一个延期项合格，当且仅当满足全部三条：① 它不在任何 packet 热路径上，或它在热路径上但只新增一个独立分支；② 它插入的 seam 在 0.9.0 里**已经存在且已被使用**（不是为它预留的空抽象）；③ 加入它不需要修改 `flux_abi.h` 之外的任何既有不变量（若需要改 ABI，则必须 bump `FLUX_ABI_MAGIC`，这是允许的）。

**不满足这三条的东西必须现在就做完，或者永久放弃。** §22.2 里"热点代理"是唯一需要改 ABI 的项，已在表中标明。

---

# 第 23 部分：失败矩阵

每一个可能失败的点，逐一写出**怎么检测、做什么、用户看到什么**。规则：任何一行的"动作"列都不允许出现"记录后继续"这种含糊说法（§15.4(1) 状态诚实性）。

## 23.1 启动期（尚未 active，全程 Direct）

| 失败点 | 检测 | 动作 | 用户可见 |
|---|---|---|---|
| 第二个实例 | `flock(LOCK_EX\|LOCK_NB)` 失败 | 立即 `exit(1)`，**不碰任何对象、不 unlink socket** | 第二次调用报"already running" |
| page size ≠ 4096 | `sysconf(_SC_PAGESIZE)` | 停在 `Inactive`，**不启动 engine、不建任何对象** | `status.last_error = "unsupported_page_size:16384"` |
| netns 不是初始 netns | `/proc/self/ns/net` 与 `/proc/1/ns/net` 的 inode 比对 | `Inactive` | `"netns_mismatch"` |
| 运行目录权限不对 | `fstatat` 检查 mode/uid | `Inactive`，**不自动 chmod**（可能是用户刻意改的） | `"runtime_dir_mode:0755 expected 0700"` |
| `all.rp_filter != 0` | 读 `/proc/sys/...` | `Inactive`（§8.4，**不写全局 sysctl**） | `"rp_filter_conflict:all=1"` + 人工处置说明 |
| veth 同名对象存在但 alias 不符 | `RTM_GETLINK` + `IFLA_IFALIAS` | `Inactive`，**绝不删除他人对象** | `"veth_conflict:flxrs0 alias mismatch"` |
| MTU 65535 被拒 | `RTM_NEWLINK` 的 ACK | `Inactive`，**不降级猜小值** | `"veth_mtu_rejected"` |
| RPDB priority 100 已被占用 | `RTM_GETRULE` dump | `Inactive`，**不换动态值**（cleanup 必须可证明） | `"rule_conflict:priority 100 occupied"` |
| table 20260 已有未知路由 | `RTM_GETROUTE` dump 且 `rtm_protocol != 202` | `Inactive` | `"route_table_conflict:20260"` |
| BTF 加载失败 | `BPF_BTF_LOAD` errno | `Inactive` | `"btf_load:EINVAL"` |
| SK_STORAGE map 创建失败 | `BPF_MAP_CREATE` errno | `Inactive` | `"map_create:tcp_decision:EINVAL"` |
| program verifier 拒绝 | `BPF_PROG_LOAD` errno | `Inactive`，**把 verifier log 前 N 行写进日志与 status**（§12.7 第 11 条） | `"prog_load:flx_cap_l2:EACCES"` + log 摘要 |
| BPF load/attach 被 SELinux 拒 | `EPERM`/`EACCES` | `Inactive`，**不注入 sepolicy**（§1.3 非目标） | `"bpf_denied:check root manager policy"` |
| `packages.list` 不可读 | `open` errno | 保持当前策略；冷启动则 `Inactive` | `"packages_list:EACCES"` |
| 配置里的 package 不存在 | 解析后查表 miss | 整个候选配置失败，**不部分应用** | `"unknown_package:0:com.foo"` |
| `appId` 越界 | 范围检查 | 同上 | `"app_id_out_of_range:1000"` |
| `sing-box check` 失败 | 子进程退出码 + stderr | 冷启动 `Inactive`；热更新保留当前 generation | `"engine_check_failed"` + stderr 前若干行 |
| engine 起不来 | pidfd 立即可读 | backoff 重试（1/2/4/8/30 s） | `"engine_exited:code=1"` |
| 4 个 socket 未在 deadline 内出现 | SOCK_DIAG 退避重查超时 | 停止 candidate，`Inactive` | `"engine_not_ready:2/4 sockets"` |
| socket inode 与 candidate pid 不符 | `/proc/<pid>/fd` 交叉核验 | 停止 candidate，`Inactive` | `"engine_socket_owner_mismatch"` |
| `clsact` 带 shared block | dump 见 `TCA_INGRESS_BLOCK`/`EGRESS_BLOCK` | **排除该 interface**，其余继续 | 该 interface `excluded(clsact_shared_block)` |
| pref 1 被未知 filter 占用 | dump + §8.5 谓词 | 排除该 interface | `excluded(tc_pref_occupied)` |
| Flux filter 不是 first-applicable | dump **顺序** | 排除该 interface | `excluded(not_first_applicable)` |
| candidate interface 超过 64 | 计数 | **整个新 topology 不 promote**，保持当前/Direct，不按名字截断 | `"too_many_interfaces:71"` |

## 23.2 运行期（已 active）

| 失败点 | 检测 | 动作 | 数据面后果 |
|---|---|---|---|
| engine 进程退出 | pidfd 可读 | publish `active=0` → backoff 重启 → 新 generation | 新流 Direct（listener lookup miss）；已入场 TCP drop |
| engine 单个 listener 关闭（进程还活着） | BPF `fault_events` 的 `EGRESS_LISTENER` | publish `active=0` → 重启整个 generation | 同上。**这是 fault ringbuf 存在的唯一理由** |
| engine event-loop 活锁（listener 在、进程在） | **不可检测**（§2.2.3(3)） | 无 | 该期间新流仍被捕获并卡住。**已公开的残余风险** |
| ingress `bpf_sk_assign` 反复失败 | `counters[IN_DROP_ASSIGN] > 0` 且 `admit_* > 0` | `status` 给出**具体假设**："engine listener may have SO_REUSEPORT — kernels < 6.5 reject assign（§9.2）" | 已入场流 drop |
| **netd 删掉某物理 interface 的 `clsact`**（连带删掉我们的 egress filter） | `RTM_DELQDISC` / `RTM_DELTFILTER` | **不动 `active`**：debounce 后在该 interface 重建 clsact + 重挂 filter | **日常事件**，每次 Wi-Fi 重连 / 蜂窝切换 / netd 重启都会发生（§8.5.1）。窗口内**仅该 interface** 上的选中流量走 Direct |
| 自有**核心**对象（`flxrs0/1`、ingress filter、rule、local route）被外力删除 | rtnetlink 事件 + 按需 dump | 先 publish `active=0`，再按 §8.5 谓词重新收敛 | 收敛期间新流 Direct |
| 未知对象抢占了我们的 identity | dump 比对失败 | 保持 `Inactive` 并报告，**不覆盖、不删除** | Direct |
| interface 消失 | `RTM_DELLINK` | 内核已连带删除其 filter；从 active 集移除 | 该 interface 上的流回 Android 路径（§2.2.3(1)） |
| interface 出现 | `RTM_NEWLINK` + admission | debounce 后 attach | 窗口内 Direct（§2.2.3(5)） |
| netlink socket 溢出 | `ENOBUFS` / `NLMSG_OVERRUN` | **丢弃批次，全量重新 dump**（§10.4.1 第 2 条） | 无（控制面内部） |
| map 更新失败（策略热更新中） | `bpf_map_update_elem` errno | 记录错误并**重新入队一次完整收敛**，不做快照回滚（§10.5） | 窗口内新流看到混合策略（良性） |
| UID entry 超限（512） | 计数 | 热更新被拒，保持当前策略 | 无变化 |
| LPM 超限（128，含本机地址） | 计数 | **拒绝激活并报告**，不静默丢弃 | Direct |
| 控制 socket 收到非 root 请求 | `SO_PEERCRED.uid != 0` | 关闭连接 | 客户端 EOF |
| 控制请求超过 64 KiB | 读取长度 | 关闭连接 | 同上 |
| decision storage 分配失败 | `bpf_sk_storage_get` 两次都 NULL | 当前包 `TC_ACT_UNSPEC`（无粘性） | 该 SYN 直连；后续 SYN 可重新决策（§2.2.1 末条） |
| `flux_decision.magic` 或 `reserved` 损坏 | 每次读取时校验 | `TC_ACT_SHOT` + `counters[DROP_CORRUPT]` | 该 socket 后续包全 drop（不泄漏） |
| control snapshot ABI magic 不符 | 每次 `ctrl()` 校验 | egress: 已入场 SHOT / 未入场 UNSPEC；ingress: SHOT | 见 §2.2 |
| 内核 < 6.5 上 assign 了刚被 unhash 的 listener | **不可检测** | 无 | 泄漏一次 socket 引用。窗口被 §9.4 的顺序压到"engine 崩溃 → pidfd 唤醒"之间的数百微秒。**已知并接受**（§9.2） |

## 23.3 停止与崩溃

| 场景 | 行为 | 遗留 |
|---|---|---|
| `fluxd stop` | publish `active=0` → `SIGTERM` engine → 短 deadline → `SIGKILL` → pidfd 确认 → 正常退出(0) | veth/BPF/TC 对象**保留**（下次启动删除重建）；service.sh 因退出码 0 不重启 |
| `fluxd disable` | 同上但 daemon 继续运行等命令 | 同上 |
| `SIGTERM` / `SIGINT` | 同 `stop` | 同上 |
| `fluxd` 被 `SIGKILL` | engine 因 `PDEATHSIG=SIGKILL` 被内核终止 → listener 消失 → **新流因 listener lookup miss 而 Direct**；已入场 TCP 的包 redirect 后在 ingress drop | TC filter + veth + rule + route 全部残留。**这是 fail-open 的关键路径**：残留的 capture 程序不会形成黑洞，因为它每次都要先查 listener |
| `service.sh` 重启 fluxd | §8.7 步骤 2 删除全部精确自有残留后重建 | 归零 |
| 设备重启 | 全部非持久内核对象自然消失 | 无 |
| 模块卸载 | `uninstall.sh` 同步请求 `fluxd stop`，然后只删 `/data/adb/flux-rs` | 内核对象等重启清除；**不 flush 任何系统对象** |

**一条贯穿全表的不变量**：`status` 报告"已清理 / Inactive / 无残留"之前，必须有一次**新的实际枚举**（TC dump、`RTM_GETRULE`、`RTM_GETROUTE`、`BPF_OBJ_GET_INFO_BY_FD`）证明对象确实不在。无法证明时报 `unknown(cleanup_required)` 并附第一个具体错误。

---

# 第 24 部分：`status` 输出与错误码规格

`status` 是这个产品唯一的诊断出口（没有 WebUI、没有周期日志、没有 telemetry）。它必须足以回答"为什么没生效"，否则 §14.2 的"零可观测性"缺陷就回来了。

## 24.1 字段规格

```jsonc
{
  "ok": true,
  "version": "0.9.0",
  "abi_magic": "0xF10C0901",
  "state": "Disabled" | "Inactive" | "Active",
  "generation": 7,
  "engine": {
    "running": true, "pid": 1234,
    "sockets_verified": 4,            // 期望 4；少于 4 说明 readiness 未闭环
    "effective_config": "run/effective-sing-box.7.json"
  },
  "policy": {
    "selected": 3, "draining": 1,
    "bypass_v4": 12, "bypass_v6": 6,  // 含固定项与本机地址项
    "self_addresses": 4               // 动态注入的本机地址条目数
  },
  "ifaces": [
    { "name": "wlan0", "ifindex": 24, "arphrd": "ether",
      "entry": "flx_cap_l2", "status": "active",
      "prog_id": 118, "prog_tag": "a1b2c3d4e5f60718", "first_applicable": true },
    { "name": "rmnet_data0", "ifindex": 30, "arphrd": "rawip",
      "entry": "flx_cap_l3", "status": "active", "…": null },
    { "name": "v4-rmnet_data0", "ifindex": 31, "arphrd": "none",
      "status": "excluded", "reason": "clat_order_unverified" }
  ],
  "counters": {                        // §6.1 的 PERCPU_ARRAY 求和
    "admit_tcp": 41, "direct_tcp": 190, "admit_udp": 388,
    "drop_inactive": 0, "drop_stale_gen": 0, "drop_handoff": 0,
    "drop_udp_frag": 0, "drop_corrupt": 0, "decision_alloc_fail": 0,
    "egress_listener_miss": 2,
    "in_assign_tcp": 41, "in_assign_udp": 388,
    "in_pass_established": 5120, "in_pass_fragment": 0,
    "in_drop_no_listener": 0, "in_drop_assign": 0,
    "in_drop_parse": 0, "in_drop_snapshot": 0
  },
  "sysctl": { "all.rp_filter": 0, "flxrs1.rp_filter": 0, "flxrs1.accept_local": 1 },
  "warnings": [ /* 见 24.3 */ ],
  "hints":    [ /* 见 24.4 */ ],
  "last_error": null
}
```

## 24.2 错误码命名规则

`last_error` 与 `ifaces[].reason` 一律用 `snake_case` 的**稳定标识符**，可选 `:` 后跟具体值。**禁止**把自由文本放进这两个字段（自由文本进 `warnings`）。已定义的集合就是 §23 两张表里出现的那些值；新增必须同时更新 §23。

分四类前缀便于分流：

| 前缀 | 含义 | 例 |
|---|---|---|
| `unsupported_*` | 设备能力不足，重试无用 | `unsupported_page_size:16384` |
| `*_conflict` | 有他人对象占位，需人工介入 | `rule_conflict:priority 100 occupied` |
| `*_failed` / `<syscall>:<errno>` | 操作失败，可能可重试 | `prog_load:flx_cap_l2:EACCES` |
| `excluded(<reason>)` | 单个 interface 被排除，其余仍工作 | `excluded(not_first_applicable)` |

## 24.3 必须产生的 warning

| 条件 | warning |
|---|---|
| 选中的包声明了 `BIND_VPN_SERVICE`（best-effort 检测） | `"0:com.foo declares BIND_VPN_SERVICE; its outer socket will be captured"` |
| 选中的 UID 有其它 shared-UID 兄弟包 | `"uid 10231 also covers: com.bar, com.baz"` |
| 用户 JSON 缺少 :53 处理 | `"no hijack-dns rule; selected apps' DNS will be forwarded verbatim and domain rules will not apply"`（§1.3.4） |
| 系统 Private DNS 非 `off` | `"system private DNS is on; name resolution bypasses Flux"`（§1.3.3 边界①） |
| 捕获到的 :53 流量 `sk_uid == 1051` | `"enforce_dns_uid appears enabled; system DNS is not per-app attributable on this device"`（边界②） |
| 用户设了 outbound `routing_mark` / `bind_interface` | `"user-set outbound routing_mark/bind_interface: Android network consequences are yours"` |
| `clsact` 非我创建 | `"clsact on wlan0 pre-existed; it will never be deleted by Flux"` |

## 24.4 必须产生的 hint（把 counter 组合翻译成假设）

零观测性的反面不是"打印更多数字"，而是**替用户做第一层推理**：

| counter 组合 | hint |
|---|---|
| `admit_* > 0` 且 `in_drop_assign > 0` | `"assign is failing; if this is 100% the engine listener may have SO_REUSEPORT (kernels < 6.5 reject it)"` |
| `admit_* > 0` 且 `in_drop_no_listener > 0` | `"packets reached the veth but no listener was found; engine may be restarting"` |
| `egress_listener_miss > 0` 且 `admit_* == 0` | `"nothing is being captured because the engine listener is absent"` |
| `direct_tcp > 0` 且 `admit_tcp == 0` | `"selected UIDs are matching but every first SYN chose DIRECT; check bypass_cidrs and active"` |
| 全部 counter 为 0 且 `state == Active` | `"no selected traffic observed; verify the app list resolves to the UIDs you expect"` |
| `drop_udp_frag > 0` | `"fragmented UDP from selected apps is dropped by design (§7.3); large DNS/QUIC payloads may fail"` |
| `in_pass_established` 远大于 `in_assign_tcp` | 正常（每条连接一次 assign、多次 pass）。**不产生 hint**，此行只为避免误报 |

---

# 第 25 部分：启动时序与边界条件

`service.sh` 在 late_start 触发，此时 Android 还没准备好。这一节把每个"太早"的情况写清楚，因为它们全都会在真机首次开机时命中。

| 时点问题 | 表现 | 处置 |
|---|---|---|
| `/data` 尚未解密（FBE，用户未解锁） | `/data/adb/flux-rs` 可访问（`/data/adb` 属 device-encrypted），但**用户配置若放在 credential-encrypted 区会读不到** | 状态根固定在 `/data/adb/flux-rs`（DE 区），因此不受影响。**禁止**把配置放到 `/data/user/0/...` |
| 网络还没起来 | 没有任何候选 interface | 正常进入 `Inactive`，等 rtnetlink 事件。**不是错误**，`last_error` 保持 null，`ifaces` 为空数组 |
| `packages.list` 还没写出 | 首次开机极早期可能缺失 | 保持 `Inactive` + `packages_list:ENOENT`；inotify 监视其 **parent 目录**（文件是原子替换，只监视文件会丢事件） |
| `sys.boot_completed` 未置位 | 与我们无关——§11.3 已消除对 binder / `cmd package` 的依赖 | 无需等待。**这是 D8 的主要收益** |
| SELinux 还在 permissive→enforcing 过渡 | BPF load 可能先成功后失败（或反之） | 不做特殊处理；失败即 `Inactive`，rtnetlink/inotify 事件会触发重试 |
| engine binary 的 `PT_LOAD` 校验 | 不在运行期做（xtask 打包时已校验） | 运行期只查 page size |
| 时钟未同步 | 只影响日志时间戳 | 不用 wall-clock 做任何判定（generation 是单调计数器，不是时间） |
| 反复重启（crash loop） | backoff 1/2/4/8/30 s；child 稳定 60 s 后复位 | **不设"失败 N 次永久锁死"**：只要 `enabled` 为真就持续低频恢复。`status` 暴露 `backoff_seconds` 便于人工判断 |

**冷启动的正确姿态是"能做多少做多少，剩下等事件"**：page size 与 netns 检查失败是终局（不重试有意义），其它一切失败都只是当前收敛周期的结果，下一个 rtnetlink / inotify / timerfd 事件会重新收敛。

---

# 第 26 部分：reactor 状态机

三个顶层状态（§10.1）× 事件 → 动作。这张表是实现 `reactor.rs` 的直接依据；**表里没有的组合就是不该发生的组合**，遇到应记录并忽略，不得自行发明处理。

| 事件 | `Disabled` | `Inactive` | `Active` |
|---|---|---|---|
| 启动完成（bootstrap） | 停在 Disabled | 尝试完整激活序列（§8.7） | — |
| `enable` | 写 `enabled=1` → 尝试激活 | 幂等，无操作 | 幂等，无操作 |
| `disable` | 幂等 | 写 `enabled=0` → 停 engine → Disabled | publish `active=0` → 停 engine → 写 `enabled=0` → Disabled |
| `reload` | 只重新校验配置，报告结果 | 重新尝试激活 | policy 域：§10.5 的加减法（**不动 `active`**）；engine 域：§9.4 的候选切换 |
| `stop` | 正常退出(0) | publish `active=0` → 停 engine → 退出(0) | 同 Inactive |
| `status` / `check` | 只读 | 只读 | 只读 |
| rtnetlink：新 interface | 忽略 | 重新评估 admission，若已就绪则激活 | debounce → admission → attach（失败只排除该 interface） |
| rtnetlink：interface 消失 | 忽略 | 更新候选集 | 从 active 集移除；若归零则 → Inactive |
| rtnetlink：地址变化 | 忽略 | 更新期望 bypass 集 | 更新本机地址 bypass（加减法，不动 `active`） |
| rtnetlink：**捕获侧**漂移（某物理 interface 的 `clsact` 或我们的 egress filter 被删） | 忽略 | 重新收敛 | **不动 `active`**：debounce → 在该 interface 上重建 clsact（若需）+ 重挂 egress filter。失败只把该 interface 移出 active 集 |
| rtnetlink：**核心**漂移（`flxrs0/1`、ingress filter、rule、local 路由被删或改） | 忽略 | 重新收敛 | **先 publish `active=0`** → 按谓词重新收敛 → 成功则 `active=1` |
| rtnetlink：`ENOBUFS`/overrun | 忽略 | 全量重 dump | 全量重 dump（§10.4.1 第 2 条） |
| inotify：`flux.toml` 变 | 只更新校验结果 | 重新尝试激活 | policy 事务（加减法） |
| inotify：`sing-box.json` 变 | 只更新校验结果 | 重新尝试激活 | engine 候选切换 |
| inotify：`packages.list` 变 | 忽略 | 重新解析 | 重新解析 → policy 事务 |
| pidfd：engine 退出 | 不应发生 | 记录 → backoff 重启 | publish `active=0` → backoff 重启 → 新 generation |
| ringbuf：current-gen fault | 不应发生 | 清 latch | publish `active=0` → 重启 generation |
| ringbuf：旧 gen / 重复 fault | 忽略 | 忽略 | **只清 latch，忽略**（handler 按 generation 幂等） |
| timerfd：debounce 到期 | — | 执行待处理的收敛 | 同 |
| timerfd：backoff 到期 | — | 重试激活 | 重试 engine 启动 |
| timerfd：readiness 退避 | — | 重查 SOCK_DIAG | 同 |
| `SIGHUP` | 等价 `reload` | 等价 `reload` | 等价 `reload` |
| `SIGTERM`/`SIGINT` | 退出(0) | publish `active=0` → 停 engine → 退出(0) | 同 |

**四条不变量**：

1. **进入 `Active` 的唯一途径**是 §8.7 步骤 10 的那一次 `control_root` pointer swap；**离开 `Active` 的第一个动作**永远是 publish `active=0`。中间没有其它路径。
2. **policy 事务不改变顶层状态**（§10.5，D5）。只有 engine generation 切换、**核心**拓扑漂移、engine 退出才会离开 `Active`。
3. **事务期间到达的事件不丢弃、不递归**：记入待处理集合，当前事务结束后由一次收敛统一消化。禁止在事务内部重入 reactor。
4. **捕获侧漂移必须局部处理，禁止升级为全局事务。** 上表把捕获侧与核心漂移分成两行，理由见 §8.5.1：netd 在每次 interface 加入/离开网络时删 `clsact`，system_server 崩溃后 netd 重启还会清空**所有** interface 的 clsact。如果对这类事件也走"publish `active=0` → 重收敛 → `active=1`"，那么**每一次 Wi-Fi 重连都会让全设备的代理流量瞬断一次**。正确处置是只重挂那个 interface 上的 filter，`active` 全程不动，其它 interface 不受影响。这是本状态机里最容易写错、代价也最直观的一处。

---

- 文档结束。字段与不变量以本文为实现合同。
- ABI 真相源：`reference/flux_abi.h`；数据面骨架：`reference/flux.bpf.c`。
- 一手依据索引见同目录 `README.md`。
