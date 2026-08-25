# 被拒方案、延期项与待确认事项

> 原 blueprint.md 第 19、21、22 部分。**章节编号未变**：本文里的 §N.x 就是全仓库引用的那个 §N.x（见 `docs/authoring.md` §1.1）。
>
> 谁读这份：有人提议「为什么不做 X」时，来查 X 是否已被评估过。规范性合同仍是 `docs/blueprint.md`。

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

# 第 21 部分：需要项目所有者确认的事项

确认本蓝图等于确认以下六条：

1. 0.9.0 采用 **TC egress → 专用 veth → TC ingress `bpf_sk_assign` → 官方 sing-box TProxy** 作为唯一候选，并先做非破坏性 Phase 0。
2. fail-open 仅覆盖可检测的 redirect 前、未入场的新 TCP / 当前 UDP；越过 admission 后的内部失败允许 drop/reset；engine event-loop 活锁不自动识别；fragment / 未知 layout / Android 改路由到未 attach 的 interface 完全回到 Android 路径。
3. actual listener 的 synthetic tuple **不是** owner proof；0.9.0 不抵抗恶意本地进程在 listener 关闭竞态中用 `IP_FREEBIND` 抢绑；随机端口与 PID/inode 核验只降低非对抗碰撞。
4. 自动恢复是 event-driven 且无周期探测：进程退出、network/config/package 变化立即处理，部分 listener 故障在下一个相关 packet 触发自愈；完全无流量时的内部故障与 event-loop 活锁不可见。
5. 官方 sing-box 资产只有 4 KiB LOAD 对齐，因此 0.9.0 只支持 4 KiB base-page 设备；不重编上游，不以 app 兼容模式冒充原生 16 KiB 支持。
6. Phase 0 通过后**仍需第二次明确授权**才执行 §18 的清理重建。

## 21.1 确认项：全部已关闭（2026-08-25 定稿）

**本节不再有待确认事项。** 保留原表作为记录，并在末尾补上定稿轮的六条。

编号用 `C`（confirmation）而不是 `Q`，是为了和 §16 的 Phase 0 证伪问题 `Q1–Q10` 区分开——两套编号此前共用 `Q` 前缀，引用时会歧义。

| # | 问题 | 结论 |
|---|---|---|
| **C1** | 仓库策略 | 删除 `.git` 并重新 `git init`。**已执行**，新历史始于 `fe77bc7`；旧仓库归档在工作区之外 |
| **C2** | 系统 DNS 处理 | 精准 per-app 捕获，零额外机制（D18）。`fchown` 已把归属放进 `sk_uid`。残余边界只有 Private DNS / `enforce_dns_uid` / mDNS 三条 |
| **C3** | 内核基线 | `5.15`。首发 Android 12 设备不在支持范围 |
| **C4** | Phase 0 设备 | SM-S9180（Android 16 / **5.15.211** / KernelSU）。它恰好就是基线内核，且实测发现**Android 版本与内核版本解耦**（升级机型），这本身成了 §16.3.5 的关键论据 |
| **C5** | 控制协议编码 | SEQPACKET 上的单行 JSON。**同时确认它就是给未来 UI 预留的接口**，`fluxd` CLI 只是第一个客户端 |
| **C6** | 文档语言 | 中文为主、专有名词保留英文（`authoring.md` §6）。文档已按读者拆分（`docs/README.md`） |
| **C7** | **是否给 sing-box 打补丁** | **不打**（D19）。永久使用官方未修改二进制 |
| **C8** | WebUI | **搁置**。协议已预留，将来做是纯增量 |
| **C9** | 开关机制 | **`disable` 文件 + inotify**，无 `action.sh` 按钮 |
| **C10** | 代理控制面 | **clash_api + zashboard**，UI 下载归 sing-box |
| **C11** | 订阅 | **做转换**（URI 列表 → outbound，落在 `flux-core`），不做跨配置格式翻译 |
| **C12** | 诊断包是否含 `logcat` | **默认不含**，`--with-logcat` 显式开启并警告。理由：`logcat -b all` 含通知内容、Wi-Fi BSSID（可定位）、蜂窝小区、账号名、其它应用自己打的日志，且**无法脱敏**——那是几千个应用产生的无结构文本。Android 自己把 `READ_LOGS` 定为 signature 级权限正是因为这个 |

### 定稿状态

**设计已定稿。** 本蓝图与 `docs/` 下各文件构成实现合同。

- Phase 0 的**观测半场**已完成（§16.2），**Q10 已通过**（§16.5.4），**Q1–Q9 待做且已授权**，工具链无障碍（WSL 编 BPF → `adb push` → 设备 `bpftool`）。
- 已无任何已知的、能推翻主路线的技术未知项。
- 清库重建**已执行**，不再需要第二次授权。

仍然成立的约束：Phase 0 断言失败若需要改全局系统语义或放弃某类设备，属**范围变更**，回 `governance.md` §1.2 找所有者。

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
| **TCX attach（6.6+）** | 见下方专门说明——它现在是**优先级最高的延期项**，因为它同时消灭两整类失败 | 在 §12.5 的 attach 层加一个分支：探测到 `BPF_LINK_CREATE` 支持 `BPF_TCX_INGRESS`/`BPF_TCX_EGRESS` 就用 link，否则回落 clsact filter。所有权谓词换成 link id。四个 BPF 程序与全部 map **一行不改** |

### 22.2.1 为什么 TCX 是延期项里唯一值得优先做的

2026-08-25 的实测把 TCX 的价值从"少一类运维噪音"提升到"消灭两整类失败"：

| 它消灭的失败类 | 在 clsact 上的表现 |
|---|---|
| **netd 删 qdisc 连带删我们的 filter**（§8.5.1） | 每次 Wi-Fi 重连 / 蜂窝切换 / netd 重启都发生，需要 §26 不变量 4 那套局部重挂逻辑 |
| **厂商占据更低的 pref 把我们挡在 chain 之外**（§8.5.3） | tc 的 pref 最小是 1，被占了就**无法排到前面**，只能靠 §8.5.4 检测出来然后放弃该 interface |

TCX 是**独立的 attach 点**，不挂在 qdisc 上，所以 `tcQdiscDelDevClsact` 碰不到它；而且它用 `BPF_F_BEFORE` / `BPF_F_AFTER` 相对**现有条目**定位，legacy clsact 整体在这套序列里只算一个条目——也就是说在 6.6+ 上我们**可以排到厂商 clsact filter 之前**，§8.5.3 的整个困境直接消失。

**但它不能替代 5.15 上的方案**，理由是 §16.3.5 那条实测事实：本机是 **Android 16 跑 5.15 内核**。内核版本不跟随系统版本，升级机型会长期停在 5.10/5.15/6.1。所以：

- clsact 路径 + §8.5.3 动态选 pref + §8.5.4 存活验证是**必须实现的主路径**，不是兜底。
- TCX 是**能力探测后的优选路径**，只在 6.6+ 上生效，且**探测方式是尝试 `BPF_LINK_CREATE` 是否成功，不是读 `uname -r`**（§16.3.5）。
- 两条路径共用同一批程序与 map，差异只在 attach 层与所有权谓词。§8.5.4 的存活验证**两条路径都要跑**——TCX 也可能被别人抢先。

**实现 TCX 分支时必须比唯一的先例做得更好。** chizi 是语料里唯一用了 TCX 的项目，但它的 `link.AttachTCX` 调用**不带任何 `BPF_F_BEFORE` / `BPF_F_AFTER` anchor**（`shared_network_tcx.go:91-95`，实测无 anchor 参数）。不带 anchor 就是"追加到末尾"，那正好放弃了 TCX 唯一比 clsact 强的地方——**相对定位**。我们做 TCX 的**全部理由**就是要排到厂商前面，所以：

- attach 时**必须**带 `BPF_F_BEFORE`，anchor 指向现有条目（legacy clsact 整体算一个条目）。
- 若内核拒绝该 anchor 组合，**回落到 clsact 路径**，不要退化成"无序追加的 TCX"——那既没有 clsact 路径的 pref 可选性，又没有 TCX 的定位能力，是两头落空。
- 返回值**一行不用改**：chizi 的注释证明 `TC_ACT_UNSPEC` 在 TCX 上同样是唯一能让链继续的值，`TC_ACT_PIPE` 会截断 TCX 程序数组（§0.5.10(a)）。

## 22.3 刻意不做，且将来也不做

nftables/iptables 后端、TUN 后端、cgroup attach、SOCKMAP/FD handoff、机型 catalog、eBPF 内域名/规则集、在线学习、flush 系统防火墙链、写全局安全 sysctl、替用户关 Private DNS。理由分散在 §1.3、§3、§19，都不是"暂时不做"。

**`bpf_redirect_peer` 也属于这一类，且更彻底：它不是"我们选择不做"，而是不存在的选项。** 它要求 TC ingress **且**目标设备在不同 netns，本设计是 egress 侧 + 同 netns，两条都不满足（§19）。它一度被我记为延期优化，那是错的。

## 22.4 这一节的判据

一个延期项合格，当且仅当满足全部三条：① 它不在任何 packet 热路径上，或它在热路径上但只新增一个独立分支；② 它插入的 seam 在 0.9.0 里**已经存在且已被使用**（不是为它预留的空抽象）；③ 加入它不需要修改 `flux_abi.h` 之外的任何既有不变量（若需要改 ABI，则必须 bump `FLUX_ABI_MAGIC`，这是允许的）。

**不满足这三条的东西必须现在就做完，或者永久放弃。** §22.2 里"热点代理"是唯一需要改 ABI 的项，已在表中标明。

---

