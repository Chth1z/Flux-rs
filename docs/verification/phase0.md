# Phase 0：编码之前的最小证伪

> 原 blueprint.md 第 16 部分。**章节编号未变**：本文里的 §N.x 就是全仓库引用的那个 §N.x（见 `docs/authoring.md` §1.1）。
>
> 谁读这份：要上机跑测试的人；以及想知道某台设备实测出了什么的人。规范性合同仍是 `docs/blueprint.md`。

---

# 第 16 部分：Phase 0 —— 编码与清库之前的最小证伪

Phase 0 在临时目录（`/tmp` 或独立 worktree）完成，只含一个最小 BPF C、一个小 loader、一份 netns 脚本与官方 sing-box。**不预建 Flux 框架，产物不进最终仓库。**

先在 Linux 主机的 network namespace 里跑 Q1–Q5（**必须是 5.15 内核**，与产品基线一致），再在一台可恢复的目标 Android 设备上跑 Q6–Q10。**Q10 只能在真机上做**，因为它要验证的是厂商 filter 的行为。

## 16.1 十个必答问题

**Q1 — SK_STORAGE first-decision**
在 TC egress 中对 `bpf_sk_fullsock(skb->sk)` 执行 `bpf_sk_storage_get(..., &initial, F_CREATE)`：verifier 是否接受？并发 SYN 是否由 `BPF_NOEXIST` 语义产生唯一 winner、loser 在 `CREATE` 返回 NULL 后能用只读重查稳定读回同一 winner？两种 state 是否在后续 egress 保持不变、并随 socket 关闭释放（无容量驱逐）？
*断言*：并发 100 条 connect，每个 socket 的 decision 恒定；`grep` 内核内存不增长；socket close 后 storage 计数回落。

**Q2 — listener 身份、assign 与共绑**
官方 sing-box `1.13.19` 以 `type:tproxy`、`listen:198.51.100.1`/`2001:db8:0:1::2` 启动后（地址按 D21 已移出 fakeip 惯用段）：4 个 socket 是否出现且 `SOCK_DIAG` inode 能与 `/proc/<pid>/fd` 交叉核验？`bpf_sk_lookup_tcp/udp` 返回的 `src_ip4/src_ip6/src_port/state/family` 是否与配置一致？`bpf_sk_assign()` 是否**成功**（即 sing-box 的 listener 确实没有 `SO_REUSEPORT`，否则会 `-ESOCKTNOSUPPORT`）？
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
6. **路由前置条件的最小集**：分别以 `all.rp_filter = 0/1`、`flxrs1.accept_local = 0/1`、**`ip_forward = 0/1`**、`arp_filter` 默认值跑矩阵，确定**真正必需的最小集**。§8.4 的预测是「需要 `flxrs1.rp_filter=0` + `accept_local=1` + `all.rp_filter=0`，不需要 `ip_forward`、不需要 `arp_filter`」；dae 三者都设了（`netns_utils.go:437-450`）。失败时**直接上 `pwru` + `kfree_skb_reason`**，不要猜（§8.4 有 dae 的原始 trace 可对照）。
7. **可达性与共存**：Flux 取到的 pref 之前没有终止 chain 的 classifier（用 §8.5.4 的存活验证判定，不靠 dump 推断）；`TC_ACT_UNSPEC` 之后后续 filter 的计数器仍在增长。

*断言*：大文件双向传输 checksum 正确；`all.rp_filter=1` 时确实 martian-source 丢包（证明 §8.4 的检查是必要的，不是多余的保守）；`ip_forward=0` 下端到端成功（否则触发 §21 的范围变更）；后续 filter 计数器有增长。

**Q6 — 真机网络分支**
一台目标 Android（内核 ≥ 5.15）上：Wi-Fi（ARPHRD_ETHER）、rmnet（ARPHRD_RAWIP）、可用时的 CLAT `v4-*` 是否都保留 UID 与原目的？VPN TUN 是否确实被排除？`/data/system/packages.list` 是否能精确解析 user/package/UID？**Android 的 `filter INPUT`（`bw_INPUT`/`fw_INPUT`）与 `nat/mangle PREROUTING` 是否放行我们注入到 `flxrs1` 的包？**
*断言*：三类接口各至少一条 TCP + 一条 UDP 端到端成功；`iptables -L -v -n` 显示无异常 drop 计数增长。

**AOSP 默认路径的风险已下调，但 OEM 路径的风险被新证据抬高了。**

下调依据：`clone/AndroidTProxyShell/tproxy.sh` 创建的链全部挂在 `mangle PREROUTING` / `mangle OUTPUT`，**从不碰 `filter INPUT`**（`tproxy.sh:968`），而它的本机路径确实要经过 INPUT（OUTPUT 打 mark → 策略路由送 `lo` → 重新入栈 → PREROUTING TPROXY → INPUT）。既然它无需在 INPUT 开口就能工作，**AOSP 默认的 `filter INPUT` 不会丢弃这类本地交付流量**。残余风险是接口差异：它的包 `iif = lo`，我们的包 `iif = flxrs1`，Android 可能存在 `-i lo` 的快捷放行。

> **2026-08-25 实测：这条残余风险已消除**（§16.9.1）。`filter INPUT` 的七条 target 全部是 `in *`，没有任何接口维度的分支，且七条的计数与 policy 计数逐字相同——所有输入包都完整走完全部链。`iif = lo` 与 `iif = flxrs1` 在 INPUT 里走的是**同一条路径**，不存在藏在 `-i lo` 后面的差异。下面第 1–3 条的实测清单**仍然要做**，因为它们答的是另一个问题："OEM 是否整体丢弃"，那要靠数据面在位后比对计数增长。

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

**若 Q9 的第 1 或 3 条不成立，D18 被证伪**：那说明该内核的 `sockfs_setattr` → `sk_uid` 链路或 AOSP 的 `fchown` 行为与源码不符。此时必须回到设计，重新在旧的"不捕获系统 DNS"与"全设备劫持 :53"之间选择，**不得**靠特判 :53 端口蒙过去。

**Q10 — 厂商 filter 在前时我们还会不会运行（阻塞项，2026-08-25 实测新增；✅ 已通过，见 §16.5.4）**

由 §8.5.3 的实测引出：三星在 `wlan0` egress 占据 `chain 0 / pref 1 / handle 0x1`，而 tc 的 priority 最小就是 1，所以我们只能排在它**后面**。而 `__tcf_classify` 一旦某个 filter 返回 `>= 0` 的动作就停止遍历——**如果厂商程序返回 `TC_ACT_OK` 或 `TC_ACT_PIPE`，我们的程序一个包都收不到，同时 attach 本身完全成功、没有任何错误。** 这是本设计目前最可能"装上了但什么都没发生"的失效模式。

1. 在 `wlan0` egress 的 **pref 2** 挂一个最小程序（只对每个包 `counters[0]++` 然后返回 `TC_ACT_UNSPEC`），产生已知流量，断言计数器**在涨**。
2. 若不涨：说明厂商 pref 1 终止了 chain。改测 pref 1 是否可抢（`NLM_F_EXCL` 应当 `EEXIST`；**不要**用 `NLM_F_REPLACE` 去顶掉厂商的）。此时要么该 interface 只能排除，要么整条 clsact 路线在三星设备上不可用，**属于范围变更，回 §21 征求确认**。
3. 在**蜂窝** interface 上重复：实测时 `rmnet_data0/1/8` 的 egress 是空的，pref 1 可用，但 `tosMarker_schedcls_egress_set_tos_mobile` 这个程序存在，说明它在某些条件下会挂上来。至少要确认"我们在 pref 2、厂商不在场"时计数器会涨。
4. 验证 §8.5.3 的竞态：我们先占 pref 2 并保持运行，然后触发 Wi-Fi 重连，观察三星的 attach 是否成功、我们的 filter 是否仍在、以及 `RTM_NEWTFILTER` 事件是否被 reactor 正确收到。
5. **由此固化一条激活步骤**：attach 之后、`publish active=1` 之前，必须用正向存活验证确认程序真的在跑（§8.5.3 约束 3）。这一步的实现方式也在本问中定稿。

*断言*：pref 2 上的计数器在真实流量下增长；`NLM_F_EXCL` 对已占用的 pref 返回 `EEXIST` 而非静默成功；厂商重新 attach 后我们的 filter 仍在且仍在计数。

## 16.2 观测半场的实测结果（SM-S9180 / Android 16 / 5.15.211-Qkernel，2026-08-25）

Phase 0 分两半：**观测半场**（只读，回答"设备实际是什么样"）与**证伪半场**（Q1–Q10，需要加载 BPF）。下表是观测半场的结果,全部通过 `adb shell su -c` 只读采集,未加载任何程序、未修改任何对象。

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

> **第二次复核(卸载旧模块、关闭 VPN、重启后)**:结论**完全一致**。全新启动、无 VPN、无 Flux 残留的干净状态下,cgroup attach 列表依然全空,而 8 个 `cgroup_sock_addr` 仍然已加载。这条更正**可复现,不是偶发**。

**(b) 厂商已经占了 egress pref 1——这是本轮最重要的发现,已导致 ABI 与激活流程改动。** 详见 **§8.5.3**。

第一轮采集时 `tc filter show` 在所有 interface 上都是空的,我据此写下"egress pref 1 在常态下是空闲的"。**第二轮推翻了它**:重启后主网变成 `wlan0`(ARPHRD_ETHER),三星的 `semUidBPF_schedcls_egress_tsm_ether` 占据了 `chain 0 / pref 1 / handle 0x1 / protocol all`——与 `flux_abi.h` 原先预定的四元组完全相同。

两轮结果不同的原因本身就是一个发现:**厂商的 attach 时刻不可预测**。第一轮 `wlan0` 处于 down(主网是蜂窝),第二轮 `wlan0` 成为主网。更关键的是第二轮内部也自相矛盾——探针第 6 节报"无 filter",而同一次运行第 10 节的 `bpftool net show` 报"已 attach";核对时间戳后确认程序在开机后 7 秒就由 bpfloader 加载(`loaded_at`),但**挂到 `wlan0` 上是在链路已带全局地址之后好几分钟**。`loaded_at` 与 attach 时刻是两件事。

因此:`FLUX_TC_PREF` 从固定常量改为 `FLUX_TC_PREF_PREFERRED`(2)/`_MIN`/`_CLAT_MAX` 三元组 + dump 后动态选取;激活流程新增"正向存活验证";Phase 0 新增 **Q10**。探针也已改为**采样两次**并显式用 clsact parent handle,否则会漏掉这类晚到的 attach。

### 16.2.3 蓝图完全没有预料到的

| 发现 | 影响 |
|---|---|
| **14 个 `epdg0..13` 接口,全部 `ARPHRD_NONE`**(VoWiFi/ePDG 隧道) | §3.3 的 admission 会逐个遍历并排除它们(既非 ETHER 也非 RAWIP,且不叫 `v4-*`)。行为正确,但**接口清单比预期长得多**(49 个),admission 的日志与 `status` 输出要能承受这个规模而不刷屏 |
| **`tun0` 处于 UP 且有 `uidrange 0-99999` 的 netd 规则**(netId 0x76) | 设备上**当前有 VPN 在跑**。按 §3.5,此时物理口上看到的是 VPN 的 outer socket,不是 app 的。**任何捕获测试在关掉 VPN 之前都不可信** |
| **Samsung 自有 BPF 规模远超 AOSP**:86 个 prog pin / 115 个 map pin,含 `mnxbNetd`、`netlog`(5 个 ringbuf)、`semSmartHS`、`semUidBPF`、`tcpAccECN`、**`tosMarker`(`tos_policy_mobile_map`)** | `tosMarker` 与 §2.2.3(6) 的 DSCP 边界直接相关:除 AOSP 的 `dscpPolicy` 外,三星还有自己的 ToS 标记路径。被代理流量丢失 app 级标记这条**影响面比蓝图写的更大** |
| **`qcom_qos_reset_POSTROUTING` 对本机源地址出向流量 `--set-xmark 0x0/0xffffffff`** | 高通 QoS 在 POSTROUTING **清空整个 fwmark**。我们不用 mark,所以无影响;但这条独立地证明了 §19 拒绝 mark 方案是对的——**在这台设备上 mark 根本活不到出口** |
| **`memlock` rlimit 仅 64 KB** | kernel ≥ 5.11 用 memcg 而非 memlock 记账 BPF 内存,所以 5.15 上不受限。但若将来回落到更老内核,16 KiB ringbuf + 12 张 map 会撞上这个上限。记录备查 |
| **`/system/bin/bpftool` 已存在**(v5.16.0 / libbpf v1.4) | Phase 0 证伪半场可以直接用它做 attach 验证与 map dump,不必自带工具 |
| **旧架构残留仍在设备上**:`/data/adb/flux`、`/sys/fs/bpf/flux/`(空目录)、以及**仍然安装着的 `flux` 模块** | 在 0.9.0 上机测试前**必须清理**,否则新旧模块会争同一批对象与目录 |
| `private_dns_mode = opportunistic` | D18 依赖的明文 DNS 路径在此模式下**确实存在**(机会性 DoT,失败回落明文)。但上游支持 DoT 时查询走 853 加密,那部分不在捕获范围内——与 §1.3 的残余边界一致 |

## 16.3 这份结果有多少能外推到别的手机

**产品面向的不是三星。** 一台设备的实测必须先分层,才能知道哪些结论可以当作普适事实写进设计、哪些只能当作"某一族设备的样本"。下面按**依据的来源**分层——层级越高,外推越可靠。

### 16.3.1 第 1 层：AOSP 源码强制,每台 Android 设备都一样

这些不是"在这台设备上观察到",而是"AOSP 的代码就这么写的,实测只是确认没被厂商改掉"。**可以直接当作设计前提。**

| 事实 | 依据 | 设计中的用处 |
|---|---|---|
| netd 的 `ip rule` 最低 priority = 10000,1–9999 空闲 | `RouteController.h:34` | §8.3 选 pref 100 |
| netd 路由表 = `1000 + ifindex` | `RouteController.h:100` | §8.3 选 table 20260 |
| fwmark 位布局(netId 0–15、16–20 netd 语义、31 wakeup) | `Fwmark.h:24-53` | §3.1 |
| netd 随 interface 加入/离开网络创建并删除 `clsact` | `RouteController.cpp:1201`、`NetworkController.cpp:152` | §8.5.1、§26 不变量 4 |
| AOSP 自身的 TC 优先级占用(ingress 1/2/3/4,egress 4/5) | `ConnectivityService.java`、`ClatCoordinator.java`、`DscpPolicyTracker.java` | §8.5.2 |
| CLAT 的 `v4-*` 是 `ARPHRD_NONE` | `ClatCoordinator.java:471` 自述 | §3.3.1 |
| `packages.list` 10 字段、`uid = userId*100000 + appId` | AOSP | D8 |
| DnsResolver 用 `fchown` 把 DNS socket 归属改回 app | `res_send.cpp:789/1092` | D18 |

### 16.3.2 第 2 层：GKI 强制的内核 config,Android 12+ 新机可靠

`CONFIG_VETH` / `NET_CLS_BPF` / `NET_SCH_INGRESS` / `BPF_SYSCALL` / `CGROUP_BPF` / `DEBUG_INFO_BTF` 全为 `y`、`CONFIG_NETKIT` 缺失——这四项在四个 GKI 分支的 `gki_defconfig` 里逐项核对过(§4),本机实测一致。

**但有两个真实的例外**,设计不能假定 GKI:

1. **从旧版本升级上来的设备可能不是 GKI**。Google 只要求**新发布**的设备用 GKI;由 Android 11 升级到 13/14 的机型可能仍是厂商自建内核。
2. **KernelSU 的 LKM / late-load 模式跑在厂商原版内核上**(§13.2.0 记录了 `KSU_RUNTIME_MODE`)。这类设备的 config 缺失概率显著更高。

所以 §4 的规则不变:**每一项都必须在 activation 时以"实际调用成功"验证,而不是查版本或查 config。** 本机 `/proc/config.gz` 可读是运气,不是保证。

### 16.3.3 第 3 层：SoC 厂商,覆盖面大但绝不通用

| 观察 | 归属 | 外推边界 |
|---|---|---|
| `rmnet_data*` 是 `ARPHRD_RAWIP` | **高通**的 rmnet 驱动 | 联发科用 `ccmni*`、三星 Exynos 用 `rmnet*`/`umts_*`,**命名与 ARPHRD 都可能不同** |
| `rmnet_ipa0`(MTU 9216) | 高通 IPA 硬件加速 | 其它平台无此设备 |
| `qcom_qos_reset_POSTROUTING` 对本机源地址出向流量 `--set-xmark 0x0/0xffffffff` | 高通 | 但它独立印证了 §19 拒绝 mark 方案是对的 |

**由此得到一条设计硬规则(本设计已经满足,此处明确写下)**:**interface admission 只按 `ARPHRD` 类型判定,绝不按名字匹配。** 唯一的例外是 CLAT 的 `v4-*` 前缀,而那是 AOSP 源码里写死的命名约定(第 1 层)。任何形如"名字以 `rmnet` 开头就当蜂窝"的代码都会在联发科设备上错。

### 16.3.4 第 4 层：OEM 特有,**不可外推**——本次最重要的发现就在这一层

| 观察 | 归属 |
|---|---|
| `semUidBPF` 占据 egress `chain 0/pref 1/handle 0x1` | 三星 |
| `tosMarker` 五个 egress 程序、`mnxbNetd`、`semSmartHS`、`semUidBPF_ape`、`tcpAccECN` | 三星 |
| 14 个 `epdg*`(`ARPHRD_NONE`,VoWiFi) | 三星 |
| 86 个 prog pin / 115 个 map pin | 三星(原生 AOSP 少得多) |

**§8.5.3 的 pref 冲突是三星特有的,但"某个 OEM 占了 egress pref 1"这个*类别*是普适风险。** 小米、OPPO、vivo、荣耀都有自己的网络增强 BPF,谁占了哪个 pref 无法从任何公开来源推断。

**因此外推的正确方式不是猜,而是改设计:**

- 不预定任何 pref,dump 后动态选取(§8.5.3 已改)。
- **attach 之后做正向存活验证**(§8.5.4),因为这是唯一与厂商无关的"我们真的在工作"的判据。
- `status` 必须报告实际取到的 pref 与同一 chain 上的其它 filter,让用户在陌生机型上能自证。

### 16.3.5 第 5 层：内核版本带——**不能从 Android 版本推断**

本机是**最有说服力的反例**:**Android 16 / SDK 36,内核却是 5.15.211**。它是从 Android 13 升级来的,GKI 分支停在 `android13-5.15`。

所以以下这类映射**只对新发布机型成立**,对升级机型无效:

| Android | 新机的 GKI 分支 |
|---|---|
| 12 | 5.10 |
| 13 | **5.15** |
| 14 | 6.1 |
| 15 | 6.6 |
| 16 | 6.12 |

受内核版本影响的三条机制:

| 机制 | 分界 | 本机(5.15) |
|---|---|---|
| `bpf_sk_assign` 拒绝 `SO_REUSEPORT` listener | < 6.5 命中 | **命中**(§9.2) |
| 未 hash socket 的引用泄漏 | < 6.5 命中 | **命中**,靠 §9.4 的顺序规避 |
| **TCX attach** | ≥ 6.6 可用 | **不可用** |

**这三条都必须运行时探测,禁止读 `uname -r` 判定。** 厂商会回移特性,升级机型的内核也不跟随系统版本。

### 16.3.6 结论：本次测试的外推价值

| 问题 | 回答 |
|---|---|
| 第 1、2 层结论能当普适前提吗 | **能**(第 2 层附带 GKI 例外的运行时验证要求) |
| `rmnet = RAWIP`、因此需要 L3 分支 | **需要 L3 分支这个结论普适**(总有非以太的蜂窝口);但**具体名字与类型不普适**,必须按 ARPHRD 判定 |
| 三星占 pref 1 这件事能外推吗 | **不能**。但"OEM 可能占 pref 1"作为**风险类别**普适,已据此改成动态选 pref + 存活验证 |
| `rp_filter=0`、`ip_forward=0` 能外推吗 | 这是**内核默认值**且 AOSP 从不设置(§8.4),所以**大概率**如此;但厂商可以在 `init.rc` 里改,**§8.4 的运行时读取 + 冲突即响亮失败不能省** |
| 一台设备够吗 | **不够,但它把设计从"猜"推进到了"知道要测什么"**。真正需要的补充样本是:一台**联发科**设备(验证 `ccmni` 的 ARPHRD)、一台 **6.6+ 新机**(验证 TCX 路径)、一台**非三星 OEM**(验证 pref 冲突的普遍性) |

**这一节的方法论要求**:今后每次在新机型上跑 `tools/phase0/observe.sh`,结论都要按上面五层归类再写进文档。把 OEM 层的观察当成普适事实,是这份设计最容易犯的错。

## 16.4 通过标准

- `2 family × 2 protocol` 的 TCP/UDP 原目的**逐字节**一致，4 个 socket 全部完成 readiness 核验。
- 任何 pre-redirect 的未入场失败保留原 skb（真实目的侧能看到该连接直连成功）；任何 post-boundary 失败明确 drop（真实目的侧看不到任何字节）。
- 活跃 TCP decision 不被容量驱逐、first-decision-wins、不原地翻转、socket 关闭后释放。
- 所有 capture filter 是 first applicable；egress "不接管" 全部用 `TC_ACT_UNSPEC`；AOSP CLAT 与后续 OEM filter 仍被执行。
- frozen control leaf 经 pointer swap 只出现完整 old/new snapshot。
- Android 系统 TC/RPDB/VPN/sysctl 对象无修改或覆盖（`all.rp_filter` 亦未被 Flux 写过）。
- 全程无需 cgroup attach、sing-box patch、SOCKMAP、heartbeat 或第二后端。

**任何一项不成立：停止进入清库与编码阶段**，修订本蓝图并重新请所有者确认。不得把 Phase 0 变成长期实验平台。

---


---

## 16.5 Q10 首次尝试的结果（2026-08-25，SM-S9180）

Q10 的决定性测量**尚未完成**，但这次尝试本身产出了三条事实，其中两条改变了工具选择。

### 16.5.1 已确定的事实

| 事实 | 影响 |
|---|---|
| **Android 的 `tc` 没有编入任何 action 模块。** `action drop` / `action gact drop` / `police` 全部报 `Unknown action "noact"`（iproute2-ss171113 找不到 action 模块时的回退） | 用 `tc` action 做观测的方案**整条作废**。也让 §12.8「不 shell out 到 tc/ip」的理由更硬：即使想用，这个 `tc` 也表达不了我们要的东西 |
| **`tc -s` 对 qdisc / class 有效，对 filter / action 返回空** | 独立确认了 §8.5.4 不能依赖 filter 级统计。该节选用 BPF map 计数器是必需而非偏好 |
| **`tc -s qdisc show` 会显示 clsact 的 drop 计数器**（`mini_qdisc_qstats_cpu_drop`） | 这是本平台上唯一可用的「TC_ACT_SHOT 发生了」观测点，将来做 Q10 与其它 TC 实验都靠它 |

### 16.5.2 厂商 filter 的瞬态性得到第三次确认

同一天内 `wlan0` egress 上三星的 `semUidBPF` filter 被观测到 **在场 → 不在场 → 再在场** 三种状态，而程序 id 95/96 **全程保持加载**。

这把 §8.5.3 的「attach 时刻不可预测」升级为「**在场与否本身是反复变化的**」。两条设计含义：

- 任何「激活时检查一次冲突」的逻辑都不足够，必须靠 `RTM_NEWTFILTER` 持续监视（§10.4 已如此规定）。
- **Q10 只能在厂商 filter 在场的窗口内测。** `tools/phase0/q10-chain-continuation.sh` 已内置检测：发现 pref 1 有真实占用者时自动改测真实场景并跳过合成用例。

### 16.5.3 阻塞项

决定性测量需要一个**编译好的 BPF 对象**（在 pref 2 挂一个只做 `counters[SAW_PACKET]++` 然后返回 `TC_ACT_UNSPEC` 的程序，用 `bpftool map dump` 读计数）。设备上已有 `/system/bin/bpftool`（v5.16.0 / libbpf v1.4），可直接用于 load 与 attach。

**构建路径已确定：在 WSL 里编。** Windows 侧无 clang、无 NDK，但 WSL 内有（所有者确认，2026-08-25）。因此：

1. WSL：`clang -target bpf -O2 -g -mcpu=v3 -c` 编出 `.o`。
2. `adb push` 到设备。
3. 设备自带 `/system/bin/bpftool`（v5.16.0 / libbpf v1.4）做 `prog load` + `net attach`。
4. `bpftool map dump` 读 `counters[FLUX_CNT_SAW_PACKET]`。

这条路径对**整个 Phase 0 证伪半场**都成立，不只是 Q10；`xtask` 的 `FLUX_BUILD_BPF=1` 分支也应当在 WSL 里跑。**Phase 0 已不再被工具链阻塞。**

Q10 还有一个**时机**约束：它只能在厂商 filter 在场的窗口内测（§16.5.2）。`tools/phase0/q10-chain-continuation.sh` 已内置检测并自动切换到真实场景。

### 16.5.4 Q10 已回答：通过（2026-08-25 20:03，SM-S9180）

**厂商 filter 在场时实测，结论是强结论。**

```
existing filters:
  pref 1 bpf chain 0 handle 0x1 prog_semUidBPF_schedcls_egress_tsm_ether id 96
attach at pref 2:
  pref 2 bpf chain 0 handle 0x1 q10_probe direct-action id 119

tx_packets delta:      15
probe invocations:     15   （8 个 CPU 的 per-CPU 值求和）
```

**调用数与接口发包数 1:1 吻合。** 因此：

- 三星在 pref 1 的程序**不终止** classifier chain。
- 每一个离开接口的包都到达了 pref 2。
- **clsact + 动态选 pref 的主路线在这台设备上成立。**

机制也顺带弄清了：`tc filter show` 的输出里**我们的 filter 显示 `direct-action`，三星的没有**。所以三星的是**非 direct-action 的 `cls_bpf`**——`cls_bpf_classify` 对非 da 程序把返回 0 解释为"未匹配，继续下一条"，而不是 `TC_ACT_OK`。这同时回答了我此前想做的对照实验：这个 `tc` 确实会打印 `direct-action`，所以三星输出里没有它**是有意义的**。

**残余风险要说清**：这只证明了**这一个厂商程序**不遮挡。别的 OEM 若用 direct-action 且返回 `TC_ACT_OK`，仍会遮挡。所以 §8.5.4 的存活验证**不因本次通过而取消**——它正是为了在陌生机型上自证。

### 16.5.5 顺带确定的四条工具链事实

达成 Q10 的过程里踩出四个坑，每一个都会改变实现方式：

| 事实 | 影响 |
|---|---|
| **`clang -target bpf` 需要 `-I/usr/include/<arch>-linux-gnu`** | 否则 `linux/bpf.h` 里的 `asm/types.h` 找不到。`xtask` 的 BPF 构建必须带这个 |
| **设备的 bpftool（libbpf v1.4）拒绝 legacy `SEC("maps")`**：`legacy map definitions in 'maps' section are not supported by libbpf v1.0+` | 蓝图原先记的"legacy `bpf_map_def` 在 Android 可用"（§0.5.7，源于 bpf2socks）**只对自建加载器成立**。而我们反正要为 `SK_STORAGE` 手写 BTF（D10），所以**全部 map 都用 BTF 定义**，代价为零、还换来 bpftool 可调试性 |
| **`tc filter add` 必须显式带 `protocol all`** | 省略会得到 `RTNETLINK answers: Invalid argument`（内核收到 protocol 0），错误信息毫无指向性 |
| **Android 的 `tc` 没有 ELF 支持**：`bpf da obj <file>` 报 `No ELF library support compiled in`，只有 `pinned` 可用 | 这把 §12.8「不 shell out 到 tc」从偏好变成**唯一选项**：就算想用 `tc` 装 BPF filter 也做不到，必须自己 load+pin 再按 netlink 挂载 |

### 16.5.6 §8.5.4 的验证状态

存活验证机制**本身已被这次实验证实可行**——探测程序、per-CPU 计数、attach/detach、读计数，整条链路跑通了，用的正是 §8.5.4 规定的形态（独立探测程序 + `TC_ACT_UNSPEC` + per-CPU 计数器）。

剩下的只是把它从脚本搬进 `fluxd`。
---

## 16.6 Q1 已通过（2026-08-25，SM-S9180 / 5.15.211，基线内核）

**权威结果**：设备就在产品基线 5.15 上，不是排练。工具：`tools/phase0/q1_probe.bpf.c` + `tools/phase0/q1-run-device.sh`，程序按 §7.3 的 E1/E2/E3 逐步复刻，并直接 include 真实的 `bpf/include/flux_abi.h`。

### 16.6.1 verifier 接受了核心组合

```
128: sched_cls  name q1_probe  tag 36d64a56ccd8ce31  gpl
     xlated 864B  jited 876B  memlock 4096B  map_ids 130,129  btf_id 52
```

即：`bpf_sk_storage_get()` 作用于 `bpf_sk_fullsock(skb->sk)` 返回的指针、在 TC egress、配一张 BTF 定义的 `SK_STORAGE` map（value 为 `struct flux_decision`）——**这个组合是整个设计的地基，现在已被基线内核接受**。

### 16.6.2 计数结果

在 `rmnet_data0`（**ARPHRD_RAWIP**，蜂窝，当时的主网）egress pref 2 上挂 20 秒：

| 槽位 | 值 | 含义 |
|---|---:|---|
| `SEEN` | 172 | 后续包找到了已存在的决策 |
| `CREATED` | 15 | 首次决策 |
| `RACE_LOSER` | 0 | 无并发竞争败者 |
| `ALLOC_FAIL` | 0 | `F_CREATE` 从未返回 NULL |
| `CORRUPT` | 0 | 存储值从未被改动 |
| `NO_FULLSOCK` | 0 | 每个 `skb->sk` 都能取到 fullsock |
| `NOT_TCP` | 24 | 非 TCP（UDP/ICMP），正确识别 |
| 接口 tx delta | **211** | |

**`172 + 15 + 24 = 211`，恰好等于接口 tx delta。** 这个精确吻合同时证明两件事：程序看到了**100%** 的出向包（该接口上没有被遮挡），且分类是**穷尽的**（没有落到任何未计数的分支）。

结论：**决策一次一 socket，之后每个包都复用同一份且未被改动。** `SEEN` 远大于 `CREATED` 就是这句话的证据。

### 16.6.3 副产物：一条会让实现者发懵的平台限制

第一版探测用 `__sync_fetch_and_add(seq, 1)` 生成唯一 id，**基线内核拒绝加载**：

```
BPF program load failed: Unknown error 524
processed 167 insns (limit 1000000) ... peak_states 15
failed to load: -524
```

`524` = `-ENOTSUPP`。关键在日志形状：**verifier 通过了**（167 条指令零抱怨），失败在其后的 JIT。原因是取原子操作的**返回值**会生成带 `BPF_FETCH` 的 `BPF_ATOMIC`，而 arm64 在 5.15 上不实现它。换成 `bpf_ktime_get_ns()` 后立即加载成功——诊断由此确证。

已写进 §7.5.0 作为硬规则。产品**天然满足**（`counters` / `uid_stats` 都是 per-CPU，无需原子；generation 由用户态发布），但调试时随手加一个全局计数器就会踩中，而 `-524` 毫无指向性。

### 16.6.4 未覆盖的部分

- **socket 关闭后存储释放**：`SK_STORAGE` 没有可枚举的条目，`bpftool` 不便直接观察。语义由内核保证（随 socket 生命周期），且 `ALLOC_FAIL = 0` 说明没有容量压力。列为"依赖内核语义，未独立验证"。
- **高并发竞争**：`RACE_LOSER = 0`，说明 8 个 `curl` 没有真正撞在一起。要观察竞争需要更激进的并发（`tools/phase0/q1-run.sh` 的 netns 版本用 40–100 个并发 connect 更容易触发），但那是**语义确认**而非风险项——`F_CREATE` 的原子性由内核保证，且败者拿到胜者的值本身就是期望行为。
---

## 16.7 Q9 已通过：D18 在实机上成立（2026-08-25，SM-S9180 / 5.15.211）

**这是 Phase 0 里最要紧的一次测量**，因为 D18（per-app DNS 零额外机制）整个压在一条断言上：netd 对明文 DNS socket 调用 `fchown()` 把它交给发起请求的 app，`sk->sk_uid` 随之改变，而 `bpf_get_socket_uid()` 读的正是 `sk->sk_uid`（源码链见 §1.3.1）。

工具：`tools/phase0/q9_probe.bpf.c` + `tools/phase0/q9-run-device.sh`。纯观测，每条路径都 `TC_ACT_UNSPEC`，不改变任何包的命运。判别方式故意做得很钝——把 egress 包按 (socket UID, 端口类别) 分桶，看明文 :53 上出现的是 app UID 还是 netd 的 1051。

### 16.7.1 结果

`rmnet_data0`（ARPHRD_RAWIP，蜂窝，当时的主网）egress，45 秒，372 个包（94 v4 / 278 v6），零解析失败：

| 类别 | UID | 归属 |
|---|---:|---|
| **UDP:53 明文 DNS** | **10265** | **`com.android.vending`（Play 商店）** |
| UDP:53 明文 DNS | 1073 | `com.google.android.networkstack.tethering` |
| TCP:443（对照组） | 多个 10xxx | 各第三方 app，逐一正确归属 |
| TCP:853 (DoT) | — | **一条都没有** |

**`1051`（netd 自身）出现零次。** 每一个明文 DNS 包都归到了真正的请求方。

**D18 成立。** per-app DNS 不需要任何额外机制——普通的 `uid_policy` 查表已经覆盖它。

### 16.7.2 三个附带结论

1. **`private_dns_mode` 的默认值是 `opportunistic`**，不是 `off`。它的语义是 netd 先试 DoT，上游拒绝才回落明文。所以"能捕获多少 DNS"**取决于运营商/路由器的 DNS 服务器是否支持 DoT**，不取决于我们。本次测试的蜂窝网络上 :853 一条都没有，全程明文，对我们是好消息；但**换一个支持 DoT 的网络，可捕获的 DNS 会显著减少**，这不是缺陷而是边界（§1.3.3 边界①），`status` 应当能让用户看出来。
2. **对照组同时验证了普通流量的 UID 归属**：:443 上每个 app 各归其位。所以 :53 的结果不是侥幸，整条 `bpf_get_socket_uid()` 路径在这台设备上都是准的。
3. 未观察到 `enforce_dns_uid`（§1.3.3 边界②）。若某设备开启，:53 会带 `1051`，按"不捕获"处理。

### 16.7.3 隐私说明

原始输出包含设备上已安装 app 的包名。此处只保留 `com.android.vending` 与 `networkstack.tethering`——两者都是 AOSP/GMS 自带、每台设备都有，不泄露使用习惯。第三方 app 只记数量与归属正确性，不记包名。`bugreport` 也必须遵守同一条线（§ux）。

---

## 16.8 段名缺陷与产品数据面基线过关（2026-08-25）

这一节是 Q9 的意外产物：写探针时 `SEC("tc/q9")` 被 libbpf 拒绝，顺手一查发现**产品代码踩了同一个坑**。

### 16.8.1 缺陷

`bpf/flux.bpf.c` 原本用 `SEC("tc/verify")`、`SEC("tc/cap_l2")`、`SEC("tc/cap_l3")`、`SEC("tc/in")`。libbpf 在 `tc/` 下**只认 `tc/ingress` 和 `tc/egress`**，其余一律：

```
libbpf: failed to guess program type from ELF section 'tc/q9'
```

**四个产品程序全都加载不了。** Q1/Q10 探针用的是裸 `SEC("tc")`，所以一直没暴露。

### 16.8.2 实测可用集（不猜）

`tools/phase0/secname-probe.sh` + `secname-load.sh` + `secname-attach.sh`，设备 bpftool v5.16 / 内核 5.15.211：

| 段名 | 加载 | 程序类型 | legacy `tc filter` 挂载 |
|---|---|---|---|
| `tc` | OK | `sched_cls` | OK |
| `classifier` | OK | `sched_cls` | OK |
| `tc/ingress` | OK | `sched_cls` | OK |
| `tc/egress` | OK | `sched_cls` | OK |
| `tcx/egress` | OK | `sched_cls` | OK |
| `action` | OK | **`sched_act`** | **失败：`RTNETLINK answers: Invalid argument`** |
| `tc/<自定名>` | **失败** | — | — |
| `classifier/<自定名>` | **失败** | — | — |
| `action/<自定名>` | **失败** | — | — |

两个陷阱值得单独记：

- **`action` 会骗过"加载成功"这一关**。它选中的是 `BPF_PROG_TYPE_SCHED_ACT`，另一种程序类型，`tc filter ... bpf da` 直接 `EINVAL`。只看加载结果会误判。
- **`tc/egress` 和 `tcx/egress` 在 5.15 上挂载正常**。原先担心 libbpf 会设 `BPF_TCX_*` 的 `expected_attach_type` 而 TCX 要到 6.6 才存在——实测这个顾虑不成立。

### 16.8.3 一段一程序，还是四个程序挤一段

`bpftool prog loadall` **能**从单个 `SEC("tc")` 里加载 4 个程序，按函数名 pin（`tools/phase0/secname-multi.bpf.c` 实测）。

这一条让决策塌缩了：4 个程序无论怎么分段都**必须**用 `loadall`（`prog load` 单数形式只接受单程序对象），而 `loadall` 认的是**函数名不是段名**。所以"bpftool 可调试性"在两种方案下**完全相同**，唯一剩下的区别是加载器复杂度：

- 一段一程序：重定位偏移天然是程序相对的，无需重定基。
- 四程序一段：要按符号 `st_value`/`st_size` 切片，再把该段的重定位逐函数重定基——手写加载器出微妙 bug 的经典位置。

**结论：一段一程序。** 映射写进 `flux_abi.h` 的 `FLUX_SEC_*` 与 `abi.rs` 的 `PROG_SECTIONS`，让 C 与加载器无法漂移：

| 程序 | 段 | 理由 |
|---|---|---|
| `flx_cap_l2` | `tc` | 与 cap_l3 成对，取两个通用别名 |
| `flx_cap_l3` | `classifier` | 同上 |
| `flx_in` | `tc/ingress` | 它确实是 ingress |
| `flx_verify` | `tc/egress` | 它确实挂在 egress（§8.5.4） |

### 16.8.4 顺带修掉的两个编译期缺陷

1. **`AF_INET` / `AF_INET6` 未定义**。`<linux/in.h>` 只给 `IPPROTO_*`；`<linux/socket.h>` 在 `-target bpf` 下与上面的 UAPI 头冲突。已在 `flux.bpf.c` 内显式定义（二者是冻结 ABI，`struct bpf_sock.family` 用的就是这两个值）。
2. **`control_root` 的内层 map 无法从 BTF 建出**：

```
libbpf: map 'control_root.inner': can't determine value size for type [95]: -22
```

`tools/phase0/btf-inspect.sh` 查出根因：`[95] FWD 'flux_control' fwd_kind=struct`——程序只通过指针接触这个结构体，clang 就把完整定义裁成了前向声明，而 FWD 没有大小。改用显式 `__uint(value_size, sizeof(struct flux_control))`：不加匿名全局、不多建一张 map，且 `sizeof` 在布局变化时仍会让构建失败。

### 16.8.5 结果：整个数据面在基线内核上通过验证器

`tools/phase0/loadall-product.sh`，内核 5.15.211：

| 程序 | xlated | jited |
|---|---:|---:|
| `flx_cap_l2` | 8408 B | 7432 B |
| `flx_cap_l3` | 9160 B | 8112 B |
| `flx_in` | 4336 B | 3736 B |
| `flx_verify` | 104 B | 152 B |

**这是实现开始前能拿到的最强证据。** §7.2–7.5 里所有难的部分——`bpf_sk_storage_get` 作用于 `bpf_sk_fullsock`、`bpf_sk_lookup_*` / `bpf_sk_assign` / `bpf_sk_release` 的引用配平、`bpf_skb_change_head`、`bpf_skb_change_type`、ARRAY_OF_MAPS 内层查找、LPM trie——**全部被真实基线内核接受**，不再只是论证。

注意边界：bpftool 是**按 BTF 声明**建 map 的，而产品由 `maps.rs` 显式建（§12.2）。所以这次过关证明的是**程序逻辑可验证**，不是 map 参数正确。后者由 `fluxd check` 负责。

**这条应当进 CI**：`bpftool prog loadall` 是最便宜的验证器门。代价是 CI runner 的内核与 arm64 5.15 有差异，所以它是补充而非替代真机验证。
---

## 16.9 Q6 观测半场 + veth 生命周期（2026-08-25，SM-S9180 / 5.15.211）

工具：`tools/phase0/q6-veth-observe.sh`。前三节纯观测；第四节创建一个**无地址、无路由**的 veth 对并在退出时删除，是 §8.4 / §8.7 能在没有数据面时验的那一半。

### 16.9.1 `filter INPUT` 没有 `-i lo` 快捷放行——一条残余风险被测掉了

§16.1 Q6 原先记着一条残余风险：AndroidTProxyShell 不在 `filter INPUT` 开口也能工作，但**它的包 `iif = lo`，我们的包 `iif = flxrs1`**，所以"Android 可能有 `-i lo` 的快捷放行"这条可能性无法排除。

实测结果（v4/v6 完全一致）：

```
Chain INPUT (policy ACCEPT 796K packets, 1455M bytes)
 pkts bytes target              prot opt in  out  source     destination
 796K 1455M oem_in              all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M bw_INPUT            all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M fw_INPUT            all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M bw_VIDEOCALL_IN     all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M bw_VIDEOCALL_OUT    all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M bw_videocall_box    all  --  *   *    0.0.0.0/0  0.0.0.0/0
 796K 1455M firewall_f          all  --  *   *    0.0.0.0/0  0.0.0.0/0
```

**每一条的 `in` 都是 `*`。** 没有任何接口维度的分支，policy 是 `ACCEPT`，并且七条 target 的计数与 policy 计数完全相同（796K/1455M），说明**所有输入包都完整走完这七条链**。

结论：`iif = lo` 与 `iif = flxrs1` 在 `filter INPUT` 里走**完全相同**的路径。既然 AndroidTProxyShell 的本地交付流量能活着穿过这些链，我们的也能。**这条残余风险在本设备上消除。**

（仍是单机结论。OEM 可以在 `oem_in` / `fw_INPUT` 里放任何东西——box4magisk 的 `oneplus_a16_fix()` 就是证据。但"接口维度的隐藏差异"这一层已经排除，剩下的是"OEM 是否整体丢弃"，那一层要等数据面到位后用计数增长比对来答。）

### 16.9.2 厂商 filter 的占位是**按接口**的，不是设备级的

§8.5.3 记的是"三星在 `wlan0` egress 占据 `chain 0 / pref 1 / handle 0x1`"。这次在**同一台设备**上，Wi-Fi 断开、蜂窝为主网时：

| 接口 | 类型 | egress filter | ingress filter |
|---|---|---|---|
| `rmnet_data0` | 519 (RAWIP) | **空** | **空** |
| `rmnet_data1` | 519 (RAWIP) | **空** | **空** |
| `rmnet_data8` | 519 (RAWIP) | **空** | **空** |

三个 rmnet 接口都有 `clsact`，但**两侧一个 filter 都没有**。

所以"厂商占 pref 1"是 **`wlan0` 专属现象**，不是这台设备的普遍行为。这对 §8.5.3 的动态 pref 选择是个直接的强化理由：**不能按设备记忆一个 pref，必须按接口逐个探测**。同一台设备上蜂窝能拿到 pref 1、Wi-Fi 拿不到。

### 16.9.3 §8.4 的 sysctl 起点

| sysctl | 实测值 | 设计要求 |
|---|---:|---|
| `net.ipv4.conf.all.rp_filter` | **0** | 必须为 0 —— **开箱即满足** |
| `net.ipv4.conf.default.rp_filter` | 0 | 影响新建接口的初值 |
| `net.ipv4.ip_forward` | **0** | 设计预测不需要它；起点就是 0，正好能验证这个预测 |
| `net.ipv4.conf.all.arp_filter` | 0 | 设计预测不需要 |
| `net.ipv4.conf.all.accept_local` | 0 | 只需在 peer 上按接口设 1，不动全局 |

`default.rp_filter = 0` 有额外含义：**新建的 `flxrs1` 继承到的初值就是 0**，我们写 `flxrs1.rp_filter=0` 是幂等确认而非真正的改动。这符合 §1.3 "不改全局设置"的非目标。

### 16.9.4 veth 生命周期：干净

| 步骤 | 结果 |
|---|---|
| `ip link add flxrs0 type veth peer name flxrs1` | 成功（ifindex 48/49） |
| 写 `flxrs1.rp_filter = 0` | 成功 |
| 写 `flxrs1.accept_local = 1` | 成功 |
| `tc qdisc add dev flxrs1 clsact` | 成功，`qdisc clsact ffff: parent ffff:fff1` |
| 两端 `up` | 两端 `operstate=up` |
| `ip link del flxrs0` | 两端**同时消失**（删一端即删对） |
| 残留检查 | 两个接口都 gone；`ip rule` / `ip route show table all` / `ip -6 rule` 中匹配 `flxrs` 的行数 = **0** |

**netd 确实注意到了新接口**：

```
NetdWrapper: NetdWrapper interface add, iface= flxrs1
NetdWrapper: NetdWrapper interface add, iface= flxrs0
```

但它**只记了日志**：没有给 `flxrs*` 创建自己的 `clsact`（我们 add 之前是 `noop`）、没有加地址、没有加路由、没有把它并入任何 network。这正是 §8.7 需要的性质——我们的 veth 上的对象是**我们独占**的，不像物理接口那样要和 netd 争 `clsact`（§8.5.1）。

**未覆盖**：本项只验了"创建-配置-删除"闭环与零残留。包能否真的穿过这条 veth 并被本地栈接受（§8.4 的 martian-source / `accept_local` 矩阵、Q5 的全部条目）需要数据面在位，无法在此提前。

### 16.9.5 顺带记下的两件事

- **存在一条 `block_all_dns` 链**（v4/v6 各一，当前 `0 references`）。它现在没被引用，但名字说明系统保留了整体阻断 DNS 的能力。若某天被引用，会与 §1.3 的 DNS 捕获直接冲突。列为已知观察，不是当前问题。
- rmnet 接口的 `operstate` 是 `unknown` 而非 `up`。RAWIP 接口不上报载波状态，所以**接口选择逻辑不能用 `operstate == "up"` 做判据**，否则会漏掉全部蜂窝接口。这是一个很容易写错的地方。