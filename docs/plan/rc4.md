# 1.0.0-rc.4 交付路径

> 计划层（AUTH-0）。落地前与代码不一致时，以本文的目标形状为准；落地后合同进 `spec/`，本文归档或删除。
>
> 产品问题只有一句：把选中 App 的原包，用最短、可从内核现证所有权的路径，交给未修改的官方 sing-box TPROXY。rc.4 允许为此改数据面主干；不允许借机打开已被否决的产品面（TUN、cgroup、打补丁的引擎、用户可见多后端、iptables/fwmark 兜底）。

---

## 0 身份与已锁定的 GOV-1.2

| 项 | 值 |
|---|---|
| 设计对照版本 | `1.0.0-rc.3` |
| 设计日期 | 2026-09-18 |
| 设备旁证 | SM-S9180 / `5.15.211-Qkernel` / KernelSU；当晚核对见 `history/clone-philosophy-tech-tradeoffs-2026-09-17.md` 第 8 节 |
| 正式 1.0.0 门 | 改到 **rc.4 完成之后**（不再在 rc.3 上签署） |

所有者 2026-09-18 当场锁定三件事（C13）：

1. **唯一数据面**是 `NF_INET_LOCAL_OUT` 的 `.ko`：按 `sk_uid` 分类，用内核 `nf_tproxy` 把原包交给官方 sing-box TPROXY inbound。删除 veth 与物理口 TC 捕获。`fluxd` 负责 `init_module`/`finit_module`。`fluxd` 死后钩子必须已经是 `NF_ACCEPT`。
2. **`insmod` 失败则 Direct** 并写出原因。不回退 TC+veth。装不上模块的设备不在支持集里。
3. **范围**是这次讨论里仍然有效的优化一次做完。被主路废掉的项不再实现（见 §2）。

## 1 目标形状

**本机产生的包在出网卡之前被判定；属选中 UID 则就地交给 listener，不经过专用网卡，也不挂物理口 clsact。**

```
app send
  → ip_local_out / ip6_output
  → NF_INET_LOCAL_OUT  (fluxrs.ko)
       未选中 / 机制旁路 / 非 TCP·UDP 客户端：NF_ACCEPT（Android 原路）
       选中且 listener 活着：nf_tproxy 绑定官方 inbound，本机投递
  → sing-box TPROXY（IP_TRANSPARENT，原 L3/L4 头）
```

回程仍走已 `accept` 的子 socket，不必再偷 WAN ingress。身份仍是 `sk->sk_uid`（含 AOSP `fchown` 之后的明文 DNS），不是 `xt_owner` 的 `f_cred`，也不是 `current_uid`。

未选中路径的预算改写为：**LOCAL_OUT 钩子上一次 UID 读取 + 一次哈希未命中 + `NF_ACCEPT`**。数字必须在本机对照现行 TC E1 实测，禁止把未测百分比写进合同（§14.3）。若比现行地板明显更差，停下回 GOV-1.2，而不是用更重的 C 分类器硬上。

## 2 「全部优化」在删掉 veth 之后还剩什么

主路一旦成立，若干曾列入候选的手段不再是交付手段。把它们做进 rc.4 是返工，不是做到最好。

| 项 | 处置 | 原因 |
|---|---|---|
| `LOCAL_OUT` `.ko` + 内核 `nf_tproxy` | **本 RC 主路径** | 唯一能删掉第二次 `ip_rcv`、`rp_filter`、物理口 TC 的形状 |
| `fluxd` 发 `SOCK_DESTROY` | **本 RC 做** | 取消勾选拆活 TCP；控制面；不靠 `.ko` 的 `destroySocket` |
| `BPF_F_INGRESS` / dummy 缩短 veth | **不做** | 没有 veth 可缩短。dae 的 INGRESS flags 只作历史对照 |
| 物理口 TCX + `BPF_F_BEFORE` | **仍延期**（§22.2.1） | 捕获不再挂物理口 clsact，TCX 不再消灭那两类失败。6.6+ 若将来有别的 TC 用途再评估 |
| LAN / 热点第三入口 | **仍延期**（§1.3、§22.2） | `LOCAL_OUT` 看不见转发；那是源 IP/MAC 的新捕获入口，不是同一条通路 |
| `BPF_PROG_TYPE_NETFILTER` | **本机死路** | 四条 helper，无 `sk_assign`/`redirect` |
| ifb 当回送设备 | **拒绝** | `netif_keep_dst` + 弹回原 `iif` |
| 从 TC 调 kfunc 偷包 | **不做** | 仍在出网卡之后；比 `LOCAL_OUT` 晚一跳，且继续跟 OEM clsact 共存 |
| TC+veth 自动回退 | **拒绝** | 永久双热路径；所有者已选 Direct |
| iptables `-j TPROXY` / fwmark | **仍拒绝**（§19） | 对象不随 fd 消失且占 packed mark。本模块直接 `nf_register_net_hook`，不写 xtables |

「在 rc.4 做到最好」= 把仍然有效的主路和控制面一次做对，而不是把已废候选再实现一遍。

## 3 机制（落地时写进蓝图的骨架）

### 3.1 所有权：fd 关掉就必须旁路

不要心跳（PHIL-3）。模块导出一个只被 `fluxd` 打开的控制节点（miscdevice 或等价 anon inode）。`.open` 把「允许偷包」置位；`.release`（进程退出、`SIGKILL`、disable）必须在返回前把钩子变成纯 `NF_ACCEPT`。删除模块必须能从内核认出自己的 `nf_hook_ops`（PHIL-5），禁止靠记事本 `rmmod`。

加载只许 `fluxd` 做。`post-fs-data` / `service.sh` 只把 `.ko` 放到模块目录，禁止 `insmod`（PHIL-6、PHIL-7）。失败则不建任何网络对象，`status` 带具体 errno / vermagic / 签名原因。

### 3.2 偷包用内核 TPROXY，不写 iptables

本机 `CONFIG_NF_TPROXY_IPV4=y` 与 `IPV6=y`。模块在 `LOCAL_OUT` 命中后调用内核 TPROXY 查找/绑定路径（符号能否链接是批 1 的证伪点；链不上就停，不改用 iptables）。不改写地址端口；官方 inbound 仍靠 `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`。

禁止占用 Android packed fwmark，禁止 `iif lo` 规则，禁止写 `all.rp_filter`。不再需要 `flxrs0/1`、pref 100、table 20260。

### 3.3 分类器在模块里，但形状必须像现在的 E1

哈希未命中立刻 `NF_ACCEPT`。不要为未选中流量做 socket lookup、不要 conntrack 双向计数、不要 skb 改写。TCP 仍是首个 `SYN && !ACK` 一次决策；已建立连接若需要粘性，用 sock 上可随 socket 销毁的存储，不用会驱逐活跃流的 LRU。

`skb->sk == NULL` 的本地包（少见）不捕获，放行。这比漏掉更安全；若实测发现系统代发漏网，再用 `sk_uid` 能看见的路径补，不改用 `current_uid`。

### 3.4 与 OEM 共存

捕获钩子不再挂 `wlan0` clsact，因此不再和本机已存在的 `prog_semUidBPF_schedcls_*_tsm_ether` 抢 pref。模块不得 flush 任何 xtables/nft/OEM 链。

## 4 产品边界（相对 rc.3 的变化）

| 仍成立 | 改变 |
|---|---|
| 未修改官方 sing-box；不打补丁 | 数据面身份从「eBPF-only」改为「LKM `LOCAL_OUT` + 官方 TPROXY」 |
| 5.15 基线；以成功 load 为准，不以 `uname` 准入 | 另加：成功 `finit_module` 且 vermagic/KMI 匹配。失败 Direct，无第二条热路径 |
| 4 KiB 页；三管理器同一 ZIP | ZIP 内按 **GKI 代** 带 `.ko`（`fluxrs-android13-5.15.ko` 这种名字），不是一机一份 |
| 不做 TUN / cgroup / 用户可见 mode | 做 `SOCK_DESTROY`（控制面） |
| 热点/LAN 仍非目标 | 物理口 TC 捕获删除后，TCX 不再是本 RC 的优先延期项 |

### 4.1 同版本通用（Re-Kernel 模型，所有者 2026-09-18）

不是「这台三星的内核树编一份」。是 **一条 GKI 代一份 `.ko`**，与 `clone/Re-Kernel/template/customize.sh:5-32` 同一套匹配：

1. `uname -r` 取主版本（`5.15.211-Qkernel-…` → `5.15`）。带 `-androidN-` 则用 N，否则 `5.15→13`、`6.1→14`、`6.6→15`。
2. 选出 `fluxrs-android${N}-${X.Y}.ko`（可带构建后缀通配，与 `rekernel-android13-5.15*` 相同）。
3. `fluxd` `finit_module`；内核拒绝则 Direct。不以 `uname` 字符串当准入（与 BPF 的 Admit-by-load 同一原则）。

编译只对着 `kernel/common` 的该代分支（android13-5.15 / android14-6.1 / …）加该代 GKI `Module.symvers`。禁止用 OEM 树当默认 `KERNEL_SRC`。

Re-Kernel 能通用，是因为它的 netfilter 只链 GKI ABI 里的 `nf_register_net_hooks` / `nf_unregister_net_hooks`（`rekernel_netfilter.c:228-241`），并且永远 `NF_ACCEPT`。批 1 的旁路模块同一约束：再加 `misc_register` / `misc_deregister`（android13-5.15 ABI 列表里有）。

`nf_tproxy_get_sock_*` **不在** 已核过的 GKI ABI 片段里。批 3 不得把它写成链接期依赖，否则一份 `.ko` 立刻变成「只有编进 TPROXY 符号的内核才能装」。解析方式（仍须保持同代通用）在批 3 单独证伪：要么该代 ABI 后来收录了这些符号，要么运行期解析且失败则 Direct，不回退 veth。

破坏了 KMI 的厂商内核（Re-Kernel `Supports/Kernels.md` 对 VIVO / Harmony 的 ✘）同样 Direct。那是产品边界，不是再编一份 OEM `.ko`。

## 5 落地时必须就地改的合同位置

不在本文复制蓝图正文。批与条款一起改，改完 `doc-check` 绿。

| 位置 | 改什么 |
|---|---|
| `spec/blueprint.md` §1.2、§1.3、§2、§4、§7、§8、§14.1 | 数据路径、对象集、地板预算 |
| `spec/failures.md` §23 | 新 token：`lkm_unknown_release` / `lkm_missing_module` / `lkm_finit:<errno>` / `lkm_control` / `lkm_io` / `lkm_tproxy_symbol` / `lkm_not_loaded` / `policy_capacity:kmod_uids`；`rp_filter` / veth / pref 100 / table 20260 不再作为启动门 |
| `spec/interaction.md` §27 | Direct 原因对用户怎么说；无 `backend=` |
| `history/rejected-and-deferred.md` §19、§21.0 | eBPF-only 产品身份 `superseded`（C13）；iptables 兜底与双后端仍拒绝 |
| 设备 Phase 4–7 | 证明对象变成模块 fd + hook，不再是 `flxrs*` / pref 100 |

章节号不重排。

## 6 批次

每一批结束时宿主门禁绿；改设备状态的步骤另要 GOV-1.2。不为下一批预建 trait。

| 顺序 | 做什么 | 退出条件 |
|---|---|---|
| **0** | 本文；GOV-1.2 记入 `review-log`；§21 C13；进度指向本文件 | 文档与所有者选择一致。**本批不改运行中数据面** |
| **1** | `kmod/` 旁路模块（只链 GKI ABI：`nf_*_net_hooks` + `misc_*`）；按 GKI 代命名；`fluxd` `finit_module`；fd `.release` 后 `live=0` | 源码已进树。在 android13-5.15 common + GKI `Module.symvers` 上编出 `fluxrs-android13-5.15.ko`；本机 `finit_module` 成功或给出内核 errno。杀持有 `/dev/fluxrs` 的进程后钩子不再计数。**本机 adb 不在时不装模块**。设备证据：`history/review-log.md` §0.6.32 |
| **2** | 未选中地板：对照现行 TC E1 测 LOCAL_OUT 空钩子成本 | 数字进 `tools/phase0/results/`；若明显更差，停。设备证据：`history/review-log.md` §0.6.33 |
| **3** | 命中路径交给官方 listener，保留原头；**不**把 `nf_tproxy_get_sock_*` 写成链接符号 | Phase 6 级 origdst 双栈通过；未选中 App 仍直连；同一 GKI 代仍一份 `.ko`。**UDP+TCP origdst 双栈已在 SM-S9180 关闭（§0.6.41–0.6.42）。** `flux-core::kmod_uapi` 与 `LoadedModule` ioctl 已进树。默认 `FLUXRS_STAGE=6` `FLUXRS_NOCFI=1`。不做第二次 `ip_rcv` / dummy 注入。 |
| **4** | 拆除 veth、物理口 TC、RPDB 100 / table 20260、`rp_filter` 门 | `dataplane::Manager` 唯一路径是加载 `.ko` + ioctl；冷启动仍删 leftover `flxrs*`。Phase 3 断言无 `flxrs*` / pref 100。蓝图 §8.7/§8.8 与 `failures.md` `lkm_*` 已改。宿主门禁绿。设备上未在持有 fd 的 `fluxd` 仍跑时重跑 Phase 3（不 disable）。Phase 5/6 的 TC 套件已跳过，等 CIDR/DRAINING ioctl。 |
| **5** | `sock_diag.rs` 发 `SOCK_DESTROY`（type 21）；禁止 `ss -K` | 取消勾选后 `SET_UIDS` 去掉该 UID，再按完整 dump 的 `idiag_uid` 拆活 TCP。dump 不全则一条都不拆。uid 0 / overflowuid / LISTEN 不碰。宿主门禁绿。WSL dump/解析通过；该内核 type 21 为 `EOPNOTSUPP`。未对设备真实 App 连接发销毁。蓝图 §7.6/§9.5 与 `failures.md` `sock_destroy_*` 已改。 |
| **6** | 包装：ZIP 内 `.ko`、Direct token、三管理器仍一份信封 | `fluxd check` 在 vermagic 不匹配时给出可执行原因 |
| **7** | 工作区命名 `1.0.0-rc.4`；候选设备回归 | 正式 1.0.0 门仍是远端 CI + §20 + 三管理器 smoke |

## 7 禁止（本 RC 最容易复活的）

- 用户可见 `backend=` 或装不上就「暂时 veth」。
- `service.sh` / `post-fs-data` 里 `insmod`。
- 用周期心跳当死亡检测。
- `iptables -t mangle -j TPROXY`、占 fwmark、写全局 `rp_filter`。
- 全机 C 钩子里做与 UID 无关的重活（conntrack、报文改写）再决定放行。
- 为 LAN 对称去挂 `NF_INET_FORWARD` 却不单开捕获身份。
- 改官方 sing-box。

## 8 PHIL-10

1. 控制节点路径、hook 优先级、模块文件名都是机制，用户不可编辑。
2. 「偷包许可」绑在 fd 上，不绑在状态文件上。
3. 不为死亡检测加周期 wakeup。
4. 策略仍只从 `fluxd` 写入；模块不解析用户配置。
5. 删除 hook / 模块以内核当时的登记为准。
6. `insmod` 失败可诊断 → Direct；静默黑洞才硬拒绝。
