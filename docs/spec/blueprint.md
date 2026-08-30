# Flux-rs 0.9.0 终极设计蓝图与开发指南

- 文档编号：`FLUX-BP-0.9.0-FINAL`
- **状态：已定稿**（2026-08-25，Asia/Hong_Kong）。全部开放项已关闭，见 `../history/rejected-and-deferred.md` §21.1。
- 性质：**唯一实现合同**。与 `docs/` 下任何其它文件冲突时以本文为准。
- 读者：实现者（人或模型）。本文假设读者不了解旧仓库，也不需要读旧文档。
- ABI 真相源：`bpf/include/flux_abi.h`（`FLUX_ABI_MAGIC = 0xF10C0903`）；数据面骨架：`bpf/flux.bpf.c`。
- 本文只是文档集的一部分，按读者拆分。导航与「章节编号 → 文件」映射见 `docs/README.md`。

## 定稿时的证据状态

写这一段是为了让实现者一眼看出**哪些能当前提用、哪些还要自己验**。

| | 状态 |
|---|---|
| Phase 0 **观测半场** | ✅ 已完成（`../history/phase0.md` §16.2）。49 个接口、GKI config、sysctl、`ip rule` 阶梯、fwmark 占用、cgroup 占用全部实测 |
| Phase 0 **Q10**（厂商 filter 是否遮挡我们） | ✅ **已通过**（§16.5.4）。厂商在 pref 1 在场时，我们在 pref 2 计到 15 次调用 / tx delta 15，1:1 吻合 |
| Phase 0 **Q1**（SK_STORAGE first-decision） | ✅ **已通过**（§16.6）。verifier 接受核心组合；172+15+24 = 211 恰好等于 tx delta |
| Phase 0 **Q9**（per-app DNS，**D18 的赌注**） | ✅ **已通过**（§16.7）。明文 :53 上出现的是 `com.android.vending`（UID 10265）等 app UID，netd 的 1051 出现**零次** |
| Phase 0 **Q2**（listener 身份、lookup、**assign 成功**） | ✅ **已通过**（§16.10）。官方 v1.13.19 的 4 个 socket 全部 inode 核验通过；lookup 4/4 命中；**`bpf_sk_assign()` 返回 0**，§9.2 由源码结论升级为实测结论 |
| **产品数据面过验证器** | ✅ **四个程序全部通过**（§16.8.5，基线 5.15.211）。`sk_storage`/`sk_assign` 引用配平、`skb_change_head`、ARRAY_OF_MAPS 内层查找、LPM trie 均被接受 |
| Phase 0 **Q3–Q8** | ⬜ 待做，**且全部无法在实现之前做**——它们要测的是 §17 各阶段产出的代码。分配见 §17.2 |
| 能推翻主路线的技术未知项 | **无** |
| 外推范围 | **一台设备**。五层分类见 §16.3；把 OEM 层观察当普适事实是本设计最容易犯的错 |

设计期共推翻自己**八次**——五次在实测前，三次在 2026-08-25 的 Phase 0 实测中（其中两条推翻的是我自己写下的结论）。全部留有「原说法 / 实际 / 处置」对照，逐条位置见 `../history/review-log.md` §0.6 开头。**结论对而理由错**比结论错更危险，所以那张表比结论本身更值得读。

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

> **已移出本文** → `docs/history/review-log.md`。章节编号未变。含全部「原说法 / 实际 / 处置」更正对照。
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
| 数据面 ABI | `FLUX_ABI_MAGIC`（见 `bpf/include/flux_abi.h`），与 SemVer 无关 |

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

## 1.6 eBPF 能力边界：已评估的加速手段与容量

本节回答三个问题：分流够不够精准、eBPF 能不能做加速、能不能承载大规模 CIDR。它们是同一个问题的三面，所以放在一起。

### 1.6.1 大规模 CIDR bypass：能，而且严格优于 ipset

`BPF_MAP_TYPE_LPM_TRIE` 就是为这件事设计的。与旧版 Flux 的 `BYPASS_SET_BACKEND=zone|ipset` 相比：

| | iptables 跳转树 | ipset `hash:net` | **`LPM_TRIE`** |
|---|---|---|---|
| 到达匹配的代价 | 遍历链 | 遍历链到 `-m set` | **无**——我们的程序已经在跑，一次 helper 调用 |
| 查找复杂度 | O(规则数) | O(1) 哈希，但需按前缀长度分桶重试 | O(前缀位数)，实际远小于 |
| 万级 CIDR | 不可行 | 可行 | **可行** |
| 内存 | 每条规则一个链项 | 预分配哈希表 | `LPM_TRIE` **内核强制 `BPF_F_NO_PREALLOC`**，按需分配 |

最后一行是关键：**`max_entries` 对 `LPM_TRIE` 只是上限，不是预分配量。** 把它设成 65536 在不用时代价为零。

**因此 `FLUX_LPM_MAX_ENTRIES` 从 128 提到 65536。** 参考量级：`chnroute` 的 IPv4 列表约 1 万条，完全在范围内。批量装载用 `BPF_MAP_UPDATE_BATCH`（5.6+，基线 5.15 具备），一次 syscall 灌入上千条。

### 1.6.2 但这不是"把路由策略搬进 Flux"

§1.4 规定 Flux 只做 UID 粗分流，域名与规则归 sing-box。大 CIDR 集看似越界，**框架要摆正**：

它不是路由策略，而是**避免一次已知无用的用户态往返**。如果某个目的地无论如何都会被 sing-box 判为 direct，那么把它捕获、跨 veth、拷进用户态、再让 sing-box 发一遍，是纯粹的浪费。在 eBPF 里 bypass 掉，这些包**根本不离开原路**。

收益是可量化的：一个在国内使用的用户，若代理浏览器，境内流量往往占多数——这部分省掉的是 veth 跳、用户态拷贝、以及第二条 TCP 连接。

**两条必须写清的语义边界**：

1. **只能按目的 IP，不能按域名。** 它补充而不取代 sing-box 的域名规则。
2. **bypass 的判定在 sing-box 之前，且是终局的。** 若某域名解析到一个被 bypass 的 IP，即使用户在 sing-box 里希望它走代理，**也不会被捕获**。这个优先级必须在文档和 `explain` 输出里说明，否则会成为"我配了规则为什么不生效"的困惑来源。

### 1.6.3 容量：实测暴露的缺陷

一台真机（SM-S9180）的 `packages.list` 里，`[10000,19999]` 范围内有 **429 个 app**。而原先的 `FLUX_UID_SELECTED_MAX = 128`、`FLUX_UID_POLICY_MAX_ENTRIES = 512`。

这意味着**"选中全部第三方应用"这个最自然的 auto 模式在设计上是做不到的**。更糟的是 `uid_policy` 的 512：按 ABI 规定，`FLUX_UID_DRAINING` 条目在一个 boot 内**永不删除**（删了会让已捕获 socket 的包泄漏到真实目的地），所以用户每改一次选择都会累积 draining 条目。429 选中 + 若干次改动 = 撑爆 512。

修正后的容量：

| 常量 | 原 | 新 | 依据 |
|---|---:|---:|---|
| `FLUX_UID_SELECTED_MAX` | 128 | **1024** | 覆盖"装满 app 的设备上全选"，实测 429，留一倍余量 |
| `FLUX_UID_POLICY_MAX_ENTRIES` | 512 | **4096** | 必须容纳 selected + 一个 boot 内累积的 draining。HASH 预分配 4096 × 约 64 B ≈ 256 KB，可接受 |
| `FLUX_LPM_MAX_ENTRIES` | 128 | **65536** | §1.6.1。`NO_PREALLOC` 强制，未用不占 |
| `FLUX_SELF_ADDR_MAX_ENTRIES` | 32 | **64** | §1.6.4 的 flag 过滤能压住 churn，但 IPv6 隐私地址仍会轮换 |

### 1.6.3a 一个必须先处理的内核缺陷：LPM trie 在 6.6.0–6.6.46 会崩

把 CIDR bypass 建在 `LPM_TRIE` 上之前，有一个**内核崩溃**风险要处理，来源是 CHIZI 的 sing-box eBPF 分支文档（它在 Android 上长期实测）：

> Linux 6.6.0 至 6.6.46 存在 LPM trie UBSAN 内核崩溃风险。涉及 UID/包名筛选、`bypass_rule_set` 或 shared 来源 CIDR 时，sing-box 会在已知未修复内核上拒绝启动相关策略。请升级到 6.6.47+，或使用包含上游修复的厂商内核。

**这直接命中我们**：`android15-6.6` 是 GKI 分支之一，落在产品支持范围内；而崩溃不是"功能失效"，是**设备重启**。

三条处置：

1. **本机地址集改用精确 HASH，不用 LPM。** 这一条独立于缺陷也成立，而且是更好的设计：本机地址永远是全长前缀（`/32`、`/128`），用 LPM 做精确匹配本就是浪费。HASH 是 O(1)、删除干净（对 §1.6.4 的 IPv6 隐私地址轮换尤其重要）。CHIZI 也正是这么规避的——"使用精确 HASH map 保存本机地址，规避部分 Linux 6.6 LPM trie 崩溃问题"。
   
   因此 map 集从 9 张变 12 张（D23 的 uid_stats 也在其中）：`bypass_v4` / `bypass_v6` 保留 `LPM_TRIE` 供**前缀**用，新增 `self_addr_v4` / `self_addr_v6` 用 `HASH` 存本机地址。`FLUX_SELF_ADDR_MAX_ENTRIES` 随之取消——两者不再共用容量。

2. **大 CIDR 集仍需 LPM，因此必须版本门禁。** 内核在 6.6.0–6.6.46 区间且用户配了 `bypass.files` 时，**拒绝加载该策略并明确报告**，而不是照常加载然后等着崩。判定方式仍是运行时探测优先，但这一条**只能靠版本判断**——崩溃无法安全探测。这是全设计里唯一允许按版本 gate 的地方，理由要写在代码注释里。

3. **固定 bypass 集（回环、私网、多播、listener）条目很少且全是短前缀**，风险面小，但为一致起见同样受第 2 条门禁保护。

### 1.6.4 本机地址 bypass 必须按 address flag 过滤

D7 规定把本机所有单播地址动态注入 bypass。**这个规定不完整**，旧版 Flux 的 `addrsyncd` 暴露了缺口——它的配置里有一项 `ignore_addr_flags`，可选值是 `temporary | optimistic | deprecated | tentative | dadfailed | stable_privacy | managetempaddr`。

那不是过度设计，是必需的：

| flag | 为什么要处理 |
|---|---|
| `tentative` | DAD 未完成，地址还不可用。此时注入是错的 |
| `dadfailed` | 地址冲突，永不可用 |
| `temporary` / `stable_privacy` | **IPv6 隐私扩展地址会定期轮换**（常见为每天）。不过滤就会持续累积，撑爆 `SELF_ADDR_MAX_ENTRIES` |
| `deprecated` | 仍服务于既有连接，**要保留**——不能因为它被弃用就移除 bypass |

因此 §10.4 的地址观测必须：读 `IFA_FLAGS`；`tentative`/`dadfailed` **不注入**；`deprecated` **保留**；`temporary`/`stable_privacy` 注入但**按 LRU 淘汰**，上限即 `FLUX_SELF_ADDR_MAX_ENTRIES`。

### 1.6.5 逐项评估过的加速手段

| 手段 | 结论 |
|---|---|
| **旧版的 `PERFORMANCE_MODE`**（`-m socket` + conntrack `--ctdir REPLY -j ACCEPT` 快路径） | **已被结构性超越。** 那是为了让已建立连接跳过规则链遍历；我们的 `tcp_decision`（`SK_STORAGE`）是 per-socket O(1) 查找，根本没有链可遍历（§7.3 的 E2 在 E3 之前）。无需移植 |
| **旧版的 `MSS_CLAMP_ENABLE`**（钳制 TCP MSS 以修运营商网络） | **在本架构下结构性地不需要。** app 的 TCP 由本机 transparent socket **终结**，只走 app→veth→本地 socket，路径 MTU 是 veth 的 65535；sing-box 到服务器是**另一条** TCP 连接，由内核正常协商 MSS。app 的 TCP 从不穿越运营商路径，所以那个问题不会发生。这是终结型代理相对转发型的固有优势 |
| **旧版的 `BLOCK_QUIC`** | **不需要，且属于错误的层。** 我们正确捕获 UDP，QUIC 会被交给 sing-box。若用户的出口不支持 UDP relay 而希望强制 TCP 回落，那是**策略**，应当写在 sing-box 的 route rule（`{"network":"udp","port":443,"outbound":"block"}`），不是 Flux 的开关 |
| **`SOCKMAP` / `sk_msg` 内核内 splice** | **拒绝，两条独立理由。** ① 需要 sing-box 把自己的 socket 放进 sockmap，违反"官方未修改二进制"（§3.8）；② splice 只在不需要变换数据时成立，而代理的意义通常正是加密——唯一可 splice 的是 `direct` 出口，而那种流量我们本来就在 §1.6.1 里 bypass 掉了。零收益 |
| **XDP** | 不适用。XDP 只有入向、且在协议栈之前，**没有 socket 上下文**，拿不到 UID |
| **`BPF_PROG_TYPE_SOCK_OPS`**（可用于设 MSS、拥塞控制等） | **禁止**。它是 cgroup attach 类型，§0.1 已全面禁止 cgroup attach |
| **`bpf_redirect_peer` 省一跳** | 结构上不可用（§19）：要求 TC ingress 且跨 netns |
| **GSO 超级包穿越 veth** | **这已经是一项加速**，且是免费的。`__is_skb_forwardable()` 对 GSO skb 有显式豁免，所以大包整个穿过 veth，遍历次数按段数下降（§16 Q4 已核实机制） |
| **per-UID 字节/包计数** | **建议做**，见 §1.6.6 |

### 1.6.6 per-UID 计数：唯一建议新增的数据面功能

现有 counters 只在决策边沿递增（§6），所以能回答"有没有在工作"，但不能回答"哪个应用走了多少"。而后者是用户最常问的问题之一，也是"系统统计会翻倍"这条边界的直接补偿（§2.2.3(4)）。

方案：一张 `PERCPU_HASH`，key 为 `uid`，value 为 `{ tx_packets, tx_bytes }`，**只在已捕获的包上更新**。

成本论证：被捕获的包已经付了一次 redirect（约一次 `dev_queue_xmit`），再加一次 per-CPU hash 更新是边际的；而**未选中的流量一行都不碰**，§14.1 的性能地基不受影响。这是它与"per-packet 存活计数"（§8.5.4 已因此改用独立探测程序）的关键区别。

明确不做的：不记目的地址、不记端口、不记时间序列。只有"这个 UID 经代理走了多少字节"。**不记录任何能重建访问历史的东西。**

# 第 2 部分：数据路径与失败语义

## 2.1 路径

```
选中 app 的 socket
 └─(1) 受支持物理接口 TC egress（chain 0 / direct-action / pref 见 §8.5.3 动态选取）
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
6. **被代理流量失去 app 请求的 DSCP 标记**。AOSP 的 `dscpPolicy` 装在物理 interface 的 **egress pref 5**（`DscpPolicyTracker.java:50-51`），而我们对捕获包返回 `TC_ACT_REDIRECT`，chain 就此终止——只要我们的 pref 小于 5，dscpPolicy 就看不到这些包。sing-box 随后发出的**出站 leg** 仍会经过 dscpPolicy，但那是 root 的 socket，带不上 app 通过 `ConnectivityManager` 申请的 per-UID DSCP 策略。**净效果：被代理流量的 app 级 QoS 标记丢失。** 影响面限于依赖 DSCP 的运营商网络，且本机实测三星另有 `tosMarker` 五个 egress 程序，受影响的下游比这一条写的更多。
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

> **接口筛选不得用 `operstate` 做判据。** 实测（§16.9.5）：`rmnet_data0` 承载着默认路由、有 v4 与 v6 全局地址、流量正在跑，而 `/sys/class/net/rmnet_data0/operstate` 读出来是 **`unknown`**，不是 `up`。RAWIP 接口不上报载波状态。所以任何形如 `operstate == "up"` 或 `IF_OPER_UP` 的过滤会**漏掉全部蜂窝接口**——恰好是 `flx_cap_l3` 唯一的适用对象。判据用 `IFF_UP` 标志（来自 `RTM_NEWLINK` 的 `ifi_flags`）加"存在 scope global 地址"，不要用 `operstate`。
>
> 同一段实测还给出另一个不该用的判据：**"有地址"不等于"netd 认为它在网络里"**。观测时 `wlan0` 带着 `192.168.x.x` 却**没有 `clsact`**，因为 Wi-Fi 刚被断开而地址还没回收。`clsact` 的有无才是 netd 视角的真相（§8.5.1），这也正是我们复用它而不是自己创建的理由。

## 3.4 CLAT464

AOSP `ClatCoordinator` 创建 `v4-*` raw-IP TUN，并在其 egress 用固定低 priority 的 TC BPF 做 IPv4→IPv6 翻译。IPv4 packet 在 `v4-*` egress 仍带原 app socket UID；翻译后的物理 IPv6 通常已属 `AID_CLAT`，不能再作为 app 选择依据。

Flux 支持 CLAT 的**全部**条件：① link 是 TUN/raw-IP 且名字匹配 `v4-*`；② 存在 CLAT 特征地址与关联 underlay；③ TC dump 中存在可识别的 AOSP CLAT egress filter；④ Flux 能在同 chain 以**某个小于 `FLUX_TC_PREF_CLAT_MAX`(4) 的可用 pref** + IPv4 protocol + handle `0x1` 安装且**位于 CLAT 之前**（§8.5.3；若 1–3 全被占则该条件不成立）；⑤ Phase 0 已在该设备证明 UID/GSO/checksum/MTU/header 转换正确。任一条件不明 → 该 interface Direct。**Flux 不删除、不移动、不替换 AOSP 的 filter。** 不硬编码 AOSP 的 priority 数值，只要求 dump 顺序满足 first-applicable 谓词。

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
│   ├── flux.bpf.c                 # 唯一 BPF 源文件（见 bpf/flux.bpf.c）
│   └── include/flux_abi.h         # C 与 Rust 共享 ABI 真相源（见 bpf/include/flux_abi.h）
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

`bpf/include/flux_abi.h` 是唯一真相源，见 `bpf/include/flux_abi.h`。`flux-core/src/abi.rs` 是手写镜像，并**必须**带 `#[test]` 断言每个 `size_of` / 字段 offset 与 C 一致（`xtask` 在 CI 里用 clang 打印 offset 对照）。改动任何布局**必须**同时改 `FLUX_ABI_MAGIC`。

## 6.1 map 集合（稳态 12 个 kernel object）

| 名称 | 类型 | key | value | max_entries / flags |
|---|---|---|---|---|
| `uid_policy` | `HASH` | `__u32 uid` | `__u8` (`FLUX_UID_*`) | 4096 |
| `bypass_v4` | `LPM_TRIE` | `flux_lpm_v4_key` | `__u8` | 65536，`BPF_F_NO_PREALLOC`（内核强制，故 `max_entries` 只是上限） |
| `bypass_v6` | `LPM_TRIE` | `flux_lpm_v6_key` | `__u8` | 65536，同上 |
| `self_addr_v4` | `HASH` | `__u8[4]` | `__u8` | 256（D20：本机地址是全长前缀，不进 LPM） |
| `self_addr_v6` | `HASH` | `__u8[16]` | `__u8` | 256，同上 |
| `uid_stats` | `PERCPU_HASH` | `__u32 uid` | `struct flux_uid_stats`（16 B） | 4096（D23，只在已捕获包上更新） |
| `tcp_decision` | `SK_STORAGE` | `int`（隐式） | `struct flux_decision`（16 B） | 0，`BPF_F_NO_PREALLOC`，**需 BTF** |
| `control_root` | `ARRAY_OF_MAPS` | `__u32 0` | 当前 leaf 引用 | 1 |
| `control_leaf` | `ARRAY`（inner） | `__u32 0` | `struct flux_control` | 1，写满后 `BPF_MAP_FREEZE` |
| `fault_latch` | `HASH` | `struct flux_fault_key` | `__u8` | 64 |
| `fault_events` | `RINGBUF` | — | `struct flux_fault_event`（32 B） | 16384 bytes |
| `counters` | `PERCPU_ARRAY` | `__u32 idx` | `__u64` | 32 |

- 发布期短暂同时存在 old/new 两个 `control_leaf`，其它时刻共 12 个。
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

字段见 `bpf/include/flux_abi.h`。要点：

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

## 7.5.0 一条比 verifier 更靠后的陷阱：arm64 5.15 不支持带返回值的原子操作

**实测于 2026-08-25，SM-S9180 / 5.15.211**（Phase 0 Q1 的副产物，§16.6）。

在 BPF 里写 `__sync_fetch_and_add(p, 1)` **并使用它的返回值**，会生成带 `BPF_FETCH` 标志的 `BPF_ATOMIC` 指令。在 arm64 5.15 上加载这样的程序会失败：

```
libbpf: prog 'q1_probe': BPF program load failed: Unknown error 524
processed 167 insns (limit 1000000) ... total_states 15 peak_states 15
libbpf: prog 'q1_probe': failed to load: -524
```

`524` 是 `-ENOTSUPP`。注意日志的形状：**verifier 本身通过了**（167 条指令、无任何抱怨），失败发生在其后的 JIT 阶段。所以这不是"程序写错了"，而是"这条指令这个平台不实现"，而 errno 完全没有指向性。

**规则：数据面禁止使用带返回值的原子操作。** 不取返回值的原子加（纯 `BPF_XADD` 形态）不受影响。

本设计**天然满足**这条：`counters` 是 `PERCPU_ARRAY`，per-CPU 数据不存在竞争，`cnt()` 用的是普通 `*v += 1`；`uid_stats`（D23）是 `PERCPU_HASH`，同理。generation 号来自 `flux_control.generation`，由用户态发布，数据面从不自增任何全局计数器。

**但实现者很容易在调试时踩进来**——想加一个"全局计数看看"，随手写 `__sync_fetch_and_add`，然后对着 `-524` 发懵。这就是记下它的理由。

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

上限：总 UID entry ≤ 4096，其中 SELECTED ≤ 1024。候选配置若会超限，热更新被拒绝并保持当前策略。

这两个数字是按实测定的，不是猜的：一台真机 `[10000,19999]` 范围内有 **429** 个 app，所以原先的 512/128 让"代理全部第三方应用"结构上不可能；而上一段那条"`DRAINING` 永不删除"的不变量意味着每改一次选择都会累积条目，429 选中再改几次就撑爆 512（§1.6.3）。

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

**可达性要求**（原"first-applicable 要求"，2026-08-25 按实测放宽）：我们的 filter 不需要是 chain 0 的**首个** classifier——那个要求在实测面前站不住，因为厂商可能已占 pref 1 而 tc 的 pref 最小就是 1（§8.5.3）。真正的要求是**在我们之前没有会终止 chain 的 classifier**。

这个条件**无法从 dump 推断**：dump 只告诉你谁在前面，不告诉你它返回什么。已知 AOSP ingress accounting 返回 `TC_ACT_UNSPEC`、CLAT translation 返回 `TC_ACT_PIPE`，但这不能替任何 OEM 程序背书。因此判定方式是**实测而非推理**：§8.5.4 的存活验证。

Direct 用 `TC_ACT_UNSPEC` 交给全部后续系统程序。以下任一成立 → 该 interface **不得**标为 active：`block`/`goto` 使 chain 0 不可达；attach 后 dump 顺序不满足所有权谓词；小于 `FLUX_TC_PREF_CLAT_MAX` 的 pref 在 `v4-*` 上全被占用；**或存活验证判定被遮挡**。

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
2. ~~**egress pref 1 无硬冲突**~~ —— **这一条已被 §8.5.3 的实测推翻**。就 AOSP 自身而言 egress pref 1 确实空着（CLAT 在 4、dscpPolicy 在 5），但**这张表只涵盖 AOSP，不涵盖 OEM**：三星的 `semUidBPF` 就占着 egress pref 1。约束仍然成立的部分是"必须排在 CLAT(pref 4) 之前"。
3. **egress pref 5 的 `dscpPolicy` 会被跳过**：只要我们的 pref 小于 5，被捕获的包在我们这里返回 `TC_ACT_REDIRECT`，chain 终止，dscpPolicy 看不到它。后果见 §2.2.3(6)。

### 8.5.3 厂商已经占了 egress pref 1：pref 不能硬编码

> **2026-08-25 实测推翻了 §8.5.2 的一个隐含前提。** 我原先假定"AOSP 只用 pref 1（ingress，`tc police`）、4、5，所以 **egress** pref 1 是我们的"。在 SM-S9180 / Android 16 上实测：

```
# tc filter show dev wlan0 parent ffff:fff3        (clsact egress)
filter protocol all pref 1 bpf chain 0 handle 0x1 \
    prog_semUidBPF_schedcls_egress_tsm_ether id 96 tag 2ef4ef809be2dd32 jited
```

三星的 `semUidBPF` 占据 **`chain 0` / `pref 1` / `handle 0x1` / `protocol all`**——与 `flux_abi.h` 里 `FLUX_TC_CHAIN` / `FLUX_TC_PREF` / `FLUX_TC_HANDLE_EGRESS` **完全相同的四元组**。ingress 侧同样被 `..._ingress_tsm_ether` 占据（对我们无影响，我们的 ingress 在自有 veth 上）。

**三条由此推出的硬约束**：

1. **pref 1 不是我们能预定的。** tc 的 priority 取值是 `1..0xFFFF`，1 已是最小值，所以在厂商占了 pref 1 的接口上，**我们无法排到它前面**。原先的固定常量 `FLUX_TC_PREF` 已删除，换成 `FLUX_TC_PREF_PREFERRED`(2) / `_MIN`(1) / `_CLAT_MAX`(4) 三个边界值 + **dump 后动态选取**，并把实际取到的 pref 记进所有权谓词与 `status`。
2. **在 CLAT 的 `v4-*` 上仍必须 < 4**（AOSP CLAT egress 在 pref 4，§3.4）。若 1/2/3 在该接口全被占，**排序约束无法满足 → 排除该 interface**，不要降级到 pref ≥ 4。
3. **"attach 成功"不再等于"能工作"。** 如果 pref 更低的厂商程序返回 `TC_ACT_OK` 或 `TC_ACT_PIPE`，classifier chain 会在我们之前终止，我们的程序**一个包也收不到，而 attach 本身完全成功**。因此激活流程必须增加一步**正向存活验证**，机制见 **§8.5.4**；判定被遮挡时**只排除该 interface**（不是整体 `Inactive`），并报告 `tc_chain_shadowed`。执行位置是 §8.7 步骤 9 之后、步骤 10 之前。

**还有一个竞态，比上面三条更难处理。** 探针第一次运行时，`wlan0` 已连上、已有全局地址、已有 `clsact`，但**还没有 filter**；几分钟后三星才把 egress 程序挂上（程序本身在开机后 7 秒就由 bpfloader 加载并 pin 了，`loaded_at` 与 attach 时刻是两件事）。含义：

- **一次性的冲突检查会漏。** 激活时 pref 1 空着，不代表它会一直空着。
- **我们若先占了 pref 1**，厂商随后的 attach 要么失败（我们悄悄弄坏了三星的流量统计），要么用 `NLM_F_REPLACE` 把我们顶掉（捕获静默停止）。两种都不可接受。
- 因此**即使 pref 1 当时是空的，也不应该占它**。选 pref 的策略是"满足排序约束的前提下，避开厂商惯用的 pref 1"，并靠 §10.4 的 `RTM_NEWTFILTER` 事件持续监视自己那一条是否还在、以及是否有新 filter 插到我们前面。

**这一条同时改变了 §2.2.3(6) 的影响面评估**：本机除 AOSP 的 `dscpPolicy` 外，三星还有 `tosMarker` 系列**五个** egress 程序（`classify_ack` / `classify_uid` / `classify_queue_mapping` / `set_queue_mapping` / `set_tos_mobile`）以及 `mnxbNetd`、`semUidBPF_ape`、`tcpAccECN` 的 ether 变体。被捕获流量绕过的下游 filter 比蓝图原先设想的多得多。

> **2026-08-25 追加实测：占位是按接口的，不是按设备的。** 上面那句"三星占了 egress pref 1"容易被读成设备级事实，**它不是**。在同一台 SM-S9180 上、Wi-Fi 断开蜂窝为主网时，`rmnet_data0` / `rmnet_data1` / `rmnet_data8` 三个接口都有 `clsact`，而 **egress 与 ingress 两侧一个 filter 都没有**（§16.9.2）。
>
> 名字本身就在提示这一点：`..._tsm_ether` 的后缀是 `ether`，它是给 `ARPHRD_ETHER` 准备的，RAWIP 的蜂窝接口不在它的范围内。
>
> **对实现的直接后果**：不得把"本设备的可用 pref"缓存成一个值，必须**逐接口 dump、逐接口选取、逐接口做 §8.5.4 的存活验证**。同一台设备上蜂窝可能拿到 pref 1（但按上面的理由仍应避开它）、Wi-Fi 只能拿 pref 2。把 wlan0 的观察外推到 rmnet 会得出错误的排除决策。

### 8.5.4 正向存活验证：唯一与厂商无关的"我们真的在工作"判据

§8.5.3 约束 3 提出了要求，这里定稿机制。**这是整个设计里唯一不依赖任何厂商知识的健康检查**，因此它的实现方式必须是确定的，不能留给实现者发挥。

**要解决的问题**：`attach` 系统调用返回成功，只证明 filter 挂上了；不证明它会被执行。若同一 chain 上有一个 pref 更低的程序返回 `TC_ACT_OK` 或 `TC_ACT_PIPE`，`__tcf_classify` 就地终止，我们的程序**一个包都收不到，且没有任何错误码**。这是本设计最可能"装上了但什么都没发生"的失效模式，而在陌生 OEM 上我们无法预知谁在前面。

**为什么不能用现有的计数器判断**：§6 规定 counters **只在决策/丢弃/fault 边沿**递增，为的是让未选中流量的稳态per-packet 成本保持为"1 helper + 1 hash miss"（§14.1）。如果设备上此刻没有被选中的 app 在通信，所有计数器都不动——而这与"程序没被执行"完全无法区分。

**为什么不能用 `tc -s filter show` 的内核统计**：`cls_bpf` 在 direct-action 模式下不走 `tcf_exts_exec`，不更新 `bstats`。而且本机的 `iproute2-ss171113` 对 `tc -s filter show` 返回空（实测），这条路在真机上根本不可靠。

**一条被否决的设计，先说清楚为什么**：最自然的想法是在 `flux_control` 里加一个 `verify` 标志，让 `flx_cap_l2/l3` 在取到快照后顺手计数。**这行不通。** 看 §7.3 的 E1：未选中流量在 `uid_policy` 查不到时就 `return TC_ACT_UNSPEC` 了，**根本走不到 `ctrl()`**——`ctrl()` 只在"已有决策"的 E2 分支里被调用。要让标志生效，就得把快照查找提到热路径最顶端，对**设备上每一个出向包**多付两次 map 查找，这直接摧毁 §14.1 的性能地基。为一个只在激活时用 2 秒的检查付永久代价，不划算。

**采用的机制：一个独立的探测程序 `flx_verify`。**

```c
SEC("tc/verify")
int flx_verify(struct __sk_buff *skb) {
	cnt(FLUX_CNT_SAW_PACKET);
	return TC_ACT_UNSPEC;   /* 不改变任何包的命运 */
}
```

流程（插在 §8.7 步骤 9 与步骤 10 之间，逐 interface 执行）：

1. 按 §8.5.3 dump 该 parent，选出目标 pref **P**。
2. 在 `(parent, protocol all, pref P, handle FLUX_TC_HANDLE_VERIFY)` 挂上 `flx_verify`。
3. 读 `counters[FLUX_CNT_SAW_PACKET]` 记基线，等一个 timerfd 窗口（建议 2 s），再读。
4. **判定**：
   - 差值 > 0 → **pref P 可达**。卸下探测程序，在同一 pref P 挂上真正的 capture 程序（handle `0x1`）。两者都是同 parent、同 protocol、同 pref 的 direct-action `cls_bpf`，位置完全等价，所以"探测能跑"即"capture 能跑"。
   - 差值 == 0 → **必须区分两种原因**，否则会把"当时没流量"误报成"被遮挡"：读该 interface 的 `/sys/class/net/<if>/statistics/tx_packets` 在同一窗口内是否增长。
     - tx 在涨而计数不动 → **确认被遮挡**。记 `tc_chain_shadowed`，把该 interface 移出 active 集，并在 `status` 里**点名**同 chain 上 pref 低于 P 的那些 filter（用户在陌生机型上靠这条自证）。
     - tx 也不涨 → 只是没流量，**不作结论**。退避后重试（复用 §10.4 的 timerfd）；到退避上限仍无流量则标注"未验证"并**允许激活**——不能因为用户当时没上网就拒绝服务。
5. 全部 interface 处理完，才做步骤 10 那一次 pointer swap 发布 `active = 1`。

**五条硬约束**：

- 验证全程 `active` **必须**为 0。让流量在"尚未确认能工作"的状态下被捕获，等于拿用户的连接做实验。反过来说，因为 `active == 0`，**卸下探测到挂上 capture 之间的那个微秒级空档是无害的**。
- `flx_verify` **只能**返回 `TC_ACT_UNSPEC`。它是观测器，不是策略。
- `FLUX_CNT_SAW_PACKET` **只由 `flx_verify` 触碰**，capture 与 ingress 程序一行都不许写它。这条是把"零热路径成本"这个性质固定下来的唯一办法。
- handle 用独立的 `0x3`，不复用 capture 的 `0x1`：所有权谓词因此永不混淆两者，而且**验证中途崩溃留下的残留仍然可被精确识别并删除**（§8.7 步骤 3 的清理要认这个 handle）。
- 判定失败**只排除该 interface**，不进 `Inactive`——与 §26 不变量 4 对捕获侧的处置一致。

**它顺带覆盖的其它失效**：attach 到了错误的 parent、interface 已 down 但 filter 还在、以及 chain 上出现了新的、pref 更低的厂商 filter。三者都表现为"tx 在涨而计数不动"。

**再验证**：稳态下若 reactor 收到 `RTM_NEWTFILTER` 且新 filter 的 pref 低于我们，可以在 **P+1** 挂一次探测——若 P+1 可达则 P 必然可达，于是无需动我们自己的 filter 就能确认仍在工作。这是这套设计相对"控制位"方案的额外好处。

**这套机制没有先例，实现时不要指望能抄。** §0.5.10 逐个读过语料里所有 attach TC filter 的项目：**没有任何一个验证程序是否真的执行**。最接近的是 asteriskd，它在 attach 后用 `RTM_GETTFILTER` dump 比对 object id / program tag / bpf name / `da` 标志——但那验证的是**身份**（"我装的那条还在不在、是不是我的"），不是**执行**。被前面的 filter 遮挡时，身份检查会**通过**。两者是不同故障，都要有：身份侧本设计由 §8.5 的所有权谓词 + `RTM_NEWTFILTER` 监视覆盖，执行侧就是本节。

**同时补一条 asteriskd 教给我们的对照**：它遇到自有槽位被外人占用时**直接拒绝启动**（`"foreign TC resource collision"`）。那是"fail closed"，简单且安全，但结果是在三星设备上完全不可用。本设计选择"换个 pref + 实测能否跑到"，能力更强，代价就是必须自己实现本节这套东西。

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
5. 加载 BTF 与 12 个 map、4 个 program（含 §8.5.4 的 `flx_verify` 探测程序）；注册 ringbuf 到 epoll；publish 初始 frozen `active=0` leaf。
6. 解析 `packages.list` 与配置，填充 `uid_policy`、两张 bypass LPM（固定 + 用户 CIDR）与两张 `self_addr` HASH（本机地址，D20）。
7. 生成 effective JSON → `sing-box check` → 启动 child → 等待 4 个 socket 通过 SOCK_DIAG + PID/inode 核验。
8. 在 `flxrs1` 创建 `clsact` 并 attach `flx_in`（**先于** egress，保证回送侧就绪）。
9. 逐个处理可支持的 interface（每个独立，失败只排除该 interface）：按 §8.5.3 dump 该 parent 选出可用 pref → 按 §8.5.4 挂 `flx_verify` 做存活验证 → 通过后卸下探测、在同一 pref 挂 `flx_cap_l2`/`flx_cap_l3`。
10. 最后一次 `control_root` pointer swap，发布完整 generation snapshot 与 `active=1`。**在此之前 `active` 全程为 0，所以第 9 步的验证不会改变任何流量的走向。**

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

## 9.0 一个会让 fakeip 完全失效的地址段冲突

移植旧版 Flux 的 `conf/template.json` 时发现的，**属于设计缺陷而非配置错误**，因为它源于两边各自都合理的选择。

> **已处置（D21，2026-08-25）。** 本节保留为记录：症状是"DNS 正常、应用连得上、什么都打不开"，几乎不可能靠猜诊断出来，所以值得写下来。

sing-box 的 `fakeip` 默认地址段是 `198.18.0.0/15`（v4）与 `fc00::/18`（v6）。而 Flux **当时**的固定 bypass 集（§11.2、D16）包含：

- `198.18.0.0/15` —— 因为 listener 曾绑在 `198.18.0.2`，整段进 bypass 以防自环；
- `fc00::/7` —— 作为 ULA 私有地址段。

**两边完全重叠。** 后果是致命的：fakeip 的全部意义就是让应用连向那个假地址、然后被代理截获；而被 Flux bypass 意味着**那些包根本不会被捕获**。fakeip 会静默地完全失效——DNS 返回假地址，应用连上去，包直连出去，然后什么都连不上。

### 9.0.1 处置

**第一，把 listener 的 bypass 从整个前缀收窄到确切地址。** 原本 bypass 整个 `/15` 与 `/32` 是过度的：防自环只需要"选中 app 不能连上 listener 本身"。这一条独立成立，与 fakeip 无关。

**第二，listener 地址移出 fakeip 的惯用段。** fakeip 用 `198.18.0.0/15` 是这个生态的既成惯例且更早，用户有肌肉记忆；Flux 原先选 `198.18.0.2` 只是"某个不可路由地址"，任意性更高。**该让的是 Flux。** 已改为：

| | 原 | 现 |
|---|---|---|
| v4 listener | `198.18.0.2` | **`198.51.100.1`**（RFC 5737 TEST-NET-2） |
| v4 bypass | `198.18.0.0/15` | **`198.51.100.1/32`** |
| v6 listener | `2001:db8::2` | **`2001:db8:0:1::2`** |
| v6 bypass | `2001:db8::/32` | **`2001:db8:0:1::2/128`** |

v6 的 fakeip 段则**必须由模板避开 ULA**（`fc00::/7` 作为私有地址段的 bypass 是正当的，不该为 fakeip 让路），建议 `2001:db8:f::/48`。

**第三——也是最重要的一条：`fluxd check` 必须交叉校验 `fakeip` 段与 bypass 集是否相交，相交即报错。** 前两条只是把默认值调对；用户随时会改这些地址段，而这个冲突的症状是"DNS 正常、应用连得上、但什么都打不开"，几乎不可能靠猜诊断出来。**自动校验才是真正的解法。**

同类的交叉校验还应覆盖：`fakeip` 段与 `tun` 段（若用户自己加了 tun）、`clash_api` 的监听地址是否为回环、以及用户在 `bypass.files` 里加载的大列表是否意外包含了 fakeip 段。

> **状态：已全部落地（2026-08-25 定稿）。** `bpf/include/flux_abi.h` 的 `FLUX_LISTEN_V4_STR` / `FLUX_LISTEN_V6_STR`、`crates/flux-core/src/abi.rs` 的镜像、`crates/flux-core/src/cidr.rs` 的固定 bypass 清单、以及 `module/template.json` 的 fakeip 段全部已改，`FLUX_ABI_MAGIC` 提到 `0xF10C0903`。第三条的交叉校验属于 `fluxd check` 的实现范围。

## 9.1 注入的 inbound（每 generation 两个，4 个 kernel socket）

| tag | family | listen | listen_port | 说明 |
|---|---|---|---|---|
| `flux-in-v4` | IPv4 | `198.51.100.1` | 随机 `actual4` | `type: "tproxy"`，TCP+UDP |
| `flux-in-v6` | IPv6 | `2001:db8:0:1::2` | 随机 `actual6` | `type: "tproxy"`，TCP+UDP |

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
| `Disabled` | `disable` 文件存在（唯一开关真相源，C9，`docs/spec/interaction.md` §27.1）。不启动 engine、不新建或激活数据面。 |
| `Inactive` | `disable` 文件不存在，但正在启动/重启，或被明确错误阻断。control `active == 0`。 |
| `Active` | control `active == 1`。 |

hot candidate 无效时**保持当前 `Active` generation**并附带 candidate error，不创造第四种持久状态。daemon 重启后只从权威文件重新求值。

## 10.2 类型骨架

```rust
// ---------- flux-core/src/config.rs ----------
pub struct FluxConfig {
    pub apps: Vec<AppSelector>,     // canonical、去重、<= 1024
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
    objs: LoadedObjects,          // 12 个 map + 4 个 prog 的 OwnedFd
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
| inotify | 状态根的 `disable` 开关文件（C9）；`config/` 目录与两个配置文件的原子替换；`/data/system/packages.list` |
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
| `fluxd enable` | 删除 `disable` 文件并请求激活。**只是开关文件的前端**（C9），不是第二个真相源 |
| `fluxd disable` | 创建 `disable` 文件、publish `active=0`、停 engine；daemon 继续等待命令 |
| `fluxd reload` | 触发 policy 与 engine 候选流程 |
| `fluxd stop` | service/uninstall 用：publish `active=0`、停 child、daemon 正常退出（exit 0） |

无 `toggle` 隐藏状态；`action.sh` 先读 `status` 再明确调用 `enable` 或 `disable`。

---

# 第 11 部分：配置与持久状态

## 11.1 唯一权威源

| 路径 | 权威内容 | 失败行为 |
|---|---|---|
| `disable`（状态根直下） | 唯一持久开关：**存在 = 停用，不存在 = 启用**（C9，`docs/spec/interaction.md` §27.1）。由既有 inotify 源监视，运行时立即生效 | 只看存在性，不读内容 |
| `config/flux.toml` | package 选择与 CIDR bypass | cold 无效 → Direct；hot 无效 → 保留当前 |
| `config/sing-box.json` | 唯一用户 engine 配置 | cold 无效 → Direct；hot 无效 → 保留当前 |
| `run/effective-sing-box.<generation>.json` | 对应 child 的一次性 immutable 生成物；事务中最多 current + candidate 两份 | 非权威源；daemon 重启后精确清理并从用户配置重建 |
| `run/daemon.lock` / `run/control.sock` | 单实例与 IPC | — |

不使用 last-known-good 持久副本；不在 TOML 里重复 `enabled`；不从 `module.prop` 推断运行状态；**Flux 从不反写用户配置**。fresh install 默认 disabled（由安装脚本创建 `disable` 文件，§13.2 的职责）。

daemon 冷启动确认没有自己的存活 child 后，只枚举并删除 `run/` 中严格匹配 `effective-sing-box.<u64>.json` 格式且属 root 的普通文件。

权限：状态根与子目录 `root:root 0700`；用户 config、generation effective 文件 `0600`；控制 socket `0600`。

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

硬限：文件 256 KiB；`apps` ≤ 1024；解析后总 UID entry ≤ 4096；IPv4/IPv6 LPM 各 ≤ 65536（**本机地址不占 LPM**，见 D20）；package 字符串与 CIDR 必须 canonical 且无重复。超限是清晰的配置错误，**不截断、不部分应用**。

**固定安全 bypass（硬编码注入）**，权威清单在 `crates/flux-core/src/cidr.rs`：

- IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、`198.51.100.1/32`（listener 本身）、`224.0.0.0/4`、`255.255.255.255/32`
- IPv6：`::/128`、`::1/128`、`fc00::/7`、`fe80::/10`、`ff00::/8`、`2001:db8:0:1::2/128`（listener 本身）

两点说明：

- **listener 只 bypass 确切地址，不是整段前缀**（D21）。原先保留整个 `/15` 与 `/32` 是过度的——防自环只需要"选中 app 不能连上 listener 本身"——而那个过度保留正好和 sing-box 的 fakeip 惯用段重叠，会让 fakeip 静默完全失效（§9.0）。
- **RFC1918 与 ULA 是硬编码 bypass。** 它们是私有地址，代理它们没有意义，且 `ip_is_private` 那类规则在 sing-box 侧也一样会判 direct——在内核里提前放行省掉一次无用的用户态往返（§1.6.2 的同一个理由）。

**动态本机地址 bypass**：reactor 把每个 live 的本机单播地址注入**专用的 `self_addr_v4` / `self_addr_v6` HASH map**，不进 LPM（D20：本机地址永远是全长前缀，用 trie 做精确匹配是浪费；HASH 删除干净；且规避 6.6.0–6.6.46 的 LPM trie 崩溃）。容量 `FLUX_SELF_ADDR_MAX_ENTRIES = 256`，按 `IFA_FLAGS` 过滤并对 IPv6 隐私地址做最久未见淘汰（§1.6.4）。

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

**由 Rust 侧显式创建，不从 ELF 推断。** `fluxd/src/bpf/maps.rs` 用一张常量表描述 12 个 map（清单与顺序见 `flux-core::abi::MAP_NAMES`）的 `map_type`、`key_size`、`value_size`、`max_entries`、`map_flags`、`name`，逐个 `BPF_MAP_CREATE`。这样 C 文件里的 map 定义只是符号占位，参数的唯一真相源在 Rust（并由 `flux_abi.h` 约束 value 布局）。

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

（`u8` 需要一条自己的 `BTF_KIND_INT`；实际实现按 `bpf/include/flux_abi.h` 的最终布局生成。）

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
- BPF：`-Wall -Wextra -Werror` 编译通过；在 CI 的 Linux runner 上实际 `BPF_PROG_LOAD` 到 verifier 通过。

  **在更新的内核上通过，不代表 5.15 的 verifier 会通过。** CI 用的是 `ubuntu-latest`，内核远新于基线，所以这一关只证明"程序在某个现代 verifier 下成立"。**基线 verifier 的证据来自设备**：Phase 3–8 的真机套件在 SM-S9180（5.15.211）上加载同一批程序，那才是 5.15 的一手结论。CI 这一关的作用是早失败，不是终局判据；两者都通过才算数（GOV-4.1 的分层）。

- shell：CI 用 `shellcheck --shell=sh --severity=warning` 检查 `module/*.sh`。**目标运行时是 BusyBox `ash`，而 shellcheck 不是 `ash`**，因此它查的是可移植性问题而非目标解释器的语法接受度；`tools/**` 下的脚本目前不在检查范围内，它们只在开发机与设备上手工执行。
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
4. **只有一份权威架构文档。** 旧设计语料里同一份文件同时规定了三种互不兼容的 attach 策略（PromoteThenAppend / 禁止 DETACH / KD 35 fail-open），实现者照着任一段写都会错（设计审计 P0 #1）；18 个 ADR 的 YAML 状态与正文互相矛盾（P1 #20）。规则：0.9.0 **没有 ADR 目录**，只有一份 `docs/guide/architecture.md`（本蓝图的落地版）。任何第二份文档若与它冲突，删掉第二份，而不是加一句"以后者为准"。

---

# 第 16 部分：Phase 0

> **已移出本文** → `docs/history/phase0.md`。章节编号未变。工具在 `tools/phase0/`。
# 第 17 部分：实施阶段

> **已移出本文** → `docs/plan/implementation.md`。章节编号未变。
>
> 移出的同时**修掉了一个循环依赖**：旧版阶段 0 的退出条件写着「§16 全部关键 seam 通过」，而 §16 的 Q5 / Q7 / Q8 只能由阶段 5–7 产出的代码来测。新版 §17.2 把剩余问题逐条分配给**真正能跑它们的阶段**，每个阶段的退出条件都由该阶段自己满足。

---

# 第 18 部分：从当前仓库过渡

> **已移出本文** → `docs/history/migration.md`。章节编号未变。
>
> 迁移已于 2026-08-25 执行完毕，是记录而非计划；本文只保留约束当前代码的内容。
---

# 第 19 部分：被拒绝的替代方案

> **已移出本文** → `docs/history/rejected-and-deferred.md`。章节编号未变。
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

# 第 21、22 部分：待确认事项与延期项

> **已移出本文** → `docs/history/rejected-and-deferred.md`。章节编号未变。
# 第 23、24 部分：失败矩阵与 status 规格

> **已移出本文** → `docs/spec/failures.md`。章节编号未变。
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
| `enable`（删除 `disable` 文件） | 尝试激活 | 幂等，无操作 | 幂等，无操作 |
| `disable`（创建 `disable` 文件） | 幂等 | 停 engine → Disabled | publish `active=0` → 停 engine → Disabled |
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
- ABI 真相源：`bpf/include/flux_abi.h`；数据面骨架：`bpf/flux.bpf.c`。
- 一手依据索引见同目录 `README.md`。
