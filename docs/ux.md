# 交互与使用体验设计

规范性技术合同在 `docs/blueprint.md`。本文只管**用户看到什么、能做什么、出问题时怎么自救**。

文档语言按 `docs/authoring.md` §7：中文为主，专有名词与有歧义处保留英文原文。

---

## 0 设计取向

这是一个 root 模块，用户是主动来找它的。**不做迎合式的引导，做透明和可控。**

目标按优先级排序，冲突时按此裁决：

**① 不能把设备弄成没网 → ② 用户能知道现在是否真的在工作 → ③ 出问题时能自己查出原因 → ④ 配置直观 → ⑤ 功能丰富。**

第 5 位是最后一位。一个只代理 3 个 app 但状态永远诚实的产品，比一个功能全面但用户搞不清有没有生效的产品好。

---

## 1 开关：`disable` 文件

### 1.1 机制

```
/data/adb/flux-rs/disable        存在 = 停用，不存在 = 启用
```

`fluxd` 用**已有的 inotify 源**（§10.1）监视这个文件，出现即 publish `active=0` 并拆除对象，消失即重新收敛。**不新增任何机制**，复用 reactor 已经有的东西。

三条性质：

- **状态天然持久。** 文件在磁盘上，重启后语义不变，不需要另一份"上次是开还是关"的记录。
- **`flux.toml` 里没有 `enabled` 键。** 开关只有一个真相源。两处都能改的开关必然会分叉。
- **`fluxd` 死了不影响安全。** 没有 daemon 就没有捕获（fail-open，§2.2.1），单实例 flock 由内核在进程死亡时释放（§11.2）。

### 1.2 与管理器的 `disable` 分开

`/data/adb/modules/flux-rs/disable` 是**管理器的**文件，语义是"下次开机不加载这个模块"。它被设置时 `service.sh` 根本不会运行，所以不需要我们处理。

我们自己的 `/data/adb/flux-rs/disable` 是**运行时**开关，立即生效。两者不冲突，也不要互相写。

> **这一点比参考项目做得好。** Vector 与 NeoZygisk 都只在 daemon 启动时读一次模块的 `disable`（`NeoZygisk/zygiskd/src/zygiskd.rs:236`），改了要重启。我们靠 inotify 做到运行时生效，代价为零——因为 reactor 本来就在监视配置文件。

### 1.3 不做 `action.sh`

按项目所有者决定。记录一下取舍以备将来重估：`action.sh` 能提供一键开关和 `module.prop` 里的状态行（`description` 会在脚本结束后被管理器重读），是唯一零操作可见的状态出口；但它要求 Magisk ≥ v28.0，且在三个管理器上行为不一致。

**如果将来要加，它应当只是 `disable` 文件的一个前端**（`touch`/`rm` 那个文件），不能成为第二个真相源。

---

## 2 配置

### 2.1 两个文件，职责不重叠

```
/data/adb/flux-rs/
├── disable                  开关（存在即停用）
├── config/
│   ├── flux.toml            Flux 自己的配置：选哪些 app、bypass 网段
│   └── sing-box.json        engine 配置（由 template.json 派生）
└── run/                     daemon.lock、control.sock、effective 生成物（§11.1）
```

**分界线是清晰的**：`flux.toml` 管"抓谁"，`sing-box.json` 管"抓到之后怎么走"。Flux 不解析代理规则，sing-box 不知道 UID 分流（§1.4）。

### 2.2 `flux.toml` 面向手编

因此：注释即文档；字段名用完整单词不用缩写；**拒绝未知键并指出最接近的合法键名**。

最后一条不是锦上添花。拼错一个字段而静默失效，是配置文件最恶劣的失败模式——用户会以为自己配对了，然后困惑为什么没生效。

```toml
# 选中的应用。格式为 "userId:packageName"，单用户设备 userId 恒为 0。
# 共享 UID 会连带捕获同 UID 的其它应用，check 时会列出来。
apps = [
    "0:com.example.browser",
]

# 额外不走代理的目的网段。回环、链路本地、多播与 listener 保留段
# 已经无条件 bypass，不需要在这里重复（见 blueprint §11.2）。
bypass_v4 = ["192.168.0.0/16"]
bypass_v6 = []
```

### 2.3 `template.json`：随模块分发的 engine 模板

模块自带 `etc/template.json`，首次启动时若 `sing-box.json` 不存在则复制过去。

**模板的契约**（§9.1 已规定，这里明确到模板层面）：

| 模板**必须**包含 | 模板**不得**包含 |
|---|---|
| `outbounds`：至少一个占位出口 + `direct` | **任何 `inbounds`** —— Flux 独占注入两个 tproxy inbound |
| `route`：含 `sniff` 与 `hijack-dns` 两条规则 | `inbounds` 相关的任何配置 |
| `dns` | 任何 Flux 需要控制的键（§9.1 的保留键清单） |
| `experimental.clash_api`（见 §3） | |
| `log` | |

`fluxd check` 会校验这两条。用户在模板里加 inbound 是**明确的错误**，不是警告——因为它会与 Flux 注入的 inbound 抢端口。

---

## 3 代理控制面：clash_api + zashboard

### 3.1 分工

Flux **不做**代理控制面。sing-box 自带 `clash_api`，zashboard 是成熟的 Clash API 前端。节点、规则、延迟测试、流量图全部归它们，Flux 一行都不碰（这也是 §22.3 拒绝"自有 Clash 代理层"的原义）。

模板里默认开启：

```json
"experimental": {
  "clash_api": {
    "external_controller": "127.0.0.1:9090",
    "secret": "<首次启动时生成>",
    "external_ui": "ui",
    "external_ui_download_url": "https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip"
  }
}
```

### 3.2 一个必须处理的安全问题

**Android 的 loopback 没有按 app 隔离。** 设备上**任何**应用都能连 `127.0.0.1:9090`，不需要任何权限。所以：

- **`secret` 是必需的，不是可选项。** 没有 secret 的 clash_api 等于让任意 app 能改你的代理配置、切换出口、读取连接列表（含访问过的域名）。
- secret 必须**首次启动时随机生成**并写入 `sing-box.json`，**不能**有一个文档里的默认值——那等于没有。
- `external_controller` 必须绑 `127.0.0.1`，**绝不能**是 `0.0.0.0`。后者会把控制面暴露到同一 Wi-Fi 下的所有设备。
- `fluxd check` 应当在检测到空 secret 或非回环监听地址时**报错**，不是警告。

> 这一条在同类项目里被普遍忽视。它值得写在 README 而不只是这里。

### 3.3 zashboard 的下载归 sing-box

`external_ui_download_url` 由 sing-box 自己处理，**Flux 不介入**：不打包、不代理下载、不校验、不管版本。

这是一条清晰的责任边界。模板里写好 URL，之后就是 sing-box 与用户之间的事。我们只负责一件相关的事：确保 §3.2 的 `secret` 存在且 `external_controller` 绑在回环——否则下载来的 UI 会成为任意 app 都能用的控制入口。

---

## 4 订阅：取回、转换、校验

`blueprint.md` §22.2 已把订阅列为延期项并规定了 seam：`fluxd subscribe` → 抓取 → 校验 → **原子替换 `sing-box.json`** → 走既有的 engine 候选事务（§10.5）。这里补上一个**明确的边界**。

### 4.1 一处更正：我先前搞错了"转换"的范围

我原先建议**不做**转换，理由是"格式转换是没有底的维护坑"。**那个判断基于对范围的误解，已撤销。**

我当时想的是 Clash YAML → sing-box JSON 这类**跨配置格式**的翻译——那确实要同时追机场私有字段、上游 schema 演进和 sing-box 自身变化三条曲线。

但这个生态里"订阅"实际指的是另一件事：**一份 base64 编码的 `scheme://` URI 列表**。读旧 Flux 的 `scripts/updater.sh` 确认了这一点——它支持 `vmess` / `ss` / `vless` / `trojan` / `hysteria` / `hysteria2` / `tuic` / `socks` / `http` / `snell` 十种 URI，并在检测到内容已经是 sing-box 格式（`.outbounds` 是数组）时直接跳过解析。

**这是有界问题**：十个稳定的、有公开定义的 URI scheme，不是格式动物园。所以转换要做。

### 4.2 三个阶段

| 阶段 | 归属 | 内容 |
|---|---|---|
| **取回** | `fluxd` | HTTP GET（带重试与超时）；自动识别并解码 base64 |
| **转换** | **`flux-core`** | URI 列表 → outbound 结构；精修；分组；并入模板 |
| **部署** | `fluxd` | `sing-box check` → 原子替换 → §10.5 的 engine 候选事务 |

**转换整个放在 `flux-core` 里，这是它最好的一次自证。** 那个 crate 的约束是"纯逻辑、无 libc、无 syscall、任何主机都能测"（§5）——而 URI 解析、正则过滤、JSON 组装恰好完全符合。含义是**订阅转换可以在 Windows 上跑单元测试，不需要设备、不需要网络**。

用 Rust 重写而不是移植 shell，理由很具体：旧实现用 awk 手写了 base64 解码器（`updater.sh:175-193`）、用正则从 JSON 里抠字段（`get_json_val`，`:204-222`）、手写了 URL 解码（`:224-245`）。这三件事在 Rust 里都是库调用，而每一个手写版本都是 bug 来源。

### 4.3 节点精修：这部分是领域知识，要照搬

旧实现的 jq 管线做了六件事，**每一件都对应真实痛点**，不是过度设计：

1. **剔除基础设施条目**：`selector` / `urltest` / `direct` / `block` / `dns` 不是节点。
2. **按正则排除伪节点。** 机场会把公告塞进节点列表当成假节点。旧实现的默认正则值得直接沿用：`(expire|traffic|官网|到期|流量|剩余|套餐|重置|联系|群组|通知|平台|网站|时间|建议|反馈|版本|更新)`。**这是这份配置里最有价值的一行**，没有它用户的节点列表里会混进一堆不能连的条目。
3. **重命名规则**（用户可配的 match/replace 列表）。
4. **可选剥离 emoji**（国旗与杂项符号）。
5. **归一化倍率写法**：`$2.0`、`2.0倍率`、`2.0X` 一律成 `2.0x`；压缩连续空格。
6. **限制 tag 长度**（默认 32），超长截断加省略号。

然后**按地区分组**：用正则匹配 tag 判定国家/地区，填进模板里空的 `selector`。旧实现内置 30 个地区的正则表（`updater.sh:60-91`）。这张表是**数据不是代码**，在 Rust 里应当是一张 `const` 表或一个可覆盖的配置文件。

### 4.4 无论如何要有的保护

- 转换后**必须先过 `sing-box check`** 才允许替换。校验失败 → 保留旧配置、报错、**不切换**。
- 还要检查**非基础设施 outbound 数量 > 0**。旧实现有这一条（`updater.sh:411-418`），它抓的是"取回成功但内容是一个错误页面"这种情况——此时 JSON 合法、`check` 也可能通过，但一个节点都没有。
- 替换必须**原子**（写临时文件 + `rename`），因为 reactor 在用 inotify 监视这个文件（§10.4）。
- 新配置启动失败 → 按 §9.4 回退到上一个可用 generation。**订阅更新不能把用户的网络搞没。**
- 内容与当前配置**逐字节相同就跳过部署**，避免无谓地重启 engine。

### 4.2 无论如何要有的保护

- 取回的配置**必须先过 `sing-box check`** 才允许替换。校验失败 → 保留旧配置、报错、**不切换**。
- 替换必须是**原子的**（写临时文件 + `rename`），因为 reactor 在用 inotify 监视这个文件（§10.4）。
- 新配置启动失败 → 按 §9.4 回退到上一个可用 generation。**订阅更新不能把用户的网络搞没。**

---

## 5 CLI：控制协议就是预留的接口

### 5.1 这个问题已经解决了

关于"预留 CLI 控制接口"——**它已经在设计里了**。§10.3 规定控制面是 **版本化 JSON over `SOCK_SEQPACKET`**，root-only（`SO_PEERCRED` 校验）。

这意味着：

- `fluxd` 命令行是这个协议的**第一个客户端**，不是唯一客户端。
- 将来的 WebUI、TUI 面板、独立 App **全部是新客户端**，协议不需要改造（§22.2 已如此记录）。
- 协议带版本号，daemon 遇到不认识的版本**拒绝而不是猜**。

所以要做的不是"预留接口"，而是**把这个协议当成公开 API 来维护**：字段规格在 §24，加字段可以，改语义要 bump 版本。

### 5.2 命令集

| 命令 | 用途 |
|---|---|
| `fluxd status` | 人类可读状态 |
| `fluxd status --json` | 机器可读（§24 规格），未来 UI 的数据源 |
| `fluxd check` | 只校验配置与能力，不改状态 |
| `fluxd reload` | 重读配置并收敛 |
| `fluxd explain <目标>` | 诊断，见 §5.3 |
| `fluxd bugreport` | 收集诊断包，见 §6 |
| `fluxd subscribe <url>` | 订阅更新（§4） |

**`enable` / `disable` 子命令只是开关文件的前端。** 开关的唯一真相源是 `disable` 文件（§1.1）；这两个子命令按 `blueprint.md` §10.6 存在（`uninstall.sh` 依赖 `fluxd disable`），但它们做的**只是**创建/删除那个文件——与 §1.3 对未来前端的要求一致，不构成第二个真相源。`status` 会在被停用时明确写出"由 /data/adb/flux-rs/disable 停用"，并给出删除它的命令。

### 5.3 `explain`：本设计最重要的一个命令

这个产品有七条公开的不可消除边界（§2.2.3）。用户一定会遇到"这个 app 为什么没走代理"。没有 `explain`，答案只能靠猜。

`fluxd explain <package|uid|interface>` **按判定顺序输出，在第一个否决处停止并说明**：

```
$ fluxd explain com.example.app

应用            com.example.app
UID             10287（用户 0）
是否选中        是
共享 UID        否

当前接管路径
  wlan0         未接管 —— 位置被占用
                我们的程序在 TC egress pref 2，但 pref 1 上的
                prog_semUidBPF_schedcls_egress_tsm_ether 终止了处理链。
                存活验证：接口发出 12043 个包，我们的程序收到 0 个。
  rmnet_data0   已接管 —— pref 2，存活验证通过

已知不会被接管的情况
  · 该应用经 DownloadManager 下载的流量（归属为下载器的 UID）
  · 该应用走 VPN 时的流量（当前无 VPN）
  · 加密 DNS（当前 Private DNS = opportunistic，明文查询会被接管）

结论
  Wi-Fi 下不生效，蜂窝下生效。原因是厂商程序占位，不是配置问题。
```

三条设计要求：

- **只报事实与实测值，不猜。** "发出 12043，收到 0" 比 "可能被遮挡" 有用得多。
- **列出"已知不会被接管的情况"**，即使当前没触发。这是把 §2.2.3 从文档搬到用户眼前的唯一办法。
- **区分"配置问题"与"环境限制"。** 前者用户能改，后者不能。混在一起会让用户徒劳地反复改配置。

### 5.4 CLI 面板（TUI）：建议不做，改进 `status`

一个 ratatui 之类的 TUI 面板要引入新依赖和相当量的渲染代码，而它能提供的信息 `status` 已经能给。

**建议的替代**：`fluxd status --watch`，在 `status` 的基础上定时重绘。约 30 行，无新依赖，覆盖"我想盯着看它是否正常"这个真实需求。

真正的图形化需求应该由 §5.1 的协议交给未来的 WebUI，而不是在终端里做一个半成品。

---

## 6 诊断包：`fluxd bugreport`

这是从 Vector 学来的、我认为最值得抄的一条实践。Vector 的 `FileSystem.getLogs`（`Vector/daemon/.../FileSystem.kt:524-625`）把用户报告问题的质量提升了一个量级：**一键生成一个包含所有排查所需信息的压缩包**。

`fluxd bugreport` 输出 `flux-rs-bugreport-<版本>-<提交>-<时间戳>.zip`，内含：

| 内容 | 为什么 |
|---|---|
| `status --json` + 全部 interface 的 `explain` | 我们自己的状态判断 |
| 构建标识：版本 + git commit + 是否 debug 构建 | Vector 的做法：把构建身份写进**压缩包注释**，文件名被改了也还在 |
| `observe.sh` 的输出（脱敏后） | 设备实际长什么样，见 `tools/phase0/` |
| 内核版本、`/proc/config.gz` 的相关项 | 能力判定的依据 |
| `tc qdisc/filter show` 全量、`ip rule`、`ip route show table all` | §8 的对象状态与冲突判定 |
| `bpftool prog/map show`、`bpftool net show` | 谁占了什么 |
| per-CPU counters 快照 | §6 的计数器，判断数据面是否在动 |
| `/data/adb/modules/*/module.prop` 与 `disable` | 模块冲突 |
| `logcat -b all -d` 的 Flux 相关行 + `dmesg` | 内核侧报错 |
| `fluxd` 自己的日志 | |

**必须默认脱敏**，规则与 `tools/phase0/observe.sh` 共用同一套过滤（`governance.md` §2.3）：地址主机部分、MAC、序列号一律掩掉。`--raw` 可关闭，但要在输出里警告。

**issue 模板要求附这个包，没有就关闭 issue。** Vector 明确这么做（`bug_report.yml:77`），理由是省下的是双方的时间。

---

## 7 第一次使用

装完模块重启后，`sing-box.json` 由 `template.json` 生成，`flux.toml` 是带注释的空选择。状态是"未配置"——**这不是错误状态**。

引导路径只有一条，写在 README 与 `flux.toml` 的注释里：

1. 编辑 `/data/adb/flux-rs/flux.toml`，把要代理的应用加进 `apps`。
2. 编辑 `/data/adb/flux-rs/sing-box.json` 填好出口（或 `fluxd subscribe <url>`）。
3. `fluxd check` 确认配置无误。
4. `fluxd reload`。

**不做**开机弹窗、通知、引导流程。

---

## 8 出问题时怎么自救

**最高优先级的体验要求**，因为最坏情况是设备没网而用户手上没有电脑。

### 8.1 设计上的保证

| 保证 | 出处 |
|---|---|
| 未入场的失败一律走直连，不影响上网 | §2.2.1 fail-open |
| `active` 未发布前不改变任何流量走向 | §8.5.4 |
| 全局 sysctl 永不被写 | §8.4 |
| `clsact` qdisc 永不删除（不破坏 tethering / CLAT） | §8.5 |
| 单实例锁由内核在进程死亡时释放 | §11.2 |
| 订阅更新失败回退到上一个可用 generation | §9.4 |

### 8.2 恢复路径，按代价从低到高

1. **`touch /data/adb/flux-rs/disable`** —— 立即停用，不需要重启。
2. **在管理器里禁用模块**并重启。
3. **卸载模块**。`uninstall.sh` 必须清理模块目录**之外**的全部状态：TC filter（不是 qdisc）、`ip rule`、路由表项、per-device sysctl、veth（§13.2）。
4. **Magisk 安全模式 / KernelSU 关闭全部模块**。设备必定恢复。

**第 1 条和第 4 条必须写进 README。** 前者是日常，后者是最终保证——用户需要事先知道它存在。

### 8.3 一条明确的非目标

**不实现"网络看门狗自动回滚"。** 理由与 §2.2.3(3) 拒绝 heartbeat 同源：判断"网络是否正常"需要主动探测，而探测本身会产生流量、需要选择探测目标、并在离线时误判。**一个会误判的自动回滚比没有更糟**——它会在用户正常使用时把代理关掉。

代替方案是把上面四条恢复路径写清楚、让状态永远诚实。

---

## 9 刻意不做

| 不做 | 理由 |
|---|---|
| 自有代理控制面（节点/规则/延迟测试） | clash_api + zashboard 已经成熟，重复造只增加攻击面（§22.3） |
| 跨配置格式的订阅翻译（如 Clash YAML → sing-box） | 那才是没有底的维护坑。URI 列表 → outbound **要做**，见 §4.1 的更正 |
| 打包或代理下载 zashboard | 归 sing-box 的 `external_ui_download_url`（§3.3） |
| WebUI | 已搁置。协议已预留（§5.1），将来做是纯增量 |
| TUI 面板 | §5.4，`status --watch` 覆盖真实需求 |
| `enable`/`disable` 子命令 | 会成为开关的第二个真相源（§5.2） |
| 网络自动回滚看门狗 | §8.3 |
| 开机通知 / 常驻通知 | 需要 App 或 binder 依赖 |
| 按域名/规则选择应用 | sing-box 的职责，Flux 只做 UID 粗分流（§1.4） |
| 安装时禁用其它代理模块 | 过于激进。冲突应当**检测并报告**，不是替用户处置 |

---

## 10 已确认的决定（2026-08-25）

| 项 | 决定 |
|---|---|
| WebUI | **搁置**。控制协议已是预留接口（§5.1），将来做是纯增量 |
| 开关 | **`disable` 文件** + inotify，无 `action.sh` 按钮（§1） |
| 配置 | 用户直接编辑 `flux.toml`；`template.json` 随模块分发（§2） |
| 代理控制面 | **clash_api + zashboard**，下载归 sing-box（§3.3） |
| 订阅 | **做转换**：URI 列表 → outbound，放在 `flux-core`（§4） |
| `explain` 深度 | **暂按现在这样**，实测数字直接给用户（§5.3） |
| 文档语言 | 中文为主，专有名词保留英文（`authoring.md` §6） |

**仍然开放的只有一件**：`fluxd bugreport` 的诊断包要不要包含 `logcat`。它信息量最大，但也最可能夹带其它 app 的隐私数据，脱敏很难做全。倾向默认**不**包含，用 `--with-logcat` 显式开启并在输出里警告。
