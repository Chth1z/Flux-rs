# Flux-rs 0.9.1 增量设计蓝图

- 文档编号：`FLUX-BP-0.9.1-DELTA`
- 状态：**已定稿**（2026-08-29，Asia/Hong_Kong）
- 基线：[`../spec/blueprint.md`](../spec/blueprint.md)，文档编号 `FLUX-BP-0.9.0-FINAL`
- 性质：0.9.1 的**规范性增量合同**，不是 0.9.0 蓝图的副本
- 目标：修正 0.9.0 文档集的冲突、过时推断与实现偏差；不借修订扩大产品范围

## 0. 如何读取这份蓝图

0.9.0 蓝图冻结保留，作为当时设计决策与推理过程的完整记录。实现 0.9.1 时：

1. 先读 `../spec/blueprint.md`；
2. 再应用本文的 `R091-*` 修订；
3. 本文没有提到的 0.9.0 条款继续有效；
4. 同一主题有冲突时，本文优先；
5. ABI 布局与常量仍以 `bpf/include/flux_abi.h` 为准，engine 资产仍以 `engine.lock` 为准。

本文不重新编号 0.9.0 的 §0–§26。每项修订使用稳定编号 `R091-NN`，并列出被覆盖的原章节。后续文档引用应写成“0.9.0 §8.5，经 R091-05 修订”，不能悄悄改变旧章节的历史含义。

### 0.1 版本与实现边界

这些修订以当前已测试实现为事实基线，并明确列出 0.9.1 仍需实施的修正；“事实基线”不表示源码已经满足本文每一项。本文**不修改 0.9.0 的 SemVer、ABI magic、配置 schema 或控制 socket 编码**。因此：

- 0.9.0 蓝图原文不改；
- 当前源码版本仍由 workspace 决定，本文件本身不授权发布 `v0.9.1`；
- 只有实施本文后、通过本文末尾的 0.9.1 验收，才可把 workspace 版本提升到 0.9.1；
- 若实施时发现必须改 `flux_abi.h` 的布局或既有 JSON 字段，必须另立明确修订项并 bump 对应版本，不能把它混进“文档纠错”。

### 0.2 合同层级

| 主题 | 当前真相源 |
|---|---|
| 0.9.1 产品行为、状态机、模块接口 | `../spec/blueprint.md` + 本文；冲突时本文优先 |
| 数据面 ABI 布局与常量 | `bpf/include/flux_abi.h` |
| engine 资产、摘要、ELF 对齐 | `engine.lock` |
| 当前实施状态 | `plan/implementation.md`，不得反向创造产品要求 |
| 真机事实 | `tools/phase0/results/` 与对应设备测试记录 |
| 历史推翻与研究依据 | `../history/review-log.md` |

`../guide/architecture.md`、`../guide/introduction.md`、`../spec/interaction.md` 与 `reference/` 是当前合同的读者投影。它们必须标明目标版本；“以蓝图为准”不是保留冲突的许可证。

---

## R091-01：把 fail-open 改为 admission-bounded 合同

**覆盖**：0.9.0 §2.2、§20；`../guide/introduction.md` 中“任何失败都不会断网”的绝对表述。

0.9.1 的唯一正确表述是：

| 时点 | 失败语义 |
|---|---|
| TCP 尚无不可变 `CAPTURED` decision；当前 UDP datagram 尚未 redirect | `TC_ACT_UNSPEC`，沿 Android 原路径 Direct |
| TCP 已有合法 `CAPTURED` decision | 内部不一致、generation 不匹配或 ingress handoff 失败时 drop/reset，禁止泄漏到真实目的 |
| packet 已 redirect 到 veth | 不能原子撤销 redirect；后续失败允许 drop |
| engine listener 仍存在但 event loop 活锁 | 0.9.1 无 heartbeat，不能自动识别 |

所以用户文档可以说“准入前失败保持 Direct”，不能说“任何失败都不断网”。这是安全边界，不是实现缺陷。

## R091-02：未选应用仍经过极短 TC 热路径

**覆盖**：0.9.0 §14.1 与用户文档中“未选应用从来没被看一眼”的冲突。

未选 UID 的实际成本是一次 TC invocation、`bpf_get_socket_uid()` 和一次 `uid_policy` HASH miss；随后立即 `TC_ACT_UNSPEC`。它不做 packet 解析、不读 control、不进入用户态、不改变 Android 后续 classifier。

面向用户可写“不被接管、不进入代理”，不得写“内核程序完全不会看到它”。

## R091-03：0.9.1 产品范围冻结

**覆盖**：0.9.0 §1.3、§13；§27.1.3、§27.3、§27.4、§27.5；`../guide/introduction.md` 的订阅与 zashboard 默认体验。

**这一项收缩的是 0.9.1 的交付范围，不是永久放弃能力。** 订阅转换（C11）、代理控制面默认体验（C10）与 Flux WebUI（C8）是 0.9.0 §21 的所有者确认项；把它们移出 0.9.1 属于 GOV-1.2 的产品能力边界变化，已由所有者于 2026-08-29 确认：**三项都在后续版本做，0.9.1 不做。** 记录见 `../history/review-log.md` §0.6.1 第 18 行。

0.9.1 范围如下：

- **不包含** `action.sh`。开关就是管理器自己的模块开关（见 R091-04），不需要第二个按钮，也就不受 Magisk v28+ 的 Action 支持限制。
- **包含** `module.prop` 的 `description=` 实时状态显示，由 `fluxd` 重写。
- **不包含** `fluxd subscribe`、订阅转换、远程 rule-set 下载或自动替换用户配置。
- **不包含** Flux WebUI，也不随包下载、托管或默认配置 zashboard。
- 用户可以在自己的完整 sing-box 配置中启用 `clash_api` 或选择任意外部 UI；Flux 只校验非空 secret 与回环监听，不负责下载或生命周期。
- Flux 永不反写 `config/flux.toml` 或 `config/sing-box.json`。安装和升级只在文件缺失时复制 bootstrap 默认值。

### 默认 `sing-box.json` 的形状

**覆盖**：本项初稿"默认只有 direct outbound、direct final route 与两条规则"的极简形状。

默认模板取自原版 Flux 的 `conf/template.json`，两个项目因此对用户呈现同一套形状（DNS 分流、`clash_mode` 规则、远程 rule-set、`PROXY`/`GLOBAL` 选择器）。约束不再是"键要少"，而是四条**默认值必须成立的性质**：

| 约束 | 为什么 |
|---|---|
| 不含 `inbounds` | Flux 注入自己的两个 tproxy inbound，模板 inbound 会与之抢监听（§9.1） |
| 不含 `experimental.clash_api` | 默认值不得开控制端口；原版那份还没有 secret，Android loopback 不按应用隔离 |
| 每个 selector/urltest 至少一个成员 | 空 selector 无法解析，fresh install 会在用户还没编辑时就 `check` 失败 |
| fakeip 的 v6 段不得落在 `fc00::/7` | Flux 把 ULA 整段固定 bypass（私网必须直连），落在里面的 fakeip 会被直连，IPv6 fakeip 静默全废。原版用的 `fc00::/18` 正好踩中，0.9.1 改用 `2001:db8:f::/48`（D21 的 v6 版本） |

`xtask` 的形状校验只检查这四条加上 `sniff`/`hijack-dns` 两条路由规则，不再枚举允许的键——模板其余部分是用户的事。

订阅转换的目标形态沿用 `Flux-original` 的领域知识（URI 列表 → outbound、机场公告条目过滤、按地区分组），该仓库因此保留在 `tools/clone-manifest.md` 里作为后续实现的参考源。但在真正开工那个版本之前，**不得为它预建未使用的 trait、schema registry、`subscribe` 子命令或协议字段**——延期项的正确形态是"到时候按当时的真实需求设计"，不是现在留一组空抽象。

## R091-04：路径、schema 与首次安装状态只有一套

**覆盖**：0.9.0 §11、§13；`../spec/interaction.md` 与 `../guide/introduction.md` 的旧路径/字段。

### 身份与路径

| 项 | 0.9.1 唯一值 |
|---|---|
| module id | `flux_rs` |
| module 目录 | `/data/adb/modules/flux_rs` |
| 状态根 | `/data/adb/flux-rs` |
| 开关 | `/data/adb/modules/flux_rs/disable`，即管理器自己的模块开关 |
| 状态显示 | `/data/adb/modules/flux_rs/module.prop` 的 `description=` |
| Flux 配置 | `/data/adb/flux-rs/config/flux.toml` |
| engine 配置 | `/data/adb/flux-rs/config/sing-box.json` |
| 包内默认 Flux 配置 | `etc/default-flux.toml` |
| 包内默认 engine 配置 | `etc/default-sing-box.json` |
| 仓库内默认 engine 源文件 | `module/template.json`；打包时映射为上一行，不是运行时路径 |

### 开关归属

**覆盖**：0.9.0 §1.1 与 C9 中"运行时开关在状态根"的表述。

开关是 Magisk / KernelSU / APatch 在用户拨动模块开关时自己创建和删除的那个 `disable` 文件。`fluxd` 用已有的 inotify source 监视模块目录，因此**管理器里的开关当场生效，不需要重启**；"下次启动不加载"这层原有语义不受影响。

- `/data/adb/flux-rs/disable` **不再存在**。0.9.1 只有一个开关文件。
- `fluxd enable` / `fluxd disable` 写的就是这同一个文件，命令行与管理器界面不可能不一致。
- Flux 在模块目录里只写 `disable` 和 `module.prop` 的 `description=` 行，绝不创建、移动或删除该目录，也不改 `module.prop` 的其它键。
- `fluxd` 的运行时路径由自身可执行文件位置推导（`<module>/bin/fluxd` → `<module>`），不硬编码 module id，因此改名或旁加载的模块仍监视自己的开关。

这条同时消掉了 0.9.0 "两个 disable 文件互不相干"的解释负担：用户只需要知道一个开关，就是他本来就会用的那个。

### `flux.toml` 唯一 schema

```toml
apps = [
  "0:com.example.browser",
]

bypass_cidrs = [
  "192.168.0.0/16",
  "fd00::/8",
]
```

不存在 `bypass_v4`、`bypass_v6`、`bypass.files`、`.srs` 导入、subscription 或 `enabled` 键。解析时按地址族写入两张 LPM map。

### 状态显示

`fluxd` 把当前状态写进 `module.prop` 的 `description=`，形式是 `<原描述>\n<emoji> [State] <要点>`，其中 `\n` 是字面两字符转义、由管理器渲染成换行。因此管理器的模块列表就是状态面板，手机上没有终端也能看出 Flux 在不在工作。

三条硬约束：**幂等**（重写必须先剥掉上一次追加的状态，否则 `description=` 会无限增长）、**去重**（渲染结果没变就不写文件）、**原子**（同目录临时文件加 `rename`，管理器不会读到半个文件）。写失败只是没有状态显示，绝不允许影响 daemon——这个文件归管理器所有。

### 首次安装

安装器先创建两份配置（仅当缺失），再在模块目录创建 `disable`。因此 fresh install 的状态是 **在管理器里显示为已禁用，且 bootstrap 配置已生成**，不是“未配置”。用户编辑两份 authority file，运行 `fluxd check`，再在管理器里打开模块（或 `fluxd enable`）。

安装器**必须**明确告知这一点。否则用户装完看到模块是灰的，会当成安装失败。升级路径不得重建这个文件：用户开着就保持开着。

## R091-05：TC preference、可达性与 `clsact` 所有权

**覆盖**：0.9.0 §3.4、§8.5、§8.7、§8.9、§12.5、§26；`../guide/architecture.md` 的固定 pref 1；所有“必须是首个 classifier”的表述。

### 每接口动态 preference

| 位置 | preference |
|---|---|
| 普通物理 L2/L3 egress | 按接口 dump 后选择，首选从 2 起；即使 1 空闲也避开 1 |
| 已确认 CLAT `v4-*` egress | 在实际 CLAT filter 之前选择，且严格 `< FLUX_TC_PREF_CLAT_MAX (4)` |
| `flxrs1` ingress | 固定 1；这是 Flux 自有接口 |
| `flx_verify` | 与该接口最终 capture filter 使用相同 pref，独立 handle `0x3` |

实际 pref 必须进入所有权记录与 status。0.9.1 在 `ifaces[]` 增加可选数字字段 `pref`；这是 additive status 字段，不删除/改名既有 JSON 字段，也不需要为唯一 CLI adapter 引入独立 wire version。禁止缓存“整台设备的可用 pref”；同一设备的 Wi-Fi 与 rmnet 可以不同。人类 `status` 输出必须逐接口打印这个值。

### 可达性而非枚举首位

Flux filter 不必是 dump 中第一个 classifier。前置 OEM filter 可以返回 `TC_ACT_UNSPEC`，Q10 已证明 SM-S9180 的 Samsung pref 1 程序在被测流量上继续执行到 pref 2。

激活条件是：

1. 身份和相对排序满足所有权谓词；
2. CLAT 位置满足约束；
3. `flx_verify` 的正向存活验证能在真实 tx 增长窗口内看到 packet；
4. 后续数值更小的 pref（即前置 filter）identity 发生变化时重新验证。

`first_applicable` 这个既有 JSON 字段名在 0.9.1 **保留以避免无关 wire 破坏**，但其合同含义是“该 filter 通过可达性验证且前置 filter 快照未漂移”，不是“dump 中排第一”。人类输出统一写“reachable / 可达”。未来若出现真正的第二个独立客户端，再在一次显式协议升级中改名。

该字段是三态的，**缺席不等于 `false`**：

| 值 | 含义 |
|---|---|
| 缺席 | 尚未得出结论：已 admitted 但 `flx_verify` 未出结果，或连 filter dump 都失败。此时禁止发布任何可达性断言 |
| `true` | 存活验证收到包，或既有自有 filter 通过身份 + 前置快照复核 |
| `false` | 明确判定不可达：链被遮挡、identity 漂移、attach 或 detach 失败 |

`tc_dump_failed` 这类"看都没看到"的情形必须留缺席，不能压成 `false`——这是"只报告已证明的状态"在这个字段上的具体落法。

关键约束：**admission 阶段不得用 dump 位置推断该字段的值。** 按 pref 大小比较得出的“我排第一”正是被本项推翻的旧语义；在 Q10 那台 SM-S9180 上它会给出 `false`，而实测该路径可用。

### `clsact` 所有权

- 物理接口的 `clsact` 由 netd 管理。Flux **不创建、不替换、不删除**。
- 物理接口缺少 `clsact` 时，以 `netd_clsact_missing` 排除；收到 netd 后续 `RTM_NEWQDISC` 再重新 admission。
- 带 shared block、非空 options、未知或重复属性的物理 `clsact` 判 foreign 并排除。
- 只有自有 `flxrs1` 的 `clsact` 由 Flux 创建；其生命周期随 veth 对。
- 对任何接口都禁止 qdisc/chain flush；只按完整 identity 删除自有 filter。

物理 `clsact` 消失是 capture-side drift：若其它 active interface 仍在，只影响该接口且不改变顶层状态；若它是最后一个 active capture interface，则按 R091-10 先发布 `active=0`。两种情况都不由 Flux 抢建 qdisc。

## R091-06：cgroup 事实与禁用结论分开写

**覆盖**：`../guide/architecture.md` 的“root cgroup 当前占满”与 Phase 0 实测冲突。

Phase 0 干净复测时，root cgroup 的 `SOCK_ADDR` attach 列表为空；已加载的 AOSP program 不能等同于“当前已 attach”。系统仍可按运行条件动态 attach，而且祖先 `flags=0` 会阻止安全共存。

因此事实表述改为“观测时为空，生命周期与共存无法由一次快照保证”；产品结论不变：0.9.1 **禁止任何 Flux cgroup BPF attach**，不抢、不替换、不依赖这些槽位。

## R091-07：map、ABI 与已知 6.6 LPM 崩溃

**覆盖**：0.9.0 §1.6、§4、§6、§7、§10.5、§11.2、§12.7；`reference/` 的旧容量。

### 唯一容量

| 对象 | 容量 |
|---|---:|
| `uid_policy` | 4096 |
| 同时 `SELECTED` | 1024 |
| `bypass_v4` / `bypass_v6` | 各 65536，`LPM_TRIE` + `NO_PREALLOC` |
| `self_addr_v4` / `self_addr_v6` | 各 256，精确 HASH |
| `uid_stats` | 4096，`PERCPU_HASH` |

本机地址只进两张 self-address HASH，不进 LPM。policy desired 集必须分别计算 `selected_uids`、用户/固定 LPM 前缀和动态 self-address 集。

`uid_stats` 是 §7 公共约束允许的第二类 per-CPU 状态；“除 counters 外禁止 per-CPU 统计”的旧句由本项覆盖。它只对已捕获 packet 更新，不改变未选 UID 热路径。

### Linux 6.6.0–6.6.46

每份有效策略都会使用固定 bypass LPM，不能只在用户配置“大列表”时 gate。`uname -r` 落在 6.6.0–6.6.46 时：

- 在创建/填充 LPM 前保持 `Inactive`；
- 报告 `unsupported_lpm_trie_kernel:<release>`；
- 不尝试以真实 LPM 操作探测，因为探测本身可能重启设备；
- 这是唯一允许按内核版本字符串拒绝激活的例外，其它能力仍以真实操作为准。

### control leaf 与诊断计数

policy update 不创建新 frozen leaf、不翻转 `active`。`selected_count` 等 control 字段只在下一次合法 leaf 发布时刷新，BPF 程序不得把它们当 policy authority；`status` 从 dataplane 当前集合计算即时计数。旧文中“更新 leaf 但无需新 leaf”的自相矛盾句由本项删除。

### ABI 校验

Rust 镜像以 compile-time `const` 断言约束 size/alignment；`cargo xtask abi-check` 编译 C 探针并逐项比较常量、size 和 offset。普通 `#[test]` 不是 C/Rust ABI 一致性的唯一门禁。

### 必需能力

`BPF_MAP_FREEZE` 与 ringbuf 都是 0.9.1 当前实现合同的一部分，失败时整体 `Inactive`；不维护“无 freeze”或“无 fault ring”第二运行模式。一个实现只有一个 adapter 时，不为假想降级路径扩张接口。

## R091-08：listener 地址与端口只有当前值

**覆盖**：0.9.0 §9.0、§9.1 中残留的旧地址说明；`../history/phase0.md` Q2 的“同端口”旧形状。

| family | listen | port |
|---|---|---|
| IPv4 | `198.51.100.1` | `actual4` |
| IPv6 | `2001:db8:0:1::2` | `actual6`，必须不同于 `actual4` |

两个端口都从 `61000..=65535` 随机选择并在 generation 内固定。固定 bypass 只含 listener 精确 `/32` 与 `/128`，不再包含 `198.18.0.0/15` 或整个 `2001:db8::/32`。

`fluxd check` 校验用户配置里全部 fakeip v4/v6 段与固定 + `bypass_cidrs` 的交集。0.9.1 没有 `bypass.files` 或 `.srs` 来源。

## R091-09：disable、stop 与 uninstall 的同步语义

**覆盖**：0.9.0 §8.8、§10、§13.2、§20、§26；`../spec/interaction.md` 与 `../guide/introduction.md` 的“立即拆除/立即清空”。

| 操作 | 同步完成的事 | 不做的事 |
|---|---|---|
| 在管理器里关掉模块 | 管理器创建开关；inotify 唤醒 daemon，走下一行 | 不需要重启，也不需要 Action 按钮 |
| `disable` | 创建同一个开关；publish `active=0`；终止 engine；daemon 继续运行 | 不 detach TC、不删 veth/rule/route/map |
| `stop` | publish `active=0`；终止 engine；daemon 退出 | 不 flush、不承诺当前 boot 零内核对象 |
| `uninstall.sh` | `stop`，然后删除 `/data/adb/flux-rs` | 不先写 `disable`（开关就在管理器即将删除的模块目录里），不扫描相似路径，不 flush 系统/Flux 网络对象 |
| 卸载后的管理器重启 | 非持久内核对象自然消失 | — |

“立即停用”只承诺新流不再 admission、engine 已停，不等同于“立即拆掉所有对象”。已 admission 的 TCP 在过渡窗口允许 drop/reset，符合 R091-01。

`disable` 文件是 desired-state authority，不是瞬时进程状态的替身。文件刚出现、engine 尚在终止时，顶层可以短暂报告 `Inactive` 并给出 pending warning；engine 已停且收敛空闲后报告 `Disabled`。`Inactive` 只表示当前不满足 `Active`、新流不被准入，**不表示 TC/veth/rule/route/map 已删除**。只有“已清理”或“无残留”这类声明必须由一次新的实际枚举证明。

## R091-10：reactor 顶层状态与 capture-side drift

**覆盖**：0.9.0 §26 的 interface 消失行与不变量 2。

`Active` 同时表示 engine generation 已提交、`control.active=1`，并且至少有一个 physical capture interface 已通过 admission。coverage 仍由逐接口 status 表达，但顶层不能在零覆盖时报告 Active。

- 单个 capture interface 消失、其它 active interface 仍在：只移除该接口，顶层保持 `Active`；该接口流量回到 Android Direct。
- 最后一个 active capture interface 消失：第一个数据面动作是 publish `active=0`，顶层进入 `Inactive`；engine 可以继续运行并等待新 interface。
- 新 interface 后续通过 admission 且 engine readiness 仍成立：重新 publish `active=1`，回到 `Active`。

离开 `Active` 的路径包括：engine generation 切换、核心拓扑漂移、最后一条 capture coverage 消失、engine/fault 事件，**以及显式 `disable`、`stop`、SIGTERM/SIGINT**。所有路径的第一个数据面动作都是 publish `active=0`。policy 事务与仍保有其它 coverage 的局部 capture-side drift 不改变顶层状态。

## R091-11：控制接口与 CLI 不预建未来协议

**覆盖**：0.9.0 §10.3/§10.6；`../spec/interaction.md` 的版本化协议、`explain`、`watch`、`subscribe` 清单。

### socket interface

SEQPACKET 上仍是单行 JSON，六个幂等 request：

```json
{"op":"status|check|enable|disable|reload|stop"}
```

0.9.1 **不新增独立 `wire_version`**。响应已有产品 `version` 与 `abi_magic`，socket 是 root-only 本地接口，当前只有 CLI 一个真实 adapter。等出现第二个独立客户端并产生实际兼容需求时，再定义协议版本；现在不为假想客户端预建 registry/migration framework。

### CLI

| 命令 | 状态 |
|---|---|
| `daemon` | 正式名；`start`、`run` 是同一前台模式的 alias |
| `status [--json]` | 当前状态 |
| `check` | 只读配置/engine 校验 |
| `enable` / `disable` / `reload` / `stop` | 当前控制命令 |
| `bugreport` | 本地生成诊断包；不是 socket request |
| `version` | 输出产品版本、ABI magic 与构建信息 |

0.9.1 没有 `explain`、`watch` 或 `subscribe`。未来命令只有在实现存在时才进入 UX 文档。

`bugreport` 默认脱敏且不含 logcat；只有显式 `--with-logcat` 才加入并发出隐私警告。`--raw` 只关闭地址脱敏，也必须警告。

## R091-12：打包与安装校验采用一条最小路径

**覆盖**：0.9.0 §13；`governance.md` 的逐文件 sidecar hash 与安装资格矩阵。

- ZIP 内容由 `xtask/src/package.rs` 的精确 14 文件 allowlist 决定（原为 15，R091-04 取消 `action.sh` 后减一）。
- engine archive/binary 由 `engine.lock` 的 size + SHA-256 验证。
- 发布物只生成归档级 `SHA256SUMS`；不在 ZIP 内生成逐文件 `.sha256` sidecar。
- `customize.sh` 检查 payload 完整性、arm64、5.15 courtesy floor，识别 manager/runtime mode并设置 owner/mode。
- 不按 root-manager 版本字符串推断 BPF 资格；唯一显式版本边界是 Magisk v28+ 才有 Action 按钮。
- 真正能力在 activation 通过真实 map/program/netlink 操作验证。
- 三管理器 install/boot/action/disable/uninstall/reboot smoke 是发布门禁，不是把复杂资格逻辑塞进安装脚本的理由。

## R091-13：验证状态、计划与历史材料分层

**覆盖**：0.9.0 开头状态表、§15、§18；`docs/README.md`、`plan/implementation.md` 与 `decisions/` 的旧状态。

1. 0.9.0 蓝图里的“定稿时状态”是 2026-08-25 快照，不再当当前进度表。
2. Phase 1–8 的实现和对应 device tests 已进入仓库；当前结论必须记录在 `plan/implementation.md`，不能继续写“功能尚未实现”或“Q3–Q8 全部待做”。
3. CI 的较新 Linux runner verifier 只是回归证据，不能冒充 5.15 基线。5.15 的 verifier/真机结果作为发布证据保留；BPF 变更后必须重新获得基线证据。
4. 0.9.0 §18 是已完成迁移的历史记录。0.9.1 **禁止执行其中删除工作树、删除 `.git` 或重新 `git init` 的步骤**；当前实现工作不依赖那份操作清单。
5. 更正表的唯一位置是 `../history/review-log.md` §0.6；governance/authoring 不再指向已移出的 `../spec/blueprint.md` §0.5。
6. 规范性技术合同是 0.9.0 基线 + 本增量；`../guide/architecture.md` 只是导览，不是第二份权威合同。

## R091-14：深模块与 seam 约束

**新增优化**：把散落在 0.9.0 §5、§10、§12 的边界收束为四个模块接口。这里的“接口”包括调用顺序、不变量、错误模式与性能约束，不只是一组 Rust 方法。

| 模块 | 对外接口 | 隐藏的实现复杂度 |
|---|---|---|
| policy | `authority files + packages snapshot + addresses → DesiredPolicy | exact error` | TOML、UID/shared UID、CIDR canonicalize、固定 bypass、容量检查 |
| dataplane | `converge inactive`、`apply_policy`、`verify/attach interface`、`publish active/inactive`、`status` | rtnetlink identity、BPF loader、map diff、TC liveness、cleanup ownership |
| engine | `validate candidate`、`start/ready`、`terminate`、`status` | immutable effective file、child identity、SOCK_DIAG、deadline、pidfd |
| reactor | 事件输入与 level-triggered 收敛 | epoll、debounce、backoff、事务排序、pending event 合并 |

硬约束：

- raw rtnetlink 只在 `fluxd/src/netlink/`；raw `bpf(2)` 只在 `fluxd/src/bpf/`。
- reactor 不看到 `nlmsghdr`、BPF attr 或 engine JSON 拼接细节。
- dataplane 不解析用户配置；它只接受完整 `DesiredPolicy`。
- policy 和 engine 是两个事务域，失败互不覆盖对方的 authority file。
- 不为单一生产实现创建公开 trait。测试需要替身时优先使用模块内部 seam；只有出现生产 + 测试两个真实 adapter 时才固化接口。
- 测试从上述模块接口断言可观察结果，不跨接口绑定内部步骤。

这四个接口是 0.9.1 评审代码结构的准绳；示例方法名不是新增 ABI。

## R091-15：验证命令必须区分 host 与 device suite

**覆盖**：GOV-4.1 的无条件 `cargo test --workspace`；本文验收中“任意主机都跑全 workspace”的隐含要求。

`flux-core` 的纯逻辑测试必须能在 Windows/Linux 运行；`fluxd` 的若干 integration binary 会直接编译 Linux/Android 的 fd、netlink、libc 与真机路径，不能在 Windows 上冒充可运行。唯一正确的门禁矩阵是：

| 环境 | 必须运行 |
|---|---|
| 任意开发主机 | `cargo fmt --all -- --check`、`cargo test -p flux-core`、`cargo test -p xtask`、`cargo xtask doc-check` |
| Windows | 再运行 `cargo test -p fluxd --bin fluxd`；不得把 device integration 编译失败误报成产品回归 |
| Linux CI | `cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`，并运行其它 workflow gate |
| Android 设备 | 只按对应 env flag/脚本运行 Phase 3–8 device suite，并执行其 cleanup/residual check |

门禁不能靠跳过真正适用的平台来变绿；同样也不能要求一个平台编译明确只属于另一平台的 harness。Linux CI 与 Android 证据仍是发布必需项，Windows host-safe 通过不能替代它们。

---

## 冲突裁决登记表

下表把 0.9.0 文档集里已知冲突全部绑定到一个修订项。历史/证据文档可以保留当时原话，但必须注明它已被哪项修订覆盖。

| 冲突族 | 0.9.1 结论 | 修订 |
|---|---|---|
| 固定 TC pref 1 vs 动态 pref | 每接口动态，避开 1 | R091-05 |
| first classifier vs liveness reachability | 以 `flx_verify` 可达为准 | R091-05 |
| 动态选择了 TC pref vs status 未暴露实际值 | `ifaces[].pref` 增加可选数字字段 | R091-05 |
| `first_applicable` 字段名 vs 实际“可达”语义 | 保留兼容字段名，收窄合同含义；人类输出写 reachable | R091-05 |
| Samsung 示例说 pref 1 遮挡 vs Q10 通过 | 该次实测未遮挡；陌生 OEM 仍需验证 | R091-05 |
| 物理 `clsact` 缺失时创建 vs 排除 | 不创建，等待 netd | R091-05 |
| cgroup 当前占用 vs 干净快照为空 | 快照为空；动态风险仍使 Flux 禁止 attach | R091-06 |
| 绝对 fail-open vs admission 后 drop | admission-bounded | R091-01 |
| 未选 packet 完全不看 vs helper + HASH miss | 后者 | R091-02 |
| disable/stop/uninstall 立即拆除 vs 保留到 reboot | inactive/停 engine，同 boot 保留对象 | R091-09 |
| `Inactive` 被当成“零对象” vs 实际只代表未激活 | 不再暗示 cleanup；无残留声明必须重新枚举 | R091-09 |
| `disable` 文件一出现就必为 `Disabled` vs engine 终止过渡态 | 文件表达 desired state；pending 时可短暂 `Inactive` | R091-09 |
| `action.sh` 有/无 | 无。开关是管理器自己的模块开关，不需要第二个按钮 | R091-03、R091-04 |
| 两个 disable 文件 vs 一个开关 | 只有管理器的 `/data/adb/modules/flux_rs/disable`；运行时那份取消 | R091-04 |
| 管理器开关"下次启动生效" vs 当场生效 | inotify 监听模块目录，当场生效；下次不加载的语义并存 | R091-04 |
| `module.prop` description 是否状态源 | 不是状态源，是状态**显示**；由 `fluxd` 幂等重写 | R091-04 |
| subscription 0.9.x 有/无 | 0.9.1 无；所有者已确认后续版本做 | R091-03 |
| 默认 clash_api/zashboard 下载有/无 | 0.9.1 默认无，用户可自行配置；所有者已确认后续版本做 | R091-03 |
| Flux 是否反写用户配置 | 永不反写 | R091-03、R091-04 |
| module id、配置、模板路径多套值 | 使用 R091-04 唯一表 | R091-04 |
| `bypass_v4/v6` vs `bypass_cidrs` | 仅 `bypass_cidrs` | R091-04 |
| CLI `start/daemon`、`explain/watch/subscribe` | `daemon` + aliases；后三者不存在 | R091-11 |
| UX 自称协议已版本化 vs wire 无版本 | 0.9.1 不设独立 wire version | R091-11 |
| v4/v6 同端口 vs 两个不同端口 | 两个不同随机端口 | R091-08 |
| 旧容量 512/128/64 vs ABI 当前值 | 4096/1024/256 | R091-07 |
| ABI 只靠测试 vs compile-time + xtask | 后者 | R091-07 |
| 逐文件 sidecar hash vs exact allowlist | allowlist + 归档级 SHA256SUMS | R091-12 |
| customize 资格矩阵 vs 最小安装检查 | 最小检查，运行时真实 admission | R091-12 |
| Phase 0 全部先于实现 vs Q3–Q8 分阶段 | 分阶段，当前进度由 plan 记录 | R091-13 |
| CI 必须 5.15 runner vs 当前较新 runner | 新 runner 只回归；5.15 另作发布证据 | R091-13 |
| `webroot` 计划 vs package 禁止 WebUI | 0.9.1 的 allowlist 禁止 `webroot` | R091-03、R091-12 |
| listener 旧/新地址 | R091-08 当前值 | R091-08 |
| self-address 64/取消/256 | 独立 HASH，各 256 | R091-07 |
| 本机地址误写进 LPM desired | 独立 self-address HASH | R091-07 |
| `bypass.files`/`.srs` 残留 | schema 不存在 | R091-04、R091-08 |
| frozen leaf policy 更新自相矛盾 | status 即时，leaf 计数延后刷新 | R091-07 |
| `uid_stats` 与“禁 per-CPU”冲突 | 明确允许现有两类 per-CPU 状态 | R091-07 |
| 最后接口消失是否离开 Active | 离开；先 publish inactive，engine 可继续等待 | R091-10 |
| blueprint vs architecture 谁权威 | 基线 + delta 权威，architecture 仅导览 | R091-13 |
| freeze/ringbuf 可选 vs 固定对象集 | 0.9.1 必需，失败 Inactive | R091-07 |
| fresh install Disabled vs“未配置” | Disabled 且 bootstrap 已生成 | R091-04 |
| logcat 默认开/关 | 默认不含，`--with-logcat` 显式开启 | R091-11 |
| 决策表仍写 Q1–Q9 待做 | 当前状态从 plan/测试证据读取 | R091-13 |
| introduction 仍称未实现 | 改为 pre-release validation | R091-13 |
| 更正表位置 §0.5/§0.6 | `../history/review-log.md` §0.6 | R091-13 |
| 0.9.0 §18 的破坏性迁移步骤 | 历史记录，0.9.1 禁止执行 | R091-13 |
| governance 无条件要求任意主机跑 workspace tests vs Windows device suite 不可编译 | host-safe / Linux CI / Android 分层 | R091-15 |

---

## 0.9.1 文档与实现验收

0.9.1 文档修订完成必须同时满足：

1. `docs/spec/blueprint.md` 的 clean-filter blob 与 0.9.0 `HEAD` 保持一致；
2. `docs/README.md` 明确基线 + 增量的读取顺序；
3. 所有当前读者文档标明 0.9.1，并与 `R091-*` 一致；
4. evidence/verification 的历史原话若保留，旁边注明当前修订，不冒充现行合同；
5. `cargo xtask doc-check` 通过；
6. `rg` 不再在当前文档中发现无注释的固定物理 pref 1、`bypass_v4/v6` schema、`fluxd subscribe`、默认 zashboard 下载、物理 `clsact` 自建或立即 teardown 承诺；
7. 若只改文档，先通过 R091-15 的当前主机门禁；Linux CI 的 `cargo test --workspace` 与 Android device suite 仍在合并/发布前执行；
8. 发布 `v0.9.1` 前仍须完成 0.9.0 §20 未被本文覆盖的全部 release gate。
