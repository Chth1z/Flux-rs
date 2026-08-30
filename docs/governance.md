# 项目治理手册

本文规定 Flux-rs 怎么被开发和维护。它约束的是**过程**，不是技术方案——技术合同是 `docs/spec/blueprint.md`，唯一一份，就地编辑（AUTH-7.2）。

写这份手册的前提是一个具体分工：**日常技术决策由负责实现的人（当前是 AI agent）做，项目所有者只在下面 GOV-1 列出的情形被打扰。** 这份手册的价值全部取决于 GOV-1 那条线画得准不准；画得太保守会把所有者变成瓶颈，太激进会让不可逆的事在没人同意时发生。

---

## GOV-1 决策权划分

### GOV-1.1 我自己决定，不问

- 任何**可逆**的技术选择：模块划分、命名、数据结构、算法、错误处理形态。
- **推翻我自己此前写下的结论**。0.9.0 设计期已有多次实例（`skb->mark` 的 scrub 语义、`bpf_redirect_peer` 的可用性、重定向到 `lo` 的失败原因、cgroup 槽位是否常驻占用）。发现自己错了就按 GOV-3 的版本化更正协议留痕，不需要请示。
- 只读的设备观测（`tools/phase0/observe.sh` 那一类）。
- 本地 commit。

### GOV-1.2 必须先问所有者

| 情形 | 为什么 |
|---|---|
| **不可逆的操作**：删库、force-push、删除远端仓库、删除工作树、`git commit --amend` 已有 commit | 无法撤销，且代价由所有者承担 |
| **改所有者的开发机**：安装工具链（LLVM/NDK）、改全局配置 | 那是他的机器，不是项目的一部分 |
| **改测试设备的持久状态**：装/卸模块、开关 VPN、写全局 sysctl、留下不会自动清理的对象 | 那是他的日用机 |
| **Phase 0 断言失败导致的范围变更** | 见 GOV-5，这是产品能力边界的变化 |
| **产品行为的取舍**：默认值影响用户可见行为、公开的能力边界、要不要放弃某类设备 | 这些是产品决定，不是工程决定 |
| **引入新的第三方依赖** | 供应链与许可证面 |
| **任何会公开可见的内容**：仓库描述、README 的对外表述、发布说明 | 对外表达 |

### GOV-1.3 问的方式

给**结构化的选项**，不要给开放式问题。每个选项写清代价，推荐项放第一并标注。所有者的时间应该花在选择上，不是花在理解上。

反面例子：「TC pref 怎么处理？」
正面例子：「pref 1 被厂商占了。① 动态选 pref + 存活验证（推荐，代价是要自己实现无先例的机制）；② 像 asteriskd 那样拒绝启动（简单，代价是三星设备完全不可用）；③ 只支持 6.6+ 用 TCX（干净，代价是放弃大部分存量设备）。」

---

## GOV-2 证据纪律

这是本项目最容易出错的地方，因为它的结论大量依赖对 AOSP、内核、厂商行为的断言。

### GOV-2.1 每条事实必须能追到来源

写进设计的任何断言，必须能指到三者之一：

1. **源码**，带 `文件:行号`。内核源要带版本（`v6.1 net/core/filter.c:2144`），因为语义会变。
2. **实测**，带设备、内核版本、日期，并存进 `tools/phase0/results/`。
3. **推理**，且**必须显式标注为推理**，并写清它依赖哪些前提。

三者之外的东西（记忆、类比、"一般来说"）**不进设计文档**。

### GOV-2.2 实测结论必须分层

按 `history/phase0.md` §16.3 的五层分类：AOSP 源码强制 / GKI 强制 / SoC 厂商 / OEM / 用户运行时。**把 OEM 层的观察当成普适事实，是这份设计最容易犯的错**，已经犯过一次（"egress pref 1 是我们的"）。

新机型跑完探针后，结论必须先归层再写进文档。

### GOV-2.3 设备测试的规矩

| 规矩 | 理由 |
|---|---|
| 只读探针与会改状态的测试**分开成不同脚本** | 前者可以随便跑，后者需要 GOV-1.2 授权 |
| 会改状态的脚本**必须有 cleanup trap**，覆盖正常退出、异常、`INT`、`TERM` | 测试中断不能留下垃圾 |
| 会改状态的脚本**必须在开头写明 blast radius** | 让人能在批准前判断风险 |
| 输出**默认脱敏**，提交前审计 | 旧仓库把设备序列号提交进了 git 历史（F-07） |
| 脱敏规则**禁止依赖 `\b`** | toybox 的 `sed -E` 不支持词边界且**静默失效**，已因此泄漏过一个地址 |
| 实测结论与预期不符时，**先怀疑测试方法** | 已发生：探针报「无 filter」而 `bpftool` 报「已 attach」，根因是厂商晚到 + 工具差异 |

### GOV-2.4 「无先例」要显式写下来

查过同类项目、确认某个做法没人做过，**要在文档里写明**。宁可知道没有先例（于是自己承担风险、加倍验证），也不要以为有人解决过。动态选 TC pref、执行存活验证、TCX 相对定位的检索记录见 `history/review-log.md` §0.5；当前合同见 §8.5。

---

## GOV-3 更正协议

设计期推翻自己会反复发生。**结论对但理由错，比结论错更危险**，因为下一个决策会建立在错误前提上。

发现此前的结论有误时：

1. **就地改正**，包括 `spec/blueprint.md`，不要在文末堆勘误，也不要另写一份增量文档描述差异（AUTH-7.2）。章节号保持不动。
2. 在 `history/review-log.md` §0.6 的对照表里加一行：**原说法 / 实际 / 处置**。这是"为什么改"的唯一的家；"改了什么"由 `git log -p` 回答。
3. 如果被推翻的是一条编号决策（`DN` / `CN`），把它在 §0.3.0 或 §21.0 状态登记里改成 `superseded` 并写明取代者。已取代的决策不得再被当作现行合同引用。
4. 如果原来的**结论**仍然成立而只是**理由**错了，必须写明——并说清正确的理由。例：`skb->mark` 那条，结论「不用 mark 传信息」不变，但理由从「传不过去」换成「不需要 + 不愿占 fwmark 位」。
5. 扫一遍所有引用该结论的地方。用 `rg` 搜关键词，不要靠记忆。
6. commit message 说明推翻了什么、依据是什么。

**不要**为了显得一致而保留错误的论证。

---

## GOV-4 验证门

### GOV-4.1 每次 commit 之前

**验证按运行平台分层；不能要求 Windows 编译 Linux/Android device harness，也不能用 Windows 的 host-safe 结果替代 Linux CI 与真机证据（§15.1）。**

任意开发主机先跑：

```bash
cargo fmt --all -- --check
cargo test -p flux-core
cargo test -p xtask
cargo xtask doc-check
```

加跑 `cargo test -p fluxd --bin fluxd`。它当前**不含测试用例**，作用是把 `fluxd` 的 host-safe 子集编一遍——在 Windows 上这是唯一能碰到那份代码的门禁，所以列在这里；不要把它的绿色当成 daemon 有测试覆盖。

Linux CI 必须额外通过：

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Android-only Phase 3–8 suite 按对应 env flag/脚本在设备上执行，且必须通过 cleanup/residual check。适用门禁全绿才提交或合并。`clippy` 的告警不允许用 `#[allow]` 绕过，除非在同一处写清为什么这条规则在这里不适用。

### GOV-4.2 改了 ABI 之后

`bpf/include/flux_abi.h` 是唯一真相源，`crates/flux-core/src/abi.rs` 是手写镜像。改任何一边必须：

1. 同步另一边。
2. 结构布局变了 → bump `FLUX_ABI_MAGIC`；只是加了纯用户态常量 → 不用 bump（头文件里有 scope note 说明界线）。
3. `abi.rs` 的 offset 断言必须更新。分工是：**关系型不变量**（`Counter::MAX <= COUNTER_SLOTS`、ringbuf 页对齐、handle 互异）写成编译期 `const _: ()`，因为撑不住自身不变量的 ABI 不该编译通过；**具体的 size/offset** 由 `cargo xtask abi-check` 交给 clang 用 `_Static_assert` 逐条核对头文件与镜像，`abi.rs` 里另有单元测试守住镜像侧。真正的跨语言证据在 `abi-check`，不在 `abi.rs` 里。

### GOV-4.3 提交实测结果之前

审计脱敏：IPv6 前缀、IPv4、MAC、链路本地地址、设备序列号、NFLOG cookie，命中数必须为 0。同时确认脱敏**确实生效过**（有 `.x.x` 或 `:redacted` 出现），否则可能是规则静默失效。

### GOV-4.4 发布之前

见 0.9.0 `spec/blueprint.md` §20，并应用本文未覆盖的 release gate。核心是：Phase 0 十问全部有结论（通过或已记录为边界），两次打包 byte-identical，`fluxd` 每个 LOAD 段 `p_align >= 0x4000`。

---

## GOV-5 Phase 0 断言失败怎么办

Phase 0 的目的就是**证伪**。断言失败是它在工作，不是事故。

失败时按影响分类：

| 影响 | 处置 |
|---|---|
| 某个 interface 类型不可用 | 改设计排除它，公开为边界，继续 |
| 某个机制需要额外前置条件（如某个 sysctl） | 加运行时检查 + 冲突即响亮失败，继续 |
| **需要改全局系统语义**（写 `all.rp_filter`、打开 `ip_forward`） | **停下，回 GOV-1.2 找所有者**。这类改动的理由与 §8.4 拒绝写全局 sysctl 同源 |
| **整条路线在某类设备上不可用** | **停下，回 GOV-1.2**。这是产品能力边界的变化 |

**禁止**用以下方式掩盖失败：token map、patch sing-box、加第二后端、加 heartbeat、放宽 fail-closed 语义。这些在 `history/rejected-and-deferred.md` §19 已逐条拒绝，理由不因为 Phase 0 失败而改变。

---

## GOV-6 文档维护

### GOV-6.1 文档集与职责

| 文件 | 是什么 | 谁改 |
|---|---|---|
| `docs/spec/blueprint.md` | **唯一规范性蓝图**，就地编辑 | 规范性变更时，按 GOV-3 |
| `docs/history/blueprint-0.9.1.md` | 0.9.1 增量，已折入 0.9.5 并冻结为记录 | 不再修改 |
| `docs/history/blueprint-0.9.2.md` | 0.9.2 增量（草案），已折入 0.9.5 并冻结为记录 | 不再修改 |
| `docs/philosophy.md` | **设计哲学**：技术决策的判据。蓝图与它冲突时改蓝图 | 判据本身被推翻时，走 GOV-3 协议 |
| `docs/index.md` | 标识符命名空间登记 + `§N → 文件` 唯一映射 | 开新命名空间或章节搬家时 |
| `docs/guide/introduction.md` | [explanation] 面向用户：是什么、取向、刻意不做 | 产品形态或边界变化时 |
| `docs/guide/architecture.md` | [explanation] 面向实现者：为什么是这个形状 | 架构变化时 |
| `docs/guide/how-to.md` | [how-to] 怎么装、怎么配、出问题怎么办 | 安装或恢复流程变化时 |
| `docs/governance.md` | 本文，过程规范 | 过程变化时 |
| `docs/spec/interaction.md` | 交互与体验设计 | 用户可见行为变化时 |
| `docs/authoring.md` | 文档撰写规范（制作规范） | 极少 |
| `AGENTS.md` | agent 会话入口：路由 + 代码里看不出的约束，≤80 行 | 路由或不成文约束变化时（AUTH-0.5） |
| `tools/phase0/results/*` | 实测原始记录，**只增不改** | 每次上机 |
| `CHANGELOG.md` | 对外可见的变化 | 发布时 |

### GOV-6.2 章节编号是稳定标识符

`spec/blueprint.md` 的 `§N.N` 编号被全仓库交叉引用（含 commit message 与代码注释）。**编号一旦发布就不再复用**——但正文可以就地改写，改的是内容不是编号（AUTH-7.2）：

- 插入新内容 → 用新的子编号（`§8.5.3`、`§8.5.4`），不要重排既有编号。
- 某节作废 → 保留编号，内容改成「已废弃，见 §X」，不要删除留空。
- 拆分文件时**编号跟着内容走，不重编**。因此 `§8.5.3` 无论在哪个文件里都指同一件事，`rg "§8\.5\.3"` 永远能找全。
- **代码只引用 `§N.N`，不引用版本化的 `R09x-NN`。** 前者跟着内容走、活得过再版；后者已随 0.9.5 折叠退役，代码里的引用已全部改写成承载它的 §。**`doc-check` 的 citations 检查强制这一条**，例外只有定义标识符语法本身的那两个文件。

### GOV-6.3 只写读者需要的，不写作者想说的

拒绝的内容：把同一论证在三处重复（改成一处 + 引用）、为对称而补的空章节、只有"待补充"的占位小节。已经这么处理过：CHANGELOG 里的架构变更理由压成一句指向 `§0`/`§19`。

---

## GOV-7 发布工程与社区流程

这一节的候选实践来自对两个成熟同类项目的逐项阅读：[JingMatrix/Vector](https://github.com/JingMatrix/Vector) 与 [JingMatrix/NeoZygisk](https://github.com/JingMatrix/NeoZygisk)。它们与 Flux-rs 的产品形态不同，因此这里只采纳已经落地并符合 §13 的最小子集；其它做法保留为候选。源码依据记在 `docs/history/review-log.md`。

### GOV-7.1 当前采纳

| 实践 | 当前做法 | 为什么 |
|---|---|---|
| **精确归档 allowlist** | `xtask/src/package.rs` 只允许 §13.1 规定的 15 个文件，意外文件使打包失败 | 供应链边界可枚举、可测试 |
| **归档级 SHA-256** | 发布物生成 `SHA256SUMS`；engine 资产另由 `engine.lock` 的 size + SHA-256 锁定 | 一条完整且可复现的校验路径，不生成包内逐文件 sidecar |
| **最小安装检查** | `customize.sh` 检查 payload、arm64、5.15 courtesy floor，并识别 Magisk/KernelSU/APatch；真实能力留给 activation 操作验证 | 避免用管理器版本字符串猜测内核能力 |
| **构建标识进入诊断面** | `fluxd version`、`bugreport` 与模块元数据提供版本、ABI 与构建信息 | 用户改名后仍能从运行产物确认身份 |
| **`panic = "abort"`** | 已在 `Cargo.toml` | daemon 不带着可能损坏的内部状态继续运行 |

### GOV-7.2 以后再说

逐文件 sidecar hash、管理器最低版本矩阵、debug/release 双 ZIP、canary prerelease、独立 debug 符号、原生 log 抓取（若 shell `logcat` 在某些 ROM 上不可靠）、认证 Unix socket 上的富 CLI、翻译 CI 门、按管理器的 `adb install` 开发任务。只有实际分发或支持问题出现时才把其中一项提升为合同。

### GOV-7.3 明确不采纳

| 不采纳 | 理由 |
|---|---|
| **不固定的 Rust nightly** | NeoZygisk CI 用未固定的 nightly（`ci.yml:36`），可复现性风险。我们固定 stable + `Cargo.lock` |
| **安装时禁用竞争模块** | Vector 会去 `touch` LSPosed 的 `disable`（`customize.sh`）。太激进。冲突应当**检测并报告**，不替用户处置 |
| **只用 Actions artifact 分发正式版本** | 正式发布物必须有公开、可校验的归档与 `SHA256SUMS`；canary 分发策略仍是延期项 |
| **仅接受英文 issue** | Vector 的政策（README:71-75）适合它的社区规模，不适合现在 |
| **随机化字符串以对抗检测** | 产品特定的隐蔽性需求，与本项目无关 |

### GOV-7.4 诊断包是支持流程的核心

Vector 的 `FileSystem.getLogs`（`Vector/daemon/.../FileSystem.kt:524-625`）是最值得抄的一条：一键生成包含全部排查信息的压缩包。Flux-rs 的对应物是 `fluxd bugreport`，内容清单见 §27.4。

**它必须默认脱敏**，且与 `tools/phase0/observe.sh` **共用同一套过滤规则**（GOV-2.3）。两处各写一套脱敏，必然有一处会漏。

## GOV-8 Git 约定

- Conventional Commits：`feat` / `fix` / `docs` / `build` / `refactor` / `test` / `chore`。
- commit message 的正文写**为什么**，不复述 diff 写了什么。推翻旧结论时写明推翻了什么、依据是什么。
- 不 amend 已存在的 commit，除非所有者明确要求。
- 不 push，除非所有者说过可以（当前状态：所有者已授权，推送时机由他决定）。
- `clone/` 与 `tools/phase0/results/` 之外的第三方源码**不进仓库**。

---

## GOV-9 这份手册自己的维护

它应该随着「哪些事被证明该问、哪些不该问」而修订。修订的触发条件：

- 我问了一件其实该自己决定的事 → 把它移进 GOV-1.1。
- 我自己做了一件其实该问的事 → 把它移进 GOV-1.2，并说明代价。
- 出现新的一类错误 → 在 GOV-2.3 或 GOV-3 加一条规矩，写清它防的是哪次具体失误。

**GOV-2.3 的每一条规矩都对应一次真实失误**，这是有意的：抽象的规矩没人遵守，带疤的规矩才有人记住。
