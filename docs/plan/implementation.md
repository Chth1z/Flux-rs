# 第 17 部分：实施阶段

> 原 `../spec/blueprint.md` 第 17 部分。**章节编号未变**：本文里的 §17.x 就是全仓库引用的那个 §17.x（见 AUTH-1.1）。
>
> 谁读这份：要动手写代码的人（或模型），从头到尾按顺序读。0.9.1 规范性合同是冻结的 `docs/spec/blueprint.md` 加 `docs/history/blueprint-0.9.1.md`；本文只管**当前进度、顺序、边界与验收**，不得反向创造产品要求。

---

## 17.0 当前实施状态（2026-09-04）

**Phase 0–8 的实现与分阶段设备验证均已进入仓库；0.9.5 合同已定稿，实现按批次 A（ABI 与命名）、B（配置模型）、C（订阅流水线）追上了 §17.0.2 的大部分，剩余项见该表。工作区版本仍是 0.9.0，尚未由本文授权发布任何版本。** 下表是当前进度真相，后续 §17.2–§17.12 保留的是实施时的阶段顺序与回归清单，不应再被读成待办状态。

| 范围 | 当前状态 | 主要证据 |
|---|---|---|
| Phase 0–2 | 已完成 | Phase 0 记录 + `de23445` 等集成修正 |
| Phase 3 | 已完成并上机验证 | `b2b719e`、`9131a5c` |
| Phase 4 | 已完成并验证 loader parity/cleanup | `a648cd4`、`08f8402` |
| Phase 5 | 已完成并验证 packet loop/cleanup | `8b36e78`、`90afdd4` |
| Phase 6 | 已完成并验证 capture semantics | `a36f05d`、`beef81d`、`3627d30` |
| Phase 7 | 已完成并验证 self-healing | `63cbdff`、`d27d44d` |
| Phase 8 | 模块生命周期与 release pipeline 已实现、设备闭环已提交 | `3c36194`、`75eeabd`；发布仍受 §20 与 §15.1 门禁约束 |
| 0.9.1 增量实施 | 文档合同已定稿；§8.5 的 status 缺口已补齐 | `ifaces[].pref` 与三态 `reachable` 已加入 wire 与人类输出；`reachable` 在存活验证前不发布结论；`print_status` 补齐逐接口行与 counters；CI 的 Windows job 按 §15.1 分层 |
| 0.9.5 批次 A–C | 已提交，Linux 全量测试 184 项与 `clippy -D warnings` 通过（WSL） | `e8f2465`、`b70b940`（A）；`56ec853`（B）；`175ecb2`（C）。尚未在真机回归：设备上跑的仍是 0.9.1 形态的安装 |
| 0.9.5 批次 D | 已提交，Linux 全量测试 186 项、两套 fake-engine 集成场景、`clippy -D warnings`、模块生命周期测试通过（WSL） | webroot 跳转页、`clash_api` 告警降级、用户文案。任务书归档在 `../history/handoff-batch-d.md`。**尚未真机回归**——设备上跑的仍是 0.9.1 形态的安装 |
| 0.9.5 批次 E | 已提交，Linux 全量测试 186+6 项、`daemon_e2e` 含新增的 reactor 崩溃恢复场景、`clippy -D warnings` 两个目标、模块生命周期测试通过（WSL） | 监督进程收进二进制（§13.2.2）。任务书归档在 `../history/handoff-batch-e.md`。**尚未真机回归** |
| 0.9.5 批次 F | 已提交，flux-core 95 项、fluxd 75 项、两套 fake-engine 集成场景、`clippy -D warnings` 两个目标通过（WSL） | SSID 维度（§29）。任务书归档在 `../history/handoff-batch-f.md`。WSL 内核没有 cfg80211，nl80211 路径只有字节级单测覆盖，**真机是唯一能验证它的地方** |
| 剩余 | **§17.0.2 与 §17.0.1 均已清空**（§20 第 14 条满足） | 发布前还需：按 `device-regression-0.9.5.md` 真机回归、Linux CI 全绿、§20 其余十三条逐条勾选、提升 workspace 版本。`cargo xtask verify-package` 已在 WSL 通过（2026-09-05：两次干净交叉构建哈希一致，15 个文件） |

### 17.0.1 设计哲学判决出的返工清单

`docs/philosophy.md` 的判据过一遍现状后，以下几处需要返工。这张表放在这里而不是哲学文档里：哲学不随版本走，而这是一份会被做完的待办（philosophy §4）。

| # | 现状 | 违反 | 处置 |
|---|---|---|---|
| ~~1~~ | ~~bypass LPM 混装机制保留网段与用户策略~~ | ~~§1~~ | ~~用闲置的 `__u8` value 字节打 `RESERVED`/`POLICY` 标；热路径仍是一次 lookup（§6.1.1）~~ 批次 A（`e8f2465`） |
| ~~2~~ | ~~模板声明 listener 地址与端口~~ | ~~§1~~ | ~~反转回注入：预填需要六道门禁，注入需要一道（§9.1）~~ 批次 B（`56ec853`）：`engine_config.rs` 只注入两个 tproxy inbound，模板带 `inbounds` 即拒绝 |
| ~~3~~ | ~~`first_applicable` 字段名与语义相反，靠四处文档解释~~ | ~~§1、§4~~ | ~~改名 `reachable`，删掉解释段落（§24）~~ |
| ~~4~~ | ~~listener 地址硬编码在 `abi.rs:145` 与 `cidr.rs` 两处~~ | ~~§4~~ | ~~固定 bypass 从 ABI 常量派生，只留一个来源~~ |
| ~~5~~ | ~~`service.sh` 里的 daemon 重启退避循环~~ | ~~§7~~ | ~~收进二进制，或写明为什么监督必须在外面（NeoZygisk 用独立 monitor 进程是可参考的答案）~~ 所有者 2026-09-05 选定收进二进制；批次 E：`fluxd daemon` 成为监督进程（§13.2.2），`service.sh` 只剩一行 `exec` |
| 6 | `clash_api` secret/监听地址为硬拒绝 | §6 | 降为告警（§23） |
| ~~7~~ | ~~0.9.1 留下的一批"必须/不得"式校验~~ | ~~§1、§2~~ | ~~逐条问"被守护的东西该不该暴露"、"能不能让它写不出来"，能消的消掉而不是改进~~ 2026-09-05 逐条过完。消掉两处（所有者拍板）：状态根模式不对不再拒绝激活，Flux 自己恢复 `root:0700` 并记日志，`service.sh` 不再 chmod；`flux-` 前缀保留收窄为两个精确的注入 inbound tag。其余保留，理由各异：`flux.toml` 的严格解析、`@file` 约束、容量上限、模板 `inbounds` 禁止、fakeip 撞 bypass 硬拒——都是系统边界上对外部输入的防御（PHIL-2 的另一半）或不可诊断的失败（PHIL-6）；veth/rule/route/TC 的身份比对是所有权证明（PHIL-5）；`rp_filter`、page size、netns 是机制的真实前提。见 review-log 第 26、27 行 |

### 17.0.2 0.9.5 合同与当前实现的差距

0.9.5 蓝图是**目标合同**：`spec/` 与代码不一致时错的是代码（AUTH-0.1）。以下是 0.9.5 已规范、实现尚未跟上的部分。**这张表是唯一的进度真相**——蓝图正文里不写"尚未实现"，那会让合同同时描述两个时态。

| # | 合同 | 当前实现 | 章节 |
|---|---|---|---|
| ~~1~~ | ~~用户权威文件是 `config/template.json`，引擎跑生成的 `run/sing-box.<gen>.json`~~ | ~~`layout.rs` 仍以 `config/sing-box.json` 为用户权威；没有生成步骤~~ | ~~§28.1~~ |
| ~~2~~ | ~~包内 bootstrap 名为 `etc/default-template.json`~~ | ~~`package.rs` 仍装成 `etc/default-sing-box.json`~~ | ~~§28.1~~ |
| ~~3~~ | ~~订阅抓取、URI 解析、节点精修、`fluxd subscribe`~~ | ~~均未实现~~ | ~~§28.3–§28.7~~ |
| ~~4~~ | ~~生成是纯函数的机检测试（把生成物的 `outbounds` 换回模板后必须深度相等）~~ | ~~未实现~~ | ~~§28.2、§15.2~~ |
| ~~5~~ | ~~`webroot/index.html` 进 allowlist~~ | ~~allowlist 当前 14 项，无 webroot~~ 批次 D：15 项；打包拒绝 `module/webroot/` 里出现第二个文件 | ~~§28.8、§13.1~~ |
| ~~6~~ | ~~`[ssid]` 维度与 nl80211 事件源~~ | ~~未实现~~ 批次 F：generic netlink 传输、纯函数判定、与开关共用的暂停路径、`status.ssid`；SSID 字节不出守护进程 | ~~§29.1–§29.2~~ |
| ~~7~~ | ~~三个维度统一黑/白名单与 `@file` 引用~~ | ~~`flux.toml` 仍是 `apps` + `bypass_cidrs` 两个平铺键~~ | ~~§11.2~~ |
| ~~8~~ | ~~bypass value 分 `FLUX_BYPASS_RESERVED` / `FLUX_BYPASS_POLICY`；`cidr_mode` 进 `flux_control` 的 `pad0[2]`；**`FLUX_ABI_MAGIC` 随之 bump**~~ | ~~loader 恒写 `1`，BPF 只判非空，magic 未变~~ | ~~§6.1.1、§6.3~~ |
| ~~9~~ | ~~运行时产物改名 `effective-sing-box.<gen>.json` → `sing-box.<gen>.json`~~ | ~~`layout.rs` 仍用旧名~~ | ~~§28.1~~ |
| ~~10~~ | ~~wire 字段 `first_applicable` → `reachable`；排除原因 `not_first_applicable` → `identity_drift`~~ | ~~`control_wire.rs` 仍是旧名~~ | ~~§24、§27.3.3~~ |
| ~~11~~ | ~~`clash_api` 的 secret / 监听地址不安全时**告警而非硬拒**~~ | ~~`checks.rs` 仍是 error~~ 批次 D：并入 `sing_box_warnings`，`check` 与 `status` 同时可见 | ~~§23、§27.2.4~~ |
| ~~12~~ | ~~listener 地址与固定 bypass 从同一处派生，不在 `abi.rs` 与 `cidr.rs` 两处硬编码~~ | ~~两处各写一遍~~ | ~~§17.0.1 第 4 项~~ |
| ~~13~~ | ~~物理 `clsact` 缺失时**排除并等 netd**，不自建~~ | ~~需核对 `dataplane` 当前行为~~ 2026-09-04 核对：`platform.rs` 的 admission 对无 `clsact` 的物理接口置 `netd_clsact_missing`，`create_clsact` 只对 `flxrs1` 调用；rtnetlink 事件组含 `RTNLGRP_TC`，任何 TC 事件经去抖后重跑全部接口的 admission | ~~§8.5~~ |
| ~~14~~ | ~~订阅刷新的一次性 timerfd、失败后按 rtnetlink 默认路由恢复重试~~ | ~~未实现~~ | ~~§29.3、§29.4~~ |
| ~~15~~ | ~~`config/` 的 inotify 覆盖 `template.json` 与 `@file` 列表，变更即重新生成并换代~~ | ~~未实现~~ | ~~§29.6~~ |
| ~~16~~ | ~~面向用户的文案按 §27 过一遍（`module.prop`、guide）~~ | ~~未做~~ 批次 D：`module.prop` 首行、安装器输出、`flux.toml` 注释、guide 示例；README 归所有者（GOV-1.2），未动 | ~~§27.1.3~~ |
| ~~17~~ | ~~换代的判据是**生成物变了**，不是"哪个文件被改了"~~ | ~~`config_event_domains` 按文件名路由，`flux.toml` 只进策略域~~ | ~~§28.6 第 3 条、§28.2~~ |

第 8 项是本表里唯一改过 ABI 的：结构大小与全部 offset 不变，但契约变了，按 GOV-4.2 已 bump magic 到 `0xF10C0904`，`flux_abi.h` 与 `abi.rs` 两侧同步。

第 17 项的判据说明保留在这里，因为它解释了为什么换代逻辑里没有"哪个文件改了"这张表：`[subscription]` 的精修规则按 §28.2 是生成的输入，改了它必须换代，但按文件名路由的话 `flux.toml` 只进策略域；反过来把 `flux.toml` 也接进引擎域，又会让每次改应用清单都白白重启一次引擎。**生成既然是纯函数，比对生成物本身就是精确的**：字节相同就不换代，不同才换。

本表已清空（2026-09-05）。各批次的任务书归档在 `../history/handoff-batch-*.md`，记录当时为什么这样分批。清空的是"合同要求而代码没有"这一维；"代码在真机上确实这样做"由 `device-regression-0.9.5.md` 回答。

**§17.0.1 的哲学返工清单与本表有重叠，但两张表的判据不同**：那张问"现状违反了哪条判据"，本表问"合同要求什么而代码还没有"。发布门禁（§20 第 14 条）只盯本表，所以任何合同要求都必须在这里有一行，否则它永远不会被实现。

**`guide/` 跟合同走，不跟当前实现走。** 0.9.5 尚未发布，没有用户拿着这份指南去操作 0.9.1 的构建；发布门禁（§20）要求本表清空。

---

## 17.1 这份计划的读法

**每个阶段的退出条件都必须由该阶段自己满足。** 这不是废话——旧版 §17 的阶段 0 写着"退出条件：§16 全部关键 seam 通过"，而 §16 里的 Q5 / Q7 / Q8 只能由阶段 5–7 产出的代码来测。那是个循环依赖，照着做会在第一天就卡住。§17.2 是它的修复。

**九条对每个阶段都成立的规则：**

1. **阶段结束时仓库必须可 build、§15.1 对当前平台适用的测试全绿、Linux CI 全绿。** 不允许"下个阶段再修"的破窗。
2. **不为下一阶段预建抽象。** 这条是旧审计"24+ 无人居住的脚手架"（`../spec/blueprint.md` §18.4）的规则化闭环。需要一个 trait 时再抽，不要提前。
3. **发现真实回归时，只为该不变量加一个聚焦测试**，不要顺手补一套。测试数量不是质量指标。
4. **实测结果与蓝图冲突时**：按 GOV-3 的更正协议处理——把"原说法 / 实际 / 处置"写进 `../history/review-log.md`，并**就地改正 `../spec/blueprint.md`**（章节号不动，AUTH-7.2）；**不得静默偏离**。代码与当前合同不一致时，先改合同再改代码。
5. **遇到 GOV-1.2 列出的决策**（改全局系统语义、产品能力边界变化、引入新依赖、放宽失败语义）：**停下，问所有者**，不要自行决定。
6. **改 ABI 走 GOV-4.2**：`flux_abi.h` 是唯一真相源，`crates/flux-core/src/abi.rs` 是手工镜像，`FLUX_ABI_MAGIC` 必须 bump，`xtask abi-check` 必须通过。
7. **设备测试遵守 GOV-2.3**：每个改设备状态的脚本都要有覆盖全部退出路径的 cleanup，并在结束时打印残留检查。
8. **`../history/rejected-and-deferred.md` §19 里被拒绝的方案不得复活。** 卡住时正确的动作是问，不是去拿一个已被逐条否决的办法。每个阶段的"禁止"小节列的就是该阶段最容易复活的那几条。
9. **禁止把失败掩盖过去。** GOV-5 点名的五种掩盖手段（token map、patch sing-box、加第二后端、加 heartbeat、放宽 fail-closed）在任何阶段都不允许。

**关于"外推范围"**：所有实测结论都来自**一台** SM-S9180 / 5.15.211。`../history/phase0.md` §16.3 给了五层分类（AOSP 强制 / GKI / SoC 厂商 / OEM / 运行期）。把 OEM 层的观察当普适事实是这个项目最容易犯的错，写代码时尤其如此——**不要把任何单机观测值硬编码**。

---

## 17.2 Phase 0 延后问题的归属（历史实施计划）

**以下“剩余”只描述阶段开始时的安排；这些问题现已随 Phase 3–8 完成。当前状态只看 §17.0。**

**已经答完的**（都在 `../history/phase0.md`）：

| 问题 | 结论 | 章节 |
|---|---|---|
| Q1 SK_STORAGE first-decision | ✅ 通过 | §16.6 |
| Q2 listener 身份 / lookup / **assign 成功** | ✅ 通过 | §16.10 |
| Q6 观测半场（`filter INPUT`、egress 基线、sysctl 起点） | ✅ 通过 | §16.9 |
| Q9 per-app DNS（D18 的赌注） | ✅ 通过 | §16.7 |
| Q10 厂商 filter 是否遮挡 | ✅ 通过 | §16.5.4 |
| 产品数据面四个程序过验证器 | ✅ 通过 | §16.8.5 |

**剩下的，以及为什么它们不可能提前做**：

| 问题 | 提前做不了的原因 | 归属 | 在该阶段的具体形式 |
|---|---|---|---|
| **Q8**（对象生命周期半） | 要有 netlink 层才有对象可清 | **阶段 3** | `kill -9 fluxd` 后重启，§8.7 的删除-重建把对象恢复到确定状态；系统 TC/RPDB/VPN 对象逐行 diff 为空 |
| **Q5.1** L2 零改写闭环 | 要有 `bpf_redirect` 与 `flx_in` | **阶段 5** | 不写任何字节即 redirect，配 ingress 的 `bpf_skb_change_type(PACKET_HOST)`，包被 `ip_rcv` 接受。**若失败则 D17 被证伪**，回退到写 dst MAC |
| **Q5.2** L3 补头闭环 | 同上 | **阶段 5** | rmnet 上 `bpf_skb_change_head(14)` + 只写 EtherType 能闭环；headroom 不足时 helper 返回 `-ENOMEM` |
| **Q5.6** sysctl 最小集 | 要有真实包穿过 veth | **阶段 5** | `all.rp_filter` / `flxrs1.accept_local` / `ip_forward` 矩阵。起点值已实测（§16.9.3），**`all.rp_filter` 与 `ip_forward` 开箱都是 0** |
| **Q5.7** 可达性与共存 | 要有 `flx_verify` | **阶段 5** | 存活验证判定我们真的在跑；`TC_ACT_UNSPEC` 之后后续 filter 计数仍在增长 |
| **Q3** TCP 生命周期 | 要有完整数据路径 | **阶段 6** | 握手/重传/FIN/RST/TFO；`accept()` 后 `getsockname()` **逐字节**等于原始目的 |
| **Q4** UDP 原目的 | 同上 | **阶段 6** | 四组（family × connected）`IP_RECVORIGDSTADDR` cmsg 逐字节一致 |
| **Q5.3–5.5** clone / TCP GSO / UDP GSO | 要有真实大流量 | **阶段 6** | 大文件上传触发重传与 GSO；QUIC 客户端触发 `UDP_SEGMENT` |
| **Q6 剩余**（OEM 链是否丢我们的包） | 要有真实捕获流量比对计数增长 | **阶段 6** | 跑一条捕获流量前后各抓一次 `iptables -L -v -n`，逐链比对。**接口维度的隐藏差异已排除**（§16.9.1），剩下的是整体丢弃 |
| **Q8**（流量语义半） | 要有数据面 | **阶段 6** | 残留 TC filter 只造成"新流 direct、已入场流 drop" |
| **Q7** 换代与故障自愈 | 要有 generation 机制 + 数据面 | **阶段 7** | `kill -9` engine 后新连接 100% direct；fault 事件数 O(1) 而非 O(packets) |

**这张表就是每个阶段退出条件的一部分**，不是"有空再跑"的清单。

---

## 17.3 阶段 0 — 实测地基（**已完成**）

**已交付**：`tools/phase0/` 下的 12 个探针与 harness，`../history/phase0.md` 的六节实测记录，`../history/review-log.md` §0.6 的三条推翻。

**退出条件（已满足）**：能推翻主路线的 seam 全部实测通过——出向（Q10 / Q1 / Q9）与入向（Q2）两半都测掉了，数据面四个程序在基线内核上过验证器。**已知能推翻主路线的技术未知项：无。**

**留给后续阶段复用的资产**（这些是回归工具，不是一次性脚本）：

| 工具 | 回答什么 | 何时重跑 |
|---|---|---|
| `q1-run-device.sh` | SK_STORAGE 首次决策语义 | 改 §7.3 算法后 |
| `q2-run-device.sh` | listener 4 socket / lookup / **assign 成功** | **每次 engine 版本升级**（§9.2 要求） |
| `q9-run-device.sh` | per-app DNS 归属（D18） | 换设备 / 换 Android 版本后 |
| `q10-run.sh` | 厂商 filter 是否遮挡 | 换设备后 |
| `q6-veth-observe.sh` | egress 基线 / OEM 链 / sysctl 起点 / veth 生命周期 | 换设备后，以及阶段 3 的 Q8 |
| `loadall-product.sh` | 数据面过验证器 | **每次改 `flux.bpf.c`**（CI 已自动跑） |
| `secname-*.sh` | 哪些 ELF 段名可加载可挂载 | 改段名时 |
| `btf-inspect.sh` | BTF 前向声明导致的 map 建不出来 | libbpf 报 "can't determine value size" 时 |
| `observe.sh` | 只读设备全景 | 接手新设备第一件事 |

---

## 17.4 阶段 1 — `flux-core` 纯逻辑（**已完成**）

**交付物**：`flux-core` 的全部纯逻辑 + 单测；`xtask`（`abi-check`、`package`）；module staging；版本与 engine pin 校验。

**必读**：`../spec/blueprint.md` §5（crate 结构）、§6（BPF ABI）、§15.2（必须保留的八个逻辑测试）、`engine.lock`。

**退出条件**：

1. **在 Windows 上** `cargo test -p flux-core` 全绿。这条是硬要求：`flux-core` 不得有任何 I/O 或平台依赖，否则后面所有逻辑就只能在设备上调。
2. §15.2 的八个逻辑测试全部存在且通过。
3. `cargo xtask abi-check` **真正实现并通过**：用 clang 算出 `flux_abi.h` 各结构的偏移，与 `abi.rs` 的镜像逐字段比对。CI 里那行 `continue-on-error: true` **已按本条删除**，workflow 中不再有任何 `continue-on-error`。
4. `cargo xtask package` 连续两次 clean build 产出的 hash 一致（可复现构建）。
5. `xtask` 校验 `engine.lock` 的两个 sha256 与 size；任一不匹配就拒绝打包。**这条已经手工验证过一次**：2026-08-26 下载 v1.13.19 的 asset，archive 与 binary 两个 digest 与 `engine.lock` 逐字相符（§16.10）。`xtask` 要做的是把它自动化。
6. `cargo xtask doc-check` 实现并接入 CI，至少覆盖以下机械检查：`docs/index.md` 的章节映射指向的文件确实存在且真有那个标题；`docs/**` 内部的相对链接可解析；**每个被引用的标识符（`§N`、`PHIL-N`、`GOV-N`、`AUTH-N`）真实存在，且蓝图之外的文档不占用 `§`**；`flux_abi.h` 的 `FLUX_SEC_*` 与 `abi.rs` 的 `SEC_*` 一字不差且都在实测可用集内（§16.8.2）；`../history/review-log.md` 的推翻编号连续且与蓝图声称的总数一致。

   第六项：`DN` / `CN` 的状态登记与文档实际定义的集合**双向相等**，状态取自固定词表，`superseded` 必须写明取代者。

   第七项（§15.4 第 3 条点名要求）：文档与 workflow 里出现的每个 `cargo xtask <sub>` 都是真实存在的任务。

   **每一项都是真实抓到过缺陷的检查**，不是假想的整洁度指标：章节映射曾指向已移出的文件；推翻计数曾同时存在 5 / 7 / 8 三个互相矛盾的说法；§18 曾把一个已执行完的迁移计划写成待办，还错称归档目录被 `.gitignore` 排除；标识符检查上线当天就抓出 `AGENTS.md` 引用了一条从没写过的 AUTH-0.5。用 Rust 写在 `xtask` 里，不要写成 PowerShell 脚本——跨平台、CI 天然能跑、且不需要绕执行策略。

   **检查范围是 `docs/`、`tools/` 与根目录的 markdown。** 根目录曾被漏在walk之外，同时携带三条已漂移的断言。

**本阶段答的 Phase 0 问题**：无（纯逻辑，无内核交互）。

**禁止**：

- **`flux-core` 里不得出现任何 I/O、`unsafe`、async、netlink、BPF。** 它存在的意义就是"能在开发机上全速测"。
- 不要为阶段 2 的 reactor 预建 trait 或事件抽象。
- 不要引入新的运行时依赖。依赖清单的变更属 GOV-1.2，要问。

---

## 17.5 阶段 2 — `fluxd` 进程骨架与 engine 生命周期（**已完成**）

**交付物**：目录 layout；`flock` 单实例；控制协议；CLI（`start`/`stop`/`status`/`check`/`bugreport`）；reactor 骨架；engine 候选生命周期（§9.4 的六步换代事务）。

**必读**：`../spec/blueprint.md` §9（sing-box 集成，尤其 §9.4）、§10（reactor）、§11（控制/日志/状态）、§26（reactor 状态机）、`docs/spec/interaction.md`。

**退出条件**：

1. **冷启动与热更新事务在设备上闭环，尚无数据面**：`fluxd` 能拉起官方 sing-box、按 PID + inode 核验 4 个 socket、写 `run/sing-box.<generation>.json`、跑 `sing-box check -c`、换代、优雅停止。
2. **`fluxd` 自己的 socket 核验必须复现 Q2 的结果**（§16.10.2）：4 个 socket，inode 与 `/proc/<pid>/fd` 对得上。这是把 Q2 从"一次性实测"变成"产品自带的持续检查"。
3. 第二个 `fluxd` 实例启动时被 `flock` 拒绝，并给出可读原因。
4. `status` 在无数据面时正确报告 `Inactive` 且**说清原因**（不是空输出）。
5. `bugreport` 产出诊断包，且默认**不含 logcat**（`docs/spec/interaction.md`）。

**本阶段答的 Phase 0 问题**：Q2 的**持续化**（不是重测）。

**禁止**：

- **不要碰内核对象**：不建 veth、不动 TC、不写 sysctl。那是阶段 3。这里最大的诱惑是"反正后面要用，顺手建了"。
- **不要给 sing-box 发 `SIGHUP`**（§9.4 末段已逐条说明理由）。
- **不要注入 §9.1 允许之外的任何 JSON 键**，特别是 `routing_mark` 与 `bind_interface`（§9.3）。
- 不要加 heartbeat 或存活探测心跳。engine 的死活用 pidfd。

---

## 17.6 阶段 3 — netlink 与内核对象所有权（**已完成**）

**交付物**：veth 创建；route/RPDB；自有 veth 的 clsact 生命周期；物理接口上的 filter 挂载与卸载；interface admission；所有权谓词；`rp_filter` 前置检查。

**必读**：`../spec/blueprint.md` §8（网络对象与所有权，全节）、§3.3（接口分类）、§10.4（netlink 事件）、§12.8（为什么不 shell out 到 `ip`/`tc`）、`../history/phase0.md` §16.9。

**退出条件**：

1. **Direct / Active / 冲突 / 恢复四条路径闭环**，`status` 逐 interface 给出原因。
2. **Q8 的对象生命周期半通过**：`kill -9 fluxd` 后重启，§8.7 的删除-重建把所有对象恢复到确定状态；`stop` + 卸载 + 重启后**零 Flux 内核残留**；系统 TC / RPDB / VPN 对象**逐行 diff 为空**。
3. `all.rp_filter != 0` 时**响亮失败并给出诊断**，不是悄悄改全局值（§8.4）。起点已实测为 0（§16.9.3），所以这条要**人为构造**来测。
4. **接口筛选不用 `operstate`**（§16.9.5：RAWIP 接口读出 `unknown`），不用"有地址"（§16.9.5：`wlan0` 有地址但无 clsact）。判据是 `IFF_UP` + scope global 地址 + netd 已建 clsact。
5. **pref 逐接口选取**，不缓存设备级值（§8.5.3 的 2026-08-25 追加段）。

**本阶段答的 Phase 0 问题**：**Q8（对象生命周期半）**。

**禁止**：

- **不得 shell out 到 `ip` / `tc`**（§12.8）。全部走 netlink，消息格式见 §8 的 netlink 规格小节。
- **不得在物理接口上创建或删除 clsact**——复用 netd 的（§8.5.1）。netd 会自己删，删掉的是它的，我们只挂 filter。
- **不得写全局 sysctl**（`all.rp_filter`、`ip_forward`）。要改就是响亮失败 + 问所有者（GOV-5）。
- **不得删除、移动或替换 AOSP 的 filter**（§3.4）。
- 不要硬编码 pref 数值。

---

## 17.7 阶段 4 — BPF 加载器（只加载，不挂载，**已完成**）

**交付物**：手写 ELF 解析、relocation、map 创建（12 张）、`SK_STORAGE` 的手写 BTF、ARRAY_OF_MAPS 内层 map、ringbuf；`fluxd check` 的 BPF 半。

**必读**：`../spec/blueprint.md` §12（BPF 加载与最小依赖，全节，尤其 §12.7 的 11 条加固）、§6（ABI）、§7.5.0（arm64 无带返回值原子操作）、§7.5.1（verifier 陷阱清单）、`../history/phase0.md` §16.8。

**退出条件**：

1. **四个程序全部加载成功、12 张 map 全部按 `maps.rs` 的参数建出**，`fluxd check` 干净通过。**不挂载、不产生任何流量**——本阶段完全可以在不影响设备网络的前提下验收。
2. `fluxd check` **交叉校验 §9.0 的 fakeip 冲突**：用户 JSON 的 fakeip 段与 Flux 的 listener 地址/固定 bypass 不得重叠。
3. ABI magic 不匹配时拒绝加载并给出可读原因。
4. §12.7 的 11 条加固全部落地，特别是 verifier 日志重试与常量回退——`bpftool` 能加载不代表我们的加载器能。
5. 加载器产出的程序与 `bpftool prog loadall` 产出的**指令数一致**（`xlated` 字节数比对，基线值见 §16.8.5）。这条是廉价的正确性交叉验证。

**本阶段答的 Phase 0 问题**：无新增（数据面过验证器已在阶段 0 答完）。

**禁止**：

- **不得使用 libbpf、aya 或任何 BPF 加载库**（§12 的核心决定）。理由是依赖体积与 Android 上的可控性，不是偏好。
- **不得使用带返回值的原子操作**（§7.5.0：arm64 5.15 上加载失败 `-ENOTSUPP`，而 verifier 已通过，errno 毫无指向性）。
- 不得改 `flux.bpf.c` 的段名（`FLUX_SEC_*` 是实测结论，§16.8.2）。
- 不要在这个阶段挂载。挂载有存活验证要求，那是阶段 5。

---

## 17.8 阶段 5 — 挂载、存活验证、skb 回送闭环（**已完成**）

**交付物**：`flx_verify` 存活验证流程（§8.5.4）；四个程序挂载；veth 回送路径打通。

**必读**：`../spec/blueprint.md` §8.5.3 / §8.5.4、§3.3（L2/L3 分支）、§8.4（路由前置条件）、`../history/phase0.md` §16.5.4 / §16.9.3。

**退出条件**：

1. **`flx_verify` 在每个准入接口上计到调用**，然后卸下探测、在同一 pref 换上 `flx_cap_l2`/`flx_cap_l3`。attach 成功**不**等于能工作（§8.5.3 约束 3）。
2. **Q5.1 通过**：L2 路径不写任何字节即 `bpf_redirect`，配 ingress 的 `bpf_skb_change_type(PACKET_HOST)`，包被 `ip_rcv` 接受。**若被 `PACKET_OTHERHOST` 丢弃，D17 被证伪**——按 GOV-3 记录，回退到写 dst MAC，不要绕。
3. **Q5.2 通过**：rmnet 上 `bpf_skb_change_head(14)` + 只写 EtherType 能闭环；headroom 不足时 helper 返回 `-ENOMEM` 而非损坏包。
4. **Q5.6 通过**：跑完 `all.rp_filter` / `flxrs1.accept_local` / `ip_forward` / `arp_filter` 矩阵，确定**真正必需的最小集**。§8.4 的预测是需要 `flxrs1.rp_filter=0` + `accept_local=1` + `all.rp_filter=0`，不需要 `ip_forward` 与 `arp_filter`。**失败时直接上 `pwru` + `kfree_skb_reason`，不要猜**（§8.4 有 dae 的原始 trace 可对照）。
5. **Q5.7 通过**：`TC_ACT_UNSPEC` 之后后续 filter 的计数器仍在增长。

**本阶段答的 Phase 0 问题**：**Q5.1、Q5.2、Q5.6、Q5.7**。

**禁止**：

- **egress"不接管"永远是 `TC_ACT_UNSPEC`**，绝不是 `TC_ACT_OK` 也绝不是 `TC_ACT_PIPE`（`flux.bpf.c` 头部注释给了两条独立理由）。dae 在 23 处返回 `TC_ACT_OK`，在 Linux 路由器上没问题，在这里是 bug。
- **不得靠 dump 推断可达性**，必须用 §8.5.4 的正向存活验证。
- 不得为了让包过去而放宽 sysctl 范围（比如改 `all.*`）。
- 不得占用 pref 1，即使当时空着（§8.5.3 的竞态说明）。

---

## 17.9 阶段 6 — 完整数据路径（**已完成**）

**交付物**：§7.2–7.5 的决策算法全部落地；`bpf_sk_assign` 路径；counters；per-UID 统计（D23）。

**必读**：`../spec/blueprint.md` §7（数据面算法，全节）、§2（失败语义）、§1.6（eBPF 能力边界）、`../spec/failures.md`。

**退出条件**：

1. **双栈 TCP/UDP 端到端 smoke 通过**（这是旧 §17 阶段 4 的原始退出条件）。
2. **Q3 通过**：`accept()` 后 `getsockname()` **逐字节**等于原始目的；旧 flow 无一个字节到达真实目的（用真实目的侧 tcpdump 证明）。
3. **Q4 通过**：四组（family × connected/unconnected）`IP_RECVORIGDSTADDR` cmsg 逐字节一致；回写路径能到达 app。
4. **Q5.3–5.5 通过**：大文件上传触发重传（clone 安全）与 TCP GSO；QUIC 客户端触发 `UDP_SEGMENT`，engine 收到的是一个个 datagram 而不是巨包。
5. **Q6 剩余通过**：跑捕获流量前后各抓一次 `iptables -L -v -n`，逐链比对 drop/reject 计数增长，**单列 OEM 自有链**。若 OEM 链丢我们的包，答案是"该设备不受支持，保持 Direct 并在 `status` 报告"——**绝不是 flush OEM 的防火墙链**（box4magisk 选了后者，与 §1.3 非目标和 §15.4(1) 直接冲突）。
6. **Q8 流量语义半通过**：残留 TC filter 只造成"新流 direct、已入场流 drop"。
7. **Q9 的第 6 条**：用户 JSON 里的 `package_name` 规则命中（前置条件已实测成立，§16.10.5）。

**本阶段答的 Phase 0 问题**：**Q3、Q4、Q5.3–5.5、Q6 剩余、Q8 流量语义半、Q9.6**。

**禁止**：

- **一旦观察到有效的 CAPTURED 决策，之后每个失败都是 `TC_ACT_SHOT`。绝不回退到真实目的。** 这是 admission-bounded fail-open 的全部含义（§2）。
- **绝不对 established/data TCP 包调 `bpf_sk_assign()`**，只对裸 SYN（`flux.bpf.c` 头部给了完整的内核机制理由）。
- 不得用特判端口 53 的方式处理 DNS（D18 已实测成立，不需要特判）。
- 不得为性能牺牲引用配平：每个 `bpf_sk_lookup_*` 在每条分支上恰好释放一次。

---

## 17.10 阶段 7 — 故障、换代与自愈（**已完成**）

**交付物**：`fault_events` ring buffer；fault latch；generation 换代与恢复；`status` 的完整故障矩阵。

**必读**：`../spec/blueprint.md` §2.2（失败语义）、§9.4（换代事务）、§26（reactor 状态机）、`../spec/failures.md`（全文）。

**退出条件**：

1. **Q7 通过**：engine 在 egress 的 `listener_alive()` 与 ingress 的 lookup 之间退出时，只影响已 redirect 的包，下一个新 SYN/datagram 恢复 Direct；`kill -9` engine 后新连接 **100% direct**。
2. **fault 事件数是 O(1) 而非 O(packets)**：latch 抑制 storm，重复/旧事件幂等。
3. 跨 generation 的 in-flight 旧包被送进新 listener 时行为如 D3 所述无害。
4. `../spec/failures.md` 的每一行**都能人为构造并观察到**，`status` 给出的假设与文档一致。
5. current fault 让 fluxd 先 inactive 再重启 generation。

**本阶段答的 Phase 0 问题**：**Q7**。

**禁止**：

- 不得加 heartbeat（GOV-5）。
- 不得放宽 fail-closed 语义来让某个测试变绿。
- 不得让 fault 处理路径自己成为 storm 源（事件要幂等且有 latch）。

---

## 17.11 阶段 8 — 模块封装与发布工程（**实现与设备验证已完成，版本发布未授权**）

**交付物**：三管理器（Magisk / KernelSU / APatch）module lifecycle；以管理器模块开关为唯一开关的 inotify 控制路径与 `module.prop` 状态显示；精确 allowlist 的 release candidate artifact。0.9.1 不包含 `action.sh`、`webroot` 或 Flux WebUI（§13.1）。

**必读**：`../spec/blueprint.md` §13（模块安装与构建）、`docs/spec/interaction.md`、`docs/guide/introduction.md`、GOV-7（发布工程与社区流程）。

**退出条件**：

1. 0.9.0 artifact / checksum / 文档三者一致。
2. 三个管理器上安装、启动、在管理器界面里开关模块（当场生效且 `module.prop` 描述随之更新）、卸载、管理器重启全部闭环；卸载脚本不 flush 内核对象，**重启后**非持久 Flux 对象归零（§8.8）。
3. `docs/guide/introduction.md` 描述的行为与实际一致——**包括那些"诚实的失败"**：流量统计翻倍、被委托的流量、OEM 冲突时保持 Direct。
4. `bugreport` 的输出满足 `docs/spec/interaction.md` 的隐私约定（默认无 logcat；不泄露第三方包名之外的使用习惯，参见 §16.7.3）。

**禁止**：

- **不得 flush OEM 的防火墙链**（box4magisk 的 `oneplus_a16_fix()` 那条路）。
- 不得在 `post-fs-data.sh` 里做网络操作（§13 给了理由）。
- 不得在模块目录里写 `disable` 与 `module.prop` 的 `description=` 之外的任何东西：那个目录属于管理器。
- 不得让 `module.prop` 写入失败影响 daemon，也不得让它变成状态的第二真相源。

---

## 17.12 CI 与阶段的对应

| CI job | 从哪个阶段起必须绿 |
|---|---|
| `fmt / clippy / test` | 阶段 1 |
| `bpf object`（编译 + **verifier gate**） | 阶段 0 起（已绿） |
| `bpf object` 的 `abi-check` | 硬门禁，无 `continue-on-error`（阶段 1 已删除） |
| `aarch64-linux-android` 交叉编译 | 阶段 1 |
| `cargo deny` | 阶段 1 |
| `shellcheck` | 阶段 8（`module/*.sh` 出现时）；`tools/phase0/*.sh` 已在阶段 0 通过 |

**verifier gate 已经证明它抓得住真 bug**：它第一次被启用时就发现四个程序的段名 libbpf 一律拒绝、根本加载不了（§16.8.1），而编译从来不会发现这种问题。
