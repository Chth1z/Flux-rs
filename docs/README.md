# 文档索引

0.9.1 的规范性技术合同由两层组成：冻结的 0.9.0 基线 [`blueprint.md`](blueprint.md)，以及增量修订 [`blueprint-0.9.1.md`](blueprint-0.9.1.md)。先读基线，再应用修订；同一主题冲突时以 0.9.1 修订为准。0.9.0 原文保留，不回写历史。

## 按你要做的事挑

| 你要做的事 | 读这个 |
|---|---|
| **我是用户，这东西是干什么的** | **`introduction.md`**（不含术语） |
| **动手写代码，不知道从哪开始** | **`plan/implementation.md`**，按阶段顺序读 |
| 实现某个模块 | `blueprint.md`，从头读到尾；再读 `blueprint-0.9.1.md` 的覆盖项 |
| 了解技术架构 | `architecture.md` |
| 上机跑测试 | `verification/phase0.md` + `../tools/phase0/README.md` |
| 查一个错误码的含义 | `reference/failures-and-status.md` |
| 质疑某条断言的依据 | `evidence/review-log.md` |
| 提议「为什么不做 X」 | `decisions/rejected-and-deferred.md`（大概已经评估过了） |
| 改用户看得见的东西 | `ux.md` |
| 搞清楚什么该问所有者 | `governance.md` |
| 写或改这些文档 | `authoring.md` |

## 章节编号 → 文件

**章节编号是全局稳定标识符，跨文件不重编。** `§8.5.3` 无论在哪个文件里都指同一件事，`rg "§8\.5\.3"` 永远能在全仓库找全引用。0.9.1 不重写这些章节，使用独立的 `R091-*` 修订号；引用已修订条款时写“§8.5.3，经 R091-05 修订”。理由见 `authoring.md` §1.1。

| 部分 | 内容 | 文件 |
|---|---|---|
| §0 | 独立复核与更正对照 | `evidence/review-log.md` |
| §1 | 产品合同 | `blueprint.md` |
| §2 | 数据路径与失败语义 | `blueprint.md` |
| §3 | Android 平台事实 | `blueprint.md` |
| §4 | 内核机制依赖清单 | `blueprint.md` |
| §5 | crate 与模块结构 | `blueprint.md` |
| §6 | BPF ABI | `blueprint.md` |
| §7 | 数据面算法 | `blueprint.md` |
| §8 | 网络对象与所有权 | `blueprint.md` |
| §9 | sing-box 集成 | `blueprint.md` |
| §10 | 控制面 | `blueprint.md` |
| §11 | 配置与持久状态 | `blueprint.md` |
| §12 | BPF 构建与最小加载器 | `blueprint.md` |
| §13 | 模块封装与构建 | `blueprint.md` |
| §14 | 性能与能效预算 | `blueprint.md` |
| §15 | 验证策略 | `blueprint.md` |
| §16 | Phase 0 十问 + 实测 + 外推分层 | `verification/phase0.md` |
| §17 | 实施阶段 | `plan/implementation.md` |
| §18 | 从旧仓库过渡 | `blueprint.md` |
| §19 | 被拒绝的替代方案 | `decisions/rejected-and-deferred.md` |
| §20 | 发布前最终验收 | `blueprint.md` |
| §21 | 需要所有者确认的事项 | `decisions/rejected-and-deferred.md` |
| §22 | 延期项与它们的 seam | `decisions/rejected-and-deferred.md` |
| §23 | 失败矩阵 | `reference/failures-and-status.md` |
| §24 | `status` 输出与错误码规格 | `reference/failures-and-status.md` |
| §25 | 启动时序与边界条件 | `blueprint.md` |
| §26 | reactor 状态机 | `blueprint.md` |

## 为什么这么拆

按**读者**拆，不按篇幅拆。判据是一句话：如果两块内容总是被同一个人在同一次工作中一起读，它们就该在同一个文件里。

技术核心（§1–§15、§18、§20、§25、§26）是一张互相引用的密网——§7.5 的不变量依赖 §8.4 的 sysctl 结论，§8.5.3 的 pref 策略依赖 §14.1 的性能预算——实现者会把它们一起读，所以保留为 0.9.0 基线。§17 已移到实施计划；0.9.1 用增量蓝图修正基线，不复制整张密网。完整论证见 `authoring.md` §1。

## 真相源

| 主题 | 唯一真相源 |
|---|---|
| 0.9.1 产品合同 | `blueprint.md` + `blueprint-0.9.1.md`；冲突时后者优先 |
| 数据面 ABI | `../bpf/include/flux_abi.h`（`crates/flux-core/src/abi.rs` 是手写镜像，offset 在**编译期**断言） |
| engine 资产 | `../engine.lock` |
| 实测数据 | `../tools/phase0/results/`，只增不改 |
| 研究引用的第三方源码 | `../tools/clone-manifest.md` + `../tools/reclone.sh` 重建 `clone/`（源码本身不进 git） |

## 当前状态

0.9.0 设计于 2026-08-25 定稿并冻结。0.9.1 增量蓝图于 2026-08-28 建立、2026-08-29 定稿，用于修正文档冲突和对齐已测试实现；它不等同于已发布 `v0.9.1`。

| | 状态 |
|---|---|
| Phase 0 观测半场 | ✅ 完成 |
| Phase 0 Q10（厂商 filter 是否遮挡我们） | ✅ **通过** |
| Phase 0 Q1（SK_STORAGE first-decision） | ✅ **通过**（基线内核，§16.6） |
| Phase 0 Q9（per-app DNS，D18 的赌注） | ✅ **通过**（§16.7） |
| 产品数据面四个程序过验证器 | ✅ **通过**（基线内核，§16.8.5） |
| Phase 0 Q2（listener / lookup / **assign 成功**） | ✅ **通过**（§16.10） |
| Phase 1–8 实现 | ✅ 已进入仓库；当前明细见 `plan/implementation.md` |
| Phase 0 Q3–Q8 | ✅ 对应 Phase 3–7 device acceptance 已提交；发布前仍按 §20 复核证据完整性 |
| 当前发布状态 | 预发布验证；没有 `v0.9.1` 发布授权 |
