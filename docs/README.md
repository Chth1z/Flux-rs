# 文档索引

`blueprint.md` 是**规范性技术合同**。任何其它文档与它冲突时以它为准。

## 按你要做的事挑

| 你要做的事 | 读这个 |
|---|---|
| **我是用户，这东西是干什么的** | **`introduction.md`**（不含术语） |
| 实现某个模块 | `blueprint.md`，从头读到尾 |
| 了解技术架构 | `architecture.md` |
| 上机跑测试 | `verification/phase0.md` + `../tools/phase0/README.md` |
| 查一个错误码的含义 | `reference/failures-and-status.md` |
| 质疑某条断言的依据 | `evidence/review-log.md` |
| 提议「为什么不做 X」 | `decisions/rejected-and-deferred.md`（大概已经评估过了） |
| 改用户看得见的东西 | `ux.md` |
| 搞清楚什么该问所有者 | `governance.md` |
| 写或改这些文档 | `authoring.md` |

## 章节编号 → 文件

**章节编号是全局稳定标识符，跨文件不重编。** `§8.5.3` 无论在哪个文件里都指同一件事，`rg "§8\.5\.3"` 永远能在全仓库找全引用。理由见 `authoring.md` §1.1。

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
| §17 | 实施阶段 | `blueprint.md` |
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

技术核心（§1–§15、§17、§18、§20、§25、§26）是一张互相引用的密网——§7.5 的不变量依赖 §8.4 的 sysctl 结论，§8.5.3 的 pref 策略依赖 §14.1 的性能预算——实现者会把它们一起读，所以不拆。移出去的四块是不同的人在不同时刻读的。完整论证见 `authoring.md` §1。

## 真相源

| 主题 | 唯一真相源 |
|---|---|
| 数据面 ABI | `../bpf/include/flux_abi.h`（`crates/flux-core/src/abi.rs` 是手写镜像，offset 在**编译期**断言） |
| engine 资产 | `../engine.lock` |
| 实测数据 | `../tools/phase0/results/`，只增不改 |
| 研究引用的第三方源码 | `../tools/clone-manifest.md` + `../tools/reclone.sh` 重建 `clone/`（源码本身不进 git） |

## 定稿状态

**设计已定稿**（2026-08-25）。全部开放项已关闭，见 `decisions/rejected-and-deferred.md` §21.1。

| | 状态 |
|---|---|
| Phase 0 观测半场 | ✅ 完成 |
| Phase 0 Q10（唯一能推翻主路线的） | ✅ **通过** |
| Phase 0 **Q1** | ✅ **通过**（基线内核，§16.6） |
| 已知能推翻主路线的技术未知项 | **无** |
