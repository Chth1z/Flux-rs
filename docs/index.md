# 标识符索引

本文是**标识符的唯一权威**：每个前缀归谁、每个号定义在哪、新号怎么发、引用怎么写。

要找"我该读哪份文档"去 [`README.md`](README.md)；要找"文档架构与语言规则"去 [`authoring.md`](authoring.md) AUTH-0。

`cargo xtask doc-check` 机器校验本文的每一张表。这不是形式：**这套规则被违反过两次，两次都发生在写规则的人手里**——`ux.md` 用自己的 §1–§8 与蓝图冲突了很久没人发现；`philosophy.md` 刚立完"编号全局唯一"就自己占了 §0–§7，还留下一处指向已不存在的 §8 的悬空引用。靠人读规则不够。

---

## 1 命名空间注册表

**`§` 只属于蓝图。** 任何其它文档的章节都必须用自己的前缀，因此一个裸引用永远只有一种读法。

| 前缀 | 含义 | 定义在 | 分配者 | 稳定性 |
|---|---|---|---|---|
| `§N[.N…]` | 蓝图部分与章节 | 见 §4 的映射表——编号跟着内容走，因此 §0 在 `history/`、§17 在 `plan/` | 蓝图作者 | 全局稳定，发布后不复用、不重排 |
| `R09x-NN` | 某版本的增量修订项 | `history/blueprint-0.9.x.md` | 已冻结 | **已退役**：不再新发；代码里不得引用（GOV-6.2，doc-check 强制），文档里残留的由 §0 前的对照表映射到承载它的 § |
| `PHIL-N` | 设计哲学的原则与章节 | `philosophy.md` | 哲学文档 | 稳定；推翻要走 GOV-3 |
| `GOV-N[.N]` | 治理手册的章节 | `governance.md` | 治理手册 | 稳定 |
| `AUTH-N[.N]` | 制作规范的章节 | `authoring.md` | 制作规范 | 稳定 |
| `DN` | 被推翻的结论 / 设计决定记录 | `history/review-log.md` | 复核记录 | 只增不改 |
| `CN` | 需所有者确认的事项 | `history/rejected-and-deferred.md` | 决策记录 | 只增不改 |
| `QN` | Phase 0 的证伪问题 | `history/phase0.md` | 已冻结 | 不再新增 |

未注册的前缀不得使用。要开一个新命名空间，先在本表加一行。

## 2 分配规则

- **号一旦发布就不复用。** 内容作废时保留编号，正文改成"已废弃，见 §X"，不删除留空。
- **插入新内容用新的子编号**（`§8.5.3`、`§8.5.4`），不重排既有编号。
- **拆分文件时编号跟着内容走。** `§8.5.3` 落在哪个文件都指同一件事——这条是拆分能安全进行的唯一前提。
- **规范性变更就地改蓝图**，不新开增量层（AUTH-7.2）。
- 全量再版（如 0.9.5）**折叠修订项但保留章节号**。代码里有数百处 `§` 引用，重编号会让历史 commit 静默指向别的东西。
- **`DN` / `CN` 引用前先看状态登记**（§0.3.0、§21.0）。已 `superseded` 的决策不得当作现行合同引用。

## 3 引用怎么写

| 写 | 不写 | 为什么 |
|---|---|---|
| `§8.5.3` | `blueprint.md §8.5.3` | `§` 已经限定了命名空间，文件名是冗余的，而且文件会移动 |
| `PHIL-1` | `philosophy.md §1` | 后者曾与蓝图 §1 冲突 |
| `GOV-3` | `governance.md §3` | 同上 |
| `§8.5，经 R091-05 修订` | 直接引 `R091-05` | 读者需要知道原条款在哪 |

被引用的编号必须真实存在。`doc-check` 覆盖 `docs/`、`tools/` 与根目录的 markdown，把悬空的 `PHIL-`/`GOV-`/`AUTH-` 引用当作缺陷报出来。

**`§` 的校验目前只到顶层部分号**：`§8.5.3` 会被核对 `8` 是不是已注册的部分，`.5.3` 不会被解析。子编号的唯一性靠 §2 的规则与人工核对，`doc-check` 抓不到。

## 4 章节编号 → 文件

蓝图命名空间的权威映射。`doc-check` 逐行验证：文件存在，且真的带着那个 `# 第 N 部分` 标题。

| 部分 | 内容 | 文件 |
|---|---|---|
| §0 | 独立复核与更正对照 | `history/review-log.md` |
| §1 | 产品合同 | `spec/blueprint.md` |
| §2 | 数据路径与失败语义 | `spec/blueprint.md` |
| §3 | Android 平台事实 | `spec/blueprint.md` |
| §4 | 内核机制依赖清单 | `spec/blueprint.md` |
| §5 | crate 与模块结构 | `spec/blueprint.md` |
| §6 | BPF ABI | `spec/blueprint.md` |
| §7 | 数据面算法 | `spec/blueprint.md` |
| §8 | 网络对象与所有权 | `spec/blueprint.md` |
| §9 | sing-box 集成 | `spec/blueprint.md` |
| §10 | 控制面 | `spec/blueprint.md` |
| §11 | 配置与持久状态 | `spec/blueprint.md` |
| §12 | BPF 构建与最小加载器 | `spec/blueprint.md` |
| §13 | 模块封装与构建 | `spec/blueprint.md` |
| §14 | 性能与能效预算 | `spec/blueprint.md` |
| §15 | 验证策略 | `spec/blueprint.md` |
| §16 | Phase 0 十问 + 实测 + 外推分层 | `history/phase0.md` |
| §17 | 实施阶段 | `plan/implementation.md` |
| §18 | 从旧仓库过渡 | `history/migration.md` |
| §19 | 被拒绝的替代方案 | `history/rejected-and-deferred.md` |
| §20 | 发布前最终验收 | `spec/blueprint.md` |
| §21 | 需要所有者确认的事项 | `history/rejected-and-deferred.md` |
| §22 | 延期项与它们的 seam | `history/rejected-and-deferred.md` |
| §23 | 失败矩阵 | `spec/failures.md` |
| §24 | `status` 输出与错误码规格 | `spec/failures.md` |
| §25 | 启动时序与边界条件 | `spec/blueprint.md` |
| §26 | reactor 状态机 | `spec/blueprint.md` |
| §27 | 交互合同 | `spec/interaction.md` |
| §28 | 订阅与配置生成 | `spec/blueprint.md` |
| §29 | 条件激活（SSID） | `spec/blueprint.md` |

§27 是 0.9.0 编号空间之后新开的一部分。这些条款此前住在 `docs/ux.md`，用它自己的 §1–§8 与蓝图冲突——`rg "§3"` 会返回两个不相干的东西。拆分时并入了全局编号。

§28 与 §29 由 0.9.5 新开：折叠 R092-01/05（订阅）与 R092-07（SSID）时，这两块内容在 0.9.0 的编号空间里没有归宿，而按 §2 的规则不能塞进别人的子编号。

## 5 真相源

| 主题 | 唯一真相源 |
|---|---|
| 产品合同 | `spec/blueprint.md`，唯一一份 |
| 技术决策的判据 | `philosophy.md` |
| 数据面 ABI | `../bpf/include/flux_abi.h`（`crates/flux-core/src/abi.rs` 是手写镜像；size/offset 由 `cargo xtask abi-check` 用 clang 的 `_Static_assert` 核对，另有 `abi.rs` 的单元测试，关系型不变量才是 `const _: ()`） |
| engine 资产 | `../engine.lock` |
| 实测数据 | `../tools/phase0/results/`，只增不改 |
| 研究引用的第三方源码 | `../tools/clone-manifest.md` + `../tools/reclone.sh` 重建 `clone/` |
| 标识符与编号 | 本文 |
