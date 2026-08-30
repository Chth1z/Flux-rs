# 文档导航

这里回答"我该读哪一份"。标识符、编号与真相源在 [`index.md`](index.md)；文档架构与语言规则在 [`authoring.md`](authoring.md) AUTH-0。

## 目录即权威等级

每个目录回答同一个问题：**这份文档和代码不一致时，谁错了？**

| 位置 | 层 | 不一致时 | 语言 |
|---|---|---|---|
| `philosophy.md` | 判据 | 合同错（它是蓝图的上游） | 英文 |
| `governance.md`、`authoring.md` | 过程 | 过程错 | 中文 |
| `spec/` | **合同** | **代码错** | 英文（0.9.5 起） |
| `guide/` | 投影 | 文档错，改文档 | 中文 |
| `history/` | 记录 | 都不错，它只记录当时发生了什么；只增不改 | 保持原样 |
| `plan/` | 计划 | 描述还没发生的事；会被做完 | 中文 |

## 按你要做的事挑

| 你要做的事 | 读这个 |
|---|---|
| **我是用户，这东西是干什么的** | **`guide/introduction.md`**（不含术语） |
| **要评审或提出一个设计** | **`philosophy.md`**（英文），先过 PHIL-10 的 checklist |
| **动手写代码，不知道从哪开始** | **`plan/implementation.md`**，按阶段顺序读 |
| 实现某个模块 | `spec/blueprint.md`，从头读到尾；0.9.5 折叠完成前，再依次读 `spec/blueprint-0.9.1.md`、`spec/blueprint-0.9.2.md` 的覆盖项 |
| 了解技术架构 | `guide/architecture.md` |
| 怎么装、怎么配、出问题怎么办 | `guide/how-to.md` |
| 上机跑测试 | `history/phase0.md` + `../tools/phase0/README.md` |
| 查一个错误码的含义 | `spec/failures.md` |
| 改用户看得见的东西 | `spec/interaction.md`（§27） |
| 质疑某条断言的依据 | `history/review-log.md` |
| 提议「为什么不做 X」 | `history/rejected-and-deferred.md`（大概已经评估过了） |
| 搞清楚什么该问所有者 | `governance.md` |
| 写或改这些文档 | `authoring.md`；引用与编号看 `index.md` |
| **引用某个 §、发一个新号** | **`index.md`** |

## 合同暂时还是三层，正在折成一层

现状：冻结的 0.9.0 基线 [`spec/blueprint.md`](spec/blueprint.md)，增量修订 [`spec/blueprint-0.9.1.md`](spec/blueprint-0.9.1.md)，再叠 [`spec/blueprint-0.9.2.md`](spec/blueprint-0.9.2.md)（草案）。按这个顺序读，冲突时取最新一层。

**这个形态正在被取消。** 0.9.5 把三层折成一份全量蓝图，两份增量移入 `history/`，此后只维护 `spec/blueprint.md` 一份、就地编辑——增量蓝图机制已废除，理由见 AUTH-7.2。`R09x-NN` 编号同时退役，由 0.9.5 的对照表映射到承载它的 §。

## 为什么这么拆

两条判据叠加，先后有序。

**先按权威等级拆**，也就是上面那张表：合同、投影、记录、计划混在一个目录里，读者无法从文件名判断"违反它意味着什么"。目录名承载这个信息，放错位置就变得显眼——这是 PHIL-2「让无效状态不可表示」用在文档上。

**再按读者拆**，不按篇幅拆：如果两块内容总是被同一个人在同一次工作中一起读，它们就该在同一个文件里。技术核心（§1–§15、§20、§25、§26）是一张互相引用的密网——§7.5 的不变量依赖 §8.4 的 sysctl 结论，§8.5.3 的 pref 策略依赖 §14.1 的性能预算——实现者会把它们一起读，所以不再往下拆。

完整论证见 AUTH-0 与 AUTH-1。
