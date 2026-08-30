# 交给实现者的任务书 B：配置模型

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md`，与它冲突时错的是本文。完成后本文删除，对应的 §17.0.2 行划掉。
>
> **前置：批次 A 必须已完成并通过验收。** 本批次依赖 A 落定的 ABI 与名字。

## 这批要解决的问题

0.9.1 把用户与引擎配置的关系搞反了：它把模板当一次性样板复制成 `sing-box.json`，之后归用户所有。后果在真机上暴露——**订阅更新必须由用户手工用 `jq` 合并**。每次刷新都要做、却要手工做的步骤，是缺失的功能，不是工作流。

本批次把关系正过来，并把 `flux.toml` 的两个平铺键换成三个共用同一套写法的维度。

## B1 — 用户拥有模板，Flux 生成引擎配置（§17.0.2 第 1、2 项）

**合同**：§28.1、§28.2、§27.2.1。

| 路径 | 归属 | 说明 |
|---|---|---|
| `config/flux.toml` | 用户权威 | Flux 自己的行为 |
| `config/template.json` | 用户权威 | sing-box 配置模板 |
| `config/*.txt` | 用户权威 | 被 `@` 引用的列表文件 |
| `run/subscription.raw` | 机器产物 | 订阅抓取的原始响应（批次 C 才产生，本批次只留位置） |
| `run/sing-box.<gen>.json` | 机器产物 | 每代一份、只读、换代即删 |

要改的地方：

- `crates/fluxd/src/layout.rs`：用户权威文件从 `sing-box.json` 改为 `template.json`。
- `xtask/src/package.rs`：包内路径 `etc/default-sing-box.json` → `etc/default-template.json`；allowlist 内容随之更新（**allowlist 是常量表，改它就是改合同边界，不要顺手加别的文件**）。
- `module/customize.sh`：复制目标名同步。
- 相关测试与 fixture。

**`Flux` 永不写 `config/` 下的任何文件。** 这条在 §28.1 是 MUST NOT，实现时不要留任何"仅在缺失时写回"的后门——安装脚本在文件缺失时复制默认值是安装行为，不是 daemon 行为，两者不要混。

## B2 — 生成是纯函数（§17.0.2 第 4 项）

**合同**：§28.2。

```
template.json  +  subscription.raw  +  flux.toml 的精修规则
  → sing-box.<gen>.json
```

只做两件事：**填空**（把 `outbounds` 为空数组的 `selector`/`urltest` 按 tag 填上对应组）与**追加**（把精修后的节点追加进 `outbounds`）。**其余逐字节透传。**

最后这句是一条必需的测试，不是意向：

> 把生成物里的 `outbounds` 换回模板的 `outbounds`，结果必须与模板**深度相等**。

重排键、丢掉一个被注释剥离的字段、归一化一个数字——任何一种都会让这个测试红。放在 `flux-core`，因此**任意开发主机都能跑，不需要设备也不需要网络**。

本批次订阅还没实现，所以生成的输入只有模板加空的节点集；纯函数性质与测试**现在就要建立**，等批次 C 再补测试就晚了——那时它会变成"让测试适应实现"。

## B3 — `flux.toml` 三个维度（§17.0.2 第 7 项）

**合同**：§11.2、§27.2.2。

`apps` + `bypass_cidrs` 两个平铺键换成 `[apps]` / `[cidr]` / `[interfaces]`，每个都是**一个 mode 加一个 list**。`[ssid]` 与 `[subscription]` 的 schema 一并落地（行为分别在批次 D 与 C，本批次只要解析与校验）。

三条不能弄错的语义：

1. **`mode = "blacklist"` 且列表为空 = 自动模式。** 不要加第三个枚举值——一个能用两种方式表达的状态迟早会分叉。
2. **`@` 开头即文件引用，只看这一个字符。** **禁止**用"能不能解析成 CIDR"来判断是不是路径：那会让一个打错的 CIDR 静默变成文件名。路径只在 `config/` 下解析，不递归（被引用的文件里不能再有 `@`），文件缺失是 `check` 错误。
3. **`status` 必须打印当前生效的 mode，不能只打印条目数。** 白名单模式下一个打错的条目会让一切静默直连——只报条目数的话，用户看到的是"策略已加载"。

容量上限见 §11.2.3。**超限是配置错误，不截断、不部分应用**：静默截断产生的是一份用户没写过、也看不见的策略。

## B4 — inotify 覆盖模板与列表文件（§17.0.2 第 15 项）

**合同**：§29.6、§26。

`config/` 目录的 inotify 已经在监听。把它接到：模板或任一 `@file` 列表变化 → 重新生成 → 校验 → 换代（§9.4 的候选切换，不是就地改写）。

**路径限定在 `config/` 下正是为了这个**：监听目录就自动覆盖了列表文件，不需要维护一个动态的 watch 集。

## 验收

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p flux-core && cargo test -p xtask
cargo xtask doc-check
```

加上 B2 那条纯函数测试必须存在且通过。

**不要碰**：`docs/spec/**`、`docs/history/**`。发现合同有问题就停下报告。

## 边界

- **不实现订阅抓取**（批次 C）。`[subscription]` 只解析与校验，`url` 为空是默认值，此时不抓取、不挂表、不创建 `run/subscription.raw`。
- 不实现 SSID 行为、webroot、`clash_api` 降级（批次 D）。
