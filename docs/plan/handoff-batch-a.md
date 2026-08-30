# 交给实现者的任务书 A：ABI 与全局改名

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md`，与它冲突时错的是本文。完成后本文删除，对应的 §17.0.2 行划掉。

## 为什么这批先做

§17.0.2 的 16 项里，这四项动的是**其它所有项都要引用的名字与布局**。先做它们，后面的批次就不必在一个正在改名的代码库上工作。

四项之间也有序：ABI 改动决定 `flux_abi.h` 与 `abi.rs` 的形状，改名决定 wire 与 layout 的形状，两者都必须在配置模型（批次 B）动手之前落定。

## A1 — bypass value 分 RESERVED 与 POLICY（§17.0.2 第 8 项）

**合同**：§6.1.1、§6.3。

`bypass_v4` / `bypass_v6` 的 value 类型已经是 `__u8`，而 loader 恒写 `1`、BPF 只判 `!= NULL`——**这个字节从来没被读过**。用它区分两类语义完全不同的条目：

```c
#define FLUX_BYPASS_RESERVED 1   /* 机制不变量，恒直连 */
#define FLUX_BYPASS_POLICY   2   /* 用户策略，受 cidr.mode 约束 */
```

判定逻辑是一次 lookup 加一个对 mode 标志的分支，见 §6.1.1 的真值表。

要改的地方：

- `bpf/include/flux_abi.h`：加两个 `#define`；`cidr_mode` 放进 `struct flux_control` 现有的 `pad0[2]`；**bump `FLUX_ABI_MAGIC`**。
- `crates/flux-core/src/abi.rs`：镜像同步，`const _: ()` 与单元测试同步。
- `crates/flux-core/src/cidr.rs`：`fixed_bypass()` 返回的条目标记为 `RESERVED`，用户条目标记为 `POLICY`。
- `crates/fluxd/src/bpf/maps.rs`：写入时带上正确的 tag，不再恒写 `1`。
- `bpf/flux.bpf.c`：`bypass_hit()` 读这个字节并按 `cidr_mode` 分支。

**结构大小与全部 offset 必须不变**——只有契约变了。`cargo xtask abi-check` 会用 clang 核对两侧；magic 不 bump 就是 GOV-4.2 违规。

**这一项是整批里唯一动 ABI 的。** 做完先跑 `cargo clippy -p fluxd --target aarch64-linux-android --all-targets`，绿了再往下——ABI 改动的漏网调用点只会在这里现形。

## A2 — `first_applicable` 改名 `reachable`（§17.0.2 第 10 项）

**合同**：§24、§27.3.3。

旧名字断言的是 dump 顺序，而 §8.5.0 已经确定**dump 位置从来不能证明程序被执行**。名字与语义相反，靠四处文档解释，这是 PHIL-1 的典型形状。

- wire 字段 `first_applicable` → `reachable`（`crates/flux-core/src/control_wire.rs`）。
- 排除原因 token `not_first_applicable` → `identity_drift`。
- 人类输出统一用 reachable / not reachable / reachability unverified。
- **三态语义不变，且必须保住**：缺席 ≠ `false`。§27.3.3 写明了理由——把两者合并会把"用户当时没上网"报成"厂商 filter 在遮挡我们"，而那正是良性情况与这个检查要找的故障。

同时删掉解释旧名字的段落，不要留"兼容字段"注释。**没有外部客户端**：§10.3 说明 CLI 是唯一真实客户端，所以这是一次干净改名，不需要兼容窗口。

## A3 — 生成物改名（§17.0.2 第 9 项）

**合同**：§28.1。

`run/effective-sing-box.<gen>.json` → `run/sing-box.<gen>.json`。文件在 `run/` 下，"effective" 不携带信息。

- `crates/fluxd/src/layout.rs` 的路径与冷启动清理的匹配模式（§11.1 规定只删严格匹配 `sing-box.<u64>.json` 且属 root 的普通文件——**模式不能放宽**，宽到能误删别人文件的模式就是会误删）。
- 所有引用该名字的测试与文档示例。

## A4 — listener 地址单一来源（§17.0.2 第 12 项）

**合同**：§9.1、§11.2；判据 PHIL-4。

listener 地址现在硬编码在 `crates/flux-core/src/abi.rs` 与 `crates/flux-core/src/cidr.rs` 两处。同一个事实两个家，没有机制保证一致。

改成：固定 bypass 里的 listener 条目**从 ABI 常量派生**，不再各写一遍。加一个单元测试断言两者相等——如果派生做对了，这个测试是同义反复；如果哪天有人又抄了一份，它会红。

## 验收

主机上能跑的全部，全绿才算完成：

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p flux-core && cargo test -p xtask
cargo xtask doc-check
cargo clippy -p fluxd --target aarch64-linux-android --all-targets
```

**最后一条不是可选的。** `fluxd` 的数据面是 Linux-only，主机门禁编译不到它——A1 改 ABI 时漏掉的调用点只有这一条会报出来。

`cargo xtask abi-check` 与 `btf-check` **需要带 BPF 后端的 clang，Windows 开发机上没有**，由 Linux CI 跑（§15.1）。**跑不了就跳过并说明，不要因此停下**；但也不要声称它们通过了。

**不要碰**：`docs/spec/**`（合同由我维护）、`docs/history/**`（只增不改）、§17.0.2 之外的任何行为。发现合同本身有问题就**停下来报告**，不要一边实现一边改合同。

## 边界

- 本批次**不实现**订阅、SSID、webroot、三维度 `flux.toml`——那些是后续批次，现在动它们会与本批次的改名互相冲突。
- `checks.rs` 的 `clash_api` 仍报 error，第 11 项在后续批次改；本批次不动。
