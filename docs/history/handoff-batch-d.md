# 交给实现者的任务书 D：收尾——webroot、告警降级、用户文案

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md`、`../spec/interaction.md`、`../spec/failures.md`，与它们冲突时错的是本文。完成并通过审查后，审查者删除本文并划掉 §17.0.2 对应的行；实现者不动 `docs/plan/`。
>
> **前置：批次 A、B、C 已完成并提交。** 模板归属、纯函数生成、订阅流水线都已就位。本批次不引入新机制，三件事都是把合同里已经写清的收尾做完。

## D0 — 不加依赖

本批次**不需要任何新的第三方依赖**。发现自己想加一个就停下来报告，不要加（GOV-1.2）。

## D1 — `webroot/index.html`（§17.0.2 第 5 项）

**合同**：§28.8、§13.1、§27.2.1、§27.2.4。

### 它是什么，不是什么

root 管理器（KernelSU、APatch）在模块列表旁给带 `webroot/index.html` 的模块显示一个按钮，点开是一个 WebView。`Flux-original` 的页面是 12 行，无条件跳到 `http://127.0.0.1:9090/ui/`。**它不是 WebUI**，C8 延期的 WebUI 也不是本批次要做的。

Flux 的版本做两处改进：跳转 URL 带上用户配置的控制器地址与 secret，用户不用手打；没配 `clash_api` 时页面说明原因，而不是跳进一个连不上的地址。

### 信息从哪来

**不从 Flux 写的任何文件来。** §27.1.2 只允许 Flux 在模块目录写 `disable` 和 `module.prop` 的 `description=` 两处；§27.2.3 默认模板不含 `clash_api`，所以安装时也没有任何 secret 可以预埋。页面在**被打开的那一刻**去问。

所有会打开 `webroot` 的管理器都暴露同一个 JavaScript 桥接对象 `ksu`（KernelSU 原生；APatch 的 FAQ 写明实现与 KernelSU 完全相同；Magisk 本身**没有** WebUI，Magisk 用户用的独立启动器 KsuWebUIStandalone / WebUI X 同样暴露 `ksu`）。裸接口是：

```js
// 回调是挂在 window 上的函数名字符串，签名 (errno, stdout, stderr)
window.cb = function (errno, stdout, stderr) { /* ... */ };
ksu.exec("<command>", JSON.stringify({}), "cb");
```

`errno` 为 0 表示成功。命令在 root shell 里跑。不要用 npm 上的 `kernelsu` 包——本页面**不允许有构建步骤**，一个文件、零依赖、零外部资源。

### 页面行为，按顺序

1. **没有桥接**（`typeof ksu === "undefined"` 或 `ksu.exec` 不是函数）：显示一句话——这个页面要从 root 管理器的模块列表打开；Magisk 没有这个入口，可用 KsuWebUI 之类的启动器。**不要**回落成无条件跳转 `127.0.0.1:9090`，那正是合同禁止的"跳进连接失败"。
2. **问守护进程**：`ksu.exec` 运行 `/data/adb/modules/flux_rs/bin/fluxd status --json`（§1.1 规定的模块路径，与 §27.5 一致）。`errno != 0` 或 `stdout` 不是 JSON → 显示 Flux 没在运行；如果刚刚才在管理器里打开模块，需要重启一次（§27.5：被禁用的模块不会启动守护进程）。
3. **引擎没跑**（`engine.running` 为假或 `engine.effective_config` 为空）：显示 `state`（Disabled / Inactive）与 `last_error`（有就显示），提示运行 `fluxd status` 看原因。
4. **读当前代的配置**：`engine.effective_config` 是绝对路径，`ksu.exec` 运行 `cat <该路径>`（路径来自 `fluxd` 自己的输出，不含空格，但仍按 shell 规则加引号），解析 JSON，取 `experimental.clash_api`。
   - 不存在，或没有 `external_controller` → 显示没配置控制面板，并说怎么配：在 `/data/adb/flux-rs/config/template.json` 加 `experimental.clash_api`（`external_controller` 监听 `127.0.0.1`、非空 `secret`、`external_ui` 指向已下载的面板），跑 `fluxd check`，再打开本页。
   - 存在但没有 `external_ui` → sing-box 不会在 `/ui/` 提供任何页面。显示地址与 secret，让用户把自己的面板指过去；**不要**跳转。
   - 都有 → 跳转。
5. **跳转 URL**。从 `external_controller` 拆出 host 与 port（要处理 `[::1]:9090` 这种带方括号的 IPv6 写法）；host 是 `0.0.0.0` 或 `::` 时用 `127.0.0.1` 去连。三种常见面板读参数的位置不同——yacd 读查询串，zashboard 与 metacubexd 读 `#/setup?` 后面的——所以两处都带：

   ```
   http://HOST:PORT/ui/?hostname=HOST&port=PORT&secret=SECRET#/setup?hostname=HOST&port=PORT&secret=SECRET
   ```

   `SECRET` 要 `encodeURIComponent`。用 `window.location.replace`，和原版一样。

页面文字用英文（与 `module.prop`、安装器输出一致），说"哪里缺了、怎么补"，不出现内部标识符（AUTH-6.1）；`last_error` 这类 token 是合同规定的稳定标识，显示它时同时给出 `fluxd status` 这条查它的命令。目标是一个 100 行上下的文件；样式几条够用就行。

### 打包与守卫

- `xtask/src/package.rs`：`ALLOWLIST` 从 14 变 15，`webroot/index.html` 紧跟 `uninstall.sh` 之后（§13.1 的顺序就是归档顺序），模式 `0644`，内容经 `normalize_lf`。
- **打包时校验 `module/webroot/` 里只有 `index.html` 一个文件**，多一个就拒绝打包并说明：多出来的任何东西就是 C8 延期的那个 WebUI。这条让 §13.1 的"禁止 WebUI"变成机器能查的性质，而不是一句叮嘱。
- `module/customize.sh`：payload 完整性检查的清单加上 `webroot/index.html`。
- `tools/phase8/module_lifecycle_test.sh` 第 106 行现在断言 `module/webroot` **不存在**，要反过来：断言它存在，且里面**恰好**一个文件 `index.html`。

## D2 — `clash_api` 不安全时告警而非硬拒（§17.0.2 第 11 项）

**合同**：§27.2.4；判据是 §23 与 PHIL-6：**只有当失败是静默且用户无法自行诊断时才硬拒绝。** 空 secret 或非回环监听是可诊断的意图差异——别的 app 连得上，用户试一下就知道——而且那是 sing-box 自己权限范围内的决定（§9.6）。

### 改什么

`crates/fluxd/src/checks.rs` 的 `check_clash_api` 现在往 `report.errors` 推；这两条要变成告警，而且**`status` 里也要看得见**（§27.2.4 原话："visible in `status`"）。

现成的路是 `sing_box_warnings(user)`：它已经同时被 `check_template_json`（`check` 路径）和 reactor 的 `refresh_config_warnings`（`status` 路径）调用。把 `clash_api` 的两条检查并进去，删掉 `check_clash_api`，两条路径自然都覆盖，不要再开第三条。

文案按 AUTH-6.1：说哪里错了、怎么改。例如：

- `clash_api secret is empty: any app on this device can reconfigure the proxy. Set experimental.clash_api.secret in config/template.json.`
- `clash_api listens on 0.0.0.0:9090, not loopback: the control port is reachable from the network. Use 127.0.0.1:<port> unless that is what you want.`

`clash_api_secret_missing` / `clash_api_not_loopback` 这两个 token **不进 `last_error`**——它们不再是错误；`warnings` 是自由文本（§24.2），token 可以作为行首前缀保留，便于 `rg`。

顺带把该函数注释里错引的 `§27.3.2` 改成 `§27.2.4`。

### 测试

- `clash_api_hardening_is_an_error_not_a_warning` 反转：`report.ok()` 为真，两条告警都在 `report.warnings` 里。改名让它说真话。
- `loopback_controller_with_secret_passes`：零告警。
- `sing_box_warnings` 是纯函数，直接对它加一个单测：`0.0.0.0` 与 `[::]` 都算非回环，`127.0.0.1`、`[::1]`、`localhost` 算回环。

## D3 — 面向用户的文案（§17.0.2 第 16 项）

**合同**：§27.1.3、§13.1；规则是 AUTH-6.1：面向用户的文字**尽量不出现标识符**，需要时给出能查到它的命令；不陈述与其它项目的差异（用户不是来做选型的）；不用实现词汇描述用户能看到的现象。

### `module.prop` 第一行

`crates/flux-core/src/version.rs` 的 `MODULE_DESCRIPTION` 改为，一字不差：

```
Per-app proxy: the apps you pick go through sing-box, everything else is left alone.
```

原句 `Transparent per-app proxying via eBPF and an unmodified official sing-box.` 是写给评审看的定位陈述——"unmodified official" 是在和别的项目撇清关系。§27.1.3 的示例已经改成新句子。`version.rs` 里三处引用原句的测试跟着改。**状态行的格式不动**：`🥰 [Active] gen N · X apps · <ifaces>` 那张表是 §27.1.3 的合同。

`docs/guide/how-to.md` 第 53 行的示例输出跟着改成新句子（`guide/` 跟合同走）。

### 安装器输出

`module/customize.sh` 末尾那段引导重写，要求：

- 第一句说清"装好了，但现在是关着的，什么都还没代理"；
- 三步各一行，命令给**完整路径** `/data/adb/modules/flux_rs/bin/fluxd check`——模块的 `bin/` 不在 PATH 上，写 `fluxd check` 用户照着敲会得到 not found；
- 首次启用要重启一次这件事保留，但用一句话说完，不解释守护进程与开关的机制。

不改 `customize.sh` 的检查逻辑，只改 `ui_print` 的文字。

### `module/flux.toml` 注释

- `[ssid]` 那行 `SSID 行为将在后续批次接通` 是计划用语，用户不知道什么是批次。改成陈述事实：这个表现在填了也不会生效。
- 顶部 `fresh install 装完即为停用状态` 里的英文术语换成中文："首次安装后为停用状态"。

### 不在本批次范围

- `README.md`：对外表述归所有者（GOV-1.2），不动。
- `fluxd` 的 CLI 帮助文本与 `status` 人类输出里的 token：后者是 §24 的合同。
- `module/template.json` 的注释。

## 验收

**只跑 `AGENTS.md` 列的主机门禁，加上 aarch64 类型检查**：

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
cargo clippy -p fluxd --target aarch64-linux-android --all-targets
```

aarch64 那条在这台 Windows 主机上会因为 `ring` 需要交叉编译器而失败——那是环境问题，不是你的改动。报告失败原因即可，审查者在 WSL 里跑。

`tools/phase8/module_lifecycle_test.sh` 需要 `sh`；有就跑（Git Bash 或 WSL），没有就说明跳过。**不要声称没跑的东西通过了。**

**Windows 上跑不了、也不要试的**：`cargo clippy --workspace --all-targets`、`cargo xtask abi-check`、`cargo xtask btf-check`。由 Linux CI 跑（§15.1）。

## 边界

- 不实现 SSID（§29.1–§29.2），那是下一批。
- 不动 `module/service.sh` 的重启循环（§17.0.1 第 5 项是所有者待决的设计问题）。
- **不要碰** `docs/spec/**`、`docs/history/**`、`docs/plan/**`、`README.md`。合同有问题就停下报告。
