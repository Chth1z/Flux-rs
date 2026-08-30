# 第 27 部分：交互合同

> **规范性合同。** 实现与本文不一致时，错的是实现。面向读者的内容分三处：[`../guide/introduction.md`](../guide/introduction.md) 讲这是什么、边界在哪（给用户），[`../guide/architecture.md`](../guide/architecture.md) 讲为什么是这个形状（给实现者），[`../guide/how-to.md`](../guide/how-to.md) 讲怎么装怎么配、出问题怎么办。
>
> §27 是 0.9.0 编号空间之后新开的一部分。这些条款此前住在 `docs/ux.md` 里，用它自己的 §1–§8 编号，与蓝图的 §1–§8 冲突——`rg "§3"` 会返回两个不相干的东西，引用必须靠文件名消歧。那违反了 `../AUTH-1.1 的全局稳定编号规则，所以拆分时并入了全局编号。

## 27.1 开关：管理器自己的模块开关

### 27.1.1 唯一真相源

```text
/data/adb/modules/flux_rs/disable
存在 = desired disabled（收敛中可短暂为 Inactive，完成后为 Disabled）
不存在 = desired enabled（随后可能是 Inactive 或 Active）
```

**这就是 Magisk / KernelSU / APatch 在你拨动模块开关时创建和删除的那个文件。** Flux 不再维护第二个开关：`/data/adb/flux-rs/disable` 不存在，`flux.toml` 里也没有 `enabled` 键。

`fluxd` 用已有 inotify source 监视模块目录：

- 文件出现：先 publish `active=0`，再停 engine；daemon 留在事件循环等待；
- 文件消失：重新读取 authority files 并收敛。

结果是**在管理器里关掉模块当场生效，不需要重启**。管理器原本的语义是"下次启动不加载"，Flux 让它同时具备当前 boot 的效力；下次启动不加载这件事仍然照旧成立。

`fluxd enable` / `fluxd disable` 写的是同一个文件，所以命令行和管理器界面永远一致，不会出现"命令行说开着、管理器显示关着"。

“立即停用”指立即停止新流 admission 并终止 engine，不表示立刻 detach TC 或删除 veth/rule/route/map。保留对象可以避免在 stop/uninstall 路径里误删系统状态；设备重启后非持久对象自然消失。

### 27.1.2 Flux 对模块目录只碰两个文件

模块目录属于管理器。Flux 只写 `disable` 和 `module.prop` 的 `description=` 行，绝不创建、移动或删除这个目录，也不改 `module.prop` 的其它键。

### 27.1.3 `module.prop` 是状态显示器

没有 `action.sh`——开关就是管理器自己的开关，不需要第二个按钮，也就不受 Magisk v28+ 的 Action 支持限制。

作为交换，`fluxd` 把当前状态写进 `module.prop` 的 `description=`，管理器的模块列表因此就是状态面板：

```text
description=Transparent per-app proxying via eBPF and an unmodified official sing-box.\n🥰 [Active] gen 7 · 3 apps · rmnet_data0
```

`\n` 是字面的两字符转义，管理器渲染成换行；第一行始终是原始描述。规则：

| 状态 | 显示 |
|---|---|
| Active | `🥰 [Active] gen N · X apps · <active 接口>` |
| Inactive，有具体错误 | `🤯 [Inactive] <稳定错误 token>` |
| Inactive，收敛中 | `🤔 [Inactive] converging` |
| Disabled，engine 已停 | `😴 [Disabled] toggle this module on to enable Flux` |
| Disabled，engine 仍在终止 | `😴 [Disabled] stopping` |

三条实现约束：写入前先比对，状态没变就不写；用同目录临时文件加 `rename` 原子替换，管理器读到的永远是完整文件；重写必须幂等，反复写不会让 `description=` 无限增长。写失败只是没有状态显示，绝不影响 daemon——`module.prop` 归管理器所有。

---

## 27.2 配置

### 27.2.1 路径与职责

```text
/data/adb/modules/flux_rs/
└── disable                          管理器拥有；唯一开关（§27.1.1）

/data/adb/flux-rs/
├── config/
│   ├── flux.toml
│   └── sing-box.json
├── fluxd.log
└── run/
    ├── daemon.lock
    ├── control.sock
    └── effective-sing-box.<generation>.json
```

**状态根下没有 `disable`。** 开关只有一个，在模块目录里，由 root 管理器创建和删除。

- `config/flux.toml`：选择 app 与 CIDR bypass；
- `config/sing-box.json`：用户拥有的完整官方 sing-box 配置；
- `run/effective-*.json`：Flux 注入内部 TProxy inbound 后的一次性生成物，不是用户配置。

Flux 永不反写两份 authority file。安装或升级只在文件缺失时复制 `etc/default-flux.toml` 与 `etc/default-sing-box.json`。

### 27.2.2 `flux.toml` 唯一 schema

```toml
# 格式为 userId:packageName。shared UID 会连带捕获同 UID 的包。
apps = [
  "0:com.example.browser",
]

# 额外 Direct 的目的网段。固定安全 bypass 无需重复。
bypass_cidrs = [
  "192.168.0.0/16",
]
```

规则：

- 拒绝未知键，并报告最接近的合法键；
- package/CIDR 必须 canonical、去重且不超容量；
- package 不存在或 shared UID 扩展必须在 `check` 中明确显示；
- 没有 `bypass_v4`、`bypass_v6`、`bypass.files`、subscription 或 `enabled`。

### 27.2.3 bootstrap engine 配置

包内路径是 `etc/default-sing-box.json`；仓库源文件是 `module/template.json`。它取自原版 Flux 的 `conf/template.json`，因此两个项目对用户是同一套形状：DNS 分流与 fakeip、`clash_mode` 规则、远程 rule-set、`PROXY`/`GLOBAL` 选择器。

默认值必须成立的四条性质（`cargo xtask template-check` 逐条检查，再用官方 sing-box 跑一次真实 `check`）：

| 约束 | 为什么 |
|---|---|
| 无 `inbounds` | Flux 运行时注入两个 tproxy inbound，模板 inbound 会与之抢监听 |
| 无 `experimental.clash_api` | 默认值不开控制端口；用户自己开的规矩见 §27.2.4 |
| 每个 selector/urltest 至少一个成员 | 空 selector 无法解析，用户还没编辑就会 `check` 失败 |
| fakeip 段避开固定 bypass | Flux 无条件 bypass 整个 ULA `fc00::/7`，落在里面的 fakeip 会被直连，IPv6 fakeip 静默全废。按解析后的前缀与 `flux_core::cidr::fixed_bypass` 求包含关系判定，不按字符串前缀——`fd00::/8` 与 `FD00::/8` 必须都被拒绝 |

模板里没有任何服务器、订阅或凭据：`PROXY` 起手只指向 `DIRECT`。用户随后把它替换为自己的完整 sing-box JSON。Flux 不替用户生成节点、规则组或订阅内容。

### 27.2.4 可选 `clash_api`

Flux 不打包 WebUI，也不管理 zashboard。用户若自行配置 `experimental.clash_api`：

- `external_controller` 必须监听 loopback；
- `secret` 必须非空；
- UI 下载、TLS、更新与访问控制由用户负责。

`fluxd check` 把不安全的 controller/secret 作为错误，而不是自动改配置。

---

## 27.3 CLI 与控制 socket

### 27.3.1 当前命令集

| 命令 | 行为 |
|---|---|
| `fluxd daemon` | 前台 reactor；`start`、`run` 是 alias |
| `fluxd status [--json]` | 人类可读或原始 JSON 状态 |
| `fluxd check` | 只读校验配置、package 解析与 engine config |
| `fluxd enable` | 删除运行时 `disable` 并请求收敛 |
| `fluxd disable` | 创建 `disable`、inactive、停 engine |
| `fluxd reload` | 分别处理 policy 与 engine candidate |
| `fluxd stop` | inactive、停 child、daemon 退出 |
| `fluxd bugreport` | 生成诊断 ZIP |
| `fluxd version` | 版本、ABI magic、构建信息 |

0.9.1 没有 `explain`、`watch` 或 `subscribe`。文档不展示不存在的命令。

### 27.3.2 socket interface

`/data/adb/flux-rs/run/control.sock` 是 mode 0600 的 root-only `SOCK_SEQPACKET`，承载六个幂等 request：`status/check/enable/disable/reload/stop`。

0.9.1 不设独立 `wire_version`。响应已有产品 `version` 与 `abi_magic`，当前只有 CLI 一个真实客户端；出现第二个独立客户端时再设计实际兼容策略。

### 27.3.3 status 的最低信息

人类输出至少包含：

- `Disabled | Inactive | Active`；
- generation 与 backoff；
- root manager/runtime mode；
- engine PID、4 个 socket readiness、effective file；
- selected/draining/bypass/self-address 计数；
- 每个候选接口一行：名字、active/excluded、entry、实际 pref、可达性、稳定 reason；
- current counters、warnings、hints、first concrete error。

`Active` 要求 engine generation 已提交、`control.active=1` 且至少有一个 physical capture interface active。最后一个 active interface 消失时顶层进入 `Inactive`；只丢失部分 coverage 时保持 `Active` 并在逐接口状态中说明。

JSON 里的 `ifaces[].pref` 是该接口 capture filter 实际占用的 preference，逐接口选择，禁止把它当设备级常量缓存。既有 `first_applicable` 字段按 R091-05 解释为“可达性已验证通过且前置快照未漂移”，不是“dump 中第一个 classifier”：

| 值 | 含义 | 人类输出 |
|---|---|---|
| 缺省（`None`） | 尚未得出结论：`flx_verify` 未出结果，或连 dump 都失败 | `reachability unverified` |
| `true` | 存活验证收到包，或已有自有 filter 通过身份 + 前置快照复核 | `reachable` |
| `false` | 明确判定不可达：链被遮挡、身份漂移或 attach 失败 | `not reachable` |

人类输出统一使用 reachable / 可达这套措辞，不出现 “first applicable”。

---

## 27.4 诊断包

`fluxd bugreport` 默认生成脱敏 ZIP：

- 包含 status、版本/ABI、root manager、有限日志尾部、网络/BPF 枚举和配置 shape；
- 不包含原始 `flux.toml` 或 `sing-box.json`；
- 地址、接口敏感值默认稳定脱敏；
- logcat 默认不含，`--with-logcat` 才显式加入并警告；
- `--raw` 关闭地址脱敏并警告；
- `-o <dir>` 选择输出目录。

诊断包不能声明“已清理”除非新的实际枚举证明对象不存在。

---

## 27.5 第一次使用

fresh install 的确定顺序：

1. 安装器创建状态根和两份缺失的 bootstrap config；
2. 在模块目录创建 `disable`，因此**装完模块在管理器里就是关的**，安装动作本身不捕获流量；
3. 用户编辑 `config/flux.toml` 与 `config/sing-box.json`；
4. 运行 `fluxd check`；
5. 检查通过后在管理器里打开这个模块（或运行 `fluxd enable`，两者写同一个文件）；
6. 用 `fluxd status` 或管理器列表里的描述确认 engine 与逐接口 coverage。

安装器必须把第 2 步说清楚，否则用户会把"装完显示已禁用"当成安装失败。升级不重建这个文件：用户开着就保持开着。

**第 5 步的首次启用需要重启一次。** 被禁用的模块不会执行 `service.sh`，所以此时还没有 daemon 在监听开关；即时生效的前提是 daemon 已经在跑。此后的每一次开关才是当场生效。

```sh
FLUXD=/data/adb/modules/flux_rs/bin/fluxd
$FLUXD check
$FLUXD enable      # 等价于在管理器里打开模块
$FLUXD status
```

如果没有任何 selected app，配置仍可合法，但 status 必须明确显示 selected=0；不能把它说成“已代理”。

---
