# 0.9.1 交互与使用体验设计

规范性合同是冻结的 `blueprint.md` 基线加 `blueprint-0.9.1.md` 增量。本文只规定用户能看到、能操作、能恢复的当前功能，不为未来 UI 或订阅预写接口。

文档语言按 `docs/authoring.md`：中文为主，专有名词与有歧义处保留英文。

---

## 0 设计取向

目标按优先级排序：

1. 模块故障不能造成全设备持久断网；准入后的 drop 边界必须明示；
2. 用户能知道现在是否真的在工作；
3. 出问题时能获得具体原因并自行恢复；
4. 配置只有一个真相源；
5. 最后才是功能数量。

所有状态文案都遵守一条规则：只报告已证明的状态。不能确认 cleanup、接口可达或 engine ready 时，明确写 unknown/pending/excluded，不用乐观措辞掩盖。

---

## 1 开关：`disable` 文件

### 1.1 唯一真相源

```text
/data/adb/flux-rs/disable
存在 = desired disabled（收敛中可短暂为 Inactive，完成后为 Disabled）
不存在 = desired enabled（随后可能是 Inactive 或 Active）
```

`fluxd` 用已有 inotify source 监视状态根：

- 文件出现：先 publish `active=0`，再停 engine；daemon 留在事件循环；
- 文件消失：重新读取 authority files 并收敛；
- `flux.toml` 没有 `enabled`；
- `module.prop` 的 description 只是显示，不是状态源。

“立即停用”指立即停止新流 admission 并终止 engine，不表示立刻 detach TC 或删除 veth/rule/route/map。保留对象可以避免在 stop/uninstall 路径里误删系统状态；设备重启后非持久对象自然消失。

### 1.2 与管理器开关分开

`/data/adb/modules/flux_rs/disable` 属于 Magisk/KernelSU/APatch，表示下次启动不加载模块。`/data/adb/flux-rs/disable` 属于 Flux 运行时，能在当前 boot 生效。Flux 不互写这两个文件。

### 1.3 `action.sh`

0.9.1 包含 `action.sh`：

1. 读取 `fluxd status`；
2. Disabled 时明确调用 `enable`；
3. 其它状态明确调用 `disable`；
4. 把简短状态写进 `module.prop description=`，供管理器刷新显示。

它不读 stdin、不保存 toggle 位、不直接改数据面。Magisk 需要 v28+ 才显示 Action；KernelSU/APatch 按各自管理器支持。

---

## 2 配置

### 2.1 路径与职责

```text
/data/adb/flux-rs/
├── disable
├── config/
│   ├── flux.toml
│   └── sing-box.json
└── run/
    ├── daemon.lock
    ├── control.sock
    └── effective-sing-box.<generation>.json
```

- `config/flux.toml`：选择 app 与 CIDR bypass；
- `config/sing-box.json`：用户拥有的完整官方 sing-box 配置；
- `run/effective-*.json`：Flux 注入内部 TProxy inbound 后的一次性生成物，不是用户配置。

Flux 永不反写两份 authority file。安装或升级只在文件缺失时复制 `etc/default-flux.toml` 与 `etc/default-sing-box.json`。

### 2.2 `flux.toml` 唯一 schema

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

### 2.3 bootstrap engine 配置

包内路径是 `etc/default-sing-box.json`；仓库源文件是 `module/template.json`。bootstrap 只包含：

| 必须包含 | 不包含 |
|---|---|
| official direct outbound | server/subscription |
| direct final route | remote rule-set |
| `sniff` rule | WebUI/zashboard 下载 |
| `hijack-dns` rule | Flux inbound（运行时注入） |

用户随后可以把它替换为任意满足边界的完整 sing-box JSON。Flux 不替用户生成节点、规则组或订阅内容。

### 2.4 可选 `clash_api`

Flux 不打包 WebUI，也不管理 zashboard。用户若自行配置 `experimental.clash_api`：

- `external_controller` 必须监听 loopback；
- `secret` 必须非空；
- UI 下载、TLS、更新与访问控制由用户负责。

`fluxd check` 把不安全的 controller/secret 作为错误，而不是自动改配置。

---

## 3 CLI 与控制 socket

### 3.1 当前命令集

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

### 3.2 socket interface

`/data/adb/flux-rs/run/control.sock` 是 mode 0600 的 root-only `SOCK_SEQPACKET`，承载六个幂等 request：`status/check/enable/disable/reload/stop`。

0.9.1 不设独立 `wire_version`。响应已有产品 `version` 与 `abi_magic`，当前只有 CLI 一个真实客户端；出现第二个独立客户端时再设计实际兼容策略。

### 3.3 status 的最低信息

人类输出至少包含：

- `Disabled | Inactive | Active`；
- generation 与 backoff；
- root manager/runtime mode；
- engine PID、4 个 socket readiness、effective file；
- selected/draining/bypass/self-address 计数；
- 每个候选接口的 active/excluded 状态和稳定 reason；
- current counters、warnings、hints、first concrete error。

`Active` 要求 engine generation 已提交、`control.active=1` 且至少有一个 physical capture interface active。最后一个 active interface 消失时顶层进入 `Inactive`；只丢失部分 coverage 时保持 `Active` 并在逐接口状态中说明。

JSON 里的既有 `first_applicable` 字段按 R091-05 解释为“admission 时可达性验证通过且前置快照未漂移”，不是“dump 中第一个 classifier”。人类输出统一使用“reachable / 可达”。

---

## 4 诊断包

`fluxd bugreport` 默认生成脱敏 ZIP：

- 包含 status、版本/ABI、root manager、有限日志尾部、网络/BPF 枚举和配置 shape；
- 不包含原始 `flux.toml` 或 `sing-box.json`；
- 地址、接口敏感值默认稳定脱敏；
- logcat 默认不含，`--with-logcat` 才显式加入并警告；
- `--raw` 关闭地址脱敏并警告；
- `-o <dir>` 选择输出目录。

诊断包不能声明“已清理”除非新的实际枚举证明对象不存在。

---

## 5 第一次使用

fresh install 的确定顺序：

1. 安装器创建状态根和两份缺失的 bootstrap config；
2. 创建 `disable`，因此安装动作本身不捕获流量；
3. 用户编辑 `config/flux.toml` 与 `config/sing-box.json`；
4. 运行 `fluxd check`；
5. 检查通过后运行 `fluxd enable`；
6. 用 `fluxd status` 确认 engine 与逐接口 coverage。

```sh
FLUXD=/data/adb/modules/flux_rs/bin/fluxd
$FLUXD check
$FLUXD enable
$FLUXD status
```

如果没有任何 selected app，配置仍可合法，但 status 必须明确显示 selected=0；不能把它说成“已代理”。

---

## 6 出问题时怎么自救

### 6.1 设计保证

- 准入前的失败保持 Direct；
- 物理接口缺 `clsact`、顺序未知或存活验证失败时，只排除该接口；若因此没有任何 active coverage，顶层按 R091-10 进入 `Inactive`；
- 不 flush 系统 qdisc/rule，不替换 AOSP BPF，不写全局安全 sysctl；
- fresh install 默认 Disabled；
- ownership 不完整时宁可不删。

已经 admission 的 TCP 不是绝对 fail-open；内部状态损坏允许 drop/reset，避免泄漏真实目的。

### 6.2 恢复路径

1. `fluxd disable` 或创建 `/data/adb/flux-rs/disable`；
2. 在 root 管理器中禁用模块并重启；
3. 卸载模块：脚本先 disable/stop，删除状态根；按管理器要求重启；
4. 使用管理器安全模式/禁用全部模块恢复启动。

卸载脚本不会同步 flush 内核网络对象。重启是“零非持久内核残留”承诺的一部分。

---

## 7 刻意不做

| 不做 | 原因 |
|---|---|
| Flux WebUI / 打包 zashboard | 不增加下载信任面和第二套状态 |
| subscription 转换或远程 rule-set | 不反写用户配置，不扩大 0.9.1 闭环 |
| `explain`/TUI/`watch` | 当前没有实现；先保证 `status` 完整诚实 |
| 自己实现代理协议 | 使用未修改官方 sing-box |
| 在 Flux 按域名选 app | UID 粗分流归 Flux，域名路由归 sing-box |
| 自动联网探测与回滚 | 离线/受限网络会误判；无 heartbeat |
| 后台常驻通知 | root 模块按需查询 |
| 立即 flush 式卸载 | 无法安全证明系统对象所有权 |

---

## 8 0.9.1 已裁决事项

| 事项 | 结论 |
|---|---|
| 开关 | `disable` + inotify；`action.sh` 只是前端 |
| 默认状态 | fresh install Disabled，bootstrap 已生成 |
| 配置 | 两份 authority file，Flux 永不反写 |
| WebUI | 不打包、不下载；用户可选外部 UI |
| 订阅 | 0.9.1 不做 |
| CLI | 只列 §3.1 已实现命令 |
| 诊断 | logcat 默认关闭 |
| 卸载 | narrow disable/stop/delete + reboot，不 flush |
| 控制协议 | 单行 JSON over SEQPACKET，无独立 wire version |
| 失败语义 | admission-bounded fail-open |
