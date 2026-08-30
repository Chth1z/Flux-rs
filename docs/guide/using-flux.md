# 怎么用 Flux-rs

> **投影。** 本文描述规范性合同，不创造合同；与 [`../spec/interaction.md`](../spec/interaction.md) 冲突时，错的是本文。
>
> 这里是取向与叙述：为什么这样设计、出问题怎么办。确切的条款——开关语义、配置 schema、命令集、status 的最低信息、诊断包的隐私约定——都在 §27。

## 设计取向

目标按优先级排序：

1. 模块故障不能造成全设备持久断网；准入后的 drop 边界必须明示；
2. 用户能知道现在是否真的在工作；
3. 出问题时能获得具体原因并自行恢复；
4. 配置只有一个真相源；
5. 最后才是功能数量。

所有状态文案都遵守一条规则：只报告已证明的状态。不能确认 cleanup、接口可达或 engine ready 时，明确写 unknown/pending/excluded，不用乐观措辞掩盖。

---

## 出问题时怎么自救

### 设计保证

- 准入前的失败保持 Direct；
- 物理接口缺 `clsact`、顺序未知或存活验证失败时，只排除该接口；若因此没有任何 active coverage，顶层按 R091-10 进入 `Inactive`；
- 不 flush 系统 qdisc/rule，不替换 AOSP BPF，不写全局安全 sysctl；
- fresh install 默认 Disabled；
- ownership 不完整时宁可不删。

已经 admission 的 TCP 不是绝对 fail-open；内部状态损坏允许 drop/reset，避免泄漏真实目的。

### 恢复路径

1. 在 root 管理器里关掉这个模块——当场生效，不用重启。等价命令是 `fluxd disable`；
2. 卸载模块：脚本先 `fluxd stop`，再删除状态根；按管理器要求重启；
3. 使用管理器安全模式/禁用全部模块恢复启动。

第 1 条现在只需要拨一下管理器里的开关，这是把开关合并到管理器那个文件之后最直接的收益：手机上没有终端也能立刻停用。

卸载脚本不会同步 flush 内核网络对象。重启是“零非持久内核残留”承诺的一部分。

---

## 0.9.1 不做的事

永久不做（理由是结构性的，不随版本改变）：

| 不做 | 原因 |
|---|---|
| 自己实现代理协议 | 使用未修改官方 sing-box |
| 在 Flux 按域名选 app | UID 粗分流归 Flux，域名路由归 sing-box |
| 自动联网探测与回滚 | 离线/受限网络会误判；无 heartbeat |
| 后台常驻通知 | root 模块按需查询 |
| 立即 flush 式卸载 | 无法安全证明系统对象所有权 |

0.9.1 不做、后续版本要做（所有者 2026-08-29 确认，见 `../history/rejected-and-deferred.md` §21.1）：

| 项 | 0.9.1 现状 |
|---|---|
| Flux WebUI / 代理控制面默认体验 | 不打包、不下载、默认不启用 `clash_api`；用户可自行配置回环 + 非空 secret 的外部 UI |
| subscription 转换 | 无 `subscribe` 命令，不下载远程 rule-set，不反写用户配置 |
| `explain` / TUI / `watch` | 没有实现；先保证 `status` 完整诚实 |

在真正开工那个版本之前不为这三项预建空接口——延期项不等于现在留脚手架。

---

## 0.9.1 已裁决事项

| 事项 | 结论 |
|---|---|
| 开关 | 管理器自己的模块开关 + inotify，当场生效；无 `action.sh` |
| 状态显示 | `module.prop` 的 `description=` 由 `fluxd` 实时重写 |
| 默认状态 | fresh install 在管理器里显示为已禁用，bootstrap 配置已生成 |
| 配置 | 两份 authority file，Flux 永不反写 |
| WebUI | 0.9.1 不打包、不下载；用户可选外部 UI。后续版本做 |
| 订阅 | 0.9.1 不做，后续版本做 |
| CLI | 只列 §3.1 已实现命令 |
| 诊断 | logcat 默认关闭 |
| 卸载 | narrow disable/stop/delete + reboot，不 flush |
| 控制协议 | 单行 JSON over SEQPACKET，无独立 wire version |
| 失败语义 | admission-bounded fail-open |
