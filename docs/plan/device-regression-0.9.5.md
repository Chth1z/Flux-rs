# 0.9.5 真机回归清单

> **这是 `plan/` 层：会被做完。** 做完后把结果按"断言 / 实测"写进 `../history/review-log.md` §0.6 的新小节，本文移入 `history/`。
>
> 需要所有者授权（GOV-1.2：装卸模块、重启是改测试机的持久状态）。所有者上次授权的设备：SM-S9180 / 5.15.211 / KernelSU。
>
> **2026-09-06 进度。** 装卸、激活表、批次 B/D/E/F 的命令行断言已写入 [`../history/review-log.md`](../history/review-log.md) §0.6.6。仍未做：设备侧订阅抓取（缺口 1）、WebUI 按钮、Phase 3–7 套件、Magisk/APatch。三个缺口待所有者定处置后，本文才移入 `history/`。

## 为什么不能原地升级

手机上跑的是 8 月 29 日装的 0.9.1 形态：用户权威文件是 `config/sing-box.json`（手工用 `jq` 合并过订阅的完整配置），`flux.toml` 是旧 schema（`apps` / `bypass_cidrs` 两个平铺键）。0.9.5 的权威文件是 `config/template.json`，`flux.toml` 是四维度 schema，**旧 `flux.toml` 会被新解析器以"未知键"拒绝**，`config/sing-box.json` 则会被无视。原地升级得到的是一个 `flux_config_invalid` 的 Inactive。

所以先卸载再装：`uninstall.sh` 只删 `/data/adb/flux-rs`，重启后内核对象自然消失（§8.8），然后当成新设备装。

## 0. 构建

WSL 里（有 NDK 27.3）：

```
cd /mnt/d/Github/Flux-rs
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.3.13750724
FLUX_BUILD_BPF=1 cargo xtask package
```

`dist/Flux-rs-v0.9.0-arm64.zip`——版本号还是 0.9.0，这是对的，发布前才提升。记下 `SHA256SUMS`。

## 1. 卸载旧的，装新的

1. KernelSU 里卸载 `Flux-rs`，重启。`ip rule`、`tc qdisc show`、`ip link` 里没有 `flxrs*`、priority 100、table 20260（§20 第 9 条）。
2. `adb push dist/*.zip /sdcard/`，KernelSU 里安装，**不要**立刻重启。安装日志应打印新的三步引导（含 `fluxd` 完整路径），模块显示为已禁用。
3. `adb shell su -c cat /data/adb/flux-rs/config/flux.toml`：新 schema、`[ssid]` 表存在。

## 2. 配置

编辑 `/data/adb/flux-rs/config/flux.toml`：`[apps]` whitelist 填 8 月 29 日那五个应用；`[subscription] url` 填 8 月 29 日用过的那个机场链接（在 `scratch/` 里，**不进任何文档**）；`[cidr]` 加 `100.64.0.0/10`（SIM 发 CGNAT 地址）。`template.json` 不动。

`/data/adb/modules/flux_rs/bin/fluxd check` 必须通过。它现在**不再**因为没有 `clash_api` secret 而失败——默认模板根本没有 `clash_api`。

## 3. 首次启用

KernelSU 里打开模块，重启一次（§27.5）。之后：

| 断言 | 怎么看 |
|---|---|
| 监督进程 + reactor 两个 `fluxd daemon`，父子关系正确 | `ps -A \| grep fluxd`，`cat /data/adb/flux-rs/run/daemon.lock` 里是 **子** 进程 pid |
| `service.log` 只有 boot 三行，没有循环痕迹 | `cat /data/adb/flux-rs/service.log` |
| 订阅抓到、精修、填进模板 | `status` 的 `warnings` 无 `subscription_*`；`run/subscription.raw` 存在；`run/sing-box.<gen>.json` 的 `outbounds` 里有机场节点，selector 组已填 |
| 三个接口 `pref 2`、`reachable` | `fluxd status`；对照 §0.6.4 的九条 |
| 捕获数 = assign 数 | `status --json` 的 `counters`：`admit_tcp == in_assign_tcp`、`admit_udp == in_assign_udp` |
| 真流量走节点 | 打开 Twitter/YouTube；引擎日志出现 `outbound/<type>[<节点>]` |
| `module.prop` 首行是新句子，状态行 `🥰 [Active] gen N · 5 apps · …` | KernelSU 模块列表 |

## 4. 0.9.5 新行为

| 批次 | 断言 | 操作 |
|---|---|---|
| B/C | 改 `template.json` 里一个无关字段（如 `log.level`），换代；再 `reload` 一次不变的模板，**不**换代、引擎 pid 不变 | `status` 的 `generation` / `engine.pid` |
| C | `fluxd subscribe` 在内容不变时不换代 | 同上 |
| C | 断网后 `fluxd subscribe` 报 `subscription_fetch_failed:<原因>`，原因不是笼统的 `request`；当前代保留 | 飞行模式 |
| D | KernelSU 模块列表的按钮打开页面：默认模板下显示"No control panel is configured"而非连接失败 | 点按钮 |
| D | 模板里加 `experimental.clash_api`（回环、secret、`external_ui`）后重开页面跳到面板且不用输 secret；把 secret 留空，`fluxd check` 只是告警、`status.warnings` 也有 | 编辑模板 |
| E | `kill -9 <reactor pid>`：1 秒后新 reactor、新引擎，监督进程 pid 不变，流量恢复；`service.log` 一行 `reactor killed by signal 9; restarting in 1 s` | `cat run/daemon.lock` 取 pid |
| E | 第二次 `fluxd daemon` 立刻以 3 退出并点名持锁 pid | 手动执行 |
| E | `kill -9 <监督进程 pid>`：reactor 和代理照常，`fluxd daemon` 再起被拒 | 之后重启恢复监督 |
| F | `[ssid]` blacklist 填当前 Wi-Fi 名：`status.ssid.paused = true`、`module.prop` 显示 `😴 [Inactive] paused on this Wi-Fi network`、引擎已停；切到蜂窝或删掉该项：恢复 Active。**`status`、`module.prop`、`fluxd.log` 里都不出现 SSID 字符串** | 编辑 `flux.toml`，`fluxd reload` |
| F | `[ssid]` 为空时 `status.ssid` 为 `null`，`/proc/<reactor pid>/net/netlink` 无 `NETLINK_GENERIC`（协议 16） | 同上 |
| D | 管理器开关：关 → 6 秒内 Disabled，开 → Active，不重启 | KernelSU 开关 |

## 5. Phase 3–7 设备套件

它们会创建和销毁 `flxrs0/1`，**与运行中的实例冲突**。先 `fluxd disable`，再按 `FLUX_PHASE{3..7}_DEVICE_TEST=1` 逐个跑（`crates/fluxd/tests/phase*_device.rs` 头部有说明），每个结束时看残留检查为空。跑完 `fluxd enable`。

## 6. 收尾

- `fluxd bugreport`：zip 里没有 `template.json`、`flux.toml`、`sing-box.<gen>.json` 原文，没有 SSID。
- 结果写进 `review-log.md`；§20 的十四条逐条打勾或写明未满足项（第 10 条三管理器 smoke 目前只能证明 KernelSU——要么找到 Magisk/APatch 设备，要么写进发布说明的边界）。
- 都过了才提升 workspace 版本、打签名 tag（§13.4、GOV-4.4）。
