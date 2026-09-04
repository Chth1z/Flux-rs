# 交给实现者的任务书 F：SSID 维度（§29）

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md` §29（含 2026-09-05 补写的匹配语义、nl80211 机制与"不激活"的定义）、§10.4、§26，以及 `../spec/failures.md` §24.1、§24.3 和 `../spec/interaction.md` §27.1.3、§27.3.3；与它们冲突时错的是本文。完成并通过审查后，审查者把本文移入 `history/` 并划掉 §17.0.2 第 6 项；实现者不动 `docs/plan/`。
>
> **前置：批次 A–E 已完成并提交。** `flux.toml` 的 `[ssid]` 表已经被解析（`flux-core::config` 的 `ssid_mode` / `ssids`），只是没人消费它。本批次把它接到顶层状态上。

## 这批要解决的问题

用户在家里或公司的 Wi-Fi 上不想走代理。`box_for_magisk` 用 `dumpsys` 轮询 SSID 来做这件事；Flux 本来就在说 netlink，多一个 generic netlink family 是它已有的能力，而且 Wi-Fi 连上、漫游、断开本身就是内核广播的事件——**不轮询、不碰 binder**。

## F0 — 不加依赖

只用 `std` 与已有的 `libc`。想加别的就停下来问。

## F1 — generic netlink 传输（`crates/fluxd/src/netlink/genl.rs`，新文件）

**合同**：§29.2 的三段——family 解析、dump 的内容、事件只是触发。

现有 `netlink/wire.rs` 已经有 nlmsghdr 与属性的编解码，`netlink/route.rs` 有请求/dump/事件三种用法的样板。generic netlink 只多一样东西：nlmsghdr 之后紧跟 4 字节 `genlmsghdr { cmd: u8, version: u8, reserved: u16 }`，然后才是属性。复用 wire 层，不要另起一套解析。

需要的能力：

| 调用 | 做什么 |
|---|---|
| `open()` | `NETLINK_GENERIC`，`SOCK_RAW \| SOCK_NONBLOCK \| SOCK_CLOEXEC` |
| `resolve_nl80211()` | 向 `GENL_ID_CTRL`（= `NLMSG_MIN_TYPE` = 0x10）发 `CTRL_CMD_GETFAMILY`（3），属性 `CTRL_ATTR_FAMILY_NAME`（2）= `"nl80211\0"`；回复里取 `CTRL_ATTR_FAMILY_ID`（1，u16）和 `CTRL_ATTR_MCAST_GROUPS`（7，嵌套：每组一个嵌套项，内含 `CTRL_ATTR_MCAST_GRP_NAME`（1）与 `CTRL_ATTR_MCAST_GRP_ID`（2，u32））里名为 `mlme` 的组 id。内核回 `ENOENT` → 返回 `None`，这台设备没有 cfg80211 |
| `join(group)` | `setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)`。**先加入再 dump**（§10.4.1 的同一条理由） |
| `dump_interfaces(family)` | nlmsghdr `type = family, flags = NLM_F_REQUEST \| NLM_F_DUMP`，genlmsghdr `cmd = NL80211_CMD_GET_INTERFACE`（5），无属性。每条回复 genl `cmd = NL80211_CMD_NEW_INTERFACE`（7），取 `NL80211_ATTR_IFINDEX`（3，u32）、`NL80211_ATTR_IFTYPE`（5，u32）、`NL80211_ATTR_SSID`（52，原始字节，可能不是 UTF-8）。没有 SSID 属性 = 没关联 |
| `drain()` | 事件 socket 上把待读消息全部读掉，只报告"有变化 / 溢出"，**不解析 SSID**——事件是触发，dump 才是真相 |

常量的值从 `clone/kernel-src/v5.15/include/uapi/linux/{nl80211,genetlink}.h` 算出，写进注释时带上头文件路径。`nl80211_commands` 枚举里有 `NL80211_CMD_NEW_BEACON = NL80211_CMD_START_AP` 这类别名，数值不递增——**逐个数，不要相信记忆**。已核对过的值：`GET_INTERFACE 5`、`NEW_INTERFACE 7`、`DEAUTHENTICATE 39`、`DISASSOCIATE 40`、`CONNECT 46`、`ROAM 47`、`DISCONNECT 48`；`ATTR_IFINDEX 3`、`ATTR_IFTYPE 5`、`ATTR_SSID 52`；`IFTYPE_STATION 2`。

属性解析按 §8.5 的 allowlist 纪律：未知属性跳过，畸形消息让整次 dump 失败。dump 失败是 `ssid_unreadable`，**不是**"没连 Wi-Fi"。

单测（纯字节，任何平台）：手工拼一条 GETFAMILY 回复（含两个嵌套的 mcast 组）能解出 family id 与 `mlme` 组 id；一条带 SSID 的 NEW_INTERFACE 与一条不带的各解一次；未知属性被跳过；截断的属性让解析失败。

## F2 — 判定是纯函数（`flux-core`）

**合同**：§29.1 的匹配表。

```rust
pub struct SsidVerdict { pub paused: bool, pub matched_entry: Option<usize> } // 1-based

pub fn ssid_verdict(mode: ListMode, list: &[String], connected: &[Vec<u8>]) -> SsidVerdict
```

- `connected` 只含 `NL80211_IFTYPE_STATION` 且带 SSID 的接口；为空 → `paused = false`，两种模式都是（§29.5：没连 Wi-Fi 时维度不参与）。
- 匹配是**字节相等**：列表项按 UTF-8 取字节与 SSID 原始字节比。不是 UTF-8 的 SSID 不可能匹配任何项，这是对的。
- blacklist：任一已连 SSID 在表里 → 暂停，`matched_entry` 是第一个命中的表项位置。
- whitelist：已连 Wi-Fi 且没有任何 SSID 在表里 → 暂停，`matched_entry = None`。

单测覆盖这四条，再加多接口（一个命中一个不命中）与非 UTF-8 SSID。

## F3 — 接进 reactor

**合同**：§29.5"什么是不激活"、§26 新增的 nl80211 行、§24.1 的 `ssid` 对象、§24.3 的两条告警、§27.1.3 的新显示行。

### 生命周期

- 当前策略的 `ssids` **非空**且 genl 还没打开 → `open` → `resolve_nl80211` → 找不到 family 就记 `ssid_unreadable`、不再重试直到策略变化；找到就 `join(mlme)` → 加进 epoll → 立刻 dump 一次。
- 列表变**空** → 从 epoll 摘掉、关掉 socket、清掉 Wi-Fi 状态。§29.5 原话：空列表**不得**产生任何 generic netlink 流量。
- genl fd 可读 → `drain()` → 置 `wifi_changed` → 挂去抖定时器，与 rtnetlink 事件走同一条路。

### 判定与暂停

在 `converge` 里，策略（候选或当前）确定之后、启动引擎之前：列表非空则 dump 接口，`ssid_verdict` 得出结论。

- `paused` → 走**与 `layout.disabled()` 完全相同**的那段收尾（发布 `active=0`、取消引擎工作、`dataplane.converge(false)`、置 `reload_requested / policy_changed / engine_config_changed` 以便恢复时全量重算）。把那段抽成一个两处共用的函数，不要复制。记 `ssid_paused = true`。
- 不暂停 → 照常。若上一轮是暂停的，这一轮就是 §8.7 的普通激活，不需要任何"恢复"特殊路径。

dump 失败 → `ssid_unreadable` 告警，按"不匹配"处理，**不阻塞激活**。

### 对外可见

- `status --json`：`ssid` 对象按 §24.1——列表为空时整个字段为 `null`；`connected` 在读不到时为 `null`；`paused`；`matched_entry`。
- 人类输出加一行，例如 `wifi:       connected · paused by [ssid] blacklist (entry 2)` / `wifi:       connected` / `wifi:       not connected` / `wifi:       unreadable (nl80211 unavailable)`；列表为空不打印这行。
- `warnings`：`ssid_unreadable: …` 与 `ssid_paused: …`，文案在 §24.3。
- `module.prop`：暂停时 `😴 [Inactive] paused on this Wi-Fi network`（§27.1.3）。这一行在"Inactive 且有 last_error"之前判断——暂停不是错误。
- 顶层状态：暂停时 `Inactive`，`last_error` **不**填任何东西。

### 绝不出现的东西

SSID 的字节**不进** `status`、`module.prop`、`fluxd.log`、bugreport。日志只写"N 个已关联的 station 接口；[ssid] blacklist 命中第 k 项；暂停"这种话。§29.5 说了为什么。

## F4 — `module/flux.toml`

`[ssid]` 那段注释里"目前填写此表不会生效"删掉，改成一句说明匹配规则：与手机 Wi-Fi 设置里显示的名字逐字相同；没连 Wi-Fi 时此表不起作用。

## F5 — 验证边界要写清楚

WSL 的内核没有 cfg80211，`daemon_e2e` 测不到 Wi-Fi；真机上也没有办法从测试里制造"连上某个 SSID"。所以本批次的机检覆盖是：F1 的字节级解析单测、F2 的判定单测、以及 `daemon_e2e` 里一条**列表为空时 `status.ssid` 为 `null` 且 `/proc/<reactor pid>/net/netlink` 里没有 `NETLINK_GENERIC` 套接字**的断言（证明"空列表零流量"）。真机手工回归的步骤由审查者写进 `plan/`。

## 验收

**只跑 `AGENTS.md` 列的主机门禁，加上 aarch64 类型检查**：

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
cargo clippy -p fluxd --target aarch64-linux-android --all-targets
```

aarch64 那条在这台 Windows 主机上会因 `ring` 需要交叉编译器而失败——环境问题，报告即可。`daemon_e2e` 由审查者在 WSL 跑。**不要声称没跑的东西通过了。**

## 边界

- 不改 `[ssid]` 的解析与 schema（已在 §11.2 / §27.2.2 定死）。
- 不读 `NL80211_CMD_GET_SCAN`、不解析 BSS IE、不碰 `wpa_supplicant` 的控制接口、不调 `dumpsys`。
- **不要碰** `docs/spec/**`、`docs/history/**`、`docs/plan/**`、`README.md`。合同有问题就停下报告。
