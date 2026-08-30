# 失败矩阵与 status 规格

> 原 blueprint.md 第 23、24 部分。**章节编号未变**：本文里的 §N.x 就是全仓库引用的那个 §N.x（见 `docs/authoring.md` §1.1）。
>
> 谁读这份：拿着一个错误码来查含义的人。本文投影 0.9.1；规范性合同是冻结的 `docs/blueprint.md` 加 `docs/blueprint-0.9.1.md`，冲突时后者优先。

---

# 第 23 部分：失败矩阵

每一个可能失败的点，逐一写出**怎么检测、做什么、用户看到什么**。规则：任何一行的"动作"列都不允许出现"记录后继续"这种含糊说法（§15.4(1) 状态诚实性）。

## 23.1 启动期（尚未 active，全程 Direct）

| 失败点 | 检测 | 动作 | 用户可见 |
|---|---|---|---|
| 第二个实例 | `flock(LOCK_EX\|LOCK_NB)` 失败 | 立即 `exit(1)`，**不碰任何对象、不 unlink socket** | 第二次调用报"already running" |
| page size ≠ 4096 | `sysconf(_SC_PAGESIZE)` | 停在 `Inactive`，**不启动 engine、不建任何对象** | `status.last_error = "unsupported_page_size:16384"` |
| netns 不是初始 netns | `/proc/self/ns/net` 与 `/proc/1/ns/net` 的 inode 比对 | `Inactive` | `"netns_mismatch"` |
| 运行目录权限不对 | `fstatat` 检查 mode/uid | `Inactive`，**不自动 chmod**（可能是用户刻意改的） | `"runtime_dir_mode:0755 expected 0700"` |
| `all.rp_filter != 0` | 读 `/proc/sys/...` | `Inactive`（§8.4，**不写全局 sysctl**） | `"rp_filter_conflict:all=1"` + 人工处置说明 |
| veth 同名对象存在但 alias 不符 | `RTM_GETLINK` + `IFLA_IFALIAS` | `Inactive`，**绝不删除他人对象** | `"veth_conflict:flxrs0 alias mismatch"` |
| MTU 65535 被拒 | `RTM_NEWLINK` 的 ACK | `Inactive`，**不降级猜小值** | `"veth_mtu_rejected"` |
| RPDB priority 100 已被占用 | `RTM_GETRULE` dump | `Inactive`，**不换动态值**（cleanup 必须可证明） | `"rule_conflict:priority 100 occupied"` |
| table 20260 已有未知路由 | `RTM_GETROUTE` dump 且 `rtm_protocol != 202` | `Inactive` | `"route_table_conflict:20260"` |
| BTF 加载失败 | `BPF_BTF_LOAD` errno | `Inactive` | `"btf_load:EINVAL"` |
| SK_STORAGE map 创建失败 | `BPF_MAP_CREATE` errno | `Inactive` | `"map_create:tcp_decision:EINVAL"` |
| program verifier 拒绝 | `BPF_PROG_LOAD` errno | `Inactive`，**把 verifier log 前 N 行写进日志与 status**（§12.7 第 11 条） | `"prog_load:flx_cap_l2:EACCES"` + log 摘要 |
| BPF load/attach 被 SELinux 拒 | `EPERM`/`EACCES` | `Inactive`，**不注入 sepolicy**（§1.3 非目标） | `"bpf_denied:check root manager policy"` |
| `packages.list` 不可读 | `open` errno | 保持当前策略；冷启动则 `Inactive` | `"packages_list:EACCES"` |
| 配置里的 package 不存在 | 解析后查表 miss | 整个候选配置失败，**不部分应用** | `"unknown_package:0:com.foo"` |
| `appId` 越界 | 范围检查 | 同上 | `"app_id_out_of_range:1000"` |
| engine binary 缺失（module 未装全 / 测试环境） | `stat` engine 路径 | `Inactive`，不进入 §9.4 事务 | `"engine_binary_missing:<path>"` |
| `config/sing-box.json` 缺失或不可读 | `open` errno | 冷启动 `Inactive`；热更新保留当前 generation | `"engine_config_missing"` / `"engine_config_unreadable:<errno>"` |
| 用户 sing-box.json 解析/校验失败（自带 inbound、保留 tag、非对象） | `flux-core` 的 `build_effective` | 冷启动 `Inactive`；热更新保留当前 generation | `"engine_config_invalid"` + 具体原因进 warnings |
| `sing-box check` 失败 | 子进程退出码 + stderr | 冷启动 `Inactive`；热更新保留当前 generation | `"engine_check_failed"` + stderr 前若干行 |
| engine 起不来 | pidfd 立即可读 | backoff 重试（1/2/4/8/30 s） | `"engine_exited:code=1"` |
| 4 个 socket 未在 deadline 内出现 | SOCK_DIAG 退避重查超时 | 停止 candidate，`Inactive` | `"engine_not_ready:2/4 sockets"` |
| socket inode 与 candidate pid 不符 | `/proc/<pid>/fd` 交叉核验 | 停止 candidate，`Inactive` | `"engine_socket_owner_mismatch"` |
| `clsact` 带 shared block | dump 见 `TCA_INGRESS_BLOCK`/`EGRESS_BLOCK` | **排除该 interface**，其余继续 | 该 interface `excluded(clsact_shared_block)` |
| 无可用 pref（`v4-*` 上 1–3 全被占） | dump + §8.5.3 | 排除该 interface | `excluded(tc_no_usable_pref)` |
| 取到 pref 但被前面的 filter 遮挡 | §8.5.4 存活验证：tx 在涨而 `SAW_PACKET` 不涨 | 排除该 interface，点名遮挡者 | `excluded(tc_chain_shadowed)` |
| 存活验证窗口内无流量 | tx 也不涨 | 退避重试；到上限仍无流量则允许激活并标注 | `warn(tc_verify_no_traffic)` |
| Flux filter 无法证明可达 | 身份/相对排序检查 + `flx_verify` 正向存活验证 | 排除该 interface；不得仅因它不是 dump 第一项而排除 | tx 增长但 probe 不涨：`excluded(tc_chain_shadowed)`；identity/前置快照漂移沿用兼容 token `excluded(not_first_applicable)`，其名字不再按字面解释 |
| candidate interface 超过 64 | 计数 | **整个新 topology 不 promote**，保持当前/Direct，不按名字截断 | `"too_many_interfaces:71"` |

## 23.2 运行期（已 active）

| 失败点 | 检测 | 动作 | 数据面后果 |
|---|---|---|---|
| engine 进程退出 | pidfd 可读 | publish `active=0` → backoff 重启 → 新 generation | 新流 Direct（listener lookup miss）；已入场 TCP drop |
| engine 单个 listener 关闭（进程还活着） | BPF `fault_events` 的 `EGRESS_LISTENER` | publish `active=0` → 重启整个 generation | 同上。**这是 fault ringbuf 存在的唯一理由** |
| engine event-loop 活锁（listener 在、进程在） | **不可检测**（§2.2.3(3)） | 无 | 该期间新流仍被捕获并卡住。**已公开的残余风险** |
| ingress `bpf_sk_assign` 反复失败 | `counters[IN_DROP_ASSIGN] > 0` 且 `admit_* > 0` | `status` 给出**具体假设**："engine listener may have SO_REUSEPORT — kernels < 6.5 reject assign（§9.2）" | 已入场流 drop |
| **netd 删掉某物理 interface 的 `clsact`**（连带删掉我们的 egress filter） | `RTM_DELQDISC` / `RTM_DELTFILTER` | 以 `netd_clsact_missing` 排除并等待 netd 重建；收到 `RTM_NEWQDISC` 后重新 admission，Flux 从不创建物理 `clsact`。其它 active coverage 尚在时不动全局 `active`；这是最后一条时按 R091-10 publish inactive | capture-side drift；窗口内该 interface 上的选中流量走 Direct |
| 自有**核心**对象（`flxrs0/1`、ingress filter、rule、local route）被外力删除 | rtnetlink 事件 + 按需 dump | 先 publish `active=0`，再按 §8.5 谓词重新收敛 | 收敛期间新流 Direct |
| 未知对象抢占了我们的 identity | dump 比对失败 | 保持 `Inactive` 并报告，**不覆盖、不删除** | Direct |
| interface 消失 | `RTM_DELLINK` | 内核已连带删除其 filter；从 active 集移除。若这是最后一个 active capture interface，先 publish `active=0` 并进入 `Inactive`；否则保持 `Active` | 该 interface 上的流回 Android 路径（R091-10） |
| interface 出现 | `RTM_NEWLINK` + admission | debounce 后 attach；若此前因零 coverage 为 `Inactive`，admission + readiness 闭环后重新 publish `active=1` | 窗口内 Direct（R091-10） |
| netlink socket 溢出 | `ENOBUFS` / `NLMSG_OVERRUN` | **丢弃批次，全量重新 dump**（§10.4.1 第 2 条） | 无（控制面内部） |
| map 更新失败（策略热更新中） | `bpf_map_update_elem` errno | 记录错误并**重新入队一次完整收敛**，不做快照回滚（§10.5） | 窗口内新流看到混合策略（良性） |
| `uid_policy` 超过 4096 或同时 `SELECTED` 超过 1024 | 分别计数 | 热更新被拒，保持当前策略 | 无变化 |
| 任一 bypass LPM 超过 65536 | 按地址族计数；本机地址不计入 LPM | **拒绝激活并报告**，不静默丢弃 | Direct |
| 任一 self-address HASH 超过 256 | 按地址族精确地址计数 | **拒绝激活并报告**，不静默丢弃 | Direct |
| 控制 socket 收到非 root 请求 | `SO_PEERCRED.uid != 0` | 关闭连接 | 客户端 EOF |
| 控制请求超过 64 KiB | 读取长度 | 关闭连接 | 同上 |
| decision storage 分配失败 | `bpf_sk_storage_get` 两次都 NULL | 当前包 `TC_ACT_UNSPEC`（无粘性） | 该 SYN 直连；后续 SYN 可重新决策（§2.2.1 末条） |
| `flux_decision.magic` 或 `reserved` 损坏 | 每次读取时校验 | `TC_ACT_SHOT` + `counters[DROP_CORRUPT]` | 该 socket 后续包全 drop（不泄漏） |
| control snapshot ABI magic 不符 | 每次 `ctrl()` 校验 | egress: 已入场 SHOT / 未入场 UNSPEC；ingress: SHOT | 见 §2.2 |
| 内核 < 6.5 上 assign 了刚被 unhash 的 listener | **不可检测** | 无 | 泄漏一次 socket 引用。窗口被 §9.4 的顺序压到"engine 崩溃 → pidfd 唤醒"之间的数百微秒。**已知并接受**（§9.2） |

## 23.3 停止与崩溃

| 场景 | 行为 | 遗留 |
|---|---|---|
| `fluxd stop` | publish `active=0` → `SIGTERM` engine → 短 deadline → `SIGKILL` → pidfd 确认 → 正常退出(0) | veth/BPF/TC 对象**保留**（下次启动删除重建）；service.sh 因退出码 0 不重启 |
| `fluxd disable` | 创建 `disable`，publish `active=0`，停止 engine；daemon 继续运行等命令 | 同上；“已停用”不表示同 boot 已拆除网络对象 |
| `SIGTERM` / `SIGINT` | 同 `stop` | 同上 |
| `fluxd` 被 `SIGKILL` | engine 因 `PDEATHSIG=SIGKILL` 被内核终止 → listener 消失 → **新流因 listener lookup miss 而 Direct**；已入场 TCP 的包 redirect 后在 ingress drop | TC filter + veth + rule + route 全部残留。**这是 fail-open 的关键路径**：残留的 capture 程序不会形成黑洞，因为它每次都要先查 listener |
| `service.sh` 重启 fluxd | §8.7 步骤 2 删除全部精确自有残留后重建 | 归零 |
| 设备重启 | 全部非持久内核对象自然消失 | 无 |
| 模块卸载 | `uninstall.sh` 同步请求 `fluxd stop`，然后只删 `/data/adb/flux-rs` | 内核对象等重启清除；**不 flush 任何系统对象** |

**一条贯穿全表的不变量**：`Inactive` 只证明 `control.active=0`、新流不再 admission，不证明 TC/veth/rule/route/map 已删除。`status` 只有在报告“已清理”或“无残留”之前，才必须有一次**新的实际枚举**（TC dump、`RTM_GETRULE`、`RTM_GETROUTE`、`BPF_OBJ_GET_INFO_BY_FD`）证明对象确实不在；无法证明时不得作出 cleanup 声明，并附第一个具体错误。

---

# 第 24 部分：`status` 输出与错误码规格

`status` 是这个产品唯一的诊断出口（没有 WebUI、没有周期日志、没有 telemetry）。它必须足以回答"为什么没生效"，否则 §14.2 的"零可观测性"缺陷就回来了。

## 24.1 字段规格

```jsonc
{
  "ok": true,
  "version": "0.9.1",                // 目标值；实施前当前 workspace 仍报告 0.9.0
  "abi_magic": "0xF10C0903",
  "state": "Disabled" | "Inactive" | "Active",
  "generation": 7,
  "engine": {
    "running": true, "pid": 1234,
    "sockets_verified": 4,            // 期望 4；少于 4 说明 readiness 未闭环
    "effective_config": "run/effective-sing-box.7.json"
  },
  "policy": {
    "selected": 3, "draining": 1,
    "bypass_v4": 12, "bypass_v6": 6,  // 固定项 + 用户 bypass_cidrs；不含本机地址
    "self_addresses": 4               // 两张精确 HASH 中的动态本机地址总数
  },
  "ifaces": [
    { "name": "wlan0", "ifindex": 24, "arphrd": "ether",
      "entry": "flx_cap_l2", "status": "active",
      "prog_id": 118, "prog_tag": "a1b2c3d4e5f60718", "pref": 2,
      "first_applicable": true },      // 兼容字段：表示已验证可达，不表示 dump 排第一
    { "name": "rmnet_data0", "ifindex": 30, "arphrd": "rawip",
      "entry": "flx_cap_l3", "status": "active", "…": null },
    { "name": "v4-rmnet_data0", "ifindex": 31, "arphrd": "none",
      "status": "excluded", "reason": "clat_order_unverified" }
  ],
  "counters": {                        // §6.1 的 PERCPU_ARRAY 求和
    "admit_tcp": 41, "direct_tcp": 190, "admit_udp": 388,
    "drop_inactive": 0, "drop_stale_gen": 0, "drop_handoff": 0,
    "drop_udp_frag": 0, "drop_corrupt": 0, "decision_alloc_fail": 0,
    "egress_listener_miss": 2,
    "in_assign_tcp": 41, "in_assign_udp": 388,
    "in_pass_established": 5120, "in_pass_fragment": 0,
    "in_drop_no_listener": 0, "in_drop_assign": 0,
    "in_drop_parse": 0, "in_drop_snapshot": 0
  },
  "sysctl": { "all.rp_filter": 0, "flxrs1.rp_filter": 0, "flxrs1.accept_local": 1 },
  "warnings": [ /* 见 24.3 */ ],
  "hints":    [ /* 见 24.4 */ ],
  "last_error": null
}
```

`disable` 文件存在表示 desired state 是 disabled。engine 尚在终止或收敛仍忙时，顶层可以短暂为 `Inactive` 并给出 pending warning；完成后才是 `Disabled`。这三个状态都不单独承诺 cleanup。

## 24.2 错误码命名规则

`last_error` 与 `ifaces[].reason` 一律用 `snake_case` 的**稳定标识符**，可选 `:` 后跟具体值。**禁止**把自由文本放进这两个字段（自由文本进 `warnings`）。已定义的集合就是 §23 两张表里出现的那些值；新增必须同时更新 §23。

分四类前缀便于分流：

| 前缀 | 含义 | 例 |
|---|---|---|
| `unsupported_*` | 设备能力不足，重试无用 | `unsupported_page_size:16384` |
| `*_conflict` | 有他人对象占位，需人工介入 | `rule_conflict:priority 100 occupied` |
| `*_failed` / `<syscall>:<errno>` | 操作失败，可能可重试 | `prog_load:flx_cap_l2:EACCES` |
| `excluded(<reason>)` | 单个 interface 被排除，其余仍工作 | `excluded(tc_chain_shadowed)` |

`not_first_applicable` 是 0.9.0 已公开的兼容 token。0.9.1 保留编码但收窄含义为“attachment identity 或已验证的前置 filter 快照不再成立”；人类文案统一说“不可达/需重新验证”，不能据字段名声称 Flux 必须排在 dump 第一项。

## 24.3 必须产生的 warning

| 条件 | warning |
|---|---|
| 选中的包声明了 `BIND_VPN_SERVICE`（best-effort 检测） | `"0:com.foo declares BIND_VPN_SERVICE; its outer socket will be captured"` |
| 选中的 UID 有其它 shared-UID 兄弟包 | `"uid 10231 also covers: com.bar, com.baz"` |
| 用户 JSON 缺少 :53 处理 | `"no hijack-dns rule; selected apps' DNS will be forwarded verbatim and domain rules will not apply"`（§1.3.4） |
| 系统 Private DNS 非 `off` | `"system private DNS is on; name resolution bypasses Flux"`（§1.3.3 边界①） |
| 捕获到的 :53 流量 `sk_uid == 1051` | `"enforce_dns_uid appears enabled; system DNS is not per-app attributable on this device"`（边界②） |
| 用户设了 outbound `routing_mark` / `bind_interface` | `"user-set outbound routing_mark/bind_interface: Android network consequences are yours"` |
| `clsact` 非我创建 | `"clsact on wlan0 pre-existed; it will never be deleted by Flux"` |

## 24.4 必须产生的 hint（把 counter 组合翻译成假设）

零观测性的反面不是"打印更多数字"，而是**替用户做第一层推理**：

| counter 组合 | hint |
|---|---|
| `admit_* > 0` 且 `in_drop_assign > 0` | `"assign is failing; if this is 100% the engine listener may have SO_REUSEPORT (kernels < 6.5 reject it)"` |
| `admit_* > 0` 且 `in_drop_no_listener > 0` | `"packets reached the veth but no listener was found; engine may be restarting"` |
| `egress_listener_miss > 0` 且 `admit_* == 0` | `"nothing is being captured because the engine listener is absent"` |
| `direct_tcp > 0` 且 `admit_tcp == 0` | `"selected UIDs are matching but every first SYN chose DIRECT; check bypass_cidrs and active"` |
| 全部 counter 为 0 且 `state == Active` | `"no selected traffic observed; verify the app list resolves to the UIDs you expect"` |
| `drop_udp_frag > 0` | `"fragmented UDP from selected apps is dropped by design (§7.3); large DNS/QUIC payloads may fail"` |
| `in_pass_established` 远大于 `in_assign_tcp` | 正常（每条连接一次 assign、多次 pass）。**不产生 hint**，此行只为避免误报 |

---

