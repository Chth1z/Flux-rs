# 1.0.0-rc.3 核心与架构升级设计

> 计划层（AUTH-0）。本文描述还没发生的事。落地前与代码不一致时，以本文的目标形状为准；落地后合同进 `spec/`，本文归档或删除。
>
> 本文不是功能清单。rc.3 的产品问题不是“能力不够”，而是若干关键不变量同时写在规范、纯函数状态表和命令式 reactor 三处，却并不共同支配执行。允许对控制面、策略提交、内核快照、停止路径和发布证据做大幅修改；不允许借升级打开已被否决的产品面。

---

## 0. 身份、来源与证据边界

### 0.1 本设计所对照的代码

| 项 | 值 |
|---|---|
| 设计对照版本 | `1.0.0-rc.2` |
| 设计对照提交 | `a0a41bc`（`refactor: deepen the 1.0 core without widening the product`） |
| 落地后工作区 | `1.0.0-rc.3`（批 0–7 已提交；当前进度见 `implementation.md` §17.0） |
| 设备旁证 | SM-S9180 / `5.15.211-Qkernel-g7a72da9438` / KernelSU 3.3.0；本树 Phase 4–6 通过，见 `history/review-log.md` §0.6.19、§0.6.27 |
| 设计对照 ABI | `FLUX_ABI_MAGIC = 0xF10C0904`；`struct flux_control` 96 字节 |
| 落地后 ABI | `FLUX_ABI_MAGIC = 0xF10C0905`（结构仍 96 字节） |
| 未完成的正式 1.0.0 门 | 远端 CI、候选 ZIP 的 §20、Phase 7、三管理器 smoke |

设计对照时点机上仍运行已装的 rc.1 二进制。§0.6.19 / §0.6.27 证明的是本树测试对象，不是候选 ZIP。

### 0.2 两份输入审计

| 简称 | 文件 | 对象 | 完成度 |
|---|---|---|---|
| 审计甲 | `Flux-rs-review-2026-09-17 (1).md` | 远端网页所见 `main`，manifest 仍写 `1.0.0-rc.1`；无固定 SHA | 完整一轮：R01–R16、模型 6 项、路线五批 |
| 审计乙 | `Flux-rs-rc3-review-2026-09-17.md` | 上传快照 `Flux-rs-main/`，版本 `1.0.0-rc.2`；内容摘要 `1c80cc9a…` | 只完成阶段一与阶段二 A，其后按作者要求暂停 |

两份都不是完整安全审计或发行认证。审计甲未克隆仓库、未编译、未跑项目测试、未上机。审计乙无 `cargo`/`clang`、无设备。本文用当前工作区源码复核它们的代码事实，补完审计乙未写的阶段二 B 至阶段六，并给出可实施的目标形状。

审计甲的行号指向当时远端 `main`；审计乙指向上传快照。下文凡写路径，均以 `a0a41bc` 为准。

### 0.3 证据等级

沿用两份审计的标记，避免把建议写成已发现的生产事故：

| 标记 | 含义 |
|---|---|
| A | 可从当前源码直接确认 |
| M | 独立模型或局部实验支持，不是生产实现已复现 |
| B | 由代码与内核/系统语义推导，仍需针对实现做故障注入 |
| D | rc.3 设计决定，不冒充现有缺陷 |

优先级：

| 级 | 含义 |
|---|---|
| R0 | 架构阻断：不解决就不应在当前形状上继续加深核心 |
| R1 | 正式候选前应关闭的正确性、响应性、可重建性 |
| R2 | 质量债务：核心不变量稳定后再做 |

### 0.4 本文保证什么、不保证什么

保证：审计甲 16 条、审计乙阶段一 8 条与阶段二 A 4 条，以及审计乙点名但未下结论的阶段二后续项，都在本文有处置（修复、改合同、或明确推迟并写原因）。不保证：完整性能排名、校园网根因、第三方 crate CVE、GitHub 仓库保护规则的未读部分、所有 OEM 共存。

---

## 1. 总体判断

**保留产品边界和数据路径主干，重做控制面的真相组织方式。**

Flux-rs 真正的技术优势仍是那条窄定义：在物理接口 TC egress 按 socket UID 判定应用流量，保持原始 L3/L4 头，经专用 veth 和 `bpf_sk_assign()` 交给未经修改的官方 sing-box；未选择的应用继续走 Android 原网络栈。rc.3 把“强大”定义为：边界准确、提交可证明、故障可解释、等待有上界——不是控制更多系统对象。

rc.2 已经把 `Phase`/`Stimulus`/`step` 放进 `flux-core`、把 attach 收成模块、给 `flx_in` 加了 I1b 快路径。这些方向对。但它留下一个结构性裂缝：`runtime::step()` 的 `Effect` 没有被执行，`Reactor` 仍然用几十个布尔字段和 `converge()` 决定副作用。纯函数测试全绿，不能证明运行代码遵循那张表。

因此 rc.3 围绕四件事设计，并且**允许为此改 ABI、改 map 拓扑、改 reactor 内部、改发布工作流**：

1. **单一真相**：`Model + Event → Model + Commands` 必须真正产生并驱动运行时命令。
2. **完整快照**：策略与内核枚举只有在能证明完整时，才能成为判定或所有权证据。
3. **单点提交**：一次策略更新只能让数据面观察到完整旧版本或完整新版本。
4. **有界等待**：任何内核、子进程、文件或网络操作都不能无界占用 reactor；超时必须能打断或隔离等待。

正确的重构边界：

- 保留 BPF 数据路径的核心机制和三 crate；
- 保留单线程状态所有权，不引入 async runtime、插件、单实现 trait、新 crate；
- 将 `reactor.rs` 从总控实现收缩为事件复用器和命令执行器；
- 将策略发布、内核 dump、引擎换代、停止路径、文件权威做成拥有明确输入/输出/提交点/取消语义的深模块；
- 将构建的“同一次运行两次相同”升级为“候选输入先冻结，再构建”。

---

## 2. 必须原样保留的资产

### 2.1 产品非目标（硬边界）

下列拒绝是竞争力，不是能力不足。rc.3 的“允许大改”**不得**重新打开它们：

- 不自行实现代理协议、DNS 路由、节点质量学习；
- 不增加 TUN、iptables/nftables、TPROXY mark、运行时后端选择器；
- 不在 eBPF 中做域名、SNI、规则集；
- 不增加多代理核心、插件系统、backend registry、通用网络框架；
- 不接管 VPN、热点、转发、容器或多 netns；
- 不把 sing-box schema 重写一遍，也不修改官方 engine；
- 不增加 Flux 自建 WebUI，不默认打开 clash 控制面（C8/C10 仍 deferred）；
- 不为测试建立模拟内核框架；
- 不引入 Tokio/async runtime、libbpf/aya（默认继续手写 loader）、数据库或事件溯源；
- 不写全局 `all.rp_filter`，不 flush OEM filter 链；
- 不引入周期健康探测（PHIL-3）；
- 不为唯一 netlink/BPF/attachment 实现预建 trait（蓝图 §5）。

### 2.2 数据面顺序与失败语义

这些不是风格，性能重构必须先保住：

1. 未准入与已准入有不同失败语义：admission 前 `TC_ACT_UNSPEC`；有效 `CAPTURED` 之后不得回落到真实目的。
2. TCP 首个裸 SYN 创建一次不可变 `DIRECT`/`CAPTURED`；已有连接不被普通策略更新重新判定。
3. 未接管路径必须让后续系统 classifier 继续执行（`TC_ACT_UNSPEC`，不是 `TC_ACT_OK`）。
4. 每次 BPF invocation 只读一次冻结 control leaf。
5. engine uid 0 不能进入选择集合。
6. 物理接口 attachment 按 dump 和存活探针证明；不创建物理 `clsact`，不删除无法证明归属的对象。
7. I1b：ingress 上已建立 TCP 与分片不 `pull_headers`、不 assign。
8. 未选 UID 的 E1 不得增加 map-in-map 额外 lookup（见第 8 节）。当前顺序是：`skb->sk` → `bpf_sk_fullsock` → `bpf_get_socket_uid` → `uid_policy` miss → `TC_ACT_UNSPEC`（`bpf/flux.bpf.c` `cap_core`）。
9. 5.15 禁止 fetching atomic（蓝图 §7.5.0）。
10. 手写 loader 只接受已声明的 relocation；缺依赖的 libbpf 继续拒绝。

### 2.3 三 crate 与单 reactor

`flux-core` 纯逻辑、禁止 `unsafe`；`fluxd` 独占系统资源；`xtask` 独占构建与发行证据。rc.3 在 crate **内**加深模块，不继续拆 crate。

进程形状保持：

```text
service.sh → fluxd supervisor（只持 reactor pid 与崩溃退避）
          → fluxd reactor（单线程 epoll）
          → 官方 sing-box（先 check，再启动并核四个 listener）
```

### 2.4 用户可见词表

`Disabled` / `Inactive` / `Active`、`module.prop` 的 DisplayKind、C9 开关文件语义，不因内部 planner 重写而增加第四种对外状态。新的内部阶段（`Activating`、`Stopping`、事务 Idle/Building）必须投影到现有三值。需要新的失败分类时走 `status` 的 error/warning 字段，不发明新的顶层 state。

---

## 3. 当前架构的真实形状（`a0a41bc`）

### 3.1 运行时并不是“step 的适配器”

`crates/flux-core/src/runtime.rs` 定义 `Phase + Stimulus → Step { phase, effects }`。模块注释写 daemon 的 epoll 是 `step` 的适配器。`crates/fluxd/src/reactor.rs` 的 `note_stimulus()` 只检查 `Effect::IgnoreUnexpected` 并打日志，**既不执行 `effects`，也不用 `Step.phase` 提交运行状态**。仓库里没有任何对 `Effect::AttemptActivation` 等的 `match`。

`Reactor` **没有存储的 `Phase` 字段**。每次 `phase()` 用 `Phase::observe(Observation)` 从 disable / engine / dataplane.active / activation_role / ssid / shutdown 等旗标反推。`step(...).phase` 从不写回。rc.3 若改为“存储 Phase”，必须与这组观测旗标对账，不能两套权威。

`note_stimulus` 的生产调用只有：`SsidPause`/`SsidResume`、`CaptureSideDrift`、`DebounceExpired`、`Sighup`、`StaleOrDuplicateFault`、`CurrentGenerationFault`。从未对 `Enable`/`Disable`/`Stop`/`Reload`/`Bootstrap`/`EngineExited`/`ActivationCommitted` 等走这张表。表驱动的副作用由旁边的 `converge()` 或手写路径完成，例如：

| `step` 表会命令 | daemon 实际做 |
|---|---|
| `Active`+`Reload` → `PolicyTransaction` 然后 `EngineCandidateSwitch` | `reload_requested=true` 后一次 `converge`，两域可能都做、也可能因 busy 都不做 |
| `Active`+`CaptureSideDrift` → 只 `ReattachCaptureLocally` | 记下 stimulus 后走完整 `converge` |
| `Enable` → `Inactive`+`AttemptActivation` | `layout.set_enabled()` + `converge("enable")`，无 `Stimulus::Enable` |
| `Stop` → `PublishInactive`+`StopEngine`+`ExitProcess` | 控制回复立刻成功；真正停在发完帧之后的 `request_shutdown` |

`Reactor` 自身仍持有约 60 个字段，其中包括：

- fd：`epoll`、`signalfd`、`inotify_fd`、五只 timerfd、控制 socket、订阅 worker；
- 事务：`engine`、`engine_transaction`、`activation_role`、`engine_cancel_requested`、`shutdown_requested`；
- dirty bits：`reload_requested`、`policy_changed`、`engine_config_changed`、`topology_changed`、`wifi_changed`、`dataplane_error_active`、`policy_retry_available`；
- 投影：`generations`、`last_error*`、`policy_error`、`subscription_error`、`current_policy`、`ssid_*`、`module_prop_status`。

实际副作用由 `converge()`、引擎事务方法和各 handler 直接决定。结果是两套状态机：一套可在 Windows 上穷举，一套真正执行。这是审计乙 A01，也是 rc.2 “reactor 降为适配器”未完成的部分。**R0。**

### 3.2 `dataplane::Manager` 仍是跨域容器

`platform.rs` 的 `Manager` 同时持有：rtnetlink 请求/事件 socket、BPF runtime、fault ring、control 镜像、owned TC filters、attachment FSM、三份 list mode、uid/bypass/self 镜像、地址 LRU、默认路由事实、展示用 `DataplaneStatus`。`apply_policy()` 与拓扑收敛、control 发布、attachment 住在同一个类型里。调用方必须知道跨域时序。rc.2 已拆出 `attachment.rs` 和 `MAP_SPECS`，但策略提交仍是原地多 map 写入。

### 3.3 蓝图自己把“第三态”写成了安全窗口

`docs/spec/blueprint.md` §10.5：

> 添加先于删除……窗口期内策略要么比旧行为更宽，要么更早应用新行为。两者都只影响尚无 decision 的流。

这与审计甲 R01 / 审计乙 A02 的反例直接冲突。更宽或更早**不是**旧策略，也不是新策略。TCP 首 SYN 会把中间结果写入 `SK_STORAGE`，于是“窗口短”推不出“影响短”。rc.3 必须改这条合同，不能在实现上继续执行它再加补丁。

当前实现（`apply_policy`，`platform.rs`）顺序为：

1. 容量预检只看**目标**集合大小，不看“先加后删”的峰值；
2. 写入新 SELECTED UID、新 bypass、新 self-address；
3. `publish_cidr_mode`（新冻结 leaf，新旧前缀并集被新 mode 解释）；
4. UID 降为 DRAINING、删除旧前缀。

任一步失败则返回错误，已写入的不回滚；reactor 记录错误并 level-trigger 重试。这是审计甲 R01+R07。

### 3.4 停止路径仍可能在紧急时创建 leaf

`MapSet::publish_control`（`maps.rs`）：第一次发布冻结的是 **map 创建时那片初始 leaf**；之后每次 control 变化都 `BPF_MAP_CREATE` 新 leaf，写入、freeze，再把 fd 写进 `control_root`，旧 fd drop 后靠 RCU 释放。稳态 12 张 map，替换瞬间短暂 13 张。`request_shutdown` 在 `publish_inactive` 失败后仍继续停引擎。正常换代对同类失败则保留旧子进程。语义不统一。审计甲 R05 / 审计乙 A05。

### 3.5 dump 与 diag 的完整性/阻塞

- `RawMessage` 只保留 `kind/seq/pid/payload`，解析时丢弃 `nlmsghdr.flags`（`wire.rs` `parse_datagram`）。
- `RequestSocket::dump` 见到任意 `NLMSG_DONE` 即成功，不解析 DONE 负状态。
- 接收用 `recv()` + 1 MiB 缓冲，不读 `MSG_TRUNC`。
- 阻塞 socket 有 3 秒 `SO_RCVTIMEO`；一次 snapshot 多次 dump，外层 20 秒控制 deadline 仍不能抢占当前 `recv`。
- `sock_diag::find_inode` 每次创建**阻塞**、**无超时**的 `NETLINK_SOCK_DIAG` socket；`probe_ready` 同步对四个 listener 各调一次。注释写“非阻塞、无 sleep”，底下的 `recv` 仍可卡住。引擎 timerfd（`READY_DEADLINE` 5s）不能打断这次 `recv`。
- sock_diag **确实**检查了 DONE 负状态。不要误报成所有路径一样。
- `cleanup_owned` 把所有权计划 **dump 两次**，仅当两次 `CleanupPlan` 相等才删除（`platform.rs`）。两次都走同一条不保留 flags/DONE/TRUNC 的 `snapshot()`，所以“两次相等”≠“完整可信”。不完整的“没看到”仍可能变成删除依据。

审计甲 R02/R03，审计乙 A03/A04。

### 3.6 文件权威

- `Layout::disabled()`：`symlink_metadata().is_ok()`。非 `NotFound` 的 EIO/EACCES 被折叠成 enabled。审计甲 R06 / 审计乙 A06。
- `make_inotify` 监视模块目录、`config/` 自身、`packages.list` 的父目录。mask 无 `IN_MOVE_SELF` / `IN_DELETE_SELF` / `IN_IGNORED`。`handle_inotify` 不重建 watch。`packages.list` 的“看父目录”是对的；`config/` 看目录 inode 则不能跟随目录替换。审计甲 R04。
- overflow 时把 policy 与 engine 都标 dirty，这是对的方向，但没有“从受信父目录重读全部权威”的单一路径。

### 3.7 其它仍成立的代码事实

| 项 | 位置 | 事实 |
|---|---|---|
| check 无 cwd | `engine.rs` `spawn_check` | `Command::new(binary).arg("check").arg(config)`，不 `current_dir` |
| 运行有 chdir | `engine.rs` 子进程 | `libc::chdir(workdir)` 后 `execv` |
| CLI enable/disable | `main.rs` + `reactor.rs` | 客户端 `Ok(response)` 不看 `ok`；服务端 enable 的 `ok` 跟的是开关文件 I/O，不是“已经 Active”。收敛中可 defer，20s 超时后仍返回当时 `overall_ok()` |
| CLI stop | `main.rs` + `reactor.rs` | 客户端通信失败也当成功；服务端回复 **永远 `ok: true`**，真正 shutdown 在帧发出之后 |
| check 输出 | `engine.rs` `EngineCheck::drain_output` | `OUTPUT_CAP` 只限制**保存**的字节；cap 之后仍 `read` 循环到 EAGAIN，CPU 预算无上界 |
| 诊断 | `bugreport.rs` | 排除原始配置；含 check 输出与日志尾；按地址/域名形状脱敏；**不**系统遮罩 URL userinfo / Authorization；`fs::write` 非 `O_EXCL` |
| 发布 | `release.yml` | workflow 级 `contents: write`；`checkout@main`；签名只查 GitHub `verified`；显式步骤小于 CI：缺 Windows host-safe、BPF verifier/abi/btf、`cargo-deny`、shellcheck/module lifecycle；无 `needs:` 绑定先前 CI |
| 依赖 | `Cargo.toml` | `version = "*"`，无提交的 `Cargo.lock`；`rust-toolchain.toml` 跟 `stable`；NDK/bpftool 跟 latest |
| CIDR/selector | `cidr.rs` `Ipv4Cidr`/`Ipv6Cidr`；`selector.rs` `AppSelector` | 字段公开，可绕过解析构造 |
| BPF 解析 | `parse_pkt` | L4 只受 `data_end` 约束；IPv6 见 `nexthdr==44` 即 fragment，不要求 8 字节 `frag_hdr` |
| I1b IPv6 分片 | `ingress_fast_path` | base `nexthdr==Fragment` 即 `TC_ACT_OK`，不要求 `payload_len>=8` |
| `drop_udp_frag` | `flux_abi.h` 与 `cap_core` | 名称写 UDP，分支尚未证明 L4 |
| `bpf_skb_change_type` | `flx_in` | 返回值未检查 |
| `uid_stats` | `uid_stat` | `bytes = skb->len`，GSO 口径是 skb 不是 L4 segment |
| UDP 热路径 | `cap_core` E2 | 已选 UID 在 parse 前总是 `bpf_sk_storage_get` |
| ELF | `object.rs` | 只接受 `R_BPF_64_64`；拒绝 `R_BPF_64_32` 与 CO-RE；上限 4 MiB / 256 section / 4096 symbol |
| `update_map` | `sys.rs` | 原始 FD + 切片，接口不绑定 map 的 key/value 尺寸 |
| 订阅 | `config.rs` + `subscription.rs` | 单源 8 MiB；默认 timeout 10s、retries 2；按源顺序；无总 deadline / 总正文预算；失败传输不覆盖已接受缓存 |

### 3.8 仍然靠注释维持的调用顺序

这些不是风格，拆 Planner 时必须变成 Command 前置条件，而不是继续散落在 `converge` 里：

1. 实例锁先于控制 socket bind / unlink。
2. `publish_inactive` 先于停/换引擎。
3. 当前 generation 的 effective 文件在旧进程可能回退期间不可改名覆盖。
4. Check →（若有活孩子则 inactive）→ 停旧 → spawn 候选 → 等四只 socket → Phase 6 TC → `publish_active` → `generations.commit`。
5. `stage_interface_policy` 先于 `converge_with_bpf` 先于 `apply_policy`。
6. attachment 进行中推迟拓扑，除非 reload/policy/engine dirty（否则自激 debounce）。
7. fakeip：策略对照 current-or-candidate 引擎用户配置；引擎用户对照剩余策略。
8. 事件 socket 在第一次 dump 之前打开。
9. `publish_active` 要求 attachment_ready、至少一个 active iface、以及先前的 inactive control。
10. 订阅 fetch 是唯一故意放在 worker 上的阻塞工作；reactor 不得 sleep。

---

## 4. 两份审计的逐条处置

每一条都给出：当前是否仍成立、rc.3 目标、不接受的修法。编号保留审计原 ID，便于对照原文。

### 4.1 架构阻断

| ID | 来源 | 级 | 证据 | 当前 | rc.3 处置 |
|---|---|---|---|---|---|
| A01 | 乙 | R0 | A | 仍成立：`note_stimulus` 不执行 effects | `step` 升级为 Planner，产出 `Commands`；reactor 只执行并回送完成事件。删掉“适配器”空话，或真正兑现。推荐兑现 |
| A02 / R01 | 甲+乙 | R0 | A+B+M | 仍成立：原地 add→mode→subtract | 废弃原地多 map 作为最终协议。`PolicyEpoch` 写入不活跃 bank，唯一 control commit 切换。模型反例升为回归测试。**同时改写蓝图 §10.5** |
| R07 | 甲 | R1（随 A02） | A+M | 仍成立：预检目标大小，执行峰值 N+1 | 随不可变 bank 消失；若过渡期仍有原地路径，必须预检峰值。最终方案不接受“先删后加”换窗口 |

### 4.2 正式候选前

| ID | 来源 | 级 | 证据 | 当前 | rc.3 处置 |
|---|---|---|---|---|---|
| A03 / R03 | 甲+乙 | R1 | A+B | 仍成立 | diag 纳入 epoll 事务或隔离 worker+epoch；deadline 属于整次 probe，不是每次 recv 的相对超时 |
| A04 / R02 | 甲+乙 | R1 | A | 仍成立 | `TrustedSnapshot`：保留 flags、DONE status、截断、overrun；不完整不能构造所有权结论 |
| A05 / R05 | 甲+乙 | R1 | A+B | 仍成立 | 进入 Active 前预创建可轮换 control leaf；紧急路径只切换已有对象；无法发布 inactive 有独立状态，不与普通更新失败混用 |
| A06 / R04 / R06 | 甲+乙 | R1 | A+M | 仍成立 | `Presence::{Present,Absent,Unreadable}`；WatchSet 看稳定父目录，处理 MOVE_SELF/DELETE_SELF/IGNORED/overflow；不可读开关不扩大接管 |
| A07 / R13 / R14 | 甲+乙 | R1 | A | 仍成立 | 候选冻结清单；release 不选 latest；CI 门禁与发布绑定同一 SHA；签名有效 ≠ 签名者被授权 |
| B01 | 乙 | R1 | A+M | 仍成立 | `l3_end` 与 `data_end` 双边界；不要求 `l3_end == skb->len` |
| B02 | 乙 | R1 | A+M | 仍成立 | 完整 8 字节 IPv6 Fragment header 才分类为 fragment；atomic fragment 本轮不扩大范围 |
| B04 | 乙 | R1 | A | 仍成立 | 畸形长度语料；与 Phase 6 GSO 正路径分开 |
| R08 | 甲 | R1 | A+B | 仍成立 | 每类 handler 一次调度的消息/字节/时间预算；level-trigger 预算耗尽后必须还能再被唤醒 |
| R11 | 甲 | R1 | A+B | 仍成立 | `EngineSpec` 同时描述 binary、cwd、env、候选文件；check 与 run 共用 |
| R12 | 甲 | R1 | A+B | 仍成立 | 总源数、总正文、节点数、生成文件、批次 deadline；迟到结果绑定来源与策略版本 |
| R10 | 甲 | R1 | A | 仍成立 | 区分请求未达、权威已写、收敛中、已达目标；stop 不得把通信失败当成幂等成功，除非能证明已经停下 |
| R16 | 甲 | R1 | A | 仍成立 | 规范化类型私有字段；只在能消灭无效状态的地方 newtype |
| R09 | 甲 | R1 | A | 仍成立 | 上层 typed map handle；通用 `as_bytes<T: Copy>` 收到封闭 POD |

### 4.3 质量与命名

| ID | 来源 | 级 | 证据 | 当前 | rc.3 处置 |
|---|---|---|---|---|---|
| A08 | 乙 | R2 | A | 仍成立 | 测试下沉到 Planner/事务接口，而不是给每个 getter 加测 |
| B03 | 乙 | R2 | A | 仍成立 | 计数改名为 `drop_selected_fragment`；hint 同步；**不**改成只丢 UDP |
| R15 | 甲 | R2 | A+C | 仍成立 | 按数据类别定义可见性；第三方自由文本默认不可信；输出排他创建 |
| R08 冷路径 | 甲 | R2 | A | 计数读取每次 `possible_cpus`+分配 | 缓存 CPU 布局、复用缓冲；不得抢占 R0/R1 |

### 4.4 审计乙点名、阶段二 A 未下结论的项

这些不是新功能，是同一数据面审查必须收口的项。

| 项 | 当前事实 | rc.3 处置 |
|---|---|---|
| `bpf_skb_change_type` 返回值 | `flx_in` 忽略 | 失败则计数并 `TC_ACT_SHOT`（已在 Flux veth 内，fail-closed，不泄漏到 Android） |
| L3 `change_head` / `store_bytes` / `bpf_redirect` | handoff 已检查前两者；`bpf_redirect` 的返回即 TC 动作 | 保持；redirect 失败不得 UNSPEC 回真实目的 |
| UDP 是否不必做 TCP storage lookup | 已选 UID 在 E2 无条件 `bpf_sk_storage_get` | 允许在能证明 `sk` 为 UDP 时跳过；不得把“省 helper”做成缓存 listener 存活 |
| `uid_stats` GSO/重传口径 | `bytes = skb->len` | 合同写明：按 skb 计，不按 L4 segment；不在热路径拆 GSO |
| listener lookup / guard / fault latch / ringbuf | 已有 synthetic tuple、guard、latch、ring 尺寸检查 | 核：不支持的 relocation 拒绝；latch 满/ring busy 不得无限唤醒；丢失要可观测 |
| 热路径 helper 排序 | E1 未选不 parse；E2 已有 decision 不 parse | 保持；双 bank 不得把 E1 变成 map-in-map |
| ABI / Map bank / control leaf / loader / 5.15 | 见第 8–9、15 节 | 允许 bump magic |

### 4.5 不把审计甲的克制读成禁止重构

审计甲第 10 节建议“小步、避免大重写”。那是在**不改提交协议**的前提下修补 R02–R06。审计乙与所有者本次指示允许大改。冲突时以本文为准：策略提交、Planner、TrustedSnapshot 允许一次做完，但**一次 PR 仍只改变一个主要不变量**（见第 25 节批次）。禁止把重命名、功能扩展和正确性修复混在同一提交。

---

## 5. 合同必须先改、再写代码的条款

PHIL-4：规范声称的原子与实现的多 syscall 窗口是两份真相。rc.3 先改合同。

### 5.1 蓝图 §10.5（必改）

删除“add-before-subtract 窗口是安全的，因为只影响无 decision 的流”。改为：

- 策略事务仍然**不改** `active` 与 engine generation（D5 这一半保留）。
- 可观察的 UID 模式、CIDR 模式、两族 bypass、self-address **构成同一个 `PolicyEpoch`**。
- 数据面在任一瞬间只解释一个 epoch。不允许“新 mode 解释旧新并集”。
- 失败时数据面继续解释**完整旧 epoch**；用户态镜像与 map 允许有未提交的不活跃 bank，但 BPF 不可见。
- 已有 TCP decision 仍然不可变；新 SYN/UDP 只看见提交后的 epoch。

### 5.2 蓝图 §6.4 与“单点提交”的分层

保留 control leaf 的冻结 + root 指针交换。明确三层不可互相推导：

1. 一个 map 元素更新在内核是原子的；
2. 一个 control 快照发布是原子的；
3. **整个策略的可观察行为**只有在 mode 与集合同属该快照（或由该快照选择的 bank）时才是原子的。

当前实现只有 1 和 2。rc.3 要做到 3。

### 5.3 蓝图 §7.2 / §7.3 / §7.5（解析）

- `skb->len` 不是解析终点；IPv4 `tot_len` / IPv6 `payload_len` 才是 `l3_end`。
- 每次 packet read 同时 ≤ `l3_end` 与 `data_end`。
- Fragment 至少意味着完整 Fragment header。
- `drop_udp_frag` 的 ABI 名与 failures hint 改为 selected+active+无 TCP decision 的 IP fragment。
- I1b 快路径对 IPv6 fragment 补最小长度检查。

### 5.4 蓝图 §8 / PHIL-5（dump）

“两次 dump 一致才删除”的前提是**每一次都是完整 dump**。不完整的“没看到”不得解释为“不存在”。

### 5.5 interaction §27 / failures §24

- 开关：`Unreadable` 不是 enabled。
- CLI：请求成功、权威文件已更新、运行状态已达目标，分三个结果；退出码不得把前两者当成第三者。
- JSON 计数与 hint 随 fragment 重命名一起改。

### 5.6 发布合同（§13 / §20）

区分两种服务：跟踪新稳定输入，与按记录重建某一发行。后者需要冻结清单。不得再用一次双构建字节相等证明未来解析不变。

---

## 6. rc.3 顶层不变量

后续细节服从这些条文；与它们冲突的优化删除。

### I1 一次事件只有一个权威规划结果

输入是 `Model + Event`，输出是 `next Model + Commands`。reactor 只能执行 Commands，完成结果作为新 Event 回送。handler 内不得另写一套隐含转移。

### I2 候选、已提交、观测是不同类型

至少区分：

- `DesiredState`：当前权威文件的纯结果；
- `Candidate<T>`：已解析，未提交；
- `Committed<T>`：提交点成功后的版本；
- `Observed<T>`：刚刚枚举出的事实，可能不完整；
- `TrustedSnapshot<T>`：携带完整性证据，允许做所有权判定。

禁止用一个 `Option<T>` 加布尔同时表达这些阶段。

### I3 策略只有完整旧快照或完整新快照

见第 8 节。原地多 map 更新不是最终方案。

### I4 停止能力在激活前预留

进入 Active 之前必须已经拥有：无需新增关键 map/fd 即可发布 inactive、终止 engine、记录失败。紧急路径只消费预留资源。

### I5 不完整 kernel dump 不能构造所有权结论

netlink 事务保留 header flags、DONE status、seq、port id、truncation、overrun、deadline。只有全部子 dump 完成才能构造 `TrustedSnapshot`。其它结果只能重试或 unknown，不得删除、接管或报告 clean。

### I6 reactor 的最大不可抢占片段有预算

可能阻塞的操作必须满足其一：

- 非阻塞 fd，纳入 epoll transaction；
- 隔离 worker，结果带 request epoch，过期可丢弃；
- 有严格常数上界的内存计算。

“socket 设置了超时”不等于业务操作有上界。

### I7 release 输入先冻结，再构建

候选身份 = 源码提交 + Cargo.lock 副本 + 工具链 + NDK + clang + engine + bpftool + actions SHA + 下载摘要。构建只消费这份清单。

### I8 解析的协议边界与内存边界分离

`l3_end` 是协议语义，`data_end` 是内存安全。二者缺一不可。admission 前畸形保持 `TC_ACT_UNSPEC`；已进 veth 保持 fail-closed。不得因更严解析给已捕获 TCP 增加 direct fallback。

### I9 未知不得伪装成事实

观察失败不是 false、不是零计数、不是空集合、不是 enabled。`Unreadable` / `Unknown` / `DumpIncomplete` 必须可构造且不可与成功观测混淆。

### I10 不因失败而扩大接管

输入不可读、候选失败、拓扑未知、开关不可确认时，捕获范围不得大于当前已证明的承诺。

---

## 7. 目标控制面形状

### 7.1 Planner 真正成为真相

```text
epoll events
    → Event decoder（只产生不可变事实：fd 就绪、pid 退出、inotify cookie、字节）
    → flux-core Planner
         Model + Event → Model + Commands
    → Command executors（fluxd，持有 fd/pid/PathBuf/Map fd）
    → Completion Event（带 CommandId 与 epoch）
```

`Planner` 不拥有 fd、pid、`PathBuf`、Map fd。它处理稳定 ID、版本、结果枚举、deadline 与脏位。资源对象留在 `fluxd` 的 executor。

这保持单线程可变状态（executor 仍只被 reactor 调），同时让转移规则在任意主机上穷举。**不引入第二个线程跑 Planner。** 订阅 fetch 已在 worker 上；它只回送带 epoch 的字节，不规划状态。

### 7.2 现有 `Effect` 不够，要升级为 Command

当前 `Effect` 已有 `AttemptActivation`、`PublishInactive`、`PolicyTransaction` 等，但：

- 没有身份、epoch、deadline、成功/失败载荷；
- reactor 不执行它们；
- `PolicyTransaction` 的含义仍是 §10.5 的 add-then-subtract。

rc.3 的 Command 至少携带：`CommandId`、domain、输入 epoch、deadline、成功类型、可分类失败、`superseded`/`cancelled`。完成事件若 epoch 不匹配，只释放资源与必要诊断，**不得提交旧候选**。

建议的域（具体类型名可在实现时调整，职责不可合并回一个大枚举）：

| 域 | 拥有者 | 典型 Command |
|---|---|---|
| Intent | Planner | 无；只反映开关/SSID |
| Policy | `dataplane::policy` | `PreparePolicy(epoch)`、`CommitPolicy(epoch)`、`AbandonPolicy(epoch)` |
| Engine | `engine` 事务对象 | `WriteEffective`、`SpawnCheck`、`SpawnRun`、`ProbeReady`、`Retire`、`Kill` |
| Topology | `dataplane::topology` | `Dump`、`Reconcile`、`Attach`、`Verify`、`DetachExact` |
| ControlPublish | `dataplane::bpf` | `Publish(leaf)`、`PublishInactive`（预留对象） |
| Watch | `WatchSet` | `Rebuild`、`Reread(domain)` |
| Fetch | subscription worker | `FetchBatch(policy_epoch)` |
| Project | layout | `WriteModuleProp`、`Reply(control)` |

### 7.3 顶层状态正交，禁止巨型总枚举

```text
IntentState    : Disabled / Enabled / SsidPaused
ServingState   : Inactive / Activating / Active(epoch) / Stopping
PolicyTxn      : Idle / Building(id) / Committing(id)
EngineTxn      : Idle / Checking / Starting / WaitingReady / Retiring
TopologyTxn    : Idle / Dumping / Attaching / Verifying
PendingWork    : 按域合并的 level-triggered dirty bits + 最高版本
```

`CommittedView` / `project()` 继续是 **唯一** 把运行事实投影成用户 `Disabled/Inactive/Active` 和 `module.prop` 的地方。rc.2 的 `Generations { next, committed }` 保留，且仍是世代唯一可写点。`Phase` 今日是观测值不是存储器；Planner 的 `ServingState` 可以成为权威，但必须能从同一组 Observation 旗标重建，禁止再维持平行的 `observe()` 表。

每次重构自问：是否减少了一条“先调用 A 再调用 B，否则坏掉”的隐藏规则？只换文件位置不算完成。

### 7.4 reactor 收缩后还剩什么

合法职责：

- epoll_wait、把就绪 fd 译成 Event；
- 调 Planner；
- 把 Command 交给对应 executor（同步短命令当场做完，长命令登记并返回 epoll）；
- 把 executor 完成译成 Event；
- 写 `module.prop`（由 Project command 触发，不在每个 handler 手写）。

非法职责：在 `handle_inotify` 里直接 `converge("disable-file change")` 并隐含一整套策略/引擎决策。

### 7.5 `dataplane::Manager` 拆职责，不拆所有权

外部仍是少量方法，内部三个深模块（具体类型，无 trait）：

1. **topology**：只接受 `TrustedNetworkSnapshot`，产出带身份的拓扑计划与 attachment 计划；删除前现场证明身份（PHIL-5）。
2. **policy**：构造 `PolicyEpoch`、写入不活跃 bank、核对计数、请求 commit。
3. **bpf runtime**：持 object、Map fd、两个预创建 control leaf、ringbuf、program identity。

外部接口示例（名称可改，宽度不可膨胀）：

- `prepare_policy(epoch) -> Result<PreparedPolicy, PolicyBuildError>`
- `commit_policy(epoch) -> Result<(), CommitError>`
- `prepare_generation(params)`
- `publish_inactive() -> Result<(), InactivePublishError>`  （不得在此时 `BPF_MAP_CREATE`）
- `reconcile_topology(TrustedSnapshot)`

`attachment.rs` 保持为 clsact / 未来 TCX 的插入点（§12.5.1），不在 rc.3 实现 TCX。

---

## 8. 策略 Epoch 与 ABI

### 8.1 为什么双 bank，以及为什么不用 ARRAY_OF_MAPS 做 uid_policy

目标：BPF 一次 `ctrl()` 看到的 `cidr_mode` 与四张策略 map 属于同一 epoch。

不采用“策略也做成 map-in-map、用 bank 当下标”作为 **uid_policy** 方案：那会在 E1 未选路径上增加一次 inner-map lookup，破坏“未选流量只付身份 helpers + 一次 hash miss”的预算。control_root 已经是 map-in-map，那次成本只发生在需要 control 的路径上，不要扩散到 E1。

采用**两套同型 map + control 里的 `policy_bank: u8`（0 或 1）**：

```text
uid_policy_0 / uid_policy_1          HASH
bypass_v4_0  / bypass_v4_1           LPM NO_PREALLOC
bypass_v6_0  / bypass_v6_1           LPM NO_PREALLOC
self_addr_v4_0 / self_addr_v4_1      HASH
self_addr_v6_0 / self_addr_v6_1      HASH
```

C 侧：

```c
if (c->policy_bank)
    mode = bpf_map_lookup_elem(&uid_policy_1, &uid);
else
    mode = bpf_map_lookup_elem(&uid_policy_0, &uid);
```

只执行一次 lookup。verifier 看到两条常量分支。5.15 上这比动态 inner map 指针更不容易把 E1 变复杂。不要写成 `maps[c->policy_bank]` 那种 verifier 看不出上界的形式。

bypass / self-address 只在已经持有 `c` 的慢路径或已选路径上使用，同样用 bank 分支，不加 map-in-map。

### 8.2 提交协议

1. Planner 产出 `PreparePolicy(epoch)`。executor 选择 **非当前** bank，清空或覆盖写入完整 desired：全部 SELECTED、DRAINING（仍不在本 boot 删除 UID 键）、RESERVED+POLICY 前缀、self-address。
2. 核对本 bank 计数与 candidate。失败则 `AbandonPolicy`，BPF 仍读旧 bank。
3. 在**预创建的另一片 control leaf** 写入完整 `flux_control`（含新 `policy_bank`、新 `cidr_mode`、旧的 `active`/`generation`/listener 字段），freeze。
4. 一次 `bpf_map_update_elem(control_root, 0, new_leaf_fd)`。这是策略的唯一可见提交点。
5. 旧 bank 变为可回收。回收不是提交的一部分；BPF 已看不见它。可在空闲时删除旧键，以便下次 prepare 有空间。

UID DRAINING 语义保留：从 SELECTED 集合消失的 UID 在**新 epoch** 里写成 DRAINING，不是先在旧 map 原地改再切 mode。

### 8.3 容量

LPM `max_entries` 仍为 `LPM_MAX_ENTRIES`（65536），`BPF_F_NO_PREALLOC`。双 bank 峰值是“旧 bank 已占用 + 新 bank 完整写入”，不是 2×max 预分配。prepare 必须拒绝“新集合 > max”以及“实现无法在不触及活动 bank 的情况下完成写入”。不要用“先删活动 bank 再写”来腾空间。

UID map：boot 期内 DRAINING 仍占用条目。总键数上限仍是 `UID_POLICY_MAX_ENTRIES`；双 bank 各自持有完整镜像，所以用户态必须负担两份 UID 条目的内存，这是可接受的控制面成本。

### 8.4 故障注入必须证明的中间态

对每一次 syscall 之后枚举：

- 旧/新策略都不该捕获的目的，不得被临时捕获；
- 旧/新都该捕获的目的，不得被临时直连；
- 新 UID + 其 bypass 必须同屏出现或都不出现；
- 满容量替换、双栈一边失败、prepare 中途 `BPF_MAP_UPDATE` 失败：活动 bank 不变。

独立模型 `flux_review_checks.py` 的四条反例必须变成仓库内测试（不必引入该 Python 文件为依赖；用 Rust 表驱动复述即可）。

### 8.5 ABI bump

`flux_control` 增加 `policy_bank`（占用现有 `pad1[8]` 的 1 字节即可，结构仍 96 字节）。**必须 bump `FLUX_ABI_MAGIC`**，即使 sizeof 不变：旧对象不得加载。建议 `0xF10C0905`。`flux_decision` 布局不改，TCP 决策稳定性保持。

同步点（同批，缺一不可）：`bpf/include/flux_abi.h`、`flux-core::abi`、`MAP_SPECS` / 生成头、`btf` 若涉及、status JSON、Phase 4 map 名表、CHANGELOG。

map 数量：12 → 18 量级（5 组双 bank 净增 5，再加一片预创建 leaf）。`MAP_NAMES` 与 Phase 4 断言一起改。

### 8.6 用户态镜像

`Manager` 里现在的 `uid_modes` / `bypass_*` / `self_*` 是第二份真相。rc.3 后：

- `CommittedPolicy` 只在 commit 成功后更新；
- 正在 prepare 的 bank 是 `Candidate`；
- `status` 的计数来自 committed，或显式标注“来自活动 bank 的现场求和”，不得把 prepare 中的半写入报成当前策略。

### 8.7 被否决的策略方案

| 方案 | 否决 |
|---|---|
| 多加一次布尔、把两次 syscall 挪近、sleep | 不消除可观察中间态 |
| 无限重试同一半更新 | 满表时无法自行腾空间；无界占用 reactor |
| 先删后加 | 引入反向窗口（该捕获的变直连） |
| 策略 ARRAY_OF_MAPS 做 E1 | 未选路径多一次 helper。control 的 freeze+root 交换模式只用于 leaf；uid_policy 用两张同型 map 的常量分支 |
| UDP 决策粘在 SK_STORAGE | UDP 没有 stickiness；每数据报重评。双 bank 不得假设 UDP 也有 immutable decision |
| 把整份策略序列化进一张冻结 array | 5.15 上大 value、更新成本、verifier 不友好 |
| 双缓冲却不证明旧读者寿命 | leaf freeze + root 交换已经解决 control；策略 map 必须靠 bank 选择，而不是“等几毫秒” |
| 热更新时清空 SK_STORAGE | 已有连接被重新解释，违反决策稳定 |

---

## 9. Control leaf 预留与停止

### 9.1 两片 leaf，加载时创建

`control_root` 仍是 `ARRAY_OF_MAPS` max=1。加载时创建 **两** 个 `control_leaf` ARRAY。任意时刻：一片是活动冻结快照，另一片是可写预备。

发布：写入预备 → freeze → 更新 root → 原先活动片变为下一轮预备（需要的话先解冻或丢弃重建；若 5.15 对 frozen map 不能复用，则**加载时创建 2，之后只轮换已有 fd，失败则保持旧 root**，仍禁止在 shutdown 路径上 `BPF_MAP_CREATE`）。

若 freeze 不可逆导致不能原地复用，则在 **prepare 进入 Active 之前** 额外创建足够的 leaf fd 放进池里，紧急时只从池取。池空时的行为见 9.2，不得悄悄 `MAP_CREATE`。

### 9.2 无法发布 inactive

独立错误类，例如 `inactive_publish_failed`。合同：

- 不得报告 Active/capturing；
- 必须尝试停引擎（pidfd + 已有 SIGTERM 路径）；
- `status` 诚实；
- 不把该失败当成普通 policy 更新失败去重试 add-then-subtract。

预分配减少失败点，不证明停止绝对成功。syscall 仍可能失败。

### 9.3 与 generation 的关系

D5：策略 commit **不**增加 engine generation，**不**改 `active`。listener 字段保持。只有 §9.4 换代和真正的 inactive/active 翻转才改这些字段。策略 bank 切换可以与换代同时发生，但是两个提交点，失败独立回滚。

---

## 10. TrustedSnapshot 与 netlink

### 10.1 类型

```text
RawMessage { kind, flags, seq, pid, payload }
DumpStatus { done_errno, dump_intr, truncated, overrun, timed_out }
TrustedSnapshot<T>    // 只从 DumpStatus 全绿的解析结果构造
IncompleteDump        // 不可转为 TrustedSnapshot
```

`NetworkSnapshot` 今日只表示“解析出了一组对象”。rc.3 拆开。所有权删除、attachment 计划、self-address 收敛，只接受 `TrustedSnapshot`。

### 10.2 协议

- `recvmsg` + 检测 `MSG_TRUNC`；截断 ⇒ 整次 dump 作废。
- 保留并判断 `NLM_F_DUMP_INTR`。
- `NLMSG_DONE` 负状态与 sock_diag 对齐（通用 dump 今日缺失）。
- seq / port id 校验保留。
- 重试：次数 + **总** deadline；网络抖动下不得无限重扫。
- ENOBUFS / overrun：已有 `DrainResult::Resync`，必须通向 FullRedump command，且该 dump 仍要完整。

### 10.3 多子 dump 的观察窗口

一次 topology snapshot 含 link/addr/rule/route/qdisc/filter 等多轮 dump。rc.3 要求：要么全部成功才构造 TrustedSnapshot，要么整体 Incomplete。不允许“link 完整、filter 截断仍去删 filter”。

两次 dump 交叉验证（蓝图已有，`cleanup_owned` 已实现“两份 CleanupPlan 相等才删”）保留，且**两次都必须是 Trusted**。两份残缺但碰巧相等的计划不得删除。

### 10.4 阻塞 vs 非阻塞

route 事件 socket 已是非阻塞。请求 socket 的阻塞+3s 超时不够。目标：topology dump 走非阻塞 + epoll 状态机（`TopologyTxn::Dumping`），每段读取有预算，整次 dump 有 deadline。

---

## 11. 有界等待

### 11.1 SOCK_DIAG

禁止在 reactor 线程上对无超时阻塞 socket 做完整 dump。

推荐（保持单 reactor，不引入 async 框架）：

- 长寿命非阻塞 `NETLINK_SOCK_DIAG` fd 纳入 epoll；
- `ProbeReady` 是状态机：发四次 dump 或一次合并策略，完成前可处理 disable/stop；
- 整次 probe 共享 deadline（现有 5s 量级，但是**能抢占**）；
- 若实现难度迫使使用 worker：结果必须带 `engine_epoch`，过期丢弃。

验收：注入只有部分 dump、没有 DONE；期间发 disable。分别测：请求响应、停止新准入、子进程退出。不能只看 CLI 是否返回。

### 11.2 handler 预算（R08）

| 来源 | 预算对象 | 超限 |
|---|---|---|
| 引擎 stdout | 字节/行 | 丢弃中间、保留头尾；`OUTPUT_CAP` 之后必须停止 `read`，不得只停保存 |
| rtnetlink 事件 | 消息数 | 设 Resync dirty bit，交还调度器；`drain_messages` 今日循环到 EAGAIN 无预算 |
| inotify | 已有 4K 缓冲 | overflow → 全量权威重读 |
| ringbuf | 已有记录尺寸检查 | busy/discard 计数；不得忙等 |
| 控制连接 | 已有会话对象 | 半开连接 deadline |

level-trigger：预算耗尽后 fd 仍就绪，必须显式保留“还要再读”的 dirty。若未来改 edge-trigger，必须单独安排续处理——本轮不改触发模式。

### 11.3 关键事件延迟目标（写入合同的是目标，不是已测值）

| 事件 | 目标 |
|---|---|
| disable / stop 开始停止准入 | 不超过当前 dump/diag 的剩余 deadline，且不得再开新的无界 recv |
| 引擎 SIGCHLD/pidfd | 本轮 epoll 内进入 PublishInactive |
| 控制 `status` | 不启动 dump；只读 committed |

数字在设备上测量后填入实施记录，不在设计阶段假装已有基线。

---

## 12. 文件权威与 WatchSet

### 12.1 观察结果类型

```text
enum AuthorityRead<T> {
    Present(T),
    Absent,
    Unreadable { error },
}
```

`disable` 文件：`Present` ⇒ Disabled；`Absent` ⇒ 开关允许启用；`Unreadable` ⇒ **不**进入 enable 转移，报告原因，捕获范围不扩大。

真正的 `ENOENT` 保持 C9 现义。EIO/EACCES/路径是文件而非目录等不得折叠。

### 12.2 WatchSet

独立小对象，不是 reactor 里三只 `wd: i32`：

- 监视**稳定父目录**（模块目录的父或模块目录本身对 disable 文件；配置目录的父；packages.list 的父——后者已经做对）；
- 校验目标 inode 与类型；
- mask 包含 `IN_MOVE_SELF`、`IN_DELETE_SELF`、`IN_IGNORED`、`IN_Q_OVERFLOW` 以及现有 CLOSE_WRITE/CREATE/DELETE/MOVE；
- 失效时从路径重新解析、重建子 watch、发出合并后的 `AuthorityDirty(domain)`；
- inotify 事件**永远不代表文件内容**，只代表可能变了。

Planner debounce 后 `Reread`。atomic 文件替换、目录替换、删除后重建、注册失败恢复，走同一条路径。

不要加永久定时扫描（PHIL-3）。不要把“文件 rename 可检测”当成“目录 rename 可检测”。

### 12.3 一次输入版本，一个候选

`configuration.rs` 已有集中读取。候选对象必须持有它实际使用的字节快照（主文件、advanced、`@file`、packages.list 相关子集），避免子模块在一次操作里各读一次“最新”。

这不是跨文件分布式事务。用户同时改多个文件时，debounce 后一次重读收敛。来源身份 ≠ 抓取策略版本。

---

## 13. 引擎事务

### 13.1 唯一所有者

`EngineTxn` 是唯一持有换代中间状态、子进程、pidfd、output fd、deadline 的对象。reactor 不得在事务外 `kill` 或再 spawn 第二个候选（允许短暂 overlapping 的旧+新，这是现有 §9.4，不是并行多引擎产品）。

### 13.2 EngineSpec

一份描述：

- binary 路径
- cwd（数据根）
- 必要环境
- 候选配置绝对路径
- listener 期望
- check 与 run 的 argv 前缀

`spawn_check` 必须 `current_dir(spec.cwd)`（或与 run 相同的 chdir 契约）。验收：从两个不同主机 cwd 调 CLI，配置含相对资源时，check 结论与 run 一致。

### 13.3 事务交错

必须表驱动覆盖：

- check 完成的同时新配置到达（旧 check 结果 epoch 不匹配 → 丢弃）；
- WaitingReady 时 disable/stop；
- 旧子进程尚未退出时候选已 ready；
- check 成功、激活失败；
- 运行提交成功、缓存 fsync 失败（权威仍是已运行的 generation，缓存失败要可见）。

### 13.4 输出风暴

`EngineCheck::drain_output` 在 `captured` 达到 `OUTPUT_CAP`（64 KiB）后仍继续 `read` 到 EAGAIN。`drain_output_head` 在缓冲满时才停。两者都要纳入第 11.2 节：保存有上限，**读取次数/时间也有上限**。

---

## 14. BPF 数据面（补完阶段二）

### 14.1 解析合同（B01/B02）

`parse_pkt` 保持现形状，不引入通用解析框架、tail call、新 map。

不要把审计乙 B01 理解成“`tot_len` 相对 `skb->len` 的检查是错的”。那条检查对 GSO 是对的：逻辑长度可以大于当前线性头。乙的 B01 是另一件事：固定 L4 头只证明了 `≤ data_end`，没有证明 `≤ nh_off + tot_len`，于是声明包尾之外、仍在 skb 里的尾随字节可以被当成 TCP/UDP 头。

进入各协议后计算一次：

```text
IPv4 l3_end = nh_off + tot_len
IPv6 l3_end = nh_off + sizeof(ipv6hdr) + payload_len
```

此后扩展头推进、Fragment header、固定 L4 头同时证明：

1. 所需字节 ≤ `l3_end`；
2. 指针 ≤ `data_end`；
3. packet-derived offset 有 verifier 可见的常量上界（现有 ihl/ext 循环上限保留）。

内部结果互斥（不必改成 C enum，但组合必须不可含糊）：

```text
UnsupportedOrMalformed | Fragment { family, daddr } | Tcp { … } | Udp { … }
```

admission 前：malformed/unsupported → `TC_ACT_UNSPEC`。ingress（已进 veth）：→ drop 计数。已有 CAPTURED decision 的包不走 parse，不受更严解析影响。

### 14.2 I1b 快路径

IPv4 fragment：现有 MF/offset 检查外，应证明最小 IPv4 头在 `data_end` 内（已有）。IPv6：在 `nexthdr==Fragment` 时要求 `payload_len >= 8` 且 8 字节 header 在 `data_end` 内，再 `TC_ACT_OK`。不要在快路径解析 inner L4。

atomic fragment（offset=0, M=0）本轮仍按 fragment 的保守语义，不扩大为继续 parse。是否放宽留给有应用兼容性证据之后。

### 14.3 计数 B03

`FLUX_CNT_DROP_UDP_FRAG` 重命名为 `FLUX_CNT_DROP_SELECTED_FRAGMENT`（或等价标识符）。定义：selected、active、未命中 bypass、无既有 TCP decision 的 IP fragment。不得改成“只丢 UDP”——那会让无 decision 的 TCP 分片直连。

ABI bump 已因 control/bank 发生，计数名可同批改。status JSON 与 `failures.md` hint 同步。

### 14.4 `bpf_skb_change_type`

失败：计数（新计数或归入 parse/handoff）+ `TC_ACT_SHOT`。不得继续 assign。包此时已经在 `flxrs1` 上：失败而不计数会变成 `PACKET_OTHERHOST`，随后 `ip_rcv` 静默丢弃，诊断指向错误层。这在 veth 内，不把包送回 Android。

### 14.5 UDP 与 TCP storage

允许：若能从 `bpf_sock` 稳定读出协议为 UDP，跳过 `bpf_sk_storage_get`。必须在 5.15 verifier 与设备上证明。禁止用“缓存 listener 一定活着”换 helper。

### 14.6 uid_stats

继续只在 captured 路径更新（E2 captured 与 E4/E5 捕获）。`packets += 1`，`bytes += skb->len`（L3 路径按现逻辑扣 Ethernet 与否保持一致）。合同写明 GSO 下是 skb 计数。不实现 Prometheus/HTTP（D23 现状）。

### 14.7 listener / fault / ringbuf

- lookup 失败：现有 miss 计数 + `fault_once`；admission 前 fail-open。
- latch 防止同 generation 风暴；`ringbuf_reserve` 失败时现实现会删 latch 以便稍后重试——这是设计，不是 bug；删除 latch 会重新开门，不得在用户态把“忽略重复”写成“已恢复”。
- ringbuf：busy/discard/wrap/损坏记录不得无限唤醒；丢失可计数。
- relocation：非 `R_BPF_64_64` 拒绝。FD 在所有失败路径成对关闭。

### 14.8 畸形语料与设备

主机：与生产对象相同的解析 helper（test-only sched_cls 或临时 veth），不要长期维护第二份 parser。语料表用审计乙 §15.1 原表，不删行。

设备：Phase 6 正路径继续；另开可清理的 malformed 子测试。断言看 counter delta，不只看 `send()` 成功。5.15.211 上四个 entry 重新 `load_embedded`，记录 insn 与 stack。不能用 CI 新内核代替。

合法 GSO/options/重传不得回归。

---

## 15. Loader 可信计算基

默认**保留**手写 loader。不因“手写有风险”而引入 libbpf。评估标准仍是：它减少的 Android 依赖 vs 维护负担。

rc.3 要补的证据，不是换框架：

- 每个 relocation 属于明确支持的形式；
- map 类型、flags、key/value、ABI/BTF 与内核 `map_info` 一致（现有 `verify_info` 扩展到双 bank）；
- 失败路径 FD/引用成对；
- C 源、clang ELF、手写 BTF、内核加载四者对应（现有 abi-check / btf-check 继续，map 数变化后更新）；
- 5.15 verifier 是产品门，不是 bpftool 在新内核上通过。
- 约束（fancy 方案的硬墙）：arm64 5.15 **禁止 fetching atomic**（verifier 过了 JIT 仍 `-ENOTSUPP`）；`-mcpu=v3` 不是 v4；helper 之后指针失效；flag 与指针不能让 verifier 相关；`bpf_sk_assign` 在 6.5 前拒绝 `SO_REUSEPORT`；禁止 tail call / BPF-to-BPF / spinlock / timer / perf event。双 bank 因此必须是 map 指针交换或常量 bank 分支，不能靠全局原子计数。
- LPM 在 **6.6.0–6.6.46** 有 UBSAN 崩溃（加载器已拒）；不是 5.15 的问题，但挡住那些内核上的双 LPM 实验。

`sys.rs`：低层 raw 保持，但标明 unsafe 前提。上层 `MapHandle<K,V>` 固化尺寸；错误长度走不到安全写接口。对无 syscall 的字节变换，适用时用 Miri；Miri 不是内核 ABI 证明。

---

## 16. 类型不可表示性

### 16.1 必须收口

- `Ipv4Cidr` / `Ipv6Cidr`：字段私有，只从解析器构造；访问器只读。
- `AppSelector`：同样。解析失败类型保留。
- `TrustedSnapshot`：无公共“从 Vec 随便包一层”的构造器。
- `PolicyEpoch` / `Candidate` / `Committed`：不同 typedef，禁止互相隐式转换。

### 16.2 不要仪式化

不必给每个 `u32` 做 newtype。uid 0 继续在 selector 解析期拒绝。control 的 `active` 保持 0/1 并在 freeze 前校验。

序列化反构（若有）必须再走验证。内部防错不替代外部防御性解析（PHIL-2：外来数据）。

---

## 17. CLI、投影、诊断

### 17.1 结果分层（不必立刻改 wire schema 到操作 ID）

最低区分：

1. 请求未送达（socket 缺失、超时、协议错）；
2. 请求已接受；
3. 权威文件更新成功（enable/disable 的 C9 文件）；
4. 收敛进行中；
5. 运行状态已达目标；
6. 候选失败但旧状态仍可用。

`status` 成功 ≠ 互联网可达。控制路径上 enable/disable 的 `ok` 今日跟开关文件，stop 的 `ok` 今日恒为 true——投影层必须把这三件事拆开，不能靠 `Response.ok` 一个布尔。

### 17.2 命令

| 命令 | 今日问题 | 目标 |
|---|---|---|
| `stop` | `Err(_)` 当成功 | 仅当能证明 daemon 未在跑（无锁/无 pid/ESRCH）才幂等成功；通信失败非零 |
| `enable`/`disable` | 忽略 `response.ok` | 文件操作失败非零；daemon 回复 `ok=false` 非零；文件已写但未收敛用 warning，不与 Active 混淆 |
| `reload` | 已看 `ok` | 保持 |
| `subscribe` | 已看 `ok`；125s 超时 | 超时作为 1；总预算见第 18 节 |

不引入任务数据库。先用现有状态机和有限枚举。

### 17.3 诊断 R15

按类别规定可见性：

| 类别 | 默认 |
|---|---|
| URL / URI userinfo / query | 遮罩 |
| 凭据、Authorization | 禁止 |
| 节点名称 | 遮罩或省略 |
| 第三方错误文本 | 当作可能含秘密 |
| 应用包名 | 允许（策略需要） |
| 网络地址 | 保持现有形状脱敏 |
| 自有结构化错误 | 安全渲染 |

canary 凭据贯穿非法配置、TLS 错误、引擎输出、ZIP。只用虚构秘密。不宣称正则能匿名化任意日志。用户指定输出目录时排他创建 + 显式权限。

文案：区分失败、继续用旧状态、暂时无法确认。历史累计 counter 不当成刚发生的事件；观察失败不渲染成零再推导无流量。

---

## 18. 订阅

已有独立 worker + eventfd，方向对。rc.3 补整体预算，不改成无限任务队列，不默认大并发。

- 上限：源数、总正文（不是只 8 MiB×N）、节点数、生成文件大小、批次 deadline。
- 确定性错误不盲目重试（4xx、解析失败）。
- 完成时校验来源集合与 `policy_epoch` 仍适用；迟到结果丢弃。
- 若并发：固定小并发，最终组装保持配置顺序。
- 失败不得覆盖已接受缓存；也不得把失败新策略写成“最后成功”。
- 手工节点可用而远端失败：按现有“独立来源可见、整体候选规则”写清，不要静默。

推算（不是实测）：5 源 ×（1+2 次）× 10s ≈ 150s。这是为何必须有批次 deadline，也是 `subscribe` CLI 125s 可能仍不够诚实的原因——要么提高可见超时并显示进度，要么缩短批次上限并在 status 里报 `deadline_exceeded`。

---

## 19. 发布与历史重建

### 19.1 两套服务

| 服务 | 做法 |
|---|---|
| 开发跟踪新稳定版 | 继续 `version = "*"`、跟 `stable`、解析官方 latest engine；由**独立更新流程**产出下一候选的冻结清单 |
| 重建某一发行 | 只消费该发行归档的冻结清单，不在 release job 里选 latest |

开放依赖是既定产品取舍，不擅自改成日常提交 `Cargo.lock`。rc.3 改变的是**候选/发行**，不是开发者每次构建。

### 19.2 冻结清单内容

源码 SHA、`Cargo.lock` 副本、`rustc -vV`、NDK 版本与 clang 路径、主机/Android BPF clang、engine 资产 URL 与摘要、bpftool 身份、GitHub Actions 的 **commit SHA**（禁止 `@main`/`@master`）、构建命令、产物摘要。

拟议的冻结命令（落地时再登记为正式 xtask 名）生成 `dist/freeze/`；现有 `cargo xtask release` 只消费该清单，不在 job 里解析 latest。

### 19.3 工作流

- CI 与 release **复用同一验证工作流**或 `workflow_call`；release 不得是较短的子集。今日缺：Windows host-safe、`FLUX_BUILD_BPF` 的 verifier/abi/btf、`cargo-deny`、shellcheck / `module_lifecycle_test.sh`；也没有 `needs:` 绑定已绿的 CI run。
- NDK 脚本与 bpftool 今日跟 `latest`；冻结后必须改读清单里的版本。
- 构建 job 只读；仅 publish job `contents: write`。
- tag 验证：GitHub `verified` **并且**签名者在 owner allowlist / 受保护 environment。
- 失败：门禁红、tag 指向不同提交、有效但非授权签名、产物与清单摘要不一致 → 不发布。

### 19.4 优化级别

`opt-level = "z"` + LTO 保留为默认，直到有同输入下 z/s/2/3 的体积、启动、RSS 数据。不凭“网络程序”改 3。BPF 编译参数单独比较。

---

## 20. 验证体系

五层不互相替代。每个测试声明验证哪一条不变量。覆盖到函数 ≠ 覆盖失败时序。

### 20.1 层

1. **纯逻辑**：Planner 表、CIDR、selector、生成确定性、策略 epoch 模型（含四条第三态反例）。
2. **协议**：netlink/IPC/ELF 畸形、DUMP_INTR、截断、DONE 负状态。
3. **daemon 集成**：假引擎、可控时间、失效 I/O、真实进程监督；check cwd。
4. **Linux/BPF**：真加载、真 map、双 bank commit、解析语料、verifier。
5. **Android**：OEM/管理器/切换/origdst/共存；畸形包 counter；disable 尾延迟。

### 20.2 故障注入矩阵（审计甲 §9.2，全部保留）

control map 创建/冻结/切换；策略第 k 次更新；netlink interrupted/truncated/DONE 错；diag 半 dump；权威文件不可读与 fsync 失败；watch 目录替换/丢失/溢出；引擎卡 check/输出风暴/早退/忽略 TERM；订阅慢源/大响应/迟到；IPC 错帧；诊断 canary；发布非授权签名。

另加：policy prepare 成功、commit 失败；inactive 发布失败；Planner epoch 不匹配的完成事件。

### 20.3 设备场景（审计甲 §9.3，全部保留）

双应用选/未选、双栈 TCP/UDP、系统明文 DNS；多用户与共享 UID；Wi-Fi/蜂窝、CLAT、VPN、热点不在范围；接口同名重建与 ifindex 变化；启停换代回滚、daemon/engine 崩溃、重启；三管理器首装停用/升级/卸载残留；不支持页大小与冲突环境的拒绝说明。

rc.2 的 Phase 4–6 不替代候选 ZIP 的 §20，也不替代 Phase 7。

### 20.4 性质测试优先生成的输入

任意合法旧/新 CIDR 模式与集合的逐步过渡；每个 map 操作位置失败的幂等恢复；任意截断点的 netlink/ELF/IPC；来源换序/重复/删除；Unicode 与混合换行不泄漏秘密；相同完整输入多次生成字节一致——**不**为伪造一致性而排序本来有语义的数组。

新测试依赖先过 GOV-1.2。多数反例用现有 `harness = false` 与 `flux-core` 测试即可。

---

## 21. 性能：先有界，再测量，再改 BPF

顺序固定：

1. 消除无界等待与无界积累（I6、R03、R08）；
2. 一次收敛内去掉重复读盘、重复 parse、重复 dump；
3. 不可变候选共享，避免无谓 clone；
4. status 路径的分配与重复 sysfs；
5. **最后**才根据测量改 BPF helper 与生成代码。

四类成本（未选 / 已选 TCP / UDP / 控制面）必须带构建摘要、内核、温度频率、包长、并发、方向、重复次数。不比较热降频与冷启动。

禁止：

- 缓存永不失效的 listener 存活；
- 热路径周期监测、字符串、动态规则、地址学习；
- 每次事件重启引擎或重建全部接口；
- 把所有大对象永久缓存；
- 只优化平均吞吐、不测停用/恢复尾延迟。

双 bank 的 E1 约束见第 8.1 节，属于性能合同，不是后期微优化。

---

## 22. 深模块接口（设计用语）

用词：模块、接口、实现、深度、接缝、适配器、杠杆、局部性。不在本设计里为“将来可能的第二实现”预留 trait。

| 模块 | 接口（调用方必须知道的） | 实现藏什么 | 接缝 |
|---|---|---|---|
| Planner | `step(model, event) -> (model, commands)`；不变量 I1–I10 | §26 表、脏位合并、epoch 作废 | 纯函数；测试即接口 |
| Policy | prepare/commit/abandon | bank 选择、map 写入、计数 | 无第二适配器；测试用真实 map 或同进程 fake map fd |
| Topology | dump→TrustedSnapshot→计划 | netlink 细节、身份谓词 | 不完整 dump 在类型上进不了删除 |
| BpfRuntime | load、publish leaf、inactive、identities | ELF、syscall、leaf 池 | 失败路径 FD |
| EngineTxn | spec + commands | fork/exec、diag 状态机 | check/run 同一 spec |
| WatchSet | dirty 事件 | inotify cookie/inode | 事件≠内容 |
| FetchBatch | epoch + 预算 + 有序结果 | TLS、重试 | worker 是执行器不是规划器 |
| Project | CommittedView | module.prop 文本 | 唯一投影 |

删除测试：加深后，旧的“调用内部顺序”测试若只断言实现细节，应删掉，改为接口上的可观察结果（审计/codebase-design：replace, don't layer）。

`configuration` 已是集中 I/O，加深为“一次读出 `DesiredState`”，不要再让 reactor 拼文件。

---

## 23. rc.3 新增的否决项

补进“提议时先查这里”，实施时不要再辩论：

| 方案 | 否决 |
|---|---|
| 用 Tokio 解决 diag 阻塞 | 单 reactor 契约；用 epoll 事务或带 epoch 的隔离 worker |
| 用健康轮询弥补 watch/dump | PHIL-3 |
| 引入 libbpf 只为少写 loader | Android 依赖；先补 TCB 证据 |
| 策略 map-in-map 做 E1 | 未选路径成本 |
| 把 `runtime::step` 测绿当成 reactor 已证明 | A01 |
| 给 `apply_policy` 再打补丁而不改 §10.5 | 第三态仍在 |
| 巨型全局 enum 覆盖所有组合 | 组合爆炸 |
| 操作 ID 数据库 / 事件溯源 | 无并行需查询的历史操作 |
| 多并行 engine | §9.4 短暂重叠已够 |
| 机型 allowlist | 能力用探测表达 |
| 微基准代替 5.15 verifier 与真机 | §15.1 |
| 为严格解析加用户开关 | 机制不是策略（PHIL-1） |
| 正式 1.0.0 与 rc.3 同一提交 | 仍需远端 CI 与 ZIP §20 |

历史否决（cgroup、TUN、nft、`bpf_redirect_peer`、抢 netd 槽位等）全部继承 `rejected-and-deferred.md`。

---

## 24. 用户可见变更与 GOV-1.2

内部重构（Planner、bank、TrustedSnapshot、WatchSet）属 GOV-1.1。下列影响用户可观察行为，实施前用选项问所有者（GOV-1.3）。推荐项标在第一。

### 24.1 策略提交从“窗口期第三态”改为真快照

1. **推荐：** 按本文 I3 提交；用户可见变化是：换 CIDR 模式/名单时，新连接不再在中间态被错误捕获或错误直连。已有 TCP 仍不重新判定。
2. 保持今日 add-then-subtract，并把第三态写进合同，声明允许。代价：R01 永久存在，TCP SYN 可固化错误决策。
3. 跨模式更新必须先 inactive 再 active。代价：用户可见短暂 Direct。

### 24.2 开关不可读

1. **推荐：** `Unreadable` 不启用、不扩大捕获，status 报原因。
2. 保持今日“metadata 失败即 enabled”。代价：EIO 时可能在用户以为关掉时仍捕获。

### 24.3 CLI 退出码

1. **推荐：** 第 17.2 节。可能让现有脚本把“daemon 没在跑时的 stop”看成失败——可用“锁不存在 ⇒ 成功”保留幂等。
2. 保持今日 stop 吞通信错误。

### 24.4 计数重命名

1. **推荐：** `drop_udp_frag` → `drop_selected_fragment`，随 ABI bump。破坏读取旧 JSON 字段的外部脚本。
2. 保留旧 JSON 键名作别名一个版本。代价：两份真相。

### 24.5 发行冻结

1. **推荐：** 开发仍 `*`；发行用 freeze 清单；Actions 钉到 SHA。
2. 开始提交仓库根 `Cargo.lock`。代价：改变“跟踪 latest”的日常语义。
3. 保持今日 release 跟 latest。代价：不可历史重建。

### 24.6 畸形包更严

1. **推荐：** 按 I8。对普通 socket 无感；对 raw 注入可能从“误捕获”变为 Direct/drop。
2. 不改解析。代价：B01/B02 留下。

ABI bump 本身对已装模块是不兼容加载（magic 检查失败）。rc.3 以模块升级分发，不做热补丁加载旧对象。

---

## 25. 实施批次

原则：一批一个主要不变量；每批改合同、代码、测试、指南；宿主门禁绿；Android/BPF 批另跑 5.15 加载。不把 rc.3 做成单笔巨型提交。

正式 1.0.0 仍在 rc.3 **之后**：远端 CI、候选 ZIP §20、Phase 7、三管理器。rc.3 版本号在核心不变量落地且本机/设备门禁记下后再改 workspace。不要在第一批就把版本改成 rc.3 却未交付 I3。

### 批 0：合同与反例（无行为承诺）

- 改写蓝图 §10.5、§6.4 分层、§7.2/7.3/7.5 解析草案、failures hint 草案。
- 把四条第三态模型写成 `flux-core` 测试（对“理想 commit”为绿，对“今日顺序”为红的文档化对照）。
- 不改生产路径。

退出：doc-check 绿；读者不再被 §10.5 告知窗口安全。

### 批 1：TrustedSnapshot + 开关/Watch 类型（I5、I9、R02、R04、R06）

- RawMessage 保留 flags；dump 完整性格；`disabled()` 三态；WatchSet 最小可用（父目录+重建）。
- 删除路径拒绝 IncompleteDump。

退出：协议层测试覆盖 DONE 负、INTR、截断；EIO 开关测试；目录替换测试（可在 Linux 主机）。

### 批 2：diag/dump 有界等待（I6、R03、R08 的 diag 部分）

- ProbeReady 状态机或 epoch worker。
- 控制请求在半 dump 时仍能 disable。

退出：注入半 dump 的集成测试；disable 不被卡住的 recv 无限挡住。

### 批 3：PolicyEpoch + ABI bump + 预留 leaf（I3、I4、R01、R05、R07）

- 双 bank BPF；magic `0xF10C0905`；Phase 4 map 表；5.15 `load_embedded`。
- `publish_inactive` 无 MAP_CREATE。
- 改 `apply_policy` 为 prepare/commit。

退出：第三态反例在真实 map 顺序上为绿；容量峰值；leaf 创建失败注入；SM-S9180 Phase 4–6。

回退：magic 不兼容，失败即不加载，不部分提交 ABI。

### 批 4：Planner 驱动（I1、A01、A08）

已落地 2026-09-17。

- `step` 产出 Commands；reactor 执行；删除平行 converge 决策。
- 生命周期测试从“调用内部顺序”迁到 Planner 接口 + 少量 executor 集成。

退出：§26 表由 Commands 覆盖；`note_stimulus` 空壳删除；capture-side drift 仍不得 `PublishInactive`。

### 批 5：EngineSpec、CLI、订阅预算、typed map、R16（R08 余、R09–R12、R16）

已落地 2026-09-17。

- `spawn_check` 与 `run` 共用 `EngineSpec.workdir`。
- CLI：`stop` 锁持有时通信失败非零；enable/disable 看文件操作，未收敛只 warning。
- 订阅批次 60s + 总正文 8 MiB；4xx/过大不重试；过期 epoch 丢弃。
- `MapPod` + spec 尺寸核对；`Ipv4Cidr`/`Ipv6Cidr`/`AppSelector` 字段私有。
- stdout 读取次数与 rtnetlink drain 有预算。

退出：相对资源 check==run；CLI 用例；订阅 deadline；错误尺寸写不进安全接口。

### 批 6：解析 l3_end、fragment 名、change_type、畸形语料（I8、B01–B04）

已落地 2026-09-17（宿主语料与对象；5.15 四 entry / Phase 6 设备重跑仍需 GOV-1.2）。

- `parse_pkt`：L4 与扩展头同时 ≤ `l3_end` 与 `data_end`。
- IPv6 fragment 要求完整 8 字节头；I1b 快路径同样。
- `FLUX_CNT_DROP_SELECTED_FRAGMENT` / JSON `drop_selected_fragment`。
- `bpf_skb_change_type` 失败则计数并 `TC_ACT_SHOT`。

退出：语料表；5.15 四 entry；Phase 6 不回归。

### 批 7：发布冻结与诊断 canary（I7、R13–R15）

已落地：`cargo xtask freeze` → `dist/freeze/`；`release` 只消费该清单；CI/`release.yml` 共用 `verify.yml`；Actions 钉 SHA；bugreport canary 与排他 `-o`。

退出：release 工作流调用完整验证；freeze 清单；canary ZIP。

### 批 8：测量驱动的性能（可选）

只在 1–7 稳定后。每个优化 PR：基线、假设、方法、收益、回归、为何不采用更复杂方案。

### 批次依赖

```text
0 → 1 → 2
0 → 3 → 4
3 → 6（ABI 已 bump 则可同批改计数名；也可 3 只加 bank，6 再改解析）
4 → 5
1,2,3,4,5,6 → 7 → （可选）8
```

批 3 与批 4 不要合成一次提交：一个是数据面提交协议，一个是用户态真相组织。

---

## 26. 文档与代码同步清单

实施某批时至少改：

| 文件 | 内容 |
|---|---|
| `spec/blueprint.md` | §5 模块树、§6.4 分层、§7.2–7.5 解析与 I1b、§8 dump、§10.5 策略、§12 map 表、§13 冻结、§14.1 E1、§15 验证、§26 与 Planner 的关系 |
| `spec/failures.md` | 新错误类、fragment 字段、hint |
| `spec/interaction.md` | CLI 退出码、开关 Unreadable、status 字段 |
| `history/review-log.md` | 只增：合同推翻与设备证据 |
| `guide/architecture.md`、`guide/dev-setup.md` | 投影：Planner、冻结、设备门 |
| `plan/implementation.md` | §17.0 进度；做完的批次移出计划 |
| `CHANGELOG.md` | 用户可见：原子策略、退出码、计数名、更严畸形解析 |
| `AGENTS.md` | 仅当出现代码里看不出的新宿主坑 |

不维护译本。合同继续英文。

---

## 27. 完成定义

称“rc.3 核心足够严谨”至少：

- 本文 R0/R1 已修复，或用明确证据/合同修订关闭（选项 24.1.2 这类必须是所有者书面选择，不能是实现者默许）；
- 同一提交的生产 BPF 经真实 loader 与目标 5.15 设备验证（含双 bank 与解析收紧）；
- 关键事件尾延迟有预算和至少一轮测量，不只是体感；
- 错误不伪装成成功、未选、空集合或零计数；
- 第三态反例成为仓库回归；
- `step` 的 Commands 被执行，或文档不再声称 reactor 是其适配器；
- 发布输入与产物可追踪；“最新构建”与“历史重建”含义清楚；
- 每条 I1–I10 至少对应一个正常测试和一个失败/竞态测试；
- 文档不再用 §10.5 旧窗口理论指导实现。

**不是**完成标准：文件短、处处抽象、测试数量大、无 unwrap、引入流行框架、一次 speed test 很快、把版本号改成 1.0.0。

正式 1.0.0 另需：远端 CI 绿、候选 ZIP 的 §20、Phase 7、三管理器 smoke。rc.3 不宣称这些已完成。

---

## 28. PHIL-10 自检

1. **内部不变量是否放到外部？** 解析严格性、bank、leaf 池、dump 完整性均不暴露为用户开关。
2. **守卫数量？** 用类型消灭第三态和 Incomplete dump，而不是在 `apply_policy` 再加布尔。
3. **无效状态不可构造？** `TrustedSnapshot`、`PolicyEpoch`、CIDR 私有字段、`Unreadable`。
4. **周期唤醒？** 无新增健康探测；订阅 interval 仍是用户配置的动作。
5. **几处可写？** 世代仍只 `Generations`；策略可见性只在 control root 提交；开关只 C9 文件。
6. **删除靠身份？** 只对 TrustedSnapshot 做所有权删除。
7. **硬失败是否不可诊断？** inactive 发布失败必须可见；开关不可读必须可见。
8. **参考实现取的是原则还是 workaround？** 不引入 inotify 轮询、不写全局 rp_filter、不引入 libbpf。

---

## 29. 审计乙未完成阶段的覆盖账本

审计乙要求按承重合同分阶段关闭。本文对应关系：

| 乙的阶段 | 本文 | 状态 |
|---|---|---|
| 阶段一 基线与顶层 | §1–3、§6–7 | 已对照 `a0a41bc` 复核并采纳 |
| 阶段二 A 解析/分片 | §14.1–14.3、§20.4 | 已采纳并指定语料 |
| 阶段二 B loader/ABI/map/handoff | §8–9、§14.4–14.8、§15 | 本文补完 |
| 阶段三 reactor/planner/engine/停止 | §7、§11、§13、§9 | 本文补完 |
| 阶段四 netlink/拓扑/TC | §10、§11、attachment 保持 rc.2 模块 | 本文补完 |
| 阶段五 配置/订阅/诊断/CLI | §12、§16–18 | 本文补完 |
| 阶段六 xtask/CI/性能/测试 | §19–21 | 本文补完 |
| 阶段七 综合路线 | §24–27 | 本文即该阶段交付 |

---

## 30. 立即不要做、可以做

在批 0/1 落地前：

1. 不要在现有 `Reactor` 上堆新事件源、新布尔、新恢复分支；
2. 不要给原地 `apply_policy` 打更多顺序补丁；
3. 不要把 `runtime::step` 单测通过当成 reactor 已证明；
4. 不要宣称当前 release 可历史复现；
5. 不要发布正式 `1.0.0`。

可以做：把本文批 0 的合同草案与反例测试写进仓库；固定候选冻结清单的 xtask 形状；修复不改变架构选择的局部错误（例如文档笔误）。

---

**本文是 rc.3 的实施合同草案。** 批 0 把其中规范性句子迁入 `spec/` 之前，实现者以本文为准；迁入之后，冲突则代码错（AUTH-0）。
