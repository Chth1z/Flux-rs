# 旧仓库过渡记录

> 本文是蓝图 **§18**，2026-08-30 从 `../spec/blueprint.md` 移入记录层。编号跟着内容走，仍是 §18，引用它的地方不必改。
>
> 移出的理由：它记的是一次**已经发生并且禁止重演**的迁移，而 `spec/` 的判据是"文档与代码不一致时，代码错"。这一条对已执行的历史不成立——它谁也不约束，只解释现有代码为什么长这样。

---

# 第 18 部分：从旧仓库过渡

> **本部分已执行完毕，现在是记录而不是计划。不要照着它再做一遍。**
>
> 重建发生在 2026-08-25，首个提交是 `fe77bc7 feat: Flux-rs 0.9.0 design contract and workspace skeleton`，45 个文件的干净树。当前工作树里**没有** `audit/`、`archive/`、`crates/flux-platform`、`crates/flux-testkit`——它们不是"待删除"，是已经不在了。
>
> **归档材料不在本工作树内。** §18.1 第 1 步列出的目录（`audit/**`、`archive/2026-08-25-superseded/`）在重建时没有被带进新树，也从未被 git 跟踪，因此 `git log` 里查不到。下面那句"该目录被 `.gitignore` 排除"**也是错的**：现在的 `.gitignore` 只有 `/clone/` 一条。
>
> 这对实现者的实际影响：**任何追溯到归档文档的引用都无法在本仓库内解析。** 但结论本身没有丢——它们已经被折叠进 `../history/phase0.md`、`../history/review-log.md` 与本文，而且 Q1 / Q2 / Q6 / Q9 / Q10 后来都在同一台设备上**重新一手实测过**（§16.5–16.10），所以那些旧的一次性证据现在只有历史价值。唯一确实无法核验的是 `../history/review-log.md` §0.5 开头引用的 `sm-s9180-sock-addr-occupancy-2026-08.md`——而那条引用恰好是**被推翻的那一条**，推翻依据是 §16.2 的一手复测，所以结论站在当前证据上，不依赖那份归档。
>
> 保留 §18.1–18.4 的原文，是因为它记录了**为什么这么迁移**以及移植清单，那些理由在读现有代码时仍然有用。

## 18.1 我的建议（与旧蓝图不同）

**所有者已决定：删除工作树与 `.git`，重新 `git init`**（D13）。因为历史将不可恢复，归档是**强制前置步骤**，不是建议。

两次确认门（清理不可逆，必须拆成两次授权）：

1. **确认本蓝图并授权 Phase 0**：只在临时目录验证 seam，**不删除任何东西**。
2. **Phase 0 全部通过后，第二次显式确认**：才执行下面的归档与清库。

第二次确认后的执行顺序：

0. **先匿名化再归档。** 逐行审计（F-07）发现 `docs/research/sm-s9180-dualstack-soak-evidence-2026-08.md:15` 提交了**真实设备序列号**，违反当时 `docs/development.md:135-136` 自己的规定。文档治理阶段（2026-08-25）已把该文件移入 `archive/2026-08-25-superseded/`，但**内容未修改**。删库重建是彻底消除它的唯一机会：复制到仓库外之前，必须把序列号 / IMEI / Android-ID 替换成稳定匿名 ID（例如 `DEV-A`），映射表另存于归档目录之外。新仓库的 CI 必须加一条 grep 检查拒绝此类标识再次进入。**注意 `git bundle` 会完整保留旧历史里的原值**，所以 bundle 属于私有归档，不得公开分发。
1. **归档（必须完成并校验后才允许删除任何文件）**：把以下内容复制到仓库外目录（建议同级 `Flux-rs-design-archive-2026-08-25/`）并生成 SHA-256 manifest：
   - 本目录 `audit/2026-08-25-flux-rs-0.9.0-final/` 全部文件；
   - `audit/2026-08-24-final-ebpf-blueprint/`（含 `primary-source-research.md`、`source-manifest.md`）；
   - `audit/2026-08-25-flux-rs-0.9.0-impl-blueprint/`；
   - `audit/2026-08-24-full-repository-line-audit/`、`audit/2026-08-24-design-and-code-audit/`；
   - `archive/2026-08-25-superseded/`（2026-08-25 文档治理已把旧 `docs/**`、`CONTEXT.md`、`README*`、`CHANGELOG.md`、`notes.md`、`task_plan.md` 全部移入，含**不可复现的真机证据**；该目录被 `.gitignore` 排除，因此不在 git 里，必须显式复制）；
   - **`audit/2026-08-25-flux-rs-0.9.0-final/`（本设计包本身）。这是本清单里最容易致命的一条**：`.gitignore:27` 的 `/audit/` 规则意味着**本蓝图、`bpf/include/flux_abi.h`、`bpf/flux.bpf.c` 全都不在 git 里**，因此 `git bundle --all` **不会**包含它们。一旦先删工作树再想起来，唯一的设计合同就永久丢失，`git reflog` 也救不回来——它从未被 git 跟踪过。**执行第 3 步之前，必须先把这个目录复制到仓库之外并核对 SHA-256。**
   - **§18.3 列出的、计划移植的全部源文件**（因为 `git init` 之后再也 `git show` 不到它们）；
   - 一份 `git bundle create ../Flux-rs-legacy.bundle --all`（**强烈建议**：一个文件，离线可读，是"删历史"与"能查证"的唯一交集）。
     > **`--all` 不包含 stash。** 本仓库现有 **18 个 stash**，其中只有 `stash@{0}` 是真 ref（`refs/stash`），`stash@{1..17}` 存在于 `refs/stash` 的 **reflog** 里，而 bundle **不携带 reflog**。要保留就必须先把每个 stash 变成真 ref：`git tag archive/stash-<N> stash@{<N>}`（逐个），再 bundle。否则 17 个 stash 静默消失。
   - **确认没有其它工作树引用本 `.git`。** 现有两个位于 `C:/Users/Chth1z/.grok/worktrees/github-flux-rs/` 的 detached-HEAD 工作树（子代理遗留）会在删除 `.git` 后损坏；先 `git worktree list` 核对再 `git worktree remove`（或确认可弃）。
2. 逐项核对 manifest 的 SHA-256 与文件数量。
3. 删除工作树内容与 `.git`，`git init`，按 §5 骨架从空目录新建，首个提交为 `chore: Flux-rs 0.9.0 initial import`。
4. 远端 force-push、删仓或改 GitHub repository 设置**另行单独授权**；本蓝图只规划本地重建。

## 18.2 清理矩阵

| 当前内容 | 动作 |
|---|---|
| `audit/**`、`archive/**` | 先归档到仓库外，再从产品库删除 |
| 旧 `README`/`README_zh`/`CONTEXT.md`/18 个 ADR/`docs/**`/`notes.md`/`task_plan.md` | **2026-08-25 已归档至 `archive/2026-08-25-superseded/`**（见该目录 `MANIFEST.md` 的取代关系表）；产品树只按 §5 重写 `README.md`、`CHANGELOG.md`、`docs/guide/architecture.md` |
| `crates/flux-platform`、`crates/flux-testkit` | 删除（部分文件按 §18.3 移植） |
| `crates/flux-core`、`crates/fluxd` | 清空后按 §5 重建（部分文件按 §18.3 移植） |
| 旧 BPF C 与已提交 `.o`（`flx_sock_addr.c`、`connect4_token.c`、`trial_prog.c`、token/cookie/proof/canary） | 删除，重写单一 `bpf/flux.bpf.c` |
| `engine/sing-box/manifest.toml`、`xtask/src/sing_box_producer.rs`、任何 patch | 删除；只从 `engine.lock` 取官方 asset |
| `META-INF/`、`webroot/`、`conf/`、`flux_service.sh`、`customize.sh`、`uninstall.sh` | 删除；从 §13.1 的 allowlist 重建 |
| `tests/shell/**`、`xtask` 的资格/canary/preflight 子命令 | 删除 |
| 旧版本号/schema/protocol/manifest 数字（module `v0.1.0-dev`、config schema 5、control protocol v9、capability schema 3、package manifest schema 4） | 删除；只保留 `0.9.0` 与 `FLUX_ABI_MAGIC` |
| `clone/`（第三方研究源码） | **保留为开发辅助资产**（2026-08-25 所有者决定，改变了原先"直接删除"的处置）。设计里几乎每一条关于 AOSP、内核和同类实现的断言，依据都在这里。**但第三方源码不进 git**：进 git 的是 `tools/clone-manifest.md`（仓库 + 固定 commit）与 `tools/reclone.sh`，二者能完整重建，同时避免仓库膨胀（约 80 MB）、许可证与来源混杂、以及"新代码抄了旧第三方实现"的嫌疑。`clone/` 由 `.gitignore` 排除 |
| `target/`、缓存、临时下载 | 删除，由 `.gitignore` + clean staging 隔离 |

执行原则是"清空后按 allowlist 新建"，不是逐文件修补。

## 18.3 应当移植（而非重写）的低层原语

审计发现的缺陷集中在策略/generation/抽象层，不在这些机械正确的原语。**移植时必须逐行复审并去掉对旧类型的依赖**，但不要从零重写。

### 18.3.0 规模现实：可移植的是个位数百分比

2026-08-25 对现有树做了逐 crate 实测（`Measure-Object -Line` 全量 `*.rs` + 逐文件读）：

| 类别 | 行数 | 占比 |
|---|---:|---:|
| Rust 总量（含测试与 xtask） | ~144,600 | 100% |
| **明确属于旧架构、必须删除** | ~64,400 | 44.5% |
| 旧架构的测试 | ~15,700 | 10.9% |
| 乐观口径的"可移植文件"（整文件计） | ~26,000 | 17.9% |
| **剥掉纠缠部分后真正能落地的** | **~8,000–12,000** | **~6–8%** |

**有效可移植 : 待删除 ≈ 1 : 8。** 这不是在评价旧代码的质量——它是**另一个系统**的成熟实现（cgroup SOCK_ADDR + token 地址 + RPDB/nftables 调和 + 资格 oracle）。

### 18.3.1 决定性事实：0.9.0 的数据面在现有树里**完全不存在**

对现有 `crates/` 与 `xtask/` 全树 grep，以下符号**零命中**：

`bpf_sk_assign` · `SCHED_CLS` · `bpf_redirect` · `RTM_NEWQDISC` · `RTM_NEWTFILTER` · `TCA_KIND` · `TCA_BPF` · `clsact` · `sk_storage` / `SK_STORAGE` · `BPF_MAP_TYPE_RINGBUF` · `btf_fd` · `BPF_BTF_LOAD` · `timerfd` · `IFLA_INFO_DATA` · `VETH_INFO_PEER`

`veth` 一词只在 `canary_facility_policy.rs` 与 `android_platform_profile_catalog.rs`（都属删除清单）里作为**名字字符串**出现；`IFLA_INFO_KIND` 只出现在**解码**路径。**因此没有任何 veth 创建代码。**

**必须从零写的清单**（无任何可移植前身）：三个 BPF 程序与全部 map、手写 BTF blob 与带 `btf_fd` 的 prog load、TC qdisc/filter 的 netlink 消息（§8.9.4–8.9.5）、veth pair 创建（`RTM_NEWLINK` + `IFLA_LINKINFO`/`IFLA_INFO_DATA`/`VETH_INFO_PEER`，§8.9.1）、ringbuf 消费者、reactor 的 timerfd 源。

### 18.3.2 移植清单（已按实测修订）

| 来源 | 行数 | 用途 | 纠缠度 | 移植去向 |
|---|---:|---|---|---|
| `flux-platform/src/bpf/sys.rs` | 661 | 裸 `bpf(2)`：prog load / map CRUD / pin / obj info / query，含 EINTR 重试与 deadline | **低**（自足） | `fluxd/src/bpf/sys.rs`。**必须扩展**：`btf_fd`、`BPF_BTF_LOAD`、TC attach |
| `flux-platform/src/seqpacket.rs` | 2,476 | `SOCK_SEQPACKET` + `SO_PEERCRED` + `SCM_CREDENTIALS` + 路径/inode 校验 | **低** | `fluxd/src/control.rs` |
| `flux-platform/src/netlink.rs` | 412 | netlink 头/属性迭代、`NLMSG_DONE`/`NLMSG_ERROR` | **低** | `fluxd/src/netlink/mod.rs` |
| `flux-platform/src/netlink/socket.rs` | 1,458 | `AF_NETLINK` socket、多播组、dump 时序、批量 recv | **中** | `fluxd/src/netlink/socket.rs` |
| `flux-platform/src/netlink/policy_routing.rs` | 1,639 | **唯一存在的 netlink 变更构造器**：`RTM_NEWROUTE`/`NEWRULE` 及其删除、`mutation_flags` | **中**（只取构造/应答处理，弃 RPDB 语义） | `fluxd/src/netlink/route.rs`——0.9.0 只需一条 rule + 一条 local 路由（§8.3） |
| `flux-platform/src/netlink/{link,route,rule}.rs` | 600 / 1,212 / 1,175 | 消息**解码**（admission、冲突检测、本机地址 bypass 都要用） | **中**（依赖 flux-core 域类型） | `fluxd/src/netlink/*` |
| `flux-platform/src/socket_diagnostics{,/implementation}.rs` | 2,414 | `NETLINK_SOCK_DIAG` 枚举、listener 冲突定位 | **中**（自足，测试重） | `fluxd/src/engine.rs`（§9.3 就绪核验） |
| `flux-platform/src/{process,child_process}.rs` | 2,182 / 718 | pidfd、fdinfo/procfs、fork/exec、`PR_SET_PDEATHSIG`、关 fd、capability set | **低–中** | `fluxd/src/engine.rs` |
| `flux-platform/src/shutdown.rs` | 186 | signalfd + `pthread_sigmask` | **低** | `fluxd/src/reactor.rs` |
| `flux-platform/src/file_observer.rs` | 862 | `inotify_init1`、watch 增删、事件解析 | **中**（`FileObservationPaths` 写死了旧文件名） | `fluxd/src/reactor.rs` |
| `flux-core/src/packages_list.rs` + `flux-platform/src/bpf/packages.rs` | 116 + 40 | `packages.list` 解析、`ANDROID_PER_USER_RANGE = 100_000` | **低** | `flux-core/src/selector.rs` |
| `flux-core/src/network_inventory.rs` | 739 | link/addr 快照域模型（interface admission + 本机地址 bypass） | **中** | `flux-core/src/inventory.rs` |
| `flux-core/src/capture_program.rs` | 671 | `CaptureIpPrefix`、canonicalize、强制 bypass 前缀（**只取 ~300–400 行**） | **中** | `flux-core/src/cidr.rs` |
| `flux-platform/src/android_kernel_capabilities.rs` | 985 | `/proc/config.gz` 解析与 CONFIG 名常量（`NET_SCH_INGRESS`/`NET_CLS_BPF`/`DEBUG_INFO_BTF`…） | **中**（弃 nftables 门禁） | `fluxd/src/probe.rs` |
| `flux-platform/src/android_identity{,_properties}.rs` | 781 + 206 | getprop/procfs 设备指纹 | **低** | `fluxd/src/status.rs` |
| `xtask/src/main.rs` 的 staging / `verify-package` / ELF 检查 / zip；`android_profile.rs` 的 NDK 与 linker 命名 | ~1,200 | 可复现打包与 aarch64 交叉编译 | **低** | `xtask/src/main.rs` |

**只当参考实现、不要整体搬**（读它们学做法，代码重写）：

- `reactor.rs`（1,166）——**不是**通用 epoll 循环，它直接绑死 `NetworkInventorySource` / `RouteNetworkInventoryDriver` / `FileObserverDriver`，且缺 timerfd 与 ringbuf 源。
- `sing_box.rs`（2,315）——内含 `POLL_INTERVAL = 10ms` **轮询**就绪，与 §10.1"无周期轮询"直接冲突。就绪判定必须改成 SOCK_DIAG + pidfd 事件驱动（§9.3）。
- `control.rs`（722）——后台线程 + mpsc 派发，与单线程 reactor 冲突。
- `bpf/sock_addr_object.rs`（354）——真实的最小 ELF 解析，但**写死了 11 个 cgroup 程序与 token map**，只有约 150 行是通用的。
- `network_observer/driver.rs`（3,233）——旧版蓝图曾把它列为"直接就是 §10.4 需要的 inventory 引擎"，**这条已撤销**：它是 generation 作用域的调和用 observer，与 §10.4.1 的三条硬规则（全量重 dump、debounce、ifindex 一致性）不同构。

**明确不得移植**：`capture_path*`、`intercept_policy`、`android_mark_authority`、`android_rpdb`、`android_tproxy_topology`、`rpdb_placement`、`address_bypass`、`fwmark_*`、`planning_residual/*`、`android_platform_profile_catalog`、`canary_facility_policy`、`statistics`、`config`、`generation_engine_config/*`、`runtime_coordinator/*`、`native_*`、`subscription/*`、`protocol`、`clash_control`、`inspection`、`offline_cleanup`（其中只有约 80 行 `flock` 租约值得看一眼）、`address_sync`、`netlink/policy_routing_session`、`bpf/{sock_addr*,token_map,occupancy,proof,throwaway,capture_journal,intercept,vpn_proc}`。这些是旧架构的产物，或被审计判为缺陷源。

### 18.3.3 顺带保住的低成本资产

| 资产 | 位置 | 为什么值钱 |
|---|---|---|
| 模块脚本 | `customize.sh`、`flux_service.sh`、`uninstall.sh`、`module.prop` | 安装模式判定与 `/data/adb/flux` 载荷布局已经调通；按 §13.2.0 补三管理器差异即可 |
| CI workflow | `.github/workflows/ci.yml` | Rust 1.93.0 + NDK r27d + `cargo deny` + shell 语法检查的组合 |
| `deny.toml` | 仓库根 | 许可证/公告策略（GPL-3.0-only） |
| `rust-toolchain.toml`、`.cargo/config.toml` | 仓库根 | 工具链固定 + `aarch64-linux-android` 目标与 linker 配置 |
| NDK 版本钉 | `xtask/src/{main,android_profile}.rs` | NDK **27.3.13750724**、API 31 的 linker 命名规则 |
| GKI CONFIG 清单 | `android_kernel_capabilities.rs` | 与 §4 的 defconfig 表互为交叉验证 |

**仓库内没有任何 `.te` / SELinux 策略文件**，§12.8 若最终需要 `sepolicy.rule` 属于新增。

## 18.4 旧审计发现的关闭方式

三份审计（`2026-08-24-full-repository-line-audit`、`2026-08-24-design-and-code-audit`、`2026-08-11-overdesign-review`）的全部结论在新设计里的归宿。**"架构性关闭"意味着该缺陷所依附的机制在 0.9.0 不存在，不是"以后再修"。**

| 旧问题族 | 代表 ID | 关闭方式 |
|---|---|---|
| `fluxd` 不编译（缺 import） | F-01 | 架构性关闭：相关模块整体删除；CI 的 `cargo build --target` 是硬门禁 |
| Generation → Capture seam 丢失完整 Intercept Policy，family/protocol 被静默放大 | F-02、设计 P1 #6 | 架构性关闭：不再有"策略编译 → 写入器重建策略"两段式。策略就是 `uid_policy` + 两张 LPM，由同一次收敛直接写入 |
| promote journal 在 restore 失败时仍删除记录 | F-03 | 架构性关闭：无 journal、无 promote。对象由 level-triggered 收敛管理（§10.5） |
| UDP Proof 用 token map 反查冒充 orig-dst cmsg | F-04 | 架构性关闭：删除 token 路径；原目的由真实 header + 官方 engine 的 `IP(V6)_RECVORIGDSTADDR` 提供，Phase 0 Q4 直接读 engine 侧的值 |
| rollback 错误被吞、状态谎报 `attached=false` | F-05 | 规则化关闭：§15.4(1) 状态报告诚实性 |
| sing-box ELF 16 KiB 门禁被特判弱化成 4 KiB | F-06 | 架构性关闭：`engine.lock` 要求四个 `PT_LOAD` **精确等于** `0x1000`，并把 4 KiB 写成产品边界；`fluxd` 自身单独要求 ≥ 16 KiB（§9.7、§13.4） |
| 真机序列号进仓库 | F-07 | §18.1 第 0 步匿名化 + 新仓库 CI grep 检查 |
| Proof 与活跃 engine 共享 socket queue | F-08 | 架构性关闭：无 production Proof daemon、不复制 engine 的 fd。readiness 用 SOCK_DIAG 只读枚举（§9.5） |
| CI 调用已删除的 xtask 命令、文档列退役命令 | F-09、F-13 | 规则化关闭：§15.4(3) 命令一致性自检 |
| fmt/clippy 红、ABI 测试断言 C 源字符串 | F-10 | 规则化关闭：§15.4(2)；`cargo xtask ci` 是硬门禁 |
| Clash / Generation 互斥只实现单向 | F-11 | 架构性关闭：0.9.0 无 Clash 控制面（§1.3） |
| 真机资格证据未闭环 | F-12 | §16 Phase 0 + §20 发布验收；证据字段从 catalog 改为一次性 smoke 记录 |
| 迁移残留 + 单次巨型提交 | F-14 | §17 分阶段交付，每阶段可 build；§18.2 清理矩阵按 allowlist 重建 |
| 设计语料同时规定三种互不兼容的 attach 策略；ADR YAML/正文互相矛盾；README 停留在旧协议与已删命令 | 设计 P0 #1–#4、P1 #20 | 规则化关闭：§15.4(4) 单一权威文档，无 ADR 目录 |
| 双 Capture 外部接口（`Capture` vs `NativeCaptureConvergence`） | 设计 P1 #5 | 架构性关闭：不为单一实现创建 trait（§5） |
| Capture Path 选择器骨架、`CapturePathId::ALL`、租约、digest、wire 残留 | 设计 P1 #7–#8、过度设计 P1 #5 | 架构性关闭：只有一条数据路径，代码里没有"路径"这个概念 |
| ~12k 行 fwmark / TPROXY topology / canary facility / Passed catalog 仍在 `flux-core` 公开 API | 设计 P1 #9–#10 | 架构性关闭：不写 fwmark、不做 topology 规划、无 catalog（§3.1、§8.3） |
| `forwarded_ingress` / `forwarded_proxy` 等已删配置键仍在类型与 digest 里 | 设计 P1 #11 | 架构性关闭：`flux.toml` 只有 `apps` 与 `bypass_cidrs`（§11.2） |
| Geek IPv4-only TCP 切片是第二条写入路径 | 设计 P1 #12 | 架构性关闭：一个数据面、两个 entry（按 L2/L3 布局，不按协议族分叉） |
| god object（coordinator / engine_supervisor / generation_source 各数千行） | 设计 P1 #13、过度设计 P0 #1 | 架构性关闭：§5 的模块划分 + §10.5 的幂等收敛取代事务编排 |
| `cidr4`/`cidr6` map 创建但未 pin | 设计 P1 #13b | 架构性关闭：不 pin 任何 map（§6.1） |
| VPN RPDB singleton 确认是空实现 | 设计 P1 #13d | 架构性关闭：VPN 处理改为"排除全部 TUN + 选中 VPN app 时告警"（§3.5、§11.3） |
| 生产 crate 里残留 TPROXY 双 inbound 编译器 / SO_MARK credential probe | 设计 P1 #13e–f、#19 | 架构性关闭：只注入两个 tproxy inbound，无 mark、无 credential probe（§9.1、§9.3） |
| ~30k–49k 行 `functional_canary` 靠 `cfg(test)` 留在树里 | 设计 P1 #14、过度设计 P0 #1 | 架构性关闭：无 canary 概念；验证靠 Phase 0 一次性 spike + §15.2 的八个逻辑测试 |
| `engine/sing-box/manifest.toml` 仍构建 patch 0002 | 设计 P1 #15 | 架构性关闭：`engine.lock` 只接受官方 asset digest，零 patch（§9.7） |
| xtask 暴露 xtables 时代资格命令、四个 Android runner 重复 session 逻辑 | 设计 P1 #16、过度设计 P1 #7 | 架构性关闭：xtask 只做 build/package/release（§13.4） |
| `statistics.rs` + `traffic_observation.rs` ~2.6k 行无消费者 | 设计 P1 #17、过度设计 §9 | 架构性关闭：换成 18 个事件级 per-CPU counter，唯一消费者是 `fluxd status`（§6.1、D12） |
| canary 状态在 6+ 个类型里重复投影、三重 deadline 检查、trust 分层无威胁表 | 过度设计 P0 #2、P1 #6、§10 | 架构性关闭：只有三个顶层状态（§10.1）、一处 admission 判定（§8.7）、一份威胁边界声明（§1.5） |
| daemon 里写裸 rtnetlink（错误 seam） | 过度设计 P0 #3 | 规则化关闭：§5 的 netlink/bpf 模块边界要求 |
| 24+ 无人居住的脚手架、先铺横向权限再做纵向闭环 | 过度设计 P0 #4 | 规则化关闭：§17"每阶段保持可 build，不为下一阶段预建抽象" |

审计里被判为"**不是缺陷**"的两项也保留：默认打包配置只读（pre-release 边界，非缺陷）；Clash 的同 UID 控制 socket 边界设计正确——后者在 0.9.0 因删除 Clash 而不适用。

