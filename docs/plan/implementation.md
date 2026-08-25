# 第 17 部分：实施阶段

> 原 `blueprint.md` 第 17 部分。**章节编号未变**：本文里的 §17.x 就是全仓库引用的那个 §17.x（见 `docs/authoring.md` §1.1）。
>
> 谁读这份：要动手写代码的人（或模型），从头到尾按顺序读。规范性合同是 `docs/blueprint.md`；本文只管**顺序、边界与验收**，不重复讲机制。

---

## 17.1 这份计划的读法

**每个阶段的退出条件都必须由该阶段自己满足。** 这不是废话——旧版 §17 的阶段 0 写着"退出条件：§16 全部关键 seam 通过"，而 §16 里的 Q5 / Q7 / Q8 只能由阶段 5–7 产出的代码来测。那是个循环依赖，照着做会在第一天就卡住。§17.2 是它的修复。

**九条对每个阶段都成立的规则：**

1. **阶段结束时仓库必须可 build、`cargo test --workspace` 全绿、CI 全绿。** 不允许"下个阶段再修"的破窗。
2. **不为下一阶段预建抽象。** 这条是旧审计"24+ 无人居住的脚手架"（`blueprint.md` §18.4）的规则化闭环。需要一个 trait 时再抽，不要提前。
3. **发现真实回归时，只为该不变量加一个聚焦测试**，不要顺手补一套。测试数量不是质量指标。
4. **实测结果与蓝图冲突时**：按 `governance.md` §3 的更正协议处理——把"原说法 / 实际 / 处置"写进 `evidence/review-log.md`，改掉蓝图，**不得静默偏离**。代码与文档不一致时，先改文档再改代码。
5. **遇到 `governance.md` §1.2 列出的决策**（改全局系统语义、产品能力边界变化、引入新依赖、放宽失败语义）：**停下，问所有者**，不要自行决定。
6. **改 ABI 走 `governance.md` §4.2**：`flux_abi.h` 是唯一真相源，`crates/flux-core/src/abi.rs` 是手工镜像，`FLUX_ABI_MAGIC` 必须 bump，`xtask abi-check` 必须通过。
7. **设备测试遵守 `governance.md` §2.3**：每个改设备状态的脚本都要有覆盖全部退出路径的 cleanup，并在结束时打印残留检查。
8. **`blueprint.md` §19 与 `decisions/rejected-and-deferred.md` 里被拒绝的方案不得复活。** 卡住时正确的动作是问，不是去拿一个已被逐条否决的办法。每个阶段的"禁止"小节列的就是该阶段最容易复活的那几条。
9. **禁止把失败掩盖过去。** `governance.md` §5 点名的五种掩盖手段（token map、patch sing-box、加第二后端、加 heartbeat、放宽 fail-closed）在任何阶段都不允许。

**关于"外推范围"**：所有实测结论都来自**一台** SM-S9180 / 5.15.211。`verification/phase0.md` §16.3 给了五层分类（AOSP 强制 / GKI / SoC 厂商 / OEM / 运行期）。把 OEM 层的观察当普适事实是这个项目最容易犯的错，写代码时尤其如此——**不要把任何单机观测值硬编码**。

---

## 17.2 Phase 0 剩余问题的归属

**已经答完的**（都在 `verification/phase0.md`）：

| 问题 | 结论 | 章节 |
|---|---|---|
| Q1 SK_STORAGE first-decision | ✅ 通过 | §16.6 |
| Q2 listener 身份 / lookup / **assign 成功** | ✅ 通过 | §16.10 |
| Q6 观测半场（`filter INPUT`、egress 基线、sysctl 起点） | ✅ 通过 | §16.9 |
| Q9 per-app DNS（D18 的赌注） | ✅ 通过 | §16.7 |
| Q10 厂商 filter 是否遮挡 | ✅ 通过 | §16.5.4 |
| 产品数据面四个程序过验证器 | ✅ 通过 | §16.8.5 |

**剩下的，以及为什么它们不可能提前做**：

| 问题 | 提前做不了的原因 | 归属 | 在该阶段的具体形式 |
|---|---|---|---|
| **Q8**（对象生命周期半） | 要有 netlink 层才有对象可清 | **阶段 3** | `kill -9 fluxd` 后重启，§8.7 的删除-重建把对象恢复到确定状态；系统 TC/RPDB/VPN 对象逐行 diff 为空 |
| **Q5.1** L2 零改写闭环 | 要有 `bpf_redirect` 与 `flx_in` | **阶段 5** | 不写任何字节即 redirect，配 ingress 的 `bpf_skb_change_type(PACKET_HOST)`，包被 `ip_rcv` 接受。**若失败则 D17 被证伪**，回退到写 dst MAC |
| **Q5.2** L3 补头闭环 | 同上 | **阶段 5** | rmnet 上 `bpf_skb_change_head(14)` + 只写 EtherType 能闭环；headroom 不足时 helper 返回 `-ENOMEM` |
| **Q5.6** sysctl 最小集 | 要有真实包穿过 veth | **阶段 5** | `all.rp_filter` / `flxrs1.accept_local` / `ip_forward` 矩阵。起点值已实测（§16.9.3），**`all.rp_filter` 与 `ip_forward` 开箱都是 0** |
| **Q5.7** 可达性与共存 | 要有 `flx_verify` | **阶段 5** | 存活验证判定我们真的在跑；`TC_ACT_UNSPEC` 之后后续 filter 计数仍在增长 |
| **Q3** TCP 生命周期 | 要有完整数据路径 | **阶段 6** | 握手/重传/FIN/RST/TFO；`accept()` 后 `getsockname()` **逐字节**等于原始目的 |
| **Q4** UDP 原目的 | 同上 | **阶段 6** | 四组（family × connected）`IP_RECVORIGDSTADDR` cmsg 逐字节一致 |
| **Q5.3–5.5** clone / TCP GSO / UDP GSO | 要有真实大流量 | **阶段 6** | 大文件上传触发重传与 GSO；QUIC 客户端触发 `UDP_SEGMENT` |
| **Q6 剩余**（OEM 链是否丢我们的包） | 要有真实捕获流量比对计数增长 | **阶段 6** | 跑一条捕获流量前后各抓一次 `iptables -L -v -n`，逐链比对。**接口维度的隐藏差异已排除**（§16.9.1），剩下的是整体丢弃 |
| **Q8**（流量语义半） | 要有数据面 | **阶段 6** | 残留 TC filter 只造成"新流 direct、已入场流 drop" |
| **Q7** 换代与故障自愈 | 要有 generation 机制 + 数据面 | **阶段 7** | `kill -9` engine 后新连接 100% direct；fault 事件数 O(1) 而非 O(packets) |

**这张表就是每个阶段退出条件的一部分**，不是"有空再跑"的清单。

---

## 17.3 阶段 0 — 实测地基（**已完成**）

**已交付**：`tools/phase0/` 下的 12 个探针与 harness，`verification/phase0.md` 的六节实测记录，`evidence/review-log.md` §0.6 的三条推翻。

**退出条件（已满足）**：能推翻主路线的 seam 全部实测通过——出向（Q10 / Q1 / Q9）与入向（Q2）两半都测掉了，数据面四个程序在基线内核上过验证器。**已知能推翻主路线的技术未知项：无。**

**留给后续阶段复用的资产**（这些是回归工具，不是一次性脚本）：

| 工具 | 回答什么 | 何时重跑 |
|---|---|---|
| `q1-run-device.sh` | SK_STORAGE 首次决策语义 | 改 §7.3 算法后 |
| `q2-run-device.sh` | listener 4 socket / lookup / **assign 成功** | **每次 engine 版本升级**（§9.2 要求） |
| `q9-run-device.sh` | per-app DNS 归属（D18） | 换设备 / 换 Android 版本后 |
| `q10-run.sh` | 厂商 filter 是否遮挡 | 换设备后 |
| `q6-veth-observe.sh` | egress 基线 / OEM 链 / sysctl 起点 / veth 生命周期 | 换设备后，以及阶段 3 的 Q8 |
| `loadall-product.sh` | 数据面过验证器 | **每次改 `flux.bpf.c`**（CI 已自动跑） |
| `secname-*.sh` | 哪些 ELF 段名可加载可挂载 | 改段名时 |
| `btf-inspect.sh` | BTF 前向声明导致的 map 建不出来 | libbpf 报 "can't determine value size" 时 |
| `observe.sh` | 只读设备全景 | 接手新设备第一件事 |

---

## 17.4 阶段 1 — `flux-core` 纯逻辑

**交付物**：`flux-core` 的全部纯逻辑 + 单测；`xtask`（`abi-check`、`package`）；module staging；版本与 engine pin 校验。

**必读**：`blueprint.md` §5（crate 结构）、§6（BPF ABI）、§15.2（必须保留的八个逻辑测试）、`engine.lock`。

**退出条件**：

1. **在 Windows 上** `cargo test -p flux-core` 全绿。这条是硬要求：`flux-core` 不得有任何 I/O 或平台依赖，否则后面所有逻辑就只能在设备上调。
2. §15.2 的八个逻辑测试全部存在且通过。
3. `cargo xtask abi-check` **真正实现并通过**：用 clang 算出 `flux_abi.h` 各结构的偏移，与 `abi.rs` 的镜像逐字段比对。CI 里那行 `continue-on-error: true` 在本阶段结束时**必须删掉**。
4. `cargo xtask package` 连续两次 clean build 产出的 hash 一致（可复现构建）。
5. `xtask` 校验 `engine.lock` 的两个 sha256 与 size；任一不匹配就拒绝打包。**这条已经手工验证过一次**：2026-08-26 下载 v1.13.19 的 asset，archive 与 binary 两个 digest 与 `engine.lock` 逐字相符（§16.10）。`xtask` 要做的是把它自动化。
6. `cargo xtask doc-check` 实现并接入 CI，至少覆盖四项机械检查：`docs/README.md` 的章节映射指向的文件确实存在且真有那个标题；`docs/**` 内部的相对链接可解析；`flux_abi.h` 的 `FLUX_SEC_*` 与 `abi.rs` 的 `SEC_*` 一字不差且都在实测可用集内（§16.8.2）；`evidence/review-log.md` 的推翻编号连续且与蓝图声称的总数一致。

   **这四项都是真实抓到过缺陷的检查**，不是假想的整洁度指标：章节映射曾指向已移出的文件；推翻计数曾同时存在 5 / 7 / 8 三个互相矛盾的说法；§18 曾把一个已执行完的迁移计划写成待办，还错称归档目录被 `.gitignore` 排除。用 Rust 写在 `xtask` 里，不要写成 PowerShell 脚本——跨平台、CI 天然能跑、且不需要绕执行策略。

**本阶段答的 Phase 0 问题**：无（纯逻辑，无内核交互）。

**禁止**：

- **`flux-core` 里不得出现任何 I/O、`unsafe`、async、netlink、BPF。** 它存在的意义就是"能在开发机上全速测"。
- 不要为阶段 2 的 reactor 预建 trait 或事件抽象。
- 不要引入新的运行时依赖。依赖清单的变更属 `governance.md` §1.2，要问。

---

## 17.5 阶段 2 — `fluxd` 进程骨架与 engine 生命周期

**交付物**：目录 layout；`flock` 单实例；控制协议；CLI（`start`/`stop`/`status`/`check`/`bugreport`）；reactor 骨架；engine 候选生命周期（§9.4 的六步换代事务）。

**必读**：`blueprint.md` §9（sing-box 集成，尤其 §9.4）、§10（reactor）、§11（控制/日志/状态）、§26（reactor 状态机）、`docs/ux.md`。

**退出条件**：

1. **冷启动与热更新事务在设备上闭环，尚无数据面**：`fluxd` 能拉起官方 sing-box、按 PID + inode 核验 4 个 socket、写 `run/effective-sing-box.<generation>.json`、跑 `sing-box check -c`、换代、优雅停止。
2. **`fluxd` 自己的 socket 核验必须复现 Q2 的结果**（§16.10.2）：4 个 socket，inode 与 `/proc/<pid>/fd` 对得上。这是把 Q2 从"一次性实测"变成"产品自带的持续检查"。
3. 第二个 `fluxd` 实例启动时被 `flock` 拒绝，并给出可读原因。
4. `status` 在无数据面时正确报告 `Inactive` 且**说清原因**（不是空输出）。
5. `bugreport` 产出诊断包，且默认**不含 logcat**（`docs/ux.md`）。

**本阶段答的 Phase 0 问题**：Q2 的**持续化**（不是重测）。

**禁止**：

- **不要碰内核对象**：不建 veth、不动 TC、不写 sysctl。那是阶段 3。这里最大的诱惑是"反正后面要用，顺手建了"。
- **不要给 sing-box 发 `SIGHUP`**（§9.4 末段已逐条说明理由）。
- **不要注入 §9.1 允许之外的任何 JSON 键**，特别是 `routing_mark` 与 `bind_interface`（§9.3）。
- 不要加 heartbeat 或存活探测心跳。engine 的死活用 pidfd。

---

## 17.6 阶段 3 — netlink 与内核对象所有权

**交付物**：veth 创建；route/RPDB；clsact/filter 挂载与卸载；interface admission；所有权谓词；`rp_filter` 前置检查。

**必读**：`blueprint.md` §8（网络对象与所有权，全节）、§3.3（接口分类）、§10.4（netlink 事件）、§12.8（为什么不 shell out 到 `ip`/`tc`）、`verification/phase0.md` §16.9。

**退出条件**：

1. **Direct / Active / 冲突 / 恢复四条路径闭环**，`status` 逐 interface 给出原因。
2. **Q8 的对象生命周期半通过**：`kill -9 fluxd` 后重启，§8.7 的删除-重建把所有对象恢复到确定状态；`stop` + 卸载 + 重启后**零 Flux 内核残留**；系统 TC / RPDB / VPN 对象**逐行 diff 为空**。
3. `all.rp_filter != 0` 时**响亮失败并给出诊断**，不是悄悄改全局值（§8.4）。起点已实测为 0（§16.9.3），所以这条要**人为构造**来测。
4. **接口筛选不用 `operstate`**（§16.9.5：RAWIP 接口读出 `unknown`），不用"有地址"（§16.9.5：`wlan0` 有地址但无 clsact）。判据是 `IFF_UP` + scope global 地址 + netd 已建 clsact。
5. **pref 逐接口选取**，不缓存设备级值（§8.5.3 的 2026-08-25 追加段）。

**本阶段答的 Phase 0 问题**：**Q8（对象生命周期半）**。

**禁止**：

- **不得 shell out 到 `ip` / `tc`**（§12.8）。全部走 netlink，消息格式见 §8 的 netlink 规格小节。
- **不得在物理接口上创建或删除 clsact**——复用 netd 的（§8.5.1）。netd 会自己删，删掉的是它的，我们只挂 filter。
- **不得写全局 sysctl**（`all.rp_filter`、`ip_forward`）。要改就是响亮失败 + 问所有者（`governance.md` §5）。
- **不得删除、移动或替换 AOSP 的 filter**（§3.4）。
- 不要硬编码 pref 数值。

---

## 17.7 阶段 4 — BPF 加载器（只加载，不挂载）

**交付物**：手写 ELF 解析、relocation、map 创建（12 张）、`SK_STORAGE` 的手写 BTF、ARRAY_OF_MAPS 内层 map、ringbuf；`fluxd check` 的 BPF 半。

**必读**：`blueprint.md` §12（BPF 加载与最小依赖，全节，尤其 §12.7 的 11 条加固）、§6（ABI）、§7.5.0（arm64 无带返回值原子操作）、§7.5.1（verifier 陷阱清单）、`verification/phase0.md` §16.8。

**退出条件**：

1. **四个程序全部加载成功、12 张 map 全部按 `maps.rs` 的参数建出**，`fluxd check` 干净通过。**不挂载、不产生任何流量**——本阶段完全可以在不影响设备网络的前提下验收。
2. `fluxd check` **交叉校验 §9.0 的 fakeip 冲突**：用户 JSON 的 fakeip 段与 Flux 的 listener 地址/固定 bypass 不得重叠。
3. ABI magic 不匹配时拒绝加载并给出可读原因。
4. §12.7 的 11 条加固全部落地，特别是 verifier 日志重试与常量回退——`bpftool` 能加载不代表我们的加载器能。
5. 加载器产出的程序与 `bpftool prog loadall` 产出的**指令数一致**（`xlated` 字节数比对，基线值见 §16.8.5）。这条是廉价的正确性交叉验证。

**本阶段答的 Phase 0 问题**：无新增（数据面过验证器已在阶段 0 答完）。

**禁止**：

- **不得使用 libbpf、aya 或任何 BPF 加载库**（§12 的核心决定）。理由是依赖体积与 Android 上的可控性，不是偏好。
- **不得使用带返回值的原子操作**（§7.5.0：arm64 5.15 上加载失败 `-ENOTSUPP`，而 verifier 已通过，errno 毫无指向性）。
- 不得改 `flux.bpf.c` 的段名（`FLUX_SEC_*` 是实测结论，§16.8.2）。
- 不要在这个阶段挂载。挂载有存活验证要求，那是阶段 5。

---

## 17.8 阶段 5 — 挂载、存活验证、skb 回送闭环

**交付物**：`flx_verify` 存活验证流程（§8.5.4）；四个程序挂载；veth 回送路径打通。

**必读**：`blueprint.md` §8.5.3 / §8.5.4、§3.3（L2/L3 分支）、§8.4（路由前置条件）、`verification/phase0.md` §16.5.4 / §16.9.3。

**退出条件**：

1. **`flx_verify` 在每个准入接口上计到调用**，然后卸下探测、在同一 pref 换上 `flx_cap_l2`/`flx_cap_l3`。attach 成功**不**等于能工作（§8.5.3 约束 3）。
2. **Q5.1 通过**：L2 路径不写任何字节即 `bpf_redirect`，配 ingress 的 `bpf_skb_change_type(PACKET_HOST)`，包被 `ip_rcv` 接受。**若被 `PACKET_OTHERHOST` 丢弃，D17 被证伪**——按 `governance.md` §3 记录，回退到写 dst MAC，不要绕。
3. **Q5.2 通过**：rmnet 上 `bpf_skb_change_head(14)` + 只写 EtherType 能闭环；headroom 不足时 helper 返回 `-ENOMEM` 而非损坏包。
4. **Q5.6 通过**：跑完 `all.rp_filter` / `flxrs1.accept_local` / `ip_forward` / `arp_filter` 矩阵，确定**真正必需的最小集**。§8.4 的预测是需要 `flxrs1.rp_filter=0` + `accept_local=1` + `all.rp_filter=0`，不需要 `ip_forward` 与 `arp_filter`。**失败时直接上 `pwru` + `kfree_skb_reason`，不要猜**（§8.4 有 dae 的原始 trace 可对照）。
5. **Q5.7 通过**：`TC_ACT_UNSPEC` 之后后续 filter 的计数器仍在增长。

**本阶段答的 Phase 0 问题**：**Q5.1、Q5.2、Q5.6、Q5.7**。

**禁止**：

- **egress"不接管"永远是 `TC_ACT_UNSPEC`**，绝不是 `TC_ACT_OK` 也绝不是 `TC_ACT_PIPE`（`flux.bpf.c` 头部注释给了两条独立理由）。dae 在 23 处返回 `TC_ACT_OK`，在 Linux 路由器上没问题，在这里是 bug。
- **不得靠 dump 推断可达性**，必须用 §8.5.4 的正向存活验证。
- 不得为了让包过去而放宽 sysctl 范围（比如改 `all.*`）。
- 不得占用 pref 1，即使当时空着（§8.5.3 的竞态说明）。

---

## 17.9 阶段 6 — 完整数据路径

**交付物**：§7.2–7.5 的决策算法全部落地；`bpf_sk_assign` 路径；counters；per-UID 统计（D23）。

**必读**：`blueprint.md` §7（数据面算法，全节）、§2（失败语义）、§1.6（eBPF 能力边界）、`reference/failures-and-status.md`。

**退出条件**：

1. **双栈 TCP/UDP 端到端 smoke 通过**（这是旧 §17 阶段 4 的原始退出条件）。
2. **Q3 通过**：`accept()` 后 `getsockname()` **逐字节**等于原始目的；旧 flow 无一个字节到达真实目的（用真实目的侧 tcpdump 证明）。
3. **Q4 通过**：四组（family × connected/unconnected）`IP_RECVORIGDSTADDR` cmsg 逐字节一致；回写路径能到达 app。
4. **Q5.3–5.5 通过**：大文件上传触发重传（clone 安全）与 TCP GSO；QUIC 客户端触发 `UDP_SEGMENT`，engine 收到的是一个个 datagram 而不是巨包。
5. **Q6 剩余通过**：跑捕获流量前后各抓一次 `iptables -L -v -n`，逐链比对 drop/reject 计数增长，**单列 OEM 自有链**。若 OEM 链丢我们的包，答案是"该设备不受支持，保持 Direct 并在 `status` 报告"——**绝不是 flush OEM 的防火墙链**（box4magisk 选了后者，与 §1.3 非目标和 §15.4(1) 直接冲突）。
6. **Q8 流量语义半通过**：残留 TC filter 只造成"新流 direct、已入场流 drop"。
7. **Q9 的第 6 条**：用户 JSON 里的 `package_name` 规则命中（前置条件已实测成立，§16.10.5）。

**本阶段答的 Phase 0 问题**：**Q3、Q4、Q5.3–5.5、Q6 剩余、Q8 流量语义半、Q9.6**。

**禁止**：

- **一旦观察到有效的 CAPTURED 决策，之后每个失败都是 `TC_ACT_SHOT`。绝不回退到真实目的。** 这是 admission-bounded fail-open 的全部含义（§2）。
- **绝不对 established/data TCP 包调 `bpf_sk_assign()`**，只对裸 SYN（`flux.bpf.c` 头部给了完整的内核机制理由）。
- 不得用特判端口 53 的方式处理 DNS（D18 已实测成立，不需要特判）。
- 不得为性能牺牲引用配平：每个 `bpf_sk_lookup_*` 在每条分支上恰好释放一次。

---

## 17.10 阶段 7 — 故障、换代与自愈

**交付物**：`fault_events` ring buffer；fault latch；generation 换代与恢复；`status` 的完整故障矩阵。

**必读**：`blueprint.md` §2.2（失败语义）、§9.4（换代事务）、§26（reactor 状态机）、`reference/failures-and-status.md`（全文）。

**退出条件**：

1. **Q7 通过**：engine 在 egress 的 `listener_alive()` 与 ingress 的 lookup 之间退出时，只影响已 redirect 的包，下一个新 SYN/datagram 恢复 Direct；`kill -9` engine 后新连接 **100% direct**。
2. **fault 事件数是 O(1) 而非 O(packets)**：latch 抑制 storm，重复/旧事件幂等。
3. 跨 generation 的 in-flight 旧包被送进新 listener 时行为如 D3 所述无害。
4. `reference/failures-and-status.md` 的每一行**都能人为构造并观察到**，`status` 给出的假设与文档一致。
5. current fault 让 fluxd 先 inactive 再重启 generation。

**本阶段答的 Phase 0 问题**：**Q7**。

**禁止**：

- 不得加 heartbeat（`governance.md` §5）。
- 不得放宽 fail-closed 语义来让某个测试变绿。
- 不得让 fault 处理路径自己成为 storm 源（事件要幂等且有 latch）。

---

## 17.11 阶段 8 — 模块封装与发布

**交付物**：三管理器（Magisk / KernelSU / APatch）module lifecycle；`action.sh`；webroot；release artifact。

**必读**：`blueprint.md` §13（模块安装与构建）、`docs/ux.md`、`docs/introduction.md`、`governance.md` §7（发布工程与社区流程）。

**退出条件**：

1. 0.9.0 artifact / checksum / 文档三者一致。
2. 三个管理器上安装、启动、`action.sh`、卸载全部闭环；卸载后**零残留**（复用阶段 3 的 Q8 检查）。
3. `docs/introduction.md` 描述的行为与实际一致——**包括那些"诚实的失败"**：流量统计翻倍、被委托的流量、OEM 冲突时保持 Direct。
4. `bugreport` 的输出满足 `docs/ux.md` 的隐私约定（默认无 logcat；不泄露第三方包名之外的使用习惯，参见 §16.7.3）。

**禁止**：

- **不得 flush OEM 的防火墙链**（box4magisk 的 `oneplus_a16_fix()` 那条路）。
- 不得在 `post-fs-data.sh` 里做网络操作（§13 给了理由）。
- 不得让 `action.sh` 做需要交互的事。

---

## 17.12 CI 与阶段的对应

| CI job | 从哪个阶段起必须绿 |
|---|---|
| `fmt / clippy / test` | 阶段 1 |
| `bpf object`（编译 + **verifier gate**） | 阶段 0 起（已绿） |
| `bpf object` 的 `abi-check` | **阶段 1 结束时删掉 `continue-on-error`** |
| `aarch64-linux-android` 交叉编译 | 阶段 1 |
| `cargo deny` | 阶段 1 |
| `shellcheck` | 阶段 8（`module/*.sh` 出现时）；`tools/phase0/*.sh` 已在阶段 0 通过 |

**verifier gate 已经证明它抓得住真 bug**：它第一次被启用时就发现四个程序的段名 libbpf 一律拒绝、根本加载不了（§16.8.1），而编译从来不会发现这种问题。
