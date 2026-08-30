# Flux-rs 0.9.2 增量设计蓝图

- 文档编号：`FLUX-BP-0.9.2-DELTA`
- 状态：**草案**（2026-08-29，Asia/Hong_Kong）
- 基线：[`../spec/blueprint.md`](../spec/blueprint.md)（`FLUX-BP-0.9.0-FINAL`）+ [`blueprint-0.9.1.md`](blueprint-0.9.1.md)（`FLUX-BP-0.9.1-DELTA`）
- 性质：0.9.2 的**规范性增量合同**
- 主题：把交互与配置模型做对，并把已有事件源用满

## 0. 如何读取这份蓝图

读取顺序是 0.9.0 基线 → 0.9.1 增量 → 本文。同一主题冲突时以最新一层为准。修订编号 `R092-NN` 稳定，覆盖旧条款时列出被覆盖项；被覆盖的原文一律保留，不回写历史。

0.9.1 的定位是"把文档和实现对齐"，它没有改变产品形态。0.9.2 相反：**它改的正是产品形态**——用户面对几个文件、每个文件负责什么、Flux 替用户做多少事。因此本文大量覆盖 0.9.1 自己的条款，这不是反复，是 0.9.1 只做了对账、没做设计。

### 0.1 这一版要解决的问题

0.9.1 交付了一个能工作但难用的产品。真机验证（`../history/review-log.md` §0.6.4）之后，让它真正可用需要人手工做三件事：把订阅的 58 个节点合并进配置、把机场的 DNS 配置迁移到新格式、逐个填包名。第一件是每次订阅更新都要重做的，第三件在选中 429 个应用时不可能手工完成。

**产品缺的不是能力，是把能力接到用户手上的那一段。**

---

## R092-01：配置模型改为「模板 + 订阅 → 生成物」

**覆盖**：0.9.0 §9.6、§11.1；0.9.1 R091-03 的"默认 `sing-box.json` 形状"与 R091-04 的路径表；`../spec/interaction.md` §27.2。

### 依据

参考实现 `Flux-original` 的 `scripts/updater.sh` 是这样组织的（`:139-149`，Phase C）：拿模板，把**每个空的 selector** 按地区填上对应节点组，再把精修后的节点追加进 `outbounds`，输出到运行配置。用户只编辑模板，生成物是机器产物，每次订阅更新重建。

0.9.1 把这个关系搞反了：它把模板当成一次性样板复制成 `sing-box.json`，之后归用户所有。后果是订阅更新必须由用户手工合并——真机验证那天这件事是用 `jq` 手工做的，那不该是临时脚本，应该是产品功能。

### 文件布局

| 路径 | 归属 | 说明 |
|---|---|---|
| `config/flux.toml` | 用户权威 | Flux 自己的行为：选谁、哪些目的地直连、哪些接口、订阅参数 |
| `config/template.json` | 用户权威 | sing-box 配置模板：DNS、路由规则、selector 骨架、inbounds |
| `config/*.txt` | 用户权威 | 被 `@` 引用的列表文件（R092-02） |
| `run/subscription.raw` | 机器产物 | 订阅抓取的**原始**响应，唯一的网络产物 |
| `run/sing-box.<gen>.json` | 机器产物 | 每代一份、只读、换代后删 |

`config/template.json` 与 `Flux-original` 的 `conf/template.json` 同名同义，交叉引用不需要额外解释。**注意 `Flux-original` 的 `config.json` 是机器产物**，本项目不使用这个名字，避免同名反义。

`effective-sing-box.<gen>.json` 更名为 `sing-box.<gen>.json`：它在 `run/` 下，"effective" 是废话。

### 生成是一个纯函数

```
template.json  +  subscription.raw  +  flux.toml 的精修规则
      → sing-box.<gen>.json
```

生成步骤只做两件事，与 `updater.sh` Phase C 一致：

1. **填空**：把模板里 `outbounds` 为空数组的 `selector`/`urltest`，按 tag 匹配到的地区组填上；tag 为 `PROXY`/`GLOBAL`/`AUTO` 的填全部节点。
2. **追加**：把精修后的节点追加进 `outbounds`。

除此之外**逐字节透传**。这条是可机检的：把生成物里的 `outbounds` 换回模板的 `outbounds`，结果必须与模板深度相等。0.9.2 必须有这个测试。

**缓存的是原始响应而不是精修结果**，因为精修规则（`exclude_pattern`、`rename`、`strip_emoji`、`max_tag_length`）住在 `flux.toml` 里。改这些规则是纯本地操作，离线也应当立即生效，不该被迫重新联网。网络产物只有一个，职责单一。

### 失败处置

沿用 `updater.sh` 的三段式（`:421-450`）：合并结果先过官方 `sing-box check`，不过就保留当前生成物并报错；部署用备份加原子 `mv`；内容与当前一致则跳过换代。**订阅更新绝不能把用户的网络搞没**——这条 0.9.0 §9.4 已经有了，本项只是把订阅接进同一条事务。

---

## R092-02：三个维度统一黑/白名单，列表可引用文件

**覆盖**：0.9.1 R091-04 的 `flux.toml` schema（`apps` + `bypass_cidrs` 两个键）。

### 依据

`git show a44a4ea:module/flux.toml` 曾经 ship 过 `[apps] mode`、`[bypass] files`、`[interfaces] mode`、`[subscription]`、`[log]`、`[advanced]`；`39127bd` 把它砍成两个键。砍的时候没有同步砍 ABI，于是：

> `a44a4ea` commit message：SM-S9180 has 429 packages inside the [10000,19999] application range, while the selected cap was 128 and uid_policy held 512. … Selected goes to 1024 and uid_policy to 4096.

**1024 与 4096 这两个容量的存在理由就是"代理全部第三方应用"这个模式。** LPM 的 65536 同理，是为 chnroute 量级的列表准备的。0.9.1 如实描述了 parser 的现状，但把实现退化记录成了设计结论。本项翻回来。

形状取自 `box_for_magisk` 的 `package.list.cfg`——**一个列表加一行模式**，而不是两个列表：

```
# black/white list mode.
mode:blacklist
# package_name ▼
# 0:com.termux
```

同一 idiom 在该项目里复用于包名、Wi-Fi SSID（`use_wifi_list_mode`）与接口开关。**统一性本身就是 UX**：用户学一次，处处适用。

### schema

```toml
[apps]
# whitelist = 只代理名单内；blacklist = 名单内不代理，其余全代理
mode = "whitelist"
list = ["0:com.twitter.android", "@apps.txt"]

[cidr]
# blacklist = 名单内直连（常规用法）；whitelist = 只捕获名单内
mode = "blacklist"
list = ["100.64.0.0/10", "@chnroute.txt"]

[interfaces]
# blacklist + 空名单 = auto：接管全部受支持的物理接口
mode = "blacklist"
list = []
```

`mode = "blacklist"` 且列表为空即"全自动"：全部第三方应用自动代理，新装应用自动纳入（`packages.list` 的 inotify 已在监听，见 R092-06）。这就是 auto 模式，不需要第三个枚举值。

`bypass` 更名为 `[cidr]`：有了 mode 之后 "bypass" 只描述其中一个方向。`cidr` 这个名字还当面堵掉一个已知误解——**这一维只看目的 IP，永远不看域名**；域名分流是 sing-box 的职责（0.9.0 §1.4）。

CIDR 的 whitelist 方向在数据面只是 LPM 命中后取不取反，一个分支。代价小，换来三处形状一致。但**白名单模式下一个打错的条目会静默地让一切直连**，所以 `status` 必须显式印出当前生效模式，不能只印条目数。

### `@` 文件引用

任何 list 里以 `@` 开头的条目是文件引用，一行一条，`#` 起始为注释。CIDR 与 Android 包名都不可能以 `@` 开头，所以不靠猜测区分——**禁止用"能不能解析成 CIDR"来判断是不是路径**，那会让一个打错的 CIDR 静默变成文件路径。

三条约束：

- **不递归。** 被引用的文件里不能再出现 `@`。避免环与无界展开，失败模式有限。
- **路径限定在 `config/` 下**，相对该目录解析。这样 inotify 监听配置目录就自动覆盖了列表文件的热重载，不需要动态扩展 watch 集。
- **文件缺失是 `check` 错误**；运行时拒绝新策略并保留当前策略，按既有 level-triggered 收敛重试。

这取代了 0.9.0 设想的 `[bypass] files` 独立键：每段配一个 `files` 是把同一个概念拆成两个旋钮，而且只有 CIDR 有、别的维度没有。

---

## R092-03：inbounds 与 listener 地址归内部，由 Flux 注入

**覆盖**：本项的初稿（模板预填）；0.9.1 R091-03 里以禁令形式表达的同一约束。

### 结论

模板不声明 `inbounds`，也看不到 listener 地址。生成步骤把两个 tproxy inbound 注入生成物。

**本项初稿写的是相反的结论。** 那次决定基于一个事实核查——`struct flux_control` 本来就携带地址（`listen_v4` 在 offset 28、`listen_v6` 在 40），所以模板声明地址**不需要改 ABI**。这证明了预填**可行**，但可行性不是设计依据。按 PHIL-1 的判据重新过一遍，结论反过来。

### 判据

问："用户改错了会发生什么？"

把 `198.51.100.1` 改成 `127.0.0.1` 看着更合理，实际后果是捕获全灭且没有任何报错。这是**机制坏掉**，不是"用户得到了他要的另一种行为"。按 §1，它属于内部。

listener 地址与 `flxrs0`/`flxrs1` 的接口名、TC 的 chain/handle 编号、map 名字是同一类东西：捕获机制的实现细节，只不过它恰好能用 sing-box 的配置语言表达。**没人会提议让用户配置 veth 叫什么名字。**

### 门禁计数

PHIL-1 的推论——数门禁：

| 方案 | 需要的校验 |
|---|---|
| 预填 | 类型是 `tproxy`；两个 tag 齐备且唯一；地址可解析且族别正确；地址不落在 fakeip 段；地址与用户 `[cidr]` 集的关系自洽；端口未被占用。**六道** |
| 注入 | 模板不声明 `inbounds`。**一道** |

六道全部只因为暴露了一个内部值而存在。把值收回内部，六道一起消失——这正是 §1 推论描述的形状。

### 一个被我用错的论据

初稿支持预填的主论据是"它让生成成为纯函数"。这个论证是错的：**三个输入的函数和两个输入的函数一样纯。** 纯性是确定性加无副作用，不是"不添加任何东西"。注入同样是纯函数，只是输入里多了一项运行时参数。

### 透明度怎么给

预填唯一真实的好处是用户能看到全貌。这个不用暴露旋钮也能给：`run/sing-box.<gen>.json` 就在磁盘上，完整可读，用户能确认究竟跑的是什么。PHIL-9 已经写明——§1 排除的是"能编辑"，不是"能看到"。

### 合同

- 模板**不得**声明 `inbounds`；声明了是硬拒绝（可诊断：`check` 直接指出这一行）。
- 生成步骤注入两个 tproxy inbound，tag 为 `flux-in-v4` / `flux-in-v6`，地址与端口来自运行时参数。
- 端口每代随机抽取并试绑定，冲突则重抽；用户无需关心，也没有可配置项。
- 固定 bypass 的 listener 条目从运行时参数派生，不再硬编码在 `cidr.rs`——这消掉 `abi.rs:145` 与 `cidr.rs` 之间的重复（PHIL-4）。

---

## R092-04：门禁分软硬两级

**覆盖**：0.9.0 §9.0.1、§23.1 与 0.9.1 R091-03 里若干"拒绝"处置。

这是一个 Magisk/KernelSU 模块，用户已经有 root。**产品定位不应包含过度的安全或兜底门禁**，用户对自己的设备有处置权。但"不兜底"不等于"不告知"。判据：

> **只有当失败是静默且用户无法自行诊断时才硬拒绝；其余一律响亮告警并放行。**

按此重新分类：

| 情形 | 0.9.1 | 0.9.2 | 理由 |
|---|---|---|---|
| `clash_api` secret 为空 | 拒绝 | **告警放行** | 用户的设备用户决定；症状可见（别的 app 能连上） |
| `clash_api` 非回环监听 | 拒绝 | **告警放行** | 同上 |
| 模板缺 `hijack-dns` | 告警 | 告警 | 不变 |
| 模板 inbounds 声明有误 | — | **拒绝** | 直接决定捕获是否工作 |
| fakeip 段与 bypass 集相交 | 拒绝 | **拒绝** | DNS 正常、应用连得上、什么都打不开，靠猜诊断不出来（D21） |
| 被 `@` 引用的文件缺失 | — | **拒绝** | 策略集会静默缩小 |
| 6.6.0–6.6.46 上的 LPM | 拒绝 | 拒绝 | 症状是设备重启（D20） |

告警必须进 `status` 的 `warnings`，并在 `module.prop` 状态行体现，不能只写进日志。

---

## R092-05：订阅流水线

**覆盖**：0.9.1 R091-03 的"不包含 `fluxd subscribe`、订阅转换"；C11 的延期状态。

所有者 2026-08-29 确认 C11 在后续版本做，本版实现。

### 配置

```toml
[subscription]
url = ""
interval = 86400          # 秒；0 = 只手动更新
timeout = 10
retries = 2
exclude_pattern = "(expire|traffic|官网|到期|流量|剩余|套餐|重置|联系|群组|通知|平台|网站|时间|建议|反馈|版本|更新)"
rename = [
  { match = "【(亚洲|北美洲|欧洲|南美洲|非洲|大洋洲|南极洲)】", replace = "" },
]
strip_emoji = true
max_tag_length = 32
```

### 输入格式

两种，按内容判定而不是按扩展名或 UA：

- **已是 sing-box JSON**：直接取 `.outbounds`。真机验证确认机场在 UA 为 `sing-box` 时直接返回完整配置。
- **base64 编码的 URI 列表**：解码后逐行解析 `vmess`/`vless`/`trojan`/`hysteria`/`hysteria2`/`tuic`/`ss`/`socks`/`http`/`snell`。

URI 解析放在 `flux-core`（纯逻辑、无 libc、无 syscall），因此可以在任意开发主机上跑单元测试，不需要设备也不需要网络。这是 `Flux-original` 用 awk 手写 base64 解码器、URL 解码器和 JSON 取值函数（`updater.sh:175-245`）的直接改进——那三件事在 Rust 里都是库调用，而每一个手写版本都是 bug 来源。

### 节点精修

顺序固定，与 `updater.sh` Phase A/B 一致：

1. 剔除基础设施类型（`selector`/`urltest`/`direct`/`block`/`dns`）；
2. 按 `exclude_pattern` 丢弃机场塞进节点列表的公告条目；
3. 按 `rename` 规则重写；
4. 可选剥离 emoji；
5. 归一化倍率写法（`$2.0`、`2.0倍率`、`2.0X` 一律成 `2.0x`），压缩连续空格；
6. 按 `max_tag_length` 截断；
7. 按地区正则分组，供 R092-01 的填空步骤使用。

第 2 步是这套流程里最有价值的一条：没有它，用户的节点列表里会混进一堆连不上的假节点。

**必须校验**：精修后非基础设施 outbound 数量 > 0。抓回来的内容是一个错误页面时 JSON 可能仍然合法、`check` 也可能通过，但一个节点都没有。

### 命令

`fluxd subscribe` 手动触发一次抓取与换代。这是 R091-11 之后第一个新增 CLI 命令，因为现在它有实现。

---

## R092-06：把已有事件源用满

**覆盖**：0.9.0 §10.4；0.9.1 R091-11 对新增自动化的沉默。

Flux 已经有 signalfd、inotify、rtnetlink、pidfd、ringbuf、timerfd 六类事件源，都接在同一个 epoll 上。本项不新增机制，只是把已经在监听的事件接到用户能感知的行为上。

| 自动化 | 事件源 | 状态 |
|---|---|---|
| 新装应用自动纳入（`mode = "blacklist"` 时） | `packages.list` 的 inotify | 已监听，仅用于重解析 UID；接上策略重算即可 |
| 编辑模板/列表文件即重新生成、校验、换代 | `config/` 的 inotify | 已监听 |
| 订阅抓取失败后等网络恢复再重试 | rtnetlink | 已监听 |
| 订阅定时刷新 | timerfd | 已有 |
| 接口出现/消失自动接管或移除 | rtnetlink | 已实现 |
| 本机地址变化自动注入 bypass | rtnetlink | 已实现 |
| 逐接口 TC pref 选择与存活验证 | — | 已实现 |

### 定时刷新不是轮询

0.9.0 §10.1 的"**没有任何周期轮询**"禁的是健康探针那一类：每 N 秒醒来问一次"状态还正常吗"。订阅定时刷新不是这个——它是挂一个 24 小时后到期的一次性 timerfd，内核到点唤醒 epoll，到期后重新挂一个。

**明确记为例外**，理由：它不查询任何状态，只在到期时执行一个用户显式配置的动作；`interval = 0` 时根本不挂表。

不使用 cron：Android 不自带 `crond`，依赖 busybox 意味着多一个外部依赖和一个额外进程，而 reactor 里的 timerfd 与现有事件循环同源、零额外依赖。

### 网络恢复重试优于定时重试

抓取失败后不启动固定间隔重试，而是等 rtnetlink 报告有可用的默认路由再试。离线时一次都不试，联网瞬间立刻试。这比退避重试既快又省电，而且用的是已经在监听的事件。

### 明确不做

**自动测速选节点。** sing-box 的 `urltest` 已经在做，重做一遍就是第二套状态，且要在 Flux 与 sing-box 之间同步"哪个节点可用"。

**网络看门狗自动回滚。** 0.9.0 §8.3 已逐条否决，理由不变：判断"网络是否正常"需要主动探测，离线与受限网络必然误判，而一个会误判的自动回滚会在用户正常使用时把代理关掉。比没有更糟。

---

## R092-07：按 Wi-Fi SSID 自动启停

**新增**。

`box_for_magisk` 有这个能力（`settings.ini:204-212` 的 `use_ssid_matching` / `use_wifi_list_mode` / `wifi_ssids_list`），用途是"在家或公司的可信网络上自动关闭代理"。

```toml
[ssid]
mode = "blacklist"        # blacklist = 名单内的 SSID 上不激活
list = ["MyHome", "@ssid.txt"]
```

第四次复用同一个黑/白名单 idiom。

**取 SSID 走 nl80211**（generic netlink，`NL80211_CMD_GET_INTERFACE`），不碰 binder、不 shell out `dumpsys`。理由与 D8 拒绝 `cmd package` 同源：binder 在 late-start 阶段可能未就绪，会引入启动顺序依赖与重试状态机；而 Flux 已经在说 netlink，加一个 generic netlink family 是同源能力，不是新机制。这一点上可以做得比参考实现干净。

SSID 变化本身也是事件驱动的（`NL80211_CMD_CONNECT`/`DISCONNECT` 的多播组），不需要轮询。

**边界**：SSID 只影响是否激活，不影响策略内容。未连 Wi-Fi 时该维度不参与判定。SSID 不可读时按"不匹配任何名单项"处理并告警，不阻止激活——这是可诊断的失败（R092-04）。

---

## R092-08：webroot

**覆盖**：0.9.1 R091-03 的"不包含 Flux WebUI"；C8 的延期状态。

`Flux-original` 的 `webroot/index.html` 一共 12 行，内容是跳转到 `http://127.0.0.1:9090/ui/`。**它不是 WebUI**，是 root 管理器模块列表里那个按钮的跳转壳子，跳到 sing-box 自己的 clash_api UI。

C8 延期的是"Flux 自己的 WebUI"，与这个 12 行的跳转壳不是一回事，成本近乎零。本版包含 webroot，C8 保持延期。

改进：跳转 URL 带上安装时生成的 secret，用户不必手工填。webroot 在 `check` 发现 `clash_api` 未配置时显示一句说明而不是跳进一个连不上的页面。

allowlist 从 14 文件增加到 15（`webroot/index.html`）。

---

## R092-09：用户可见文案

**覆盖**：0.9.1 R091-04 的 `module.prop` 状态行格式；`../guide/introduction.md`、`../spec/interaction.md` 的若干表述。

### module.prop

`Flux-original` 的基础描述是 `Seamlessly redirect your network Flux.`——一句话，面向用户。

0.9.1 写的是 `Transparent per-app proxying via eBPF and an unmodified official sing-box.`。这是**写给评审看的定位陈述**："unmodified official" 是在与其它项目撇清关系，用户不关心 sing-box 有没有被改过。同样，状态行 `🥰 [Active] gen 18 · 5 apps · rmnet_data0, rmnet_data1, rmnet_data8, wlan0` 里的 generation 和四个网卡名是开发者的调试信息。

手机列表里那一行，用户真正想知道的是**通了没有、走的哪个节点、有没有出问题**。修订为：

| 状态 | 显示 |
|---|---|
| Active | `已启用 · N 个应用 · <当前节点>` |
| Active 但有告警 | `已启用 · N 个应用 · <第一条告警的人话版本>` |
| Inactive | `未生效 · <原因的人话版本>` |
| Disabled | `已停用` |

当前节点从 clash_api 读（已配置时），读不到就省略这一段而不是显示占位符。generation 与接口列表移出，它们属于 `fluxd status`。

### 通用规则

面向用户的文案（`module.prop`、`status` 的人类输出、安装器提示、`../guide/introduction.md`、配置文件注释）遵守：

- 不出现内部标识符，除非同时给出查它的命令；
- 不陈述与其它项目的差异，用户不是来做选型的；
- 不用"transparent"、"data plane"、"admission"这类实现词汇描述用户能观察到的现象；
- 错误信息说"哪里错了、怎么改"，不说"违反了哪条不变量"。

AUTH-6 已有类似要求，本项把它扩展到 `module.prop` 与安装器输出，并明确"去除定位陈述"这一条。

---

## R092-10：`first_applicable` 改名为 `reachable`

**覆盖**：0.9.1 R091-05 的兼容字段保留决定。

0.9.1 保留了 `first_applicable` 这个字段名，同时把语义收窄成"可达性已验证"，理由是"避免无关 wire 破坏"，代价是一个名字与语义相反的字段，外加四份文档里的解释段落。

但 R091-11 是同一份文档写的，原话是"当前只有 CLI 一个真实客户端…不为假想客户端预建 registry/migration framework"。**按这条逻辑，这里的兼容性在保护一个不存在的客户端。** 唯一的客户端在同一个仓库里。

改名为 `reachable`，三态语义不变（缺席 = 未得出结论，`true` = 已验证可达，`false` = 明确不可达）。reason token `not_first_applicable` 一并改为 `identity_drift`，因为它实际表示的是 attachment identity 或前置 filter 快照不再成立。删除 0.9.1 里所有"这个字段其实不是字面意思"的解释段落。

这条是自我纠正：0.9.1 在别处正确地拒绝为假想客户端预建协议，却在这里为同一个假想客户端保留了一个坏名字。

---

## R092-11：bypass 集拆成 RESERVED 与 POLICY 两类

**覆盖**：0.9.0 §6 的 `bypass_v4`/`bypass_v6` 单一语义；R092-02 里"`[cidr]` 的 mode 作用于整个 bypass 集"的含糊表述。

### 问题

现在一个 LPM 集在干两件不相干的事：

| | 内部：机制不变量 | 外部：用户策略 |
|---|---|---|
| 内容 | 回环、链路本地、多播广播、listener 地址、本机地址 | LAN、chnroute、CGNAT 网关 |
| 违反后果 | 自环、与本地服务抢端口，机制坏掉 | 用户自己的取舍 |
| 受 `mode` 影响 | **永不** | 受 |

混装的直接代价：白名单语义含糊（listener 要不要算进用户的白名单？）、fakeip 检查要对一个并集推理、listener 地址要在两处各写一遍。

这正是 PHIL-1 的形状。参考实现也是这么分的：`AndroidTProxyShell/tproxy.sh:980-1012` 用链序把机制排在策略之前，`box4magisk/box/scripts/net.inotify:15-22` 把本机地址当 *anti-loopback rule* 单独插入，与用户的 `cn.zone` 不同路径。

本项目其实已经拆过一半：D20 把本机地址移进独立的 `self_addr_*` HASH，`bpf/flux.bpf.c:420-439` 的 `bypass_hit()` 因此是两级结构。本项把第二级也拆干净。

### 做法

`bypass_v4`/`bypass_v6` 的 value 类型已经是 `__u8`，而 loader 恒写 `1`（`maps.rs:318`）、BPF 只判 `!= NULL`（`flux.bpf.c:430`）——**这个字节从来没被读过**。用它打标，不新增 map、不新增 lookup：

```c
#define FLUX_BYPASS_RESERVED 1   /* 机制不变量，恒直连 */
#define FLUX_BYPASS_POLICY   2   /* 用户策略，受 cidr.mode 约束 */
```

判定逻辑（一次 lookup，加一个对 control 中 mode 标志的分支）：

| LPM 结果 | blacklist | whitelist |
|---|---|---|
| 命中 `RESERVED` | 直连 | 直连 |
| 命中 `POLICY` | 直连 | **捕获** |
| 未命中 | 捕获 | 直连 |

`cidr_mode` 放进 `flux_control` 现有的 `pad0[2]`：结构大小与所有 offset 不变，但契约变了，因此 `FLUX_ABI_MAGIC` 必须 bump（GOV-4.2）。这是可能范围内最小的 ABI 变更。

### 落地的好处

- 白名单语义不再含糊：RESERVED 无视 mode，用户集里根本没有 listener，"要不要把它加进白名单"这个问题消失；
- fakeip 检查分成两句可分别判定的话：与 RESERVED 相交是硬拒绝（机制，PHIL-6），与 POLICY 的关系随 mode 而定且属用户取舍；
- `[cidr]` 的文档缩成一句话：它只描述用户策略。

---

## 冲突裁决登记表

| 冲突族 | 0.9.2 结论 | 修订 |
|---|---|---|
| 模板是一次性样板 vs 持续的生成输入 | 模板是权威输入，生成物每代重建 | R092-01 |
| 用户直接编辑完整 sing-box 配置 vs 只编辑模板 | 只编辑模板；节点来自订阅 | R092-01 |
| `effective-sing-box.<gen>.json` 命名 | `run/sing-box.<gen>.json` | R092-01 |
| 缓存精修结果 vs 缓存原始响应 | 缓存原始响应，精修是纯函数 | R092-01 |
| `apps` 单一数组 vs 黑/白名单模式 | 一个列表加一个 mode，四个维度统一 | R092-02 |
| 1024/4096/65536 容量无对应功能 | 恢复 `mode = "blacklist"` 全自动与文件引用 | R092-02 |
| `[bypass]` vs `[cidr]` | `[cidr]`，并明确只看目的 IP 不看域名 | R092-02 |
| 每段独立的 `files` 键 vs 统一 `@` 引用 | 统一 `@`，不递归、限定在 `config/` 下 | R092-02 |
| inbounds 由 Flux 注入 vs 模板声明 | 注入；listener 属内部不变量 | R092-03 |
| 预填可行（ABI 支持）是否等于预填正确 | 不等于；六道门禁 vs 一道 | R092-03 |
| 固定 bypass 硬编码 listener 地址 | 从运行时参数派生，消掉重复 | R092-03 |
| bypass 集混装机制保留网段与用户策略 | value 字节打 `RESERVED`/`POLICY` 标，一次 lookup 不变 | R092-11 |
| 安全门禁一律硬拒绝 | 只有静默且不可诊断的失败才硬拒绝 | R092-04 |
| clash_api secret/监听地址 | 告警放行，不再拒绝 | R092-04 |
| 0.9.x 无订阅 | 本版实现，含 URI 解析与节点精修 | R092-05 |
| URI 解析放在何处 | `flux-core`，任意主机可测 | R092-05 |
| 定时刷新是否违反"禁止轮询" | 不违反，明确记为例外；不用 cron | R092-06 |
| 订阅重试策略 | 等 rtnetlink 报告网络恢复，不定时盲试 | R092-06 |
| 新装应用是否自动纳入 | `mode = "blacklist"` 时自动纳入 | R092-06 |
| 自动测速选节点 | 不做，`urltest` 是 sing-box 的职责 | R092-06 |
| 网络看门狗自动回滚 | 不做，§8.3 的否决理由不变 | R092-06 |
| SSID 自动启停的取值方式 | nl80211 generic netlink，不碰 binder | R092-07 |
| webroot 属于 C8 WebUI | 不属于；12 行跳转壳，本版包含 | R092-08 |
| allowlist 文件数 | 15（新增 `webroot/index.html`） | R092-08 |
| `module.prop` 展示定位陈述与调试信息 | 改为面向用户的状态 | R092-09 |
| `first_applicable` 保留兼容名 | 改名 `reachable`；token 改 `identity_drift` | R092-10 |

---

## 0.9.2 验收

1. 生成纯函数性质有测试：生成物的 `outbounds` 换回模板的 `outbounds` 后，与模板深度相等；
2. 订阅两种输入格式（sing-box JSON、base64 URI 列表）各有 `flux-core` 单元测试，不需要网络；
3. 节点精修的七个步骤各有测试，尤其是公告条目过滤；
4. 四个维度的黑/白名单各有测试，含空名单即全自动；
5. `@` 文件引用有测试：正常加载、缺失报错、拒绝递归、拒绝越出 `config/`；
6. 模板 inbounds 的读取与校验有测试，含端口占用的报错路径；
7. `cargo xtask template-check` 用官方 sing-box 校验新模板；
8. R091-15 的分层门禁全绿；
9. 真机复验 `../history/review-log.md` §0.6.4 的九条断言仍然成立，外加：订阅换代、SSID 启停、webroot 跳转、新装应用自动纳入；
10. 用户可见文案按 R092-09 复核，`rg` 不再在面向用户的文件里发现 "unmodified official"、"data plane"、"admission" 这类词。
