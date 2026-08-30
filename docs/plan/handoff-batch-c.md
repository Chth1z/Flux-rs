# 交给实现者的任务书 C：订阅流水线

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md`，与它冲突时错的是本文。完成后本文删除，对应的 §17.0.2 行划掉。
>
> **前置：批次 A、B 已完成并提交。** 模板归属、纯函数生成、三维度配置都已就位，本批次只往里填订阅。

## 这批要解决的问题

真机测试暴露的那个手工 `jq` 合并步骤，批次 B 只解决了一半——生成已经是纯函数，但**输入里的节点集始终是空的**。本批次把节点接上。

参照实现是 `Flux-original` 的 `updater.sh`。它用 awk 手写了 base64 解码、URL 解码和 JSON 字段提取（`updater.sh:175-245`）。**在 Rust 里这三样都是库调用**，§28.3 已经写明：每一个手写版本都是缺陷来源。这条理由同样适用于 HTTP 本身——所以本批次引入依赖，而不是手写协议。

## C0 — 依赖（已获所有者批准，GOV-1.2）

四个，**就这四个**。再需要别的就停下来问，不要自己加。

```toml
ureq       = { version = "3", default-features = false, features = ["rustls"] }
base64     = "0.23"
url        = "2"
regex-lite = "0.1"
```

`ureq` 阻塞式、纯 Rust、不引入异步运行时。

`regex-lite` 而不是 `regex`：后者带 Unicode 表，约 1.5 MB，占整个二进制很大一块。`regex-lite` 约 100 KB，支持 Unicode 字面量（`exclude_pattern` 里那些中文词能匹配），只是不支持 `\p{...}` 字符类且更慢——**对几百个节点 tag 而言速度无关紧要**。

### C0.1 根证书自己读，不用 platform-verifier

`ureq` 的 `platform-verifier` 在 Android 上要经 JNI 调 JVM，还要捆一个 Kotlin AAR。**`fluxd` 是没有 JVM 的原生守护进程，用不了。**

Flux 本来就是 root，直接读设备的证书目录，按出现顺序：

```
/system/etc/security/cacerts/
/apex/com.android.conscrypt/cacerts/      # Android 14+ 移到了这里
/data/misc/user/0/cacerts-added/          # 用户自己装的 CA
```

`ureq::tls::Certificate::from_pem` 自己会解析 PEM，**不需要再加解析依赖**；喂给 `RootCerts::new_with_certs`。用户自建 CA 的自托管订阅因此能用，这正是选这条路的原因。

**一张都没读到时硬失败，报错里列出试过的路径。** 不要静默回落到打包根证书：那会让"信任从哪来"变成运行时才知道的事，而这是最不该含糊的一件事。

### C0.2 抓取绝不能阻塞 reactor

事件循环是单线程 epoll，一次几秒的 HTTPS 往返会让整个守护进程停摆——包括 rtnetlink 和引擎监督。抓取放工作线程，结果经 eventfd 交回主循环，作为**第七个事件源**接进现有的 epoll。这不是新机制，是既有形状的又一个实例。

`THIRD_PARTY_NOTICES.md` 同步更新。

## C1 — 输入格式按内容判别（§17.0.2 第 3 项）

**合同**：§28.3。

两种格式，**只看内容**——不看扩展名、不看 URL 后缀、不看 `Content-Type`：

- **已经是 sing-box JSON**：取 `.outbounds`。
- **base64 编码的 URI 列表**：解码后逐行解析 `vmess` `vless` `trojan` `hysteria` `hysteria2` `tuic` `ss` `socks` `http` `snell`。

**为什么不信 `Content-Type`**：机场返回什么头完全不可控，同一个 URL 换个 UA 就换格式。内容是唯一可信的信号。

**URI 解析必须放 `flux-core`**：纯逻辑、不碰 libc、不做系统调用。因此它在**任意开发主机上都能跑单测，不需要设备也不需要网络**——这是本批次唯一能被充分测试的部分，测试要写厚。

## C2 — 精修（§28.4）

七步，顺序固定，不能重排：

1. 丢掉基础设施类型（`selector` `urltest` `direct` `block` `dns`）；
2. 丢掉命中 `exclude_pattern` 的条目；
3. 按 `rename` 规则改写 tag；
4. 可选剥离 emoji；
5. 归一化倍率写法（`$2.0`、`2.0倍率`、`2.0X` 统一成 `2.0x`），并合并连续空白；
6. 截断到 `max_tag_length`；
7. 按地区正则分组，供 §28.2 的填空使用。

**第 2 步是这七步里最值得的一步。** 机场把公告——到期日、流量配额、联系方式——当成假节点塞进列表。没有这一步，用户的 selector 里会塞满永远连不上的条目，而**每一条看起来都像一个节点**。

由此引出一条硬规则：**精修后非基础设施 outbound 数为零时，生成必须失败。** 一个返回错误页的抓取可以是语法合法的 JSON，可以通过 `sing-box check`，却一个节点都没有——**数量是区分这两者的唯一判据**。

## C3 — 缓存存原始响应（§28.5）

`run/subscription.raw` 存**精修前**的原始响应。

精修规则住在 `flux.toml`，所以改规则是纯本地操作。**缓存精修后的结果会让一次本地编辑需要一次网络往返才能看到效果**——离线时直接失败，在线时也慢。

顺带保住另一件事：树里**恰好一个文件来自网络**。诊断和信任都依赖这个边界清晰。

## C4 — 更新绝不能把网络搞断（§28.6）

三阶段，接到 §9.4 既有的候选切换上，**不要给订阅单开一条部署路径**：

1. 合并结果必须先过官方 `sing-box check`；失败则保留当前代并报错；
2. 部署是备份加原子 `rename`；
3. **新内容与当前代完全相同时，跳过换代**，不为没有变化的东西重启引擎。

## C5 — 换代的判据是生成物变了（§17.0.2 第 17 项）

**合同**：§28.6 第 3 条。

第 3 条不只服务于订阅，它是**换代的通用判据**。现在 `config_event_domains` 按文件名路由，于是 `flux.toml` 只进策略域——可 `[subscription]` 的精修规则按 §28.2 是生成的输入，改了它必须换代。反过来把 `flux.toml` 也接进引擎域，又会让每次改应用清单都白白重启一次引擎。

**两难只是因为判据选错了。** 生成既然是纯函数，比对生成物本身就是精确的：字节相同就不换代，不同才换。这样"哪个文件改了"根本不需要知道，`config_event_domains` 里那张按文件名分派的表可以一起删掉。

## C6 — 刷新的两个触发源（§17.0.2 第 14 项）

**合同**：§29.3、§29.4。

- **一次性 timerfd**：按 `interval` 定时刷新。`interval = 0` 表示只手动刷新，此时不挂表。
- **失败后按 rtnetlink 默认路由恢复重试**：抓取失败不进退避轮询——**等网络回来这个事件本身**。默认路由出现即重试一次。

两者都用既有事件源，§29.6 已经列明，不要新增机制。

## C7 — `fluxd subscribe`（§28.7）

触发一次抓取；结果不同则换一次代。

**这是 R091-11 冻结命令集之后加的第一个命令**，加它的理由正是那次冻结允许的理由：现在它背后有实现了。除此之外刷新只由 §29.3 的定时器和网络恢复驱动，**永不轮询**。

## 验收

**只跑 `AGENTS.md` 列的主机门禁，加上 aarch64 类型检查**：

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
cargo clippy -p fluxd --target aarch64-linux-android --all-targets
```

**Windows 上跑不了、也不要试的**：`cargo clippy --workspace --all-targets`（设备测试 crate 是 Linux-only）、`cargo xtask abi-check`、`cargo xtask btf-check`（需要带 BPF 后端的 clang）。这三条由 Linux CI 跑（§15.1）。跳过并说明，**但不要声称它们通过了**。

C1 与 C2 的单测要覆盖到：十种 URI 各一例、base64 与 JSON 两种输入的判别、七步精修的顺序、以及**零节点必须报错**。这些都不需要网络。

**合并测试要克制**：一个测试断言一件事。把四个不变量塞进一个测试，失败时看不出坏的是哪一个，而且其中一条悄悄失效不会有人发现——批次 B 已经发生过一次。

## 边界

- 不做 webroot（§28.8）、`clash_api` 告警降级、`clsact` 排除、文案过审——那是批次 D。
- 不实现 SSID 行为（§29.1–§29.2）。
- **不要碰** `docs/spec/**` 与 `docs/history/**`。合同有问题就停下报告。
