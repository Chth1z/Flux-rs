# 怎么装、怎么配、出问题怎么办

> **投影。** 本文只讲怎么做，不讲为什么这么设计——那些在 [`introduction.md`](introduction.md)（对用户）和 [`architecture.md`](architecture.md)（对实现者）。
>
> 确切条款——开关语义、配置 schema、命令集、`status` 的最低信息、诊断包的隐私约定——在 [`../spec/interaction.md`](../spec/interaction.md) §27。与它冲突时，错的是本文。

## 装之前确认三件事

- 手机已 root：Magisk、KernelSU 或 APatch 三者之一
- 内核 5.15 或更新
- arm64 处理器

版本号只是入场券。装上之后 Flux 会**实际做一遍**所需的每项内核操作，做不到就明确告诉你是哪一项——不是查版本号了事。

## 装完之后

**装完是关着的，这是故意的。** 管理器里模块显示为已禁用不是装失败，是在等你填配置。

### 1. 填两个文件

都在 `/data/adb/flux-rs/config/`：

| 文件 | 干什么 |
|---|---|
| `flux.toml` | 挑哪些应用走代理、订阅地址。带注释，照着填 |
| `template.json` | 代理配置的**模板**：DNS、路由规则、节点分组的骨架 |

**你编辑模板，不编辑引擎实际跑的那份。** Flux 拿模板加上订阅内容，生成 `run/sing-box.<代数>.json` 交给 sing-box。`config/` 下的都是你的，Flux 永不改写；`run/` 下的都是机器产物，随时可以删掉重建。

这样订阅更新才不需要你手工合并——填空和追加节点是 Flux 的活。

### 2. 自检

```
fluxd check
```

它会校验两份配置并报告这台设备能不能跑。有问题就在这一步说清楚，不用等打开之后猜。

### 3. 在管理器里打开它

**开关就是你 root 管理器里那个模块开关**，Flux 不另做一个。管理器拨动开关时会写一个文件，Flux 直接盯着它，所以**关掉当场生效，不用重启**。管理器原本"下次启动不加载"的意思照旧成立，只是现在它同时也立刻停。

因此没有额外的 Action 按钮要点。命令行 `fluxd enable` / `fluxd disable` 改的是同一个文件，不会出现命令行和管理器界面各说各话。

> 首次安装后需要重启一次，模块才真正加载；之后的开关都是当场生效。

## 看它有没有在工作

不用开终端：管理器里这个模块的描述就是实时状态。

```
Transparent per-app proxying via eBPF and an unmodified official sing-box.
🥰 [Active] gen 7 · 3 apps · rmnet_data0
```

出问题时它会说是哪一种问题，比如 `🤯 [Inactive] unsupported_lpm_trie_kernel:6.6.30`，或者 `😴 [Disabled] toggle this module on to enable Flux`。

要更细的就跑 `fluxd status`。它逐接口报告，包括某个接口为什么被排除——完整示例与怎么读见 [`introduction.md`](introduction.md#状态会直接列出覆盖面)。

## 出问题怎么自救

三条路从轻到重，**任何一条都不需要电脑**：

1. **在管理器里关掉这个模块。** 当场停止新流准入并停 engine，不用重启。内核对象留到 daemon 重建或设备重启。等价命令是 `fluxd disable`。
2. **卸载模块。** 脚本先 `fluxd stop`，再删除状态根，然后按管理器要求重启；重启后非持久内核对象消失。
3. **管理器安全模式 / 关闭全部模块。** 这条**必定恢复**，是最终保证。你应该在装之前就知道它存在。

第 1 条现在只需拨一下管理器里的开关——这是把开关合并进管理器那个文件之后最直接的收益：手机上没有终端也能立刻停用。

卸载脚本**不会**同步 flush 内核网络对象。重启是"零非持久内核残留"承诺的一部分，不是遗漏。

## 代理本身怎么配

Flux 只负责"挑出哪些应用的流量"。挑出来之后怎么走——用哪个服务器、按什么规则——由 [sing-box](https://github.com/SagerNet/sing-box) 负责，Flux **原封不动**用官方版本，不打补丁。

订阅在 `flux.toml` 的 `[subscription]` 里填地址就行，Flux 自己抓取、解析并填进模板的节点分组；`fluxd subscribe` 手动触发一次。抓回来的原始响应存在 `run/subscription.raw`，精修规则（排除公告条目、改名、剥 emoji、截断）都在 `flux.toml` 里，**改这些规则不需要重新联网**。

更新永远先过官方 `sing-box check` 才部署，不过就保留当前配置并报错——订阅更新不会把你的网络搞没。

要用外部控制面板，就在模板里启用 `clash_api`——Flux 只要求控制器监听回环且 secret 非空。管理器里那个按钮会跳过去，URL 自带 secret。

哪些能力现在还没有、计划在后续版本做，以 [`../history/rejected-and-deferred.md`](../history/rejected-and-deferred.md) §21.0 的状态登记为准。
