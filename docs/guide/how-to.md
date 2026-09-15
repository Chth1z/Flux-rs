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
| `flux.toml` | 挑哪些应用走代理，配置手工节点和可选订阅 |
| `template.json` | 代理配置的**模板**：DNS、路由规则、节点分组的骨架 |

**你编辑模板，不编辑引擎实际跑的那份。** Flux 拿模板加上手工节点和可用订阅内容，生成 `run/sing-box.<代数>.json` 交给 sing-box。`config/` 下的都是你的，Flux 永不改写；`run/` 下的都是机器产物，随时可以删掉重建。

这样订阅更新才不需要你手工合并——填空和追加节点是 Flux 的活。

### 2. 在管理器里打开它

**开关就是你 root 管理器里那个模块开关**，Flux 不另做一个。管理器拨动开关时会写一个文件，Flux 直接盯着它，所以**关掉当场生效，不用重启**。管理器原本"下次启动不加载"的意思照旧成立，只是现在它同时也立刻停。

因此没有额外的 Action 按钮要点。命令行 `fluxd enable` / `fluxd disable` 改的是同一个文件，不会出现命令行和管理器界面各说各话。

> 首次安装后需要重启一次，模块才真正加载；之后的开关都是当场生效。

首次启动会把可用节点组成完整配置，交给官方 sing-box 检查，通过后激活。订阅可选：只用手工节点也能运行；同时配置了订阅而暂时下载失败时，只要现有输入仍能生成有效配置，就能激活并显示下载错误。没有可用节点或配置无效时显示 `Inactive` 及具体原因。

## 看它有没有在工作

不用开终端：管理器里这个模块的描述就是实时状态。

```
Per-app proxy: the apps you pick go through sing-box, everything else is left alone.
🥰 [Active] gen 7 · 3 apps · rmnet_data0
```

出问题时它会说是哪一种问题，比如 `🤯 [Inactive] unsupported_lpm_trie_kernel:6.6.30`，或者 `😴 [Disabled] toggle this module on to enable Flux`。

要更细的就跑 `fluxd status`。它逐接口报告，包括某个接口为什么被排除——完整示例与怎么读见 [`introduction.md`](introduction.md#状态会直接列出覆盖面)。

需要诊断配置和设备能力时运行 `fluxd check`。它只检查、不下载订阅；`engine_config_unfilled` 表示手工节点和已有缓存仍无法填充分组。启用前无需先跑这条命令，启动过程会验证完整配置。

## 出问题怎么自救

三条路从轻到重，**任何一条都不需要电脑**：

1. **在管理器里关掉这个模块。** 当场停止新流准入并停 engine，不用重启。内核对象留到 daemon 重建或设备重启。等价命令是 `fluxd disable`。
2. **卸载模块。** 脚本先 `fluxd stop`，再删除状态根，然后按管理器要求重启；重启后非持久内核对象消失。
3. **管理器安全模式 / 关闭全部模块。** 这条**必定恢复**，是最终保证。你应该在装之前就知道它存在。

第 1 条现在只需拨一下管理器里的开关——这是把开关合并进管理器那个文件之后最直接的收益：手机上没有终端也能立刻停用。

卸载脚本**不会**同步 flush 内核网络对象。重启是"零非持久内核残留"承诺的一部分，不是遗漏。

## 代理本身怎么配

Flux 只负责"挑出哪些应用的流量"。挑出来之后怎么走——用哪个服务器、按什么规则——由 [sing-box](https://github.com/SagerNet/sing-box) 负责，Flux **原封不动**用官方版本，不打补丁。

### 手工节点、订阅可以任选或混用

只用手工节点时，在 `flux.toml` 加上：

```toml
[nodes]
list = ["@nodes.txt"]
```

在同目录的 `nodes.txt` 中每行放一条完整分享链接。以下只示意格式，替换成自己的原始链接：

```text
# 整行注释；链接内部的 # 后面是节点名
hysteria2://user%3Apassword@proxy.example.invalid:443?sni=front.example.invalid#US-LA-hy2
```

也可以直接写 `list = ["hysteria2://…", "vless://…"]`，或与 `@nodes.txt` 混写。
列表文件只能是 `config/` 的直接子文件，不能继续引用另一个文件。粘贴原始 URI，不带聊天消息中的花括号或 Markdown 链接包装。

订阅在同一份 `flux.toml` 中按需增加；已有这个表时只改值，不重复声明：

```toml
[subscription]
url = "https://provider.example.invalid/subscription"
interval = 86400
```

只用手工节点时，省略 `[subscription]` 或保持 `url = ""`。`interval = 0` 关闭定时刷新；`fluxd subscribe` 仍可手动抓取，失败后的网络恢复事件也可触发重试。非零刷新计划不会因为一次失败而消失。

**原来的 `outbounds` 菜单保持原样。** 节点名称匹配地区时会进入对应空分组，例如 `US-LA-hy2`。没有地区标识的名字照常保留；你可以在现有菜单里显式引用它，或者自行增加空 `AUTO` 分组接收全部节点。`nodes_unreferenced` 表示节点已加入配置，但没有分组引用它，不会替你改名或重排菜单。

手工节点不会经过机场公告过滤、改名或截断。Hysteria2 的 userinfo 会完整解码，`hy2://` 也可用。转换器无法准确表达的参数会明确报错，例如当前未实现的 VLESS 非 `none` 加密、未知传输，以及 Hysteria2 的 `pinSHA256`、`mport`；不会静默删掉后继续。引擎新特性也可以直接使用原生 sing-box JSON 配置，最终由实际安装的官方引擎检查。

### 抓取和名称整理按职责分开

普通使用只需订阅 URL 和刷新间隔。`timeout`、`retries` 可在 `[subscription]` 中按需填写；排除公告、改名、去 emoji 和截断名称属于 `[subscription.refine]`：

```toml
[subscription.refine]
strip_emoji = false
max_tag_length = 64
rename = [{ match = "旧名称", replace = "新名称" }]
```

省略的项使用内置默认值。无需增加“普通/极客模式”，也无需为这几项再建配置文件。只有长列表用 `@file` 拆出，常用的 `flux.toml` 保持简短。

**旧配置迁移一次：** 把原先 `[subscription]` 中的 `exclude_pattern`、`rename`、`strip_emoji`、`max_tag_length` 移到 `[subscription.refine]` 下；`url`、`interval`、`timeout`、`retries` 留在原表。旧平铺键会报未知配置项；Flux 不会改写你的文件。

抓回来的原始响应保存在 `run/subscription.raw`，只用于当前配置的 URL；换订阅不会混入旧来源。**修改名称整理规则无需重新联网。**

更新永远先过官方 `sing-box check` 才部署，不过就保留当前配置并报错——订阅更新不会把你的网络搞没。

要用外部控制面板，就在模板里启用 `clash_api`。建议控制器监听回环且 secret 非空；Flux 会对不符合这两项的配置给出告警。管理器里那个按钮会跳过去，URL 自带 secret。

哪些能力现在还没有、计划在后续版本做，以 [`../history/rejected-and-deferred.md`](../history/rejected-and-deferred.md) §21.0 的状态登记为准。
