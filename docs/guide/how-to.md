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

### 1. 填好主配置和模板

都在 `/data/adb/flux-rs/config/`：

| 文件 | 干什么 |
|---|---|
| `flux.toml` | 应用、地址、接口、Wi-Fi 选择，以及统一的节点来源 |
| `advanced.toml` | 可选的抓取、名称整理、分组和日志保留策略 |
| `template.json` | 代理配置的**模板**：DNS、路由规则、节点分组的骨架 |

**你编辑模板，不编辑引擎实际跑的那份。** Flux 拿模板加上手工节点和可用订阅内容，生成 `run/sing-box.<代数>.json` 交给 sing-box。运行中的 daemon 只读取 `config/`；安装升级时可进行一次结构迁移并保留原件。日志、缓存、生成配置和默认诊断包归 `run/`。它跨重启保留；不要删除运行中 daemon 的锁和 socket。

此前 Rust 版本若使用 `flux_rs` 模块 id，本次安装会迁移到 `Flux-rs`，保留配置和管理器开关，并把旧 Rust 模块交给管理器在重启时移除。旧模块的启动、卸载入口会先退出，避免再次运行旧程序或删除已经移交的配置。旧版 shell Flux 不参与这次迁移。

这样订阅更新才不需要你手工合并——填空和追加节点是 Flux 的活。

### 2. 在管理器里打开它

**开关就是你 root 管理器里那个模块开关**，Flux 不另做一个。管理器拨动开关时会写一个文件，Flux 直接盯着它，所以**关掉当场生效，不用重启**。管理器原本"下次启动不加载"的意思照旧成立，只是现在它同时也立刻停。

因此没有额外的 Action 按钮要点。命令行 `fluxd enable` / `fluxd disable` 改的是同一个文件，不会出现命令行和管理器界面各说各话。

> 首次安装后需要重启一次，模块才真正加载；之后的开关都是当场生效。

首次启动会把可用节点组成完整配置，交给官方 sing-box 检查，通过后激活。订阅可选：只用手工节点也能运行；同时配置了订阅而暂时下载失败时，只要现有输入仍能生成有效配置，就能激活并显示下载错误。没有可用节点或配置无效时显示 `Inactive` 及具体原因。

## 看它有没有在工作

不用开终端：管理器里这个模块的描述就是实时状态。

```
Seamlessly redirect your network Flux.
🥰 [RUNNING] PID: 1234 · 黑名单 · 排除清单 3 项 · rmnet_data0
```

出问题时它会说是哪一种问题，比如 `🤯 [FAILED] unsupported_lpm_trie_kernel:6.6.30`，或者 `😴 [STOPPED] 已停止`。

`RUNNING` 表示本地接管已就绪，不证明节点或互联网可达。配置更新被拒绝时，正在运行的旧代可继续显示 `RUNNING` 并附上更新错误。

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

### 一个节点来源列表

`flux.toml` 的 `[nodes]` 同时接收订阅和手工节点：

```toml
[nodes]
sources = [
  "https://provider.example.invalid/subscription",
  "@nodes.txt",
]
```

只用手工节点就删除订阅项；只用订阅就删除本地文件项。也可以直接放完整的 `hysteria2://…`、`vless://…` 等分享链接。多个订阅按来源顺序合并，相同 URL 只取第一次；手工节点保持名称，不经过机场公告过滤或改名。来源间重名会报告冲突位置，不自动覆盖或重命名。

`nodes.txt` 在同一个目录，每行一条手工 URI：

```text
# 只有整行注释；链接内部 # 后面是节点名
hysteria2://user%3Apassword@proxy.example.invalid:443?sni=front.example.invalid#US-LA-hy2
```

文件只能是 `config/` 的直接子文件，不能递归引用。粘贴原始 URI，不要连同 Markdown 链接包装一起复制。

HTTP(S) 字符串代表订阅。手工 HTTP 代理用明确的对象写法：

```toml
[nodes]
sources = [{ node = "http://user:password@proxy.example.invalid:8080#HTTP" }]
```

本地节点文件里的 HTTP URI 本来就是手工节点，无需额外包装。

**原有出站菜单保留。** 自带模板的 `PROXY` 指向地区组。例如节点名含 `US`，便可在原有菜单里选择 `US`。没有匹配节点的空地区组填为 `DIRECT`。未被菜单引用的节点会显示 `nodes_unreferenced`；可以自行引用其名称或添加空 `AUTO` 分组。

分享 URI 无法准确转换的字段会报错，例如尚未支持的 VLESS 非 `none` 加密、未知传输或 Hysteria2 的 `pinSHA256`、`mport`。不会删除字段后冒充支持。原生 sing-box JSON 则由实际安装的官方引擎校验。

### 常用选择与进阶策略分开

四个流量选择维度默认都是 `blacklist`、空清单。`apps` 空黑名单会选择已安装的普通应用；系统 UID 和 root 的边界不变。需要只选少量应用时，显式填写：

```toml
[apps]
mode = "whitelist"
list = ["0:com.example.browser"]
```

缺失 `flux.toml` 是配置错误；删除文件不会让默认黑名单扩大接管。

`advanced.toml` 可省略。首装提供带注释的参考文件，常见自定义如下：

```toml
[nodes.fetch]
interval = 0       # 关闭定时刷新，仍可手动刷新或在网络恢复时重试
timeout = 10
retries = 2
user_agent = ""    # 空值使用内置 UA

[nodes.refine]
strip_emoji = false
max_tag_length = 64
rename = [{ match = "旧名称", replace = "新名称" }]

[nodes.groups]
HK = "香港|Hong Kong|HK"

[log]
max_size_mib = 4
retain = 1
```

省略项使用内置默认值。分组正则匹配节点的最终名称，不区分大小写；写了某个地区就替换该地区规则，其余内置规则保留。只填现有空分组，不创建菜单。`PROXY`、`GLOBAL`、`AUTO` 始终收全部节点。日志在实际写入时轮转，`retain = 0` 仅留当前文件。

两份 TOML 没有重叠字段和覆盖优先级。DNS、路由、TLS、出站和引擎日志直接使用 `template.json` 的原生字段；不在进阶文件里重复包装。

### 升级与运行文件

安装器保留当前配置和模板。旧 Rust 配置的 `nodes.list`、`subscription.url` 合并进 `nodes.sources`，抓取和名称整理移到进阶文件；旧的隐式 whitelist 在可识别的旧安装上被显式保留。迁移前的原件在 `run/migrations/`，失败时提示冲突字段。已经使用新结构的配置保持字节不变。模板始终原样保留。

每个远端来源只有一个 `run/cache/sources/<来源标识>.raw`，没有配套 URL 文件或清洗结果缓存。来源换序可复用缓存，换 URL 不会串用旧响应。名称整理和分组修改可以离线重建。只有通过正常验证和激活的响应才替换缓存；某个来源失败仍会尝试其余来源，错误会继续显示。

`fluxd subscribe` 手动刷新所有远端来源；默认每天刷新一次。失败不会取消非零刷新计划。生成结果相同则不重启引擎，候选检查不通过则保留当前代。

模块 ID 为 `Flux-rs`，命令位于 `/data/adb/modules/Flux-rs/bin/fluxd`。许可证和构建说明随发行 ZIP 提供，设备只安装运行所需文件及配置参考；运行日志是 `run/fluxd.log`，默认引擎缓存是 `run/cache/sing-box.db`。模板里显式指定的非空缓存路径及其它相对路径保持原有含义。

要用外部控制面板，就在模板里启用 `clash_api`。建议控制器监听回环且 secret 非空；Flux 会对不符合这两项的配置给出告警。管理器里那个按钮会跳过去，URL 自带 secret。

开启后在校园网无法联网，或希望借鉴 Clash-Config 的 DNS、分流策略时，见 [`校园网排查与参考配置适配`](network-policy.md)。

哪些能力现在还没有、计划在后续版本做，以 [`../history/rejected-and-deferred.md`](../history/rejected-and-deferred.md) §21.0 的状态登记为准。
