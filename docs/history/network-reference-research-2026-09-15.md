# 网络参考研究：配置适配、协议字段与校园认证

**研究日期：2026-09-15。结论：参考仓库可提供 sing-box 策略的组织方式，但其配置不能直接成为 Flux 的默认配置；校园网现象尚无已证实根因。** 本次仅阅读第一方源码、文档与现有源码克隆，没有访问设备、连接节点或使用真实订阅凭据。本文是当日证据记录与适配建议，不新增产品合同；最终设计仍以 `../spec/` 为准。

## 当日版本与证据范围

**当日已确认事实：官方 GitHub `releases/latest` 返回 `v1.14.1`，发布时间为 `2026-09-15T00:06:50Z`，`prerelease=false`、`draft=false`。** 本次先详细核对了已有的 1.13.19 源码，再对当前稳定版 1.14.1 的相关选项与实现作有界复核。[发布 API][sb-latest-api]、[1.14.1 发布页][sb-latest-release]。

用户当日明确要求项目不锁定 sing-box 或其它依赖，默认跟随最新稳定版。下列版本与提交仅使研究证据可复核，不是项目依赖锁定要求；“1.13.19 已核对”也不等于“1.14.1 已运行测试”。模板原有 `outbounds` 保持用户给出的内容，研究建议不授权转换器改写其菜单或节点对象。

| 来源 | 本次使用的版本或提交 | 核对方式 |
|---|---|---|
| Niklaus88/Clash-Config | `589628799323e4b88f861dd3aba29f028018b6e5` | `git ls-remote` 确认当日 main，随后读取固定提交的 JSON、YAML、两个 JS 脚本与 LICENSE |
| 官方 sing-box，原有核对基线 | `1.13.19`，`b5ebaa1fc0f2b94256180b95468e73ef53caa27d` | 研究开始时的 `../../engine.lock` 记录与本地克隆 HEAD 一致；不延续为锁版策略 |
| 官方 sing-box，当日最新稳定版 | `1.14.1`，`1ac1a339cb1223e9c70eae14c44411c75033c02d` | 官方发布 API 与 `git ls-remote` 标签；复核相关源码，未运行该版本二进制 |
| 官方 Hysteria | `e1366b173ccf5706e1e4630fe8aa654a4b574085` | `git ls-remote` 确认当日 master，读取固定提交的 URI parser；协议说明另见官方 URI 文档 |
| AOSP Connectivity | `2519a78731526d2eb20ae8812acdcab6ef7a09b6` | 本地固定克隆 HEAD |
| AOSP DnsResolver | `4d70e9efa5ae4b5eae682e5267fa09a2d694d23e` | 本地固定克隆 HEAD |
| AOSP NetworkStack | main 页面记录的 `83ea07ed94890b52265e07d6760c7ed8f4cbd344`；`NetworkMonitor.java` blob `3ae8557f5ab560f60aa83f0cc1c4d025e272438d` | 官方 Gitiles 的提交页面与源码页面 |
| AOSP CaptivePortalLogin | main 页面记录的 `8c97766cbe1763840181f66e5960b5d3ac0a4d66` | 官方 Gitiles 的提交页面与源码页面 |

AOSP 的两份在线 main 快照提交日期分别为 2025-03-23、2025-03-25；它们用于证明代码中的机制分层，不代表用户设备的 Android/OEM 版本。本次没有取得设备版本或厂商认证实现。[NetworkStack 提交][aosp-nm-commit]、[CaptivePortalLogin 提交][aosp-cpl-commit]。

## 先处理可确定的协议兼容性

### VLESS 非 none encryption 在两份已核对版本中不受支持

**源码事实：sing-box 1.13.19 没有 VLESS `encryption` 配置字段，也没有对应的客户端构造参数。** `option/vless.go:17–27` 的 outbound 字段包括 UUID、flow、TLS、transport、multiplex 与 packet_encoding；`protocol/vless/outbound.go:91` 调用 `vless.NewClient(options.UUID, options.Flow, logger)`。因此 `encryption=mlkem768x25519plus.native.0rtt...` 无法原义转换到这份官方引擎。[选项][sb-vless-option]、[构造][sb-vless-outbound]。

**文档事实：该字符串是 Xray 的 VLESS Encryption 设置，不能当作 `packet_encoding` 或 TLS 曲线名称。** Xray 官方文档将其定义为以点连接的握手、外观、恢复等配置。sing-box 的 `packet_encoding` 构造只接受空值、`packetaddr`、`xudp`。[Xray VLESS 文档][xray-vless]、[sing-box packet encoding 分支][sb-vless-outbound]。

**当前稳定版复核：** 1.14.1 的 `VLESSOutboundOptions` 仍没有 `encryption` 字段；升级到当日稳定版未消除上述兼容性限制。[1.14.1 VLESS 选项][sb14-vless-option]。

**适配建议（推断）：** 对明确的非 `none` encryption 给出含字段与实际引擎版本的兼容性错误，保留当前运行代；不跳过坏节点后部分应用当前候选。不要删掉字段后把它计为兼容节点，也不要用节点名字或地区代替协议判断。URI 缺省或 `none` 可按普通 VLESS 语义处理，输出时无需制造引擎不存在的 encryption 字段。配置检查成功仅证明配置被接受，不能证明节点的网络连通性。

### Hysteria2 auth 必须保留完整内容

**源码与文档事实：Hysteria2 的 URI auth 是整体认证值；userpass 形式仍需把冒号与密码保留下来。** 官方 URI 说明要求特殊字符百分号编码；官方 parser 在存在 URL password 时拼回 `username + ":" + password`，否则使用解码后的 username。[URI 说明][hy-uri]、[app/cmd/client.go:550–585][hy-parser]。

下列均为文档专用合成值，未连接任何服务：

| URI 的 userinfo | 转换后的 sing-box `password` |
|---|---|
| `demo%3Apa%3Ass` | `demo:pa:ss` |
| `demo:pa%3Ass` | `demo:pa:ss` |
| `a%253Ab` | `a%3Ab`，只解码一次 |

**源码事实与对应映射：** `option/hysteria2.go:112–124` 用一个 `password` 字符串保存认证；`protocol/hysteria2/outbound.go:44–81` 要求 TLS，并把该字符串直接交给客户端。[Hysteria2 选项][sb-hy-option]、[Hysteria2 构造][sb-hy-outbound]。

| URI 项 | sing-box 1.13.19 映射或边界 |
|---|---|
| `hysteria2` / `hy2` | outbound `type: "hysteria2"`；URI 没有端口时协议默认 443 |
| `sni` | `tls.server_name` |
| `insecure=1` / `0` | `tls.insecure: true` / `false`；原值决定证书验证策略，转换器不统一改写 |
| `obfs=salamander` 与 `obfs-password` | `obfs: {"type":"salamander","password":"..."}`；空密码被引擎拒绝 |
| 无 obfs | 省略 `obfs` 对象 |
| `obfs=gecko` | 1.13.19 不支持；当日稳定版 1.14.1 已支持，不能把旧版限制写成永久拒绝规则 |
| 其它未知 obfs 类型 | 已核对的两个版本均在 switch 的 default 分支报错；不能静默变成无混淆 |

端口与 URI 布尔值来自[官方 URI 说明][hy-uri]；SNI、insecure 来自[官方 parser][hy-parser]；obfs 差异见 [1.13.19 switch][sb-hy-outbound] 与 [1.14.1 switch:58–74][sb14-hy-outbound]。此处说明引擎能力，不代替具体 URI 扩展参数的逐项转换与配置检查。

**另一个不能改名搬运的字段是 `pinSHA256`。** Hysteria 对 leaf 证书原始 DER 求 SHA-256；sing-box `certificate_public_key_sha256` 对 `x509.MarshalPKIXPublicKey` 产生的公钥 SPKI 编码求摘要。二者不是同一个值，转换器若没有精确实现原语义，就应报告不支持，不能直接映射字段名。1.14.1 仍使用公钥摘要。[Hysteria client.go:362–378][hy-pin]、[1.13.19 std_client.go:223–239][sb-pin]、[1.14.1 std_client.go:267–282][sb14-pin]。

**适配建议（推断）：** 将节点来源、结构清洗和模板策略分开。入口与地区分组按用户模板原有菜单处理，保留模板原始 `outbounds`；不依据本研究增加分组、改写菜单或重排节点对象。某个名称包含地区、流量或日期，并不能从上述协议证据推出节点是否能工作。

## Clash-Config 能继承什么

**源码事实：固定参考的 `sing-box.json` 自称面向 1.14.0+，同时包含 `http_clients`、`route.default_http_client`、TUN `auto_route/strict_route`、额外 mixed 监听、公共 DoH、FakeIP、策略组与远端规则集。** 它还按端口和含 `stun` 的域名拦截，并将 `gstatic.com` 等域整体送代理。[sing-box.json:1–103、356–418][ref-sb]。

**源码事实：Clash YAML/JS 属于另一种配置接口。** YAML 的 `respect-rules`、`proxy-server-nameserver`、`fake-ip-filter`、`proxy-providers` 等不能按键名移进 sing-box。通用 JS 直接覆盖 DNS、sniffer、代理组和规则，并给现有节点设 `udp = true`；iOS JS 还夹带 Apple 更新域名拦截。[YAML:22–77][ref-yaml]、[通用脚本:246–416][ref-js]、[iOS 脚本:63–121][ref-ios]。

| 参考做法 | Flux 适配判断 |
|---|---|
| selector、按服务分流、remote binary rule-set | 可作为用户 sing-box 策略；按用户模板原有引用关系处理，不改原始 `outbounds` |
| 代理 DNS 的显式 detour、单独的节点域名解析器 | 1.13.19 可表达；能避免解析代理节点本身又依赖同一代理，但不能证明认证前公共 DNS 或节点可达 |
| `action: sniff`、`protocol: dns` + `action: hijack-dns`、新式 HTTPS/FakeIP DNS | 1.13.19 有对应实现；仅作用于已经进入 sing-box 的流量 |
| `default_domain_resolver` 字符串简写 | 1.13.19 已支持，不是 1.14 独有字段 |
| `http_clients`、`route.default_http_client` | 1.13.19 没有，若专门适配旧版可用 remote rule-set 的 `download_detour` 表达下载出口；1.14.1 已支持，不应按旧版限制从当前稳定版模板删除 |
| `type: block` outbound | 1.13.19 与 1.14.1 均仍注册，不能误报“1.13 已移除”；本任务保留模板原有 outbound |
| TUN、auto_route、strict_route、额外 mixed 监听 | 不移植到 Flux；捕获入口由 Flux 的 TProxy 机制产生 |
| Clash JS 的 `udp = true`、图标、探测参数、iOS 更新拦截 | 没有一键迁移含义；更不能据此宣称远端节点支持 UDP 或手机无泄漏 |

旧版判断依据：[option/options.go:12–36][sb-options]、[option/route.go:5–22][sb-route-options]、[DomainResolveOptions:118–132][sb-domain-resolver]、[rule-set 选项:123–127][sb-ruleset-options]、[block 注册][sb-registry]、[sniff 实现][sb-sniff]。当前稳定版证据：[1.14.1 顶层选项:13–29][sb14-options]、[route 选项:4–22][sb14-route-options]、[block 注册:82][sb14-registry]。

**适配结论（推断）：** 参考配置所列两项明确的 1.14 字段在当日稳定版已有对应选项，不能据其使用 1.14 特性就判定不可用。其 TUN/mixed 入口仍不符合 Flux 的 TProxy 捕获模式；DNS 与分流策略仍需按下文的环境边界评估。本次没有运行整份参考配置，不能据选项存在宣称完整配置已通过 `check`。上表是当日可行性分析，不要求 Flux 新增开关、另建规则引擎或自动改写用户模板。

**许可事实：上游是 MIT，署名 `Copyright (c) 2026 Niklaus88`。** 许可允许复制修改，但副本或实质部分需保留 copyright 与 permission notice，且许可不提供效果保证。后续若复制实质配置或脚本，应随实际分发物保留该通知；外链规则集和图标的许可证不由这份 MIT 自动覆盖。[固定 LICENSE:1–19][ref-license]。

## DNS 与所谓 WebRTC 防泄漏的真实边界

**结论（推断）：只能描述规则实际覆盖的流量，不能承诺“彻底防泄漏”。** 前提是 Flux 只捕获选中 UID，且 Android DNS 存在不同 socket 身份；对未选中应用的流量，本来就没有修改授权。AOSP 明文 DNS 的 socket 在常规分支归到请求 UID，另有 `enforce_dns_uid` 分支；Private DNS 的 TLS socket 用 `AID_DNS`。因此不能从“DNS 被引擎劫持”推出系统所有 DNS 都走了代理。[res_send.cpp:789–790、1092–1093][aosp-res-send]、[resolv_private.h:253–255][aosp-res-tag]、[DnsTlsSocket.cpp:82][aosp-dot]。

**标准事实：STUN 的 3478/5349 是默认端口，URI 允许显式指定其它端口；ICE 还存在本机接口候选和中继候选。** 因此拦截固定端口及域名关键词不覆盖所有 STUN，也不能阻止应用通过信令传送它已经知道的地址。[RFC 7064，3.1–3.2][rfc-stun]、[RFC 8445，5.1.1][rfc-ice]。

**源码事实：sing-box 1.13.19 默认 UDP sniff 包含 STUN 检测，但它只识别所见数据包。** 检测器检查 STUN magic cookie、长度并标记 protocol；它不是浏览器 ICE API 的控制器。[route/route.go:642–650][sb-sniff]、[common/sniff/stun.go:12–24][sb-stun]。

**适配建议（推断）：** 不默认加入整组 STUN/UDP 端口拒绝。用户选择限制 WebRTC 时，可用可解释的 sing-box `protocol: stun`/端口策略，并说明可能使通话、会议、游戏连接失败；它仍不覆盖加密封装或仅通过信令暴露的候选。参考脚本专门给检测网站走代理，单个检测网页通过也不能证明其它目的地适用相同路径。[参考脚本:185–205][ref-js]。

## 校园网：local DNS 不能简单替代校园 DNS

**源码事实：官方 1.13.19 的裸 CLI `type: local` 没有走 Bionic/netd 的解析路径。** 非 Darwin 的 `local.go:82–93` 在 hosts 未命中后调用 `local_shared.go:19–25`；后者经 `resolv.go:23–29` 读取 `/etc/resolv.conf`，再自行发 UDP/TCP。读取失败时走 Go 的 `defaultNS` 回退，并不会读取 Android 的 LinkProperties。Linux 的 systemd-resolved 分支也不是 Android DNS 接口。[local.go][sb-local]、[local_shared.go][sb-local-shared]、[resolv.go][sb-resolv]、[resolv_unix.go:17–28][sb-resolv-unix]。

**源码与文档事实：图形客户端另有平台注入。** `experimental/libbox/config.go:25–37` 只有取得平台 `LocalDNSTransport` 才覆盖 local 注册；1.13.19 文档也明确 Android 图形客户端使用平台 DNS。旧版 `address: local` 文档关于 CGO 的说明，不能证明新版 `type: local` 裸 CLI 使用了系统 DNS。[libbox 注册][sb-libbox-dns]、[1.13.19 local 文档:49–54][sb-local-doc]。

**1.14.1 复核边界：** 当前文档仍明确 Android 图形客户端通过平台接口解析，理由是没有其它方式取得上游 DNS。源码已重构为 `configSource` 与 `systemconfig`，`local_shared.go` 从配置生成独立 UDP/TCP DNS transport；本次未追完 1.14.1 Android 构建的系统配置读取全链路，也未做裸 CLI 运行验证。因此，不能把 1.13.19 的文件路径细节未经核对套用到 1.14.1，也没有证据支持“换成 local 就能自动使用校园 DNS”。[1.14.1 local 文档:50–54][sb14-local-doc]、[local.go:43–60、140–160][sb14-local]、[local_shared.go:24–76][sb14-local-shared]。

**适配建议（推断）：** 不能把默认 DoH 改成 `type: local` 后宣称已恢复校园分配的 DNS。若用户确认了 DNS 服务器地址或认证应用，可让相关原始 DNS 连接在 `hijack-dns` 前走 DIRECT，从而保留它的原目的地址；若要按“查询的域名”分流到校园 DNS，则还需要一个已知可用的校园 DNS server 来源。

**这里存在一个容易写错的边界：** DNS sniff 只设置 `metadata.Protocol`，没有将 question name 填到 route 的 `Domain`。所以 `route.domain_suffix` 加 `protocol: dns` 不是按 DNS 查询域名旁路的可靠办法；查询域名属于 `dns.rules` 的匹配层。[common/sniff/dns.go:48–56][sb-dns-sniff]。上述 DIRECT 连接也仍由引擎新建，不能额外承诺保留 Android 原请求的 Network 绑定。

## 认证恢复不等于默认路由事件

**源码事实：Android 把 DNS/HTTP 探测、认证页面、VALIDATED 能力和默认网络选择分开处理。** NetworkMonitor 的探测 Network 使用 Private DNS bypass；`sendDnsAndHttpProbes` 先查 DNS 再发 HTTP，HTTPS 探测有单独组合逻辑；关闭认证页面会发 `CMD_FORCE_REEVALUATION`。这些代码不是 rtnetlink 默认路由事件的别名。[NetworkMonitor.java:1050–1070、2343–2347、2940–3000、3189–3200][aosp-nm]。

**源码事实：能力变化不保证发生网络切换。** ConnectivityService 在验证结果变化时更新 VALIDATED 和 capability；`processDefaultNetworkChanges` 只对真实的 network reassignment 调用 `makeDefault`，后者才调用 netd 的 `networkSetDefault`。[ConnectivityService.java:5089–5094、10592–10602、11342–11353、11508–11517][aosp-cs]。

**源码事实：认证 WebView 有特定网络语义。** CaptivePortalLogin 从 intent 取得目标 Network，使用其 Private DNS bypass copy，并在 WebView 初始化时 `bindProcessToNetwork(mNetwork)`；这不能简化成“所有认证连接都使用系统当前默认出口”。[CaptivePortalLoginActivity.java:548–555、673–678][aosp-cpl]。

**推断：** 校园认证放行可以只改变网关侧状态及 Android capability，设备的接口、地址、默认路由仍保持不变。因而“等默认路由事件再恢复引擎”不能保证涵盖认证完成；反过来，仅凭开启 Flux 后失败，也不能证实引擎没有恢复、DNS 被污染、QUIC 被阻止或网卡识别错误中的任何一种。

以下是需要现场证据区分的候选，不是已确认根因：

| 候选 | 成立所需前提 | 能区分它的证据 |
|---|---|---|
| 认证 DNS 路径被公共 DoH/FakeIP 替代 | 相关 UID 被捕获，且门户依赖校园 DNS 的回答或重定向 | 选中 UID、DNS 原目的、命中规则、认证域名在两条解析路径的结果 |
| 认证 HTTP 被送到代理出口 | 认证应用或浏览器被选中，规则把相关目的送代理 | 实际捕获 UID、引擎 rule/outbound 与门户访问结果 |
| 原 Network 绑定在代理新连接时改变 | 应用绑定校园 Wi-Fi，而 root 引擎的新连接采用其它默认接口 | 同时记录系统默认网络、认证目标 Network、引擎实际出口 |
| 认证后没有触发预期恢复动作 | 网络已放行，但仅能力变更或旧连接/缓存仍失败 | 同一时段的认证结果、路由事件、引擎错误；不能仅凭重启后恢复倒推原因 |

**适配建议（推断）：** 认证所需域名应先有证据，再在用户 sing-box 策略中配置其解析与出口。公共 DoH、全量 FakeIP、把 `gstatic.com` 整域送代理、硬编码 hosts 都可能改变门户预期路径；固定参考没有 `GoogleHosts`，不能把其它配置中的硬编码地址归到该提交。统一设置 `tls.insecure=true` 只改变证书验证，不能修复 DNS、Network 绑定或认证流程。[参考路由][ref-sb]、[TLS 验证分支:94–120][sb-tls]。

## Android 裸 CLI 的 wifi_ssid 不是图形客户端能力

**源码与文档事实：1.13.19 的 Android Wi-Fi 状态支持明确限于图形客户端。** CLI 的 Linux 后备依次尝试 NetworkManager、IWD、wpa_supplicant、ConnMan；其中 wpa_supplicant 实际寻找 `/var/run/wpa_supplicant`、`/run/wpa_supplicant` 的控制 socket，其它后台依赖 D-Bus。此路径不包含 Android Framework 的 Wi-Fi bridge。[Wi-Fi 支持表][sb-wifi-doc]、[wifi_linux.go:12–27][sb-wifi-linux]、[wifi_linux_wpa.go:29–57][sb-wifi-wpa]。

**源码事实：** `route/network.go:195–208` 的 monitor 创建失败仅发警告；无本地 monitor、也无平台 interface 时 `UpdateWIFIState` 直接返回。`wifi_ssid` 匹配读取的是该 network manager 的 Wi-Fi 状态，而不是 Flux 已知的 SSID。[network.go:445–454][sb-network]、[wifi_ssid matcher][sb-wifi-rule]。

**适配建议（推断）：** 不向 Flux 默认模板注入依赖裸 CLI 自动取得 Android SSID 的路由规则。Flux 已有 SSID 条件激活应继续从自己的已定义事件源取得事实；若未来要让引擎使用同一事实，应先设计清楚派生接口，不能认为两进程自动共享状态。非标准 Android 若额外提供兼容的 Linux Wi-Fi daemon，属于另一套需要验证的环境，不是当前承诺。

### network_strategy 也依赖图形客户端的平台接口

**1.14.1 文档与源码事实：** `network_strategy` 的文档支持范围是 Android/Apple 图形客户端，且要启用 `auto_detect_interface`。`common/dialer/default.go:99–120` 仅在非空 `platformInterface` 且 `UsePlatformNetworkInterfaces()` 为真时装载该策略；否则走普通自动接口绑定分支。因此不能把 `network_strategy` 与 `bind_interface`、Linux `routing_mark` 并列成裸 CLI 用户都可依赖的多网络出口方案。[1.14.1 Dial 文档:184–209][sb14-dial-doc]、[DefaultDialer:99–124][sb14-dialer]。本次未运行多网卡或认证恢复试验。

## 当日建议的边界

**PHIL-10 复核结论（推断）：** 协议转换修正解决外部输入的真实差异；DNS、WebRTC、服务分流保持在 sing-box 策略层；TProxy 入口与 UID 选择仍由 Flux 的机制掌握。以上建议不需要新增轮询、不需要修改系统 DNS 或默认路由、不需要补丁引擎，也不通过维护第二份节点名单或 SSID 真相源解决问题。

本次完成的是源码核对。未执行设备验证、真实网络探测或整份上游配置的运行测试。后续生成的配置仍需经过实际采用的官方稳定版 `check`，并记录此次检查版本；不把一次检查版本变成项目永久锁版。校园网恢复效果只能由授权现场的分层证据确认。

[sb-latest-api]: https://api.github.com/repos/SagerNet/sing-box/releases/latest
[sb-latest-release]: https://github.com/SagerNet/sing-box/releases/tag/v1.14.1
[sb14-vless-option]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/vless.go#L16-L26
[sb14-hy-outbound]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/protocol/hysteria2/outbound.go#L58-L74
[sb14-pin]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/tls/std_client.go#L267-L282
[sb14-options]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/options.go#L13-L29
[sb14-route-options]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/route.go#L4-L22
[sb14-registry]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/include/registry.go#L82
[sb14-local-doc]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/dns/server/local.md#L50-L54
[sb14-local]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/dns/transport/local/local.go#L43-L60
[sb14-local-shared]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/dns/transport/local/local_shared.go#L24-L76
[sb14-dial-doc]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/shared/dial.md#L184-L209
[sb14-dialer]: https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/dialer/default.go#L99-L124

[ref-sb]: https://github.com/Niklaus88/Clash-Config/blob/589628799323e4b88f861dd3aba29f028018b6e5/sing-box.json
[ref-yaml]: https://github.com/Niklaus88/Clash-Config/blob/589628799323e4b88f861dd3aba29f028018b6e5/clash-config.yaml
[ref-js]: https://github.com/Niklaus88/Clash-Config/blob/589628799323e4b88f861dd3aba29f028018b6e5/clash-script.js
[ref-ios]: https://github.com/Niklaus88/Clash-Config/blob/589628799323e4b88f861dd3aba29f028018b6e5/clash-ios-script.js
[ref-license]: https://github.com/Niklaus88/Clash-Config/blob/589628799323e4b88f861dd3aba29f028018b6e5/LICENSE
[sb-vless-option]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/vless.go#L17-L27
[sb-vless-outbound]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/vless/outbound.go#L78-L99
[xray-vless]: https://xtls.github.io/config/outbounds/vless.html#outboundconfigurationobject
[hy-uri]: https://v2.hysteria.network/docs/developers/URI-Scheme/
[hy-parser]: https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L550-L585
[hy-pin]: https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L362-L378
[sb-hy-option]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/hysteria2.go#L112-L124
[sb-hy-outbound]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/hysteria2/outbound.go#L42-L82
[sb-pin]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L223
[sb-options]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/options.go#L12-L36
[sb-route-options]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/route.go#L5-L22
[sb-domain-resolver]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/outbound.go#L118-L132
[sb-ruleset-options]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/rule_set.go#L123-L127
[sb-registry]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/include/registry.go#L72-L80
[sb-sniff]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/route/route.go#L586-L650
[sb-stun]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/sniff/stun.go#L12-L24
[aosp-res-send]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/res_send.cpp#789
[aosp-res-tag]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/resolv_private.h#253
[aosp-dot]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsSocket.cpp#82
[rfc-stun]: https://www.rfc-editor.org/rfc/rfc7064.html#section-3
[rfc-ice]: https://www.rfc-editor.org/rfc/rfc8445.html#section-5.1.1
[sb-local]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/local/local.go#L82-L94
[sb-local-shared]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/local/local_shared.go#L19-L25
[sb-resolv]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/local/resolv.go#L23-L29
[sb-resolv-unix]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/local/resolv_unix.go#L17-L28
[sb-libbox-dns]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/experimental/libbox/config.go#L25-L37
[sb-local-doc]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/docs/configuration/dns/server/local.md#L49-L54
[sb-dns-sniff]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/sniff/dns.go#L48-L56
[aosp-nm-commit]: https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344
[aosp-nm]: https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/NetworkMonitor.java
[aosp-cs]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/service/src/com/android/server/ConnectivityService.java#5089
[aosp-cpl-commit]: https://android.googlesource.com/platform/packages/modules/CaptivePortalLogin/+/8c97766cbe1763840181f66e5960b5d3ac0a4d66
[aosp-cpl]: https://android.googlesource.com/platform/packages/modules/CaptivePortalLogin/+/8c97766cbe1763840181f66e5960b5d3ac0a4d66/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
[sb-tls]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L94-L120
[sb-wifi-doc]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/docs/configuration/shared/wifi-state.md#L14-L35
[sb-wifi-linux]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/settings/wifi_linux.go#L12-L27
[sb-wifi-wpa]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/settings/wifi_linux_wpa.go#L29-L57
[sb-network]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/route/network.go#L445-L454
[sb-wifi-rule]: https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/route/rule/rule_item_wifi_ssid.go

## 同日补充：1.14.1 bare CLI 的系统 DNS 配置来源

主代理在研究稿封板后补齐了普通 local transport 的新读取链。**源码事实：** `systemconfig/source_resolv.go` 的构建条件为 `!windows && !(darwin && cgo)`，包含 Android；第 21 行固定读取 `/etc/resolv.conf`，第 34–42 行初始化并提供这份配置。文件无法读取时，第 88–92 行采用 `defaultServers`；`config.go:17–20` 将其定义为 IPv4/IPv6 loopback 的 53 端口。`local_shared.go:25–42、63–76` 再按这份 server 列表建立独立 UDP/TCP transport。该普通 CLI 路径没有从 Android LinkProperties 获得校园 DNS，也不是 Bionic `getaddrinfo`。这补齐了上文 1.14.1 未追完的源码范围；仍未进行 Android 实机运行验证。

依据：[source_resolv.go](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/dns/transport/local/systemconfig/source_resolv.go#L1-L42)、[config.go](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/dns/transport/local/systemconfig/config.go#L17-L20)、[local_shared.go](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/dns/transport/local/local_shared.go#L25-L76)。

## 同日补充：1.14.1 与捕获机制衔接的源码范围

主代理逐行核对了当前稳定版的 TProxy 入站、TCP/UDP listener 及 Linux redir 辅助函数。**源码事实：** `protocol/redirect/tproxy.go:92–116` 的 TCP 目的地址来自接受连接的 `LocalAddr`，UDP 目的地址来自 `GetOriginalDestinationFromOOB`；后者在 `common/redir/tproxy_linux.go:43–55` 区分 IPv4/IPv6 orig-dst 控制消息。两条监听路径仍进入 `redir.TProxy`，设置 REUSEADDR、TRANSPARENT 和 UDP 原目的地址选项；这些已读路径没有设置 REUSEPORT。Flux 注入的四个字段没有启用额外的 bind_interface、routing_mark、ReuseAddr、FastOpen 或 MPTCP 分支。

依据：[TProxy 入站](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/protocol/redirect/tproxy.go#L92-L116)、[Linux socket 选项与 OOB](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/redir/tproxy_linux.go#L14-L55)、[TCP listener](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/listener/listener_tcp.go#L22-L74)、[UDP listener](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/listener/listener_udp.go#L23-L54)。这不是全依赖树的负面搜索，也没有执行 Android 上的 assign 或原目的地址测试；实际设备断言仍需运行本次候选。
