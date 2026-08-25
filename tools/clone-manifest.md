# 研究用克隆清单

`clone/` 是**开发辅助资产**：设计里几乎每一条关于 AOSP、内核和同类实现的断言，依据都在这里。

**但第三方源码不进 git。** 进 git 的是这份清单——它能把 `clone/` 完整重建，同时避免三件事：仓库膨胀（约 80 MB）、许可证与来源混杂、以及"新代码抄了旧第三方实现"的嫌疑。`clone/` 由 `.gitignore` 排除。

重建：`tools/reclone.sh`（在 WSL 或 Linux 上跑）。

## 清单（截至 2026-08-25）

固定 commit 是有意的：内核与 AOSP 的语义随版本变，`§4.2.3` 这样的引用只有在 commit 固定时才有意义。

| 目录 | 仓库 | commit |
|---|---|---|
| `aosp-Connectivity` | `https://android.googlesource.com/platform/packages/modules/Connectivity` | `2519a78731` |
| `aosp-DnsResolver` | `https://android.googlesource.com/platform/packages/modules/DnsResolver` | `4d70e9efa5` |
| `aosp-netd` | `https://android.googlesource.com/platform/system/netd` | `e11b8688b1` |
| `sing-box-official-1.13.19` | `https://github.com/SagerNet/sing-box` | `b5ebaa1fc0` |
| `chizi-sing-box-ebpf-cilium` | `https://github.com/CHIZI-0618/sing-box` | `45a5bd8d6c` |
| `dae` | `https://github.com/daeuniverse/dae` | `caa6f5e917` |
| `honk` | `https://github.com/daeuniverse/honk` | `131e71b8db` |
| `asteriskd` | `https://github.com/Asterisk4Magisk/asteriskd` | `0e6705e424` |
| `bpf2socks` | `https://github.com/Asterisk4Magisk/bpf2socks` | `885a313abe` |
| `bpfmatcher` | `https://github.com/Asterisk4Magisk/bpfmatcher` | `b814407819` |
| `AndroidTProxyShell` | `https://github.com/CHIZI-0618/AndroidTProxyShell` | `4b6ddd8779` |
| `box4magisk` | `https://github.com/CHIZI-0618/box4magisk` | `1aabf31ad8` |
| `box_for_magisk` | `https://github.com/taamarin/box_for_magisk` | `a87244943a` |
| `mihomo` | `https://github.com/MetaCubeX/mihomo` | `f295ba6da4` |
| `tun2socks` | `https://github.com/xjasonlyu/tun2socks` | `d24a73449e` |
| `hev-socks5-tunnel` | `https://github.com/heiher/hev-socks5-tunnel` | `0428c4ebb0` |
| `Vector` | `https://github.com/JingMatrix/Vector` | `5e4dcb92a1` |
| `NeoZygisk` | `https://github.com/JingMatrix/NeoZygisk` | `ec29fb101d` |
| `Flux-original` | `https://github.com/Chth1z/Flux` | `c978b75d87` |

### 不是 git 仓库的三个目录

它们是按需抓取的文件集合，`reclone.sh` 会重新下载：

| 目录 | 内容 |
|---|---|
| `kernel-src/` | `raw.githubusercontent.com/torvalds/linux/<tag>/...` 下的相关内核源文件，按 `v5.10` / `v6.1` / `v6.6` / `v6.12` 分目录。**引用内核源必须带版本**，因为语义会变 |
| `gki/` | 四个 GKI 分支的 arm64 `gki_defconfig`（`android12-5.10` / `android13-5.15` / `android14-6.1` / `android15-6.6`） |
| `mihomo-ebpf-historical/` | mihomo 后来移除的 eBPF 组件，从历史 commit 取出 |

## 各项在设计里的用处

| 目录 | 支撑了什么 |
|---|---|
| `aosp-netd`、`aosp-Connectivity` | netd 的 `ip rule` 底线 10000、路由表偏移 1000、fwmark 位布局、netd 增删 `clsact`、AOSP TC 优先级占用、CLAT 是 `ARPHRD_NONE` |
| `aosp-DnsResolver` | **D18 的源码链**：`fchown()` 把 DNS socket 归属改回 app |
| `sing-box-official-1.13.19` | tproxy 合同四点逐行证实；全树零 `SO_REUSEPORT` |
| `chizi-sing-box-ebpf-cilium` | 打补丁路线的对照（D19）；`TC_ACT_UNSPEC` 在 TCX 上同样必要；**LPM trie 在 6.6.0–6.6.46 的崩溃**（D20） |
| `dae`、`honk` | TC → veth → `sk_assign` 原语；也反证了 `TC_ACT_OK` 在 Android 会遮挡系统 filter |
| `asteriskd`、`bpf2socks` | 加载器加固清单；TC 槽位冲突的"fail closed"对照；legacy map 定义的适用边界 |
| `Vector`、`NeoZygisk` | 发布工程与社区流程（`governance.md` §7）：安装时 SHA-256、管理器版本矩阵、canary 作为 prerelease、诊断包 |
| `Flux-original` | 订阅转换的语义（D22 之外的那一半）、节点精修的领域知识、配置文件风格 |
| `kernel-src`、`gki` | §4 的内核机制清单与 config 核对 |
| `mihomo`、`tun2socks`、`hev-socks5-tunnel` | 反例：确认它们是 TUN/用户态栈方案，**没有 eBPF 数据面**，不必在那里花时间 |

## 引用规矩

`authoring.md` §2 要求每条断言可追溯。引用这里的源码时：

- 给 `目录/文件:行号`。
- **内核源必须带版本**：`v6.1 net/core/filter.c:2144`，不是 `filter.c:2144`。
- 引用 dae 时**只引 `control/kern/*.c`**：它的 `docs/en/how-it-works.md` 关于 WAN 改写目的与关闭 checksum 的描述与当前代码矛盾。
