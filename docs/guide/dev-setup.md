# 从零搭一台能跑全部门禁的开发机

> **投影，how-to。** 写给下一个接手的人（或下一台机器）：照着做能在一个下午内跑完 `AGENTS.md` 列的全部门禁、交叉构建模块包、在真机上做回归。规则与理由不在这里——门禁的分层在 `../spec/blueprint.md` §15.1，验证纪律在 `../governance.md` GOV-4。与它们冲突时，错的是本文。
>
> 本文描述的是**当前实际在用的**那套配置（Windows 11 + WSL2 Ubuntu），不是唯一可行的配置。纯 Linux 主机把 WSL 那一节直接当本机做即可。

## 三层，各自能跑什么

| 层 | 能跑 | 跑不了 |
|---|---|---|
| Windows 主机 | `cargo fmt`、`flux-core` 与 `xtask` 的全部单测、`fluxd --bin` 的宿主安全子集、`cargo xtask doc-check` | 任何 `fluxd` 的 Linux 代码、集成测试、aarch64 类型检查（`ring` 要交叉编译器） |
| WSL / Linux | 上面全部，加 `cargo clippy --workspace -D warnings`、`cargo test --workspace`（含两套 fake-engine 集成套件）、aarch64 clippy、BPF 编译、`abi-check` / `btf-check` / `template-check`、`verify-package`、shellcheck、模块生命周期测试 | Phase 3–7 真机套件、nl80211 路径（WSL 内核没有 cfg80211） |
| 真机（adb + root） | Phase 3–7 套件、`../plan/device-regression-0.9.5.md` 的整张表 | — |

**Windows 的绿色不能替代 Linux CI，两者都不能替代真机**（§15.1）。

## Windows 主机

1. 装 rustup。工具链版本由 `rust-toolchain.toml` 钉死（当前 1.93.0，含 `rustfmt`、`clippy`、`aarch64-linux-android` target），进仓库目录后 `cargo` 会自动装。
2. 装 Git。仓库文件一律 LF、无 BOM；`.gitattributes` 已对脚本、`module/**`、BPF 源与 lock 文件强制 `eol=lf`。
3. 装 `rg`（ripgrep）。文档与代码里的章节引用靠它查。
4. **不要用 PowerShell 读写含中文的文件**——5.1 版按 GBK 解释无 BOM 文件，写会毁字、读会数错行。用编辑器或 `rg`；`.ps1` 脚本保持纯 ASCII。提交说明用 `git commit -F <file>`，PowerShell 没有 heredoc。

宿主门禁：

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
```

## WSL（Ubuntu）

一次性安装：

```sh
# Rust：与 Windows 侧同一份 rust-toolchain.toml 生效
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# BPF 编译与 ABI 核对：带 bpf 后端的 clang；libbpf 头文件只用其 header-only 子集
sudo apt-get install -y clang llvm libbpf-dev
# clang -target bpf 不搜 x86_64 的多架构 include 目录，<linux/types.h> 找不到 <asm/types.h>
sudo ln -sfn /usr/include/x86_64-linux-gnu/asm /usr/include/asm
# 其余门禁工具
sudo apt-get install -y shellcheck unzip curl bpftool
```

`bpftool` 只用于验证器门（`bpftool prog loadall`）；Ubuntu 的 `/usr/sbin/bpftool` 在 WSL 内核上通常能用，CI 因宿主内核过新而自行编译 v7.5.0，本机不必。

**NDK**：Android 交叉构建需要 NDK **r27**（CI 用 `r27d`，本机是 `27.3.13750724`）。放在 `~/Android/Sdk/ndk/<版本>/`，然后在跑交叉构建的 shell 里：

```sh
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.3.13750724
export PATH="$HOME/.cargo/bin:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
```

顺序有讲究：`~/.cargo/bin` 在前（非登录 shell 不 source `~/.cargo/env`），NDK 的 clang 在后，别让它遮住宿主的 clang——BPF 目标要用宿主那个。`.cargo/config.toml` 已把 `aarch64-linux-android` 的 linker 指向 `aarch64-linux-android31-clang`，PATH 对了就能找到。

**target 目录**：从 WSL 构建 `/mnt/d` 上的仓库时，用 `CARGO_TARGET_DIR=/tmp/flux-linux`（Linux）和 `/tmp/flux-android`（aarch64），一是避免和 Windows 侧的 `target/` 互相覆盖，二是 9p 文件系统上的增量构建慢得离谱。`verify-package` 例外——它要清理 `target/aarch64-linux-android` 做两次干净构建，就让它用仓库内的 `target/`。

Linux 门禁：

```sh
cd /mnt/d/Github/Flux-rs
CARGO_TARGET_DIR=/tmp/flux-linux   cargo clippy --workspace --all-targets -- -D warnings
CARGO_TARGET_DIR=/tmp/flux-linux   cargo test --workspace
CARGO_TARGET_DIR=/tmp/flux-android cargo clippy -p fluxd --target aarch64-linux-android --all-targets -- -D warnings
shellcheck --shell=sh --severity=warning module/*.sh
sh tools/phase8/module_lifecycle_test.sh
```

`cargo test --workspace` 里 `daemon_e2e` 与 `engine_lifecycle` 会真的起一个 `fluxd daemon`（测试二进制自己冒充 sing-box），跑完应无残留：`pgrep -a fluxd` 为空。Phase 3–7 的测试二进制在这里只会打印 `skipped`。

BPF 与打包：

```sh
export FLUX_BUILD_BPF=1
cargo xtask abi-check        # clang 的 offset 对照 abi.rs 镜像
cargo xtask btf-check        # 手写 BTF 对照 clang 的 .BTF
cargo xtask template-check   # 官方 sing-box 校验默认模板
cargo xtask verify-package   # 两次干净交叉构建，字节一致才算过；产物在 dist/
```

`verify-package` 第一次会下载 `engine.lock` 钉死的官方 sing-box 资产（约 18 MB）到 `target/xtask/engine/`，之后复用。

## 真机

- 设备须 root（Magisk / KernelSU / APatch），内核 ≥ 5.15，arm64。全部实测结论目前来自一台 SM-S9180 / 5.15.211 / KernelSU；**第二台不同 SoC、不同 OEM 的设备是最缺的验证资源**（GOV-2.2）。
- Windows 侧装 platform-tools，`adb devices` 能看到设备；shell 命令用 `adb shell su -c '...'`。
- 装卸模块、重启、开关 VPN 都是改所有者日用机的持久状态，**先取得授权**（GOV-1.2）。
- Phase 3–7 套件用 `FLUX_PHASE{3..7}_DEVICE_TEST=1` 门控，会创建和销毁 `flxrs0/1`，与运行中的实例冲突：先 `fluxd disable`，跑完看每个套件末尾的残留检查为空，再 `fluxd enable`。
- 完整回归步骤见 `../plan/device-regression-0.9.5.md`。

## `scratch/`

仓库根下的 `scratch/` 被 gitignore：存机场订阅链接、含凭据的设备配置、一次性脚本。**永远不要 `git add` 它，不要把它的内容引进任何文档。**

## 发布

发布只由签名的 `v*` tag 触发（`.github/workflows/release.yml`），tag 去掉 `v` 后必须等于 `Cargo.toml` 的 `[workspace.package] version`。签名密钥归所有者，不在任何机器的仓库目录里。发布前的十四条门禁见 `../spec/blueprint.md` §20。
