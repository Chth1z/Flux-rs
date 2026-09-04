# 交给实现者的任务书 E：监督进程收进二进制

> **这是 `plan/` 层：它描述还没发生的事。** 合同在 `../spec/blueprint.md` §13.2.2（新写）、§10.3、§25，以及 `../spec/failures.md` §23.1、§23.3；与它们冲突时错的是本文。完成并通过审查后，审查者把本文移入 `history/` 并划掉 §17.0.1 第 5 项；实现者不动 `docs/plan/`。
>
> **前置：批次 A–D 已完成并提交。** 本批次不碰数据面、不碰配置模型、不加依赖。

## 这批要解决的问题

`module/service.sh` 第 60–75 行是一个 shell 循环：`fluxd daemon` 非零退出就按 1/2/4/8 s 退避重启。它的行为取决于退出码和时间，按 PHIL-7 的判据本就属于二进制。它还有一个真缺陷：**任何**非零退出都重启，包括"另一个实例已在运行"——第二次执行 `service.sh` 会以 8 秒间隔永远重试，对着正在工作的实例撞。

所有者 2026-09-05 选定：监督收进二进制，参照 NeoZygisk 的独立 monitor 进程形态——脚本只启动一个进程，然后什么都不管。

## E0 — 不加依赖

只用 `std` 与已有的 `libc`。想加别的就停下来问。

## E1 — 监督进程（§13.2.2）

**合同**：§13.2.2 整节，逐条都是要求，不是建议。这里只说实现形状。

### 两个进程，一个二进制

`fluxd daemon` 现在是**监督进程**。它重新执行自己——`Command::new("/proc/self/exe")`，不是 `current_exe()` 的路径：模块文件被替换后，`/proc/self/exe` 仍指向正在运行的那份镜像，崩溃重启不会换成另一版二进制——参数仍是 `daemon`，环境里多一个 `FLUX_SUPERVISOR=<监督进程 pid>`。子进程看到这个变量就直接进 `reactor::run_daemon()`，也就是今天的全部守护进程逻辑，一行不改。

`main.rs` 的分派：

```rust
"daemon" | "start" | "run" => {
    if std::env::var_os("FLUX_SUPERVISOR").is_some() {
        ExitCode::from(reactor::run_daemon())
    } else {
        ExitCode::from(supervisor::run())
    }
}
```

新模块 `crates/fluxd/src/supervisor.rs`，和其余守护进程代码一样只在 Linux/Android 编译。

### 监督进程做的事，按顺序

1. 用 `sigprocmask` 阻塞 `SIGCHLD`、`SIGTERM`、`SIGINT`、`SIGHUP`。
2. 启动 reactor。`pre_exec` 里把信号掩码清空（`SIG_SETMASK` 到空集）——阻塞集会穿过 `execve`，reactor 必须从干净状态开始（它自己会为 signalfd 再阻塞它要的）。stdio 直接继承：`service.sh` 已把它们指向 `service.log`。
3. 记下启动时刻，然后 `sigwaitinfo` 等四个信号之一：
   - `SIGCHLD`：`waitpid(child, WNOHANG)` 直到收回子进程（`EINTR` 重试）。没收到就继续等。
   - `SIGTERM` / `SIGINT`：`kill(child, 同一信号)`，记下"正在停止"和 10 秒期限；之后改用 `sigtimedwait` 等到期限，到期子进程还没退出就 `SIGKILL`。
   - `SIGHUP`：`kill(child, SIGHUP)`，继续等。
4. 子进程退出后：
   - 正在停止 → 以子进程的状态退出（正常退出取它的码；被信号杀死算 1），**不重启**。
   - 退出码 `0` → 退出 `0`。
   - 退出码 `3` → 记一行"another fluxd instance holds the lock; not restarting"，退出 `3`。
   - 其余退出码或被信号杀死 → 算一次崩溃。存活 ≥ 60 s 则把崩溃计数清零；退避秒数取 `[1, 2, 4, 8, 30]` 里按计数封顶的那一格，计数加一；记一行 `fluxd: reactor exited with code N; restarting in S s`（或 `killed by signal N`）；然后 `sigtimedwait` **一次**，超时 S 秒——期间来 `SIGTERM`/`SIGINT` 就直接退出 `0`（没有子进程可停），来 `SIGHUP` 忽略；超时则回到第 2 步。
5. `Command::spawn` 本身失败（例如 `ENOMEM`）也算一次崩溃，走同样的退避。

`BACKOFF_STEPS` 与 `BACKOFF_RESET_AFTER` 已经在 `reactor.rs` 里（第 49、52 行，给引擎用的）。**只能有一份定义**：挪到两边都能用的地方，不要复制。

### 不许做的

- 不碰 `run/daemon.lock`、控制 socket、netlink、BPF、状态根下的任何文件。监督进程和 reactor 之间只有 `waitpid` 与 `kill`。
- 不轮询。除了上面那一次 `sigtimedwait`，没有任何定时器、没有 `sleep`。
- 不 panic。`panic = "abort"` 下监督进程一 panic 就没了，而它存在的唯一理由是不会失败。所有 libc 调用检查返回值；拿不到的信息就记一行然后按最保守的分支走。
- 不给 reactor 设 `PR_SET_PDEATHSIG`。§13.2.2 写了为什么，也写了这与 §13.3 对引擎的规则为何相反。
- 不加 CLI 命令、不改 wire。`FLUX_SUPERVISOR` 是唯一的标记。

### reactor 侧的一处改动

`reactor::run_daemon` 里 `LockError::Held` 分支现在返回 `1`，改为 `3`。用一个有名字的常量（放在监督进程模块里，两边引用），不要裸数字。其他启动失败仍是 `1`——它们是崩溃，要退避重启。

## E2 — `service.sh` 变成一行

第 57–75 行的注释和循环整个换成：

```sh
exec "$MODDIR/bin/fluxd" daemon >>"$LOG" 2>&1
```

前面的管理器识别与三个 `FLUX_ROOT_MANAGER*` 导出保留——它们经环境穿过监督进程到 reactor。脚本末尾的 `exit 0` 不再需要（`exec` 不返回）。

`tools/phase8/module_lifecycle_test.sh` 用一个假 `fluxd` 跑 `service.sh`，`exec` 下照样工作。加一条断言：`service.sh` 去掉注释后不含 `while` 与 `sleep`——脚本不得监督，那是二进制的活。

## E3 — 测试

### `crates/fluxd/tests/daemon_e2e.rs`

- 用 `std::os::unix::process::CommandExt::process_group(0)` 启动 `fluxd daemon`，让监督进程成为进程组首进程；失败路径里的 `daemon.kill()` 改成对**进程组**发 `SIGKILL`（`libc::kill(-(pid), SIGKILL)`），否则 reactor 会成为孤儿、继续持锁，让下一次测试运行在"already running"上失败。引擎由 reactor 的 `PDEATHSIG=SIGKILL` 带走。
- `scenario_second_instance_rejected`：第二个 `fluxd daemon` 的退出码现在是 **3**（监督进程原样传出 reactor 的 3）；被点名的 pid 是 **reactor** 的，不再等于 `daemon.id()`——从 `run/daemon.lock` 的内容读锁持有者 pid 来比对。
- **新场景：reactor 崩溃恢复。** 放在引擎 SIGKILL 恢复之后：从 `run/daemon.lock` 读 reactor pid，对它 `SIGKILL`；断言 `daemon.id()`（监督进程）仍然存活；在 1 秒退避加启动时间之内（给 5 秒上限）`status` 重新应答，`run/daemon.lock` 里是一个**新的** pid，引擎 pid 也变了（旧引擎随 reactor 一起死，新 reactor 按 §8.7 重建）。
- `scenario_stop` 语义不变：`fluxd stop` 后监督进程以 0 退出、socket 被删。它现在同时证明了"reactor 以 0 退出 → 监督进程不重启"。

### `crates/fluxd/tests/phase7_device.rs`

`spawn_daemon` 加 `process_group(0)`；`stop_best_effort` 的 `child.kill()` 回退改成杀进程组。行为断言不变。

### 单元测试（`supervisor.rs` 内，Linux）

把"看到什么退出状态 → 做什么"写成一个纯函数（输入：退出码或信号、是否正在停止、存活时长、当前崩溃计数；输出：退出/不重启退出/退避 S 秒后重启），对它测：0 → 退出；3 → 不重启；1 → 退避 1 s；连续五次崩溃 → 1/2/4/8/30；存活 60 s 后再崩 → 回到 1 s；正在停止时任何退出 → 不重启。信号等待与 `waitpid` 那层不做单测，由 e2e 的崩溃恢复场景覆盖。

## 验收

**只跑 `AGENTS.md` 列的主机门禁，加上 aarch64 类型检查**：

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
cargo clippy -p fluxd --target aarch64-linux-android --all-targets
```

aarch64 那条在这台 Windows 主机上会因为 `ring` 需要交叉编译器而失败——环境问题，报告即可，审查者在 WSL 跑。`daemon_e2e` 与 `module_lifecycle_test.sh` 同样由审查者在 WSL 跑；你在 Windows 上只能保证它们编译。**不要声称没跑的东西通过了。**

## 边界

- 不实现 SSID（§29），那是批次 F。
- 不改 reactor 的引擎监督逻辑、退避定时器、状态机。
- **不要碰** `docs/spec/**`、`docs/history/**`、`docs/plan/**`、`README.md`。合同有问题就停下报告。
