//! The Flux-rs daemon and its CLI.
//!
//! Module dependency direction (blueprint §5), which must not be violated:
//!
//! ```text
//! main -> {supervisor, reactor}
//! reactor -> {supervisor's shared policy constants, layout, control, packages,
//!             netlink, bpf, dataplane, engine, subscription, configuration}
//! ```
//!
//! Nothing below `reactor` depends back on it. All traffic and control state
//! lives in the reactor's single `Reactor` struct; the supervisor keeps only
//! its child pid and crash count, and there are no mutable globals.
//!
//! Two encapsulation boundaries inherited from the old repository's
//! over-design review (blueprint §5, final paragraph):
//!
//! * Raw netlink message construction, sequence numbers, ACK and timeout
//!   handling appear ONLY inside `netlink`.
//! * Raw `bpf(2)` appears ONLY inside `bpf`.
//!
//! `reactor` and `dataplane` see typed operations (`create_veth`, `add_rule`,
//! `attach_filter`, `publish_control`) and never an `nlmsghdr`.
//!
//! The daemon itself is Linux/Android-only; on other targets only `version`
//! and `help` work, so `cargo check` stays green on any development host.

mod bpf;
mod dataplane;
mod packages;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod bugreport;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod checks;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod configuration;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod control;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod engine;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod install;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod layout;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod logger;
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod netlink;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod reactor;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod subscription;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod supervisor;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod time;
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod watch;

use std::process::ExitCode;

/// `stop` after a socket or protocol failure (`docs/spec/interaction.md` §27.3.4).
/// Success requires proof the daemon is gone: `daemon.lock` is not held.
fn stop_unreachable_exit(lock_held: bool) -> u8 {
    if lock_held {
        1
    } else {
        0
    }
}

/// `enable`/`disable` once the C9 file operation has a result. The process
/// exit is not `Response.ok` for "runtime already Active/Disabled".
fn authority_file_exit(file_ok: bool, runtime_at_target: bool) -> (u8, bool) {
    if file_ok {
        (0, !runtime_at_target)
    } else {
        (1, false)
    }
}

/// Embedded data plane. Empty unless the build set `FLUX_BUILD_BPF=1`; the
/// loader refuses a zero-length object rather than pretending to attach.
const BPF_OBJECT: &[u8] = include_bytes!(env!("FLUX_BPF_OBJECT"));

fn usage() -> &'static str {
    "\
fluxd — transparent per-app proxying for rooted Android

USAGE:
    fluxd <COMMAND> [OPTIONS]

COMMANDS:
    daemon     Run the daemon in the foreground (aliases: start, run)
    status     Ask the daemon for its state (--json for the raw response)
    check      Validate configuration and engine without changing anything
    reload     Ask the daemon to re-read configuration and converge
    subscribe  Fetch the subscription once and rotate only when output changes
    stop       Ask the daemon to publish inactive, stop the engine, and exit
    enable     Remove the disable file (the daemon reacts via inotify)
    disable    Create the disable file (the daemon reacts via inotify)
    bugreport  Write a diagnostic zip (--with-logcat, --raw, -o <dir>)
    version    Print version and ABI magic

The design contract is docs/spec/blueprint.md.
"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };

    match command {
        "version" => {
            println!(
                "fluxd {} (ABI magic {:#010X}, commit {}, bpf object {} bytes)",
                flux_core::VERSION,
                flux_core::abi::FLUX_ABI_MAGIC,
                option_env!("FLUX_COMMIT").unwrap_or("unknown"),
                BPF_OBJECT.len(),
            );
            ExitCode::SUCCESS
        }
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        _ => dispatch(command, &args[1..]),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn dispatch(command: &str, _rest: &[String]) -> ExitCode {
    eprintln!("fluxd: `{command}` requires Linux/Android; this host build supports only `version` and `help`");
    ExitCode::from(69) // EX_UNAVAILABLE
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn dispatch(command: &str, rest: &[String]) -> ExitCode {
    use std::io::{Read, Write};
    use std::time::Duration;

    use flux_core::control_wire::{Request, Response, State};

    use crate::engine::EngineSpec;
    use crate::layout::Layout;

    /// One request against the running daemon, or a readable refusal.
    fn ask(layout: &Layout, request: Request) -> Result<Response, String> {
        ask_with_timeout(layout, request, Duration::from_secs(30))
    }

    fn ask_with_timeout(
        layout: &Layout,
        request: Request,
        timeout: Duration,
    ) -> Result<Response, String> {
        control::request(&layout.control_socket(), &request, timeout).map_err(|e| {
            format!(
                "fluxd daemon is not reachable at {} ({e})",
                layout.control_socket().display()
            )
        })
    }

    fn print_status(response: &Response) {
        let state = match response.state {
            State::Disabled => "Disabled",
            State::Inactive => "Inactive",
            State::Active => "Active",
        };
        println!("state:      {state}");
        println!("generation: {}", response.generation);
        println!(
            "manager:    {} {} ({})",
            response.root_manager.name,
            response.root_manager.version,
            response.root_manager.runtime_mode
        );
        if response.backoff_seconds > 0 {
            println!("backoff:    {}s", response.backoff_seconds);
        }
        match (response.engine.running, response.engine.pid) {
            (true, Some(pid)) => {
                println!(
                    "engine:     running (pid {pid}, {}/4 sockets verified)",
                    response.engine.sockets_verified
                );
                if let Some(config) = &response.engine.effective_config {
                    println!("            config {config}");
                }
            }
            _ => println!("engine:     not running"),
        }
        println!(
            "policy:     apps {} ({} selected, {} draining); cidr {} ({} v4, {} v6); interfaces {}; {} self addresses",
            response.policy.apps_mode.as_str(),
            response.policy.selected,
            response.policy.draining,
            response.policy.cidr_mode.as_str(),
            response.policy.bypass_v4,
            response.policy.bypass_v6,
            response.policy.interfaces_mode.as_str(),
            response.policy.self_addresses
        );
        if let Some(ssid) = response.ssid {
            let wifi = match (ssid.connected, ssid.paused, ssid.matched_entry) {
                (None, _, _) => "unreadable".to_string(),
                (Some(false), _, _) => "not connected".to_string(),
                (Some(true), true, Some(entry)) => {
                    format!("connected \u{b7} paused by [ssid] blacklist (entry {entry})")
                }
                (Some(true), true, None) => {
                    "connected \u{b7} paused by [ssid] whitelist".to_string()
                }
                (Some(true), false, _) => "connected".to_string(),
            };
            println!("wifi:       {wifi}");
        }
        for iface in &response.ifaces {
            println!("interface:  {}", describe_iface(iface));
        }
        let counters = &response.counters;
        println!(
            "traffic:    tcp {} captured / {} direct, udp {} captured; assigned {} tcp / {} udp",
            counters.admit_tcp,
            counters.direct_tcp,
            counters.admit_udp,
            counters.in_assign_tcp,
            counters.in_assign_udp
        );
        let dropped = counters.drop_inactive
            + counters.drop_stale_gen
            + counters.drop_handoff
            + counters.drop_selected_fragment
            + counters.drop_corrupt
            + counters.in_drop_no_listener
            + counters.in_drop_assign
            + counters.in_drop_parse;
        if dropped > 0 || counters.egress_listener_miss > 0 {
            println!(
                "drops:      {dropped} total, {} egress listener misses",
                counters.egress_listener_miss
            );
        }
        match &response.last_error {
            Some(error) => println!("last error: {error}"),
            None => println!("last error: none"),
        }
        for warning in &response.warnings {
            println!("warning:    {warning}");
        }
        for hint in &response.hints {
            println!("hint:       {hint}");
        }
    }

    /// One line per candidate interface with tri-state reachability (§27.3.3).
    fn describe_iface(iface: &flux_core::control_wire::IfaceStatus) -> String {
        let mut detail = Vec::new();
        if let Some(entry) = &iface.entry {
            detail.push(entry.clone());
        }
        if let Some(pref) = iface.pref {
            detail.push(format!("pref {pref}"));
        }
        match iface.reachable {
            Some(true) => detail.push("reachable".to_string()),
            Some(false) => detail.push("not reachable".to_string()),
            None => detail.push("reachability unverified".to_string()),
        }
        if let Some(reason) = &iface.reason {
            detail.push(reason.clone());
        }
        format!("{} {} ({})", iface.name, iface.status, detail.join(", "))
    }

    let layout = Layout::product();
    match command {
        "install" => {
            let mut root = None;
            let mut defaults = None;
            let mut legacy = false;
            let mut args = rest.iter();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--root" => root = args.next().map(std::path::PathBuf::from),
                    "--defaults" => defaults = args.next().map(std::path::PathBuf::from),
                    "--legacy-config" => legacy = true,
                    _ => {
                        eprintln!(
                            "fluxd install: expected --root PATH --defaults PATH [--legacy-config]"
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            let (Some(root), Some(defaults)) = (root, defaults) else {
                eprintln!("fluxd install: --root and --defaults are required");
                return ExitCode::from(2);
            };
            if !root.is_absolute() || !defaults.is_absolute() {
                eprintln!("fluxd install: paths must be absolute");
                return ExitCode::from(2);
            }
            match install::run(&Layout::at(root), &defaults, legacy) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("fluxd install: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        // Internal plumbing for the read-only Phase 0 probe. Keeping the
        // redactor here gives bugreport and observe.sh exactly one masking
        // implementation without adding a packaged helper script.
        "__redact-stdin" => {
            const MAX_STDIN: u64 = 16 * 1024 * 1024;
            let mut input = String::new();
            match std::io::stdin()
                .take(MAX_STDIN + 1)
                .read_to_string(&mut input)
            {
                Ok(size) if size as u64 <= MAX_STDIN => {
                    let output = bugreport::redact(&input);
                    match std::io::stdout().write_all(output.as_bytes()) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("fluxd: cannot write redacted output: {error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Ok(_) => {
                    eprintln!("fluxd: redactor input exceeds the 16 MiB limit");
                    ExitCode::FAILURE
                }
                Err(error) => {
                    eprintln!("fluxd: cannot read redactor input: {error}");
                    ExitCode::FAILURE
                }
            }
        }

        // Blueprint §10.6 calls it `daemon`; `start` (implementation plan
        // §17.5) and `run` (service.sh, phase 1) are aliases of the same
        // foreground mode — service.sh owns backgrounding.
        "daemon" | "start" | "run" => {
            if std::env::var_os("FLUX_SUPERVISOR").is_some() {
                ExitCode::from(reactor::run_daemon())
            } else {
                ExitCode::from(supervisor::run())
            }
        }

        "status" => {
            let json = rest.iter().any(|a| a == "--json");
            match ask(&layout, Request::Status) {
                Ok(response) => {
                    if json {
                        match flux_core::control_wire::to_line(&response) {
                            Ok(line) => println!("{line}"),
                            Err(e) => {
                                eprintln!("fluxd: cannot encode response: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    } else {
                        print_status(&response);
                    }
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("{message}");
                    eprintln!("(is the daemon running? start it with `fluxd daemon`)");
                    ExitCode::FAILURE
                }
            }
        }

        "check" => {
            let spec = EngineSpec::product(&layout);
            let report = checks::full_check(&layout, &spec);
            for error in &report.errors {
                println!("error:   {error}");
            }
            for warning in &report.warnings {
                println!("warning: {warning}");
            }
            if report.ok() {
                println!("check: ok");
                ExitCode::SUCCESS
            } else {
                println!("check: FAILED ({} error(s))", report.errors.len());
                ExitCode::FAILURE
            }
        }

        "reload" => match ask(&layout, Request::Reload) {
            Ok(response) => {
                print_status(&response);
                if response.ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },

        "subscribe" => {
            match ask_with_timeout(
                &layout,
                Request::Subscribe,
                crate::subscription::MAX_FETCH_BATCH + Duration::from_secs(5),
            ) {
                Ok(response) => {
                    print_status(&response);
                    if response.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }

        "stop" => match ask(&layout, Request::Stop) {
            Ok(_) => {
                println!("fluxd: daemon stopping");
                ExitCode::SUCCESS
            }
            Err(message) => {
                let lock_held = layout.instance_lock_held();
                if lock_held {
                    eprintln!("{message}");
                } else {
                    println!("fluxd: daemon is not running");
                }
                ExitCode::from(stop_unreachable_exit(lock_held))
            }
        },

        // enable/disable are thin front-ends over the C9 disable file — the
        // ONLY switch truth (docs/spec/interaction.md §27.1.3). The daemon notices via inotify;
        // when it is running we also ask over the socket for synchronous
        // feedback, but the file operation alone is already complete.
        "enable" => {
            if let Err(e) = layout.ensure() {
                eprintln!("fluxd: {e}");
                return ExitCode::FAILURE;
            }
            match ask(&layout, Request::Enable) {
                Ok(response) => {
                    print_status(&response);
                    let (code, warn) =
                        authority_file_exit(response.ok, response.state == State::Active);
                    if warn {
                        eprintln!("fluxd: switch updated; runtime is not Active yet");
                    }
                    ExitCode::from(code)
                }
                Err(_) => match layout.set_enabled() {
                    Ok(()) => {
                        println!("fluxd: enabled (switch persisted; daemon did not reply)");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("fluxd: cannot remove the disable file: {e}");
                        ExitCode::FAILURE
                    }
                },
            }
        }

        "disable" => {
            if let Err(e) = layout.ensure() {
                eprintln!("fluxd: {e}");
                return ExitCode::FAILURE;
            }
            match ask(&layout, Request::Disable) {
                Ok(response) => {
                    print_status(&response);
                    let (code, warn) =
                        authority_file_exit(response.ok, response.state == State::Disabled);
                    if warn {
                        eprintln!("fluxd: switch updated; runtime has not reached Disabled yet");
                    }
                    ExitCode::from(code)
                }
                Err(_) => match layout.set_disabled() {
                    Ok(()) => {
                        println!("fluxd: disabled (switch persisted; daemon did not reply)");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("fluxd: cannot create the disable file: {e}");
                        ExitCode::FAILURE
                    }
                },
            }
        }

        "bugreport" => {
            let mut options = bugreport::BugreportOptions::default();
            let mut iter = rest.iter();
            while let Some(arg) = iter.next() {
                match arg.as_str() {
                    "--with-logcat" => options.with_logcat = true,
                    "--raw" => options.raw = true,
                    "-o" | "--output" => match iter.next() {
                        Some(dir) => options.output_dir = Some(dir.into()),
                        None => {
                            eprintln!("fluxd: {arg} needs a directory argument");
                            return ExitCode::from(2);
                        }
                    },
                    other => {
                        eprintln!("fluxd: unknown bugreport option `{other}`");
                        return ExitCode::from(2);
                    }
                }
            }
            if options.with_logcat {
                eprintln!(
                    "fluxd: including logcat on explicit request; it may contain \
                     other apps' output"
                );
            }
            match bugreport::run(&layout, &options) {
                Ok(path) => {
                    println!("bug report written: {}", path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("fluxd: bugreport failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        other => {
            eprintln!("fluxd: unknown command `{other}`");
            eprint!("{}", usage());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_is_failure_while_the_instance_lock_is_held() {
        assert_eq!(stop_unreachable_exit(true), 1);
        assert_eq!(stop_unreachable_exit(false), 0);
    }

    #[test]
    fn enable_disable_succeed_once_the_authority_file_is_written() {
        assert_eq!(authority_file_exit(true, false), (0, true));
        assert_eq!(authority_file_exit(true, true), (0, false));
        assert_eq!(authority_file_exit(false, false), (1, false));
    }
}
