//! The Flux-rs daemon and its CLI.
//!
//! Module dependency direction (blueprint §5), which must not be violated:
//!
//! ```text
//! main -> reactor -> {layout, control, packages, netlink, bpf, dataplane, engine}
//! ```
//!
//! Nothing below `reactor` depends back on it. All runtime state lives in the
//! reactor's single `Reactor` struct; there are no mutable globals.
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
mod control;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod engine;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod layout;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod netlink;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod reactor;

use std::process::ExitCode;

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
    stop       Ask the daemon to detach and exit
    enable     Remove the disable file (the daemon reacts via inotify)
    disable    Create the disable file (the daemon reacts via inotify)
    bugreport  Write a diagnostic zip (--with-logcat, --raw, -o <dir>)
    version    Print version and ABI magic

The design contract is docs/blueprint.md.
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
    use std::time::Duration;

    use flux_core::control_wire::{Request, Response, State};

    use crate::engine::EngineSpec;
    use crate::layout::Layout;

    /// One request against the running daemon, or a readable refusal.
    fn ask(layout: &Layout, request: Request) -> Result<Response, String> {
        control::request(&layout.control_socket(), &request, Duration::from_secs(30)).map_err(|e| {
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
            "policy:     {} apps selected, {} bypass v4, {} bypass v6",
            response.policy.selected, response.policy.bypass_v4, response.policy.bypass_v6
        );
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

    let layout = Layout::product();
    match command {
        // Blueprint §10.6 calls it `daemon`; `start` (implementation plan
        // §17.5) and `run` (service.sh, phase 1) are aliases of the same
        // foreground mode — service.sh owns backgrounding.
        "daemon" | "start" | "run" => ExitCode::from(reactor::run_daemon()),

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

        "stop" => match ask(&layout, Request::Stop) {
            Ok(_) => {
                println!("fluxd: daemon stopping");
                ExitCode::SUCCESS
            }
            Err(_) => {
                // Idempotent by §10.3: stopping a stopped daemon succeeds.
                println!("fluxd: daemon is not running");
                ExitCode::SUCCESS
            }
        },

        // enable/disable are thin front-ends over the C9 disable file — the
        // ONLY switch truth (docs/ux.md §1.3). The daemon notices via inotify;
        // when it is running we also ask over the socket for synchronous
        // feedback, but the file operation alone is already complete.
        "enable" => {
            if let Err(e) = layout.ensure() {
                eprintln!("fluxd: cannot create {}: {e}", layout.root().display());
                return ExitCode::FAILURE;
            }
            match ask(&layout, Request::Enable) {
                Ok(response) => {
                    print_status(&response);
                    ExitCode::SUCCESS
                }
                Err(_) => match layout.set_enabled() {
                    Ok(()) => {
                        println!("fluxd: enabled (daemon not running; switch persisted)");
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
                eprintln!("fluxd: cannot create {}: {e}", layout.root().display());
                return ExitCode::FAILURE;
            }
            match ask(&layout, Request::Disable) {
                Ok(response) => {
                    print_status(&response);
                    ExitCode::SUCCESS
                }
                Err(_) => match layout.set_disabled() {
                    Ok(()) => {
                        println!("fluxd: disabled (daemon not running; switch persisted)");
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
