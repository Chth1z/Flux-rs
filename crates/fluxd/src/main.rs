//! The Flux-rs daemon and its CLI.
//!
//! Module dependency direction (blueprint §5), which must not be violated:
//!
//! ```text
//! main -> reactor -> {layout, control, packages, netlink, bpf, dataplane, engine}
//! ```
//!
//! Nothing below `reactor` depends back on it. All runtime state lives in a
//! single `Runtime` owned by `reactor`; there are no mutable globals.
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

// Skeleton commit: the module tree and its documented constants exist, the
// implementations do not. Remove this attribute as the phases in §17 land; it
// must be gone before 0.9.0 ships, because by then every constant here has a
// caller.
#![allow(dead_code)]

mod control;
mod dataplane;
mod engine;
mod layout;
mod packages;
mod reactor;

mod bpf;
mod netlink;

use std::process::ExitCode;

/// Embedded data plane. Empty unless the build set `FLUX_BUILD_BPF=1`; the
/// loader refuses a zero-length object rather than pretending to attach.
const BPF_OBJECT: &[u8] = include_bytes!(env!("FLUX_BPF_OBJECT"));

fn usage() -> &'static str {
    "\
fluxd 0.9.0 — transparent per-app proxying for rooted Android

USAGE:
    fluxd <COMMAND>

COMMANDS:
    run        Run the daemon in the foreground (used by service.sh)
    status     Print daemon state as JSON
    check      Validate configuration without changing anything
    enable     Persist enabled=true and activate
    disable    Persist enabled=false and detach
    reload     Re-read configuration and converge
    stop       Detach and exit
    version    Print version and ABI magic

The design contract is docs/blueprint.md. This build is a skeleton: no
command is implemented yet.
"
}

fn main() -> ExitCode {
    let Some(command) = std::env::args().nth(1) else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };

    match command.as_str() {
        "version" => {
            println!(
                "fluxd {} (ABI magic {:#010x}, bpf object {} bytes)",
                flux_core::VERSION,
                flux_core::abi::FLUX_ABI_MAGIC,
                BPF_OBJECT.len(),
            );
            ExitCode::SUCCESS
        }
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        "run" | "status" | "check" | "enable" | "disable" | "reload" | "stop" => {
            eprintln!("fluxd: `{command}` is not implemented yet (see docs/blueprint.md §17)");
            ExitCode::from(69) // EX_UNAVAILABLE
        }
        other => {
            eprintln!("fluxd: unknown command `{other}`");
            eprint!("{}", usage());
            ExitCode::from(2)
        }
    }
}
