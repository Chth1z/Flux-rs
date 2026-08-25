//! Build, packaging and release automation.
//!
//! Implements blueprint §13.1 and §15.1. Runs on the development host only and
//! is never shipped.
//!
//! Packaging rules that must not be relaxed:
//!
//! * The module ZIP is built from an explicit **allowlist**, never by excluding
//!   paths from the working tree.
//! * Two consecutive packaging runs must produce byte-identical archives.
//! * Every `LOAD` segment of `fluxd` must have `p_align >= 0x4000` so the
//!   module works on 16 KiB base-page devices; the pinned official sing-box is
//!   still `0x1000` and is checked against `engine.lock` rather than rebuilt.
//!
//! Not implemented yet — Phase 7 (blueprint §17).

use std::process::ExitCode;

fn usage() -> &'static str {
    "\
cargo xtask <TASK>

TASKS:
    ci             fmt --check, clippy -D warnings, test, deny
    abi-check      compare bpf/include/flux_abi.h offsets against flux-core::abi
    build-bpf      compile bpf/flux.bpf.c with clang
    package        build the module ZIP from the allowlist
    verify-package re-package and assert byte-identical output
"
}

fn main() -> ExitCode {
    let Some(task) = std::env::args().nth(1) else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };

    match task.as_str() {
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        "ci" | "abi-check" | "build-bpf" | "package" | "verify-package" => {
            eprintln!("xtask: `{task}` is not implemented yet (see docs/blueprint.md §17)");
            ExitCode::from(69)
        }
        other => {
            eprintln!("xtask: unknown task `{other}`");
            eprint!("{}", usage());
            ExitCode::from(2)
        }
    }
}
