//! Build, packaging and release automation.
//!
//! Implements blueprint §13.1/§13.4 and §15.1, plus the doc checks of
//! `docs/plan/implementation.md` §17.4. Runs on the development host only and
//! is never shipped.
//!
//! Packaging rules that must not be relaxed:
//!
//! * The module ZIP is built from an explicit **allowlist**, never by excluding
//!   paths from the working tree.
//! * Two consecutive packaging runs must produce byte-identical archives.
//! * Every `LOAD` segment of `fluxd` must have `p_align >= 0x4000` so the
//!   module works on 16 KiB base-page devices; official sing-box alignment is
//!   measured from the resolved official asset, which is never rebuilt.

mod abi_check;
mod btf_check;
mod cdefs;
mod doc_check;
mod elf;
mod engine_release;
mod fidelity;
mod freeze;
mod package;
mod sha256;
mod util;
mod zip;

use std::process::{Command, ExitCode};

/// Every dispatchable task name.
///
/// Exists so that `doc-check` can reject a `cargo xtask <sub>` cited in a
/// document or a workflow that no longer resolves — blueprint §15.4 rule 3
/// orders that check, after an audit found CI invoking a task that had been
/// deleted and documents listing retired ones.
pub const TASKS: [&str; 11] = [
    "ci",
    "abi-check",
    "btf-check",
    "template-check",
    "doc-check",
    "fidelity",
    "build-bpf",
    "package",
    "verify-package",
    "freeze",
    "release",
];

fn usage() -> &'static str {
    "\
cargo xtask <TASK>

TASKS:
    ci             fmt --check, clippy -D warnings, test, deny, doc-check
    abi-check      clang-computed flux_abi.h layout vs the flux-core::abi mirror
    btf-check      clang .BTF flux_decision layout vs the hand-written blob
    template-check latest official sing-box validates the shipped default template
    doc-check      the mechanical documentation checks (implementation.md \u{a7}17.4)
    fidelity A B   what a re-issue of a document dropped: citations, cross-refs,
                   identifiers, constants
    build-bpf      compile bpf/flux.bpf.c with clang
    package        build the module ZIP from the allowlist
    verify-package package twice from clean cross-build state, assert equal hashes
    freeze         record candidate identity under dist/freeze/
    release TAG    verify TAG/version against a freeze list, never /releases/latest
"
}

fn ci() -> Result<(), String> {
    let root = util::repo_root();
    let cargo = util::cargo();
    let steps: [&[&str]; 3] = [
        &["fmt", "--all", "--", "--check"],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace"],
    ];
    for step in steps {
        util::run(
            Command::new(&cargo).args(step).current_dir(&root),
            &format!("cargo {}", step[0]),
        )?;
    }
    // cargo-deny is a separate install; CI runs it in its own job, so a
    // missing binary here is reported but not fatal to the local loop.
    match Command::new(&cargo)
        .args(["deny", "check"])
        .current_dir(&root)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => return Err(format!("cargo deny check exited with {status}")),
        Err(_) => {
            println!("ci: cargo-deny not installed, skipping (CI's supply-chain job runs it)")
        }
    }
    doc_check::run()
}

fn main() -> ExitCode {
    let Some(task) = std::env::args().nth(1) else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };

    let result = match task.as_str() {
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        "ci" => ci(),
        "abi-check" => abi_check::run(),
        "btf-check" => btf_check::run(),
        "template-check" => package::template_check(),
        "doc-check" => doc_check::run(),
        "fidelity" => {
            let mut args = std::env::args().skip(2);
            match (args.next(), args.next()) {
                (Some(before), Some(after)) => fidelity::run(&before, &after),
                _ => {
                    Err("fidelity takes two document paths: the earlier, then the re-issue".into())
                }
            }
        }
        "build-bpf" => package::build_bpf(),
        "package" => package::run(),
        "verify-package" => package::verify(),
        "freeze" => freeze::run(),
        "release" => match std::env::args().nth(2) {
            Some(tag) => package::release(&tag),
            None => Err("release requires the pushed v* tag as its only argument".into()),
        },
        other => {
            eprintln!("xtask: unknown task `{other}`");
            eprint!("{}", usage());
            return ExitCode::from(2);
        }
    };
    debug_assert!(
        TASKS.contains(&task.as_str()),
        "`{task}` dispatched but missing from TASKS, which doc-check validates against"
    );

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask {task}: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{usage, TASKS};

    #[test]
    fn every_task_is_documented_in_usage() {
        let text = usage();
        for task in TASKS {
            assert!(
                text.contains(task),
                "`{task}` is dispatchable but absent from usage()"
            );
        }
    }
}
