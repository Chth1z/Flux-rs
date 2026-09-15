//! Compiles `bpf/flux.bpf.c` into the object embedded in the daemon.
//!
//! Blueprint D10: we do not link libbpf, libelf or zlib. clang emits the
//! object, `include_bytes!` embeds it, and `src/bpf/` loads it with raw
//! `bpf(2)` calls and a hand-built BTF blob.
//!
//! BPF compilation is opt-in via `FLUX_BUILD_BPF=1` so that `cargo build`,
//! `cargo test` and `cargo clippy` work on a machine without a bpf-capable
//! clang. Release packaging sets it and `xtask` verifies the object is present.

use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR always set by cargo"));
    let object = out_dir.join("flux.bpf.o");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let repo_root = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/fluxd is two levels below the repo root");
    let source = repo_root.join("bpf").join("flux.bpf.c");
    let include = repo_root.join("bpf").join("include");

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", include.display());
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=FLUX_BUILD_BPF");
    println!("cargo:rerun-if-env-changed=FLUX_COMMIT");
    println!("cargo:rustc-env=FLUX_BPF_OBJECT={}", object.display());

    if env::var_os("FLUX_BUILD_BPF").is_none() {
        // Emit an empty object so `include_bytes!` still resolves. The loader
        // refuses to run against a zero-length object, so this can never be
        // mistaken for a working build at runtime.
        fs::write(&object, b"").expect("write placeholder bpf object");
        println!(
            "cargo:warning=FLUX_BUILD_BPF unset: embedding an empty BPF object. \
             This build cannot attach a data plane."
        );
        return;
    }

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let prefix_map = format!("{}=.", repo_root.display());
    let mut command = Command::new(&clang);
    command
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-mcpu=v3",
            "-D__TARGET_ARCH_arm64",
        ])
        .arg(format!("-ffile-prefix-map={prefix_map}"))
        .arg(format!("-fdebug-prefix-map={prefix_map}"))
        .arg(format!("-I{}", include.display()));
    if let Some(system_include) = multiarch_include() {
        command.arg(format!("-I{}", system_include.display()));
    }
    let status = command
        .args(["-MD", "-MT", "flux_bpf", "-MF"])
        .arg(out_dir.join("flux.bpf.d"))
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {clang}: {e}"));

    assert!(status.success(), "{clang} failed to compile {source:?}");
    // Clang includes system headers in -MD output. Track the actual inputs,
    // including paths escaped by Make syntax, without duplicating its search.
    let dependencies = fs::read_to_string(out_dir.join("flux.bpf.d"))
        .expect("read clang dependency file")
        .replace("\\\n", "");
    let mut path = String::new();
    let mut escaped = false;
    for ch in dependencies
        .trim_start_matches("flux_bpf:")
        .chars()
        .chain([' '])
    {
        if escaped {
            path.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch.is_whitespace() {
            if !path.is_empty() {
                println!("cargo:rerun-if-changed={}", path.replace("$$", "$"));
                path.clear();
            }
        } else {
            path.push(ch);
        }
    }
}

fn multiarch_include() -> Option<PathBuf> {
    let output = Command::new("cc").arg("-print-multiarch").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let triple = std::str::from_utf8(&output.stdout).ok()?.trim();
    let include = PathBuf::from("/usr/include").join(triple);
    include.is_dir().then_some(include)
}
