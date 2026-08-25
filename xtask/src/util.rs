//! Small shared helpers: repo layout, subprocess wrappers, file access.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, derived from this crate's manifest directory so it
/// works no matter where `cargo xtask` is invoked from.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits one level below the repo root")
        .to_path_buf()
}

/// The `cargo` binary to re-invoke. Cargo sets `$CARGO` for `cargo run`, so
/// nested invocations use the exact same cargo rather than whatever is first
/// on PATH.
pub fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// The C compiler used for ABI offset computation and the BPF object.
pub fn clang() -> String {
    std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string())
}

/// Run a command with inherited stdio and fail with a readable message.
pub fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let program = cmd.get_program().to_string_lossy().to_string();
    let status = cmd
        .status()
        .map_err(|e| format!("{what}: failed to run `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what}: `{program}` exited with {status}"))
    }
}

pub fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}

pub fn write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, data).map_err(|e| format!("write {}: {e}", path.display()))
}

/// CRLF -> LF. Packaged text files are LF regardless of the checkout
/// (blueprint §13.4 step 5); `module.prop` in particular must be LF
/// (blueprint §13.2.0).
pub fn normalize_lf(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut iter = text.iter().peekable();
    while let Some(&b) = iter.next() {
        if b == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        out.push(b);
    }
    out
}
