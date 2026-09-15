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

/// Cargo owns output-path resolution, including relative environment values
/// and .cargo configuration. Never infer the built artifact from repo_root.
pub fn target_dir(root: &Path) -> Result<PathBuf, String> {
    target_dir_from_command(Command::new(cargo()).current_dir(root).args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
    ]))
}

fn target_dir_from_command(command: &mut Command) -> Result<PathBuf, String> {
    let output = command
        .output()
        .map_err(|error| format!("cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata output: {error}"))?;
    let path = metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("cargo metadata did not return an absolute target_directory")?;
    Ok(path)
}

/// An exclusively created directory owned by this invocation. A failed run
/// retains its artifacts for diagnosis; a successful caller may remove it.
pub fn work_dir(parent: &Path, name: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {}: {error}", parent.display()))?;
    for attempt in 0..1000 {
        let path = parent.join(format!("{name}-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create {}: {error}", path.display())),
        }
    }
    Err(format!(
        "no free {name} directory under {}",
        parent.display()
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_resolves_configured_and_environment_target_directories() {
        let work = work_dir(&std::env::temp_dir(), "flux-target-dir-test").unwrap();
        write_bytes(
            &work.join("Cargo.toml"),
            b"[package]\nname = \"target-dir-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\n",
        )
        .unwrap();
        write_bytes(&work.join("src/main.rs"), b"fn main() {}\n").unwrap();
        write_bytes(
            &work.join(".cargo/config.toml"),
            b"[build]\ntarget-dir = \"configured-output\"\n",
        )
        .unwrap();
        for (override_dir, suffix) in [
            (None, "configured-output"),
            (Some("environment-output"), "environment-output"),
        ] {
            let mut command = Command::new(cargo());
            command
                .current_dir(&work)
                .args([
                    "metadata",
                    "--no-deps",
                    "--format-version",
                    "1",
                    "--offline",
                ])
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_BUILD_TARGET_DIR");
            if let Some(path) = override_dir {
                command.env("CARGO_TARGET_DIR", path);
            }
            let actual = target_dir_from_command(&mut command).unwrap();
            assert!(actual.is_absolute());
            assert_eq!(actual.file_name().unwrap(), suffix);
            // Canonicalise the existing parent, since Windows may report its
            // temporary root with different spelling than temp_dir().
            assert_eq!(
                actual.parent().unwrap().canonicalize().unwrap(),
                work.canonicalize().unwrap()
            );
        }
        std::fs::remove_dir_all(&work).unwrap();
    }
}
