//! Runtime directory layout, permissions and the single-instance lock.
//!
//! Implements blueprint §11.1 and §10.3. The lock is `flock(LOCK_EX|LOCK_NB)`
//! on a file the daemon holds open for its whole life, so it is released by the
//! kernel even on `SIGKILL` — there is no stale-lock recovery path to get wrong.
//!
//! The on/off switch is the presence of the `disable` file (owner decision C9,
//! `docs/ux.md` §1): present = disabled, absent = enabled. There is no second
//! truth source; `fluxd enable`/`fluxd disable` only create or remove it.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Root of all runtime state (blueprint §1.1).
pub const RUNTIME_ROOT: &str = "/data/adb/flux-rs";

/// Environment override for the runtime root. A test hook only: it lets the
/// integration tests run a full daemon against a temp directory as an ordinary
/// user. Production (`service.sh`) never sets it.
pub const RUNTIME_ROOT_ENV: &str = "FLUX_RUNTIME_ROOT";

/// Environment override for the engine binary path. Same status as
/// [`RUNTIME_ROOT_ENV`]: a test hook, never set in production, where the
/// binary is the module-shipped `sing-box` next to `fluxd`.
pub const ENGINE_BIN_ENV: &str = "FLUX_ENGINE_BIN";

/// The runtime paths of one Flux instance. All accessors are pure path
/// arithmetic; only [`Layout::ensure`] and the lock/switch helpers touch the
/// filesystem.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// The production layout, honouring the [`RUNTIME_ROOT_ENV`] test hook.
    pub fn product() -> Self {
        match std::env::var_os(RUNTIME_ROOT_ENV) {
            Some(root) if !root.is_empty() => Self::at(PathBuf::from(root)),
            _ => Self::at(PathBuf::from(RUNTIME_ROOT)),
        }
    }

    /// A layout rooted at an arbitrary directory (tests use temp dirs).
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    /// The switch file: present = disabled (C9, `docs/ux.md` §1).
    pub fn disable_file(&self) -> PathBuf {
        self.root.join("disable")
    }

    /// Single-instance lock (blueprint §10.3).
    pub fn lock_path(&self) -> PathBuf {
        self.run_dir().join("daemon.lock")
    }

    /// Control socket (blueprint §10.3).
    pub fn control_socket(&self) -> PathBuf {
        self.run_dir().join("control.sock")
    }

    pub fn flux_toml(&self) -> PathBuf {
        self.config_dir().join("flux.toml")
    }

    pub fn sing_box_json(&self) -> PathBuf {
        self.config_dir().join("sing-box.json")
    }

    /// The daemon's own log. Appended by the daemon and the engine's captured
    /// stdout/stderr (blueprint §13.3); included in `bugreport`.
    pub fn log_file(&self) -> PathBuf {
        self.root.join("fluxd.log")
    }

    /// The immutable per-generation engine config (blueprint §11.1).
    pub fn effective_path(&self, generation: u64) -> PathBuf {
        self.run_dir()
            .join(format!("effective-sing-box.{generation}.json"))
    }

    /// Creates the root, `run/` and `config/` directories with mode 0700.
    /// Pre-existing directories are left untouched — a wrong mode is reported
    /// by [`Layout::mode_error`], never silently chmodded (§23.1).
    pub fn ensure(&self) -> io::Result<()> {
        for dir in [self.root.clone(), self.run_dir(), self.config_dir()] {
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Verifies the runtime directories are private to our own uid. Returns a
    /// stable error token per §23.1 (`runtime_dir_mode:0755 expected 0700`) or
    /// `None` when everything is in order. We never chmod on the user's
    /// behalf: a loosened mode may be deliberate and silently tightening it
    /// would hide that.
    pub fn mode_error(&self) -> Option<String> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let own_uid = unsafe { libc::geteuid() };
        for dir in [self.root.clone(), self.run_dir(), self.config_dir()] {
            let meta = fs::metadata(&dir).ok()?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                return Some(format!("runtime_dir_mode:0{mode:o} expected 0700"));
            }
            if meta.uid() != own_uid {
                return Some(format!("runtime_dir_owner:{} expected {own_uid}", meta.uid()));
            }
        }
        None
    }

    /// Whether the switch says "disabled" (file present).
    pub fn disabled(&self) -> bool {
        self.disable_file().symlink_metadata().is_ok()
    }

    /// Creates the disable file (idempotent).
    pub fn set_disabled(&self) -> io::Result<()> {
        match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.disable_file())
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Removes the disable file (idempotent).
    pub fn set_enabled(&self) -> io::Result<()> {
        match fs::remove_file(self.disable_file()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Deletes stale `run/effective-sing-box.<u64>.json` files. Only called at
    /// cold start, after the daemon has confirmed it has no live child of its
    /// own (blueprint §11.1): the daemon just started, so any such file is a
    /// leftover from a previous instance. Strict match only — anything else in
    /// `run/` is not ours to delete.
    pub fn clean_stale_effective(&self) -> io::Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        let entries = match fs::read_dir(self.run_dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(removed),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if !is_effective_name(&name) {
                continue;
            }
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let path = entry.path();
            fs::remove_file(&path)?;
            removed.push(path);
        }
        Ok(removed)
    }

    /// The engine binary: the module ships `sing-box` next to `fluxd`
    /// (blueprint §13.1); tests override via [`ENGINE_BIN_ENV`].
    pub fn engine_binary(&self) -> PathBuf {
        if let Some(bin) = std::env::var_os(ENGINE_BIN_ENV) {
            if !bin.is_empty() {
                return PathBuf::from(bin);
            }
        }
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf));
        match exe_dir {
            Some(dir) => dir.join("sing-box"),
            None => PathBuf::from("sing-box"),
        }
    }
}

/// Strictly `effective-sing-box.<u64>.json`.
fn is_effective_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(middle) = name
        .strip_prefix("effective-sing-box.")
        .and_then(|rest| rest.strip_suffix(".json"))
    else {
        return false;
    };
    !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_digit()) && middle.parse::<u64>().is_ok()
}

/// Why the single-instance lock could not be taken.
#[derive(Debug)]
pub enum LockError {
    /// Another daemon holds the lock. The contained string is the holder's
    /// recorded pid, when readable.
    Held(Option<String>),
    /// Filesystem error opening or locking.
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Held(Some(pid)) => {
                write!(f, "another fluxd instance is already running (pid {pid} per run/daemon.lock)")
            }
            LockError::Held(None) => write!(f, "another fluxd instance is already running (run/daemon.lock is held)"),
            LockError::Io(e) => write!(f, "cannot take run/daemon.lock: {e}"),
        }
    }
}

/// The held single-instance lock. Dropping it (or dying, even by `SIGKILL`)
/// releases the `flock`; the file itself is never deleted.
#[derive(Debug)]
pub struct InstanceLock {
    file: fs::File,
}

impl InstanceLock {
    /// Takes `flock(LOCK_EX|LOCK_NB)` on `run/daemon.lock`. On contention the
    /// second instance must exit immediately without touching anything — no
    /// socket unlink, no object cleanup (blueprint §10.3, §23.1).
    pub fn acquire(layout: &Layout) -> Result<Self, LockError> {
        use std::io::{Read, Seek, Write};

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(layout.lock_path())
            .map_err(LockError::Io)?;

        // SAFETY: flock on a valid owned fd; LOCK_NB makes it non-blocking.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                let mut holder = String::new();
                let _ = file.read_to_string(&mut holder);
                let holder = holder.trim().to_string();
                return Err(LockError::Held((!holder.is_empty()).then_some(holder)));
            }
            return Err(LockError::Io(err));
        }

        // Record our pid for the readable rejection message of a later second
        // instance. Best effort; the lock itself is the authority.
        let _ = file.set_len(0);
        let _ = file.rewind();
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        let _ = writeln!(file, "{pid}");
        let _ = file.flush();

        Ok(Self { file })
    }

    /// The raw lock fd, kept only so the borrow lives as long as the daemon.
    pub fn as_raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let mut dir = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        dir.push(format!("flux-layout-{tag}-{pid}"));
        let _ = fs::remove_dir_all(&dir);
        Layout::at(dir)
    }

    #[test]
    fn ensure_creates_private_directories() {
        let layout = tmp_layout("ensure");
        layout.ensure().expect("create");
        assert!(layout.mode_error().is_none());
        for dir in [layout.root().to_path_buf(), layout.run_dir(), layout.config_dir()] {
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{dir:?}");
        }
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn wrong_mode_is_reported_not_fixed() {
        let layout = tmp_layout("mode");
        layout.ensure().expect("create");
        fs::set_permissions(layout.root(), fs::Permissions::from_mode(0o755)).unwrap();
        let err = layout.mode_error().expect("must report");
        assert_eq!(err, "runtime_dir_mode:0755 expected 0700");
        // Not silently repaired.
        let mode = fs::metadata(layout.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn second_lock_is_rejected_with_the_holder_pid() {
        let layout = tmp_layout("lock");
        layout.ensure().expect("create");

        let first = InstanceLock::acquire(&layout).expect("first lock");
        // flock is per open file description, so a second open of the same
        // path conflicts even inside one process.
        match InstanceLock::acquire(&layout) {
            Err(LockError::Held(Some(pid))) => {
                // SAFETY: getpid has no preconditions and cannot fail.
                let own = unsafe { libc::getpid() };
                assert_eq!(pid, own.to_string());
            }
            other => panic!("expected Held with pid, got {other:?}"),
        }
        drop(first);
        // Released on drop: a fresh acquire succeeds.
        InstanceLock::acquire(&layout).expect("re-acquire after drop");
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn disable_file_is_the_switch_and_is_idempotent() {
        let layout = tmp_layout("switch");
        layout.ensure().expect("create");
        assert!(!layout.disabled());
        layout.set_disabled().unwrap();
        layout.set_disabled().unwrap();
        assert!(layout.disabled());
        layout.set_enabled().unwrap();
        layout.set_enabled().unwrap();
        assert!(!layout.disabled());
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn stale_effective_cleanup_is_strict() {
        let layout = tmp_layout("stale");
        layout.ensure().expect("create");
        let run = layout.run_dir();
        for name in [
            "effective-sing-box.7.json",
            "effective-sing-box.18446744073709551615.json",
        ] {
            fs::write(run.join(name), b"{}").unwrap();
        }
        // Decoys that must survive: wrong shapes and non-u64 numbers.
        for name in [
            "effective-sing-box.x.json",
            "effective-sing-box..json",
            "effective-sing-box.7.json.bak",
            "effective-sing-box.99999999999999999999.json", // > u64::MAX
            "other.json",
            "daemon.lock",
        ] {
            fs::write(run.join(name), b"keep").unwrap();
        }
        let removed = layout.clean_stale_effective().unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!run.join("effective-sing-box.7.json").exists());
        for name in [
            "effective-sing-box.x.json",
            "effective-sing-box..json",
            "effective-sing-box.7.json.bak",
            "effective-sing-box.99999999999999999999.json",
            "other.json",
            "daemon.lock",
        ] {
            assert!(run.join(name).exists(), "{name} must survive");
        }
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn effective_name_matcher_is_exact() {
        assert!(is_effective_name(OsStr::new("effective-sing-box.1.json")));
        assert!(is_effective_name(OsStr::new("effective-sing-box.0.json")));
        assert!(!is_effective_name(OsStr::new("effective-sing-box.-1.json")));
        assert!(!is_effective_name(OsStr::new("effective-sing-box.1.json2")));
        assert!(!is_effective_name(OsStr::new("effective-sing-box.json")));
        assert!(!is_effective_name(OsStr::new("Effective-sing-box.1.json")));
    }
}
