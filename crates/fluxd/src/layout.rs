//! Runtime directory layout, permissions and the single-instance lock.
//!
//! Implements blueprint §11.1 and §10.3. The lock is `flock(LOCK_EX|LOCK_NB)`
//! on a file the daemon holds open for its whole life, so it is released by the
//! kernel even on `SIGKILL` — there is no stale-lock recovery path to get wrong.
//!
//! The on/off switch is the presence of `disable` in the root manager's own
//! module directory (owner decision C9, `docs/spec/interaction.md` §27.1):
//! present = disabled, absent = enabled, any other metadata failure =
//! [`Presence::Unreadable`]. Unreadable MUST NOT be treated as enabled.

use flux_core::snapshot::Presence;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

/// Reads at most `cap` bytes; the caller's parser enforces its own limit, this
/// only prevents an accidentally huge file from being slurped whole.
pub(crate) fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(cap as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Root of all runtime state (blueprint §1.1).
pub const RUNTIME_ROOT: &str = "/data/adb/flux-rs";

/// The root manager's module directory: where the `disable` switch and
/// `module.prop` live. Note the underscore, and note that this directory
/// belongs to the manager — Flux writes only those two files and never
/// creates, moves or deletes the directory itself.
pub const MODULE_DIR: &str = "/data/adb/modules/Flux-rs";

/// Environment override for the runtime root. A test hook only: it lets the
/// integration tests run a full daemon against a temp directory as an ordinary
/// user. Production (`service.sh`) never sets it.
pub const RUNTIME_ROOT_ENV: &str = "FLUX_RUNTIME_ROOT";

/// Environment override for the module directory. Same status as
/// [`RUNTIME_ROOT_ENV`]: a test hook so integration tests can own a writable
/// switch directory. Production never sets it.
pub const MODULE_DIR_ENV: &str = "FLUX_MODULE_DIR";

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
    module_dir: PathBuf,
}

impl Layout {
    /// The production layout, honouring the [`RUNTIME_ROOT_ENV`] and
    /// [`MODULE_DIR_ENV`] test hooks.
    pub fn product() -> Self {
        let root = match std::env::var_os(RUNTIME_ROOT_ENV) {
            Some(root) if !root.is_empty() => PathBuf::from(root),
            _ => PathBuf::from(RUNTIME_ROOT),
        };
        let module_dir = match std::env::var_os(MODULE_DIR_ENV) {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => installed_module_dir(),
        };
        Self::at(root).with_module_dir(module_dir)
    }

    /// A layout rooted at an arbitrary directory, with the switch in that same
    /// directory (tests use temp dirs they own).
    pub fn at(root: PathBuf) -> Self {
        Self {
            module_dir: root.clone(),
            root,
        }
    }

    /// Points the switch and `module.prop` at the manager's module directory,
    /// which is a different tree from the runtime state root.
    pub fn with_module_dir(mut self, module_dir: PathBuf) -> Self {
        self.module_dir = module_dir;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The manager's module directory. Flux writes `disable` and the
    /// `description=` line of `module.prop` here and nothing else.
    pub fn module_dir(&self) -> &Path {
        &self.module_dir
    }

    /// The manager's `module.prop`, whose `description=` doubles as the live
    /// status readout in the manager's module list.
    pub fn module_prop(&self) -> PathBuf {
        self.module_dir.join("module.prop")
    }

    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    /// The switch file: present = disabled (C9, `docs/spec/interaction.md` §27.1). This is the
    /// manager's own module toggle, so the manager UI and `fluxd enable` /
    /// `fluxd disable` drive one file rather than two.
    pub fn disable_file(&self) -> PathBuf {
        self.module_dir.join("disable")
    }

    /// Single-instance lock (blueprint §10.3).
    pub fn lock_path(&self) -> PathBuf {
        self.run_dir().join("daemon.lock")
    }

    /// True when another process holds `daemon.lock`. Failure to inspect the
    /// lock is treated as held: `stop` must not claim success without proof
    /// the daemon is gone.
    pub fn instance_lock_held(&self) -> bool {
        match InstanceLock::acquire(self) {
            Err(LockError::Held(_)) => true,
            Ok(_) => false,
            Err(_) => true,
        }
    }

    /// Control socket (blueprint §10.3).
    pub fn control_socket(&self) -> PathBuf {
        self.run_dir().join("control.sock")
    }

    pub fn flux_toml(&self) -> PathBuf {
        self.config_dir().join("flux.toml")
    }

    /// The user-owned sing-box template. The daemon only reads this path.
    pub fn template_json(&self) -> PathBuf {
        self.config_dir().join("template.json")
    }

    /// Optional disjoint advanced policy (§11.2.4).
    pub fn advanced_toml(&self) -> PathBuf {
        self.config_dir().join("advanced.toml")
    }

    /// Source-addressed raw response caches (§28.5).
    pub fn source_cache_dir(&self) -> PathBuf {
        self.run_dir().join("cache/sources")
    }

    pub fn source_cache(&self, source: &flux_core::subscription::RemoteSource) -> PathBuf {
        self.source_cache_dir().join(format!("{}.raw", source.id()))
    }

    pub fn engine_cache(&self) -> PathBuf {
        self.run_dir().join("cache/sing-box.db")
    }

    /// The daemon's own log. Appended by the daemon and the engine's captured
    /// stdout/stderr (blueprint §13.3); included in `bugreport`.
    pub fn log_file(&self) -> PathBuf {
        self.run_dir().join("fluxd.log")
    }

    /// The immutable per-generation engine config (blueprint §11.1).
    pub fn effective_path(&self, generation: u64) -> PathBuf {
        self.run_dir().join(format!("sing-box.{generation}.json"))
    }

    /// Makes the root, `run/` and `config/` exist as directories owned by this
    /// uid with mode 0700, and returns one line per repair it had to make so
    /// the caller can log it.
    ///
    /// The three directories are Flux's own (§11.1), so a drifted mode or owner
    /// is restored rather than reported as a fault — the same way the daemon
    /// rebuilds any other object it owns. What is refused is a symlink or a
    /// non-directory at one of the paths: that is somebody else's object where
    /// Flux's private directory has to be, and Flux never replaces or follows
    /// an object it cannot prove is its own (§23.1, PHIL-5).
    pub fn ensure(&self) -> Result<Vec<String>, RootError> {
        Self::ensure_directories([
            self.root.clone(),
            self.run_dir(),
            self.config_dir(),
            self.run_dir().join("cache"),
        ])
    }

    pub fn ensure_source_cache(&self) -> io::Result<()> {
        Self::ensure_directories([self.source_cache_dir()])
            .map(|_| ())
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn ensure_directories(
        dirs: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Vec<String>, RootError> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let own_uid = unsafe { libc::geteuid() };
        let mut repairs = Vec::new();
        for dir in dirs {
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => continue,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(RootError::Io { path: dir, error }),
            }
            let meta = fs::symlink_metadata(&dir).map_err(|error| RootError::Io {
                path: dir.clone(),
                error,
            })?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(RootError::NotADirectory(dir));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    RootError::Io {
                        path: dir.clone(),
                        error,
                    }
                })?;
                repairs.push(format!(
                    "{}: mode 0{mode:o} restored to 0700",
                    dir.display()
                ));
            }
            if meta.uid() != own_uid {
                std::os::unix::fs::chown(&dir, Some(own_uid), None).map_err(|error| {
                    RootError::Io {
                        path: dir.clone(),
                        error,
                    }
                })?;
                repairs.push(format!(
                    "{}: owner uid {} restored to {own_uid}",
                    dir.display(),
                    meta.uid()
                ));
            }
        }
        Ok(repairs)
    }

    /// Observation of the manager switch file (C9). Contents are never read.
    pub fn disable_presence(&self) -> Presence {
        match self.disable_file().symlink_metadata() {
            Ok(_) => Presence::Present,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Presence::Absent,
            Err(_) => Presence::Unreadable,
        }
    }

    /// Whether capture must not be requested from the switch.
    ///
    /// True for both a present `disable` file and an unreadable path. Only
    /// [`Presence::Absent`] permits capture (blueprint §11.1).
    pub fn disabled(&self) -> bool {
        !self.disable_presence().capture_permitted()
    }

    /// Creates the disable file (idempotent).
    pub fn set_disabled(&self) -> io::Result<()> {
        match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

    /// Deletes stale `run/sing-box.<u64>.json` files. Only called at
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
            let meta = fs::symlink_metadata(entry.path())?;
            // Production runs as root; host tests run as their own euid. A
            // symlink or foreign-owned lookalike is never ours to remove.
            // SAFETY: geteuid has no preconditions and cannot fail.
            let own_uid = unsafe { libc::geteuid() };
            if meta.file_type().is_symlink() || !meta.is_file() || meta.uid() != own_uid {
                continue;
            }
            let path = entry.path();
            fs::remove_file(&path)?;
            removed.push(path);
        }
        Ok(removed)
    }

    /// Removes the two exact temporary names used by subscription cache
    /// replacement. A killed writer may leave one behind between fsync and
    /// rename; no other name in `run/` is considered daemon-owned here.
    pub fn clean_stale_subscription_temps(&self) -> io::Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        for path in [
            self.run_dir().join(".subscription.raw.subscription.tmp"),
            self.run_dir().join(".subscription.url.subscription.tmp"),
        ] {
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            // SAFETY: geteuid has no preconditions and cannot fail.
            let own_uid = unsafe { libc::geteuid() };
            if meta.file_type().is_symlink() || !meta.is_file() || meta.uid() != own_uid {
                continue;
            }
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

/// The module directory Flux is actually installed in.
///
/// Derived from the running binary (`<module>/bin/fluxd`) rather than hardcoded
/// so a renamed or side-loaded module still watches its own switch. Falls back
/// to [`MODULE_DIR`], which makes a wrong deployment fail loudly at the inotify
/// watch instead of silently watching a directory nobody writes.
fn installed_module_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            let bin = exe.parent()?;
            (bin.file_name() == Some(OsStr::new("bin")))
                .then(|| bin.parent().map(Path::to_path_buf))?
        })
        .unwrap_or_else(|| PathBuf::from(MODULE_DIR))
}

/// Strictly `sing-box.<u64>.json`.
fn is_effective_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(middle) = name
        .strip_prefix("sing-box.")
        .and_then(|rest| rest.strip_suffix(".json"))
    else {
        return false;
    };
    !middle.is_empty()
        && middle.bytes().all(|b| b.is_ascii_digit())
        && middle.parse::<u64>().is_ok()
}

/// Why the state root cannot be used at all (§23.1). Both variants are
/// terminal for this convergence round; neither is repaired.
#[derive(Debug)]
pub enum RootError {
    /// A symlink or a non-directory sits where one of Flux's private
    /// directories must be. It is not Flux's object, so it is left alone.
    NotADirectory(PathBuf),
    /// The directory could not be created, inspected or restored.
    Io { path: PathBuf, error: io::Error },
}

impl RootError {
    /// The stable `last_error` token of §24.2.
    pub fn token(&self) -> String {
        match self {
            RootError::NotADirectory(path) => {
                format!("runtime_dir_type:{} expected directory", path.display())
            }
            RootError::Io { path, error } => format!(
                "runtime_dir_unusable:{}:{}",
                path.display(),
                error
                    .raw_os_error()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("{:?}", error.kind()))
            ),
        }
    }
}

impl std::fmt::Display for RootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootError::NotADirectory(path) => write!(
                f,
                "{} is a symlink or not a directory; Flux needs a private directory there and will not replace what it finds",
                path.display()
            ),
            RootError::Io { path, error } => {
                write!(f, "cannot set up {}: {error}", path.display())
            }
        }
    }
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
                write!(
                    f,
                    "another fluxd instance is already running (pid {pid} per run/daemon.lock)"
                )
            }
            LockError::Held(None) => write!(
                f,
                "another fluxd instance is already running (run/daemon.lock is held)"
            ),
            LockError::Io(e) => write!(f, "cannot take run/daemon.lock: {e}"),
        }
    }
}

/// The held single-instance lock. Dropping it (or dying, even by `SIGKILL`)
/// releases the `flock`; the file itself is never deleted.
#[derive(Debug)]
pub struct InstanceLock {
    /// Held purely for its open file description: the flock lives and dies
    /// with it. Nothing ever reads it back.
    _file: fs::File,
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
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

        Ok(Self { _file: file })
    }
}

/// Durable private same-directory replacement, shared by accepted caches and installation.
pub fn write_private_replace(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.write.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("raw")
    ));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
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
        assert_eq!(
            layout.template_json(),
            layout.config_dir().join("template.json")
        );
        assert_eq!(layout.log_file(), layout.run_dir().join("fluxd.log"));
        assert_eq!(
            layout.source_cache_dir(),
            layout.run_dir().join("cache/sources")
        );
        assert!(layout.ensure().expect("idempotent").is_empty());
        for dir in [
            layout.root().to_path_buf(),
            layout.run_dir(),
            layout.config_dir(),
        ] {
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{dir:?}");
        }
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn drifted_mode_is_restored_and_reported() {
        let layout = tmp_layout("mode");
        layout.ensure().expect("create");
        fs::set_permissions(layout.root(), fs::Permissions::from_mode(0o755)).unwrap();
        let repairs = layout.ensure().expect("the root is ours to repair");
        assert_eq!(repairs.len(), 1, "{repairs:?}");
        assert!(
            repairs[0].ends_with("mode 0755 restored to 0700"),
            "{repairs:?}"
        );
        let mode = fs::metadata(layout.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // A second pass finds nothing to do.
        assert!(layout.ensure().expect("clean").is_empty());
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn a_symlink_where_a_directory_belongs_is_refused_not_replaced() {
        let layout = tmp_layout("symlink");
        fs::create_dir_all(layout.root()).unwrap();
        let elsewhere = layout.root().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, layout.run_dir()).unwrap();
        match layout.ensure() {
            Err(RootError::NotADirectory(path)) => {
                assert_eq!(path, layout.run_dir());
                let error = RootError::NotADirectory(path);
                assert!(error.token().starts_with("runtime_dir_type:"), "{error}");
            }
            other => panic!("a symlink must be refused, got {other:?}"),
        }
        // Still a symlink: nothing was unlinked or followed.
        assert!(fs::symlink_metadata(layout.run_dir())
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn second_lock_is_rejected_with_the_holder_pid() {
        let layout = tmp_layout("lock");
        layout.ensure().expect("create");

        let first = InstanceLock::acquire(&layout).expect("first lock");
        assert!(layout.instance_lock_held());
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
        assert!(!layout.instance_lock_held());
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
    fn unreadable_disable_is_not_treated_as_enabled() {
        let layout = tmp_layout("switch-unreadable");
        layout.ensure().expect("create");
        assert_eq!(layout.disable_presence(), Presence::Absent);
        // Root can still search a 000 directory it owns, so the EACCES path
        // is only asserted for an unprivileged uid.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            fs::remove_dir_all(layout.root()).unwrap();
            return;
        }
        fs::set_permissions(layout.root(), fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(layout.disable_presence(), Presence::Unreadable);
        assert!(layout.disabled(), "Unreadable must not collapse to enabled");
        fs::set_permissions(layout.root(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn stale_effective_cleanup_is_strict() {
        let layout = tmp_layout("stale");
        layout.ensure().expect("create");
        let run = layout.run_dir();
        for name in ["sing-box.7.json", "sing-box.18446744073709551615.json"] {
            fs::write(run.join(name), b"{}").unwrap();
        }
        // Decoys that must survive: wrong shapes and non-u64 numbers.
        for name in [
            "sing-box.x.json",
            "sing-box..json",
            "sing-box.7.json.bak",
            "sing-box.99999999999999999999.json", // > u64::MAX
            "effective-sing-box.7.json",
            "other.json",
            "daemon.lock",
        ] {
            fs::write(run.join(name), b"keep").unwrap();
        }
        let removed = layout.clean_stale_effective().unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!run.join("sing-box.7.json").exists());
        for name in [
            "sing-box.x.json",
            "sing-box..json",
            "sing-box.7.json.bak",
            "sing-box.99999999999999999999.json",
            "effective-sing-box.7.json",
            "other.json",
            "daemon.lock",
        ] {
            assert!(run.join(name).exists(), "{name} must survive");
        }
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn stale_subscription_temp_cleanup_is_strict() {
        let layout = tmp_layout("subscription-temp");
        layout.ensure().expect("create");
        let run = layout.run_dir();
        for name in [
            ".subscription.raw.subscription.tmp",
            ".subscription.url.subscription.tmp",
        ] {
            fs::write(run.join(name), b"stale").unwrap();
        }
        for name in [
            ".subscription.raw.subscription.123",
            ".subscription.raw.subscription.tmp.bak",
            "subscription.raw",
        ] {
            fs::write(run.join(name), b"keep").unwrap();
        }

        let removed = layout.clean_stale_subscription_temps().unwrap();
        assert_eq!(removed.len(), 2);
        for name in [
            ".subscription.raw.subscription.123",
            ".subscription.raw.subscription.tmp.bak",
            "subscription.raw",
        ] {
            assert!(run.join(name).exists(), "{name}");
        }
        fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn effective_name_matcher_is_exact() {
        assert!(is_effective_name(OsStr::new("sing-box.1.json")));
        assert!(is_effective_name(OsStr::new("sing-box.0.json")));
        assert!(!is_effective_name(OsStr::new("sing-box.-1.json")));
        assert!(!is_effective_name(OsStr::new("sing-box.1.json2")));
        assert!(!is_effective_name(OsStr::new("sing-box.json")));
        assert!(!is_effective_name(OsStr::new("Sing-box.1.json")));
        assert!(!is_effective_name(OsStr::new("effective-sing-box.1.json")));
    }
}
