//! Inotify watches on stable parent directories (blueprint §11.1, audit R04).
//!
//! Config is watched via the module directory (its parent) plus a watch on
//! `config/` itself. `MOVE_SELF` / `DELETE_SELF` / `IN_IGNORED` rebuild the
//! child watch rather than following a replaced inode. Overflow marks every
//! authority dirty so the next convergence rereads from those parents.

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::layout::Layout;

/// Linux `IN_CLOSE_WRITE`.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
/// Linux `IN_MOVED_FROM`.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
/// Linux `IN_MOVED_TO`.
pub const IN_MOVED_TO: u32 = 0x0000_0080;
/// Linux `IN_CREATE`.
pub const IN_CREATE: u32 = 0x0000_0100;
/// Linux `IN_DELETE`.
pub const IN_DELETE: u32 = 0x0000_0200;
/// Linux `IN_DELETE_SELF`.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
/// Linux `IN_MOVE_SELF`.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
/// Linux `IN_Q_OVERFLOW`.
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
/// Linux `IN_IGNORED`.
pub const IN_IGNORED: u32 = 0x0000_8000;

#[cfg(any(target_os = "linux", target_os = "android"))]
const MODULE_MASK: u32 = IN_CREATE
    | IN_DELETE
    | IN_MOVED_TO
    | IN_MOVED_FROM
    | IN_MOVE_SELF
    | IN_DELETE_SELF
    | IN_IGNORED;
#[cfg(any(target_os = "linux", target_os = "android"))]
const CONFIG_MASK: u32 = IN_CLOSE_WRITE
    | IN_CREATE
    | IN_DELETE
    | IN_MOVED_TO
    | IN_MOVED_FROM
    | IN_MOVE_SELF
    | IN_DELETE_SELF
    | IN_IGNORED;
#[cfg(any(target_os = "linux", target_os = "android"))]
const PACKAGES_MASK: u32 = CONFIG_MASK;

/// One parsed `inotify_event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    /// Watch descriptor.
    pub wd: i32,
    /// Event mask.
    pub mask: u32,
    /// Optional child name, without a trailing NUL.
    pub name: String,
}

/// Interest decoded from one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchAction {
    /// The manager `disable` file appeared or disappeared.
    Switch,
    /// A file under `config/` changed; policy and engine both recompute.
    Config,
    /// `packages.list` changed.
    Policy,
    /// A watched directory was replaced or the watch was dropped; rebuild.
    Rebuild,
    /// Queue overflow: reread every authority from the parent directories.
    Overflow,
}

/// Maps one inotify event onto a [`WatchAction`].
pub fn classify(
    event: &WatchEvent,
    module_wd: i32,
    config_wd: i32,
    packages_wd: Option<i32>,
) -> Option<WatchAction> {
    if event.mask & IN_Q_OVERFLOW != 0 {
        return Some(WatchAction::Overflow);
    }
    if event.mask & (IN_MOVE_SELF | IN_DELETE_SELF | IN_IGNORED) != 0 {
        return Some(WatchAction::Rebuild);
    }
    if event.wd == module_wd {
        if event.name == "disable" {
            return Some(WatchAction::Switch);
        }
        if event.name == "config" {
            return Some(WatchAction::Rebuild);
        }
        return None;
    }
    if event.wd == config_wd && !event.name.is_empty() {
        // Filename does not decide the domain: generated-byte equality does.
        return Some(WatchAction::Config);
    }
    if packages_wd == Some(event.wd) && event.name == "packages.list" {
        return Some(WatchAction::Policy);
    }
    None
}

/// Owns the inotify fd and the current watch descriptors.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct WatchSet {
    fd: OwnedFd,
    module_wd: i32,
    config_wd: i32,
    packages_wd: Option<i32>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl WatchSet {
    /// Creates the fd and installs the initial watches.
    pub fn open(layout: &Layout) -> io::Result<Self> {
        // SAFETY: inotify_init1; the fd is owned immediately.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just returned by the kernel.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut set = Self {
            fd,
            module_wd: -1,
            config_wd: -1,
            packages_wd: None,
        };
        set.rebuild(layout)?;
        Ok(set)
    }

    /// Epoll token fd.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Re-adds watches on the current directory inodes.
    pub fn rebuild(&mut self, layout: &Layout) -> io::Result<()> {
        self.module_wd = add_watch(self.fd.as_raw_fd(), layout.module_dir(), MODULE_MASK)?;
        self.config_wd = add_watch(self.fd.as_raw_fd(), &layout.config_dir(), CONFIG_MASK)?;
        self.packages_wd = Path::new(crate::packages::PACKAGES_LIST_PATH)
            .parent()
            .filter(|parent| parent.exists())
            .and_then(|parent| add_watch(self.fd.as_raw_fd(), parent, PACKAGES_MASK).ok());
        Ok(())
    }

    /// Drain the current inotify queue into decoded actions.
    pub fn drain(&self) -> io::Result<Vec<WatchAction>> {
        let mut buf = [0u8; 4096];
        let mut actions = Vec::new();
        loop {
            // SAFETY: buf is valid for its length; the fd is non-blocking.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            for event in parse_inotify(&buf[..n as usize]) {
                if let Some(action) =
                    classify(&event, self.module_wd, self.config_wd, self.packages_wd)
                {
                    actions.push(action);
                }
            }
        }
        Ok(actions)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn add_watch(fd: i32, dir: &Path, mask: u32) -> io::Result<i32> {
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    // SAFETY: valid fd and NUL-terminated path.
    let wd = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
    if wd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(wd)
}

fn parse_inotify(buf: &[u8]) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    const EVENT_HEAD: usize = 16; // sizeof(inotify_event) without name, on 64-bit
    while offset + EVENT_HEAD <= buf.len() {
        let wd = i32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        let name_len =
            u32::from_ne_bytes(buf[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let name_end = (offset + EVENT_HEAD + name_len).min(buf.len());
        let name_bytes = &buf[offset + EVENT_HEAD..name_end];
        let name = name_bytes
            .split(|b| *b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        events.push(WatchEvent { wd, mask, name });
        offset += EVENT_HEAD + name_len;
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(wd: i32, mask: u32, name: &str) -> WatchEvent {
        WatchEvent {
            wd,
            mask,
            name: name.to_string(),
        }
    }

    #[test]
    fn overflow_wins() {
        assert_eq!(
            classify(&event(1, IN_Q_OVERFLOW | IN_CREATE, "disable"), 1, 2, None),
            Some(WatchAction::Overflow)
        );
    }

    #[test]
    fn move_self_rebuilds() {
        assert_eq!(
            classify(&event(2, IN_MOVE_SELF, ""), 1, 2, None),
            Some(WatchAction::Rebuild)
        );
        assert_eq!(
            classify(&event(2, IN_DELETE_SELF, ""), 1, 2, None),
            Some(WatchAction::Rebuild)
        );
        assert_eq!(
            classify(&event(2, IN_IGNORED, ""), 1, 2, None),
            Some(WatchAction::Rebuild)
        );
    }

    #[test]
    fn disable_file_is_the_switch() {
        assert_eq!(
            classify(&event(1, IN_CREATE, "disable"), 1, 2, None),
            Some(WatchAction::Switch)
        );
        assert_eq!(classify(&event(1, IN_DELETE, "other"), 1, 2, None), None);
    }

    #[test]
    fn config_directory_replacement_rebuilds() {
        assert_eq!(
            classify(&event(1, IN_MOVED_FROM, "config"), 1, 2, None),
            Some(WatchAction::Rebuild)
        );
        assert_eq!(
            classify(&event(1, IN_MOVED_TO, "config"), 1, 2, None),
            Some(WatchAction::Rebuild)
        );
    }

    #[test]
    fn config_child_dirties_engine_and_policy_together() {
        assert_eq!(
            classify(&event(2, IN_CLOSE_WRITE, "flux.toml"), 1, 2, None),
            Some(WatchAction::Config)
        );
    }

    #[test]
    fn packages_list_is_policy() {
        assert_eq!(
            classify(&event(3, IN_CLOSE_WRITE, "packages.list"), 1, 2, Some(3)),
            Some(WatchAction::Policy)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn watchset_open_and_rebuild_on_a_layout() {
        use crate::layout::Layout;
        let mut dir = std::env::temp_dir();
        let pid = std::process::id();
        dir.push(format!("flux-watch-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = Layout::at(dir.clone());
        layout.ensure().expect("layout");
        let mut set = WatchSet::open(&layout).expect("inotify");
        set.rebuild(&layout).expect("rebuild");
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn parse_inotify_reads_a_named_event() {
        let mut buf = vec![0u8; 16 + 8];
        buf[0..4].copy_from_slice(&7i32.to_ne_bytes());
        buf[4..8].copy_from_slice(&IN_CREATE.to_ne_bytes());
        buf[12..16].copy_from_slice(&8u32.to_ne_bytes());
        buf[16..23].copy_from_slice(b"disable");
        let events = parse_inotify(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].wd, 7);
        assert_eq!(events[0].name, "disable");
        assert_eq!(events[0].mask, IN_CREATE);
    }
}
