//! Load the GKI-line `fluxrs.ko` and hold `/dev/fluxrs`.
//!
//! `docs/plan/rc4.md`: `fluxd` is the only loader (`finit_module`). Closing
//! this fd, including `SIGKILL`, clears the hook's live flag. The module
//! itself stays resident; a later start opens the node again. Ioctl numbers
//! live in [`flux_core::kmod_uapi`]. [`crate::dataplane::Manager`] holds the
//! fd: close, `SIGKILL`, and disable all return the hook to `NF_ACCEPT`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use flux_core::gki_line::{self, GkiLine};
use flux_core::kmod_uapi;

/// miscdevice node created by `kmod/fluxrs_ctl.c`.
pub const CTL_PATH: &str = "/dev/fluxrs";

/// Directory under the manager module that ships `fluxrs-androidN-X.Y*.ko`.
pub const DIR_NAME: &str = "kmod";

/// Kernel module name passed to `delete_module(2)` (from `obj-m := fluxrs.o`).
pub const MODULE_NAME: &str = "fluxrs";

#[cfg(target_arch = "aarch64")]
const NR_FINIT_MODULE: libc::c_long = 273;
#[cfg(target_arch = "aarch64")]
const NR_DELETE_MODULE: libc::c_long = 106;

#[cfg(target_arch = "x86_64")]
const NR_FINIT_MODULE: libc::c_long = 313;
#[cfg(target_arch = "x86_64")]
const NR_DELETE_MODULE: libc::c_long = 176;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("Flux has no audited finit_module fallback for this architecture");

/// Why the GKI-line module could not become the live control fd.
#[allow(dead_code)]
#[derive(Debug)]
pub enum LoadError {
    /// `uname -r` did not map to a GKI generation Flux ships.
    UnknownRelease(String),
    /// No `fluxrs-androidN-X.Y*.ko` in the kmod directory.
    MissingModule {
        /// Generation we looked for.
        line: GkiLine,
        /// Directory that was listed.
        dir: PathBuf,
    },
    /// `finit_module` failed. `EEXIST` is handled by opening the node instead.
    Finit {
        /// Path of the `.ko` we tried.
        path: PathBuf,
        /// Kernel errno.
        error: io::Error,
    },
    /// `/dev/fluxrs` could not be opened after the module was present.
    Control(io::Error),
    /// Listing or opening the `.ko` failed before the syscall.
    Io(io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::UnknownRelease(release) => {
                write!(f, "no GKI line for uname release {release}")
            }
            LoadError::MissingModule { line, dir } => {
                write!(f, "no {}*.ko in {}", line.module_stem(), dir.display())
            }
            LoadError::Finit { path, error } => {
                write!(f, "finit_module {}: {error}", path.display())
            }
            LoadError::Control(error) => write!(f, "open {CTL_PATH}: {error}"),
            LoadError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Live control fd. Dropping it (or the process) returns the hook to `NF_ACCEPT`.
#[allow(dead_code)]
pub struct LoadedModule {
    _ctl: OwnedFd,
}

#[allow(dead_code)]
impl LoadedModule {
    /// Borrow the control fd. Tests and diagnostics hold this to keep live=1.
    pub fn ctl_fd(&self) -> std::os::fd::RawFd {
        self._ctl.as_raw_fd()
    }

    /// Publish the official TPROXY bind addresses (network byte order on the wire).
    pub fn set_listeners(
        &self,
        v4: Ipv4Addr,
        v4_port: u16,
        v6: Ipv6Addr,
        v6_port: u16,
    ) -> io::Result<()> {
        let mut listeners = kmod_uapi::Listeners {
            v4_addr: u32::from_ne_bytes(v4.octets()),
            v4_port: v4_port.to_be(),
            pad0: 0,
            v6_addr: v6.octets(),
            v6_port: v6_port.to_be(),
            pad1: 0,
        };
        ioctl(
            self._ctl.as_raw_fd(),
            kmod_uapi::SET_LISTENERS,
            &mut listeners,
        )
    }

    /// Replace the selected-UID table. Empty slice clears it.
    pub fn set_uids(&self, uids: &[u32]) -> io::Result<()> {
        if uids.len() > kmod_uapi::UID_SLOT_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many UIDs for FLUXRS_SET_UIDS",
            ));
        }
        let mut body = kmod_uapi::Uids {
            count: uids.len() as u32,
            uids: [0; kmod_uapi::UID_SLOT_MAX],
        };
        body.uids[..uids.len()].copy_from_slice(uids);
        ioctl(self._ctl.as_raw_fd(), kmod_uapi::SET_UIDS, &mut body)
    }

    /// Publish `cidr_mode`, bypass prefixes, and exact self-addresses as one epoch.
    pub fn set_bypass(
        &self,
        cidr_mode: u32,
        v4: &[kmod_uapi::Pfx4],
        v6: &[kmod_uapi::Pfx6],
        self4: &[u32],
        self6: &[[u8; 16]],
    ) -> io::Result<()> {
        if v4.len() > kmod_uapi::LPM_MAX || v6.len() > kmod_uapi::LPM_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many prefixes for FLUXRS_SET_BYPASS",
            ));
        }
        if self4.len() > kmod_uapi::SELF_MAX || self6.len() > kmod_uapi::SELF_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many self-addresses for FLUXRS_SET_BYPASS",
            ));
        }
        let mut body = kmod_uapi::encode_bypass(cidr_mode, v4, v6, self4, self6);
        ioctl_bytes(self._ctl.as_raw_fd(), kmod_uapi::SET_BYPASS, &mut body)
    }

    /// Drop every published UID. Listeners stay until replaced or the fd closes.
    pub fn clear_uids(&self) -> io::Result<()> {
        let fd = self._ctl.as_raw_fd();
        loop {
            // SAFETY: fd is the exclusive /dev/fluxrs; CLEAR_UIDS takes no arg.
            let result = unsafe { libc::ioctl(fd, kmod_uapi::CLEAR_UIDS as libc::c_ulong) };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Counters from the hook. Does not change live/steal state.
    pub fn status(&self) -> io::Result<kmod_uapi::Status> {
        let mut status = kmod_uapi::Status::default();
        ioctl(self._ctl.as_raw_fd(), kmod_uapi::GET_STATUS, &mut status)?;
        Ok(status)
    }
}

fn ioctl<T>(fd: std::os::fd::RawFd, req: u32, arg: &mut T) -> io::Result<()> {
    loop {
        // SAFETY: fd is /dev/fluxrs; req is a fluxrs ioctl; arg matches the
        // kernel struct size encoded in req.
        let result = unsafe { libc::ioctl(fd, req as libc::c_ulong, arg as *mut T) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn ioctl_bytes(fd: std::os::fd::RawFd, req: u32, arg: &mut [u8]) -> io::Result<()> {
    loop {
        // SAFETY: fd is /dev/fluxrs; req is SET_BYPASS; arg is the packed
        // header-plus-arrays buffer the kernel copy_from_user reads.
        let result = unsafe { libc::ioctl(fd, req as libc::c_ulong, arg.as_mut_ptr()) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `uname -r` as the kernel reports it.
pub fn kernel_release() -> io::Result<String> {
    // SAFETY: uname writes one fixed-size utsname; zeroing is valid.
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: uname guarantees a NUL-terminated release field.
    Ok(unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

/// Best-effort `delete_module`. EBUSY/ENOENT are returned to the caller.
pub fn unload() -> io::Result<()> {
    delete_module()
}

/// Load the matching `.ko` for `release` from `kmod_dir` and open `/dev/fluxrs`.
///
/// `EEXIST` from `finit_module` means a previous start left the module
/// resident; that is success so long as the control node opens.
pub fn load_from_dir(kmod_dir: &Path, release: &str) -> Result<LoadedModule, LoadError> {
    let line = gki_line::from_uname_release(release)
        .ok_or_else(|| LoadError::UnknownRelease(release.to_string()))?;
    let name = pick_name(kmod_dir, line)?;
    let path = kmod_dir.join(name);
    match finit_module(&path) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
        Err(error) => {
            return Err(LoadError::Finit { path, error });
        }
    }
    match open_ctl() {
        Ok(ctl) => Ok(LoadedModule { _ctl: ctl }),
        Err(error) => {
            let _ = delete_module();
            Err(LoadError::Control(error))
        }
    }
}

fn pick_name(kmod_dir: &Path, line: GkiLine) -> Result<String, LoadError> {
    let mut names = Vec::new();
    let entries = fs::read_dir(kmod_dir).map_err(LoadError::Io)?;
    for entry in entries {
        let entry = entry.map_err(LoadError::Io)?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    gki_line::pick_module_file(line, names.iter().map(String::as_str))
        .map(str::to_owned)
        .ok_or_else(|| LoadError::MissingModule {
            line,
            dir: kmod_dir.to_path_buf(),
        })
}

fn finit_module(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    let fd = file.as_raw_fd();
    loop {
        // SAFETY: fd is an open `.ko`; the empty param string is a valid
        // NUL-terminated empty argv for finit_module; flags are 0.
        let result = unsafe {
            libc::syscall(
                NR_FINIT_MODULE,
                fd,
                b"\0".as_ptr().cast::<libc::c_char>(),
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn open_ctl() -> io::Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(CTL_PATH)?;
    Ok(OwnedFd::from(file))
}

fn delete_module() -> io::Result<()> {
    let mut name = Vec::from(MODULE_NAME.as_bytes());
    name.push(0);
    loop {
        // SAFETY: name is a NUL-terminated module name; O_NONBLOCK avoids
        // waiting on an unexpected refcount (batch 1 recovery only).
        let result = unsafe {
            libc::syscall(
                NR_DELETE_MODULE,
                name.as_ptr().cast::<libc::c_char>(),
                libc::O_NONBLOCK,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_name_selects_the_gki_line_file() {
        let dir = std::env::temp_dir().join(format!("fluxrs-kmod-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        File::create(dir.join("fluxrs-android13-5.15.ko")).unwrap();
        File::create(dir.join("fluxrs-android14-6.1.ko")).unwrap();
        let line = gki_line::from_uname_release("5.15.211-Qkernel").unwrap();
        let name = pick_name(&dir, line).unwrap();
        assert_eq!(name, "fluxrs-android13-5.15.ko");
        assert_eq!(DIR_NAME, "kmod");
        assert_eq!(kmod_uapi::UID_SLOT_MAX, 1024);
        assert_eq!(kmod_uapi::SET_LISTENERS, 0x401C_4601);
        assert_eq!(kmod_uapi::SET_BYPASS, 0x4014_4605);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn uapi_fallback_constants_match_linux() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(NR_FINIT_MODULE, 313);
            assert_eq!(NR_DELETE_MODULE, 176);
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(NR_FINIT_MODULE, 273);
            assert_eq!(NR_DELETE_MODULE, 106);
        }
    }
}
