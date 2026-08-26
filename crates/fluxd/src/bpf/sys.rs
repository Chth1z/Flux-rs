//! Raw `bpf(2)` command encoders.
//!
//! Each command uses a zeroed byte buffer and writes only documented UAPI
//! fields. This avoids depending on an NDK-specific `union bpf_attr` layout
//! while keeping every unsafe syscall and kernel pointer in this module.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
pub const BPF_OBJ_NAME_LEN: usize = 16;
pub const BPF_F_NO_PREALLOC: u32 = 1;
#[allow(dead_code)] // Phase 5 checksum-adjusting TC calls use this UAPI flag.
pub const BPF_F_MARK_MANGLED_0: u64 = 1 << 6;

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
#[allow(dead_code)] // The checked query seam is consumed when Phase 5 attaches.
const BPF_PROG_QUERY: u32 = 16;
const BPF_BTF_LOAD: u32 = 18;
#[allow(dead_code)] // Control snapshots are frozen in Phase 5.
const BPF_MAP_FREEZE: u32 = 22;

const VERIFIER_LOG_BYTES: usize = 256 * 1024;

// §12.7(1): hard-coded syscall-number fallback. We deliberately do not use
// libc::SYS_bpf, which is missing from some Android NDK UAPI combinations.
#[cfg(target_arch = "aarch64")]
const NR_BPF: libc::c_long = 280;
#[cfg(target_arch = "arm")]
const NR_BPF: libc::c_long = 386;
#[cfg(target_arch = "x86")]
const NR_BPF: libc::c_long = 357;
#[cfg(target_arch = "x86_64")]
const NR_BPF: libc::c_long = 321;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
compile_error!("Flux has no audited __NR_bpf fallback for this architecture");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapCreate<'a> {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: Option<RawFd>,
    pub name: &'a str,
    pub btf_fd: Option<RawFd>,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: String,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    pub program_type: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub xlated_prog_len: u32,
    pub name: String,
}

#[derive(Debug)]
pub struct ProgramLoadFailure {
    pub error: io::Error,
    pub log: String,
}

#[repr(C)]
#[derive(Default)]
struct RawMapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    _pad: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Default)]
struct RawProgramInfo {
    program_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; BPF_OBJ_NAME_LEN],
    ifindex: u32,
    gpl_compatible: u32,
}

pub fn load_btf(blob: &[u8]) -> io::Result<OwnedFd> {
    let mut log = vec![0u8; 64 * 1024];
    let mut attr = [0u8; 32];
    put_u64(&mut attr, 0, ptr_u64(blob.as_ptr()));
    put_u64(&mut attr, 8, ptr_u64(log.as_mut_ptr()));
    put_u32(&mut attr, 16, checked_u32(blob.len(), "BTF blob")?);
    put_u32(&mut attr, 20, checked_u32(log.len(), "BTF log")?);
    put_u32(&mut attr, 24, 1);
    bpf_fd(BPF_BTF_LOAD, &mut attr)
}

pub fn create_map(spec: MapCreate<'_>) -> io::Result<OwnedFd> {
    validate_name(spec.name)?;
    let mut attr = [0u8; 72];
    put_u32(&mut attr, 0, spec.map_type);
    put_u32(&mut attr, 4, spec.key_size);
    put_u32(&mut attr, 8, spec.value_size);
    put_u32(&mut attr, 12, spec.max_entries);
    put_u32(&mut attr, 16, spec.map_flags);
    if let Some(fd) = spec.inner_map_fd {
        put_u32(&mut attr, 20, fd_u32(fd)?);
    }
    put_name(&mut attr[28..28 + BPF_OBJ_NAME_LEN], spec.name);
    if let Some(fd) = spec.btf_fd {
        put_u32(&mut attr, 48, fd_u32(fd)?);
        put_u32(&mut attr, 52, spec.btf_key_type_id);
        put_u32(&mut attr, 56, spec.btf_value_type_id);
    }
    bpf_fd(BPF_MAP_CREATE, &mut attr)
}

#[allow(dead_code)] // Phase 5 publishes control_root and policy entries.
pub fn update_map(map_fd: RawFd, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
    let mut attr = [0u8; 32];
    put_u32(&mut attr, 0, fd_u32(map_fd)?);
    put_u64(&mut attr, 8, ptr_u64(key.as_ptr()));
    put_u64(&mut attr, 16, ptr_u64(value.as_ptr()));
    put_u64(&mut attr, 24, flags);
    bpf_zero(BPF_MAP_UPDATE_ELEM, &mut attr)
}

#[allow(dead_code)] // Phase 5 freezes each immutable control leaf.
pub fn freeze_map(map_fd: RawFd) -> io::Result<()> {
    let mut attr = [0u8; 4];
    put_u32(&mut attr, 0, fd_u32(map_fd)?);
    bpf_zero(BPF_MAP_FREEZE, &mut attr)
}

pub fn load_sched_cls(name: &str, instructions: &[u8]) -> Result<OwnedFd, ProgramLoadFailure> {
    if instructions.is_empty() || !instructions.len().is_multiple_of(8) {
        return Err(ProgramLoadFailure {
            error: io::Error::new(io::ErrorKind::InvalidInput, "invalid BPF instruction bytes"),
            log: String::new(),
        });
    }
    if let Err(error) = validate_name(name) {
        return Err(ProgramLoadFailure {
            error,
            log: String::new(),
        });
    }

    let mut log = vec![0u8; VERIFIER_LOG_BYTES];
    match load_sched_cls_once(name, instructions, Some(&mut log)) {
        Ok(fd) => Ok(fd),
        Err(first)
            if matches!(
                first.raw_os_error(),
                Some(libc::EAGAIN) | Some(libc::ENOSPC)
            ) =>
        {
            let first_errno = first.raw_os_error();
            match load_sched_cls_once(name, instructions, None) {
                Ok(fd) => Ok(fd),
                Err(second) => {
                    let error = if matches!(
                        second.raw_os_error(),
                        Some(libc::EAGAIN) | Some(libc::ENOSPC)
                    ) {
                        first_errno.map_or(second, io::Error::from_raw_os_error)
                    } else {
                        second
                    };
                    Err(ProgramLoadFailure {
                        error,
                        log: log_text(&log),
                    })
                }
            }
        }
        Err(error) => Err(ProgramLoadFailure {
            error,
            log: log_text(&log),
        }),
    }
}

fn load_sched_cls_once(
    name: &str,
    instructions: &[u8],
    log: Option<&mut [u8]>,
) -> io::Result<OwnedFd> {
    static LICENSE: &[u8] = b"GPL\0";
    let mut attr = [0u8; 120];
    put_u32(&mut attr, 0, BPF_PROG_TYPE_SCHED_CLS);
    put_u32(
        &mut attr,
        4,
        checked_u32(instructions.len() / 8, "BPF instruction count")?,
    );
    put_u64(&mut attr, 8, ptr_u64(instructions.as_ptr()));
    put_u64(&mut attr, 16, ptr_u64(LICENSE.as_ptr()));
    if let Some(log) = log {
        put_u32(&mut attr, 24, 1);
        put_u32(&mut attr, 28, checked_u32(log.len(), "verifier log")?);
        put_u64(&mut attr, 32, ptr_u64(log.as_mut_ptr()));
    }
    put_name(&mut attr[48..48 + BPF_OBJ_NAME_LEN], name);
    // expected_attach_type, func_info, line_info and BTF fields remain zero.
    bpf_fd(BPF_PROG_LOAD, &mut attr)
}

pub fn map_info(fd: RawFd) -> io::Result<MapInfo> {
    let mut raw = RawMapInfo::default();
    object_info(fd, &mut raw)?;
    Ok(MapInfo {
        map_type: raw.map_type,
        id: raw.id,
        key_size: raw.key_size,
        value_size: raw.value_size,
        max_entries: raw.max_entries,
        map_flags: raw.map_flags,
        name: parse_name(&raw.name),
        btf_id: raw.btf_id,
        btf_key_type_id: raw.btf_key_type_id,
        btf_value_type_id: raw.btf_value_type_id,
    })
}

pub fn program_info(fd: RawFd) -> io::Result<ProgramInfo> {
    let mut raw = RawProgramInfo::default();
    object_info(fd, &mut raw)?;
    Ok(ProgramInfo {
        program_type: raw.program_type,
        id: raw.id,
        tag: raw.tag,
        xlated_prog_len: raw.xlated_prog_len,
        name: parse_name(&raw.name),
    })
}

pub fn program_fd_by_id_verified(id: u32) -> io::Result<OwnedFd> {
    let fd = fd_by_id(BPF_PROG_GET_FD_BY_ID, id)?;
    if program_info(fd.as_raw_fd())?.id != id {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(fd)
}

#[allow(dead_code)] // Device cleanup tests and Phase 5 ownership use this.
pub fn map_fd_by_id_verified(id: u32) -> io::Result<OwnedFd> {
    let fd = fd_by_id(BPF_MAP_GET_FD_BY_ID, id)?;
    if map_info(fd.as_raw_fd())?.id != id {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(fd)
}

/// Checklist §12.7(7), ready for Phase 5's attachment inventory.
#[allow(dead_code)] // Phase 4 loads but does not attach/query programs.
pub fn query_program_ids(
    target_fd: RawFd,
    attach_type: u32,
    capacity: usize,
) -> io::Result<Vec<u32>> {
    if capacity == 0 || capacity > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF_PROG_QUERY capacity is invalid",
        ));
    }
    let mut ids = vec![0u32; capacity];
    let mut attr = [0u8; 32];
    put_u32(&mut attr, 0, fd_u32(target_fd)?);
    put_u32(&mut attr, 4, attach_type);
    put_u64(&mut attr, 16, ptr_u64(ids.as_mut_ptr()));
    put_u32(&mut attr, 24, capacity as u32);
    let result = bpf_zero(BPF_PROG_QUERY, &mut attr);
    let reported = get_u32(&attr, 24) as usize;
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ENOSPC) || reported > capacity => {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        Err(error) => return Err(error),
        Ok(()) if reported > capacity => {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        Ok(()) => {}
    }
    ids.truncate(reported);
    Ok(ids)
}

fn fd_by_id(command: u32, id: u32) -> io::Result<OwnedFd> {
    let mut attr = [0u8; 16];
    put_u32(&mut attr, 0, id);
    bpf_fd(command, &mut attr)
}

fn object_info<T>(fd: RawFd, info: &mut T) -> io::Result<()> {
    let mut attr = [0u8; 16];
    put_u32(&mut attr, 0, fd_u32(fd)?);
    put_u32(
        &mut attr,
        4,
        checked_u32(size_of::<T>(), "BPF object info")?,
    );
    put_u64(&mut attr, 8, ptr_u64(info as *mut T));
    bpf_zero(BPF_OBJ_GET_INFO_BY_FD, &mut attr)
}

fn bpf_fd(command: u32, attr: &mut [u8]) -> io::Result<OwnedFd> {
    let result = bpf_call(command, attr)?;
    let fd = i32::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bpf returned invalid fd"))?;
    // SAFETY: a successful FD-producing bpf command returns a new owned FD.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bpf_zero(command: u32, attr: &mut [u8]) -> io::Result<()> {
    let result = bpf_call(command, attr)?;
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bpf command {command} returned {result}, expected zero"),
        ))
    }
}

fn bpf_call(command: u32, attr: &mut [u8]) -> io::Result<libc::c_long> {
    loop {
        // SAFETY: attr is writable and valid for attr.len(); command-specific
        // encoders above populate only documented bpf_attr fields.
        let result = unsafe {
            libc::syscall(
                NR_BPF,
                command as libc::c_uint,
                attr.as_mut_ptr().cast::<c_void>(),
                attr.len() as libc::c_uint,
            )
        };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= BPF_OBJ_NAME_LEN
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid BPF object name `{name}`"),
        ));
    }
    Ok(())
}

fn put_name(dst: &mut [u8], name: &str) {
    dst[..name.len()].copy_from_slice(name.as_bytes());
}

fn parse_name(bytes: &[u8; BPF_OBJ_NAME_LEN]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn log_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn checked_u32(value: usize, label: &str) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} does not fit u32"),
        )
    })
}

fn fd_u32(fd: RawFd) -> io::Result<u32> {
    u32::try_from(fd).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative fd"))
}

fn ptr_u64<T>(pointer: *const T) -> u64 {
    pointer as usize as u64
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed attr range"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_info_layout_matches_linux_uapi_prefixes() {
        assert_eq!(std::mem::offset_of!(RawMapInfo, name), 24);
        assert_eq!(std::mem::offset_of!(RawMapInfo, btf_id), 64);
        assert_eq!(std::mem::offset_of!(RawProgramInfo, name), 64);
        assert_eq!(std::mem::offset_of!(RawProgramInfo, xlated_prog_len), 20);
    }

    #[test]
    fn names_are_nul_padded_and_bounded() {
        let mut raw = [0u8; BPF_OBJ_NAME_LEN];
        put_name(&mut raw, "flx_in");
        assert_eq!(parse_name(&raw), "flx_in");
        assert!(validate_name("1234567890123456").is_err());
        assert!(validate_name("bad-name").is_err());
    }

    #[test]
    fn uapi_fallback_constants_match_linux() {
        assert_eq!(BPF_F_NO_PREALLOC, 1);
        assert_eq!(BPF_OBJ_NAME_LEN, 16);
    }
}
