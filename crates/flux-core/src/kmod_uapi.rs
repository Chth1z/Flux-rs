//! Userspace mirror of `kmod/fluxrs.h` ioctl numbers and structs.
//!
//! Encoding matches Linux `asm-generic/ioctl.h` (`_IOC_WRITE=1`, 14-bit size).
//! Keep this file free of `libc`; `fluxd` issues the syscalls.

/// `FLUXRS_IOCTL_MAGIC`.
pub const MAGIC: u8 = b'F';

/// Maximum UIDs in one `FLUXRS_SET_UIDS` (kernel `fluxrs_uids.uids`).
pub const UID_SLOT_MAX: usize = 64;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT)
        | ((MAGIC as u32) << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)
}

const fn iow<T>(nr: u32) -> u32 {
    ioc(IOC_WRITE, nr, core::mem::size_of::<T>() as u32)
}

const fn ior<T>(nr: u32) -> u32 {
    ioc(IOC_READ, nr, core::mem::size_of::<T>() as u32)
}

/// Packed like `struct fluxrs_listeners`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Listeners {
    /// IPv4 listener address, network byte order.
    pub v4_addr: u32,
    /// IPv4 listener port, network byte order.
    pub v4_port: u16,
    /// Alignment pad.
    pub pad0: u16,
    /// IPv6 listener address, network byte order.
    pub v6_addr: [u8; 16],
    /// IPv6 listener port, network byte order.
    pub v6_port: u16,
    /// Alignment pad.
    pub pad1: u16,
}

/// Packed like `struct fluxrs_uids`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Uids {
    /// Number of occupied slots in [`Self::uids`].
    pub count: u32,
    /// Selected app UIDs; unused slots are 0.
    pub uids: [u32; UID_SLOT_MAX],
}

impl Default for Uids {
    fn default() -> Self {
        Self {
            count: 0,
            uids: [0; UID_SLOT_MAX],
        }
    }
}

/// Packed like `struct fluxrs_status`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// 1 while the control fd is held.
    pub live: u32,
    /// 1 when this build can steal (stage ≥ 2 and tproxy symbols if needed).
    pub steal_ready: u32,
    /// LOCAL_OUT hits on a selected UID.
    pub selected_seen: u64,
    /// Packets the worker stole (or delivered, at stage 6).
    pub stolen: u64,
    /// Selected packets that missed a transparent listener.
    pub miss_listener: u64,
}

/// `FLUXRS_SET_LISTENERS`.
pub const SET_LISTENERS: u32 = iow::<Listeners>(1);
/// `FLUXRS_SET_UIDS`.
pub const SET_UIDS: u32 = iow::<Uids>(2);
/// `FLUXRS_CLEAR_UIDS`.
pub const CLEAR_UIDS: u32 = ioc(0, 3, 0);
/// `FLUXRS_GET_STATUS`.
pub const GET_STATUS: u32 = ior::<Status>(4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_layout_matches_the_kernel_header() {
        assert_eq!(core::mem::size_of::<Listeners>(), 28);
        assert_eq!(core::mem::align_of::<Listeners>(), 4);
        assert_eq!(core::mem::size_of::<Uids>(), 260);
        assert_eq!(core::mem::size_of::<Status>(), 32);
        assert_eq!(SET_LISTENERS, 0x401C_4601);
        assert_eq!(SET_UIDS, 0x4104_4602);
        assert_eq!(CLEAR_UIDS, 0x0000_4603);
        assert_eq!(GET_STATUS, 0x8020_4604);
    }
}
