//! Userspace mirror of `kmod/fluxrs.h` ioctl numbers and structs.
//!
//! Encoding matches Linux `asm-generic/ioctl.h` (`_IOC_WRITE=1`, 14-bit size).
//! Keep this file free of `libc`; `fluxd` issues the syscalls.

/// `FLUXRS_IOCTL_MAGIC`.
pub const MAGIC: u8 = b'F';

/// Maximum UIDs in one `FLUXRS_SET_UIDS` (kernel `fluxrs_uids.uids`).
/// Lockstep [`crate::abi::UID_SELECTED_MAX`].
pub const UID_SLOT_MAX: usize = 1024;

/// Maximum prefixes per family in one `FLUXRS_SET_BYPASS`.
/// Lockstep [`crate::abi::LPM_MAX_ENTRIES`].
pub const LPM_MAX: usize = 65536;

/// Maximum exact self-addresses per family in one `FLUXRS_SET_BYPASS`.
/// Lockstep [`crate::abi::SELF_ADDR_MAX_ENTRIES`].
pub const SELF_MAX: usize = 256;

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

/// Packed like `struct fluxrs_bypass` (header only; arrays follow in the buffer).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bypass {
    /// `0` blacklist, `1` whitelist. Lockstep [`crate::abi::CidrMode`].
    pub cidr_mode: u32,
    /// Number of IPv4 prefixes that follow the header.
    pub v4_count: u32,
    /// Number of IPv6 prefixes that follow the IPv4 array.
    pub v6_count: u32,
    /// Number of exact IPv4 self-addresses.
    pub self4_count: u32,
    /// Number of exact IPv6 self-addresses.
    pub self6_count: u32,
}

/// Packed like `struct fluxrs_pfx4`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pfx4 {
    /// Network address, network byte order (in-memory bytes match the IP header).
    pub addr: u32,
    /// Prefix length `0..=32`.
    pub prefixlen: u8,
    /// [`crate::abi::BypassTag`] as `u8`.
    pub tag: u8,
    /// Alignment pad.
    pub pad: [u8; 2],
}

/// Packed like `struct fluxrs_pfx6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pfx6 {
    /// Network address, network byte order.
    pub addr: [u8; 16],
    /// Prefix length `0..=128`.
    pub prefixlen: u8,
    /// [`crate::abi::BypassTag`] as `u8`.
    pub tag: u8,
    /// Alignment pad.
    pub pad: [u8; 2],
}

/// Byte length of a `SET_BYPASS` userspace buffer.
pub const fn bypass_payload_len(v4: usize, v6: usize, self4: usize, self6: usize) -> usize {
    core::mem::size_of::<Bypass>()
        + v4 * core::mem::size_of::<Pfx4>()
        + v6 * core::mem::size_of::<Pfx6>()
        + self4 * 4
        + self6 * 16
}

/// Pack `FLUXRS_SET_BYPASS` as the kernel copies it: header then four arrays.
pub fn encode_bypass(
    cidr_mode: u32,
    v4: &[Pfx4],
    v6: &[Pfx6],
    self4: &[u32],
    self6: &[[u8; 16]],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(bypass_payload_len(
        v4.len(),
        v6.len(),
        self4.len(),
        self6.len(),
    ));
    buf.extend_from_slice(&cidr_mode.to_ne_bytes());
    buf.extend_from_slice(&(v4.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&(v6.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&(self4.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&(self6.len() as u32).to_ne_bytes());
    for prefix in v4 {
        buf.extend_from_slice(&prefix.addr.to_ne_bytes());
        buf.push(prefix.prefixlen);
        buf.push(prefix.tag);
        buf.extend_from_slice(&prefix.pad);
    }
    for prefix in v6 {
        buf.extend_from_slice(&prefix.addr);
        buf.push(prefix.prefixlen);
        buf.push(prefix.tag);
        buf.extend_from_slice(&prefix.pad);
    }
    for addr in self4 {
        buf.extend_from_slice(&addr.to_ne_bytes());
    }
    for addr in self6 {
        buf.extend_from_slice(addr);
    }
    buf
}

/// `FLUXRS_SET_LISTENERS`.
pub const SET_LISTENERS: u32 = iow::<Listeners>(1);
/// `FLUXRS_SET_UIDS`.
pub const SET_UIDS: u32 = iow::<Uids>(2);
/// `FLUXRS_CLEAR_UIDS`.
pub const CLEAR_UIDS: u32 = ioc(0, 3, 0);
/// `FLUXRS_GET_STATUS`.
pub const GET_STATUS: u32 = ior::<Status>(4);
/// `FLUXRS_SET_BYPASS` (ioctl size is the header; arrays follow in the buffer).
pub const SET_BYPASS: u32 = iow::<Bypass>(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{self, BypassTag};

    #[test]
    fn c_layout_matches_the_kernel_header() {
        assert_eq!(core::mem::size_of::<Listeners>(), 28);
        assert_eq!(core::mem::align_of::<Listeners>(), 4);
        assert_eq!(core::mem::size_of::<Uids>(), 4 + UID_SLOT_MAX * 4);
        assert_eq!(core::mem::size_of::<Uids>(), 4100);
        assert_eq!(core::mem::size_of::<Status>(), 32);
        assert_eq!(core::mem::size_of::<Bypass>(), 20);
        assert_eq!(core::mem::size_of::<Pfx4>(), 8);
        assert_eq!(core::mem::size_of::<Pfx6>(), 20);
        assert_eq!(SET_LISTENERS, 0x401C_4601);
        assert_eq!(SET_UIDS, 0x5004_4602);
        assert_eq!(CLEAR_UIDS, 0x0000_4603);
        assert_eq!(GET_STATUS, 0x8020_4604);
        assert_eq!(SET_BYPASS, 0x4014_4605);
        assert_eq!(UID_SLOT_MAX, abi::UID_SELECTED_MAX as usize);
        assert_eq!(LPM_MAX, abi::LPM_MAX_ENTRIES as usize);
        assert_eq!(SELF_MAX, abi::SELF_ADDR_MAX_ENTRIES as usize);
    }

    #[test]
    fn encode_bypass_packs_header_then_arrays() {
        let v4 = [Pfx4 {
            addr: u32::from_ne_bytes([10, 0, 0, 0]),
            prefixlen: 8,
            tag: BypassTag::Policy as u8,
            pad: [0, 0],
        }];
        let self6 = [[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]];
        let buf = encode_bypass(1, &v4, &[], &[u32::from_ne_bytes([127, 0, 0, 1])], &self6);
        assert_eq!(buf.len(), bypass_payload_len(1, 0, 1, 1));
        assert_eq!(&buf[0..4], &1u32.to_ne_bytes());
        assert_eq!(&buf[4..8], &1u32.to_ne_bytes());
        assert_eq!(&buf[8..12], &0u32.to_ne_bytes());
        assert_eq!(&buf[12..16], &1u32.to_ne_bytes());
        assert_eq!(&buf[16..20], &1u32.to_ne_bytes());
        assert_eq!(&buf[20..24], &[10, 0, 0, 0]);
        assert_eq!(buf[24], 8);
        assert_eq!(buf[25], BypassTag::Policy as u8);
        assert_eq!(&buf[28..32], &[127, 0, 0, 1]);
        assert_eq!(&buf[32..48], &self6[0]);
    }
}
