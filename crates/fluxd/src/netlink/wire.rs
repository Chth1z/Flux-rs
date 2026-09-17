use std::io;
use std::mem::size_of;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::mem::MaybeUninit;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub(crate) const NLMSG_NOOP: u16 = 1;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
pub(crate) const NLMSG_OVERRUN: u16 = 4;

pub(crate) const NLM_F_REQUEST: u16 = 0x0001;
pub(crate) const NLM_F_ACK: u16 = 0x0004;
pub(crate) const NLM_F_ROOT: u16 = 0x0100;
pub(crate) const NLM_F_MATCH: u16 = 0x0200;
pub(crate) const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub(crate) const NLM_F_DUMP_INTR: u16 = 0x0010;
pub(crate) const NLM_F_EXCL: u16 = 0x0200;
pub(crate) const NLM_F_CREATE: u16 = 0x0400;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));
const MAX_DATAGRAM: usize = 1024 * 1024;
/// Level-triggered drain budget. Exhaustion is treated as overrun so the
/// reactor returns to epoll with a resync dirty bit (rc.3 R08).
const DRAIN_MESSAGE_BUDGET: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NlMsgHdr {
    pub len: u32,
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct IfInfoMsg {
    pub family: u8,
    pub pad: u8,
    pub arphrd: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct IfAddrMsg {
    pub family: u8,
    pub prefix_len: u8,
    pub flags: u8,
    pub scope: u8,
    pub index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg(test)]
pub(crate) struct NdMsg {
    pub family: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub ifindex: i32,
    pub state: u16,
    pub flags: u8,
    pub kind: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct RtMsg {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FibRuleHdr {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub reserved1: u8,
    pub reserved2: u8,
    pub action: u8,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct TcMsg {
    pub family: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub ifindex: i32,
    pub handle: u32,
    pub parent: u32,
    pub info: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct RawMessage {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    Quiet,
    Changed,
    Resync,
}

pub(crate) fn align4(len: usize) -> usize {
    (len + 3) & !3
}

pub(crate) fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: `value` is alive for the returned slice lifetime and the slice
    // spans exactly its object representation. Kernel UAPI structs used here
    // contain no references.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

pub(crate) fn read_struct<T: Copy>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() < size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short netlink payload",
        ));
    }
    // SAFETY: the length was checked and read_unaligned accepts arbitrary
    // alignment. All callers request plain kernel UAPI structs.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

pub(crate) struct MessageBuilder {
    bytes: Vec<u8>,
    nested: Vec<usize>,
}

impl MessageBuilder {
    pub fn new(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Self {
        let header = NlMsgHdr {
            len: 0,
            kind,
            flags,
            seq,
            pid: 0,
        };
        let mut bytes = Vec::with_capacity(size_of::<NlMsgHdr>() + payload.len() + 128);
        bytes.extend_from_slice(as_bytes(&header));
        bytes.extend_from_slice(payload);
        Self {
            bytes,
            nested: Vec::new(),
        }
    }

    pub fn attr(&mut self, kind: u16, payload: &[u8]) {
        let len = 4usize + payload.len();
        self.bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        self.bytes.extend_from_slice(&kind.to_ne_bytes());
        self.bytes.extend_from_slice(payload);
        self.bytes.resize(align4(self.bytes.len()), 0);
    }

    pub fn attr_u32(&mut self, kind: u16, value: u32) {
        self.attr(kind, &value.to_ne_bytes());
    }

    pub fn attr_cstr(&mut self, kind: u16, value: &str) {
        let mut bytes = Vec::with_capacity(value.len() + 1);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        self.attr(kind, &bytes);
    }

    pub fn begin_nested(&mut self, kind: u16) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(&0u16.to_ne_bytes());
        self.bytes
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        self.nested.push(start);
    }

    pub fn nested_payload(&mut self, payload: &[u8]) {
        self.bytes.extend_from_slice(payload);
    }

    pub fn end_nested(&mut self) {
        let start = self.nested.pop().expect("balanced nested attributes");
        let len = self.bytes.len() - start;
        self.bytes[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
        self.bytes.resize(align4(self.bytes.len()), 0);
    }

    pub fn finish(mut self) -> Vec<u8> {
        assert!(self.nested.is_empty(), "unclosed nested netlink attribute");
        let len = self.bytes.len() as u32;
        self.bytes[0..4].copy_from_slice(&len.to_ne_bytes());
        self.bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Attr<'a> {
    pub kind: u16,
    pub nested: bool,
    pub payload: &'a [u8],
}

pub(crate) fn attrs(mut bytes: &[u8]) -> io::Result<Vec<Attr<'_>>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink attribute header",
            ));
        }
        let len = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let raw_kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        if len < 4 || len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink attribute length",
            ));
        }
        out.push(Attr {
            kind: raw_kind & NLA_TYPE_MASK,
            nested: raw_kind & NLA_F_NESTED != 0,
            payload: &bytes[4..len],
        });
        let advance = align4(len);
        if advance > bytes.len() {
            if len == bytes.len() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink attribute padding",
            ));
        }
        bytes = &bytes[advance..];
    }
    Ok(out)
}

pub(crate) fn attr_u32(attr: Attr<'_>) -> io::Result<u32> {
    if attr.payload.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink u32 attribute has the wrong size",
        ));
    }
    Ok(u32::from_ne_bytes(
        attr.payload.try_into().expect("size checked"),
    ))
}

pub(crate) fn attr_u16(attr: Attr<'_>) -> io::Result<u16> {
    if attr.payload.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink u16 attribute has the wrong size",
        ));
    }
    Ok(u16::from_ne_bytes(
        attr.payload.try_into().expect("size checked"),
    ))
}

pub(crate) fn attr_cstr(attr: Attr<'_>) -> io::Result<String> {
    let Some((&0, text)) = attr.payload.split_last() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink string attribute is not NUL-terminated",
        ));
    };
    if text.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink string attribute contains an embedded NUL",
        ));
    }
    std::str::from_utf8(text)
        .map(str::to_owned)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "netlink string is not UTF-8"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn netlink_address(pid: u32, groups: u32) -> libc::sockaddr_nl {
    // sockaddr_nl contains a libc-private padding field on some targets, so it
    // must be zero-initialized rather than constructed with a literal.
    // SAFETY: all-zero is a valid sockaddr_nl before the public fields are set.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_pid = pid;
    address.nl_groups = groups;
    address
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_socket(
    protocol: libc::c_int,
    groups: u32,
    nonblocking: bool,
) -> io::Result<(OwnedFd, u32)> {
    let mut kind = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
    if nonblocking {
        kind |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: valid constants; ownership of a successful descriptor is moved
    // into OwnedFd immediately.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, kind, protocol) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly-created descriptor owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = netlink_address(0, groups);
    // SAFETY: address points to a fully initialized sockaddr_nl.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut local = MaybeUninit::<libc::sockaddr_nl>::zeroed();
    let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: local and len describe writable storage for getsockname.
    let rc = unsafe { libc::getsockname(fd.as_raw_fd(), local.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getsockname succeeded and initialized the sockaddr.
    let local = unsafe { local.assume_init() };
    Ok((fd, local.nl_pid))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) struct RequestSocket {
    fd: OwnedFd,
    port_id: u32,
    seq: u32,
    nonblocking: bool,
    pending: Vec<RawMessage>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl RequestSocket {
    pub fn open() -> io::Result<Self> {
        Self::open_protocol(libc::NETLINK_ROUTE, false)
    }

    pub fn open_nonblocking(protocol: libc::c_int) -> io::Result<Self> {
        Self::open_protocol(protocol, true)
    }

    fn open_protocol(protocol: libc::c_int, nonblocking: bool) -> io::Result<Self> {
        let (fd, port_id) = open_socket(protocol, 0, nonblocking)?;
        if !nonblocking {
            let timeout = libc::timeval {
                tv_sec: 3,
                tv_usec: 0,
            };
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                // SAFETY: timeout points to a timeval of the stated size.
                let rc = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&timeout as *const libc::timeval).cast(),
                        size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(Self {
            fd,
            port_id,
            seq: 0,
            nonblocking,
            pending: Vec::new(),
        })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    pub fn ack(&mut self, request: Vec<u8>, seq: u32) -> io::Result<()> {
        self.send(&request)?;
        loop {
            for message in self.recv(seq)? {
                match message.kind {
                    NLMSG_ERROR => return parse_ack(&message.payload),
                    NLMSG_OVERRUN => return Err(overrun()),
                    NLMSG_NOOP => {}
                    _ => {}
                }
            }
        }
    }

    pub fn request(&mut self, request: Vec<u8>, seq: u32) -> io::Result<RawMessage> {
        self.send(&request)?;
        loop {
            for message in self.recv(seq)? {
                match message.kind {
                    NLMSG_ERROR => parse_ack(&message.payload)?,
                    NLMSG_OVERRUN => return Err(overrun()),
                    NLMSG_NOOP => {}
                    NLMSG_DONE => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "netlink request completed without a response",
                        ));
                    }
                    _ => return Ok(message),
                }
            }
        }
    }

    pub fn dump(&mut self, request: Vec<u8>, seq: u32) -> io::Result<Vec<RawMessage>> {
        self.send(&request)?;
        let mut out = Vec::new();
        loop {
            match feed_dump(out, &self.recv(seq)?, false)? {
                DumpFeed::NeedMore(next) => out = next,
                DumpFeed::Complete(done) => return Ok(done),
            }
        }
    }

    pub(crate) fn send(&self, request: &[u8]) -> io::Result<()> {
        let kernel = netlink_address(0, 0);
        // SAFETY: buffers and destination sockaddr are valid for this call.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink send",
            ));
        }
        Ok(())
    }

    fn recv(&mut self, seq: u32) -> io::Result<Vec<RawMessage>> {
        if self.nonblocking {
            wait_fd(self.fd.as_raw_fd(), libc::POLLIN)?;
        }
        self.recv_matching(seq)
    }

    /// One datagram, no `poll`. `WouldBlock` means return to epoll (§9.5).
    pub(crate) fn try_recv(&mut self, seq: u32) -> io::Result<Vec<RawMessage>> {
        let pending = self.take_pending(seq);
        if !pending.is_empty() {
            return Ok(pending);
        }
        self.recv_matching(seq)
    }

    fn take_pending(&mut self, seq: u32) -> Vec<RawMessage> {
        let mut matching = Vec::new();
        let mut leftover = Vec::new();
        for message in std::mem::take(&mut self.pending) {
            if message.seq == seq {
                matching.push(message);
            } else {
                leftover.push(message);
            }
        }
        self.pending = leftover;
        matching
    }

    fn recv_matching(&mut self, seq: u32) -> io::Result<Vec<RawMessage>> {
        let mut bytes = vec![0u8; MAX_DATAGRAM];
        let (read, truncated) = recv_datagram(self.fd.as_raw_fd(), &mut bytes)?;
        if truncated {
            return Err(dump_truncated());
        }
        bytes.truncate(read);
        let mut matching = Vec::new();
        for message in parse_datagram(&bytes)? {
            if message.seq != seq {
                if self.nonblocking {
                    self.pending.push(message);
                }
                continue;
            }
            if message.pid != 0 && message.pid != self.port_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink response came from an unexpected port",
                ));
            }
            matching.push(message);
        }
        Ok(matching)
    }

    pub fn drain_messages(&mut self) -> io::Result<(Vec<RawMessage>, bool)> {
        debug_assert!(self.nonblocking);
        let mut pending = std::mem::take(&mut self.pending);
        let (mut received, resync) = drain_messages(self.fd.as_raw_fd())?;
        pending.append(&mut received);
        Ok((pending, resync))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) struct NonblockingSocket {
    fd: OwnedFd,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl NonblockingSocket {
    pub fn open(groups: u32) -> io::Result<Self> {
        let (fd, _) = open_socket(libc::NETLINK_ROUTE, groups, true)?;
        Ok(Self { fd })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn drain(&self) -> io::Result<DrainResult> {
        let (messages, resync) = drain_messages(self.fd.as_raw_fd())?;
        if resync {
            Ok(DrainResult::Resync)
        } else if messages.is_empty() {
            Ok(DrainResult::Quiet)
        } else {
            Ok(DrainResult::Changed)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn drain_messages(fd: RawFd) -> io::Result<(Vec<RawMessage>, bool)> {
    let mut messages = Vec::new();
    loop {
        let mut bytes = vec![0u8; MAX_DATAGRAM];
        let (read, truncated) = match recv_datagram(fd, &mut bytes) {
            Ok(pair) => pair,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok((messages, false));
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                return Ok((Vec::new(), true));
            }
            Err(error) => return Err(error),
        };
        if truncated {
            return Ok((Vec::new(), true));
        }
        bytes.truncate(read);
        for message in parse_datagram(&bytes)? {
            if message.kind == NLMSG_OVERRUN {
                return Ok((Vec::new(), true));
            }
            messages.push(message);
            if messages.len() >= DRAIN_MESSAGE_BUDGET {
                return Ok((Vec::new(), true));
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_fd(fd: RawFd, events: libc::c_short) -> io::Result<()> {
    let mut poll_fd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: poll_fd points to one initialized pollfd for the call.
        let rc = unsafe { libc::poll(&mut poll_fd, 1, 3_000) };
        if rc > 0 {
            return Ok(());
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "netlink response timed out",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// One datagram via `recvmsg` so `MSG_TRUNC` is visible (blueprint §8.5).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_datagram(fd: RawFd, bytes: &mut [u8]) -> io::Result<(usize, bool)> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: `msghdr` is a C struct of integer and pointer fields. A
    // zeroed instance is an empty message; we fill `msg_iov` before the call.
    let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: `msg` points at one iovec covering `bytes`; the kernel writes
    // at most `bytes.len()` and reports truncation in `msg_flags`.
    let read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    let truncated = msg.msg_flags & libc::MSG_TRUNC != 0;
    Ok((read as usize, truncated))
}

fn parse_datagram(bytes: &[u8]) -> io::Result<Vec<RawMessage>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < size_of::<NlMsgHdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink message header",
            ));
        }
        let header: NlMsgHdr = read_struct(&bytes[offset..])?;
        let len = header.len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink message length",
            ));
        }
        out.push(RawMessage {
            kind: header.kind,
            flags: header.flags,
            seq: header.seq,
            pid: header.pid,
            payload: bytes[offset + size_of::<NlMsgHdr>()..offset + len].to_vec(),
        });
        let advance = align4(len);
        if offset + advance > bytes.len() {
            if offset + len == bytes.len() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink message padding",
            ));
        }
        offset += advance;
    }
    Ok(out)
}

fn parse_ack(payload: &[u8]) -> io::Result<()> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short NLMSG_ERROR payload",
        ));
    }
    let error = i32::from_ne_bytes(payload[0..4].try_into().expect("size checked"));
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error.saturating_neg()))
    }
}

fn parse_done_status(payload: &[u8]) -> i32 {
    if payload.len() < 4 {
        0
    } else {
        i32::from_ne_bytes(payload[0..4].try_into().expect("size checked"))
    }
}

/// Incremental dump assembly. A datagram without `NLMSG_DONE` is not a
/// successful empty dump: "not seen" is not "absent" (blueprint §8.5, §9.5).
#[derive(Debug)]
pub(crate) enum DumpFeed {
    NeedMore(Vec<RawMessage>),
    Complete(Vec<RawMessage>),
}

pub(crate) fn feed_dump(
    mut items: Vec<RawMessage>,
    messages: &[RawMessage],
    truncated: bool,
) -> io::Result<DumpFeed> {
    if truncated {
        return Err(dump_truncated());
    }
    for message in messages {
        match message.kind {
            NLMSG_DONE => return finish_dump(items, message, false).map(DumpFeed::Complete),
            NLMSG_ERROR => parse_ack(&message.payload)?,
            NLMSG_OVERRUN => return Err(overrun()),
            NLMSG_NOOP => {}
            _ => {
                if message.flags & NLM_F_DUMP_INTR != 0 {
                    return Err(dump_interrupted());
                }
                items.push(message.clone());
            }
        }
    }
    Ok(DumpFeed::NeedMore(items))
}

fn finish_dump(
    items: Vec<RawMessage>,
    done: &RawMessage,
    truncated: bool,
) -> io::Result<Vec<RawMessage>> {
    let interrupted =
        done.flags & NLM_F_DUMP_INTR != 0 || items.iter().any(|m| m.flags & NLM_F_DUMP_INTR != 0);
    let done_status = parse_done_status(&done.payload);
    flux_core::snapshot::TrustedSnapshot::try_from_parts(
        items,
        interrupted,
        truncated,
        false,
        done_status,
    )
    .map(flux_core::snapshot::TrustedSnapshot::into_inner)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn overrun() -> io::Error {
    io::Error::other("netlink dump overrun; a full resynchronization is required")
}

fn dump_interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "netlink dump interrupted (NLM_F_DUMP_INTR)",
    )
}

fn dump_truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "netlink datagram truncated (MSG_TRUNC)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_attributes_round_trip() {
        let payload = IfInfoMsg::default();
        let mut message = MessageBuilder::new(16, NLM_F_REQUEST, 7, as_bytes(&payload));
        message.attr_cstr(3, "flxrs0");
        message.begin_nested(18);
        message.attr_cstr(1, "veth");
        message.end_nested();
        let bytes = message.finish();
        let header: NlMsgHdr = read_struct(&bytes).unwrap();
        assert_eq!(header.len as usize, bytes.len());
        let top = attrs(&bytes[size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>()..]).unwrap();
        assert_eq!(attr_cstr(top[0]).unwrap(), "flxrs0");
        assert!(top[1].nested);
        let inner = attrs(top[1].payload).unwrap();
        assert_eq!(attr_cstr(inner[0]).unwrap(), "veth");
    }

    #[test]
    fn malformed_attribute_is_rejected() {
        assert!(attrs(&[3, 0, 1, 0]).is_err());
        assert!(attrs(&[8, 0, 1, 0, 1, 2, 3]).is_err());
    }

    #[test]
    fn ack_errno_is_preserved() {
        assert!(parse_ack(&0i32.to_ne_bytes()).is_ok());
        const LINUX_EEXIST: i32 = 17;
        let error = parse_ack(&(-LINUX_EEXIST).to_ne_bytes()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(LINUX_EEXIST));
    }

    fn done_message(flags: u16, status: i32) -> RawMessage {
        RawMessage {
            kind: NLMSG_DONE,
            flags,
            seq: 1,
            pid: 0,
            payload: status.to_ne_bytes().to_vec(),
        }
    }

    #[test]
    fn parse_datagram_preserves_header_flags() {
        let bytes = MessageBuilder::new(16, NLM_F_DUMP_INTR | NLM_F_REQUEST, 9, &[]).finish();
        let messages = parse_datagram(&bytes).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].flags, NLM_F_DUMP_INTR | NLM_F_REQUEST);
        assert_eq!(messages[0].seq, 9);
    }

    #[test]
    fn dump_done_zero_is_complete() {
        let out = finish_dump(Vec::new(), &done_message(0, 0), false).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn dump_done_negative_is_incomplete() {
        let error = finish_dump(Vec::new(), &done_message(0, -2), false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("done_status=-2"));
    }

    #[test]
    fn dump_intr_flag_is_incomplete() {
        let error = finish_dump(Vec::new(), &done_message(NLM_F_DUMP_INTR, 0), false).unwrap_err();
        assert!(error.to_string().contains("interrupted=true"));
    }

    #[test]
    fn dump_intr_on_a_data_message_is_incomplete() {
        let item = RawMessage {
            kind: 16,
            flags: NLM_F_DUMP_INTR,
            seq: 1,
            pid: 0,
            payload: Vec::new(),
        };
        let error = finish_dump(vec![item], &done_message(0, 0), false).unwrap_err();
        assert!(error.to_string().contains("interrupted=true"));
    }

    #[test]
    fn dump_truncation_is_incomplete() {
        let error = finish_dump(Vec::new(), &done_message(0, 0), true).unwrap_err();
        assert!(error.to_string().contains("truncated=true"));
    }

    fn data_message(kind: u16) -> RawMessage {
        RawMessage {
            kind,
            flags: 0,
            seq: 1,
            pid: 0,
            payload: Vec::new(),
        }
    }

    #[test]
    fn dump_without_done_is_need_more_not_complete() {
        let item = data_message(16);
        match feed_dump(Vec::new(), &[item], false).unwrap() {
            DumpFeed::NeedMore(items) => assert_eq!(items.len(), 1),
            DumpFeed::Complete(_) => panic!("a dump without NLMSG_DONE is not complete"),
        }
    }

    #[test]
    fn empty_datagram_is_need_more_not_absence() {
        match feed_dump(Vec::new(), &[], false).unwrap() {
            DumpFeed::NeedMore(items) => assert!(items.is_empty()),
            DumpFeed::Complete(_) => panic!("silence is not a complete dump"),
        }
    }

    #[test]
    fn dump_done_after_items_is_complete() {
        let item = data_message(16);
        match feed_dump(vec![item], &[done_message(0, 0)], false).unwrap() {
            DumpFeed::Complete(items) => assert_eq!(items.len(), 1),
            DumpFeed::NeedMore(_) => panic!("NLMSG_DONE must complete a clean dump"),
        }
    }
}
