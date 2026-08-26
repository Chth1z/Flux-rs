//! `NETLINK_ROUTE` socket with ACK handling (blueprint §8.9).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::attr::AttrIter;

pub const NLMSG_HDRLEN: usize = 16;

/// Opens a bound `NETLINK_ROUTE` socket.
pub fn open_route_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2).
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd returned by socket().
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zero-initialized sockaddr_nl is valid for bind().
    let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    addr.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: valid sockaddr_nl for bind.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Sends one netlink message and waits for `NLMSG_ERROR` with `error == 0`.
pub fn request_ack(sock: &OwnedFd, msg: &[u8]) -> io::Result<()> {
    send_all(sock, msg)?;
    wait_ack(sock)
}

/// Sends one dump request and collects all `RTM_*` payloads until `NLMSG_DONE`.
pub fn dump(sock: &OwnedFd, msg: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    send_all(sock, msg)?;
    recv_dump(sock)
}

fn send_all(sock: &OwnedFd, msg: &[u8]) -> io::Result<()> {
    // SAFETY: msg valid for length.
    let sent = unsafe { libc::send(sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
    if sent != msg.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_ack(sock: &OwnedFd) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buf valid for recv.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        let mut off = 0;
        while off + NLMSG_HDRLEN <= n {
            let nl_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let nl_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if nl_len < NLMSG_HDRLEN || off + nl_len > n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated netlink message",
                ));
            }
            let payload = &buf[off + NLMSG_HDRLEN..off + nl_len];
            match nl_type {
                t if t == libc::NLMSG_ERROR as u16 => {
                    if payload.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let err = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    if err == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-err));
                }
                t if t == libc::NLMSG_NOOP as u16 => {}
                _ => {}
            }
            off += nl_align(nl_len);
        }
    }
}

fn recv_dump(sock: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        // SAFETY: buf valid for recv.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        let mut off = 0;
        while off + NLMSG_HDRLEN <= n {
            let nl_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let nl_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if nl_len < NLMSG_HDRLEN || off + nl_len > n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated netlink dump",
                ));
            }
            let payload = &buf[off + NLMSG_HDRLEN..off + nl_len];
            match nl_type {
                t if t == libc::NLMSG_DONE as u16 => {
                    if payload.len() >= 4 {
                        let status = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
                        if status != 0 {
                            return Err(io::Error::from_raw_os_error(-status));
                        }
                    }
                    return Ok(out);
                }
                t if t == libc::NLMSG_ERROR as u16 => {
                    if payload.len() >= 4 {
                        let err = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
                        if err != 0 {
                            return Err(io::Error::from_raw_os_error(-err));
                        }
                    }
                }
                _ => out.push(payload.to_vec()),
            }
            off += nl_align(nl_len);
        }
    }
}

/// Build an `nlmsghdr` + fixed header + attrs message.
pub fn build_msg(nl_type: u16, flags: u16, seq: u32, header: &[u8], attrs: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + header.len() + attrs.len();
    let mut msg = vec![0u8; len];
    msg[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    msg[4..6].copy_from_slice(&nl_type.to_ne_bytes());
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    msg[8..12].copy_from_slice(&seq.to_ne_bytes());
    msg[12..16].copy_from_slice(&0u32.to_ne_bytes());
    msg[NLMSG_HDRLEN..NLMSG_HDRLEN + header.len()].copy_from_slice(header);
    msg[NLMSG_HDRLEN + header.len()..].copy_from_slice(attrs);
    msg
}

pub fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Parse `IFLA_IFNAME` from a link dump payload (`ifinfomsg` + attrs).
pub fn link_ifname(payload: &[u8]) -> Option<String> {
    if payload.len() < super::consts::IFINFOMSG_LEN {
        return None;
    }
    let attrs = &payload[super::consts::IFINFOMSG_LEN..];
    for (kind, data) in AttrIter::new(attrs).flatten() {
        if kind == libc::IFLA_IFNAME {
            return Some(String::from_utf8_lossy(data).into_owned());
        }
    }
    None
}

pub fn link_ifindex(payload: &[u8]) -> Option<u32> {
    if payload.len() < 8 {
        return None;
    }
    let idx = i32::from_ne_bytes(payload[4..8].try_into().unwrap_or([0, 0, 0, 0]));
    Some(idx as u32)
}

pub fn link_flags(payload: &[u8]) -> u32 {
    if payload.len() < 12 {
        return 0;
    }
    u32::from_ne_bytes(payload[8..12].try_into().unwrap_or([0, 0, 0, 0]))
}
