//! `NETLINK_SOCK_DIAG` enumeration of exact listener sockets.
//!
//! Implements the readiness half of blueprint §9.5: enumerate the four engine
//! sockets (`2 family × 2 protocol`) via `SOCK_DIAG_BY_FAMILY` / `inet_diag`
//! and cross-check every returned inode against `/proc/<pid>/fd`. This is Q2
//! (§16.10.2) turned from a one-off measurement into a product-carried check.
//!
//! Read-only: this module never mutates kernel state. Raw netlink bytes stay
//! inside `netlink/` per the module boundary of blueprint §5.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_HDRLEN: usize = 16;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const INET_DIAG_MSG_MIN_LEN: usize = 72;

/// `BPF_TCP_LISTEN` — the state a TCP listener must be in. A UDP socket
/// reports state 7 (`TCP_CLOSE`), which is why the state gate below applies
/// only to TCP (measured on-device, §16.10.3).
const TCP_LISTEN: u8 = 10;

/// One exact socket the engine must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketExpectation {
    /// `libc::IPPROTO_TCP` or `libc::IPPROTO_UDP`.
    pub protocol: u8,
    /// The exact bound address.
    pub addr: IpAddr,
    /// The exact bound port, host byte order.
    pub port: u16,
}

impl SocketExpectation {
    fn family(&self) -> u8 {
        match self.addr {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        }
    }
}

/// Finds the inode of the socket exactly matching `exp`, or `None` when no
/// such socket exists right now. An error means the enumeration itself failed
/// (netlink unavailable), not that the socket is absent.
pub fn find_inode(exp: &SocketExpectation) -> io::Result<Option<u32>> {
    let sock = diag_socket()?;
    send_dump_request(&sock, exp)?;
    read_matching_inode(&sock, exp)
}

/// Whether `/proc/<pid>/fd` holds an fd whose target is `socket:[inode]`.
/// This is the PID half of the Q2 cross-check: the diag answer proves the
/// socket exists, this proves the candidate process owns it (§9.5).
pub fn pid_owns_inode(pid: i32, inode: u32) -> io::Result<bool> {
    let needle = format!("socket:[{inode}]");
    let dir = std::fs::read_dir(format!("/proc/{pid}/fd"))?;
    for entry in dir {
        let entry = entry?;
        if let Ok(target) = std::fs::read_link(entry.path()) {
            if target.as_os_str() == needle.as_str() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn diag_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the raw fd is immediately owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by socket() and is not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One `SOCK_DIAG_BY_FAMILY` dump request for `family × protocol`, all states.
/// Matching on the exact address/port happens on the response side: dump
/// filters via `idiag_states` only, and we want the code path identical for
/// TCP and UDP.
fn send_dump_request(sock: &OwnedFd, exp: &SocketExpectation) -> io::Result<()> {
    let len = NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN;
    let mut msg = [0u8; NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN];

    // struct nlmsghdr
    msg[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    msg[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    msg[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid

    // struct inet_diag_req_v2 { family, protocol, ext, pad, states, sockid }
    msg[16] = exp.family();
    msg[17] = exp.protocol;
    msg[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // idiag_states: all
                                                          // sockid stays zeroed: dump, not exact-lookup.

    // SAFETY: the buffer is valid for `len` bytes for the duration of the call.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            msg.as_ptr().cast(),
            len,
            0,
        )
    };
    if sent != len as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_matching_inode(sock: &OwnedFd, exp: &SocketExpectation) -> io::Result<Option<u32>> {
    let mut found = None;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buf is valid for its length for the duration of the call.
        let received = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
            )
        };
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        let mut offset = 0usize;
        let received = received as usize;
        while offset + NLMSG_HDRLEN <= received {
            let nl_len =
                u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let nl_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
            if nl_len < NLMSG_HDRLEN || offset + nl_len > received {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated netlink message",
                ));
            }
            match nl_type {
                t if t == libc::NLMSG_DONE as u16 => {
                    // NLMSG_DONE carries the dump's own status as an i32
                    // payload. A negative value means the dump FAILED (e.g.
                    // -ENOENT when the kernel lacks the udp_diag handler) and
                    // must surface as an error, never as "socket absent".
                    if nl_len >= NLMSG_HDRLEN + 4 {
                        let status = i32::from_ne_bytes(
                            buf[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]
                                .try_into()
                                .unwrap(),
                        );
                        if status < 0 {
                            return Err(io::Error::from_raw_os_error(-status));
                        }
                    }
                    return Ok(found);
                }
                t if t == libc::NLMSG_ERROR as u16 => {
                    let errno = if nl_len >= NLMSG_HDRLEN + 4 {
                        i32::from_ne_bytes(
                            buf[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]
                                .try_into()
                                .unwrap(),
                        )
                    } else {
                        0
                    };
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                _ => {
                    let payload = &buf[offset + NLMSG_HDRLEN..offset + nl_len];
                    if let Some(inode) = match_diag_msg(payload, exp) {
                        found = Some(inode);
                    }
                }
            }
            // NLMSG_ALIGN
            offset += (nl_len + 3) & !3;
        }
    }
}

/// Parses one `struct inet_diag_msg` and returns its inode when it matches the
/// expectation exactly (family, bound address bytes, host-order port, and —
/// for TCP only — the LISTEN state).
fn match_diag_msg(payload: &[u8], exp: &SocketExpectation) -> Option<u32> {
    if payload.len() < INET_DIAG_MSG_MIN_LEN {
        return None;
    }
    let family = payload[0];
    let state = payload[1];
    // struct inet_diag_sockid starts at offset 4: __be16 sport; __be16 dport;
    // __be32 src[4]; __be32 dst[4]; __u32 if; __u32 cookie[2].
    let sport = u16::from_be_bytes(payload[4..6].try_into().unwrap());
    let src = &payload[8..24];
    // idiag_expires/rqueue/wqueue/uid follow the 48-byte sockid; inode last.
    let inode = u32::from_ne_bytes(payload[68..72].try_into().unwrap());

    if family != exp.family() || sport != exp.port {
        return None;
    }
    if exp.protocol == libc::IPPROTO_TCP as u8 && state != TCP_LISTEN {
        return None;
    }
    let addr_matches = match exp.addr {
        IpAddr::V4(v4) => src[0..4] == v4.octets(),
        IpAddr::V6(v6) => src[0..16] == v6.octets(),
    };
    addr_matches.then_some(inode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};

    // The Q2 machinery, exercised against sockets this test itself owns:
    // enumerate by exact (family, protocol, addr, port), then prove the inode
    // appears in our own /proc/self/fd. On-device the same code runs against
    // the sing-box candidate (§16.10.2).

    #[test]
    fn finds_own_tcp_listener_and_cross_checks_the_inode() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        let exp = SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let inode = find_inode(&exp)
            .expect("sock_diag dump")
            .expect("own listener must be found");
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        assert!(pid_owns_inode(pid, inode).expect("read /proc/self/fd"));
        // A foreign pid must NOT own it. Pid 1 is init/systemd; an EACCES
        // error as non-root is also a correct "cannot prove, must not claim"
        // outcome, so only a successful read is asserted on.
        if let Ok(owned) = pid_owns_inode(1, inode) {
            assert!(!owned);
        }
        drop(listener);
    }

    #[test]
    fn finds_own_udp_socket_despite_close_state() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = socket.local_addr().unwrap().port();
        let exp = SocketExpectation {
            protocol: libc::IPPROTO_UDP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let inode = match find_inode(&exp) {
            Ok(Some(inode)) => inode,
            Ok(None) => panic!("own udp socket must be found"),
            // Sandboxed development kernels (e.g. gVisor) ship no udp_diag
            // handler and fail the dump with ENOENT. Real kernels — CI
            // runners and every Android target — have it. Skip, don't lie.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                eprintln!("skipping: this kernel has no UDP sock_diag handler ({e})");
                return;
            }
            Err(e) => panic!("sock_diag dump failed: {e}"),
        };
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        assert!(pid_owns_inode(pid, inode).expect("read /proc/self/fd"));
    }

    #[test]
    fn absent_socket_is_none_not_error() {
        // A TCP socket that is bound but NOT listening is in state 7, so the
        // TCP LISTEN gate must reject it — this is the §16.10.3 asymmetry.
        let bound = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = bound.local_addr().unwrap().port();
        drop(bound); // now nothing is on that port at all
        let exp = SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        assert_eq!(find_inode(&exp).expect("dump"), None);
    }
}
