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
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use super::wire::{
    feed_dump, DumpFeed, MessageBuilder, RawMessage, RequestSocket, NLM_F_DUMP, NLM_F_REQUEST,
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const INET_DIAG_MSG_MIN_LEN: usize = 72;
const FIND_INODE_DEADLINE: Duration = Duration::from_secs(3);
const FIND_INODE_DATAGRAMS: u32 = 64;

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

/// One non-blocking readiness dump of the four engine listeners (§9.5).
///
/// The reactor keeps this fd in epoll and returns between datagrams so
/// disable, stop and pidfd stay serviceable. A dump without `NLMSG_DONE` is
/// [`ProbeStep::Wait`], never "socket absent".
pub struct ProbeReady {
    socket: RequestSocket,
    expectations: [SocketExpectation; 4],
    index: usize,
    seq: u32,
    collected: Vec<RawMessage>,
    inodes: [Option<u32>; 4],
}

/// Progress of one [`ProbeReady`] datagram.
#[derive(Debug)]
pub enum ProbeStep {
    /// Need another readable event, or the next dump request was just sent.
    Wait,
    /// All four dumps completed; some listeners were not present.
    Pending {
        verified: u8,
        inodes: [Option<u32>; 4],
    },
    /// All four dumps completed and matched.
    Ready { inodes: [u32; 4] },
}

impl ProbeReady {
    pub fn start(expectations: [SocketExpectation; 4]) -> io::Result<Self> {
        let socket = RequestSocket::open_nonblocking(libc::NETLINK_SOCK_DIAG)?;
        let mut probe = Self {
            socket,
            expectations,
            index: 0,
            seq: 0,
            collected: Vec::new(),
            inodes: [None; 4],
        };
        probe.send_current()?;
        Ok(probe)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Consume one datagram. MUST NOT `poll`/`recv` in a loop.
    pub fn on_readable(&mut self) -> io::Result<ProbeStep> {
        let messages = match self.socket.try_recv(self.seq) {
            Ok(messages) => messages,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(ProbeStep::Wait);
            }
            Err(error) => return Err(error),
        };
        match feed_dump(std::mem::take(&mut self.collected), &messages, false)? {
            DumpFeed::NeedMore(items) => {
                self.collected = items;
                Ok(ProbeStep::Wait)
            }
            DumpFeed::Complete(items) => {
                let exp = &self.expectations[self.index];
                self.inodes[self.index] = items
                    .iter()
                    .find_map(|message| match_diag_msg(&message.payload, exp));
                self.index += 1;
                if self.index < self.expectations.len() {
                    self.send_current()?;
                    Ok(ProbeStep::Wait)
                } else {
                    Ok(self.finish_round())
                }
            }
        }
    }

    fn send_current(&mut self) -> io::Result<()> {
        self.seq = self.socket.next_seq();
        self.collected.clear();
        self.socket
            .send(&dump_request(&self.expectations[self.index], self.seq))
    }

    fn finish_round(&self) -> ProbeStep {
        let verified = self.inodes.iter().filter(|inode| inode.is_some()).count() as u8;
        match self.inodes {
            [Some(a), Some(b), Some(c), Some(d)] => ProbeStep::Ready {
                inodes: [a, b, c, d],
            },
            inodes => ProbeStep::Pending { verified, inodes },
        }
    }
}

/// Finds the inode of the socket exactly matching `exp`, or `None` when no
/// such socket exists right now. An error means the enumeration itself failed
/// (netlink unavailable or the dump never completed), not that the socket is
/// absent.
///
/// Bounded helper for tests and device checks. The reactor MUST drive
/// [`ProbeReady`] from epoll instead of calling this.
pub fn find_inode(exp: &SocketExpectation) -> io::Result<Option<u32>> {
    let mut socket = RequestSocket::open_nonblocking(libc::NETLINK_SOCK_DIAG)?;
    let seq = socket.next_seq();
    socket.send(&dump_request(exp, seq))?;
    let mut collected = Vec::new();
    let deadline = Instant::now() + FIND_INODE_DEADLINE;
    let mut datagrams = 0u32;
    loop {
        if datagrams >= FIND_INODE_DATAGRAMS || Instant::now() >= deadline {
            return Err(incomplete_diag());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || !poll_readable(socket.as_raw_fd(), remaining)? {
            return Err(incomplete_diag());
        }
        datagrams += 1;
        let messages = match socket.try_recv(seq) {
            Ok(messages) => messages,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        match feed_dump(std::mem::take(&mut collected), &messages, false)? {
            DumpFeed::NeedMore(items) => collected = items,
            DumpFeed::Complete(items) => {
                return Ok(items
                    .iter()
                    .find_map(|message| match_diag_msg(&message.payload, exp)));
            }
        }
    }
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

/// Incomplete dumps (`NLMSG_DONE` missing, interrupted, truncated) are retried
/// until the readiness deadline. Hard errors (`ENOENT`, `EPERM`) are not.
pub(crate) fn dump_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData
            | io::ErrorKind::Interrupted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
    )
}

/// One `SOCK_DIAG_BY_FAMILY` dump request for `family × protocol`, all states.
/// Matching on the exact address/port happens on the response side: dump
/// filters via `idiag_states` only, and we want the code path identical for
/// TCP and UDP.
fn dump_request(exp: &SocketExpectation, seq: u32) -> Vec<u8> {
    let mut req = [0u8; INET_DIAG_REQ_V2_LEN];
    req[0] = exp.family();
    req[1] = exp.protocol;
    req[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
    MessageBuilder::new(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, seq, &req).finish()
}

fn incomplete_diag() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "incomplete sock_diag dump (no NLMSG_DONE)",
    )
}

fn poll_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    loop {
        // SAFETY: pfd is valid for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc > 0 {
            return Ok(true);
        }
        if rc == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
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
    use std::time::{Duration, Instant};

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

    fn unused_tcp_port() -> u16 {
        let bound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = bound.local_addr().unwrap().port();
        drop(bound);
        port
    }

    #[test]
    fn probe_ready_reports_absence_only_after_done() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        let present = SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let missing = SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: unused_tcp_port(),
        };
        let mut probe = ProbeReady::start([present, missing, missing, missing]).expect("start");
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(
                Instant::now() < deadline,
                "ProbeReady did not finish four dumps"
            );
            if !poll_readable(
                probe.as_raw_fd(),
                deadline.saturating_duration_since(Instant::now()),
            )
            .expect("poll")
            {
                panic!("ProbeReady timed out waiting for sock_diag");
            }
            match probe.on_readable().expect("on_readable") {
                ProbeStep::Wait => continue,
                ProbeStep::Pending { verified, inodes } => {
                    assert_eq!(verified, 1);
                    assert!(inodes[0].is_some());
                    assert!(inodes[1].is_none());
                    assert!(inodes[2].is_none());
                    assert!(inodes[3].is_none());
                    break;
                }
                ProbeStep::Ready { .. } => {
                    panic!("unused ports must not become Ready")
                }
            }
        }
        drop(listener);
    }
}
