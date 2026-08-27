//! `SOCK_SEQPACKET` control server and client.
//!
//! Implements blueprint §10.3: one single-line JSON message per SEQPACKET
//! frame (the transport preserves message boundaries, so there is no length
//! prefix), 64 KiB request cap, and a root-only peer gate via `SO_PEERCRED`.
//!
//! Peer gate detail: the daemon accepts uid 0 or its own euid. On the device
//! the daemon runs as root, so the two are the same check the blueprint
//! specifies; on a development host it lets the test daemon talk to its own
//! test client without weakening anything the product ships.
//!
//! Only the flock owner ever unlinks a stale socket (blueprint §10.3): the
//! daemon calls [`ControlServer::bind`] strictly after taking the instance
//! lock, and a rejected second instance exits without touching the path.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use flux_core::control_wire::{self, Request, Response, MAX_REQUEST_BYTES};

/// Upper bound for one response frame. Responses carry per-interface tables
/// and counters and may legitimately exceed the request cap.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

fn sockaddr_un(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: sockaddr_un is a plain-old-data struct; zeroing it is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

fn seqpacket_socket(nonblocking: bool) -> io::Result<OwnedFd> {
    let mut ty = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    if nonblocking {
        ty |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: plain socket(2); the fd is immediately owned.
    let fd = unsafe { libc::socket(libc::AF_UNIX, ty, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned by the kernel, not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The listening control socket, owned by the daemon.
#[derive(Debug)]
pub struct ControlServer {
    fd: OwnedFd,
}

impl ControlServer {
    /// Unlinks any stale socket at `path` (we hold the instance lock, so it
    /// can only be a leftover of a dead daemon), binds, chmods to 0600 and
    /// listens. Non-blocking: accepts are driven by epoll.
    pub fn bind(path: &Path) -> io::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                // SAFETY: geteuid has no preconditions and cannot fail.
                let own_uid = unsafe { libc::geteuid() };
                if !meta.file_type().is_socket() || meta.uid() != own_uid {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing to unlink non-owned or non-socket control path {}",
                            path.display()
                        ),
                    ));
                }
                std::fs::remove_file(path)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let fd = seqpacket_socket(true)?;
        let (addr, len) = sockaddr_un(path)?;
        // SAFETY: addr is a valid sockaddr_un of the stated length.
        let rc = unsafe { libc::bind(fd.as_raw_fd(), std::ptr::addr_of!(addr).cast(), len) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        // SAFETY: listen(2) on a bound socket.
        if unsafe { libc::listen(fd.as_raw_fd(), 8) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Accepts one pending connection, or `None` when none is queued.
    pub fn accept(&self) -> io::Result<Option<ControlConn>> {
        // SAFETY: accept4(2) on our listening socket; the fd is owned below.
        let fd = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err);
        }
        // SAFETY: just returned by accept4, not owned elsewhere.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Some(ControlConn { fd }))
    }
}

/// One accepted control connection: exactly one request, one response.
#[derive(Debug)]
pub struct ControlConn {
    fd: OwnedFd,
}

impl ControlConn {
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The peer's uid via `SO_PEERCRED`.
    pub fn peer_uid(&self) -> io::Result<u32> {
        // SAFETY: ucred is plain-old-data; the kernel fills it.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid fd, valid out-pointer and length.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    /// Whether the peer may issue requests: root, or the daemon's own euid
    /// (identical to root on the device, see the module header).
    pub fn peer_allowed(&self) -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let own = unsafe { libc::geteuid() };
        matches!(self.peer_uid(), Ok(uid) if uid == 0 || uid == own)
    }

    /// Reads one request frame. Oversize or malformed frames are protocol
    /// violations answered by closing the connection (blueprint §23.2).
    pub fn recv_request(&self) -> io::Result<Request> {
        let mut buf = vec![0u8; MAX_REQUEST_BYTES + 1];
        let n = recv_once(&self.fd, &mut buf)?;
        if n > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request exceeds 64 KiB",
            ));
        }
        let line = std::str::from_utf8(&buf[..n])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request is not UTF-8"))?;
        control_wire::from_line(line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Sends one response frame.
    pub fn send_response(&self, response: &Response) -> io::Result<()> {
        let line = control_wire::to_line(response)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        send_once(&self.fd, line.as_bytes())
    }
}

fn set_socket_timeouts(fd: &OwnedFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: valid fd; tv is a valid timeval for the call's duration.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_once(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: buf is valid for its length for the duration of the call.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

fn send_once(fd: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
    loop {
        // SAFETY: bytes is valid for its length for the duration of the call.
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short SEQPACKET send",
            ));
        }
        return Ok(());
    }
}

/// Client side: one request, one response, bounded by `timeout` end to end.
pub fn request(path: &Path, request: &Request, timeout: Duration) -> io::Result<Response> {
    let fd = seqpacket_socket(false)?;
    set_socket_timeouts(&fd, timeout)?;
    let (addr, len) = sockaddr_un(path)?;
    // SAFETY: addr is a valid sockaddr_un of the stated length.
    let rc = unsafe { libc::connect(fd.as_raw_fd(), std::ptr::addr_of!(addr).cast(), len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let line = control_wire::to_line(request)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    send_once(&fd, line.as_bytes())?;

    let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
    let n = recv_once(&fd, &mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "daemon closed the connection (rejected request?)",
        ));
    }
    let line = std::str::from_utf8(&buf[..n])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response is not UTF-8"))?;
    control_wire::from_line(line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_socket(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        dir.push(format!("flux-ctl-{tag}-{pid}.sock"));
        let _ = std::fs::remove_file(&dir);
        dir
    }

    #[test]
    fn request_response_round_trip_over_a_real_seqpacket() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_socket("rt");
        let server = ControlServer::bind(&path).expect("bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "control socket must be 0600");

        let client_path = path.clone();
        let client = std::thread::spawn(move || {
            request(&client_path, &Request::Status, Duration::from_secs(5)).expect("client")
        });

        // Single-threaded accept loop, as the daemon would run it.
        let conn = loop {
            if let Some(conn) = server.accept().expect("accept") {
                break conn;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(conn.peer_allowed(), "same-uid peer must be allowed");
        let req = conn.recv_request().expect("request decodes");
        assert_eq!(req, Request::Status);

        let response = sample_response();
        conn.send_response(&response).expect("send");
        let got = client.join().expect("client thread");
        assert_eq!(got, response);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn oversize_request_is_rejected() {
        let path = tmp_socket("big");
        let server = ControlServer::bind(&path).expect("bind");

        let client_path = path.clone();
        let client = std::thread::spawn(move || {
            let fd = seqpacket_socket(false).unwrap();
            let (addr, len) = sockaddr_un(&client_path).unwrap();
            // SAFETY: valid sockaddr for the call's duration.
            let rc = unsafe { libc::connect(fd.as_raw_fd(), std::ptr::addr_of!(addr).cast(), len) };
            assert_eq!(rc, 0);
            let huge = vec![b'x'; MAX_REQUEST_BYTES + 1];
            let _ = send_once(&fd, &huge);
        });

        let conn = loop {
            if let Some(conn) = server.accept().expect("accept") {
                break conn;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let err = conn.recv_request().expect_err("must reject");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    fn sample_response() -> Response {
        use flux_core::control_wire::{Counters, EngineStatus, PolicyCounts, State};
        Response {
            ok: true,
            version: flux_core::VERSION.to_string(),
            abi_magic: format!("{:#010X}", flux_core::abi::FLUX_ABI_MAGIC),
            state: State::Inactive,
            generation: 0,
            backoff_seconds: 0,
            engine: EngineStatus {
                running: false,
                pid: None,
                sockets_verified: 0,
                effective_config: None,
            },
            policy: PolicyCounts::default(),
            ifaces: vec![],
            counters: Counters::default(),
            sysctl: Default::default(),
            warnings: vec![],
            hints: vec![],
            last_error: None,
        }
    }
}
