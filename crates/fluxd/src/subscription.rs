//! Blocking subscription transport kept outside the single-threaded reactor.
//!
//! The worker owns no daemon state. It reads Android's certificate stores,
//! performs one bounded ureq transaction (including configured retries), sends
//! the result through an in-process channel, and wakes epoll through eventfd.
//! The reactor remains the only place that parses, caches, or applies a result
//! (blueprint §28.3–§28.7).

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use ureq::tls::{Certificate, RootCerts, TlsConfig};

/// Android trust stores, in the order required by the Batch C contract.
const ANDROID_CERT_DIRS: [&str; 3] = [
    "/system/etc/security/cacerts/",
    "/apex/com.android.conscrypt/cacerts/",
    "/data/misc/user/0/cacerts-added/",
];

/// A subscription is configuration input, so use the same defensive ceiling
/// as the engine template rather than letting a server exhaust daemon memory.
pub const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;

/// Immutable request handed to a blocking worker thread.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub url: String,
    pub timeout: Duration,
    pub retries: u32,
}

/// Stable fetch failure exposed through daemon status.
#[derive(Debug, Clone)]
pub struct FetchError {
    pub token: String,
    pub detail: String,
}

/// One completed request, including the URL whose result it represents.
#[derive(Debug)]
pub struct FetchResult {
    pub url: String,
    pub result: Result<Vec<u8>, FetchError>,
}

/// At most one blocking fetch in flight, with eventfd completion notification.
pub struct Worker {
    event: Arc<OwnedFd>,
    sender: mpsc::Sender<FetchResult>,
    receiver: mpsc::Receiver<FetchResult>,
    busy: bool,
}

impl Worker {
    pub fn new() -> io::Result<Self> {
        // SAFETY: eventfd has no pointer arguments; the returned fd is owned
        // immediately and remains alive through the Arc cloned by a worker.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned and has no other owner.
        let event = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        let (sender, receiver) = mpsc::channel();
        Ok(Self {
            event,
            sender,
            receiver,
            busy: false,
        })
    }

    pub fn event_fd(&self) -> RawFd {
        self.event.as_raw_fd()
    }

    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Starts one blocking request. `Ok(false)` means an existing request is
    /// already serving the trigger, preserving idempotence without a queue.
    pub fn start(&mut self, request: FetchRequest) -> io::Result<bool> {
        if self.busy {
            return Ok(false);
        }
        let sender = self.sender.clone();
        let event = Arc::clone(&self.event);
        std::thread::Builder::new()
            .name("flux-subscription".to_string())
            .spawn(move || {
                let url = request.url.clone();
                let result = fetch(request);
                if sender.send(FetchResult { url, result }).is_ok() {
                    signal(&event);
                }
            })?;
        self.busy = true;
        Ok(true)
    }

    /// Drains the event counter and takes the single completed result.
    pub fn take_result(&mut self) -> Option<FetchResult> {
        drain(self.event.as_raw_fd());
        let result = self.receiver.try_recv().ok();
        if result.is_some() {
            self.busy = false;
        }
        result
    }
}

fn fetch(request: FetchRequest) -> Result<Vec<u8>, FetchError> {
    let certs = load_android_roots()?;
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&certs))
        .build();
    let agent = ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(request.timeout))
        .user_agent(format!("Flux/{} (sing-box; Android)", flux_core::VERSION))
        .tls_config(tls)
        .build()
        .new_agent();

    let attempts = request.retries.saturating_add(1);
    let mut last = None;
    for attempt in 1..=attempts {
        match fetch_once(&agent, &request.url) {
            Ok(bytes) => return Ok(bytes),
            Err((reason, detail)) => {
                last = Some((reason, format!("attempt {attempt}/{attempts}: {detail}")));
            }
        }
    }
    let (reason, detail) = last.unwrap_or(("request", "subscription request failed".to_string()));
    Err(FetchError {
        token: format!("subscription_fetch_failed:{reason}"),
        detail,
    })
}

fn fetch_once(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, (&'static str, String)> {
    let mut response = agent
        .get(url)
        .call()
        .map_err(|_| ("request", "subscription request failed".to_string()))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(
            u64::try_from(MAX_SUBSCRIPTION_BYTES + 1)
                .expect("the 8 MiB subscription limit fits in u64"),
        )
        .read_to_vec()
        .map_err(|_| {
            (
                "body",
                "subscription response body could not be read".to_string(),
            )
        })?;
    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        Err((
            "too_large",
            format!(
                "subscription response exceeds the {}-byte limit",
                MAX_SUBSCRIPTION_BYTES
            ),
        ))
    } else {
        Ok(bytes)
    }
}

fn load_android_roots() -> Result<Vec<Certificate<'static>>, FetchError> {
    let mut certs = Vec::new();
    for directory in ANDROID_CERT_DIRS {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let Ok(pem) = fs::read(entry.path()) else {
                continue;
            };
            if let Ok(certificate) = Certificate::from_pem(&pem) {
                certs.push(certificate);
            }
        }
    }
    if certs.is_empty() {
        return Err(FetchError {
            token: "subscription_fetch_failed:no_root_certificates".to_string(),
            detail: format!(
                "no root certificate could be read; tried {}",
                ANDROID_CERT_DIRS.join(", ")
            ),
        });
    }
    Ok(certs)
}

fn signal(event: &OwnedFd) {
    let value = 1u64.to_ne_bytes();
    // SAFETY: event is a live eventfd and value is the required eight bytes.
    unsafe {
        libc::write(event.as_raw_fd(), value.as_ptr().cast(), value.len());
    }
}

fn drain(fd: RawFd) {
    let mut value = [0u8; 8];
    // SAFETY: fd is a non-blocking eventfd and value is an eight-byte buffer.
    unsafe {
        libc::read(fd, value.as_mut_ptr().cast(), value.len());
    }
}
