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

use crate::layout::{read_capped, Layout};
use flux_core::config::FluxConfig;

/// Selects current pending input before consulting the accepted URL-bound cache.
/// A replacement response must remain usable even when old disk state is unreadable.
pub fn subscription_snapshot<'a>(
    layout: &Layout,
    flux: &FluxConfig,
    pending: Option<&'a [u8]>,
    use_cache: bool,
) -> Result<Option<std::borrow::Cow<'a, [u8]>>, (String, String)> {
    if flux.subscription.url.is_empty() {
        return Ok(None);
    }
    if let Some(raw) = pending {
        return Ok(Some(std::borrow::Cow::Borrowed(raw)));
    }
    if !use_cache {
        return Ok(None);
    }
    let binding_path = layout.subscription_url_binding();
    let binding = match read_capped(
        &binding_path,
        flux_core::config::MAX_CONFIG_BYTES.saturating_add(1),
    ) {
        Ok(binding) => binding,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err((
                "subscription_fetch_failed:cache_read".to_string(),
                format!("{}: {error}", binding_path.display()),
            ));
        }
    };
    if binding.len() > flux_core::config::MAX_CONFIG_BYTES {
        return Err((
            "subscription_fetch_failed:too_large".to_string(),
            format!("{} exceeds the Flux config limit", binding_path.display()),
        ));
    }
    if binding != flux.subscription.url.as_bytes() {
        return Ok(None);
    }
    let path = layout.subscription_raw();
    let raw = match read_capped(&path, crate::subscription::MAX_SUBSCRIPTION_BYTES + 1) {
        Ok(raw) => raw,
        // A first-use check is read-only and may precede the initial fetch.
        // The daemon will fetch before it creates an enabled generation.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err((
                "subscription_fetch_failed:cache_read".to_string(),
                format!("{}: {error}", path.display()),
            ));
        }
    };
    if raw.len() > crate::subscription::MAX_SUBSCRIPTION_BYTES {
        return Err((
            "subscription_fetch_failed:too_large".to_string(),
            format!(
                "{} exceeds the {}-byte limit",
                path.display(),
                crate::subscription::MAX_SUBSCRIPTION_BYTES
            ),
        ));
    }
    Ok(Some(std::borrow::Cow::Owned(raw)))
}

pub fn subscription_error_status(
    error: &flux_core::subscription::SubscriptionError,
) -> (String, String) {
    use flux_core::subscription::SubscriptionError;
    let token = match error {
        SubscriptionError::ZeroNodes => "subscription_empty",
        SubscriptionError::InvalidExcludePattern(_)
        | SubscriptionError::InvalidRenamePattern { .. } => "flux_config_invalid",
        _ => "subscription_fetch_failed:invalid_content",
    };
    (token.to_string(), error.to_string())
}

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

/// ureq is built with `rustls-no-provider`, so the crypto provider is a choice
/// made here rather than a feature flag's side effect. Installing it as the
/// process default is what ureq consults; a second install attempt only
/// reports that one is already in place, which is the state we want.
fn ensure_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
    });
}

fn fetch(request: FetchRequest) -> Result<Vec<u8>, FetchError> {
    ensure_crypto_provider();
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

/// Names the cause of a failed request (§23.1: `subscription_fetch_failed:<reason>`
/// distinguishes DNS, TLS, HTTP status and timeout) without echoing the URL,
/// which carries the provider token. ureq's own `Display` is safe for every
/// variant kept here; `BadUri` is the one that would repeat the URL, so it is
/// described rather than printed.
fn classify(error: &ureq::Error) -> (&'static str, String) {
    match error {
        ureq::Error::StatusCode(code) => ("http", format!("HTTP status {code}")),
        ureq::Error::HostNotFound => ("dns", "host name did not resolve".to_string()),
        ureq::Error::Timeout(phase) => ("timeout", format!("timed out during {phase}")),
        ureq::Error::ConnectionFailed => ("connect", "connection failed".to_string()),
        ureq::Error::Rustls(inner) => ("tls", format!("TLS handshake failed: {inner}")),
        ureq::Error::Tls(inner) => ("tls", format!("TLS failed: {inner}")),
        ureq::Error::Pem(inner) => ("tls", format!("root certificate PEM: {inner:?}")),
        ureq::Error::Io(inner) => classify_io(inner),
        ureq::Error::BadUri(_) => ("url", "the subscription URL is malformed".to_string()),
        ureq::Error::RequireHttpsOnly(_) => {
            ("url", "the subscription URL is not https".to_string())
        }
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            ("redirect", format!("{error}"))
        }
        ureq::Error::BodyExceedsLimit(_) => ("too_large", format!("{error}")),
        other => ("request", format!("{other}")),
    }
}

/// Bionic's getaddrinfo surfaces as `Error::Io` rather than `HostNotFound`
/// when the lookup itself fails. The message is the only stable discriminator
/// and never contains the URL.
fn classify_io(error: &io::Error) -> (&'static str, String) {
    let detail = error.to_string();
    let lower = detail.to_ascii_lowercase();
    if lower.contains("failed to lookup address")
        || lower.contains("no address associated")
        || lower.contains("name or service not known")
        || lower.contains("temporary failure in name resolution")
        || lower.contains("nodename nor servname")
    {
        ("dns", detail)
    } else {
        ("io", format!("I/O error: {detail}"))
    }
}

fn fetch_once(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, (&'static str, String)> {
    let mut response = agent.get(url).call().map_err(|error| classify(&error))?;
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

#[cfg(test)]
mod tests {
    use super::classify_io;
    use std::io::{self, ErrorKind};

    #[test]
    fn lookup_failures_are_dns() {
        let error = io::Error::other(
            "failed to lookup address information: No address associated with hostname",
        );
        let (token, detail) = classify_io(&error);
        assert_eq!(token, "dns");
        assert!(detail.contains("failed to lookup address information"));
    }

    #[test]
    fn other_io_stays_io() {
        let error = io::Error::new(ErrorKind::ConnectionRefused, "connection refused");
        assert_eq!(
            classify_io(&error),
            ("io", "I/O error: connection refused".to_string())
        );
    }
}
