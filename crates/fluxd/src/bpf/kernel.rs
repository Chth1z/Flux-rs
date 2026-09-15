//! Preflight for the one release-based exclusion in blueprint §1.6.3a.
//! This belongs to the loader so capability checks cannot bypass it.

use super::LoadError;

pub(super) fn release() -> Result<String, LoadError> {
    // SAFETY: uname writes one fixed-size utsname value into valid storage.
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    // SAFETY: `uts` points to writable storage for one complete utsname.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(LoadError::verify(
            "kernel_release_unreadable",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: uname guarantees NUL-terminated fields.
    Ok(unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

pub(super) fn validate(release: &str) -> Result<(), LoadError> {
    // Real LPM operations cannot safely probe this defect. Every Flux runtime
    // needs LPM entries, so the exclusion applies even to an empty user policy.
    let version = release.split(['-', '+']).next().unwrap_or(release);
    let mut numbers = version.split('.');
    let major = numbers.next().and_then(|part| part.parse::<u64>().ok());
    let minor = numbers.next().and_then(|part| part.parse::<u64>().ok());
    if (major, minor) != (Some(6), Some(6)) {
        return Ok(());
    }
    let patch = numbers.next().and_then(|part| part.parse::<u64>().ok());
    if patch.is_some_and(|patch| patch >= 47) {
        return Ok(());
    }
    Err(LoadError::verify(
        &format!("unsupported_lpm_trie_kernel:{release}"),
        "Linux 6.6.0-6.6.46 has a known LPM trie UBSAN crash; upgrade to 6.6.47+",
    ))
}
