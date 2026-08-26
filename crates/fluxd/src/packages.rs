//! Reads `/data/system/packages.list` and feeds
//! [`flux_core::selector`].
//!
//! Implements blueprint D8. Deliberately a plain file read plus inotify: going
//! through binder (`cmd package`) would make activation depend on
//! `system_server` readiness during late boot.
//!
//! The parser itself remains in `flux-core`; this module owns the runtime I/O
//! boundary and its hard size limit.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

use std::io::{self, Read};

/// Source of truth for package-to-UID mapping.
pub const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";

/// Largest accepted package database (blueprint §11.3).
pub const MAX_PACKAGES_BYTES: usize = 8 * 1024 * 1024;

/// Reads the package database without ever allocating past its contract cap.
pub fn read() -> io::Result<String> {
    let file = std::fs::File::open(PACKAGES_LIST_PATH)?;
    let mut bytes = Vec::new();
    file.take((MAX_PACKAGES_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKAGES_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packages.list exceeds the 8 MiB limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "packages.list is not UTF-8"))
}
