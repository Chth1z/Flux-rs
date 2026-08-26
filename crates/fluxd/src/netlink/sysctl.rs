//! Read-only sysctl access (blueprint §8.9.6).

use std::fs;
use std::io;
use std::path::Path;

/// Reads an integer sysctl value from `/proc/sys/...`.
pub fn read_i64(path: &Path) -> io::Result<i64> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    trimmed
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sysctl not an integer"))
}

/// `net.ipv4.conf.all.rp_filter` — read only (§8.4).
pub fn all_rp_filter() -> io::Result<i64> {
    read_i64(Path::new("/proc/sys/net/ipv4/conf/all/rp_filter"))
}

/// Per-interface sysctl under `net/ipv4/conf/<if>/name`.
pub fn iface_ipv4_conf(iface: &str, name: &str) -> io::Result<i64> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{name}");
    read_i64(Path::new(&path))
}

/// Writes a per-interface sysctl (only for Flux-owned interfaces like `flxrs1`).
pub fn write_iface_ipv4_conf(iface: &str, name: &str, value: i64) -> io::Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{name}");
    fs::write(path, value.to_string())
}
