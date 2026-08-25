//! CIDR canonicalisation, the fixed bypass set, and LPM key encoding.
//!
//! Implements blueprint §7.2 and D7/D16. The fixed bypass set below is not a
//! convenience default: every entry is load-bearing.
//!
//! Not implemented yet — Phase 1 (blueprint §17).

/// Prefixes that are permanently in the bypass set, whatever the user config
/// says.
///
/// The listener address is included because sing-box's TProxy UDP write-back
/// binds the original destination with `IP_TRANSPARENT`; if a selected app could
/// target the listener, the write-back would collide with the listener itself
/// (blueprint D7, D16, upstream issue #3646).
///
/// Note it is the exact listener address, not its prefix. Reserving a whole
/// prefix was overkill for self-loop prevention and it collided with sing-box's
/// conventional fakeip range, which made fakeip fail silently and completely
/// (blueprint D21, §9.0).
pub const FIXED_BYPASS_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.51.100.1/32", // the listener itself, nothing wider
    "224.0.0.0/4",
    "255.255.255.255/32",
];

/// IPv6 counterpart of [`FIXED_BYPASS_V4`].
pub const FIXED_BYPASS_V6: &[&str] = &[
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8:0:1::2/128", // the listener itself, nothing wider
];

/// Why a user-supplied prefix was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The text was not `address/prefixlen`.
    Malformed,
    /// `prefixlen` exceeded the family width.
    PrefixTooLong,
    /// Host bits were set below `prefixlen`.
    HostBitsSet,
    /// Adding the prefix would exceed the LPM capacity.
    CapacityExceeded,
}
