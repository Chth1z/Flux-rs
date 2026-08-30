//! CIDR canonicalisation, the fixed bypass set, and LPM key encoding.
//!
//! Implements blueprint §7.2, §11.2 and D7/D16/D21. The fixed bypass set below
//! is not a convenience default: every entry is load-bearing.
//!
//! Nothing here does I/O; a caller hands in the text. Blueprint §15.2 test 2
//! lives at the bottom: canonicalisation, fixed bypass injection, LPM key
//! encoding and the capacity ceiling.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::abi::{BypassTag, LpmV4Key, LpmV6Key, LISTEN_V4_STR, LISTEN_V6_STR, LPM_MAX_ENTRIES};

/// Non-listener prefixes that are permanently in the bypass set, whatever the
/// user config says. [`fixed_bypass_v4`] adds the listener host route from the
/// ABI identity rather than duplicating its address here.
///
/// The listener address must be included because sing-box's TProxy UDP write-back
/// binds the original destination with `IP_TRANSPARENT`; if a selected app could
/// target the listener, the write-back would collide with the listener itself
/// (blueprint D7, D16, upstream issue #3646).
///
/// Note it is the exact listener address, not its prefix. Reserving a whole
/// prefix was overkill for self-loop prevention and it collided with sing-box's
/// conventional fakeip range, which made fakeip fail silently and completely
/// (blueprint D21, §9.0).
const FIXED_BYPASS_V4_PREFIXES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

/// IPv6 counterpart of [`FIXED_BYPASS_V4_PREFIXES`].
const FIXED_BYPASS_V6_PREFIXES: &[&str] =
    &["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

/// Why a user-supplied prefix was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The text was not `address/prefixlen`, or the address was not itself
    /// canonical (leading zeros, uncompressed IPv6, and the like).
    Malformed(String),
    /// `prefixlen` exceeded the family width.
    PrefixTooLong(u8),
    /// Host bits were set below `prefixlen`, so the text was not canonical.
    HostBitsSet(String),
    /// Adding the prefix would exceed the LPM capacity.
    CapacityExceeded,
}

/// A canonical IPv4 prefix: the address has no bits set below `prefix_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    /// Network address, already masked to `prefix_len`.
    pub addr: Ipv4Addr,
    /// Prefix length in bits, `0..=32`.
    pub prefix_len: u8,
}

/// A canonical IPv6 prefix: the address has no bits set below `prefix_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Cidr {
    /// Network address, already masked to `prefix_len`.
    pub addr: Ipv6Addr,
    /// Prefix length in bits, `0..=128`.
    pub prefix_len: u8,
}

/// A bypass prefix together with the semantic tag stored as its LPM value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BypassEntry<C> {
    /// Canonical prefix used as the LPM key.
    pub cidr: C,
    /// Whether this is an invariant or user policy.
    pub tag: BypassTag,
}

impl<C> BypassEntry<C> {
    /// Tags a mechanism-owned prefix that is always direct.
    pub const fn reserved(cidr: C) -> Self {
        Self {
            cidr,
            tag: BypassTag::Reserved,
        }
    }

    /// Tags a user-owned prefix interpreted according to `cidr_mode`.
    pub const fn policy(cidr: C) -> Self {
        Self {
            cidr,
            tag: BypassTag::Policy,
        }
    }
}

/// Tagged IPv4 bypass prefix.
pub type Ipv4Bypass = BypassEntry<Ipv4Cidr>;
/// Tagged IPv6 bypass prefix.
pub type Ipv6Bypass = BypassEntry<Ipv6Cidr>;

fn split_prefix(text: &str) -> Result<(&str, u8), CidrError> {
    let (addr, len) = text
        .split_once('/')
        .ok_or_else(|| CidrError::Malformed(text.to_string()))?;
    let prefix_len: u8 = len
        .parse()
        .map_err(|_| CidrError::Malformed(text.to_string()))?;
    Ok((addr, prefix_len))
}

impl Ipv4Cidr {
    /// Parses a canonical `a.b.c.d/n`.
    ///
    /// Rejects a missing prefix, a prefix above 32, a non-canonical address
    /// (Rust's parser already refuses leading zeros), and any host bits set
    /// below the prefix. It never silently masks: a non-canonical prefix is a
    /// configuration error, not something to fix up (blueprint §11.2).
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let (addr_str, prefix_len) = split_prefix(text)?;
        if prefix_len > 32 {
            return Err(CidrError::PrefixTooLong(prefix_len));
        }
        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|_| CidrError::Malformed(text.to_string()))?;
        if text != format!("{addr}/{prefix_len}") {
            return Err(CidrError::Malformed(text.to_string()));
        }
        let bits = u32::from(addr);
        let mask = mask32(prefix_len);
        if bits & !mask != 0 {
            return Err(CidrError::HostBitsSet(text.to_string()));
        }
        Ok(Self { addr, prefix_len })
    }

    /// Encodes this prefix as the LPM trie key the data plane expects.
    ///
    /// `addr` bytes are network byte order, which is exactly what
    /// [`Ipv4Addr::octets`] returns, so they can be compared against packet
    /// bytes directly (blueprint §6, `be` fields).
    pub fn to_lpm_key(self) -> LpmV4Key {
        LpmV4Key {
            prefixlen: u32::from(self.prefix_len),
            addr: self.addr.octets(),
        }
    }

    /// Whether every address in `other` is also in `self`.
    ///
    /// A shorter prefix cannot be contained in a longer one however the bits
    /// line up, so the length test comes first.
    pub fn contains_prefix(self, other: &Self) -> bool {
        other.prefix_len >= self.prefix_len
            && u32::from(other.addr) & mask32(self.prefix_len) == u32::from(self.addr)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Ipv6Cidr {
    /// Parses a canonical `addr/n`. See [`Ipv4Cidr::parse`] for the rules.
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let (addr_str, prefix_len) = split_prefix(text)?;
        if prefix_len > 128 {
            return Err(CidrError::PrefixTooLong(prefix_len));
        }
        let addr: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| CidrError::Malformed(text.to_string()))?;
        if text != format!("{addr}/{prefix_len}") {
            return Err(CidrError::Malformed(text.to_string()));
        }
        let bits = u128::from(addr);
        let mask = mask128(prefix_len);
        if bits & !mask != 0 {
            return Err(CidrError::HostBitsSet(text.to_string()));
        }
        Ok(Self { addr, prefix_len })
    }

    /// Encodes this prefix as the LPM trie key the data plane expects.
    pub fn to_lpm_key(self) -> LpmV6Key {
        LpmV6Key {
            prefixlen: u32::from(self.prefix_len),
            addr: self.addr.octets(),
        }
    }

    /// Whether every address in `other` is also in `self`. See
    /// [`Ipv4Cidr::contains_prefix`].
    pub fn contains_prefix(self, other: &Self) -> bool {
        other.prefix_len >= self.prefix_len
            && u128::from(other.addr) & mask128(self.prefix_len) == u128::from(self.addr)
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

fn mask32(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        n if n >= 32 => u32::MAX,
        n => u32::MAX << (32 - n),
    }
}

fn mask128(prefix_len: u8) -> u128 {
    match prefix_len {
        0 => 0,
        n if n >= 128 => u128::MAX,
        n => u128::MAX << (128 - n),
    }
}

/// The fixed IPv4 bypass prefixes, parsed once and tagged as mechanism-owned.
/// The listener `/32` is derived from [`LISTEN_V4_STR`].
pub fn fixed_bypass_v4() -> &'static [Ipv4Bypass] {
    static CELL: OnceLock<Vec<Ipv4Bypass>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut entries = FIXED_BYPASS_V4_PREFIXES
            .iter()
            .map(|s| {
                BypassEntry::reserved(
                    Ipv4Cidr::parse(s).expect("fixed bypass constant is a canonical prefix"),
                )
            })
            .collect::<Vec<_>>();
        entries.push(BypassEntry::reserved(Ipv4Cidr {
            addr: LISTEN_V4_STR
                .parse()
                .expect("IPv4 listener ABI constant is an address"),
            prefix_len: 32,
        }));
        entries
    })
}

/// The fixed IPv6 bypass prefixes, parsed once and tagged as mechanism-owned.
/// The listener `/128` is derived from [`LISTEN_V6_STR`].
pub fn fixed_bypass_v6() -> &'static [Ipv6Bypass] {
    static CELL: OnceLock<Vec<Ipv6Bypass>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut entries = FIXED_BYPASS_V6_PREFIXES
            .iter()
            .map(|s| {
                BypassEntry::reserved(
                    Ipv6Cidr::parse(s).expect("fixed bypass constant is a canonical prefix"),
                )
            })
            .collect::<Vec<_>>();
        entries.push(BypassEntry::reserved(Ipv6Cidr {
            addr: LISTEN_V6_STR
                .parse()
                .expect("IPv6 listener ABI constant is an address"),
            prefix_len: 128,
        }));
        entries
    })
}

/// Fixed safe bypass and listener prefixes, injected regardless of user config.
///
/// Does not include the device's own dynamic addresses: those are a runtime
/// input from rtnetlink, not a compile-time constant (blueprint §11.2, D7/D20).
pub fn fixed_bypass() -> (&'static [Ipv4Bypass], &'static [Ipv6Bypass]) {
    (fixed_bypass_v4(), fixed_bypass_v6())
}

/// The most IPv4 prefixes the trie can hold, echoing [`LPM_MAX_ENTRIES`].
pub const MAX_BYPASS_V4: u32 = LPM_MAX_ENTRIES;
/// The most IPv6 prefixes the trie can hold.
pub const MAX_BYPASS_V6: u32 = LPM_MAX_ENTRIES;

#[cfg(test)]
mod tests {
    use super::*;

    // Blueprint §15.2 test 2: IPv4/IPv6 CIDR canonicalise, fixed bypass
    // injection, LPM key encoding, capacity ceiling.

    #[test]
    fn parses_canonical_v4_prefixes() {
        let c = Ipv4Cidr::parse("192.168.0.0/16").expect("canonical");
        assert_eq!(c.addr, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(c.prefix_len, 16);
        assert_eq!(c.to_string(), "192.168.0.0/16");

        assert_eq!(
            Ipv4Cidr::parse("0.0.0.0/0").expect("default route"),
            Ipv4Cidr {
                addr: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0
            }
        );
    }

    #[test]
    fn rejects_non_canonical_v4() {
        // Host bits set below the prefix.
        assert!(matches!(
            Ipv4Cidr::parse("192.168.0.1/16"),
            Err(CidrError::HostBitsSet(_))
        ));
        // Prefix wider than the family.
        assert_eq!(
            Ipv4Cidr::parse("10.0.0.0/33"),
            Err(CidrError::PrefixTooLong(33))
        );
        // Missing prefix.
        assert!(matches!(
            Ipv4Cidr::parse("10.0.0.0"),
            Err(CidrError::Malformed(_))
        ));
        // Leading zeros are ambiguous (octal) and Rust's parser refuses them.
        assert!(matches!(
            Ipv4Cidr::parse("010.0.0.0/8"),
            Err(CidrError::Malformed(_))
        ));
    }

    #[test]
    fn parses_and_canonicalises_v6() {
        let c = Ipv6Cidr::parse("2001:db8::2/128").expect("canonical");
        assert_eq!(c.prefix_len, 128);
        // Display is the canonical compressed form.
        assert_eq!(c.to_string(), "2001:db8::2/128");

        assert!(matches!(
            Ipv6Cidr::parse("2001:db8::1/32"),
            Err(CidrError::HostBitsSet(_))
        ));
        assert_eq!(
            Ipv6Cidr::parse("::/129"),
            Err(CidrError::PrefixTooLong(129))
        );
        assert!(matches!(
            Ipv6Cidr::parse("2001:0db8:0:1:0:0:0:2/128"),
            Err(CidrError::Malformed(_))
        ));
        assert!(matches!(
            Ipv6Cidr::parse("2001:DB8:0:1::2/128"),
            Err(CidrError::Malformed(_))
        ));
    }

    #[test]
    fn lpm_key_encoding_is_network_order() {
        let key = Ipv4Cidr::parse("172.16.0.0/12").unwrap().to_lpm_key();
        assert_eq!(key.prefixlen, 12);
        assert_eq!(key.addr, [172, 16, 0, 0]);

        let key6 = Ipv6Cidr::parse("fc00::/7").unwrap().to_lpm_key();
        assert_eq!(key6.prefixlen, 7);
        assert_eq!(key6.addr[0], 0xfc);
        assert_eq!(key6.addr[1..], [0u8; 15]);
    }

    #[test]
    fn fixed_bypass_is_canonical_and_reserved() {
        let (v4, v6) = fixed_bypass();
        assert_eq!(v4.len(), FIXED_BYPASS_V4_PREFIXES.len() + 1);
        assert_eq!(v6.len(), FIXED_BYPASS_V6_PREFIXES.len() + 1);
        assert!(v4.iter().all(|entry| entry.tag == BypassTag::Reserved));
        assert!(v6.iter().all(|entry| entry.tag == BypassTag::Reserved));

        // The old fakeip-colliding /15 must NOT be present (blueprint §9.0).
        assert!(!v4.iter().any(|entry| entry.cidr.prefix_len == 15));

        let user = BypassEntry::policy(Ipv4Cidr::parse("100.64.0.0/10").unwrap());
        assert_eq!(user.tag, BypassTag::Policy);
    }

    #[test]
    fn fixed_bypass_listener_addresses_match_the_abi() {
        let (v4, v6) = fixed_bypass();
        let listen_v4: Ipv4Addr = LISTEN_V4_STR.parse().expect("IPv4 listener ABI address");
        let listen_v6: Ipv6Addr = LISTEN_V6_STR.parse().expect("IPv6 listener ABI address");
        let expected_v4 = Ipv4Cidr {
            addr: listen_v4,
            prefix_len: 32,
        };
        let expected_v6 = Ipv6Cidr {
            addr: listen_v6,
            prefix_len: 128,
        };

        // The listener is bypassed as an exact address, never a wider prefix
        // (blueprint D21): a /32 and a /128, not the old /15 and /32.
        assert_eq!(
            v4.iter().filter(|entry| entry.cidr == expected_v4).count(),
            1
        );
        assert_eq!(
            v6.iter().filter(|entry| entry.cidr == expected_v6).count(),
            1
        );
    }

    #[test]
    fn capacity_ceiling_matches_the_abi() {
        assert_eq!(MAX_BYPASS_V4, 65_536);
        assert_eq!(MAX_BYPASS_V6, 65_536);
    }
}
