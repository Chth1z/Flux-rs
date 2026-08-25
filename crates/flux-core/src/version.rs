//! SemVer arithmetic for module packaging.
//!
//! Implements blueprint §13.1. Magisk's `module.prop` needs a monotonically
//! increasing integer `versionCode`, so it is derived from the SemVer triple
//! rather than maintained by hand.

/// Derives a monotonic `versionCode` from a SemVer triple.
///
/// The encoding reserves three decimal digits each for minor and patch, which
/// is why both are capped below.
pub fn version_code(major: u32, minor: u32, patch: u32) -> Option<u32> {
    if minor > 999 || patch > 999 {
        return None;
    }
    Some(major * 1_000_000 + minor * 1_000 + patch)
}

/// Parses a `major.minor.patch` string, rejecting pre-release and build
/// metadata because `versionCode` cannot represent them.
pub fn parse_triple(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_version_parses_and_encodes() {
        let (major, minor, patch) = parse_triple(crate::VERSION).expect("workspace version");
        assert_eq!((major, minor, patch), (0, 9, 0));
        assert_eq!(version_code(major, minor, patch), Some(9_000));
    }

    #[test]
    fn version_code_is_monotonic_across_components() {
        assert!(version_code(0, 9, 0) < version_code(0, 9, 1));
        assert!(version_code(0, 9, 999) < version_code(0, 10, 0));
        assert!(version_code(0, 999, 999) < version_code(1, 0, 0));
    }

    #[test]
    fn version_code_rejects_unrepresentable_components() {
        assert_eq!(version_code(0, 1000, 0), None);
        assert_eq!(version_code(0, 0, 1000), None);
    }

    #[test]
    fn parse_rejects_prerelease_and_extra_components() {
        assert_eq!(parse_triple("0.9.0-rc1"), None);
        assert_eq!(parse_triple("0.9.0.1"), None);
        assert_eq!(parse_triple("0.9"), None);
    }
}
