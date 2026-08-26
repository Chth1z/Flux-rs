//! SemVer arithmetic and packaging metadata for the module.
//!
//! Implements blueprint §13.1 and §13.4. There is a single version source, the
//! workspace manifest; everything a release needs — `versionCode`, the
//! `module.prop` body, the artifact name — is derived from it here so no second
//! version file can drift out of sync (blueprint §15.4(3)).

/// The root module id (blueprint §1.1, §13.1). Note the underscore: the module
/// installs to `/data/adb/modules/flux_rs`, while the runtime state root is
/// `/data/adb/flux-rs` with a hyphen.
pub const MODULE_ID: &str = "flux_rs";
/// Human-readable module name.
pub const MODULE_NAME: &str = "Flux-rs";
/// Module author, as it should appear in `module.prop`.
pub const MODULE_AUTHOR: &str = "Flux-rs contributors";
/// One-line description that does not overstate fail-open (blueprint §13.1).
pub const MODULE_DESCRIPTION: &str =
    "Transparent per-app proxying via eBPF and an unmodified official sing-box.";

/// Derives a monotonic `versionCode` from a SemVer triple.
///
/// The encoding reserves three decimal digits each for minor and patch, which
/// is why both are capped below (blueprint §13.4).
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

/// The git-tag form of a version, e.g. `v0.9.0` (blueprint §1.1, §13.4).
pub fn version_tag(version: &str) -> String {
    format!("v{version}")
}

/// The release artifact name, e.g. `Flux-rs-v0.9.0-arm64.zip` (blueprint §13.4).
pub fn artifact_name(version: &str) -> String {
    format!("{MODULE_NAME}-{}-arm64.zip", version_tag(version))
}

/// Renders `module.prop` for a version (blueprint §13.1, §13.4).
///
/// LF line endings, one trailing newline, and no `updateJson` for 0.9.0. The id
/// matches `^[a-zA-Z][a-zA-Z0-9._-]+$` as the Magisk parser requires
/// (blueprint §13.2.0).
pub fn module_prop(version: &str) -> Option<String> {
    let (major, minor, patch) = parse_triple(version)?;
    let code = version_code(major, minor, patch)?;
    Some(format!(
        "id={MODULE_ID}\n\
         name={MODULE_NAME}\n\
         version={tag}\n\
         versionCode={code}\n\
         author={MODULE_AUTHOR}\n\
         description={MODULE_DESCRIPTION}\n",
        tag = version_tag(version),
    ))
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

    // Blueprint §15.2 test 8: SemVer -> versionCode / module.prop / artifact
    // name.

    #[test]
    fn artifact_name_matches_the_blueprint() {
        assert_eq!(artifact_name("0.9.0"), "Flux-rs-v0.9.0-arm64.zip");
        assert_eq!(artifact_name(crate::VERSION), "Flux-rs-v0.9.0-arm64.zip");
    }

    #[test]
    fn module_prop_is_derived_and_well_formed() {
        let prop = module_prop("0.9.0").expect("valid version");
        assert_eq!(
            prop,
            "id=flux_rs\n\
             name=Flux-rs\n\
             version=v0.9.0\n\
             versionCode=9000\n\
             author=Flux-rs contributors\n\
             description=Transparent per-app proxying via eBPF and an unmodified official sing-box.\n"
        );
        // LF only, exactly one trailing newline, id matches the Magisk pattern.
        assert!(!prop.contains('\r'));
        assert!(prop.ends_with('\n') && !prop.ends_with("\n\n"));
        assert!(prop.contains("id=flux_rs"));
        // 0.9.0 ships no updateJson (blueprint §13.1).
        assert!(!prop.contains("updateJson"));
    }

    #[test]
    fn module_prop_rejects_unrepresentable_versions() {
        assert_eq!(module_prop("0.9.0-rc1"), None);
        assert_eq!(module_prop("0.1000.0"), None);
    }
}
