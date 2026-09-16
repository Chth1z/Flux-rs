//! SemVer arithmetic and packaging metadata for the module.
//!
//! Implements blueprint §13.1 and §13.4. There is a single version source, the
//! workspace manifest; everything a release needs — `versionCode`, the
//! `module.prop` body, the artifact name — is derived from it here so no second
//! version file can drift out of sync (blueprint §15.4(3)).

/// The root module id and installation directory name (blueprint §13.1).
pub const MODULE_ID: &str = "Flux-rs";
/// Human-readable module name.
pub const MODULE_NAME: &str = "Flux-rs";
/// Module author, as it should appear in `module.prop`.
pub const MODULE_AUTHOR: &str = "Flux-rs contributors";
/// Base description, before the daemon appends its live status (§13.1).
pub const MODULE_DESCRIPTION: &str = "Seamlessly redirect your network Flux.";

/// Derives a monotonic `versionCode` from a SemVer triple.
///
/// Equivalent to the final-release code from [`Version::version_code`].
pub fn version_code(major: u32, minor: u32, patch: u32) -> Option<u32> {
    Version {
        major,
        minor,
        patch,
        release_candidate: None,
    }
    .version_code()
}

/// Canonical release version or release candidate supported by the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// Major release number.
    pub major: u32,
    /// Minor release number, at most 99.
    pub minor: u32,
    /// Patch release number, at most 99.
    pub patch: u32,
    /// Candidate sequence, 0 through 998; `None` denotes the final release.
    pub release_candidate: Option<u32>,
}

impl Version {
    /// Checked monotonic encoding, bounded by Android's signed 32-bit integer.
    ///
    /// `((major * 100 + minor) * 100 + patch) * 1000 + stage`, where candidate
    /// N has stage N and the final release has stage 999. The component bounds
    /// reserve disjoint ranges for every patch, minor and major. Major releases
    /// through 213 fit completely; 214 fits only up to the integer limit.
    /// The new 0.9.0 code 900999 exceeds its historical code 9000. VCS provenance
    /// never affects this ordering (blueprint §13.4).
    pub fn version_code(self) -> Option<u32> {
        if self.minor > 99 || self.patch > 99 || self.release_candidate.is_some_and(|n| n > 998) {
            return None;
        }
        let code = self
            .major
            .checked_mul(100)?
            .checked_add(self.minor)?
            .checked_mul(100)?
            .checked_add(self.patch)?
            .checked_mul(1000)?
            .checked_add(self.release_candidate.unwrap_or(999))?;
        (code <= i32::MAX as u32).then_some(code)
    }
}

fn canonical_number(text: &str) -> Option<u32> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

/// Parses canonical `major.minor.patch` or `major.minor.patch-rc.N`, rejecting
/// unknown prereleases, build metadata, leading zeros and unrepresentable codes.
pub fn parse_version(text: &str) -> Option<Version> {
    let (triple, release_candidate) = match text.split_once("-rc.") {
        Some((triple, candidate)) => (triple, Some(canonical_number(candidate)?)),
        None => (text, None),
    };
    let mut parts = triple.split('.');
    let version = Version {
        major: canonical_number(parts.next()?)?,
        minor: canonical_number(parts.next()?)?,
        patch: canonical_number(parts.next()?)?,
        release_candidate,
    };
    if parts.next().is_some() {
        return None;
    }
    version.version_code()?;
    Some(version)
}

/// Parses a canonical representable final-release triple, rejecting candidates.
pub fn parse_triple(text: &str) -> Option<(u32, u32, u32)> {
    let version = parse_version(text)?;
    version
        .release_candidate
        .is_none()
        .then_some((version.major, version.minor, version.patch))
}

/// The git-tag form of a version, e.g. `v0.9.0` (blueprint §1.1, §13.4).
pub fn version_tag(version: &str) -> String {
    format!("v{version}")
}

/// The release artifact name, e.g. `Flux-rs-v0.9.0-arm64.zip` (blueprint §13.4).
pub fn artifact_name(version: &str) -> String {
    format!("{MODULE_NAME}-{}-arm64.zip", version_tag(version))
}

/// Development artifact with an explicit hexadecimal VCS revision and dirty
/// marker. Callers should supply the full revision to avoid abbreviated-id
/// collisions; 7 through 64 lowercase hexadecimal digits are accepted.
pub fn development_artifact_name(version: &str, revision: &str, dirty: bool) -> Option<String> {
    parse_version(version)?;
    if !(7..=64).contains(&revision.len())
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let dirty = if dirty { "-dirty" } else { "" };
    Some(format!(
        "{MODULE_NAME}-{}-g{revision}{dirty}-arm64.zip",
        version_tag(version)
    ))
}

/// Renders `module.prop` for a version (blueprint §13.1, §13.4).
///
/// LF line endings, one trailing newline, and no `updateJson` for 0.9.0. The id
/// matches `^[a-zA-Z][a-zA-Z0-9._-]+$` as the Magisk parser requires
/// (blueprint §13.2.0).
pub fn module_prop(version: &str) -> Option<String> {
    let code = parse_version(version)?.version_code()?;
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

/// The two-character escape the root managers render as a line break inside
/// `description=`. It is a literal backslash followed by `n`, not a newline:
/// `module.prop` is strictly one key per physical line.
const DESCRIPTION_BREAK: &str = "\\n";

/// The base description with any previously appended status line removed.
///
/// The daemon rewrites `description=` on every state change, so this has to be
/// idempotent: appending to an already-appended value would grow the line
/// without bound.
pub fn description_base(prop: &str) -> Option<&str> {
    let line = prop
        .lines()
        .find_map(|line| line.strip_prefix("description="))?;
    let base = match line.find(DESCRIPTION_BREAK) {
        Some(at) => &line[..at],
        None => line,
    };
    Some(base.trim())
}

/// Rewrites `description=` so the manager list doubles as a live status
/// readout, preserving every other key and the file's line order.
///
/// A missing `description=` is appended rather than treated as an error: the
/// file still belongs to the manager, and refusing to report status because one
/// key was edited away would be worse than reporting it.
pub fn module_prop_with_status(prop: &str, status: &str) -> String {
    let base = description_base(prop).unwrap_or(MODULE_DESCRIPTION);
    let base = if base.is_empty() {
        MODULE_DESCRIPTION
    } else {
        base
    };
    let rendered = format!("description={base}{DESCRIPTION_BREAK}{status}");

    let mut out = String::with_capacity(prop.len() + status.len() + 16);
    let mut replaced = false;
    for line in prop.lines() {
        if line.starts_with("description=") && !replaced {
            out.push_str(&rendered);
            replaced = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !replaced {
        out.push_str(&rendered);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_version_parses_and_encodes() {
        let version = parse_version(crate::VERSION).expect("workspace version");
        assert!(version.version_code().unwrap() > 9_000);
        assert!(module_prop(crate::VERSION).is_some());
    }

    #[test]
    fn version_code_is_monotonic_across_components() {
        assert!(version_code(0, 9, 0) < version_code(0, 9, 1));
        assert!(version_code(0, 9, 99) < version_code(0, 10, 0));
        assert!(version_code(0, 99, 99) < version_code(1, 0, 0));
        let ordered = [
            "0.9.0-rc.0",
            "0.9.0-rc.1",
            "0.9.0-rc.998",
            "0.9.0",
            "0.9.1-rc.0",
            "0.9.99",
            "0.10.0-rc.0",
            "0.99.99",
            "1.0.0-rc.0",
            "1.0.0",
        ];
        let codes: Vec<_> = ordered
            .iter()
            .map(|text| parse_version(text).unwrap().version_code().unwrap())
            .collect();
        assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(codes[0] > 9_000);
    }

    #[test]
    fn version_code_rejects_unrepresentable_components() {
        assert_eq!(version_code(0, 1000, 0), None);
        assert_eq!(version_code(0, 0, 1000), None);
        assert_eq!(version_code(u32::MAX, 0, 0), None);
        assert_eq!(version_code(215, 0, 0), None);
        assert_eq!(version_code(214, 74, 82), Some(2_147_482_999));
        assert_eq!(version_code(214, 74, 83), None);
        assert_eq!(
            parse_version("214.74.83-rc.647").unwrap().version_code(),
            Some(i32::MAX as u32)
        );
        assert_eq!(parse_version("214.74.83-rc.648"), None);
    }

    #[test]
    fn parse_rejects_prerelease_and_extra_components() {
        assert_eq!(parse_triple("0.9.0-rc1"), None);
        assert_eq!(parse_triple("0.9.0.1"), None);
        assert_eq!(parse_triple("0.9"), None);
        for bad in [
            "",
            " 0.9.0",
            "+0.9.0",
            "00.9.0",
            "0.09.0",
            "0.9.00",
            "0.9.0\n",
            "0.9.0+build",
            "0.9.0-rc.",
            "0.9.0-rc.01",
            "0.9.0-rc.+1",
            "0.9.0-rc.999",
            "0.9.0-rc.1-rc.2",
            "999999999999.0.0",
        ] {
            assert!(parse_version(bad).is_none(), "accepted {bad:?}");
        }
    }

    // Blueprint §15.2 test 8: SemVer -> versionCode / module.prop / artifact
    // name.

    #[test]
    fn artifact_name_matches_the_blueprint() {
        assert_eq!(artifact_name("0.9.0"), "Flux-rs-v0.9.0-arm64.zip");
        assert_eq!(
            artifact_name(crate::VERSION),
            format!("Flux-rs-v{}-arm64.zip", crate::VERSION)
        );
        assert_eq!(
            development_artifact_name("1.0.0-rc.2", "abcdef0", true).as_deref(),
            Some("Flux-rs-v1.0.0-rc.2-gabcdef0-dirty-arm64.zip")
        );
        assert_ne!(
            development_artifact_name("1.0.0", "abcdef0", false),
            development_artifact_name("1.0.0", "abcdef1", false)
        );
        for bad in ["", "abc", "../abcdef", "abcdefg", "ABCDEF0", "abcdef0\n"] {
            assert_eq!(development_artifact_name("1.0.0", bad, false), None);
        }
        assert_eq!(development_artifact_name("bad", "abcdef0", false), None);
    }

    #[test]
    fn module_prop_is_derived_and_well_formed() {
        let prop = module_prop("0.9.0").expect("valid version");
        assert_eq!(
            prop,
            "id=Flux-rs\n\
             name=Flux-rs\n\
             version=v0.9.0\n\
             versionCode=900999\n\
             author=Flux-rs contributors\n\
             description=Seamlessly redirect your network Flux.\n"
        );
        // LF only, exactly one trailing newline, id matches the Magisk pattern.
        assert!(!prop.contains('\r'));
        assert!(prop.ends_with('\n') && !prop.ends_with("\n\n"));
        assert!(prop.contains("id=Flux-rs"));
        // 0.9.0 ships no updateJson (blueprint §13.1).
        assert!(!prop.contains("updateJson"));
    }

    #[test]
    fn module_prop_rejects_unrepresentable_versions() {
        assert_eq!(module_prop("0.9.0-rc1"), None);
        assert_eq!(module_prop("0.1000.0"), None);
        assert!(module_prop("1.0.0-rc.1")
            .unwrap()
            .contains("versionCode=10000001\n"));
    }

    #[test]
    fn status_rewrite_preserves_every_other_key_and_order() {
        let prop = module_prop("0.9.0").expect("valid version");
        let out = module_prop_with_status(&prop, "[Active] gen 7");
        let keys: Vec<&str> = out
            .lines()
            .map(|line| line.split('=').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "id",
                "name",
                "version",
                "versionCode",
                "author",
                "description"
            ]
        );
        assert!(out.contains("description=Seamlessly redirect your network Flux.\\n[Active] gen 7"));
        assert!(!out.contains('\r'));
        assert!(out.ends_with('\n') && !out.ends_with("\n\n"));
    }

    #[test]
    fn status_rewrite_is_idempotent_and_does_not_accumulate() {
        let prop = module_prop("0.9.0").expect("valid version");
        let once = module_prop_with_status(&prop, "[Active] gen 7");
        let twice = module_prop_with_status(&once, "[Disabled]");
        let thrice = module_prop_with_status(&twice, "[Disabled]");
        assert_eq!(twice, thrice);
        assert_eq!(twice.matches("\\n").count(), 1);
        assert_eq!(
            description_base(&thrice),
            Some(MODULE_DESCRIPTION),
            "the base description must survive repeated rewrites"
        );
    }

    #[test]
    fn status_rewrite_recovers_from_a_missing_or_empty_description() {
        let out = module_prop_with_status("id=flux_rs\nversion=v0.9.0\n", "[Inactive]");
        assert!(out.starts_with("id=flux_rs\nversion=v0.9.0\n"));
        assert!(out.ends_with(&format!("description={MODULE_DESCRIPTION}\\n[Inactive]\n")));

        let blank = module_prop_with_status("description=\n", "[Inactive]");
        assert_eq!(
            blank,
            format!("description={MODULE_DESCRIPTION}\\n[Inactive]\n")
        );
    }

    #[test]
    fn description_base_strips_only_the_status_suffix() {
        assert_eq!(description_base("description=A B\\n[Active]"), Some("A B"));
        assert_eq!(description_base("description=  A B  "), Some("A B"));
        assert_eq!(description_base("name=x\n"), None);
    }
}
