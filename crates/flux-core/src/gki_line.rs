//! Map `uname -r` to one GKI generation and pick the matching `fluxrs-*.ko`.
//!
//! The matching rule is the same as `clone/Re-Kernel/template/customize.sh`:
//! take the `X.Y` series from the release string, take an explicit `-androidN-`
//! if present, otherwise map the series onto the GKI Android number. Admission
//! is still `finit_module` succeeding, not this string (`docs/plan/rc4.md` §4.1).

use std::fmt;

/// One Android GKI generation, e.g. `android13-5.15`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GkiLine {
    android: u32,
    kernel_major: u32,
    kernel_minor: u32,
}

impl GkiLine {
    /// Android GKI generation number (`13` in `android13-5.15`).
    pub fn android(self) -> u32 {
        self.android
    }

    /// Kernel series major (`5` in `android13-5.15`).
    pub fn kernel_major(self) -> u32 {
        self.kernel_major
    }

    /// Kernel series minor (`15` in `android13-5.15`).
    pub fn kernel_minor(self) -> u32 {
        self.kernel_minor
    }

    /// `androidN-X.Y`, the token Re-Kernel uses as `TARGET_VER`.
    pub fn name(self) -> String {
        format!(
            "android{}-{}.{}",
            self.android, self.kernel_major, self.kernel_minor
        )
    }

    /// Prefix of the shipped module file, without a trailing suffix or `.ko`.
    pub fn module_stem(self) -> String {
        format!("fluxrs-{}", self.name())
    }

    /// Whether `filename` is a module built for this generation.
    ///
    /// Accepts `fluxrs-android13-5.15.ko` and `fluxrs-android13-5.15-<build>.ko`.
    /// Rejects a longer series token (`fluxrs-android13-5.150.ko`).
    pub fn matches_module_file(self, filename: &str) -> bool {
        let stem = self.module_stem();
        let rest = match filename.strip_prefix(&stem) {
            Some(rest) => rest,
            None => return false,
        };
        let body = match rest.strip_suffix(".ko") {
            Some(body) => body,
            None => return false,
        };
        body.is_empty() || body.starts_with('-')
    }
}

impl fmt::Display for GkiLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

/// Maps a `uname -r` release string to a GKI generation.
///
/// Returns `None` when the series is not one of the GKI lines Flux ships.
pub fn from_uname_release(release: &str) -> Option<GkiLine> {
    let release = release.trim();
    if release.is_empty() {
        return None;
    }
    let series = release.split('-').next()?;
    let (kernel_major, kernel_minor) = parse_series(series)?;
    let android = match android_from_release(release) {
        Some(n) => n,
        None => android_for_series(kernel_major, kernel_minor)?,
    };
    Some(GkiLine {
        android,
        kernel_major,
        kernel_minor,
    })
}

/// Picks one shipped `.ko` for `line` from a directory listing.
///
/// Prefers the unsuffixed `fluxrs-androidN-X.Y.ko`. If only suffixed builds
/// exist, the lexicographically first match wins so the choice is stable.
pub fn pick_module_file<'a>(
    line: GkiLine,
    names: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let exact = line.module_stem() + ".ko";
    let mut fallback: Option<&'a str> = None;
    for name in names {
        if !line.matches_module_file(name) {
            continue;
        }
        if name == exact {
            return Some(name);
        }
        match fallback {
            None => fallback = Some(name),
            Some(current) if name < current => fallback = Some(name),
            Some(_) => {}
        }
    }
    fallback
}

fn parse_series(series: &str) -> Option<(u32, u32)> {
    let mut parts = series.split('.');
    let major = parse_component(parts.next()?)?;
    let minor = parse_component(parts.next()?)?;
    Some((major, minor))
}

fn parse_component(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn android_from_release(release: &str) -> Option<u32> {
    let after = release.split_once("-android")?.1;
    let token = after.split('-').next()?;
    parse_component(token)
}

fn android_for_series(major: u32, minor: u32) -> Option<u32> {
    match (major, minor) {
        (5, 10) => Some(12),
        (5, 15) => Some(13),
        (6, 1) => Some(14),
        (6, 6) => Some(15),
        (6, 12) => Some(16),
        (6, 18) => Some(17),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qkernel_without_android_token_maps_to_android13_5_15() {
        let line = from_uname_release("5.15.211-Qkernel-g7a72da9438").unwrap();
        assert_eq!(line.name(), "android13-5.15");
        assert_eq!(line.module_stem(), "fluxrs-android13-5.15");
    }

    #[test]
    fn explicit_android_token_wins_over_the_series_default() {
        let line = from_uname_release("5.15.137-android14-11").unwrap();
        assert_eq!(line.name(), "android14-5.15");
    }

    #[test]
    fn android13_token_on_5_15_stays_android13() {
        let line = from_uname_release("5.15.137-android13-9").unwrap();
        assert_eq!(line.name(), "android13-5.15");
    }

    #[test]
    fn six_one_without_token_maps_to_android14() {
        let line = from_uname_release("6.1.75-something").unwrap();
        assert_eq!(line.name(), "android14-6.1");
    }

    #[test]
    fn unknown_series_is_none() {
        assert!(from_uname_release("5.4.233-something").is_none());
        assert!(from_uname_release("").is_none());
        assert!(from_uname_release("not-a-release").is_none());
    }

    #[test]
    fn module_file_match_rejects_a_longer_series_token() {
        let line = from_uname_release("5.15.211-Qkernel").unwrap();
        assert!(line.matches_module_file("fluxrs-android13-5.15.ko"));
        assert!(line.matches_module_file("fluxrs-android13-5.15-gabc.ko"));
        assert!(!line.matches_module_file("fluxrs-android13-5.150.ko"));
        assert!(!line.matches_module_file("fluxrs-android13-5.15.ko.bak"));
        assert!(!line.matches_module_file("rekernel-android13-5.15.ko"));
    }

    #[test]
    fn pick_prefers_the_unsuffixed_name() {
        let line = from_uname_release("5.15.0").unwrap();
        let names = [
            "fluxrs-android13-5.15-gabc.ko",
            "fluxrs-android13-5.15.ko",
            "fluxrs-android14-6.1.ko",
        ];
        assert_eq!(
            pick_module_file(line, names),
            Some("fluxrs-android13-5.15.ko")
        );
    }

    #[test]
    fn pick_is_stable_when_only_suffixed_builds_exist() {
        let line = from_uname_release("5.15.0").unwrap();
        let names = ["fluxrs-android13-5.15-z.ko", "fluxrs-android13-5.15-a.ko"];
        assert_eq!(
            pick_module_file(line, names),
            Some("fluxrs-android13-5.15-a.ko")
        );
    }
}
