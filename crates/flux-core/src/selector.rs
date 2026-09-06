//! App selector resolution: `"userId:packageName"` -> Android UID.
//!
//! Implements blueprint §1.1, §11.3 and D8/D9. Reads nothing itself; the caller
//! hands in the contents of `/data/system/packages.list`.
//!
//! Two rules that are structural, not stylistic:
//!
//! * `appId` 0 is never accepted. The engine runs as root, so refusing uid 0 is
//!   what guarantees it can never appear in `uid_policy`, and therefore that no
//!   self-exclusion logic is needed anywhere (blueprint §2.3, D9). Every other
//!   uid `packages.list` names is the user's to select, including a system one;
//!   blacklist mode still expands only `[APP_ID_MIN, APP_ID_MAX]`, so a system
//!   uid can only ever enter by being written down (§1.4).
//! * Resolution never goes through binder. `cmd package` would introduce a
//!   `system_server` readiness dependency at boot; a plain file read plus
//!   inotify does not (blueprint D8).
//!
//! Blueprint §15.2 test 1 lives at the bottom: `userId:package` canonical
//! parse, uid 0 rejection, shared-UID listing, and the hard cap.

use std::collections::BTreeMap;

use crate::abi::{APP_ID_MAX, APP_ID_MIN, USER_ID_MAX, USER_ID_STRIDE};

/// Why a selector could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorError {
    /// The selector was not `userId:packageName` or `packageName`.
    Malformed(String),
    /// `userId` was above [`USER_ID_MAX`].
    UserIdOutOfRange(u32),
    /// `appId` was 0 — the engine's own uid — or would not fit one user's
    /// stride, so the composed UID would belong to another user.
    AppIdOutOfRange(u32),
    /// The package was absent from `packages.list`.
    UnknownPackage(String),
}
/// A resolved selection: one Android UID plus the inputs that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Android user id, 0 for the primary user.
    pub user_id: u32,
    /// Package name as written in `packages.list`.
    pub package: String,
    /// `user_id * USER_ID_STRIDE + app_id`.
    pub uid: u32,
}

/// A parsed selector before it is resolved against `packages.list`.
///
/// Canonical form is `userId:packageName`; a bare `packageName` means user 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSelector {
    /// Android user id, 0 for the primary user.
    pub user_id: u32,
    /// Package name, exactly as written.
    pub package: String,
}

impl AppSelector {
    /// Parses `"userId:packageName"` or a bare `"packageName"` (user 0).
    ///
    /// The user id is validated here because it needs no package database; the
    /// app id cannot be, since it comes from `packages.list`.
    pub fn parse(text: &str) -> Result<Self, SelectorError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(SelectorError::Malformed(text.to_string()));
        }
        let (user_id, package) = match trimmed.split_once(':') {
            Some((user, package)) => {
                let user_id: u32 = user
                    .parse()
                    .map_err(|_| SelectorError::Malformed(text.to_string()))?;
                (user_id, package)
            }
            None => (0, trimmed),
        };
        if package.is_empty() || package.contains(':') {
            return Err(SelectorError::Malformed(text.to_string()));
        }
        if user_id > USER_ID_MAX {
            return Err(SelectorError::UserIdOutOfRange(user_id));
        }
        Ok(Self {
            user_id,
            package: package.to_string(),
        })
    }

    /// The canonical `userId:packageName` rendering, used for de-duplication.
    pub fn canonical(&self) -> String {
        format!("{}:{}", self.user_id, self.package)
    }
}

/// Composes an Android UID from a user id and an app id.
///
/// Refuses exactly two things: `appId` 0, because that is the engine's own uid
/// and admitting it is what would open the capture loop (§7.4); and an `appId`
/// at or beyond one user's stride, because the composed UID would then land in
/// a different user. A system uid such as 1000 or 2000 composes normally — the
/// caller warns about what selecting it means (§1.4).
pub fn compose_uid(user_id: u32, app_id: u32) -> Result<u32, SelectorError> {
    if user_id > USER_ID_MAX {
        return Err(SelectorError::UserIdOutOfRange(user_id));
    }
    if app_id == 0 || app_id >= USER_ID_STRIDE {
        return Err(SelectorError::AppIdOutOfRange(app_id));
    }
    Ok(user_id * USER_ID_STRIDE + app_id)
}

/// Whether an app id is outside the ordinary Android application range, and so
/// belongs to the platform rather than to an installed app.
pub fn is_system_app_id(app_id: u32) -> bool {
    !(APP_ID_MIN..=APP_ID_MAX).contains(&app_id)
}

/// Splits an Android UID back into `(user_id, app_id)`.
pub fn decompose_uid(uid: u32) -> (u32, u32) {
    (uid / USER_ID_STRIDE, uid % USER_ID_STRIDE)
}

/// A parsed view of `/data/system/packages.list` (blueprint §11.3).
///
/// Maps package name to app id and app id to the set of packages that share it.
/// Shared UIDs are common (a vendor's apps often share one), and selecting any
/// package in a shared UID captures all of them, so the sharing set must be
/// reported to the user.
#[derive(Debug, Clone, Default)]
pub struct PackageIndex {
    by_package: BTreeMap<String, u32>,
    by_app_id: BTreeMap<u32, Vec<String>>,
}

impl PackageIndex {
    /// Parses the package database.
    ///
    /// Infallible by design (blueprint §10.2): a line without a package name and
    /// a numeric uid in the first two whitespace-separated columns is skipped
    /// rather than failing the whole parse, so one stray line cannot lock the
    /// user out of every selection. The daemon decides what an empty index
    /// means; this function only reports what it could read.
    pub fn parse(text: &str) -> Self {
        let mut by_package = BTreeMap::new();
        let mut by_app_id: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(package) = fields.next() else {
                continue;
            };
            let Some(uid) = fields.next().and_then(|f| f.parse::<u32>().ok()) else {
                continue;
            };
            let app_id = uid % USER_ID_STRIDE;
            by_package.insert(package.to_string(), app_id);
            let bucket = by_app_id.entry(app_id).or_default();
            if !bucket.iter().any(|p| p == package) {
                bucket.push(package.to_string());
            }
        }
        for bucket in by_app_id.values_mut() {
            bucket.sort();
        }
        Self {
            by_package,
            by_app_id,
        }
    }

    /// The app id (user-0 uid) of a package, if present.
    pub fn app_id(&self, package: &str) -> Option<u32> {
        self.by_package.get(package).copied()
    }

    /// Every package that shares an app id, sorted. Empty if the id is unknown.
    pub fn shared_with(&self, app_id: u32) -> Vec<&str> {
        self.by_app_id
            .get(&app_id)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Every installed third-party application id, sorted and de-duplicated.
    ///
    /// Blacklist app mode expands this iterator into concrete UIDs, so it stays
    /// inside `[APP_ID_MIN, APP_ID_MAX]`: "proxy everything except these apps"
    /// must never sweep the platform's own uids in. A system uid enters the
    /// policy only by being written down in whitelist mode (§1.4, §11.2.1).
    pub fn application_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.by_app_id
            .keys()
            .copied()
            .filter(|app_id| (APP_ID_MIN..=APP_ID_MAX).contains(app_id))
    }

    /// Resolves a parsed selector to a concrete [`Selection`].
    ///
    /// Fails if the package is unknown or its app id is refused by
    /// [`compose_uid`]; a shared UID is not an error, it is surfaced by
    /// [`shared_with`].
    ///
    /// [`shared_with`]: PackageIndex::shared_with
    pub fn resolve(&self, selector: &AppSelector) -> Result<Selection, SelectorError> {
        let app_id = self
            .app_id(&selector.package)
            .ok_or_else(|| SelectorError::UnknownPackage(selector.package.clone()))?;
        let uid = compose_uid(selector.user_id, app_id)?;
        Ok(Selection {
            user_id: selector.user_id,
            package: selector.package.clone(),
            uid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_accepts_the_application_range() {
        assert_eq!(compose_uid(0, 10_000), Ok(10_000));
        assert_eq!(compose_uid(0, 19_999), Ok(19_999));
        assert_eq!(compose_uid(10, 10_123), Ok(1_010_123));
    }

    /// A system uid is the user's to select once they write it down; only uid 0
    /// and an app id that would cross into another user are refused (§1.4).
    #[test]
    fn compose_accepts_system_uids_but_never_root_or_a_foreign_user() {
        assert_eq!(compose_uid(0, 1000), Ok(1000));
        assert_eq!(compose_uid(0, 2000), Ok(2000));
        assert_eq!(compose_uid(0, 90_000), Ok(90_000));
        assert_eq!(compose_uid(10, 2000), Ok(1_002_000));

        assert_eq!(compose_uid(0, 0), Err(SelectorError::AppIdOutOfRange(0)));
        assert_eq!(
            compose_uid(0, USER_ID_STRIDE),
            Err(SelectorError::AppIdOutOfRange(USER_ID_STRIDE))
        );
    }

    #[test]
    fn system_app_ids_are_recognised_for_the_warning() {
        assert!(is_system_app_id(1000));
        assert!(is_system_app_id(2000));
        assert!(is_system_app_id(90_000));
        assert!(!is_system_app_id(10_000));
        assert!(!is_system_app_id(19_999));
    }

    #[test]
    fn compose_rejects_impossible_user_ids() {
        assert_eq!(
            compose_uid(1000, 10_000),
            Err(SelectorError::UserIdOutOfRange(1000))
        );
    }

    #[test]
    fn decompose_round_trips() {
        for (user, app) in [(0u32, 10_000u32), (0, 19_999), (10, 10_123), (999, 15_555)] {
            let uid = compose_uid(user, app).expect("in range");
            assert_eq!(decompose_uid(uid), (user, app));
        }
    }

    #[test]
    fn root_can_never_be_composed() {
        // The engine runs as uid 0. Blueprint §2.3 relies on this being
        // unrepresentable rather than filtered.
        for user in [0u32, 1, 999] {
            assert!(compose_uid(user, 0).is_err());
        }
    }

    // Blueprint §15.2 test 1: userId:package canonical parse, appId range
    // rejection, shared UID listing, hard limits.

    #[test]
    fn selector_parse_is_canonical() {
        assert_eq!(
            AppSelector::parse("0:com.example.browser").unwrap(),
            AppSelector {
                user_id: 0,
                package: "com.example.browser".to_string()
            }
        );
        // A bare package name means user 0.
        let bare = AppSelector::parse("com.example.app").unwrap();
        assert_eq!(bare.user_id, 0);
        assert_eq!(bare.canonical(), "0:com.example.app");
        // Whitespace is trimmed, so the canonical form is stable.
        assert_eq!(
            AppSelector::parse(" 10:com.x ").unwrap().canonical(),
            "10:com.x"
        );
    }

    #[test]
    fn selector_parse_rejects_garbage() {
        assert!(matches!(
            AppSelector::parse(""),
            Err(SelectorError::Malformed(_))
        ));
        assert!(matches!(
            AppSelector::parse("x:com.foo"),
            Err(SelectorError::Malformed(_))
        ));
        assert!(matches!(
            AppSelector::parse("0:"),
            Err(SelectorError::Malformed(_))
        ));
        assert_eq!(
            AppSelector::parse("1000:com.foo"),
            Err(SelectorError::UserIdOutOfRange(1000))
        );
    }

    const SAMPLE_PACKAGES: &str = "\
com.example.browser 10231 0 /data/user/0/com.example.browser default:targetSdkVersion=34 none 0
com.example.chat 10232 0 /data/user/0/com.example.chat default:targetSdkVersion=33 none 0
com.vendor.first 10500 0 /data/user/0/com.vendor.first default none 0
com.vendor.second 10500 0 /data/user/0/com.vendor.second default none 0
android 1000 0 /data/system default none 0
com.example.rootowned 0 0 /data/system default none 0
";

    #[test]
    fn package_index_resolves_and_lists_shared_uids() {
        let index = PackageIndex::parse(SAMPLE_PACKAGES);
        assert_eq!(index.app_id("com.example.browser"), Some(10_231));
        assert_eq!(
            index.application_ids().collect::<Vec<_>>(),
            vec![10_231, 10_232, 10_500]
        );

        let selection = index
            .resolve(&AppSelector::parse("0:com.example.browser").unwrap())
            .unwrap();
        assert_eq!(selection.uid, 10_231);

        // Both vendor packages share app id 10500.
        assert_eq!(
            index.shared_with(10_500),
            vec!["com.vendor.first", "com.vendor.second"]
        );
        // A non-shared id lists just itself.
        assert_eq!(index.shared_with(10_231), vec!["com.example.browser"]);
        // An unknown id lists nothing.
        assert!(index.shared_with(12_345).is_empty());
    }

    #[test]
    fn package_index_resolves_a_system_package_and_refuses_root_and_unknown() {
        let index = PackageIndex::parse(SAMPLE_PACKAGES);
        // `android` is uid 1000: selectable once written down, and flagged as a
        // system uid so the caller can warn (§1.4).
        let selection = index
            .resolve(&AppSelector::parse("0:android").unwrap())
            .expect("a system package resolves");
        assert_eq!(selection.uid, 1000);
        assert!(is_system_app_id(selection.uid));

        // Nothing running as root can be selected: that is the loop invariant.
        assert_eq!(
            index.resolve(&AppSelector::parse("0:com.example.rootowned").unwrap()),
            Err(SelectorError::AppIdOutOfRange(0))
        );
        assert_eq!(
            index.resolve(&AppSelector::parse("0:com.absent").unwrap()),
            Err(SelectorError::UnknownPackage("com.absent".to_string()))
        );
    }

    /// Blacklist mode must never sweep the platform in: `application_ids` stays
    /// inside the app range even though a system package is in the file.
    #[test]
    fn blacklist_expansion_excludes_system_uids() {
        let index = PackageIndex::parse(SAMPLE_PACKAGES);
        assert_eq!(
            index.application_ids().collect::<Vec<_>>(),
            vec![10_231, 10_232, 10_500]
        );
    }
}
