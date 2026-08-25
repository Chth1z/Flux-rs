//! App selector resolution: `"userId:packageName"` -> Android UID.
//!
//! Implements blueprint §1.1 and D8/D9. Reads nothing itself; the caller hands
//! in the contents of `/data/system/packages.list`.
//!
//! Two rules that are structural, not stylistic:
//!
//! * Only `appId` in `[10000, 19999]` is accepted. This is what guarantees the
//!   root-owned engine (uid 0) can never appear in `uid_policy`, so no
//!   self-exclusion logic is needed anywhere (blueprint §2.3, D9).
//! * Resolution never goes through binder. `cmd package` would introduce a
//!   `system_server` readiness dependency at boot; a plain file read plus
//!   inotify does not (blueprint D8).
//!
//! Not implemented yet — Phase 1 (blueprint §17).

use crate::abi::{APP_ID_MAX, APP_ID_MIN, USER_ID_MAX, USER_ID_STRIDE};

/// Why a selector could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorError {
    /// The selector was not `userId:packageName` or `packageName`.
    Malformed,
    /// `userId` was above [`USER_ID_MAX`].
    UserIdOutOfRange(u32),
    /// `appId` was outside `[APP_ID_MIN, APP_ID_MAX]`.
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

/// Composes an Android UID from a user id and an app id.
///
/// Both bounds are checked, because accepting an out-of-range `appId` is how a
/// user would otherwise be able to select `system_server` and brick the device.
pub fn compose_uid(user_id: u32, app_id: u32) -> Result<u32, SelectorError> {
    if user_id > USER_ID_MAX {
        return Err(SelectorError::UserIdOutOfRange(user_id));
    }
    if !(APP_ID_MIN..=APP_ID_MAX).contains(&app_id) {
        return Err(SelectorError::AppIdOutOfRange(app_id));
    }
    Ok(user_id * USER_ID_STRIDE + app_id)
}

/// Splits an Android UID back into `(user_id, app_id)`.
pub fn decompose_uid(uid: u32) -> (u32, u32) {
    (uid / USER_ID_STRIDE, uid % USER_ID_STRIDE)
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

    #[test]
    fn compose_rejects_system_and_isolated_uids() {
        assert_eq!(compose_uid(0, 0), Err(SelectorError::AppIdOutOfRange(0)));
        assert_eq!(
            compose_uid(0, 1000),
            Err(SelectorError::AppIdOutOfRange(1000))
        );
        assert_eq!(
            compose_uid(0, 90_000),
            Err(SelectorError::AppIdOutOfRange(90_000))
        );
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
}
