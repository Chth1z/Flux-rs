//! Reads `/data/system/packages.list` and feeds
//! [`flux_core::selector`].
//!
//! Implements blueprint D8. Deliberately a plain file read plus inotify: going
//! through binder (`cmd package`) would make activation depend on
//! `system_server` readiness during late boot.
//!
//! Not implemented yet — Phase 3 (blueprint §17).

/// Source of truth for package-to-UID mapping.
pub const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";
