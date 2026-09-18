//! Unique dataplane: LOCAL_OUT `fluxrs.ko`, leftover veth cleanup, Phase 6 arm.
//!
//! Capture is the GKI-line module (`kmod/`). This module still speaks typed
//! rtnetlink so a cold start can delete leftover `flxrs*` / pref-100 objects
//! from the previous dataplane. It does not construct raw netlink; it does not
//! create veth or attach physical TC. `attachment.rs` returns Complete once
//! the module is live.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dataplane/platform.rs"]
mod platform;

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[allow(unused_imports)]
pub use platform::TestFilterSpec;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::{AttachmentProgress, DataplaneError, DesiredPolicy, Manager};
