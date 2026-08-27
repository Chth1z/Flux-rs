//! Network-object ownership, interface admission and Phase 6 activation.
//!
//! This module coordinates typed rtnetlink operations. It does not construct
//! raw messages; the platform manager owns the BPF runtime and attachment
//! lifecycle. See blueprint §7-§8 and implementation plan §17.6-§17.9.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dataplane/platform.rs"]
mod platform;

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[allow(unused_imports)]
pub use platform::TestFilterSpec;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::{AttachmentProgress, DataplaneError, DesiredPolicy, Manager};
