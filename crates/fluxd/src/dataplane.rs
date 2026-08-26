//! Phase 3 network-object ownership and interface admission.
//!
//! This module coordinates typed rtnetlink operations. It does not construct
//! raw messages and it does not load BPF programs; loading is Phase 4 and
//! attaching a live generation is Phase 5. See blueprint §8 and §17.6.

#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "dataplane/platform.rs"]
mod platform;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::Manager;
