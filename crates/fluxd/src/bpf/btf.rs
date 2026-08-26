//! Loads the minimal SK_STORAGE BTF built by `flux-core`.

use std::io;
use std::os::fd::OwnedFd;

pub fn load() -> io::Result<OwnedFd> {
    super::sys::load_btf(&flux_core::btf::flux_decision_btf())
}
