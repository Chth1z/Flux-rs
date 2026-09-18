//! Destructive Phase 3 device test.
//!
//! Blast radius: loads the GKI-line `fluxrs.ko` and holds `/dev/fluxrs`. It
//! still deletes leftover exact-owned `flxrs*` / pref-100 / table 20260 objects
//! from the previous dataplane. The cleanup guard unloads the module and
//! removes those leftovers on success, panic and ordinary process exit. Run
//! only on an authorized rooted device with `FLUX_PHASE3_DEVICE_TEST=1` and
//! `fluxrs-android13-5.15.ko` in `FLUX_KMOD_DIR` or `/data/adb/modules/Flux-rs/kmod`.

#![allow(dead_code, unused_imports)]

#[path = "../src/bpf/mod.rs"]
mod bpf;
#[path = "../src/dataplane.rs"]
mod dataplane;
#[path = "../src/kmod.rs"]
mod kmod;
#[path = "../src/netlink/mod.rs"]
mod netlink;

use std::process;

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(mut manager) = dataplane::Manager::open() {
            if let Err(error) = manager.cleanup_for_test() {
                eprintln!("phase3 cleanup failed: {error}");
            }
        }
    }
}

fn main() {
    if std::env::var_os("FLUX_PHASE3_DEVICE_TEST").is_none() {
        println!("phase3 device test: skipped (set FLUX_PHASE3_DEVICE_TEST=1)");
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("phase3 device test requires root");
        process::exit(77);
    }

    let _cleanup = Cleanup;
    let mut initial = dataplane::Manager::open().expect("open initial manager");
    initial
        .cleanup_for_test()
        .expect("clean exact-owned pre-test leftovers");
    assert_clean();

    // The child owns the first lifecycle and dies without running cleanup.
    // SAFETY: the process is single-threaded here; the child performs only
    // async-signal-independent Rust work before deliberately killing itself.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let mut manager = dataplane::Manager::open().expect("open child manager");
        manager.converge(true);
        assert_ready(&manager);
        assert_complete();
        // SAFETY: raise targets the current process with a valid signal.
        unsafe { libc::raise(libc::SIGKILL) };
        unreachable!();
    }

    let mut status = 0;
    // SAFETY: pid is the live child returned by fork and status is writable.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert_complete();

    // A fresh manager must identify, delete and deterministically recreate the
    // crash leftovers before reporting the Phase 3 seam ready.
    let mut recovered = dataplane::Manager::open().expect("open recovery manager");
    recovered.converge(true);
    assert_ready(&recovered);
    assert_complete();

    recovered
        .cleanup_for_test()
        .expect("remove exact-owned post-test objects");
    assert_clean();
    println!("phase3 device test: PASS (kill-9 recovery and exact cleanup)");
}

fn assert_ready(manager: &dataplane::Manager) {
    let status = manager.status();
    assert!(status.error.is_none(), "topology error: {:?}", status.error);
    assert!(
        status.topology_ready,
        "LOCAL_OUT module did not become ready"
    );
    assert!(status.bpf_ready, "LOCAL_OUT steal is not ready");
    assert!(
        std::path::Path::new("/dev/fluxrs").exists(),
        "/dev/fluxrs missing after converge"
    );
}

fn assert_complete() {
    let mut route = netlink::RouteNetlink::open().expect("open validation socket");
    let snapshot = route.snapshot().expect("dump validation snapshot");
    assert!(
        !snapshot
            .links
            .iter()
            .any(|link| link.name == "flxrs0" || link.name == "flxrs1"),
        "unique dataplane must not create flxrs*"
    );
    assert!(
        !snapshot.rules.iter().any(|rule| rule.priority == Some(100)),
        "unique dataplane must not install pref 100"
    );
    assert!(
        !snapshot.routes.iter().any(|route| route.table == 20_260),
        "unique dataplane must not install table 20260"
    );
    assert!(
        std::path::Path::new("/dev/fluxrs").exists(),
        "control node missing while module should be resident"
    );
}

fn assert_clean() {
    let mut route = netlink::RouteNetlink::open().expect("open clean validation socket");
    let snapshot = route.snapshot().expect("dump clean validation snapshot");
    assert!(!snapshot
        .links
        .iter()
        .any(|link| link.name == "flxrs0" || link.name == "flxrs1"));
    assert!(!snapshot.rules.iter().any(|rule| rule.priority == Some(100)));
    assert!(!snapshot.routes.iter().any(|route| route.table == 20_260));
    assert!(
        !std::path::Path::new("/dev/fluxrs").exists(),
        "control node remains after unload"
    );
}
