//! Destructive Phase 3 device test.
//!
//! Blast radius: creates only the reserved flxrs0/flxrs1 veth pair, its peer
//! clsact, RPDB priority 100 and table 20260 routes. It writes only per-peer
//! sysctls. The cleanup guard removes those exact-owned objects on success,
//! panic and ordinary process exit. Run only on an authorized rooted device
//! with `FLUX_PHASE3_DEVICE_TEST=1`.

// This executable imports the product modules by path so the exact production
// encoder is exercised on Android; unrelated binary-only entry points are
// intentionally unused in this test crate.
#![allow(dead_code, unused_imports)]

#[path = "../src/bpf/mod.rs"]
mod bpf;
#[path = "../src/dataplane.rs"]
mod dataplane;
#[path = "../src/netlink/mod.rs"]
mod netlink;

use std::process;

const HOST_ALIAS: &str = "flux-rs:managed:v1:host";
const PEER_ALIAS: &str = "flux-rs:managed:v1:peer";

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
    assert!(status.topology_ready, "topology did not become ready");
    assert_eq!(status.sysctl.get("all.rp_filter"), Some(&0));
    assert_eq!(status.sysctl.get("flxrs1.rp_filter"), Some(&0));
    assert_eq!(status.sysctl.get("flxrs1.accept_local"), Some(&1));
    assert!(
        !status.ifaces.is_empty(),
        "device must expose at least one upstream candidate"
    );
    assert!(
        status.ifaces.iter().any(|iface| iface.status == "admitted"),
        "no physical upstream was admitted: {:?}",
        status.ifaces
    );
    for iface in &status.ifaces {
        match iface.status.as_str() {
            "admitted" => {
                assert!(
                    iface.entry.is_some(),
                    "admitted interface lacks entry: {iface:?}"
                );
                assert_eq!(iface.first_applicable, Some(true), "{iface:?}");
            }
            "excluded" => {
                assert!(
                    iface.reason.is_some(),
                    "excluded interface lacks reason: {iface:?}"
                );
            }
            other => panic!("unknown interface status {other}: {iface:?}"),
        }
    }
}

fn assert_complete() {
    let mut route = netlink::RouteNetlink::open().expect("open validation socket");
    let snapshot = route.snapshot().expect("dump validation snapshot");
    let host = snapshot
        .links
        .iter()
        .find(|link| link.name == "flxrs0")
        .expect("flxrs0 exists");
    let peer = snapshot
        .links
        .iter()
        .find(|link| link.name == "flxrs1")
        .expect("flxrs1 exists");
    assert_eq!(host.alias.as_deref(), Some(HOST_ALIAS));
    assert_eq!(peer.alias.as_deref(), Some(PEER_ALIAS));
    assert_eq!(host.peer_ifindex, Some(peer.ifindex));
    assert_eq!(peer.peer_ifindex, Some(host.ifindex));
    assert_eq!(host.mtu, 65_535);
    assert_eq!(peer.mtu, 65_535);
    assert!(snapshot.rules.iter().any(|rule| {
        rule.family as i32 == libc::AF_INET
            && rule.priority == Some(100)
            && rule.table == 20_260
            && rule.iif_name.as_deref() == Some("flxrs1")
    }));
    assert!(snapshot.rules.iter().any(|rule| {
        rule.family as i32 == libc::AF_INET6
            && rule.priority == Some(100)
            && rule.table == 20_260
            && rule.iif_name.as_deref() == Some("flxrs1")
    }));
    assert!(snapshot
        .routes
        .iter()
        .any(|route| route.family as i32 == libc::AF_INET
            && route.table == 20_260
            && route.protocol == 202));
    assert!(snapshot
        .routes
        .iter()
        .any(|route| route.family as i32 == libc::AF_INET6
            && route.table == 20_260
            && route.protocol == 202));
    assert!(snapshot.qdiscs.iter().any(|qdisc| {
        qdisc.ifindex == peer.ifindex
            && qdisc.kind.as_deref() == Some("clsact")
            && qdisc.handle == netlink::TC_CLSACT_HANDLE
    }));
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
}
