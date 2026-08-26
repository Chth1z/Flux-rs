//! The §9.4 generation transaction, end to end against a fake engine
//! (`harness = false`: this binary IS the fake engine when spawned with
//! sing-box argv, so no external helper and no new dependency).
//!
//! Scenarios, in order:
//!
//! 1. Cold start — the transaction closes: effective file written, check run,
//!    spawn, 4/4 sockets verified by pid+inode (§17.5 exit criterion 1).
//! 2. Q2 reproduced explicitly (§16.10.2, exit criterion 2): the four sockets
//!    found via sock_diag, each inode present in `/proc/<pid>/fd`.
//! 3. Hot switch — new generation promoted, old pid gone, old file deleted.
//! 4. Failed candidate — step 6 restarts the old generation from its
//!    untouched file; the candidate error is preserved.
//! 5. Graceful stop — SIGTERM path, effective file removed.
//! 6. Cold-start failure — a crashing engine yields `engine_exited`, no child.
//! 7. A live but never-ready candidate is terminated and cannot become orphaned.
//!
//! Requires a kernel with `udp_diag` (CI runners and devices have it; some
//! sandboxes do not — the run degrades to a skip with a loud note).

// The src modules are compiled into this test crate directly (fluxd is a
// binary crate, there is no library to link). Only part of their surface is
// exercised here, hence the dead_code allowance; unused_imports covers their
// embedded #[cfg(test)] modules, whose #[test] fns are stripped when built
// without the libtest harness while their imports remain.
#![allow(dead_code, unused_imports)]

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "../src/layout.rs"]
mod layout;

// The path attribute on the inline module re-anchors its children's base
// directory at the real src/netlink, so the child file resolves.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "../src/netlink"]
mod netlink {
    pub mod sock_diag;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "../src/engine.rs"]
mod engine;

#[path = "common/fake_engine.rs"]
mod fake_engine;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    println!("engine_lifecycle: skipped (Linux/Android-only)");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    fake_engine::maybe_run();
    tests::run_all();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::engine::{self, EngineChild, EngineError, EngineSpec};
    use crate::layout::Layout;
    use crate::netlink::sock_diag::{find_inode, pid_owns_inode, SocketExpectation};

    pub fn run_all() {
        if !udp_diag_supported() {
            println!(
                "engine_lifecycle: SKIPPED — this kernel has no udp_diag handler \
                 (sandbox?); CI runners and devices run the full scenario"
            );
            return;
        }

        let layout = temp_layout();
        let spec = EngineSpec {
            binary: std::env::current_exe().expect("own path"),
            workdir: layout.root().to_path_buf(),
            listen_v4: Ipv4Addr::LOCALHOST,
            listen_v6: Ipv6Addr::LOCALHOST,
        };
        let user = serde_json::json!({
            "outbounds": [ { "type": "direct", "tag": "direct" } ]
        });

        let child = cold_start_closes(&layout, &spec, &user);
        let child = q2_reproduced(&spec, child);
        let child = hot_switch_closes(&layout, &spec, &user, child);
        let child = failed_candidate_recovers_old_generation(&layout, &spec, &user, child);
        graceful_stop(&layout, child);
        cold_start_failure_reports_exit(&layout, &spec, &user);
        never_ready_candidate_is_reaped(&layout, &spec, &user);

        std::fs::remove_dir_all(layout.root()).expect("cleanup");
        println!("engine_lifecycle: all scenarios passed");
    }

    fn temp_layout() -> Layout {
        let mut dir = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        dir.push(format!("flux-lifecycle-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = Layout::at(dir);
        layout.ensure().expect("layout");
        layout
    }

    /// Whether this kernel can enumerate UDP sockets via sock_diag.
    fn udp_diag_supported() -> bool {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe");
        let exp = SocketExpectation {
            protocol: libc::IPPROTO_UDP as u8,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: probe.local_addr().unwrap().port(),
        };
        matches!(find_inode(&exp), Ok(Some(_)))
    }

    fn expectations(spec: &EngineSpec, child: &EngineChild) -> [SocketExpectation; 4] {
        [
            (
                libc::IPPROTO_TCP,
                IpAddr::V4(spec.listen_v4),
                child.params.port_v4,
            ),
            (
                libc::IPPROTO_UDP,
                IpAddr::V4(spec.listen_v4),
                child.params.port_v4,
            ),
            (
                libc::IPPROTO_TCP,
                IpAddr::V6(spec.listen_v6),
                child.params.port_v6,
            ),
            (
                libc::IPPROTO_UDP,
                IpAddr::V6(spec.listen_v6),
                child.params.port_v6,
            ),
        ]
        .map(|(protocol, addr, port)| SocketExpectation {
            protocol: protocol as u8,
            addr,
            port,
        })
    }

    fn cold_start_closes(
        layout: &Layout,
        spec: &EngineSpec,
        user: &serde_json::Value,
    ) -> EngineChild {
        let outcome = engine::run_generation_switch(layout, spec, user, None, 1);
        for line in &outcome.log {
            println!("  cold start: {line}");
        }
        outcome.result.expect("cold start must close");
        let child = outcome.engine.expect("engine running");
        assert_eq!(child.params.generation, 1);
        assert_eq!(child.sockets_verified, 4, "4/4 sockets verified");
        assert_eq!(child.effective, layout.effective_path(1));
        assert!(child.effective.exists(), "generation file exists");
        assert!(child.start_time > 0, "starttime read from /proc");
        println!("PASS cold start (pid {})", child.pid);
        child
    }

    /// §16.10.2 (Q2), reproduced as a product check rather than a lab
    /// measurement: all four sockets found by exact (family, protocol, addr,
    /// port), every inode present in `/proc/<pid>/fd`.
    fn q2_reproduced(spec: &EngineSpec, child: EngineChild) -> EngineChild {
        for exp in expectations(spec, &child) {
            let inode = find_inode(&exp)
                .expect("sock_diag dump")
                .unwrap_or_else(|| panic!("socket must exist: {exp:?}"));
            assert!(
                pid_owns_inode(child.pid, inode).expect("read /proc/<pid>/fd"),
                "inode {inode} must appear in /proc/{}/fd ({exp:?})",
                child.pid
            );
        }
        println!("PASS Q2: 4 sockets, inodes match /proc/{}/fd", child.pid);
        child
    }

    fn hot_switch_closes(
        layout: &Layout,
        spec: &EngineSpec,
        user: &serde_json::Value,
        old: EngineChild,
    ) -> EngineChild {
        let old_pid = old.pid;
        let old_path = old.effective.clone();
        let outcome = engine::run_generation_switch(layout, spec, user, Some(old), 2);
        for line in &outcome.log {
            println!("  hot switch: {line}");
        }
        outcome.result.expect("hot switch must close");
        let child = outcome.engine.expect("engine running");
        assert_eq!(child.params.generation, 2);
        assert_ne!(child.pid, old_pid, "a fresh candidate process");
        assert_eq!(child.sockets_verified, 4);
        assert!(
            !old_path.exists(),
            "old generation file deleted after commit"
        );
        assert!(child.effective.exists());
        assert!(
            engine::proc_start_time(old_pid).is_none(),
            "old engine (pid {old_pid}) must be gone"
        );
        println!("PASS hot switch (pid {old_pid} -> {})", child.pid);
        child
    }

    fn failed_candidate_recovers_old_generation(
        layout: &Layout,
        spec: &EngineSpec,
        user: &serde_json::Value,
        old: EngineChild,
    ) -> EngineChild {
        let old_generation = old.params.generation;
        let old_path = old.effective.clone();

        let flag = layout.root().join("fail-once.flag");
        std::fs::write(&flag, b"1").expect("flag");
        std::env::set_var("FLUX_FAKE_FAIL_ONCE", &flag);
        let outcome = engine::run_generation_switch(layout, spec, user, Some(old), 3);
        std::env::remove_var("FLUX_FAKE_FAIL_ONCE");
        for line in &outcome.log {
            println!("  recovery: {line}");
        }

        let err = outcome.result.expect_err("candidate must fail");
        assert!(
            matches!(err, EngineError::Exited { .. }),
            "candidate failure is engine_exited, got {}",
            err.token()
        );
        assert!(
            matches!(outcome.recovery, Some(Ok(()))),
            "step-6 recovery must succeed"
        );
        let child = outcome.engine.expect("old generation running again");
        assert_eq!(
            child.params.generation, old_generation,
            "recovered child runs the OLD generation"
        );
        assert_eq!(child.effective, old_path);
        assert!(old_path.exists(), "old generation file untouched (§9.4)");
        assert!(
            !layout.effective_path(3).exists(),
            "failed candidate's file removed"
        );
        assert_eq!(child.sockets_verified, 4);
        println!("PASS failed candidate recovered generation {old_generation}");
        child
    }

    fn graceful_stop(layout: &Layout, child: EngineChild) {
        let pid = child.pid;
        let effective = child.effective.clone();
        let exit = engine::stop_engine(&child).expect("graceful stop");
        assert_eq!(exit, "signal=15", "clean SIGTERM termination");
        assert!(!effective.exists(), "generation file removed on stop");
        assert!(engine::proc_start_time(pid).is_none(), "pid {pid} gone");
        let _ = layout;
        println!("PASS graceful stop (signal=15)");
    }

    fn cold_start_failure_reports_exit(
        layout: &Layout,
        spec: &EngineSpec,
        user: &serde_json::Value,
    ) {
        std::env::set_var("FLUX_FAKE_CRASH", "1");
        let outcome = engine::run_generation_switch(layout, spec, user, None, 4);
        std::env::remove_var("FLUX_FAKE_CRASH");
        let err = outcome.result.expect_err("crashing engine must fail");
        assert_eq!(err.token(), "engine_exited:code=7");
        assert!(
            err.detail()
                .is_some_and(|d| d.contains("crashing on request")),
            "captured output surfaces in the detail"
        );
        assert!(outcome.engine.is_none());
        assert!(
            !layout.effective_path(4).exists(),
            "failed candidate's file removed"
        );
        println!("PASS cold-start failure reported as engine_exited:code=7");
    }

    fn never_ready_candidate_is_reaped(
        layout: &Layout,
        spec: &EngineSpec,
        user: &serde_json::Value,
    ) {
        let pid_file = layout.root().join("never-ready.pid");
        std::env::set_var("FLUX_FAKE_NOT_READY", "1");
        std::env::set_var("FLUX_FAKE_PID_FILE", &pid_file);
        let outcome = engine::run_generation_switch(layout, spec, user, None, 5);
        std::env::remove_var("FLUX_FAKE_NOT_READY");
        std::env::remove_var("FLUX_FAKE_PID_FILE");

        assert!(matches!(outcome.result, Err(EngineError::NotReady { .. })));
        assert!(
            outcome.engine.is_none(),
            "unready child must not remain owned"
        );
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("fake engine wrote its pid")
            .parse()
            .expect("pid");
        assert!(
            engine::proc_start_time(pid).is_none(),
            "never-ready candidate pid {pid} must be terminated and reaped"
        );
        let _ = std::fs::remove_file(pid_file);
        println!("PASS never-ready candidate terminated (pid {pid})");
    }
}
