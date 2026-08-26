//! Root-only Phase 5 acceptance test for an authorized Android device.
//!
//! The L2 loop and Q5.6 sysctl matrix run in a disposable network namespace.
//! The root namespace test attaches only exact-owned Flux filters, selects
//! uid 0 for a bounded UDP probe, proves the RAWIP loop, publishes inactive,
//! and deliberately dies so a fresh manager can verify crash cleanup.

#![allow(dead_code, unused_imports)]

#[path = "../src/bpf/mod.rs"]
mod bpf;
#[path = "../src/dataplane.rs"]
mod dataplane;
#[path = "../src/netlink/mod.rs"]
mod netlink;

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::process;
use std::time::Duration;

use flux_core::abi::{self, Counter};

const BPF_OBJECT: &[u8] = include_bytes!(env!("FLUX_BPF_OBJECT"));
const TEST_TX: &str = "flxq5tx";
const TEST_RX: &str = "flxq5rx";
const IP_TRANSPARENT: libc::c_int = 19;

struct HostCleanup;

impl Drop for HostCleanup {
    fn drop(&mut self) {
        if let Ok(mut manager) = dataplane::Manager::open() {
            if let Err(error) = manager.cleanup_for_test() {
                eprintln!("phase5 host cleanup failed: {error}");
            }
        }
    }
}

fn main() {
    if std::env::var_os("FLUX_PHASE5_DEVICE_TEST").is_none() {
        println!("phase5 device test: skipped (set FLUX_PHASE5_DEVICE_TEST=1)");
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("phase5 device test requires root");
        process::exit(77);
    }

    let global_before = global_sysctls();
    run_isolated_child();

    let _cleanup = HostCleanup;
    let mut initial = dataplane::Manager::open().expect("open initial manager");
    initial
        .cleanup_for_test()
        .expect("clean exact-owned pre-test leftovers");
    drop(initial);
    assert_host_clean();

    // The child leaves TC programs referenced by the qdiscs, just like a
    // daemon crash. SIGKILL is raised only after every RAWIP assertion passed.
    // SAFETY: the test process is single-threaded at this point.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
    if pid == 0 {
        run_host_rawip();
        // SAFETY: raise targets this process with a valid signal.
        unsafe { libc::raise(libc::SIGKILL) };
        unreachable!();
    }
    assert_killed_child(pid);
    assert_host_has_flux_filters();

    let mut recovered = dataplane::Manager::open().expect("open recovery manager");
    recovered.converge_with_bpf(true, BPF_OBJECT);
    assert!(
        recovered.status().error.is_none(),
        "Phase 5 crash recovery failed: {:?}",
        recovered.status().error
    );
    recovered
        .cleanup_for_test()
        .expect("remove recovered Phase 5 objects");
    assert_host_clean();
    assert_eq!(global_sysctls(), global_before, "global sysctls changed");

    println!(
        "phase5 device test: PASS (Q5.1 L2 loop, Q5.2 RAWIP loop, Q5.6 isolated matrix, Q5.7 continuation, crash cleanup)"
    );
}

fn run_isolated_child() {
    let root_netns = fs::metadata("/proc/self/ns/net")
        .expect("stat root netns")
        .ino();
    // SAFETY: the process is single-threaded; the child immediately moves
    // into a disposable network namespace and exits after the test.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
    if pid == 0 {
        // SAFETY: CLONE_NEWNET creates a private network namespace for this
        // child. No interface is moved out of the owner's root namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            eprintln!(
                "unshare(CLONE_NEWNET) failed: {}",
                io::Error::last_os_error()
            );
            process::exit(1);
        }
        let isolated_netns = fs::metadata("/proc/self/ns/net")
            .expect("stat isolated netns")
            .ino();
        assert_ne!(
            isolated_netns, root_netns,
            "CLONE_NEWNET did not leave the root network namespace"
        );
        run_l2_and_sysctl_matrix();
        process::exit(0);
    }
    let mut status = 0;
    // SAFETY: pid is the live child returned by fork and status is writable.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "isolated L2 child failed with wait status {status}"
    );
}

fn run_l2_and_sysctl_matrix() {
    write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", 0);
    let mut route = netlink::RouteNetlink::open().expect("open isolated route socket");
    let lo = netlink::RouteNetlink::if_nametoindex("lo").expect("isolated lo");
    route.set_link_up(lo).expect("bring isolated lo up");

    let (listener, port) = transparent_listener();
    let mut manager = dataplane::Manager::open().expect("open isolated manager");
    manager.converge_with_bpf(true, BPF_OBJECT);
    assert!(
        manager.status().error.is_none(),
        "isolated topology failed: {:?}",
        manager.status().error
    );
    manager
        .prepare_generation(51, port, port)
        .expect("publish isolated inactive generation");
    assert_eq!(
        manager.begin_attachment().expect("attach isolated ingress"),
        dataplane::AttachmentProgress::Complete
    );

    route
        .create_veth(TEST_TX, TEST_RX, 1500)
        .expect("create isolated test veth");
    let tx = netlink::RouteNetlink::if_nametoindex(TEST_TX).expect("test tx ifindex");
    let rx = netlink::RouteNetlink::if_nametoindex(TEST_RX).expect("test rx ifindex");
    route.set_link_up(tx).expect("bring test tx up");
    route.set_link_up(rx).expect("bring test rx up");
    route
        .add_ipv4_address(tx, [203, 0, 113, 1], 24)
        .expect("assign controlled sender address");
    let rx_mac = route
        .dump_links()
        .expect("dump controlled veth")
        .into_iter()
        .find(|link| link.ifindex == rx)
        .expect("controlled receiver link")
        .address;
    route
        .add_ipv4_neighbor(tx, [203, 0, 113, 2], &rx_mac)
        .expect("install controlled permanent neighbor");
    route.create_clsact(tx).expect("create test clsact");

    // Q5.7: the same UNSPEC probe at P and P+1 must execute twice for every
    // packet. This proves continuation without relying on tc statistics.
    manager
        .attach_filter_for_test(dataplane::TestFilterSpec {
            ifname: TEST_TX,
            ifindex: tx,
            parent: netlink::TC_H_EGRESS,
            handle: abi::TC_HANDLE_VERIFY,
            priority: 2,
            protocol: netlink::ETH_P_ALL,
            program_name: abi::PROG_VERIFY,
        })
        .expect("attach first continuation probe");
    manager
        .attach_filter_for_test(dataplane::TestFilterSpec {
            ifname: TEST_TX,
            ifindex: tx,
            parent: netlink::TC_H_EGRESS,
            handle: abi::TC_HANDLE_VERIFY,
            priority: 3,
            protocol: netlink::ETH_P_ALL,
            program_name: abi::PROG_VERIFY,
        })
        .expect("attach second continuation probe");
    let before = manager
        .counter_for_test(Counter::SawPacket)
        .expect("read continuation baseline");
    for sequence in 0..4u8 {
        send_udp_bound_to(TEST_TX, "203.0.113.2", &[b'u', b'n', b's', sequence])
            .expect("send continuation packet");
    }
    std::thread::sleep(Duration::from_millis(100));
    let after = manager
        .counter_for_test(Counter::SawPacket)
        .expect("read continuation result");
    assert!(
        after >= before + 8,
        "two UNSPEC filters did not both run: before={before}, after={after}"
    );
    manager
        .detach_filter_for_test(TEST_TX, netlink::TC_H_EGRESS, abi::TC_HANDLE_VERIFY)
        .expect("detach first continuation probe");
    manager
        .detach_filter_for_test(TEST_TX, netlink::TC_H_EGRESS, abi::TC_HANDLE_VERIFY)
        .expect("detach second continuation probe");

    manager
        .attach_filter_for_test(dataplane::TestFilterSpec {
            ifname: TEST_TX,
            ifindex: tx,
            parent: netlink::TC_H_EGRESS,
            handle: abi::TC_HANDLE_EGRESS,
            priority: 2,
            protocol: netlink::ETH_P_ALL,
            program_name: abi::PROG_CAP_L2,
        })
        .expect("attach controlled L2 capture");
    manager
        .publish_test_active(0)
        .expect("publish isolated active test leaf");

    // Q5.1 and Q5.6. The source is loopback-local so accept_local and strict
    // rp_filter are observable. All global writes are confined to this child
    // namespace and disappear when it exits.
    set_matrix(0, 0, 1, 0, 0);
    send_and_expect(&listener, b"baseline", true);
    set_matrix(0, 0, 0, 0, 0);
    send_and_expect(&listener, b"accept-local-off", false);
    set_matrix(0, 1, 1, 0, 0);
    send_and_expect(&listener, b"iface-rpf-on", false);
    set_matrix(1, 0, 1, 0, 0);
    send_and_expect(&listener, b"all-rpf-on", false);
    set_matrix(0, 0, 1, 1, 0);
    send_and_expect(&listener, b"forward-on", true);
    set_matrix(0, 0, 1, 0, 1);
    send_and_expect(&listener, b"arp-filter-on", true);

    manager
        .publish_test_inactive()
        .expect("restore isolated inactive control");
    manager
        .detach_filter_for_test(TEST_TX, netlink::TC_H_EGRESS, abi::TC_HANDLE_EGRESS)
        .expect("detach controlled L2 capture");
    route.delete_link(tx).expect("delete isolated test veth");
    manager
        .cleanup_for_test()
        .expect("cleanup isolated Flux objects");
}

fn run_host_rawip() {
    let (listener, port) = transparent_listener();
    let mut manager = dataplane::Manager::open().expect("open host manager");
    manager.converge_with_bpf(true, BPF_OBJECT);
    assert!(
        manager.status().error.is_none(),
        "host topology/load failed: {:?}",
        manager.status().error
    );
    manager
        .prepare_generation(52, port, port)
        .expect("publish host inactive generation");
    drive_liveness(&mut manager);

    let l3_ifaces = manager
        .status()
        .ifaces
        .iter()
        .filter(|iface| {
            iface.status == "active" && iface.entry.as_deref() == Some(abi::PROG_CAP_L3)
        })
        .map(|iface| iface.name.clone())
        .collect::<Vec<_>>();
    assert!(!l3_ifaces.is_empty(), "no active RAWIP interface on device");
    assert!(
        manager
            .status()
            .warnings
            .iter()
            .all(|warning| !warning.contains("tc_verify_no_traffic")),
        "an admitted interface was not positively verified: {:?}",
        manager.status().warnings
    );

    let admit_before = manager
        .counter_for_test(Counter::AdmitUdp)
        .expect("read UDP admit baseline");
    let assign_before = manager
        .counter_for_test(Counter::InAssignUdp)
        .expect("read UDP assign baseline");
    let handoff_drop_before = manager
        .counter_for_test(Counter::DropHandoff)
        .expect("read handoff-drop baseline");
    manager
        .publish_test_active(0)
        .expect("publish host active test leaf");

    let mut delivered = false;
    for (index, ifname) in l3_ifaces.iter().enumerate() {
        let payload = format!("rawip-{index}-{ifname}").into_bytes();
        if send_udp_bound(ifname, &payload).is_err() {
            continue;
        }
        if recv_payload(&listener, &payload, true).is_ok() {
            delivered = true;
            println!("phase5_rawip_closed_loop iface={ifname}");
            break;
        }
    }
    assert!(
        delivered,
        "no active RAWIP interface completed the veth loop"
    );
    assert!(
        manager
            .counter_for_test(Counter::AdmitUdp)
            .expect("read UDP admit result")
            > admit_before,
        "RAWIP UDP was not admitted"
    );
    assert!(
        manager
            .counter_for_test(Counter::InAssignUdp)
            .expect("read UDP assign result")
            > assign_before,
        "RAWIP UDP did not reach bpf_sk_assign"
    );
    assert_eq!(
        manager
            .counter_for_test(Counter::DropHandoff)
            .expect("read handoff-drop result"),
        handoff_drop_before,
        "RAWIP change_head/EtherType handoff reported a failure"
    );
    manager
        .publish_test_inactive()
        .expect("publish inactive before deliberate crash");
}

fn drive_liveness(manager: &mut dataplane::Manager) {
    let mut seen = BTreeSet::new();
    let mut progress = manager.begin_attachment().expect("begin TC attachment");
    loop {
        let dataplane::AttachmentProgress::Wait(delay) = progress else {
            break;
        };
        let ifname = current_verify_iface(manager).expect("one verification filter is attached");
        let before = manager
            .counter_for_test(Counter::SawPacket)
            .expect("read liveness baseline");
        send_udp_bound(&ifname, b"phase5-liveness").expect("send interface liveness probe");
        std::thread::sleep(delay);
        progress = manager.advance_attachment().expect("advance TC attachment");
        let after = manager
            .counter_for_test(Counter::SawPacket)
            .expect("read liveness result");
        assert!(after > before, "flx_verify did not run on {ifname}");
        seen.insert(ifname);
    }
    assert!(manager.status().attachment_ready);
    let active = manager
        .status()
        .ifaces
        .iter()
        .filter(|iface| iface.status == "active")
        .count();
    assert_eq!(
        seen.len(),
        active,
        "not every active interface was verified"
    );
}

fn current_verify_iface(manager: &dataplane::Manager) -> Option<String> {
    let mut route = netlink::RouteNetlink::open().ok()?;
    manager.status().ifaces.iter().find_map(|iface| {
        route
            .dump_filters(iface.ifindex, netlink::TC_H_EGRESS)
            .ok()?
            .iter()
            .any(|filter| {
                filter.handle == abi::TC_HANDLE_VERIFY
                    && filter.prog_name.as_deref() == Some(abi::PROG_VERIFY)
            })
            .then(|| iface.name.clone())
    })
}

fn transparent_listener() -> (UdpSocket, u16) {
    // SAFETY: socket has no pointer preconditions and returns a new fd.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        raw >= 0,
        "create UDP listener: {}",
        io::Error::last_os_error()
    );
    // SAFETY: raw is newly returned and uniquely owned.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let enabled: libc::c_int = 1;
    // SAFETY: socket fd is valid and enabled points to a c_int of the stated size.
    let rc = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::SOL_IP,
            IP_TRANSPARENT,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "IP_TRANSPARENT failed: {}",
        io::Error::last_os_error()
    );
    let octets = abi::LISTEN_V4_STR
        .parse::<std::net::Ipv4Addr>()
        .expect("fixed listener address")
        .octets();
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(octets),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: owned and address are valid for bind's duration.
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind UDP listener: {}", io::Error::last_os_error());
    let socket = UdpSocket::from(owned);
    socket
        .set_read_timeout(Some(Duration::from_millis(700)))
        .expect("set listener timeout");
    let port = socket.local_addr().expect("listener address").port();
    (socket, port)
}

fn send_udp_bound(ifname: &str, payload: &[u8]) -> io::Result<()> {
    send_udp_bound_to(ifname, "198.51.100.3", payload)
}

fn send_udp_bound_to(ifname: &str, destination: &str, payload: &[u8]) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut name = ifname.as_bytes().to_vec();
    name.push(0);
    // SAFETY: fd and NUL-terminated interface-name buffer are valid.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    socket.send_to(payload, (destination, 53_000))?;
    Ok(())
}

fn send_and_expect(listener: &UdpSocket, payload: &[u8], expected: bool) {
    send_udp_bound_to(TEST_TX, "203.0.113.2", payload).expect("send matrix packet");
    recv_payload(listener, payload, expected).unwrap_or_else(|error| panic!("{error}"));
}

fn recv_payload(listener: &UdpSocket, expected: &[u8], should_arrive: bool) -> Result<(), String> {
    let mut buffer = [0u8; 256];
    match listener.recv_from(&mut buffer) {
        Ok((length, _)) if should_arrive && &buffer[..length] == expected => Ok(()),
        Ok((length, _)) if should_arrive => Err(format!(
            "received wrong payload: expected={expected:?}, actual={:?}",
            &buffer[..length]
        )),
        Ok((length, _)) => Err(format!(
            "packet unexpectedly survived matrix case: {:?}",
            &buffer[..length]
        )),
        Err(error)
            if !should_arrive
                && matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
        {
            Ok(())
        }
        Err(error) => Err(format!("listener receive failed: {error}")),
    }
}

fn set_matrix(all_rpf: i32, peer_rpf: i32, accept_local: i32, forward: i32, arp: i32) {
    write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", all_rpf);
    write_sysctl("/proc/sys/net/ipv4/conf/flxrs1/rp_filter", peer_rpf);
    write_sysctl("/proc/sys/net/ipv4/conf/flxrs1/accept_local", accept_local);
    write_sysctl("/proc/sys/net/ipv4/ip_forward", forward);
    write_sysctl("/proc/sys/net/ipv4/conf/all/arp_filter", arp);
}

fn write_sysctl(path: &str, value: i32) {
    fs::write(path, format!("{value}\n"))
        .unwrap_or_else(|error| panic!("write {path}={value} failed: {error}"));
}

fn global_sysctls() -> Vec<(String, String)> {
    [
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/conf/all/arp_filter",
    ]
    .into_iter()
    .map(|path| {
        (
            path.to_string(),
            fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path} failed: {error}")),
        )
    })
    .collect()
}

fn assert_killed_child(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: pid is the live child returned by fork and status is writable.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
}

fn assert_host_has_flux_filters() {
    assert!(
        flux_filters().iter().any(|(_, name)| name == abi::PROG_IN),
        "deliberate crash left no ingress filter"
    );
    assert!(
        flux_filters()
            .iter()
            .any(|(_, name)| name == abi::PROG_CAP_L3),
        "deliberate crash left no RAWIP capture filter"
    );
}

fn assert_host_clean() {
    let mut route = netlink::RouteNetlink::open().expect("open clean validation socket");
    let snapshot = route.snapshot().expect("dump clean validation snapshot");
    assert!(!snapshot
        .links
        .iter()
        .any(|link| link.name == "flxrs0" || link.name == "flxrs1"));
    assert!(!snapshot.rules.iter().any(|rule| rule.priority == Some(100)));
    assert!(!snapshot.routes.iter().any(|route| route.table == 20_260));
    assert!(
        flux_filters().is_empty(),
        "Flux TC filters remain after cleanup"
    );
}

fn flux_filters() -> Vec<(String, String)> {
    let mut route = netlink::RouteNetlink::open().expect("open filter validation socket");
    let snapshot = route.snapshot().expect("dump filter validation snapshot");
    let mut found = Vec::new();
    for link in &snapshot.links {
        for parent in [netlink::TC_H_INGRESS, netlink::TC_H_EGRESS] {
            let Ok(filters) = route.dump_filters(link.ifindex, parent) else {
                continue;
            };
            for filter in filters {
                if let Some(name) = filter.prog_name.filter(|name| name.starts_with("flx_")) {
                    found.push((link.name.clone(), name));
                }
            }
        }
    }
    found
}
