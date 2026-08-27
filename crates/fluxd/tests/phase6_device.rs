//! Root-only Phase 6 data-path acceptance test for an authorized Android device.
//!
//! The test uses only exact-owned Flux objects and restores them on every
//! ordinary exit. It selects the test process UID, drives the production
//! policy/control APIs, verifies dual-stack TCP and UDP transparent delivery,
//! exercises a large TCP write and UDP GSO, checks DRAINING semantics and
//! per-UID accounting, then publishes inactive before cleanup.

#![allow(dead_code, unused_imports)]

#[path = "../src/bpf/mod.rs"]
mod bpf;
#[path = "../src/dataplane.rs"]
mod dataplane;
#[path = "../src/netlink/mod.rs"]
mod netlink;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{self, Child, Command, Stdio};
use std::time::{Duration, Instant};

use flux_core::abi::{self, Counter};

const BPF_OBJECT: &[u8] = include_bytes!(env!("FLUX_BPF_OBJECT"));
const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
const UDP_SEGMENT: libc::c_int = 103;
const V4_DEST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
const V6_DEST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 77);
const OFFICIAL_TCP4_DEST_PORT: u16 = 42_111;
const OFFICIAL_TCP6_DEST_PORT: u16 = 42_112;
const OFFICIAL_UDP4_DEST_PORT: u16 = 42_113;
const OFFICIAL_UDP6_DEST_PORT: u16 = 42_114;
const PACKAGE_RULE_DEST_PORT: u16 = 42_101;
const PACKAGE_RULE_REPLY: &[u8] = b"flux-package-rule-hit";
const PACKAGE_RULE_CLIENT: &str = "--package-rule-client";

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(mut manager) = dataplane::Manager::open() {
            if let Err(error) = manager.cleanup_for_test() {
                eprintln!("phase6 cleanup failed: {error}");
            }
        }
    }
}

struct TempEngineFiles {
    config: PathBuf,
    log: PathBuf,
}

impl Drop for TempEngineFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.config);
        let _ = std::fs::remove_file(&self.log);
    }
}

struct EngineChild(Child);

impl Drop for EngineChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Listeners {
    tcp4: TcpListener,
    udp4: UdpSocket,
    tcp6: TcpListener,
    udp6: UdpSocket,
    port4: u16,
    port6: u16,
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some(PACKAGE_RULE_CLIENT) {
        package_rule_client_main();
        return;
    }
    if std::env::var_os("FLUX_PHASE6_DEVICE_TEST").is_none() {
        println!("phase6 device test: skipped (set FLUX_PHASE6_DEVICE_TEST=1)");
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("phase6 device test requires root");
        process::exit(77);
    }

    let _cleanup = Cleanup;
    let mut stale = dataplane::Manager::open().expect("open stale-object manager");
    stale
        .cleanup_for_test()
        .expect("remove exact-owned leftovers");
    drop(stale);
    let firewall_before = firewall_drop_counters();

    let listeners = open_listeners();
    let mut manager = dataplane::Manager::open().expect("open Phase 6 manager");
    manager.converge_with_bpf(true, BPF_OBJECT);
    assert!(
        manager.status().error.is_none(),
        "data-plane convergence failed: {:?}",
        manager.status().error
    );

    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() } as u32;
    let mut desired = dataplane::DesiredPolicy::default();
    desired.selected_uids.insert(uid);
    let (fixed4, fixed6) = flux_core::config::FluxConfig::fixed_bypass();
    desired
        .bypass_v4
        .extend(fixed4.iter().copied().map(|cidr| cidr.to_lpm_key()));
    desired
        .bypass_v6
        .extend(fixed6.iter().copied().map(|cidr| cidr.to_lpm_key()));
    manager
        .apply_policy(&desired)
        .expect("install Phase 6 policy");
    manager
        .prepare_generation(61, listeners.port4, listeners.port6)
        .expect("publish inactive Phase 6 generation");
    drive_liveness(&mut manager);
    manager.publish_active().expect("commit active=1");
    assert!(manager.status().active, "manager did not report active");
    assert_eq!(manager.status().policy.selected, 1);

    let active_ifaces = manager
        .status()
        .ifaces
        .iter()
        .filter(|iface| iface.status == "active")
        .map(|iface| iface.name.clone())
        .collect::<Vec<_>>();
    assert!(
        !active_ifaces.is_empty(),
        "no positively verified interface"
    );

    let stats_before = manager.uid_stats_for_test(uid).unwrap_or_default();
    let iface4 = udp_smoke(
        &listeners.udp4,
        &active_ifaces,
        SocketAddr::new(IpAddr::V4(V4_DEST), 40_001),
        false,
        b"udp4-unconnected",
    );
    udp_smoke_on(
        &listeners.udp4,
        &iface4,
        SocketAddr::new(IpAddr::V4(V4_DEST), 40_002),
        true,
        b"udp4-connected",
    );
    let iface6 = udp_smoke(
        &listeners.udp6,
        &active_ifaces,
        SocketAddr::new(IpAddr::V6(V6_DEST), 40_003),
        false,
        b"udp6-unconnected",
    );
    udp_smoke_on(
        &listeners.udp6,
        &iface6,
        SocketAddr::new(IpAddr::V6(V6_DEST), 40_004),
        true,
        b"udp6-connected",
    );

    let (mut app4, mut accepted4) = tcp_smoke(
        &listeners.tcp4,
        &active_ifaces,
        SocketAddr::new(IpAddr::V4(V4_DEST), 41_001),
        b"tcp4",
    );
    let (app6, accepted6) = tcp_smoke(
        &listeners.tcp6,
        &active_ifaces,
        SocketAddr::new(IpAddr::V6(V6_DEST), 41_002),
        b"tcp6",
    );

    // A multi-megabyte write exercises cloned retransmit/GSO-safe capture.
    let large = vec![0x5au8; 2 * 1024 * 1024];
    let mut upload_reader = accepted4.try_clone().expect("clone TCP proxy socket");
    let upload_len = large.len();
    let reader = std::thread::spawn(move || {
        let mut received = vec![0u8; upload_len];
        upload_reader
            .read_exact(&mut received)
            .expect("receive large TCP upload");
        received
    });
    app4.write_all(&large).expect("large TCP upload");
    let received = reader.join().expect("large TCP reader panicked");
    assert_eq!(received, large, "large TCP upload was corrupted");

    udp_gso_smoke(
        &listeners.udp4,
        &iface4,
        SocketAddr::new(IpAddr::V4(V4_DEST), 40_005),
    );

    let stats_after = manager.uid_stats_for_test(uid).expect("read uid_stats");
    assert!(stats_after.packets > stats_before.packets);
    assert!(stats_after.bytes >= stats_before.bytes + large.len() as u64);

    // A hot bypass update does not flip active or change generation. New UDP
    // takes the direct path while the prefix exists, then is captured again.
    let mut bypassed = desired.clone();
    bypassed.bypass_v4.insert(
        flux_core::cidr::Ipv4Cidr::parse("203.0.113.77/32")
            .unwrap()
            .to_lpm_key(),
    );
    manager.apply_policy(&bypassed).expect("add hot bypass");
    let bypass_app = UdpSocket::bind("0.0.0.0:0").expect("bind bypass probe");
    bind_to_device(bypass_app.as_raw_fd(), &iface4).expect("bind bypass probe interface");
    bypass_app
        .send_to(b"must-go-direct", (V4_DEST, 40_006))
        .expect("send bypass probe");
    assert!(
        recv_origdst(&listeners.udp4).is_err(),
        "hot bypass packet reached the transparent listener"
    );
    manager.apply_policy(&desired).expect("remove hot bypass");
    udp_smoke_on(
        &listeners.udp4,
        &iface4,
        SocketAddr::new(IpAddr::V4(V4_DEST), 40_007),
        false,
        b"captured-after-bypass",
    );

    // Policy removal is add-first/remove-second and leaves a boot-lifetime
    // DRAINING entry. Existing captured TCP remains captured.
    let draining = dataplane::DesiredPolicy {
        bypass_v4: desired.bypass_v4.clone(),
        bypass_v6: desired.bypass_v6.clone(),
        ..dataplane::DesiredPolicy::default()
    };
    manager
        .apply_policy(&draining)
        .expect("downgrade UID to draining");
    assert_eq!(manager.status().policy.selected, 0);
    assert_eq!(manager.status().policy.draining, 1);
    let direct_app = UdpSocket::bind("0.0.0.0:0").expect("bind draining probe");
    bind_to_device(direct_app.as_raw_fd(), &iface4).expect("bind draining probe interface");
    direct_app
        .send_to(b"new-flow-direct", (V4_DEST, 40_008))
        .expect("send draining probe");
    assert!(
        recv_origdst(&listeners.udp4).is_err(),
        "new UDP was captured for a DRAINING UID"
    );
    app4.write_all(b"draining-existing")
        .expect("write existing TCP");
    let mut existing = [0u8; 17];
    accepted4
        .read_exact(&mut existing)
        .expect("existing captured TCP survives draining");
    assert_eq!(&existing, b"draining-existing");

    manager.publish_inactive().expect("publish active=0");
    app4.set_write_timeout(Some(Duration::from_millis(500)))
        .expect("set inactive write timeout");
    let _ = app4.write(b"must-not-leak");
    accepted4
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set inactive read timeout");
    let mut blocked = [0u8; 32];
    assert!(
        matches!(
            accepted4.read(&mut blocked),
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ),
        "an admitted TCP byte crossed after active=0"
    );

    report_firewall_deltas(&firewall_before, &firewall_drop_counters());

    manager.cleanup_for_test().expect("remove Phase 6 objects");
    drop(manager);
    drop(app4);
    drop(accepted4);
    drop(app6);
    drop(accepted6);
    drop(listeners);

    let engine_binary = std::env::var_os("FLUX_PHASE6_ENGINE_BIN")
        .expect("FLUX_PHASE6_ENGINE_BIN must name the pinned official Android sing-box");
    package_name_rule_smoke(PathBuf::from(engine_binary), &iface4);
    println!(
        "phase6 device test: PASS (dual-stack TCP/UDP origdst, TCP large write, UDP GSO, uid_stats, DRAINING, active=0 drop, package_name route)"
    );
}

fn package_rule_client_main() {
    let mut args = std::env::args().skip(2);
    let ifname = args.next().unwrap_or_default();
    let destination = args
        .next()
        .and_then(|value| value.parse::<SocketAddr>().ok());
    let owner_uid = args.next().and_then(|value| value.parse::<u32>().ok());
    let result = destination
        .zip(owner_uid)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination or owner UID missing",
            )
        })
        .and_then(|(destination, owner_uid)| {
            tcp_connect_timeout(&ifname, destination, owner_uid, Duration::from_secs(5))
        })
        .and_then(|mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(b"package-rule-probe")?;
            let mut reply = vec![0u8; PACKAGE_RULE_REPLY.len()];
            stream.read_exact(&mut reply)?;
            if reply == PACKAGE_RULE_REPLY {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected package-rule response",
                ))
            }
        });
    process::exit(if result.is_ok() { 0 } else { 78 });
}

fn package_name_rule_smoke(engine_binary: PathBuf, preferred_iface: &str) {
    let ((package_name, matching_uid), (_, rejected_uid)) = package_rule_candidates();
    let reservation = open_listeners();
    let (port4, port6) = (reservation.port4, reservation.port6);
    drop(reservation);

    let official_tcp4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind official-engine IPv4 TCP responder");
    let official_tcp6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .expect("bind official-engine IPv6 TCP responder");
    official_tcp4
        .set_nonblocking(true)
        .expect("nonblocking official-engine IPv4 TCP responder");
    official_tcp6
        .set_nonblocking(true)
        .expect("nonblocking official-engine IPv6 TCP responder");
    let official_udp4 =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind official-engine IPv4 UDP responder");
    let official_udp6 =
        UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind official-engine IPv6 UDP responder");
    official_udp4
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout official-engine IPv4 UDP responder");
    official_udp6
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout official-engine IPv6 UDP responder");
    let official_tcp4_port = official_tcp4.local_addr().unwrap().port();
    let official_tcp6_port = official_tcp6.local_addr().unwrap().port();
    let official_udp4_port = official_udp4.local_addr().unwrap().port();
    let official_udp6_port = official_udp6.local_addr().unwrap().port();

    let reply_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind package-rule response listener");
    reply_listener
        .set_nonblocking(true)
        .expect("nonblocking package-rule listener");
    let reply_port = reply_listener.local_addr().unwrap().port();

    let pid = process::id();
    let files = TempEngineFiles {
        config: PathBuf::from(format!("/data/local/tmp/flux-phase6-q9-{pid}.json")),
        log: PathBuf::from(format!("/data/local/tmp/flux-phase6-q9-{pid}.log")),
    };
    let user = serde_json::json!({
        "log": {
            "level": "trace",
            "output": files.log,
            "timestamp": false
        },
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "route": {
            "rules": [
                {
                    "network": "tcp",
                    "ip_cidr": format!("{V4_DEST}/32"),
                    "port": OFFICIAL_TCP4_DEST_PORT,
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "127.0.0.1",
                    "override_port": official_tcp4_port
                },
                {
                    "network": "tcp",
                    "ip_cidr": format!("{V6_DEST}/128"),
                    "port": OFFICIAL_TCP6_DEST_PORT,
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "::1",
                    "override_port": official_tcp6_port
                },
                {
                    "network": "udp",
                    "ip_cidr": format!("{V4_DEST}/32"),
                    "port": OFFICIAL_UDP4_DEST_PORT,
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "127.0.0.1",
                    "override_port": official_udp4_port
                },
                {
                    "network": "udp",
                    "ip_cidr": format!("{V6_DEST}/128"),
                    "port": OFFICIAL_UDP6_DEST_PORT,
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "::1",
                    "override_port": official_udp6_port
                },
                {
                    "package_name": [package_name],
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "127.0.0.1",
                    "override_port": reply_port
                },
                { "action": "reject" }
            ]
        }
    });
    let params = flux_core::engine_config::EngineParams {
        generation: 62,
        port_v4: port4,
        port_v6: port6,
    };
    let effective = flux_core::engine_config::build_effective(&user, &params)
        .expect("build package-rule engine config");
    let mut config = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&files.config)
        .expect("create private package-rule config");
    config
        .write_all(effective.to_string().as_bytes())
        .expect("write package-rule config");
    drop(config);

    let child = Command::new(&engine_binary)
        .args(["run", "-c"])
        .arg(&files.config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start pinned official sing-box");
    let mut engine = EngineChild(child);
    wait_for_engine_sockets(&mut engine.0, params);

    let mut manager = dataplane::Manager::open().expect("open package-rule manager");
    manager.converge_with_bpf(true, BPF_OBJECT);
    assert!(
        manager.status().error.is_none(),
        "package-rule data-plane convergence failed: {:?}",
        manager.status().error
    );
    let mut desired = dataplane::DesiredPolicy::default();
    desired.selected_uids.extend([matching_uid, rejected_uid]);
    let (fixed4, fixed6) = flux_core::config::FluxConfig::fixed_bypass();
    desired
        .bypass_v4
        .extend(fixed4.iter().copied().map(|cidr| cidr.to_lpm_key()));
    desired
        .bypass_v6
        .extend(fixed6.iter().copied().map(|cidr| cidr.to_lpm_key()));
    manager
        .apply_policy(&desired)
        .expect("install package-rule UID policy");
    manager
        .prepare_generation(params.generation, params.port_v4, params.port_v6)
        .expect("prepare package-rule generation");
    drive_liveness(&mut manager);
    manager
        .publish_active()
        .expect("activate package-rule data plane");
    let ifname = manager
        .status()
        .ifaces
        .iter()
        .find(|iface| iface.status == "active" && iface.name == preferred_iface)
        .or_else(|| {
            manager
                .status()
                .ifaces
                .iter()
                .find(|iface| iface.status == "active")
        })
        .map(|iface| iface.name.clone())
        .expect("package-rule test needs an active interface");

    official_tcp_origdst_smoke(
        &official_tcp4,
        &ifname,
        SocketAddr::new(IpAddr::V4(V4_DEST), OFFICIAL_TCP4_DEST_PORT),
        matching_uid,
        b"official-tcp4",
    );
    official_tcp_origdst_smoke(
        &official_tcp6,
        &ifname,
        SocketAddr::new(IpAddr::V6(V6_DEST), OFFICIAL_TCP6_DEST_PORT),
        matching_uid,
        b"official-tcp6",
    );
    official_udp_origdst_smoke(
        &official_udp4,
        &ifname,
        SocketAddr::new(IpAddr::V4(V4_DEST), OFFICIAL_UDP4_DEST_PORT),
        matching_uid,
        b"official-udp4",
    );
    official_udp_origdst_smoke(
        &official_udp6,
        &ifname,
        SocketAddr::new(IpAddr::V6(V6_DEST), OFFICIAL_UDP6_DEST_PORT),
        matching_uid,
        b"official-udp6",
    );
    println!("phase6 official sing-box dual-stack TCP/UDP origdst routes: PASS");

    let destination = SocketAddr::new(IpAddr::V4(V4_DEST), PACKAGE_RULE_DEST_PORT);
    let counters_before = manager.counters().expect("read pre-Q9 counters");

    let responder = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match reply_listener.accept() {
                Ok((mut stream, _)) => {
                    let mut probe = [0u8; 18];
                    stream
                        .read_exact(&mut probe)
                        .expect("read package-rule probe");
                    assert_eq!(&probe, b"package-rule-probe");
                    stream
                        .write_all(PACKAGE_RULE_REPLY)
                        .expect("write package-rule reply");
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "package rule did not reach responder"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("package-rule accept failed: {error}"),
            }
        }
    });

    let matched = run_package_rule_client(matching_uid, &ifname, destination);
    if !matched.success() {
        let counters_after = manager.counters().expect("read failed-Q9 counters");
        let log = std::fs::read_to_string(&files.log).unwrap_or_default();
        eprintln!(
            "phase6_q9_diag admitted={} assigned={} package_db={} process_found={} process_failed={} rule0={} reject_rule={}",
            counters_after
                .admit_tcp
                .saturating_sub(counters_before.admit_tcp),
            counters_after
                .in_assign_tcp
                .saturating_sub(counters_before.in_assign_tcp),
            log.contains("updated packages list:"),
            log.contains("found package name:"),
            log.contains("failed to search process:"),
            log.contains("match[0]"),
            log.contains("match[1]")
        );
    }
    assert!(
        matched.success(),
        "matching package_name rule did not route"
    );
    responder.join().expect("package-rule responder panicked");
    let rejected = run_package_rule_client(rejected_uid, &ifname, destination);
    assert!(
        !rejected.success(),
        "non-matching package escaped the catch-all reject rule"
    );

    manager
        .publish_inactive()
        .expect("freeze package-rule data plane");
    manager
        .cleanup_for_test()
        .expect("remove package-rule test objects");
    drop(manager);
    drop(engine);
    drop(files);
    println!("phase6 package_name route: PASS");
}

fn official_tcp_origdst_smoke(
    responder: &TcpListener,
    ifname: &str,
    destination: SocketAddr,
    owner_uid: u32,
    payload: &[u8],
) {
    let mut app = tcp_connect_timeout(ifname, destination, owner_uid, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("official sing-box TCP connect to {destination}: {error}"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut accepted = loop {
        match responder.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "official sing-box did not route TCP {destination}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("official sing-box TCP responder failed: {error}"),
        }
    };
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout official-engine TCP responder");
    app.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout official-engine TCP app");
    app.write_all(payload)
        .expect("write official-engine TCP probe");
    let mut received = vec![0u8; payload.len()];
    accepted
        .read_exact(&mut received)
        .expect("read official-engine TCP probe");
    assert_eq!(received, payload);
    accepted
        .write_all(b"official-reply")
        .expect("write official-engine TCP reply");
    let mut reply = [0u8; 14];
    app.read_exact(&mut reply)
        .expect("read official-engine TCP reply");
    assert_eq!(&reply, b"official-reply");
}

fn official_udp_origdst_smoke(
    responder: &UdpSocket,
    ifname: &str,
    destination: SocketAddr,
    owner_uid: u32,
    payload: &[u8],
) {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let app = UdpSocket::bind(bind).expect("bind official-engine UDP app");
    bind_to_device(app.as_raw_fd(), ifname).expect("bind official-engine UDP app interface");
    // The route test must use an app-owned socket so sing-box's root-owned
    // outbound socket cannot be selected and recaptured.
    // SAFETY: fchown accepts this live socket fd; gid=-1 leaves its group alone.
    let chown =
        unsafe { libc::fchown(app.as_raw_fd(), owner_uid as libc::uid_t, libc::gid_t::MAX) };
    assert_eq!(
        chown,
        0,
        "fchown official-engine UDP app: {}",
        io::Error::last_os_error()
    );
    app.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout official-engine UDP app");
    app.send_to(payload, destination)
        .expect("send official-engine UDP probe");
    let mut received = vec![0u8; payload.len()];
    let (length, peer) = responder
        .recv_from(&mut received)
        .expect("official sing-box did not route UDP destination");
    received.truncate(length);
    assert_eq!(received, payload);
    responder
        .send_to(b"official-reply", peer)
        .expect("write official-engine UDP reply");
    let mut reply = [0u8; 14];
    let (length, source) = app
        .recv_from(&mut reply)
        .expect("read official-engine UDP reply");
    assert_eq!(&reply[..length], b"official-reply");
    assert_eq!(source, destination);
}

fn package_rule_candidates() -> ((String, u32), (String, u32)) {
    let packages = std::fs::read_to_string("/data/system/packages.list")
        .expect("read Android packages.list for package_name acceptance");
    let mut app_ids = BTreeSet::new();
    let mut candidates = Vec::new();
    for line in packages.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(package) = fields.first().copied() else {
            continue;
        };
        let Some(uid) = fields.get(1).and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        // packages.list field 6 is the supplementary-GID list. Requiring
        // AID_INET avoids selecting an app that Android's owner firewall
        // discards before TC egress, which would test permission state rather
        // than sing-box package matching.
        let has_inet = fields
            .get(5)
            .is_some_and(|gids| gids.split(',').any(|gid| gid == "3003"));
        let app_id = uid % abi::USER_ID_STRIDE;
        if !has_inet
            || !(abi::APP_ID_MIN..=abi::APP_ID_MAX).contains(&app_id)
            || !app_ids.insert(app_id)
        {
            continue;
        }
        candidates.push((package.to_string(), uid));
    }
    assert!(
        candidates.len() >= 2,
        "package_name test needs two network-enabled application UIDs"
    );
    let target_index = candidates
        .iter()
        .position(|(package, _)| package == "com.android.vending")
        .unwrap_or(0);
    let target = candidates.remove(target_index);
    let rejected = candidates
        .into_iter()
        .find(|(_, uid)| uid % abi::USER_ID_STRIDE != target.1 % abi::USER_ID_STRIDE)
        .expect("package_name test needs a distinct negative-control appId");
    (target, rejected)
}

fn run_package_rule_client(uid: u32, ifname: &str, destination: SocketAddr) -> process::ExitStatus {
    Command::new(std::env::current_exe().expect("current Phase 6 test path"))
        .arg(PACKAGE_RULE_CLIENT)
        .arg(ifname)
        .arg(destination.to_string())
        .arg(uid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run package-rule client under selected app UID")
}

fn wait_for_engine_sockets(child: &mut Child, params: flux_core::engine_config::EngineParams) {
    let expectations = [
        netlink::sock_diag::SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V4(abi::LISTEN_V4_STR.parse().unwrap()),
            port: params.port_v4,
        },
        netlink::sock_diag::SocketExpectation {
            protocol: libc::IPPROTO_UDP as u8,
            addr: IpAddr::V4(abi::LISTEN_V4_STR.parse().unwrap()),
            port: params.port_v4,
        },
        netlink::sock_diag::SocketExpectation {
            protocol: libc::IPPROTO_TCP as u8,
            addr: IpAddr::V6(abi::LISTEN_V6_STR.parse().unwrap()),
            port: params.port_v6,
        },
        netlink::sock_diag::SocketExpectation {
            protocol: libc::IPPROTO_UDP as u8,
            addr: IpAddr::V6(abi::LISTEN_V6_STR.parse().unwrap()),
            port: params.port_v6,
        },
    ];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.try_wait().expect("poll official engine").is_none(),
            "official engine exited before socket readiness"
        );
        let pid = child.id() as i32;
        let ready = expectations.iter().all(|expectation| {
            netlink::sock_diag::find_inode(expectation)
                .ok()
                .flatten()
                .is_some_and(|inode| {
                    netlink::sock_diag::pid_owns_inode(pid, inode).unwrap_or(false)
                })
        });
        if ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "official engine sockets not ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn open_listeners() -> Listeners {
    let (tcp4, port4) =
        transparent_tcp(IpAddr::V4(abi::LISTEN_V4_STR.parse().expect("listener v4")));
    let udp4 = transparent_udp(
        SocketAddr::new(IpAddr::V4(abi::LISTEN_V4_STR.parse().unwrap()), port4),
        false,
    );
    let (tcp6, port6) =
        transparent_tcp(IpAddr::V6(abi::LISTEN_V6_STR.parse().expect("listener v6")));
    let udp6 = transparent_udp(
        SocketAddr::new(IpAddr::V6(abi::LISTEN_V6_STR.parse().unwrap()), port6),
        true,
    );
    for listener in [&tcp4, &tcp6] {
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
    }
    for socket in [&udp4, &udp6] {
        socket
            .set_read_timeout(Some(Duration::from_millis(700)))
            .expect("UDP timeout");
    }
    Listeners {
        tcp4,
        udp4,
        tcp6,
        udp6,
        port4,
        port6,
    }
}

fn transparent_tcp(ip: IpAddr) -> (TcpListener, u16) {
    let family = if ip.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = socket(family, libc::SOCK_STREAM);
    set_int(fd.as_raw_fd(), libc::SOL_IP, IP_TRANSPARENT, 1);
    set_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    bind_socket(fd.as_raw_fd(), SocketAddr::new(ip, 0));
    // SAFETY: fd is a valid bound stream socket and backlog is positive.
    assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 16) }, 0);
    let listener = TcpListener::from(fd);
    let port = listener.local_addr().expect("TCP listener address").port();
    (listener, port)
}

fn transparent_udp(address: SocketAddr, v6: bool) -> UdpSocket {
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = socket(family, libc::SOCK_DGRAM);
    set_int(fd.as_raw_fd(), libc::SOL_IP, IP_TRANSPARENT, 1);
    set_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    set_int(
        fd.as_raw_fd(),
        if v6 { libc::SOL_IPV6 } else { libc::SOL_IP },
        if v6 {
            IPV6_RECVORIGDSTADDR
        } else {
            IP_RECVORIGDSTADDR
        },
        1,
    );
    bind_socket(fd.as_raw_fd(), address);
    UdpSocket::from(fd)
}

fn socket(family: libc::c_int, kind: libc::c_int) -> OwnedFd {
    // SAFETY: socket takes scalar arguments and returns a fresh descriptor.
    let raw = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0, "socket failed: {}", io::Error::last_os_error());
    // SAFETY: raw was just returned and is uniquely owned here.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn set_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
    // SAFETY: fd is live and the value points to one initialized c_int.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt({name}): {}", io::Error::last_os_error());
}

fn bind_socket(fd: RawFd, address: SocketAddr) {
    let (storage, length) = encode_sockaddr(address);
    // SAFETY: storage contains the family-specific sockaddr for `length` bytes.
    let rc = unsafe {
        libc::bind(
            fd,
            (&storage as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    assert_eq!(rc, 0, "bind {address}: {}", io::Error::last_os_error());
}

fn encode_sockaddr(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroed bytes are valid output storage before writing a sockaddr.
    let mut storage = unsafe { zeroed::<libc::sockaddr_storage>() };
    match address {
        SocketAddr::V4(address) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), value) };
            (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(address) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in6.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), value) };
            (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

fn bind_to_device(fd: RawFd, ifname: &str) -> io::Result<()> {
    let mut name = ifname.as_bytes().to_vec();
    name.push(0);
    // SAFETY: name is NUL-terminated and live for the setsockopt call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    (rc == 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

fn udp_smoke(
    listener: &UdpSocket,
    ifaces: &[String],
    destination: SocketAddr,
    connected: bool,
    payload: &[u8],
) -> String {
    for ifname in ifaces {
        if udp_smoke_try(listener, ifname, destination, connected, payload).is_ok() {
            return ifname.clone();
        }
    }
    panic!("no active interface delivered {destination}");
}

fn udp_smoke_on(
    listener: &UdpSocket,
    ifname: &str,
    destination: SocketAddr,
    connected: bool,
    payload: &[u8],
) {
    udp_smoke_try(listener, ifname, destination, connected, payload)
        .unwrap_or_else(|error| panic!("{ifname} did not deliver {destination}: {error}"));
}

fn udp_smoke_try(
    listener: &UdpSocket,
    ifname: &str,
    destination: SocketAddr,
    connected: bool,
    payload: &[u8],
) -> Result<(), String> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let app = UdpSocket::bind(bind).map_err(|error| error.to_string())?;
    bind_to_device(app.as_raw_fd(), ifname).map_err(|error| error.to_string())?;
    if connected {
        app.connect(destination)
            .map_err(|error| error.to_string())?;
        app.send(payload).map_err(|error| error.to_string())?;
    } else {
        app.send_to(payload, destination)
            .map_err(|error| error.to_string())?;
    }
    let (body, original, source) = recv_origdst(listener).map_err(|error| error.to_string())?;
    if body != payload || original != destination {
        return Err(format!(
            "origdst mismatch: body={body:?}, destination={original}"
        ));
    }
    let reply = transparent_reply_socket(original);
    reply
        .send_to(b"reply", source)
        .map_err(|error| error.to_string())?;
    app.set_read_timeout(Some(Duration::from_millis(700)))
        .map_err(|error| error.to_string())?;
    let mut reply_body = [0u8; 16];
    if connected {
        let length = app
            .recv(&mut reply_body)
            .map_err(|error| error.to_string())?;
        if &reply_body[..length] != b"reply" {
            return Err("connected UDP reply payload mismatch".to_string());
        }
    } else {
        let (length, peer) = app
            .recv_from(&mut reply_body)
            .map_err(|error| error.to_string())?;
        if &reply_body[..length] != b"reply" || peer != destination {
            return Err(format!("unconnected UDP reply mismatch: peer={peer}"));
        }
    }
    Ok(())
}

fn transparent_reply_socket(source: SocketAddr) -> UdpSocket {
    let family = if source.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = socket(family, libc::SOCK_DGRAM);
    set_int(fd.as_raw_fd(), libc::SOL_IP, IP_TRANSPARENT, 1);
    set_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    bind_socket(fd.as_raw_fd(), source);
    UdpSocket::from(fd)
}

fn recv_origdst(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr, SocketAddr)> {
    let mut body = [0u8; 2048];
    // SAFETY: zeroed sockaddr_storage is valid output storage for recvmsg.
    let mut source = unsafe { zeroed::<libc::sockaddr_storage>() };
    let mut control = [0u8; 256];
    let mut iovec = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    let mut message = libc::msghdr {
        msg_name: (&mut source as *mut libc::sockaddr_storage).cast(),
        msg_namelen: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: msghdr points to live body, source and control buffers.
    let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: recvmsg initialized msg_controllen; libc validates header bounds.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !cmsg.is_null() {
        // SAFETY: FIRSTHDR/NXTHDR returned this in-bounds header pointer.
        let header = unsafe { &*cmsg };
        let is_v4 = header.cmsg_level == libc::SOL_IP && header.cmsg_type == IP_RECVORIGDSTADDR;
        let is_v6 = header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == IPV6_RECVORIGDSTADDR;
        if is_v4 || is_v6 {
            // SAFETY: the kernel supplied a family-matching sockaddr cmsg.
            let address = unsafe {
                decode_sockaddr(
                    libc::CMSG_DATA(cmsg).cast(),
                    if is_v4 { libc::AF_INET } else { libc::AF_INET6 },
                )
            };
            // SAFETY: recvmsg filled msg_name with the reported source family.
            let source_address = unsafe {
                decode_sockaddr(
                    (&source as *const libc::sockaddr_storage).cast(),
                    i32::from(source.ss_family),
                )
            };
            return Ok((body[..length as usize].to_vec(), address, source_address));
        }
        // SAFETY: cmsg is the current in-bounds header for this msghdr.
        cmsg = unsafe { libc::CMSG_NXTHDR(&message, cmsg) };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "origdst cmsg missing",
    ))
}

unsafe fn decode_sockaddr(pointer: *const libc::sockaddr, family: libc::c_int) -> SocketAddr {
    if family == libc::AF_INET {
        // SAFETY: caller proves pointer addresses an initialized sockaddr_in.
        let value = unsafe { *(pointer.cast::<libc::sockaddr_in>()) };
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(value.sin_addr.s_addr.to_ne_bytes())),
            u16::from_be(value.sin_port),
        )
    } else {
        // SAFETY: caller proves pointer addresses an initialized sockaddr_in6.
        let value = unsafe { *(pointer.cast::<libc::sockaddr_in6>()) };
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(value.sin6_addr.s6_addr)),
            u16::from_be(value.sin6_port),
        )
    }
}

fn tcp_smoke(
    listener: &TcpListener,
    ifaces: &[String],
    destination: SocketAddr,
    payload: &[u8],
) -> (TcpStream, TcpStream) {
    for ifname in ifaces {
        let Ok(mut app) = tcp_connect(ifname, destination) else {
            continue;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut accepted = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "TCP accept timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("TCP accept failed: {error}"),
            }
        };
        assert_eq!(
            accepted.local_addr().expect("accepted local address"),
            destination
        );
        app.write_all(payload).expect("TCP app write");
        let mut received = vec![0u8; payload.len()];
        accepted.read_exact(&mut received).expect("TCP proxy read");
        assert_eq!(received, payload);
        accepted.write_all(b"reply").expect("TCP proxy reply");
        let mut reply = [0u8; 5];
        app.read_exact(&mut reply).expect("TCP app reply");
        assert_eq!(&reply, b"reply");
        return (app, accepted);
    }
    panic!("no active interface completed TCP {destination}");
}

fn tcp_connect(ifname: &str, destination: SocketAddr) -> io::Result<TcpStream> {
    let family = if destination.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = socket(family, libc::SOCK_STREAM);
    bind_to_device(fd.as_raw_fd(), ifname)?;
    let (address, length) = encode_sockaddr(destination);
    // SAFETY: fd is live and address contains a sockaddr of the supplied length.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpStream::from(fd))
}

fn tcp_connect_timeout(
    ifname: &str,
    destination: SocketAddr,
    owner_uid: u32,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let family = if destination.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = socket(family, libc::SOCK_STREAM);
    bind_to_device(fd.as_raw_fd(), ifname)?;
    // The kernel and sing-box both attribute traffic from `sk_uid`. Android's
    // DNS resolver sets it with fchown too; retaining root here keeps the
    // interface bind legal while making the socket belong to the selected app.
    // SAFETY: fchown accepts this live socket fd; gid=-1 leaves its group alone.
    if unsafe { libc::fchown(fd.as_raw_fd(), owner_uid as libc::uid_t, libc::gid_t::MAX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_GETFL/F_SETFL operate on this live socket fd.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setting O_NONBLOCK preserves every existing descriptor flag.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (address, length) = encode_sockaddr(destination);
    // SAFETY: fd is live and address contains a sockaddr of the supplied length.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let milliseconds = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        loop {
            // SAFETY: pollfd points to one initialized entry for the call.
            let polled = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
            if polled > 0 {
                break;
            }
            if polled == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        let mut socket_error = 0i32;
        let mut socket_error_len = size_of::<i32>() as libc::socklen_t;
        // SAFETY: both output pointers describe one live i32 value.
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut i32).cast(),
                &mut socket_error_len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
    }
    // SAFETY: restore the descriptor flags captured before connect.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpStream::from(fd))
}

fn udp_gso_smoke(listener: &UdpSocket, ifname: &str, destination: SocketAddr) {
    let app = UdpSocket::bind("0.0.0.0:0").expect("bind UDP GSO app");
    bind_to_device(app.as_raw_fd(), ifname).expect("bind UDP GSO interface");
    let segment = 256u16;
    let payload = vec![0xa5u8; usize::from(segment) * 4];
    let (address, address_len) = encode_sockaddr(destination);
    let mut iovec = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: CMSG_SPACE is arithmetic for this fixed payload size.
    let space = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let message = libc::msghdr {
        msg_name: (&address as *const libc::sockaddr_storage)
            .cast_mut()
            .cast(),
        msg_namelen: address_len,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: message owns a control buffer sized with CMSG_SPACE.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!cmsg.is_null());
    // SAFETY: cmsg and its u16 data area are within the control buffer.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), segment);
    }
    // SAFETY: msghdr points to live payload, destination and control buffers.
    let sent = unsafe { libc::sendmsg(app.as_raw_fd(), &message, 0) };
    assert_eq!(
        sent,
        payload.len() as isize,
        "UDP_SEGMENT send failed: {}",
        io::Error::last_os_error()
    );
    for _ in 0..4 {
        let (datagram, original, _) = recv_origdst(listener).expect("receive UDP GSO segment");
        assert_eq!(datagram, vec![0xa5u8; usize::from(segment)]);
        assert_eq!(original, destination);
    }
}

fn drive_liveness(manager: &mut dataplane::Manager) {
    let mut progress = manager.begin_attachment().expect("begin TC attachment");
    loop {
        let dataplane::AttachmentProgress::Wait(delay) = progress else {
            break;
        };
        let ifname = current_verify_iface(manager).expect("verification filter missing");
        let before = manager.counter_for_test(Counter::SawPacket).unwrap();
        let socket = UdpSocket::bind("0.0.0.0:0").expect("liveness socket");
        bind_to_device(socket.as_raw_fd(), &ifname).expect("bind liveness interface");
        let _ = socket.send_to(b"phase6-liveness", (V4_DEST, 49_999));
        std::thread::sleep(delay);
        progress = manager.advance_attachment().expect("advance TC attachment");
        let after = manager.counter_for_test(Counter::SawPacket).unwrap();
        assert!(after > before, "liveness probe did not run on {ifname}");
    }
    assert!(manager.status().attachment_ready);
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

fn firewall_drop_counters() -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    for (family, binary) in [
        ("v4", "/system/bin/iptables"),
        ("v6", "/system/bin/ip6tables"),
    ] {
        let output = Command::new(binary)
            .args(["-L", "-v", "-n", "-x"])
            .output()
            .unwrap_or_else(|error| panic!("run {binary}: {error}"));
        assert!(
            output.status.success(),
            "{binary} counter snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        let mut chain = "?";
        for line in text.lines() {
            if let Some(name) = line
                .strip_prefix("Chain ")
                .and_then(|tail| tail.split_whitespace().next())
            {
                chain = name;
                continue;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 3 || !matches!(fields[2], "DROP" | "REJECT") {
                continue;
            }
            let Ok(packets) = fields[0].parse::<u64>() else {
                continue;
            };
            let key = format!("{family}:{chain}:{}", fields[2..].join(" "));
            counters.insert(key, packets);
        }
    }
    counters
}

fn report_firewall_deltas(before: &BTreeMap<String, u64>, after: &BTreeMap<String, u64>) {
    let mut changed = 0usize;
    for (rule, current) in after {
        let delta = current.saturating_sub(before.get(rule).copied().unwrap_or(0));
        if delta == 0 {
            continue;
        }
        changed += 1;
        let chain = rule.split(':').nth(1).unwrap_or("?");
        let owner = if matches!(chain, "INPUT" | "OUTPUT" | "FORWARD") {
            "base"
        } else {
            "oem_or_android"
        };
        println!("phase6_firewall_delta owner={owner} packets={delta} rule={rule}");
    }
    if changed == 0 {
        println!("phase6_firewall_delta none");
    }
}
