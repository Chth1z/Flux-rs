use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::fd::RawFd;

use flux_core::control_wire::IfaceStatus;

use crate::netlink::{self, DrainResult, EventSocket, Filter, NetworkSnapshot, RouteNetlink};

const HOST_NAME: &str = "flxrs0";
const PEER_NAME: &str = "flxrs1";
const HOST_ALIAS: &str = "flux-rs:managed:v1:host";
const PEER_ALIAS: &str = "flux-rs:managed:v1:peer";
const VETH_MTU: u32 = 65_535;
const ROUTE_TABLE: u32 = 20_260;
const ROUTE_PROTOCOL: u8 = 202;
const RULE_PRIORITY: u32 = 100;
const TC_PREF_PREFERRED: u16 = 2;
const TC_PREF_CLAT_MAX: u16 = 4;
const MAX_INTERFACES: usize = 64;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneError {
    pub code: String,
    pub detail: String,
}

impl DataplaneError {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    fn io(operation: &str, error: io::Error) -> Self {
        let errno = error
            .raw_os_error()
            .map(errno_name)
            .unwrap_or_else(|| format!("{:?}", error.kind()));
        Self::new(
            format!("{operation}:{errno}"),
            format!("{operation} failed: {error}"),
        )
    }
}

impl std::fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.code, self.detail)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DataplaneStatus {
    pub topology_ready: bool,
    pub ifaces: Vec<IfaceStatus>,
    pub sysctl: BTreeMap<String, i64>,
    pub warnings: Vec<String>,
    pub error: Option<DataplaneError>,
}

pub struct Manager {
    route: RouteNetlink,
    events: EventSocket,
    test_bypass: bool,
    reconciled_once: bool,
    status: DataplaneStatus,
}

impl Manager {
    /// Opens the event socket before the initial dump, closing the race between
    /// subscription and the first snapshot (§10.4.1).
    pub fn open() -> io::Result<Self> {
        let events = EventSocket::open()?;
        let route = RouteNetlink::open()?;
        Ok(Self {
            route,
            events,
            // The daemon E2E exercises engine transactions in an unprivileged
            // namespace. Release builds cannot enable this seam; the real
            // Phase 3 lifecycle has its own root-only device test.
            test_bypass: cfg!(debug_assertions)
                && std::env::var_os("FLUX_TEST_SKIP_DATAPLANE").as_deref()
                    == Some(std::ffi::OsStr::new("1")),
            reconciled_once: false,
            status: DataplaneStatus::default(),
        })
    }

    pub fn event_fd(&self) -> RawFd {
        self.events.as_raw_fd()
    }

    pub fn drain_events(&self) -> io::Result<DrainResult> {
        self.events.drain()
    }

    pub fn status(&self) -> &DataplaneStatus {
        &self.status
    }

    /// Device integration tests need to leave the owner's phone exactly as it
    /// was. This is not a production stop path: normal stop intentionally
    /// retains owned kernel objects until the next cold start (§8.8).
    #[cfg(test)]
    #[allow(dead_code)] // Used by the separately compiled phase3_device target.
    pub fn cleanup_for_test(&mut self) -> Result<(), String> {
        self.cleanup_owned().map_err(|error| error.to_string())
    }

    /// Reconciles only Phase 3 objects. `enabled=false` still performs the one
    /// cold-start stale-object cleanup, but creates nothing.
    pub fn converge(&mut self, enabled: bool) {
        if self.test_bypass {
            self.status = DataplaneStatus {
                warnings: vec![
                    "no data plane: debug-only daemon integration-test bypass".to_string()
                ],
                ..DataplaneStatus::default()
            };
            return;
        }

        let mut next = DataplaneStatus {
            sysctl: read_status_sysctls(),
            ..DataplaneStatus::default()
        };

        if !self.reconciled_once {
            match self.cleanup_owned() {
                Ok(()) => self.reconciled_once = true,
                Err(error) => {
                    next.error = Some(error);
                    self.status = next;
                    return;
                }
            }
        }

        if !enabled {
            self.status = next;
            return;
        }

        if let Err(error) = validate_rp_filter(&next.sysctl) {
            next.error = Some(error);
            self.status = next;
            return;
        }

        if let Err(error) = self.ensure_topology() {
            next.error = Some(error);
            self.status = next;
            return;
        }

        match self.admit_interfaces() {
            Ok(ifaces) => {
                next.topology_ready = true;
                next.ifaces = ifaces;
                next.sysctl = read_status_sysctls();
                next.warnings.push(
                    "phase-3 network seam is ready; BPF loading and live attachment belong to phases 4 and 5"
                        .to_string(),
                );
            }
            Err(error) => next.error = Some(error),
        }
        self.status = next;
    }

    /// Removes only objects that satisfy the complete Phase 3 ownership
    /// predicate. The plan is dumped twice before the first deletion.
    fn cleanup_owned(&mut self) -> Result<(), DataplaneError> {
        let first = self.cleanup_plan()?;
        let second = self.cleanup_plan()?;
        if first != second {
            return Err(DataplaneError::new(
                "network_snapshot_stale",
                "Flux-owned objects changed between the two ownership dumps",
            ));
        }

        for family in &second.rule_families {
            ignore_absent(
                self.route
                    .delete_rule(*family, RULE_PRIORITY, ROUTE_TABLE, PEER_NAME),
            )
            .map_err(|e| DataplaneError::io("rule_delete", e))?;
        }
        for family in &second.route_families {
            ignore_absent(self.route.delete_local_route(
                *family,
                ROUTE_TABLE,
                ROUTE_PROTOCOL,
                second.lo_ifindex,
            ))
            .map_err(|e| DataplaneError::io("route_delete", e))?;
        }
        if let Some(host_ifindex) = second.host_ifindex {
            ignore_absent(self.route.delete_link(host_ifindex))
                .map_err(|e| DataplaneError::io("veth_delete", e))?;
        }
        Ok(())
    }

    fn cleanup_plan(&mut self) -> Result<CleanupPlan, DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        let lo_ifindex = link_named(&snapshot, "lo")
            .map(|link| link.ifindex)
            .ok_or_else(|| DataplaneError::new("loopback_missing", "rtnetlink has no lo"))?;
        let pair = classify_pair(&snapshot)?;

        let mut rule_families = Vec::new();
        for rule in snapshot
            .rules
            .iter()
            .filter(|rule| rule.priority == Some(RULE_PRIORITY))
        {
            if is_owned_rule(rule) {
                rule_families.push(rule.family);
            } else {
                return Err(DataplaneError::new(
                    "rule_conflict:priority 100 occupied",
                    format!("foreign rule at priority {RULE_PRIORITY}: {rule:?}"),
                ));
            }
        }
        rule_families.sort_unstable();
        rule_families.dedup();

        let mut route_families = Vec::new();
        for route in snapshot
            .routes
            .iter()
            .filter(|route| route.table == ROUTE_TABLE)
        {
            if is_owned_route(route, lo_ifindex) {
                route_families.push(route.family);
            } else {
                return Err(DataplaneError::new(
                    "route_table_conflict:20260",
                    format!("foreign route in table {ROUTE_TABLE}: {route:?}"),
                ));
            }
        }
        route_families.sort_unstable();
        route_families.dedup();

        Ok(CleanupPlan {
            host_ifindex: pair.map(|(host, _)| host.ifindex),
            lo_ifindex,
            rule_families,
            route_families,
        })
    }

    fn ensure_topology(&mut self) -> Result<(), DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        match topology_state(&snapshot)? {
            TopologyState::Complete => return Ok(()),
            TopologyState::Absent => {}
            TopologyState::OwnedDrift => self.cleanup_owned()?,
        }
        self.create_topology()
    }

    fn create_topology(&mut self) -> Result<(), DataplaneError> {
        let before = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        reject_policy_conflicts(&before)?;
        let lo_ifindex = link_named(&before, "lo")
            .map(|link| link.ifindex)
            .ok_or_else(|| DataplaneError::new("loopback_missing", "rtnetlink has no lo"))?;

        self.route
            .create_veth(HOST_NAME, PEER_NAME, VETH_MTU)
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::EINVAL) {
                    DataplaneError::new(
                        "veth_mtu_rejected",
                        "the kernel rejected RTM_NEWLINK for MTU 65535",
                    )
                } else if error.raw_os_error() == Some(libc::EEXIST) {
                    DataplaneError::new(
                        "veth_conflict:flxrs0 already exists",
                        "RTM_NEWLINK CREATE|EXCL reported EEXIST",
                    )
                } else {
                    DataplaneError::io("veth_create", error)
                }
            })?;

        let created = self
            .route
            .dump_links()
            .map_err(|e| DataplaneError::io("link_dump", e))?;
        let host = created.iter().find(|link| link.name == HOST_NAME);
        let peer = created.iter().find(|link| link.name == PEER_NAME);
        let (host_ifindex, peer_ifindex) = match (host, peer) {
            (Some(host), Some(peer))
                if host.kind.as_deref() == Some("veth")
                    && peer.kind.as_deref() == Some("veth")
                    && host.peer_ifindex == Some(peer.ifindex)
                    && peer.peer_ifindex == Some(host.ifindex)
                    && host.master_ifindex.is_none()
                    && peer.master_ifindex.is_none()
                    && host.mtu == VETH_MTU
                    && peer.mtu == VETH_MTU =>
            {
                (host.ifindex, peer.ifindex)
            }
            _ => {
                // RTM_NEWLINK CREATE|EXCL succeeded in this function, so an
                // object at the returned host name is the just-created pair.
                if let Some(host) = host {
                    let _ = self.route.delete_link(host.ifindex);
                }
                return Err(DataplaneError::new(
                    "veth_layout_failed",
                    format!(
                        "the created pair was not an owned reciprocal veth: host={host:?}, peer={peer:?}"
                    ),
                ));
            }
        };

        // Blueprint §8.9.1 requires aliases to be set after pair creation.
        // Android 5.15 silently ignores IFLA_IFALIAS attributes carried in the
        // create request, so both markers deliberately use indexed SETLINK.
        if let Err(error) = self.route.set_link_alias(host_ifindex, HOST_ALIAS) {
            self.rollback_created(host_ifindex, lo_ifindex);
            return Err(DataplaneError::io("veth_host_alias", error));
        }
        if let Err(error) = self.route.set_link_alias(peer_ifindex, PEER_ALIAS) {
            self.rollback_created(host_ifindex, lo_ifindex);
            return Err(DataplaneError::io("veth_peer_alias", error));
        }

        if let Err(error) = self.finish_topology(host_ifindex, peer_ifindex, lo_ifindex) {
            self.rollback_created(host_ifindex, lo_ifindex);
            return Err(error);
        }

        let after = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        if topology_state(&after)? != TopologyState::Complete {
            self.rollback_created(host_ifindex, lo_ifindex);
            return Err(DataplaneError::new(
                "topology_verify_failed",
                "post-create dump did not match the exact Flux topology",
            ));
        }
        Ok(())
    }

    fn finish_topology(
        &mut self,
        host_ifindex: u32,
        peer_ifindex: u32,
        lo_ifindex: u32,
    ) -> Result<(), DataplaneError> {
        // Set address generation before IFF_UP. Otherwise the kernel creates
        // an IPv6 link-local address immediately and the addressless veth
        // contract is already violated before convergence can inspect it.
        write_veth_sysctls()?;

        self.route
            .set_link_up(host_ifindex)
            .map_err(|e| DataplaneError::io("veth_host_up", e))?;
        self.route
            .set_link_up(peer_ifindex)
            .map_err(|e| DataplaneError::io("veth_peer_up", e))?;

        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            self.route
                .add_local_route(family, ROUTE_TABLE, ROUTE_PROTOCOL, lo_ifindex)
                .map_err(|e| DataplaneError::io("route_create", e))?;
            self.route
                .add_rule(family, RULE_PRIORITY, ROUTE_TABLE, PEER_NAME)
                .map_err(|e| DataplaneError::io("rule_create", e))?;
        }

        match self.route.create_clsact(peer_ifindex) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                let qdiscs = self
                    .route
                    .dump_qdiscs()
                    .map_err(|e| DataplaneError::io("qdisc_dump", e))?;
                if !qdiscs.iter().any(|qdisc| exact_clsact(qdisc, peer_ifindex)) {
                    return Err(DataplaneError::new(
                        "clsact_conflict:flxrs1",
                        "the peer clsact slot exists but is not an exact local clsact",
                    ));
                }
            }
            Err(error) => return Err(DataplaneError::io("clsact_create", error)),
        }
        Ok(())
    }

    fn rollback_created(&mut self, host_ifindex: u32, lo_ifindex: u32) {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let _ = self
                .route
                .delete_rule(family, RULE_PRIORITY, ROUTE_TABLE, PEER_NAME);
            let _ = self
                .route
                .delete_local_route(family, ROUTE_TABLE, ROUTE_PROTOCOL, lo_ifindex);
        }
        let _ = self.route.delete_link(host_ifindex);
    }

    fn admit_interfaces(&mut self) -> Result<Vec<IfaceStatus>, DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        let mut candidates = snapshot
            .links
            .iter()
            .filter(|link| is_potential_candidate(link, &snapshot))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|link| link.ifindex);
        if candidates.len() > MAX_INTERFACES {
            return Err(DataplaneError::new(
                format!("too_many_interfaces:{}", candidates.len()),
                "the topology candidate exceeds the 64-interface hard limit",
            ));
        }

        let mut statuses = Vec::with_capacity(candidates.len());
        for link in candidates {
            statuses.push(self.admit_one(link, &snapshot));
        }
        Ok(statuses)
    }

    fn admit_one(&mut self, link: &netlink::Link, snapshot: &NetworkSnapshot) -> IfaceStatus {
        let mut status = IfaceStatus {
            name: link.name.clone(),
            ifindex: link.ifindex,
            arphrd: arphrd_name(link.arphrd).map(str::to_string),
            entry: None,
            status: "excluded".to_string(),
            prog_id: None,
            prog_tag: None,
            first_applicable: None,
            reason: None,
        };

        if excluded_kind(link.kind.as_deref()) || link.master_ifindex.is_some() {
            status.reason = Some("unsupported_link_type".to_string());
            return status;
        }
        if !has_default_route(link.ifindex, snapshot) {
            status.reason = Some("not_upstream".to_string());
            return status;
        }

        let entry = match link.arphrd {
            1 => "flx_cap_l2",
            519 | 0xfffe => "flx_cap_l3",
            _ => {
                status.reason = Some("unsupported_arphrd".to_string());
                return status;
            }
        };

        let clsact = snapshot
            .qdiscs
            .iter()
            .find(|qdisc| qdisc.ifindex == link.ifindex && qdisc.kind.as_deref() == Some("clsact"));
        let Some(clsact) = clsact else {
            // Physical clsact belongs to netd. Flux never creates it.
            status.reason = Some("netd_clsact_missing".to_string());
            return status;
        };
        if clsact.ingress_block || clsact.egress_block || clsact.options_nonempty {
            status.reason = Some("clsact_shared_block".to_string());
            return status;
        }
        if clsact.unknown_attrs || clsact.duplicate_attrs {
            status.reason = Some("clsact_foreign".to_string());
            return status;
        }

        match RouteNetlink::if_nametoindex(&link.name) {
            Ok(current) if current == link.ifindex => {}
            _ => {
                status.reason = Some("interface_reused".to_string());
                return status;
            }
        }

        let filters = match self.route.dump_filters(link.ifindex, netlink::TC_H_EGRESS) {
            Ok(filters) => filters,
            Err(_) => {
                status.reason = Some("tc_dump_failed".to_string());
                status.first_applicable = Some(false);
                return status;
            }
        };
        let Some(pref) = select_pref(link, &filters) else {
            status.reason = Some(
                if link.name.starts_with("v4-") {
                    "clat_order_unverified"
                } else {
                    "tc_no_usable_pref"
                }
                .to_string(),
            );
            return status;
        };

        status.entry = Some(entry.to_string());
        status.status = "admitted".to_string();
        status.first_applicable = Some(
            filters
                .iter()
                .filter(|filter| filter.chain == 0)
                .all(|filter| filter.priority >= pref),
        );
        status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupPlan {
    host_ifindex: Option<u32>,
    lo_ifindex: u32,
    rule_families: Vec<u8>,
    route_families: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologyState {
    Absent,
    Complete,
    OwnedDrift,
}

fn topology_state(snapshot: &NetworkSnapshot) -> Result<TopologyState, DataplaneError> {
    let pair = classify_pair(snapshot)?;
    let Some((host, peer)) = pair else {
        reject_policy_conflicts(snapshot)?;
        let has_owned_policy = snapshot.rules.iter().any(is_owned_rule)
            || snapshot
                .routes
                .iter()
                .any(|route| route.table == ROUTE_TABLE && route.protocol == ROUTE_PROTOCOL);
        return Ok(if has_owned_policy {
            TopologyState::OwnedDrift
        } else {
            TopologyState::Absent
        });
    };
    reject_policy_conflicts(snapshot)?;
    let lo = link_named(snapshot, "lo")
        .map(|link| link.ifindex)
        .ok_or_else(|| DataplaneError::new("loopback_missing", "rtnetlink has no lo"))?;

    let addresses_empty = !snapshot
        .addresses
        .iter()
        .any(|address| address.ifindex == host.ifindex || address.ifindex == peer.ifindex);
    let links_exact = host.alias.as_deref() == Some(HOST_ALIAS)
        && peer.alias.as_deref() == Some(PEER_ALIAS)
        && host.mtu == VETH_MTU
        && peer.mtu == VETH_MTU
        && host.flags & netlink::IFF_UP != 0
        && peer.flags & netlink::IFF_UP != 0
        && host.master_ifindex.is_none()
        && peer.master_ifindex.is_none()
        && addresses_empty;
    let qdisc_exact = snapshot
        .qdiscs
        .iter()
        .any(|qdisc| exact_clsact(qdisc, peer.ifindex));
    let rules_exact = [libc::AF_INET as u8, libc::AF_INET6 as u8]
        .iter()
        .all(|family| {
            snapshot
                .rules
                .iter()
                .any(|rule| rule.family == *family && is_owned_rule(rule))
        });
    let routes_exact = [libc::AF_INET as u8, libc::AF_INET6 as u8]
        .iter()
        .all(|family| {
            snapshot
                .routes
                .iter()
                .any(|route| route.family == *family && is_owned_route(route, lo))
        });
    if links_exact && qdisc_exact && rules_exact && routes_exact {
        Ok(TopologyState::Complete)
    } else {
        Ok(TopologyState::OwnedDrift)
    }
}

fn classify_pair(
    snapshot: &NetworkSnapshot,
) -> Result<Option<(&netlink::Link, &netlink::Link)>, DataplaneError> {
    let host = link_named(snapshot, HOST_NAME);
    let peer = link_named(snapshot, PEER_NAME);
    match (host, peer) {
        (None, None) => Ok(None),
        (Some(host), Some(peer))
            if host.kind.as_deref() == Some("veth")
                && peer.kind.as_deref() == Some("veth")
                && host.alias.as_deref() == Some(HOST_ALIAS)
                && peer.alias.as_deref() == Some(PEER_ALIAS)
                && host.peer_ifindex == Some(peer.ifindex)
                && peer.peer_ifindex == Some(host.ifindex)
                && host.master_ifindex.is_none()
                && peer.master_ifindex.is_none() =>
        {
            Ok(Some((host, peer)))
        }
        (Some(host), _) if host.alias.as_deref() != Some(HOST_ALIAS) => Err(DataplaneError::new(
            "veth_conflict:flxrs0 alias mismatch",
            format!("{HOST_NAME} exists with alias {:?}", host.alias),
        )),
        (_, Some(peer)) if peer.alias.as_deref() != Some(PEER_ALIAS) => Err(DataplaneError::new(
            "veth_conflict:flxrs1 alias mismatch",
            format!("{PEER_NAME} exists with alias {:?}", peer.alias),
        )),
        _ => Err(DataplaneError::new(
            "veth_conflict:layout mismatch",
            "the reserved names do not form the exact owned veth pair",
        )),
    }
}

fn reject_policy_conflicts(snapshot: &NetworkSnapshot) -> Result<(), DataplaneError> {
    for rule in snapshot
        .rules
        .iter()
        .filter(|rule| rule.priority == Some(RULE_PRIORITY))
    {
        if !is_owned_rule(rule) {
            return Err(DataplaneError::new(
                "rule_conflict:priority 100 occupied",
                format!("foreign rule: {rule:?}"),
            ));
        }
    }
    let lo = link_named(snapshot, "lo").map(|link| link.ifindex);
    for route in snapshot
        .routes
        .iter()
        .filter(|route| route.table == ROUTE_TABLE)
    {
        if lo.is_none_or(|lo| !is_owned_route(route, lo)) {
            return Err(DataplaneError::new(
                "route_table_conflict:20260",
                format!("foreign route: {route:?}"),
            ));
        }
    }
    Ok(())
}

fn is_owned_rule(rule: &netlink::Rule) -> bool {
    matches!(rule.family as i32, libc::AF_INET | libc::AF_INET6)
        && rule.dst_len == 0
        && rule.src_len == 0
        && rule.table == ROUTE_TABLE
        && rule.action == 1
        && rule.priority == Some(RULE_PRIORITY)
        && rule.iif_name.as_deref() == Some(PEER_NAME)
        && rule.suppress_prefix_len == Some(u32::MAX)
        && rule.protocol == Some(0)
        && !rule.extra_attrs
}

fn is_owned_route(route: &netlink::Route, lo_ifindex: u32) -> bool {
    matches!(route.family as i32, libc::AF_INET | libc::AF_INET6)
        && route.dst_len == 0
        && route.table == ROUTE_TABLE
        && route.protocol == ROUTE_PROTOCOL
        && route.kind == 2
        && route.oif == Some(lo_ifindex)
        && !route.has_dst
        && match route.family as i32 {
            libc::AF_INET => {
                route.scope == 254 && route.metric.is_none() && route.preference.is_none()
            }
            libc::AF_INET6 => {
                route.scope == 0 && route.metric == Some(1_024) && route.preference == Some(0)
            }
            _ => false,
        }
        && !route.extra_attrs
}

fn exact_clsact(qdisc: &netlink::Qdisc, ifindex: u32) -> bool {
    qdisc.ifindex == ifindex
        && qdisc.handle == netlink::TC_CLSACT_HANDLE
        && qdisc.parent == netlink::TC_H_CLSACT
        && qdisc.kind.as_deref() == Some("clsact")
        && !qdisc.options_nonempty
        && !qdisc.ingress_block
        && !qdisc.egress_block
        && !qdisc.unknown_attrs
        && !qdisc.duplicate_attrs
}

fn link_named<'a>(snapshot: &'a NetworkSnapshot, name: &str) -> Option<&'a netlink::Link> {
    snapshot.links.iter().find(|link| link.name == name)
}

fn is_potential_candidate(link: &netlink::Link, snapshot: &NetworkSnapshot) -> bool {
    link.name != "lo"
        && link.name != HOST_NAME
        && link.name != PEER_NAME
        && link.flags & netlink::IFF_UP != 0
        && link.flags & netlink::IFF_LOOPBACK == 0
        && snapshot.addresses.iter().any(|address| {
            address.ifindex == link.ifindex
                && address.scope == RT_SCOPE_UNIVERSE
                && matches!(address.family as i32, libc::AF_INET | libc::AF_INET6)
        })
}

fn has_default_route(ifindex: u32, snapshot: &NetworkSnapshot) -> bool {
    snapshot.routes.iter().any(|route| {
        route.oif == Some(ifindex)
            && route.dst_len == 0
            && !route.has_dst
            && route.kind == RTN_UNICAST
    })
}

fn excluded_kind(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "tun"
                | "tap"
                | "bridge"
                | "bond"
                | "veth"
                | "dummy"
                | "team"
                | "ifb"
                | "vlan"
                | "vrf"
                | "wireguard"
                | "ipip"
                | "sit"
                | "gre"
                | "gretap"
                | "erspan"
        )
    )
}

fn select_pref(link: &netlink::Link, filters: &[Filter]) -> Option<u16> {
    let chain_zero = filters.iter().filter(|filter| filter.chain == 0);
    let occupied: BTreeSet<u16> = chain_zero.clone().map(|filter| filter.priority).collect();
    if link.name.starts_with("v4-") {
        // CLAT requires a recognizable AOSP filter and a slot before its
        // actual dump position. Never infer the position from a constant.
        let clat_pref = chain_zero
            .filter(|filter| {
                filter
                    .prog_name
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().contains("clat"))
            })
            .map(|filter| filter.priority)
            .min()?;
        (TC_PREF_PREFERRED..clat_pref.min(TC_PREF_CLAT_MAX)).find(|pref| !occupied.contains(pref))
    } else {
        (TC_PREF_PREFERRED..=u16::MAX).find(|pref| !occupied.contains(pref))
    }
}

fn arphrd_name(arphrd: u16) -> Option<&'static str> {
    match arphrd {
        1 => Some("ether"),
        519 => Some("rawip"),
        0xfffe => Some("none"),
        _ => None,
    }
}

fn write_veth_sysctls() -> Result<(), DataplaneError> {
    for (path, value) in [
        ("/proc/sys/net/ipv6/conf/flxrs0/addr_gen_mode", "1\n"),
        ("/proc/sys/net/ipv6/conf/flxrs1/addr_gen_mode", "1\n"),
        ("/proc/sys/net/ipv4/conf/flxrs1/rp_filter", "0\n"),
        ("/proc/sys/net/ipv4/conf/flxrs1/accept_local", "1\n"),
        ("/proc/sys/net/ipv6/conf/flxrs1/accept_ra", "0\n"),
        ("/proc/sys/net/ipv6/conf/flxrs1/autoconf", "0\n"),
    ] {
        fs::write(path, value).map_err(|error| {
            DataplaneError::io(
                path.rsplit('/').next().unwrap_or("peer_sysctl_write"),
                error,
            )
        })?;
    }
    Ok(())
}

fn read_status_sysctls() -> BTreeMap<String, i64> {
    let mut values = BTreeMap::new();
    for (name, path) in [
        ("all.rp_filter", "/proc/sys/net/ipv4/conf/all/rp_filter"),
        (
            "flxrs1.rp_filter",
            "/proc/sys/net/ipv4/conf/flxrs1/rp_filter",
        ),
        (
            "flxrs1.accept_local",
            "/proc/sys/net/ipv4/conf/flxrs1/accept_local",
        ),
        (
            "flxrs1.accept_ra",
            "/proc/sys/net/ipv6/conf/flxrs1/accept_ra",
        ),
        ("flxrs1.autoconf", "/proc/sys/net/ipv6/conf/flxrs1/autoconf"),
    ] {
        if let Ok(value) = fs::read_to_string(path) {
            if let Ok(value) = value.trim().parse::<i64>() {
                values.insert(name.to_string(), value);
            }
        }
    }
    values
}

fn validate_rp_filter(values: &BTreeMap<String, i64>) -> Result<(), DataplaneError> {
    match values.get("all.rp_filter").copied() {
        Some(0) => Ok(()),
        Some(value) => Err(DataplaneError::new(
            format!("rp_filter_conflict:all={value}"),
            "effective rp_filter is max(all, interface); Flux never writes the global value",
        )),
        None => Err(DataplaneError::new(
            "rp_filter_read_failed",
            "cannot read /proc/sys/net/ipv4/conf/all/rp_filter",
        )),
    }
}

fn ignore_absent(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        other => other,
    }
}

fn errno_name(errno: i32) -> String {
    match errno {
        libc::EACCES => "EACCES".to_string(),
        libc::EEXIST => "EEXIST".to_string(),
        libc::EINVAL => "EINVAL".to_string(),
        libc::ENODEV => "ENODEV".to_string(),
        libc::ENOENT => "ENOENT".to_string(),
        libc::ENOSPC => "ENOSPC".to_string(),
        libc::EPERM => "EPERM".to_string(),
        libc::ESTALE => "ESTALE".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str) -> netlink::Link {
        netlink::Link {
            ifindex: 7,
            name: name.to_string(),
            alias: None,
            kind: None,
            peer_ifindex: None,
            master_ifindex: None,
            arphrd: 1,
            flags: netlink::IFF_UP,
            mtu: 1500,
            address: vec![0; 6],
            unknown_attrs: false,
            duplicate_attrs: false,
        }
    }

    fn filter(pref: u16, name: &str) -> Filter {
        Filter {
            ifindex: 7,
            parent: netlink::TC_H_EGRESS,
            handle: 1,
            chain: 0,
            priority: pref,
            protocol: netlink::ETH_P_ALL,
            kind: Some("bpf".to_string()),
            direct_action: true,
            prog_id: Some(1),
            prog_tag: Some([0; 8]),
            prog_name: Some(name.to_string()),
            flags_gen: Some(0),
            unknown_attrs: false,
            duplicate_attrs: false,
        }
    }

    #[test]
    fn pref_is_selected_per_interface_and_never_uses_one() {
        assert_eq!(select_pref(&link("wlan0"), &[filter(1, "oem")]), Some(2));
        assert_eq!(
            select_pref(&link("wlan0"), &[filter(1, "oem"), filter(2, "oem2")]),
            Some(3)
        );
        let mut other_chain = filter(2, "other-chain");
        other_chain.chain = 7;
        assert_eq!(
            select_pref(&link("wlan0"), &[filter(1, "oem"), other_chain]),
            Some(2)
        );
    }

    #[test]
    fn clat_requires_a_recognizable_filter_and_a_slot_before_it() {
        assert_eq!(select_pref(&link("v4-rmnet0"), &[]), None);
        assert_eq!(
            select_pref(&link("v4-rmnet0"), &[filter(4, "prog_clat_egress")]),
            Some(2)
        );
        let mut other_chain_clat = filter(4, "prog_clat_egress");
        other_chain_clat.chain = 1;
        assert_eq!(select_pref(&link("v4-rmnet0"), &[other_chain_clat]), None);
        assert_eq!(
            select_pref(
                &link("v4-rmnet0"),
                &[
                    filter(2, "oem"),
                    filter(3, "oem2"),
                    filter(4, "prog_clat_egress")
                ]
            ),
            None
        );
    }

    #[test]
    fn owned_pair_remains_identifiable_when_address_state_drifts() {
        let mut host = link(HOST_NAME);
        host.ifindex = 60;
        host.alias = Some(HOST_ALIAS.to_string());
        host.kind = Some("veth".to_string());
        host.peer_ifindex = Some(59);
        let mut peer = link(PEER_NAME);
        peer.ifindex = 59;
        peer.alias = Some(PEER_ALIAS.to_string());
        peer.kind = Some("veth".to_string());
        peer.peer_ifindex = Some(60);
        let mut lo = link("lo");
        lo.ifindex = 1;
        lo.flags |= netlink::IFF_LOOPBACK;
        let snapshot = NetworkSnapshot {
            links: vec![lo, host, peer],
            addresses: vec![netlink::Address {
                ifindex: 60,
                family: libc::AF_INET6 as u8,
                prefix_len: 64,
                scope: 253,
                bytes: vec![0xfe, 0x80],
            }],
            ..NetworkSnapshot::default()
        };

        assert!(classify_pair(&snapshot).unwrap().is_some());
        assert_eq!(
            topology_state(&snapshot).unwrap(),
            TopologyState::OwnedDrift
        );
    }

    #[test]
    fn global_rp_filter_is_checked_without_ever_being_changed() {
        let mut values = BTreeMap::new();
        assert_eq!(
            validate_rp_filter(&values).unwrap_err().code,
            "rp_filter_read_failed"
        );
        values.insert("all.rp_filter".to_string(), 1);
        assert_eq!(
            validate_rp_filter(&values).unwrap_err().code,
            "rp_filter_conflict:all=1"
        );
        values.insert("all.rp_filter".to_string(), 0);
        assert!(validate_rp_filter(&values).is_ok());
    }

    #[test]
    fn android_kernel_rule_and_route_defaults_are_owned_exactly() {
        let rule = netlink::Rule {
            family: libc::AF_INET as u8,
            dst_len: 0,
            src_len: 0,
            table: ROUTE_TABLE,
            action: 1,
            priority: Some(RULE_PRIORITY),
            iif_name: Some(PEER_NAME.to_string()),
            suppress_prefix_len: Some(u32::MAX),
            protocol: Some(0),
            extra_attrs: false,
            extra_attr_kinds: Vec::new(),
        };
        assert!(is_owned_rule(&rule));
        let mut changed = rule.clone();
        changed.protocol = Some(3);
        assert!(!is_owned_rule(&changed));

        let v4 = netlink::Route {
            family: libc::AF_INET as u8,
            dst_len: 0,
            table: ROUTE_TABLE,
            protocol: ROUTE_PROTOCOL,
            scope: 254,
            kind: 2,
            oif: Some(1),
            has_dst: false,
            metric: None,
            preference: None,
            extra_attrs: false,
            extra_attr_kinds: Vec::new(),
        };
        assert!(is_owned_route(&v4, 1));
        let v6 = netlink::Route {
            family: libc::AF_INET6 as u8,
            scope: 0,
            metric: Some(1_024),
            preference: Some(0),
            ..v4.clone()
        };
        assert!(is_owned_route(&v6, 1));
        let mut changed = v6;
        changed.metric = Some(1_023);
        assert!(!is_owned_route(&changed, 1));
    }
}
