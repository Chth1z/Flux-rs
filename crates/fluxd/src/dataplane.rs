//! Network object lifecycle, control leaf publication and interface admission.
//!
//! Implements blueprint §8. Phase 3 covers veth, route/RPDB, clsact ownership,
//! interface admission and `rp_filter` preconditions. BPF program attach remains
//! Phase 5; the loader remains Phase 4.

use std::io;

use flux_core::abi;
use flux_core::control_wire::IfaceStatus;

use crate::netlink::admission;
use crate::netlink::link;
use crate::netlink::route;
use crate::netlink::rule;
use crate::netlink::sysctl;
use crate::netlink::tc::{self, ClsactState, EGRESS_PARENT, INGRESS_PARENT};

/// Outcome of the §8.4 `all.rp_filter` gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpFilterGate {
    Ok,
    Blocked(i64),
    Unreadable(String),
}

/// Preconditions and owned kernel objects for one activation attempt.
#[derive(Debug)]
pub struct DataplaneSnapshot {
    pub rp_filter: RpFilterGate,
    pub veth_host_index: Option<i32>,
    pub veth_peer_index: Option<i32>,
    pub peer_clsact: Option<ClsactState>,
    pub interfaces: Vec<IfaceStatus>,
}

impl DataplaneSnapshot {
    /// Read-only probe used by `status` and `check` before any mutation.
    pub fn probe(seq: u32) -> io::Result<Self> {
        let rp = match sysctl::all_rp_filter() {
            Ok(0) => RpFilterGate::Ok,
            Ok(v) => RpFilterGate::Blocked(v),
            Err(e) => RpFilterGate::Unreadable(e.to_string()),
        };
        let indices = link::find_veth_indices(seq)?;
        let peer_clsact = if let Some((_, peer)) = indices {
            if tc::has_clsact(seq + 10, peer).unwrap_or(false) {
                tc::dump_clsact_attrs(seq + 11, peer)
                    .map(|a| {
                        if a.is_foreign() {
                            ClsactState::Foreign
                        } else {
                            ClsactState::Present
                        }
                    })
                    .ok()
            } else {
                None
            }
        } else {
            None
        };
        let interfaces = admission::evaluate_interfaces(seq + 20)?
            .into_iter()
            .map(|(_, st)| st)
            .collect();
        Ok(Self {
            rp_filter: rp,
            veth_host_index: indices.map(|(h, _)| h),
            veth_peer_index: indices.map(|(_, p)| p),
            peer_clsact,
            interfaces,
        })
    }

    /// §8.7 steps 2–4 subset: cleanup leftovers, then create veth, routes, rules,
    /// peer ingress clsact, and per-interface sysctl on `flxrs1`.
    pub fn install_base_objects(seq: u32) -> io::Result<(i32, i32)> {
        Self::cleanup_leftovers(seq)?;
        match sysctl::all_rp_filter()? {
            0 => {}
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("all.rp_filter={v} blocks activation (§8.4)"),
                ));
            }
        }
        link::create_veth_pair(seq)?;
        let (host, peer) = link::find_veth_indices(seq + 1)?.unwrap_or((0, 0));
        link::set_alias(seq + 2, host, abi::VETH_HOST_ALIAS)?;
        link::set_alias(seq + 3, peer, abi::VETH_PEER_ALIAS)?;
        link::set_link_up(seq + 4, host)?;
        link::set_link_up(seq + 5, peer)?;
        route::install_table_routes(seq + 6)?;
        rule::install_rules(seq + 7)?;
        if matches!(tc::ensure_clsact(seq + 8, peer)?, ClsactState::Foreign) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "flxrs1 clsact is foreign",
            ));
        }
        sysctl::write_iface_ipv4_conf(abi::VETH_PEER, "rp_filter", 0)?;
        sysctl::write_iface_ipv4_conf(abi::VETH_PEER, "accept_local", 1)?;
        Ok((host, peer))
    }

    /// Removes Flux-owned objects (§8.7 step 2 / §8.8).
    pub fn cleanup_leftovers(seq: u32) -> io::Result<()> {
        let _ = rule::remove_rules(seq);
        let _ = route::remove_table_routes(seq);
        if let Ok(Some((host, peer))) = link::find_veth_indices(seq + 1) {
            let _ = link::delete_link(seq + 2, host);
            let _ = link::delete_link(seq + 3, peer);
        }
        Ok(())
    }

    /// Returns egress/ingress filter dumps for diagnostics (Phase 5 status).
    #[allow(dead_code)]
    pub fn dump_flux_tc(
        seq: u32,
        ifindex: i32,
    ) -> io::Result<(Vec<tc::TcFilterInfo>, Vec<tc::TcFilterInfo>)> {
        let egress = tc::dump_filters(seq, ifindex, EGRESS_PARENT)?;
        let ingress = tc::dump_filters(seq + 1, ifindex, INGRESS_PARENT)?;
        Ok((egress, ingress))
    }
}

#[cfg(test)]
mod netlink_lifecycle_tests {
    use super::*;

    #[test]
    fn veth_routes_rules_clsact_in_netns() {
        // SAFETY: unshare into a new network namespace for an isolated test.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            eprintln!("SKIP veth_routes_rules_clsact_in_netns — unshare failed");
            return;
        }
        let lo = crate::netlink::link::if_nametoindex("lo").expect("lo");
        crate::netlink::link::set_link_up(1, lo).expect("lo up");
        let seq = 900u32;
        DataplaneSnapshot::cleanup_leftovers(seq).expect("preclean");
        let (host, peer) =
            DataplaneSnapshot::install_base_objects(seq + 1).expect("install base objects");
        assert!(host > 0 && peer > 0);
        assert!(crate::netlink::tc::has_clsact(seq + 50, peer).expect("clsact"));
        DataplaneSnapshot::cleanup_leftovers(seq + 100).expect("cleanup");
        assert!(crate::netlink::link::find_veth_indices(seq + 101)
            .expect("find")
            .is_none());
    }
}
