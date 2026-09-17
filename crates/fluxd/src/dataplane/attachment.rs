//! Clsact attach, liveness probe, and identity predicate (blueprint §12.5.1).
//!
//! This revision implements only the clsact path. A later 6.6+ TCX path
//! replaces the internals of this file — `BPF_F_BEFORE`, fall back to
//! clsact if the kernel rejects the anchor, never append-only TCX — without
//! a `trait Attach` while only one adapter exists, and without changing the
//! four BPF programs or the map set. Ownership is still proven from a kernel
//! dump, never from `attached: Vec` alone.

use std::collections::BTreeSet;
use std::fs;

use flux_core::abi::{self, Counter};
use flux_core::control_wire::IfaceStatus;

use crate::bpf::{self, ProgramIdentity};
use crate::netlink::{self, Filter, FilterIdentity, NetworkSnapshot, RouteNetlink, TcAttach};

use super::{
    expected_stale_filter, tc_filter_conflict, AttachmentProgress, AttachmentState, DataplaneError,
    FilterSlot, Manager, OwnedFilter, Verification, HOST_NAME, PEER_NAME, TC_PREF_CLAT_MAX,
    TC_PREF_PREFERRED, TC_VERIFY_MAX_ATTEMPTS, TC_VERIFY_WINDOW,
};

impl Manager {
    /// Starts §8.7 steps 8-9. The caller arms a timerfd for every `Wait` and
    /// calls `advance_attachment` when it expires; the reactor never sleeps.
    pub fn begin_attachment(&mut self) -> Result<AttachmentProgress, DataplaneError> {
        if self.test_bypass {
            self.status.attachment_ready = true;
            return Ok(AttachmentProgress::Complete);
        }
        if self.status.attachment_ready {
            return Ok(AttachmentProgress::Complete);
        }
        if let Some(verification) = self
            .attachment
            .as_ref()
            .and_then(|state| state.verifying.as_ref())
        {
            return Ok(AttachmentProgress::Wait(verification.wait));
        }
        if !self.status.topology_ready || !self.status.bpf_ready {
            return Err(DataplaneError::new(
                "dataplane_not_ready",
                "topology and inactive BPF runtime must exist before TC attachment",
            ));
        }

        self.ensure_ingress_attached()?;
        let pending = self
            .status
            .ifaces
            .iter()
            .filter(|iface| iface.status == "admitted")
            .cloned()
            .collect();
        self.attachment = Some(AttachmentState {
            pending,
            verifying: None,
        });
        self.start_next_verification()
    }
    pub fn attachment_in_progress(&self) -> bool {
        self.attachment.is_some()
    }
    pub fn advance_attachment(&mut self) -> Result<AttachmentProgress, DataplaneError> {
        if self.attachment.is_none() {
            return Ok(AttachmentProgress::Complete);
        }
        let verification = self
            .attachment
            .as_mut()
            .and_then(|state| state.verifying.take())
            .ok_or_else(|| {
                DataplaneError::new(
                    "tc_verify_not_pending",
                    "attachment timer fired without a live verification probe",
                )
            })?;
        let tx = match read_tx_packets(&verification.iface.name) {
            Ok(tx) => tx,
            Err(error) => {
                let _ = self.detach_recorded(
                    &verification.iface.name,
                    netlink::TC_H_EGRESS,
                    abi::TC_HANDLE_VERIFY,
                );
                self.exclude_iface(
                    &verification.iface,
                    attachment_reason(&error),
                    Some(error.to_string()),
                );
                return self.start_next_verification();
            }
        };
        let counter = match self
            .runtime
            .as_ref()
            .expect("attachment requires runtime")
            .maps()
            .counter_sum(Counter::SawPacket)
            .map_err(|error| DataplaneError::map_op("counter_read", error))
        {
            Ok(counter) => counter,
            Err(error) => {
                self.attachment
                    .as_mut()
                    .expect("attachment state retained")
                    .verifying = Some(verification);
                return Err(error);
            }
        };

        if counter > verification.baseline_counter {
            self.finish_verified_interface(verification, None);
            return self.start_next_verification();
        }
        if tx > verification.baseline_tx {
            let lower = self.lower_filter_names(&verification.iface, verification.pref);
            self.detach_recorded(
                &verification.iface.name,
                netlink::TC_H_EGRESS,
                abi::TC_HANDLE_VERIFY,
            )?;
            self.exclude_iface(
                &verification.iface,
                "tc_chain_shadowed",
                Some(format!(
                    "{} tx increased while flx_verify did not; lower-pref filters: {}",
                    verification.iface.name,
                    lower.join(", ")
                )),
            );
            return self.start_next_verification();
        }
        if verification.attempts >= TC_VERIFY_MAX_ATTEMPTS {
            self.finish_verified_interface(
                verification,
                Some("tc_verify_no_traffic: liveness could not be concluded before activation"),
            );
            return self.start_next_verification();
        }

        let mut retry = verification;
        retry.attempts += 1;
        retry.baseline_counter = counter;
        retry.baseline_tx = tx;
        let wait = TC_VERIFY_WINDOW * (1u32 << (retry.attempts - 1));
        retry.wait = wait;
        self.attachment
            .as_mut()
            .expect("attachment state retained")
            .verifying = Some(retry);
        Ok(AttachmentProgress::Wait(wait))
    }
    pub fn cancel_attachment(&mut self) -> Result<(), DataplaneError> {
        self.status.attachment_ready = false;
        let verification_ifname = self
            .attachment
            .as_ref()
            .and_then(|state| state.verifying.as_ref())
            .map(|verification| verification.iface.name.clone());
        if let Some(ifname) = verification_ifname {
            self.detach_recorded(&ifname, netlink::TC_H_EGRESS, abi::TC_HANDLE_VERIFY)?;
        }
        self.attachment = None;
        Ok(())
    }
    fn ensure_ingress_attached(&mut self) -> Result<(), DataplaneError> {
        let ifindex = RouteNetlink::if_nametoindex(PEER_NAME)
            .map_err(|error| DataplaneError::io("if_nametoindex", error))?;
        if let Some(index) = self.attached.iter().position(|filter| {
            filter.ifname == PEER_NAME
                && filter.identity.parent == netlink::TC_H_INGRESS
                && filter.identity.handle == abi::TC_HANDLE_INGRESS
        }) {
            let existing = self.attached[index].clone();
            if self.verify_owned_filter(&existing).is_ok() {
                return Ok(());
            }
            // Ingress is part of the core capture path. Freeze the public
            // control pointer before repairing anything underneath it.
            if self.status.active {
                self.publish_inactive()?;
            }
            // A netd clsact reset removes the filter underneath our process.
            // Forget the stale record and let `attach_exact` either restore
            // an empty slot or reject a foreign replacement.
            self.attached.remove(index);
        }
        if self.status.active {
            self.publish_inactive()?;
        }
        self.attach_exact(FilterSlot {
            ifname: PEER_NAME,
            ifindex,
            parent: netlink::TC_H_INGRESS,
            handle: abi::TC_HANDLE_INGRESS,
            priority: 1,
            protocol: netlink::ETH_P_ALL,
            program_name: abi::PROG_IN,
        })?;
        Ok(())
    }
    fn start_next_verification(&mut self) -> Result<AttachmentProgress, DataplaneError> {
        loop {
            let Some(iface) = self
                .attachment
                .as_mut()
                .expect("attachment state exists")
                .pending
                .pop_front()
            else {
                self.attachment = None;
                let has_active = self
                    .status
                    .ifaces
                    .iter()
                    .any(|iface| iface.status == "active");
                self.status.attachment_ready = has_active;
                if self.status.active && !has_active {
                    self.publish_inactive()?;
                }
                self.status
                    .warnings
                    .retain(|warning| !warning.contains("capture waits for engine readiness"));
                return Ok(AttachmentProgress::Complete);
            };

            match self.start_verification(iface.clone()) {
                Ok(verification) => {
                    self.attachment
                        .as_mut()
                        .expect("attachment state exists")
                        .verifying = Some(verification);
                    return Ok(AttachmentProgress::Wait(TC_VERIFY_WINDOW));
                }
                Err(error) => {
                    self.exclude_iface(&iface, attachment_reason(&error), Some(error.to_string()));
                }
            }
        }
    }
    fn start_verification(&mut self, iface: IfaceStatus) -> Result<Verification, DataplaneError> {
        let current = RouteNetlink::if_nametoindex(&iface.name)
            .map_err(|error| DataplaneError::io("if_nametoindex", error))?;
        if current != iface.ifindex {
            return Err(DataplaneError::new(
                "interface_reused",
                format!("{} changed ifindex before TC attach", iface.name),
            ));
        }
        let filters = self
            .route
            .dump_filters(current, netlink::TC_H_EGRESS)
            .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
        let link = self
            .route
            .dump_links()
            .map_err(|error| DataplaneError::io("link_dump", error))?
            .into_iter()
            .find(|link| link.ifindex == current && link.name == iface.name)
            .ok_or_else(|| DataplaneError::new("interface_reused", "link disappeared"))?;
        let pref = select_pref(&link, &filters).ok_or_else(|| {
            DataplaneError::new("tc_no_usable_pref", "no preference satisfies ordering")
        })?;
        self.attach_exact(FilterSlot {
            ifname: &iface.name,
            ifindex: current,
            parent: netlink::TC_H_EGRESS,
            handle: abi::TC_HANDLE_VERIFY,
            priority: pref,
            protocol: netlink::ETH_P_ALL,
            program_name: abi::PROG_VERIFY,
        })?;
        let baselines = (|| {
            let baseline_counter = self
                .runtime
                .as_ref()
                .expect("runtime exists")
                .maps()
                .counter_sum(Counter::SawPacket)
                .map_err(|error| DataplaneError::map_op("counter_read", error))?;
            let baseline_tx = read_tx_packets(&iface.name)?;
            Ok::<_, DataplaneError>((baseline_counter, baseline_tx))
        })();
        let (baseline_counter, baseline_tx) = match baselines {
            Ok(baselines) => baselines,
            Err(error) => {
                self.detach_recorded(&iface.name, netlink::TC_H_EGRESS, abi::TC_HANDLE_VERIFY)?;
                return Err(error);
            }
        };
        Ok(Verification {
            iface,
            pref,
            baseline_counter,
            baseline_tx,
            attempts: 1,
            wait: TC_VERIFY_WINDOW,
        })
    }
    fn finish_verified_interface(&mut self, verification: Verification, warning: Option<&str>) {
        let result = self.detach_recorded(
            &verification.iface.name,
            netlink::TC_H_EGRESS,
            abi::TC_HANDLE_VERIFY,
        );
        let result = result.and_then(|()| {
            let protocol = if verification.iface.name.starts_with("v4-") {
                0x0800
            } else {
                netlink::ETH_P_ALL
            };
            let entry = verification
                .iface
                .entry
                .as_deref()
                .ok_or_else(|| DataplaneError::new("tc_attach_failed", "entry missing"))?;
            self.attach_exact(FilterSlot {
                ifname: &verification.iface.name,
                ifindex: verification.iface.ifindex,
                parent: netlink::TC_H_EGRESS,
                handle: abi::TC_HANDLE_EGRESS,
                priority: verification.pref,
                protocol,
                program_name: entry,
            })?;
            if let Err(error) = self.record_capture_order(
                &verification.iface.name,
                verification.iface.ifindex,
                verification.pref,
            ) {
                self.detach_recorded(
                    &verification.iface.name,
                    netlink::TC_H_EGRESS,
                    abi::TC_HANDLE_EGRESS,
                )?;
                return Err(error);
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.activate_iface(&verification.iface, warning);
            }
            Err(error) => self.exclude_iface(
                &verification.iface,
                attachment_reason(&error),
                Some(error.to_string()),
            ),
        }
    }
    pub(super) fn attach_exact(
        &mut self,
        slot: FilterSlot<'_>,
    ) -> Result<OwnedFilter, DataplaneError> {
        let FilterSlot {
            ifname,
            ifindex,
            parent,
            handle,
            priority,
            protocol,
            program_name,
        } = slot;
        if RouteNetlink::if_nametoindex(ifname).ok() != Some(ifindex) {
            return Err(DataplaneError::new(
                "interface_reused",
                format!("{ifname} changed before RTM_NEWTFILTER"),
            ));
        }
        let runtime = self.runtime.as_ref().ok_or_else(|| {
            DataplaneError::new("bpf_runtime_missing", "cannot attach without runtime")
        })?;
        let program = runtime.program_identity(program_name).ok_or_else(|| {
            DataplaneError::new("prog_identity_mismatch", format!("{program_name} absent"))
        })?;
        let before = self
            .route
            .dump_filters(ifindex, parent)
            .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
        if before.iter().any(|filter| {
            filter.handle == handle
                && filter.chain == abi::TC_CHAIN
                && filter.priority == priority
                && filter.protocol == protocol
        }) {
            return Err(DataplaneError::new(
                "tc_no_usable_pref",
                format!("{ifname} TC identity is already occupied"),
            ));
        }
        self.route
            .attach_filter(TcAttach {
                ifindex,
                parent,
                handle,
                chain: abi::TC_CHAIN,
                priority,
                protocol,
                program_fd: runtime
                    .program_fd(program_name)
                    .expect("identity and fd share a table"),
                program_name,
            })
            .map_err(|error| DataplaneError::io("tc_attach_failed", error))?;

        let owned = self.record_attached_filter(slot, &program)?;
        self.verify_owned_filter(&owned)?;
        self.attached.push(owned.clone());
        Ok(owned)
    }
    fn record_attached_filter(
        &mut self,
        slot: FilterSlot<'_>,
        program: &ProgramIdentity,
    ) -> Result<OwnedFilter, DataplaneError> {
        let FilterSlot {
            ifname,
            ifindex,
            parent,
            handle,
            priority,
            protocol,
            ..
        } = slot;
        let filters = self
            .route
            .dump_filters(ifindex, parent)
            .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
        let mut matches = filters.iter().filter_map(|filter| {
            let flags_gen = filter.flags_gen?;
            let identity = filter_identity(
                ifindex, parent, handle, priority, protocol, program, flags_gen,
            );
            identity.matches(filter).then_some(identity)
        });
        let Some(identity) = matches.next() else {
            return Err(DataplaneError::new(
                "identity_drift",
                format!(
                    "{ifname} attached filter did not expose a complete identity: dump={filters:?}"
                ),
            ));
        };
        if matches.next().is_some() {
            return Err(DataplaneError::new(
                "identity_drift",
                format!("{ifname} attached filter identity was not unique"),
            ));
        }
        if !bpf::attached_program_owned(program.id, &program.name, program.tag)
            .map_err(DataplaneError::bpf)?
        {
            return Err(DataplaneError::new(
                "identity_drift",
                format!("{ifname} attached program map set is foreign"),
            ));
        }
        Ok(OwnedFilter {
            ifname: ifname.to_string(),
            identity,
            lower_filters: Vec::new(),
        })
    }
    fn record_capture_order(
        &mut self,
        ifname: &str,
        ifindex: u32,
        pref: u16,
    ) -> Result<(), DataplaneError> {
        let filters = self
            .route
            .dump_filters(ifindex, netlink::TC_H_EGRESS)
            .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
        let lower = lower_filter_snapshot(&filters, pref);
        let owned = self
            .attached
            .iter_mut()
            .find(|owned| {
                owned.ifname == ifname
                    && owned.identity.parent == netlink::TC_H_EGRESS
                    && owned.identity.handle == abi::TC_HANDLE_EGRESS
                    && owned.identity.priority == pref
            })
            .ok_or_else(|| {
                DataplaneError::new(
                    "identity_drift",
                    format!("{ifname} capture record disappeared after attach"),
                )
            })?;
        owned.lower_filters = lower;
        Ok(())
    }
    pub(super) fn verify_owned_filter(
        &mut self,
        owned: &OwnedFilter,
    ) -> Result<(), DataplaneError> {
        if RouteNetlink::if_nametoindex(&owned.ifname).ok() != Some(owned.identity.ifindex) {
            return Err(DataplaneError::new(
                "interface_reused",
                format!("{} changed before filter verification", owned.ifname),
            ));
        }
        let filters = self
            .route
            .dump_filters(owned.identity.ifindex, owned.identity.parent)
            .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
        let Some(filter) = filters.iter().find(|filter| owned.identity.matches(filter)) else {
            return Err(DataplaneError::new(
                "identity_drift",
                format!(
                    "{} attached filter identity did not round-trip: expected={:?}, dump={filters:?}",
                    owned.ifname, owned.identity
                ),
            ));
        };
        if !bpf::attached_program_owned(
            filter.prog_id.expect("identity requires id"),
            filter.prog_name.as_deref().expect("identity requires name"),
            filter.prog_tag.expect("identity requires tag"),
        )
        .map_err(DataplaneError::bpf)?
        {
            return Err(DataplaneError::new(
                "identity_drift",
                format!("{} attached program map set is foreign", owned.ifname),
            ));
        }
        Ok(())
    }
    pub(super) fn detach_recorded(
        &mut self,
        ifname: &str,
        parent: u32,
        handle: u32,
    ) -> Result<(), DataplaneError> {
        let Some(index) = self.attached.iter().position(|filter| {
            filter.ifname == ifname
                && filter.identity.parent == parent
                && filter.identity.handle == handle
        }) else {
            return Ok(());
        };
        let owned = self.attached[index].clone();
        self.detach_identity(&owned)?;
        self.attached.remove(index);
        Ok(())
    }
    /// Deletes one recorded filter, if there is still one of ours to delete.
    ///
    /// A record the dump no longer backs is not a failure. §8.5.1: netd deletes
    /// a physical `clsact` every time an interface joins or leaves a network,
    /// which takes the filter underneath it along, so every Wi-Fi handover
    /// empties a slot Flux still has written down. The slot being occupied by
    /// something that is not ours reaches the same conclusion by the rule that
    /// Flux deletes only exact matches: whatever is there, our filter is not.
    /// Reporting either as an error escalates capture-side drift into a global
    /// transaction, which §26 invariant 4 forbids.
    pub(super) fn detach_identity(&mut self, owned: &OwnedFilter) -> Result<(), DataplaneError> {
        let Some(first) = self.dump_recorded_parent(owned)? else {
            return Ok(());
        };
        let Some(second) = self.dump_recorded_parent(owned)? else {
            return Ok(());
        };
        if first != second {
            return Err(DataplaneError::new(
                "tc_filter:ESTALE",
                format!(
                    "{} filter identity changed across the double dump",
                    owned.ifname
                ),
            ));
        }
        let Some(filter) = second.iter().find(|filter| owned.identity.matches(filter)) else {
            return Ok(());
        };
        if !bpf::attached_program_owned(
            filter.prog_id.expect("identity requires id"),
            filter.prog_name.as_deref().expect("identity requires name"),
            filter.prog_tag.expect("identity requires tag"),
        )
        .map_err(DataplaneError::bpf)?
        {
            return Err(DataplaneError::new(
                "tc_filter:ESTALE",
                format!("{} recorded filter program map set changed", owned.ifname),
            ));
        }
        if RouteNetlink::if_nametoindex(&owned.ifname).ok() != Some(owned.identity.ifindex) {
            return Err(DataplaneError::new(
                "tc_filter:ESTALE",
                format!("{} identity changed before delete", owned.ifname),
            ));
        }
        self.route
            .detach_filter(
                owned.identity.ifindex,
                owned.identity.parent,
                owned.identity.handle,
                owned.identity.chain,
                owned.identity.priority,
                owned.identity.protocol,
            )
            .map_err(|error| DataplaneError::io("tc_detach_failed", error))
    }
    /// Dumps the parent a recorded filter hangs from. `None` means the
    /// interface itself is gone, which took every filter on it along.
    fn dump_recorded_parent(
        &mut self,
        owned: &OwnedFilter,
    ) -> Result<Option<Vec<Filter>>, DataplaneError> {
        match self
            .route
            .dump_filters(owned.identity.ifindex, owned.identity.parent)
        {
            Ok(filters) => Ok(Some(filters)),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENODEV) | Some(libc::ENOENT)
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(DataplaneError::io("tc_dump_failed", error)),
        }
    }
    fn lower_filter_names(&mut self, iface: &IfaceStatus, pref: u16) -> Vec<String> {
        self.route
            .dump_filters(iface.ifindex, netlink::TC_H_EGRESS)
            .unwrap_or_default()
            .into_iter()
            .filter(|filter| filter.chain == abi::TC_CHAIN && filter.priority < pref)
            .map(|filter| {
                filter
                    .prog_name
                    .unwrap_or_else(|| format!("pref{}", filter.priority))
            })
            .collect()
    }
    pub(super) fn tc_cleanup_plan(
        &mut self,
        snapshot: &NetworkSnapshot,
        peer_ifindex: Option<u32>,
    ) -> Result<Vec<OwnedFilter>, DataplaneError> {
        let mut owned = Vec::new();
        for link in &snapshot.links {
            let Some(qdisc) = snapshot.qdiscs.iter().find(|qdisc| {
                qdisc.ifindex == link.ifindex && qdisc.kind.as_deref() == Some("clsact")
            }) else {
                continue;
            };
            let qdisc_owned = exact_clsact(qdisc, link.ifindex);

            let mut parents = Vec::with_capacity(2);
            if peer_ifindex == Some(link.ifindex) {
                parents.push(netlink::TC_H_INGRESS);
            }
            if link.name != HOST_NAME && link.name != PEER_NAME && link.name != "lo" {
                parents.push(netlink::TC_H_EGRESS);
            }

            for parent in parents {
                let filters = self
                    .route
                    .dump_filters(link.ifindex, parent)
                    .map_err(|error| DataplaneError::io("tc_dump_failed", error))?;
                for filter in filters {
                    let name = filter.prog_name.as_deref().unwrap_or_default();
                    let fixed_ingress_slot = parent == netlink::TC_H_INGRESS
                        && filter.chain == abi::TC_CHAIN
                        && filter.priority == 1
                        && filter.protocol == netlink::ETH_P_ALL
                        && filter.handle == abi::TC_HANDLE_INGRESS;
                    if !name.starts_with("flx_") && !fixed_ingress_slot {
                        continue;
                    }

                    let expected = qdisc_owned
                        && expected_stale_filter(link, peer_ifindex, parent, &filter, name);
                    let Some(prog_id) = filter.prog_id else {
                        return Err(tc_filter_conflict(link, &filter));
                    };
                    let Some(prog_tag) = filter.prog_tag else {
                        return Err(tc_filter_conflict(link, &filter));
                    };
                    let Some(flags_gen) = filter.flags_gen else {
                        return Err(tc_filter_conflict(link, &filter));
                    };
                    let identity = FilterIdentity {
                        ifindex: link.ifindex,
                        parent,
                        handle: filter.handle,
                        chain: abi::TC_CHAIN,
                        priority: filter.priority,
                        protocol: filter.protocol,
                        prog_id,
                        prog_tag,
                        prog_name: name.to_string(),
                        flags_gen,
                    };
                    if !expected
                        || !identity.matches(&filter)
                        || !bpf::attached_program_owned(prog_id, name, prog_tag)
                            .map_err(DataplaneError::bpf)?
                    {
                        return Err(tc_filter_conflict(link, &filter));
                    }
                    owned.push(OwnedFilter {
                        ifname: link.name.clone(),
                        identity,
                        lower_filters: Vec::new(),
                    });
                }
            }
        }
        owned.sort_by(|left, right| {
            (
                left.identity.ifindex,
                left.identity.parent,
                left.identity.priority,
                left.identity.protocol,
                left.identity.handle,
                left.identity.prog_id,
            )
                .cmp(&(
                    right.identity.ifindex,
                    right.identity.parent,
                    right.identity.priority,
                    right.identity.protocol,
                    right.identity.handle,
                    right.identity.prog_id,
                ))
        });
        Ok(owned)
    }
}

pub(super) fn exact_clsact(qdisc: &netlink::Qdisc, ifindex: u32) -> bool {
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
pub(super) fn select_pref(link: &netlink::Link, filters: &[Filter]) -> Option<u16> {
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
pub(super) fn lower_filter_snapshot(filters: &[Filter], pref: u16) -> Vec<Filter> {
    let mut lower = filters
        .iter()
        .filter(|filter| filter.chain == abi::TC_CHAIN && filter.priority < pref)
        .cloned()
        .collect::<Vec<_>>();
    lower.sort_by(|left, right| {
        (
            left.priority,
            left.protocol,
            left.handle,
            left.kind.as_deref(),
            left.prog_name.as_deref(),
            left.prog_id,
            left.prog_tag,
            left.direct_action,
            left.bpf_flags,
            left.flags_gen,
            left.unknown_attrs,
            left.duplicate_attrs,
        )
            .cmp(&(
                right.priority,
                right.protocol,
                right.handle,
                right.kind.as_deref(),
                right.prog_name.as_deref(),
                right.prog_id,
                right.prog_tag,
                right.direct_action,
                right.bpf_flags,
                right.flags_gen,
                right.unknown_attrs,
                right.duplicate_attrs,
            ))
    });
    lower
}
fn filter_identity(
    ifindex: u32,
    parent: u32,
    handle: u32,
    priority: u16,
    protocol: u16,
    program: &ProgramIdentity,
    flags_gen: u32,
) -> FilterIdentity {
    FilterIdentity {
        ifindex,
        parent,
        handle,
        chain: abi::TC_CHAIN,
        priority,
        protocol,
        prog_id: program.id,
        prog_tag: program.tag,
        prog_name: program.name.clone(),
        flags_gen,
    }
}
fn read_tx_packets(ifname: &str) -> Result<u64, DataplaneError> {
    let path = format!("/sys/class/net/{ifname}/statistics/tx_packets");
    let value = fs::read_to_string(&path)
        .map_err(|error| DataplaneError::io("tc_verify_tx_read", error))?;
    value.trim().parse::<u64>().map_err(|error| {
        DataplaneError::new(
            "tc_verify_tx_read",
            format!("{path} did not contain a u64: {error}"),
        )
    })
}
fn attachment_reason(error: &DataplaneError) -> &'static str {
    if error.code == "interface_reused" {
        "interface_reused"
    } else if error.code.starts_with("tc_dump") {
        "tc_dump_failed"
    } else if error.code == "identity_drift" {
        "identity_drift"
    } else {
        "tc_no_usable_pref"
    }
}
