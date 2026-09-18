use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(test)]
use flux_core::abi::UidStats;
use flux_core::abi::{self, Control, Counter, FaultKey, LpmV4Key, LpmV6Key};
use flux_core::cidr::{Ipv4Cidr, Ipv6Cidr};
use flux_core::config::ListMode;
use flux_core::control_wire::{Counters, IfaceStatus, PolicyCounts};
use flux_core::policy_epoch::{self, PolicyEpoch};

use crate::bpf::{self, RingBuffer, Runtime};
use crate::netlink::{
    self, DrainResult, EventSocket, Filter, FilterIdentity, NetworkSnapshot, RouteNetlink,
};

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
const TC_VERIFY_WINDOW: Duration = Duration::from_secs(2);
const TC_VERIFY_MAX_ATTEMPTS: u8 = 3;
const IFA_F_SECONDARY_TEMPORARY: u32 = 0x01;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredPolicy {
    pub apps_mode: ListMode,
    pub cidr_mode: ListMode,
    pub interfaces_mode: ListMode,
    pub interfaces: BTreeSet<String>,
    pub selected_uids: BTreeSet<u32>,
    pub bypass_v4: BTreeMap<LpmV4Key, abi::BypassTag>,
    pub bypass_v6: BTreeMap<LpmV6Key, abi::BypassTag>,
}

impl Default for DesiredPolicy {
    fn default() -> Self {
        Self {
            apps_mode: ListMode::Whitelist,
            cidr_mode: ListMode::Blacklist,
            interfaces_mode: ListMode::Blacklist,
            interfaces: BTreeSet::new(),
            selected_uids: BTreeSet::new(),
            bypass_v4: BTreeMap::new(),
            bypass_v6: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentProgress {
    Wait(Duration),
    Complete,
}

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

    fn bpf(error: bpf::LoadError) -> Self {
        let mut detail = error.detail;
        if let Some(log) = error.verifier_log {
            detail.push_str("\nverifier log:\n");
            detail.push_str(&log);
        }
        Self::new(error.code, detail)
    }

    fn map_op(stage: &'static str, error: io::Error) -> Self {
        Self::bpf(bpf::LoadError::maps(stage, error))
    }
}

impl std::fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.code, self.detail)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DataplaneStatus {
    pub active: bool,
    pub topology_ready: bool,
    pub bpf_ready: bool,
    pub attachment_ready: bool,
    pub ifaces: Vec<IfaceStatus>,
    pub sysctl: BTreeMap<String, i64>,
    pub policy: PolicyCounts,
    pub warnings: Vec<String>,
    pub error: Option<DataplaneError>,
}

pub struct Manager {
    route: RouteNetlink,
    events: EventSocket,
    test_bypass: bool,
    reconciled_once: bool,
    runtime: Option<Runtime>,
    fault_ring: Option<RingBuffer>,
    last_control: Option<Control>,
    attached: Vec<OwnedFilter>,
    attachment: Option<AttachmentState>,
    apps_mode: ListMode,
    cidr_mode: ListMode,
    interfaces_mode: ListMode,
    interfaces: BTreeSet<String>,
    uid_modes: BTreeMap<u32, u8>,
    bypass_v4: BTreeMap<LpmV4Key, abi::BypassTag>,
    bypass_v6: BTreeMap<LpmV6Key, abi::BypassTag>,
    self_v4: BTreeSet<[u8; 4]>,
    self_v6: BTreeSet<[u8; 16]>,
    address_seen_v4: BTreeMap<[u8; 4], u64>,
    address_seen_v6: BTreeMap<[u8; 16], u64>,
    address_tick: u64,
    /// Last full rtnetlink snapshot contained an up, globally addressed link
    /// with a unicast default route. Subscription retry consumes this event-
    /// driven fact; it is not a periodic probe (blueprint §29.4).
    default_route_ready: bool,
    kmod_dir: PathBuf,
    kmod: Option<crate::kmod::LoadedModule>,
    status: DataplaneStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedFilter {
    ifname: String,
    identity: FilterIdentity,
    lower_filters: Vec<Filter>,
}

#[derive(Clone, Copy)]
struct FilterSlot<'a> {
    ifname: &'a str,
    ifindex: u32,
    parent: u32,
    handle: u32,
    priority: u16,
    protocol: u16,
    program_name: &'a str,
}

/// Input to `attach_filter_for_test`; constructed only by the device tests
/// that include this module, never by this crate's own unit tests.
#[cfg(test)]
#[allow(dead_code)]
pub struct TestFilterSpec<'a> {
    pub ifname: &'a str,
    pub ifindex: u32,
    pub parent: u32,
    pub handle: u32,
    pub priority: u16,
    pub protocol: u16,
    pub program_name: &'a str,
}

struct AttachmentState {
    pending: VecDeque<IfaceStatus>,
    verifying: Option<Verification>,
}

struct Verification {
    iface: IfaceStatus,
    pref: u16,
    baseline_counter: u64,
    baseline_tx: u64,
    attempts: u8,
    wait: Duration,
}

mod attachment;
use attachment::{exact_clsact, lower_filter_snapshot, select_pref};

type SelfAddressSelection = (BTreeSet<[u8; 4]>, BTreeSet<[u8; 16]>, bool);

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
            runtime: None,
            fault_ring: None,
            last_control: None,
            attached: Vec::new(),
            attachment: None,
            apps_mode: ListMode::Whitelist,
            cidr_mode: ListMode::Blacklist,
            interfaces_mode: ListMode::Blacklist,
            interfaces: BTreeSet::new(),
            uid_modes: BTreeMap::new(),
            bypass_v4: BTreeMap::new(),
            bypass_v6: BTreeMap::new(),
            self_v4: BTreeSet::new(),
            self_v6: BTreeSet::new(),
            address_seen_v4: BTreeMap::new(),
            address_seen_v6: BTreeMap::new(),
            address_tick: 0,
            default_route_ready: false,
            kmod_dir: default_kmod_dir(),
            kmod: None,
            status: DataplaneStatus::default(),
        })
    }

    /// Directory that holds `fluxrs-androidN-X.Y*.ko`. Reactor points this at
    /// the manager module so test layout overrides apply.
    pub fn set_kmod_dir(&mut self, dir: PathBuf) {
        self.kmod_dir = dir;
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

    /// Refreshes the event-driven default-route fact without creating or
    /// mutating any data-plane object. Subscription recovery calls this at
    /// request boundaries and after debounced rtnetlink events, never from a
    /// periodic probe (blueprint §29.4).
    pub fn refresh_default_route_ready(&mut self) -> Result<bool, DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|error| DataplaneError::io("rtnetlink_dump", error))?;
        self.default_route_ready = snapshot.links.iter().any(|link| {
            is_potential_candidate(link, &snapshot) && has_default_route(link.ifindex, &snapshot)
        });
        Ok(self.default_route_ready)
    }

    /// Stages the interface dimension before topology admission runs.
    ///
    /// This mutates no kernel object. `converge_with_bpf` consumes the staged
    /// predicate, and `apply_policy` commits the complete policy dimensions.
    pub fn stage_interface_policy(&mut self, desired: &DesiredPolicy) {
        self.interfaces_mode = desired.interfaces_mode;
        self.interfaces.clone_from(&desired.interfaces);
        self.status.policy.interfaces_mode = desired.interfaces_mode;
    }

    pub fn fault_fd(&self) -> Option<RawFd> {
        self.fault_ring.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn drain_faults(&mut self) -> Result<Vec<abi::FaultEvent>, DataplaneError> {
        match self.fault_ring.as_mut() {
            Some(ring) => ring
                .drain_faults()
                .map_err(|error| DataplaneError::io("ringbuf_drain", error)),
            None => Ok(Vec::new()),
        }
    }

    pub fn counters(&self) -> Result<Counters, DataplaneError> {
        if let Some(kmod) = self.kmod.as_ref() {
            let status = kmod
                .status()
                .map_err(|error| DataplaneError::io("lkm_status", error))?;
            return Ok(Counters {
                egress_listener_miss: status.miss_listener,
                in_assign_tcp: status.stolen,
                ..Counters::default()
            });
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(Counters::default());
        };
        let read = |counter| {
            runtime
                .maps()
                .counter_sum(counter)
                .map_err(|error| DataplaneError::map_op("counter_read", error))
        };
        Ok(Counters {
            admit_tcp: read(Counter::AdmitTcp)?,
            direct_tcp: read(Counter::DirectTcp)?,
            admit_udp: read(Counter::AdmitUdp)?,
            drop_inactive: read(Counter::DropInactive)?,
            drop_stale_gen: read(Counter::DropStaleGen)?,
            drop_handoff: read(Counter::DropHandoff)?,
            drop_selected_fragment: read(Counter::DropSelectedFragment)?,
            drop_corrupt: read(Counter::DropCorrupt)?,
            decision_alloc_fail: read(Counter::DecisionAllocFail)?,
            egress_listener_miss: read(Counter::EgressListenerMiss)?,
            in_assign_tcp: read(Counter::InAssignTcp)?,
            in_assign_udp: read(Counter::InAssignUdp)?,
            in_pass_established: read(Counter::InPassEstablished)?,
            in_pass_fragment: read(Counter::InPassFragment)?,
            in_drop_no_listener: read(Counter::InDropNoListener)?,
            in_drop_assign: read(Counter::InDropAssign)?,
            in_drop_parse: read(Counter::InDropParse)?,
            in_drop_snapshot: read(Counter::InDropSnapshot)?,
        })
    }
}

/// Seams for the Phase 3–7 device tests, which compile this module into their
/// own binaries by path. The daemon's own unit tests never call them, so this
/// block — and only this block — allows dead code.
#[cfg(test)]
#[allow(dead_code)]
impl Manager {
    /// Device integration tests need to leave the owner's phone exactly as it
    /// was. This is not a production stop path: normal stop intentionally
    /// retains owned kernel objects until the next cold start (§8.8).
    pub fn cleanup_for_test(&mut self) -> Result<(), String> {
        self.drop_kmod();
        let _ = crate::kmod::unload();
        self.cleanup_owned().map_err(|error| error.to_string())
    }

    pub fn publish_test_active(&mut self, uid: u32) -> Result<(), DataplaneError> {
        let mut control = self.last_control.ok_or_else(|| {
            DataplaneError::new("control_missing", "inactive test control was not published")
        })?;
        let runtime = self.runtime.as_mut().ok_or_else(|| {
            DataplaneError::new("bpf_runtime_missing", "test runtime was not loaded")
        })?;
        runtime
            .maps()
            .update_uid_mode(control.policy_bank & 1, uid, abi::UidMode::Selected as u8)
            .map_err(|error| DataplaneError::map_op("uid_policy_update", error))?;
        control.active = 1;
        runtime
            .maps_mut()
            .publish_control(&control)
            .map_err(|error| DataplaneError::map_op("control_publish", error))?;
        self.last_control = Some(control);
        Ok(())
    }

    pub fn publish_test_inactive(&mut self) -> Result<(), DataplaneError> {
        let mut control = self.last_control.ok_or_else(|| {
            DataplaneError::new("control_missing", "test control was not published")
        })?;
        if control.active == 0 {
            return Ok(());
        }
        control.active = 0;
        self.runtime
            .as_mut()
            .ok_or_else(|| {
                DataplaneError::new("bpf_runtime_missing", "test runtime was not loaded")
            })?
            .maps_mut()
            .publish_control(&control)
            .map_err(|error| DataplaneError::map_op("control_publish", error))?;
        self.last_control = Some(control);
        Ok(())
    }

    pub fn attach_filter_for_test(
        &mut self,
        spec: TestFilterSpec<'_>,
    ) -> Result<(), DataplaneError> {
        self.attach_exact(FilterSlot {
            ifname: spec.ifname,
            ifindex: spec.ifindex,
            parent: spec.parent,
            handle: spec.handle,
            priority: spec.priority,
            protocol: spec.protocol,
            program_name: spec.program_name,
        })?;
        Ok(())
    }

    pub fn detach_filter_for_test(
        &mut self,
        ifname: &str,
        parent: u32,
        handle: u32,
    ) -> Result<(), DataplaneError> {
        self.detach_recorded(ifname, parent, handle)
    }

    pub fn counter_for_test(&self, counter: Counter) -> Result<u64, DataplaneError> {
        self.runtime
            .as_ref()
            .ok_or_else(|| {
                DataplaneError::new("bpf_runtime_missing", "test runtime was not loaded")
            })?
            .maps()
            .counter_sum(counter)
            .map_err(|error| DataplaneError::map_op("counter_read", error))
    }

    pub fn uid_stats_for_test(&self, uid: u32) -> Result<UidStats, DataplaneError> {
        self.runtime
            .as_ref()
            .ok_or_else(|| {
                DataplaneError::new("bpf_runtime_missing", "test runtime was not loaded")
            })?
            .maps()
            .uid_stats_sum(uid)
            .map_err(|error| DataplaneError::map_op("uid_stats_read", error))
    }
}

impl Manager {
    /// Phase 3-only compatibility seam used by its device lifecycle test.
    pub fn converge(&mut self, enabled: bool) {
        self.converge_inner(enabled, None);
    }

    /// Reconciles §8.7 steps 2-5: leftover veth cleanup, then `fluxrs.ko`.
    /// `enabled=false` still performs the one cold-start stale-object cleanup,
    /// but loads nothing.
    pub fn converge_with_bpf(&mut self, enabled: bool, object: &[u8]) {
        self.converge_inner(enabled, Some(object));
    }

    fn converge_inner(&mut self, enabled: bool, object: Option<&[u8]>) {
        if self.test_bypass {
            self.status = DataplaneStatus {
                policy: self.status.policy,
                warnings: vec![
                    "no data plane: debug-only daemon integration-test bypass".to_string()
                ],
                ..DataplaneStatus::default()
            };
            return;
        }

        let mut next = DataplaneStatus {
            active: self.status.active,
            sysctl: read_status_sysctls(),
            policy: self.status.policy,
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
            self.drop_kmod();
            if let Err(error) = self.publish_inactive() {
                next.error = Some(error);
                self.status = next;
                return;
            }
            next.active = false;
            self.status = next;
            return;
        }

        if let Err(error) = self.ensure_kmod() {
            next.error = Some(error);
            self.status = next;
            return;
        }

        next.topology_ready = true;
        next.bpf_ready = true;
        next.attachment_ready = self.kmod.is_some();
        next.sysctl = read_status_sysctls();
        if object.is_none() {
            next.warnings.push(
                "phase-3 network seam is the LOCAL_OUT module; no BPF object was requested"
                    .to_string(),
            );
        } else if !next.active {
            next.warnings.push(
                "LOCAL_OUT module is loaded with steal idle until the engine is ready".to_string(),
            );
        }
        self.status = next;
    }

    fn drop_kmod(&mut self) {
        self.kmod = None;
        self.status.attachment_ready = false;
        self.status.bpf_ready = false;
        self.status.topology_ready = false;
    }

    fn ensure_kmod(&mut self) -> Result<(), DataplaneError> {
        if self.kmod.is_none() {
            let release = crate::kmod::kernel_release()
                .map_err(|error| DataplaneError::io("uname", error))?;
            let loaded =
                crate::kmod::load_from_dir(&self.kmod_dir, &release).map_err(kmod_load_error)?;
            self.kmod = Some(loaded);
        }
        let status = self
            .kmod
            .as_ref()
            .expect("just loaded")
            .status()
            .map_err(|error| DataplaneError::io("lkm_status", error))?;
        if status.steal_ready == 0 {
            self.drop_kmod();
            return Err(DataplaneError::new(
                "lkm_tproxy_symbol",
                "fluxrs loaded but nf_tproxy symbols were not resolved",
            ));
        }
        if self.last_control.is_none() {
            self.last_control = Some(inactive_control(0, 0, 1, 0, 0)?);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn ensure_inactive_runtime(&mut self, object: &[u8]) -> Result<(), DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|error| DataplaneError::io("rtnetlink_dump", error))?;
        let host = link_named(&snapshot, HOST_NAME)
            .ok_or_else(|| DataplaneError::new("veth_missing:flxrs0", "owned host veth absent"))?;
        let peer = link_named(&snapshot, PEER_NAME)
            .ok_or_else(|| DataplaneError::new("veth_missing:flxrs1", "owned peer veth absent"))?;
        let mut control = inactive_control(host.ifindex, peer.ifindex, 1, 0, 0)?;
        control.cidr_mode = cidr_mode_value(self.cidr_mode);

        if self.runtime.is_none() {
            let mut runtime = Runtime::load_embedded(object).map_err(DataplaneError::bpf)?;
            runtime
                .maps_mut()
                .publish_control(&control)
                .map_err(|error| DataplaneError::map_op("control_publish", error))?;
            let ring = runtime.fault_ring().map_err(DataplaneError::bpf)?;
            self.runtime = Some(runtime);
            self.fault_ring = Some(ring);
            self.last_control = Some(control);
        }
        Ok(())
    }

    /// Converges the policy domain without changing `active` or generation.
    /// The inactive bank is written in full, then one control-leaf swap names
    /// it (blueprint §10.5). The live bank is not mutated.
    pub fn apply_policy(&mut self, desired: &DesiredPolicy) -> Result<(), DataplaneError> {
        if self.test_bypass {
            self.status.policy = PolicyCounts {
                apps_mode: desired.apps_mode,
                cidr_mode: desired.cidr_mode,
                interfaces_mode: desired.interfaces_mode,
                selected: desired.selected_uids.len() as u32,
                bypass_v4: desired.bypass_v4.len() as u32,
                bypass_v6: desired.bypass_v6.len() as u32,
                ..PolicyCounts::default()
            };
            return Ok(());
        }
        if desired.selected_uids.len() > abi::UID_SELECTED_MAX as usize {
            return Err(DataplaneError::new(
                "policy_capacity:selected",
                "selected UID count exceeds the ABI limit",
            ));
        }
        if desired.selected_uids.len() > flux_core::kmod_uapi::UID_SLOT_MAX {
            return Err(DataplaneError::new(
                "policy_capacity:kmod_uids",
                "selected UID count exceeds the LOCAL_OUT ioctl table",
            ));
        }
        if desired.bypass_v4.len() > abi::LPM_MAX_ENTRIES as usize
            || desired.bypass_v6.len() > abi::LPM_MAX_ENTRIES as usize
        {
            return Err(DataplaneError::new(
                "policy_capacity:bypass",
                "bypass prefix count exceeds the ABI limit",
            ));
        }

        let snapshot = self
            .route
            .snapshot()
            .map_err(|error| DataplaneError::io("rtnetlink_dump", error))?;
        let (desired_self_v4, desired_self_v6, truncated) =
            self.desired_self_addresses(&snapshot.addresses)?;

        let from = self.live_epoch();
        let wanted = desired_epoch(desired, &desired_self_v4, &desired_self_v6);
        let next = policy_epoch::committed(&from, &wanted);
        if next.selected.len() + next.draining.len() > abi::UID_POLICY_MAX_ENTRIES as usize {
            return Err(DataplaneError::new(
                "policy_capacity:uid_policy",
                "selected plus boot-lifetime draining UIDs exceed the ABI limit",
            ));
        }

        let selected: Vec<u32> = next.selected.iter().copied().collect();
        let dropped: Vec<u32> = from.selected.difference(&next.selected).copied().collect();
        self.kmod
            .as_ref()
            .ok_or_else(|| {
                DataplaneError::new(
                    "lkm_not_loaded",
                    "LOCAL_OUT module is not holding /dev/fluxrs",
                )
            })?
            .set_uids(&selected)
            .map_err(|error| DataplaneError::io("lkm_set_uids", error))?;
        self.status
            .warnings
            .retain(|warning| !warning.starts_with("sock_destroy_"));
        if !dropped.is_empty() {
            match crate::netlink::sock_diag::destroy_tcp_for_uids(&dropped) {
                Ok(_) => {}
                Err(error) if crate::netlink::sock_diag::dump_retryable(&error) => {
                    self.status.warnings.push(
                        "sock_destroy_incomplete: live TCP of unselected UIDs was not reset"
                            .to_string(),
                    );
                }
                Err(error) => {
                    self.status
                        .warnings
                        .push(format!("sock_destroy_failed:{error}"));
                }
            }
        }

        if let Some(last) = self.last_control.as_mut() {
            last.selected_count = next.selected.len() as u32;
            last.draining_count = next.draining.len() as u32;
            last.bypass_v4_count = next.bypass_v4.len() as u32;
            last.bypass_v6_count = next.bypass_v6.len() as u32;
            last.cidr_mode = cidr_mode_value(desired.cidr_mode);
        }

        self.uid_modes = uid_modes_from_epoch(&next);
        self.bypass_v4.clone_from(&desired.bypass_v4);
        self.bypass_v6.clone_from(&desired.bypass_v6);
        self.self_v4 = desired_self_v4;
        self.self_v6 = desired_self_v6;
        self.apps_mode = desired.apps_mode;
        self.cidr_mode = desired.cidr_mode;
        self.interfaces_mode = desired.interfaces_mode;
        self.interfaces.clone_from(&desired.interfaces);

        self.status.policy = self.policy_counts();
        self.status
            .warnings
            .retain(|warning| !warning.contains("self_addr_lru"));
        if truncated {
            self.status.warnings.push(
                "self_addr_lru: more than 256 live privacy addresses; oldest entries were omitted"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn live_epoch(&self) -> PolicyEpoch {
        let mut epoch = PolicyEpoch::new(match self.cidr_mode {
            ListMode::Blacklist => abi::CidrMode::Blacklist,
            ListMode::Whitelist => abi::CidrMode::Whitelist,
        });
        for (uid, mode) in &self.uid_modes {
            if *mode == abi::UidMode::Selected as u8 {
                epoch.selected.insert(*uid);
            } else if *mode == abi::UidMode::Draining as u8 {
                epoch.draining.insert(*uid);
            }
        }
        epoch.bypass_v4 = self
            .bypass_v4
            .iter()
            .map(|(key, tag)| (lpm_v4_to_cidr(*key), *tag))
            .collect();
        epoch.bypass_v6 = self
            .bypass_v6
            .iter()
            .map(|(key, tag)| (lpm_v6_to_cidr(*key), *tag))
            .collect();
        epoch.self_v4 = self.self_v4.iter().copied().map(Ipv4Addr::from).collect();
        epoch.self_v6 = self.self_v6.iter().copied().map(Ipv6Addr::from).collect();
        epoch
    }

    #[allow(dead_code)]
    fn write_policy_bank(&mut self, bank: u8, epoch: &PolicyEpoch) -> Result<(), DataplaneError> {
        let maps = self.maps_mut()?;
        for uid in &epoch.selected {
            maps.update_uid_mode(bank, *uid, abi::UidMode::Selected as u8)
                .map_err(|error| DataplaneError::map_op("uid_policy_update", error))?;
        }
        for uid in &epoch.draining {
            maps.update_uid_mode(bank, *uid, abi::UidMode::Draining as u8)
                .map_err(|error| DataplaneError::map_op("uid_policy_update", error))?;
        }
        for uid in maps
            .uid_keys(bank)
            .map_err(|error| DataplaneError::map_op("uid_policy_keys", error))?
        {
            if !epoch.selected.contains(&uid) && !epoch.draining.contains(&uid) {
                maps.delete_uid_mode(bank, uid)
                    .map_err(|error| DataplaneError::map_op("uid_policy_delete", error))?;
            }
        }

        for (cidr, tag) in &epoch.bypass_v4 {
            maps.update_bypass_v4(bank, &cidr.to_lpm_key(), *tag)
                .map_err(|error| DataplaneError::map_op("bypass_v4_update", error))?;
        }
        let desired_v4: BTreeSet<LpmV4Key> = epoch
            .bypass_v4
            .keys()
            .map(|cidr| cidr.to_lpm_key())
            .collect();
        for key in maps
            .bypass_v4_keys(bank)
            .map_err(|error| DataplaneError::map_op("bypass_v4_keys", error))?
        {
            if !desired_v4.contains(&key) {
                maps.delete_bypass_v4(bank, &key)
                    .map_err(|error| DataplaneError::map_op("bypass_v4_delete", error))?;
            }
        }

        for (cidr, tag) in &epoch.bypass_v6 {
            maps.update_bypass_v6(bank, &cidr.to_lpm_key(), *tag)
                .map_err(|error| DataplaneError::map_op("bypass_v6_update", error))?;
        }
        let desired_v6: BTreeSet<LpmV6Key> = epoch
            .bypass_v6
            .keys()
            .map(|cidr| cidr.to_lpm_key())
            .collect();
        for key in maps
            .bypass_v6_keys(bank)
            .map_err(|error| DataplaneError::map_op("bypass_v6_keys", error))?
        {
            if !desired_v6.contains(&key) {
                maps.delete_bypass_v6(bank, &key)
                    .map_err(|error| DataplaneError::map_op("bypass_v6_delete", error))?;
            }
        }

        let desired_self_v4: BTreeSet<[u8; 4]> = epoch
            .self_v4
            .iter()
            .copied()
            .map(|addr| addr.octets())
            .collect();
        for address in &desired_self_v4 {
            maps.update_self_v4(bank, address)
                .map_err(|error| DataplaneError::map_op("self_addr_v4_update", error))?;
        }
        for address in maps
            .self_v4_keys(bank)
            .map_err(|error| DataplaneError::map_op("self_addr_v4_keys", error))?
        {
            if !desired_self_v4.contains(&address) {
                maps.delete_self_v4(bank, &address)
                    .map_err(|error| DataplaneError::map_op("self_addr_v4_delete", error))?;
            }
        }

        let desired_self_v6: BTreeSet<[u8; 16]> = epoch
            .self_v6
            .iter()
            .copied()
            .map(|addr| addr.octets())
            .collect();
        for address in &desired_self_v6 {
            maps.update_self_v6(bank, address)
                .map_err(|error| DataplaneError::map_op("self_addr_v6_update", error))?;
        }
        for address in maps
            .self_v6_keys(bank)
            .map_err(|error| DataplaneError::map_op("self_addr_v6_keys", error))?
        {
            if !desired_self_v6.contains(&address) {
                maps.delete_self_v6(bank, &address)
                    .map_err(|error| DataplaneError::map_op("self_addr_v6_delete", error))?;
            }
        }
        Ok(())
    }

    pub fn clear_fault_latch(&self) -> Result<(), DataplaneError> {
        if self.test_bypass || self.runtime.is_none() {
            return Ok(());
        }
        self.maps()?
            .clear_fault_latch()
            .map_err(|error| DataplaneError::map_op("fault_latch_clear", error))
    }

    pub fn delete_fault_latch(&self, key: &FaultKey) -> Result<(), DataplaneError> {
        if self.test_bypass || self.runtime.is_none() {
            return Ok(());
        }
        self.maps()?
            .delete_fault_latch(key)
            .map_err(|error| DataplaneError::map_op("fault_latch_delete", error))
    }

    /// The sole Phase 6 commit point. The LOCAL_OUT module must already hold
    /// `/dev/fluxrs` with `steal_ready` before userspace `active=1`.
    pub fn publish_active(&mut self) -> Result<(), DataplaneError> {
        if self.test_bypass {
            return Ok(());
        }
        if !self.status.attachment_ready {
            return Err(DataplaneError::new(
                "dataplane_not_ready",
                "LOCAL_OUT module is not ready for activation",
            ));
        }
        let mut control = self.last_control.ok_or_else(|| {
            DataplaneError::new("control_missing", "inactive generation was not published")
        })?;
        control.active = 1;
        let counts = self.policy_counts();
        control.selected_count = counts.selected;
        control.draining_count = counts.draining;
        control.bypass_v4_count = counts.bypass_v4;
        control.bypass_v6_count = counts.bypass_v6;
        self.last_control = Some(control);
        self.status.active = true;
        Ok(())
    }

    pub fn publish_inactive(&mut self) -> Result<(), DataplaneError> {
        if self.test_bypass {
            return Ok(());
        }
        let Some(mut control) = self.last_control else {
            self.status.active = false;
            return Ok(());
        };
        if control.active != 0 {
            control.active = 0;
            self.last_control = Some(control);
        }
        if let Some(kmod) = self.kmod.as_ref() {
            kmod.clear_uids()
                .map_err(|error| DataplaneError::io("lkm_clear_uids", error))?;
        }
        self.status.active = false;
        Ok(())
    }

    fn runtime_ref(&self) -> Result<&Runtime, DataplaneError> {
        self.runtime.as_ref().ok_or_else(|| {
            DataplaneError::new("bpf_runtime_missing", "Phase 6 runtime has not been loaded")
        })
    }

    fn runtime_mut(&mut self) -> Result<&mut Runtime, DataplaneError> {
        self.runtime.as_mut().ok_or_else(|| {
            DataplaneError::new("bpf_runtime_missing", "Phase 6 runtime has not been loaded")
        })
    }

    #[allow(dead_code)]
    fn maps(&self) -> Result<&crate::bpf::MapSet, DataplaneError> {
        Ok(self.runtime_ref()?.maps())
    }

    #[allow(dead_code)]
    fn maps_mut(&mut self) -> Result<&mut crate::bpf::MapSet, DataplaneError> {
        Ok(self.runtime_mut()?.maps_mut())
    }

    fn policy_counts(&self) -> PolicyCounts {
        PolicyCounts {
            apps_mode: self.apps_mode,
            cidr_mode: self.cidr_mode,
            interfaces_mode: self.interfaces_mode,
            selected: self
                .uid_modes
                .values()
                .filter(|mode| **mode == abi::UidMode::Selected as u8)
                .count() as u32,
            draining: self
                .uid_modes
                .values()
                .filter(|mode| **mode == abi::UidMode::Draining as u8)
                .count() as u32,
            bypass_v4: self.bypass_v4.len() as u32,
            bypass_v6: self.bypass_v6.len() as u32,
            self_addresses: (self.self_v4.len() + self.self_v6.len()) as u32,
        }
    }

    fn desired_self_addresses(
        &mut self,
        addresses: &[netlink::Address],
    ) -> Result<SelfAddressSelection, DataplaneError> {
        let mut v4 = BTreeMap::<[u8; 4], bool>::new();
        let mut v6 = BTreeMap::<[u8; 16], bool>::new();
        for address in addresses {
            if address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED) != 0 {
                continue;
            }
            match address.family as i32 {
                libc::AF_INET if address.bytes.len() == 4 => {
                    let bytes: [u8; 4] =
                        address.bytes.as_slice().try_into().expect("length checked");
                    let ip = Ipv4Addr::from(bytes);
                    if ip.is_unspecified() || ip.is_multicast() {
                        continue;
                    }
                    v4.entry(bytes)
                        .and_modify(|existing| *existing = false)
                        .or_insert(false);
                }
                libc::AF_INET6 if address.bytes.len() == 16 => {
                    let bytes: [u8; 16] =
                        address.bytes.as_slice().try_into().expect("length checked");
                    let ip = Ipv6Addr::from(bytes);
                    if ip.is_unspecified() || ip.is_multicast() {
                        continue;
                    }
                    let privacy = is_privacy_address(address.family, address.flags);
                    v6.entry(bytes)
                        .and_modify(|existing| *existing &= privacy)
                        .or_insert(privacy);
                }
                _ => {}
            }
        }

        self.address_seen_v4
            .retain(|address, _| v4.contains_key(address));
        self.address_seen_v6
            .retain(|address, _| v6.contains_key(address));
        for address in v4.keys() {
            if !self.address_seen_v4.contains_key(address) {
                self.address_tick = self.address_tick.saturating_add(1);
                self.address_seen_v4.insert(*address, self.address_tick);
            }
        }
        for address in v6.keys() {
            if !self.address_seen_v6.contains_key(address) {
                self.address_tick = self.address_tick.saturating_add(1);
                self.address_seen_v6.insert(*address, self.address_tick);
            }
        }

        let (v4, truncated_v4) = select_self_addresses(
            &v4,
            &self.address_seen_v4,
            abi::SELF_ADDR_MAX_ENTRIES as usize,
        )?;
        let (v6, truncated_v6) = select_self_addresses(
            &v6,
            &self.address_seen_v6,
            abi::SELF_ADDR_MAX_ENTRIES as usize,
        )?;
        Ok((v4, v6, truncated_v4 || truncated_v6))
    }

    pub fn prepare_generation(
        &mut self,
        generation: u64,
        port_v4: u16,
        port_v6: u16,
    ) -> Result<(), DataplaneError> {
        if self.test_bypass {
            return Ok(());
        }
        let mut control = inactive_control(0, 0, generation, port_v4, port_v6)?;
        control.cidr_mode = cidr_mode_value(self.cidr_mode);
        if let Some(last) = self.last_control {
            control.policy_bank = last.policy_bank & 1;
        }
        let counts = self.policy_counts();
        control.selected_count = counts.selected;
        control.draining_count = counts.draining;
        control.bypass_v4_count = counts.bypass_v4;
        control.bypass_v6_count = counts.bypass_v6;
        let listen_v4 = abi::LISTEN_V4_STR
            .parse::<Ipv4Addr>()
            .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?;
        let listen_v6 = abi::LISTEN_V6_STR
            .parse::<Ipv6Addr>()
            .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?;
        self.kmod
            .as_ref()
            .ok_or_else(|| {
                DataplaneError::new(
                    "lkm_not_loaded",
                    "LOCAL_OUT module is not holding /dev/fluxrs",
                )
            })?
            .set_listeners(listen_v4, port_v4, listen_v6, port_v6)
            .map_err(|error| DataplaneError::io("lkm_set_listeners", error))?;
        self.last_control = Some(control);
        self.status.active = false;
        Ok(())
    }

    fn activate_iface(&mut self, iface: &IfaceStatus, warning: Option<&str>) {
        if let Some(status) = self
            .status
            .ifaces
            .iter_mut()
            .find(|status| status.name == iface.name && status.ifindex == iface.ifindex)
        {
            status.status = "active".to_string();
            status.reason = None;
            status.reachable = Some(true);
            if let Some(entry) = status.entry.as_deref() {
                if let Some(program) = self
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.program_identity(entry))
                {
                    status.prog_id = Some(program.id);
                    status.prog_tag = Some(hex_tag(program.tag));
                }
            }
        }
        if let Some(warning) = warning {
            self.status
                .warnings
                .push(format!("{}: {warning}", iface.name));
        }
    }

    fn exclude_iface(&mut self, iface: &IfaceStatus, reason: &str, warning: Option<String>) {
        if let Some(status) = self
            .status
            .ifaces
            .iter_mut()
            .find(|status| status.name == iface.name && status.ifindex == iface.ifindex)
        {
            status.status = "excluded".to_string();
            status.reason = Some(reason.to_string());
            status.prog_id = None;
            status.prog_tag = None;
            // Every caller reaches here after an attach or liveness attempt,
            // so reachability is decided and negative, not merely unknown.
            status.reachable = Some(false);
        }
        if let Some(warning) = warning {
            self.status.warnings.push(warning);
        }
    }

    /// Removes only objects that satisfy the complete ownership
    /// predicate. The plan is dumped twice before the first deletion.
    /// Each dump is a TrustedSnapshot: an incomplete view cannot become a
    /// deletion permit.
    fn cleanup_owned(&mut self) -> Result<(), DataplaneError> {
        let first = self.cleanup_plan()?;
        let second = self.cleanup_plan()?;
        if first != second {
            return Err(DataplaneError::new(
                "network_snapshot_stale",
                "Flux-owned objects changed between the two ownership dumps",
            ));
        }

        for filter in &second.tc_filters {
            self.detach_identity(filter)?;
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
        self.attached.clear();
        self.attachment = None;
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
        let tc_filters = self.tc_cleanup_plan(&snapshot, pair.map(|(_, peer)| peer.ifindex))?;

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
            tc_filters,
            host_ifindex: pair.map(|(host, _)| host.ifindex),
            lo_ifindex,
            rule_families,
            route_families,
        })
    }

    #[allow(dead_code)]
    fn ensure_topology(&mut self) -> Result<(), DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        let state = topology_state(&snapshot)?;
        if state == TopologyState::Complete {
            return Ok(());
        }
        // Veth/rule/route repair is a core-path mutation. No captured socket
        // may observe it under active=1 (§10.4.2).
        self.publish_inactive()?;
        self.status.attachment_ready = false;
        if state == TopologyState::OwnedDrift {
            self.cleanup_owned()?;
        }
        self.create_topology()
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn admit_interfaces(&mut self) -> Result<Vec<IfaceStatus>, DataplaneError> {
        let snapshot = self
            .route
            .snapshot()
            .map_err(|e| DataplaneError::io("rtnetlink_dump", e))?;
        self.default_route_ready = snapshot.links.iter().any(|link| {
            is_potential_candidate(link, &snapshot) && has_default_route(link.ifindex, &snapshot)
        });
        let mut candidates = snapshot
            .links
            .iter()
            .filter(|link| is_potential_candidate(link, &snapshot))
            .filter(|link| {
                self.interfaces_mode
                    .includes(self.interfaces.contains(&link.name))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|link| link.ifindex);
        if candidates.len() > MAX_INTERFACES {
            return Err(DataplaneError::new(
                format!("too_many_interfaces:{}", candidates.len()),
                "the topology candidate exceeds the 64-interface hard limit",
            ));
        }

        let selected = candidates
            .iter()
            .map(|link| (link.name.clone(), link.ifindex))
            .collect::<BTreeSet<_>>();
        let stale = self
            .attached
            .iter()
            .filter(|owned| {
                owned.identity.parent == netlink::TC_H_EGRESS
                    && owned.identity.handle == abi::TC_HANDLE_EGRESS
                    && !selected.contains(&(owned.ifname.clone(), owned.identity.ifindex))
            })
            .cloned()
            .collect::<Vec<_>>();
        for owned in stale {
            self.detach_identity(&owned)?;
            self.attached
                .retain(|candidate| candidate.identity != owned.identity);
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
            pref: None,
            reachable: None,
            reason: None,
        };

        if (excluded_kind(link.kind.as_deref()) && !is_clat_link(link))
            || link.master_ifindex.is_some()
        {
            status.reason = Some("unsupported_link_type".to_string());
            return status;
        }
        if !has_default_route(link.ifindex, snapshot) {
            status.reason = Some("not_upstream".to_string());
            return status;
        }

        let entry = match link.arphrd {
            1 => "flx_cap_l2",
            519 => "flx_cap_l3",
            0xfffe if is_clat_link(link) => "flx_cap_l3",
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

        let mut filters = match self.route.dump_filters(link.ifindex, netlink::TC_H_EGRESS) {
            Ok(filters) => filters,
            Err(_) => {
                // A failed enumeration is not a reachability verdict, so
                // `reachable` stays absent rather than claiming false.
                status.reason = Some("tc_dump_failed".to_string());
                return status;
            }
        };

        if let Some(index) = self.attached.iter().position(|owned| {
            owned.ifname == link.name
                && owned.identity.ifindex == link.ifindex
                && owned.identity.parent == netlink::TC_H_EGRESS
                && owned.identity.handle == abi::TC_HANDLE_EGRESS
        }) {
            let owned = self.attached[index].clone();
            if self.verify_owned_filter(&owned).is_ok() {
                let lower = lower_filter_snapshot(&filters, owned.identity.priority);
                if owned.identity.prog_name == entry && lower == owned.lower_filters {
                    status.entry = Some(entry.to_string());
                    status.status = "active".to_string();
                    status.prog_id = Some(owned.identity.prog_id);
                    status.prog_tag = Some(hex_tag(owned.identity.prog_tag));
                    status.pref = Some(owned.identity.priority);
                    status.reachable = Some(true);
                    return status;
                }
                if self.detach_identity(&owned).is_err() {
                    status.entry = Some(entry.to_string());
                    status.reason = Some("identity_drift".to_string());
                    status.pref = Some(owned.identity.priority);
                    status.reachable = Some(false);
                    return status;
                }
                self.attached.remove(index);
                filters = match self.route.dump_filters(link.ifindex, netlink::TC_H_EGRESS) {
                    Ok(filters) => filters,
                    Err(_) => {
                        status.entry = Some(entry.to_string());
                        status.reason = Some("tc_dump_failed".to_string());
                        return status;
                    }
                };
            } else {
                self.attached.remove(index);
                if filters.iter().any(|filter| {
                    filter.chain == owned.identity.chain
                        && filter.priority == owned.identity.priority
                        && filter.protocol == owned.identity.protocol
                        && filter.handle == owned.identity.handle
                }) {
                    status.entry = Some(entry.to_string());
                    status.reason = Some("identity_drift".to_string());
                    status.pref = Some(owned.identity.priority);
                    status.reachable = Some(false);
                    return status;
                }
            }
        }

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
        status.pref = Some(pref);
        // Reachability is decided by the flx_verify liveness probe, not by
        // where we land in the dump. Leave the field absent until that probe
        // concludes, so `admitted` never advertises an unverified verdict.
        status.reachable = None;
        status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupPlan {
    tc_filters: Vec<OwnedFilter>,
    host_ifindex: Option<u32>,
    lo_ifindex: u32,
    rule_families: Vec<u8>,
    route_families: Vec<u8>,
}

fn select_self_addresses<const N: usize>(
    candidates: &BTreeMap<[u8; N], bool>,
    seen: &BTreeMap<[u8; N], u64>,
    capacity: usize,
) -> Result<(BTreeSet<[u8; N]>, bool), DataplaneError> {
    let mut selected = candidates
        .iter()
        .filter_map(|(address, privacy)| (!*privacy).then_some(*address))
        .collect::<BTreeSet<_>>();
    if selected.len() > capacity {
        return Err(DataplaneError::new(
            "policy_capacity:self_addr",
            "non-privacy device addresses exceed the exact bypass map limit",
        ));
    }
    let mut privacy = candidates
        .iter()
        .filter_map(|(address, is_privacy)| {
            (*is_privacy).then_some((Reverse(seen.get(address).copied().unwrap_or(0)), *address))
        })
        .collect::<Vec<_>>();
    privacy.sort_unstable();
    let available = capacity - selected.len();
    let truncated = privacy.len() > available;
    selected.extend(
        privacy
            .into_iter()
            .take(available)
            .map(|(_, address)| address),
    );
    Ok((selected, truncated))
}

fn is_privacy_address(family: u8, flags: u32) -> bool {
    family as i32 == libc::AF_INET6
        && flags & (IFA_F_SECONDARY_TEMPORARY | IFA_F_STABLE_PRIVACY) != 0
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

fn expected_stale_filter(
    link: &netlink::Link,
    peer_ifindex: Option<u32>,
    parent: u32,
    filter: &Filter,
    name: &str,
) -> bool {
    if parent == netlink::TC_H_INGRESS {
        return peer_ifindex == Some(link.ifindex)
            && name == abi::PROG_IN
            && filter.chain == abi::TC_CHAIN
            && filter.priority == 1
            && filter.protocol == netlink::ETH_P_ALL
            && filter.handle == abi::TC_HANDLE_INGRESS;
    }
    if parent != netlink::TC_H_EGRESS
        || link.master_ifindex.is_some()
        || (excluded_kind(link.kind.as_deref()) && !is_clat_link(link))
        || filter.chain != abi::TC_CHAIN
        || filter.priority < TC_PREF_PREFERRED
        || (link.name.starts_with("v4-") && filter.priority >= TC_PREF_CLAT_MAX)
    {
        return false;
    }

    match name {
        abi::PROG_VERIFY => {
            filter.handle == abi::TC_HANDLE_VERIFY && filter.protocol == netlink::ETH_P_ALL
        }
        abi::PROG_CAP_L2 => {
            link.arphrd == 1
                && filter.handle == abi::TC_HANDLE_EGRESS
                && filter.protocol == netlink::ETH_P_ALL
        }
        abi::PROG_CAP_L3 => {
            (link.arphrd == 519 || is_clat_link(link))
                && filter.handle == abi::TC_HANDLE_EGRESS
                && filter.protocol
                    == if link.name.starts_with("v4-") {
                        0x0800
                    } else {
                        netlink::ETH_P_ALL
                    }
        }
        _ => false,
    }
}

fn tc_filter_conflict(link: &netlink::Link, filter: &Filter) -> DataplaneError {
    DataplaneError::new(
        format!("tc_filter_conflict:{}", link.name),
        format!(
            "{} contains a Flux-named or reserved-slot filter that fails the complete ownership predicate: {filter:?}",
            link.name
        ),
    )
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

fn is_clat_link(link: &netlink::Link) -> bool {
    link.name.starts_with("v4-") && link.arphrd == 0xfffe && link.kind.as_deref() == Some("tun")
}

fn arphrd_name(arphrd: u16) -> Option<&'static str> {
    match arphrd {
        1 => Some("ether"),
        519 => Some("rawip"),
        0xfffe => Some("none"),
        _ => None,
    }
}

fn cidr_mode_value(mode: ListMode) -> u16 {
    match mode {
        ListMode::Blacklist => abi::CidrMode::Blacklist as u16,
        ListMode::Whitelist => abi::CidrMode::Whitelist as u16,
    }
}

fn desired_epoch(
    desired: &DesiredPolicy,
    self_v4: &BTreeSet<[u8; 4]>,
    self_v6: &BTreeSet<[u8; 16]>,
) -> PolicyEpoch {
    let mut epoch = PolicyEpoch::new(match desired.cidr_mode {
        ListMode::Blacklist => abi::CidrMode::Blacklist,
        ListMode::Whitelist => abi::CidrMode::Whitelist,
    });
    epoch.selected = desired.selected_uids.clone();
    epoch.bypass_v4 = desired
        .bypass_v4
        .iter()
        .map(|(key, tag)| (lpm_v4_to_cidr(*key), *tag))
        .collect();
    epoch.bypass_v6 = desired
        .bypass_v6
        .iter()
        .map(|(key, tag)| (lpm_v6_to_cidr(*key), *tag))
        .collect();
    epoch.self_v4 = self_v4.iter().copied().map(Ipv4Addr::from).collect();
    epoch.self_v6 = self_v6.iter().copied().map(Ipv6Addr::from).collect();
    epoch
}

fn uid_modes_from_epoch(epoch: &PolicyEpoch) -> BTreeMap<u32, u8> {
    let mut modes = BTreeMap::new();
    for uid in &epoch.selected {
        modes.insert(*uid, abi::UidMode::Selected as u8);
    }
    for uid in &epoch.draining {
        modes.insert(*uid, abi::UidMode::Draining as u8);
    }
    modes
}

fn lpm_v4_to_cidr(key: LpmV4Key) -> Ipv4Cidr {
    Ipv4Cidr::from_octets(key.addr, u8::try_from(key.prefixlen).unwrap_or(32).min(32))
        .unwrap_or_else(|_| Ipv4Cidr::from_octets([0; 4], 0).expect("0.0.0.0/0 is canonical"))
}

fn lpm_v6_to_cidr(key: LpmV6Key) -> Ipv6Cidr {
    Ipv6Cidr::from_octets(
        key.addr,
        u8::try_from(key.prefixlen).unwrap_or(128).min(128),
    )
    .unwrap_or_else(|_| Ipv6Cidr::from_octets([0; 16], 0).expect("::/0 is canonical"))
}

fn inactive_control(
    host_ifindex: u32,
    peer_ifindex: u32,
    generation: u64,
    port_v4: u16,
    port_v6: u16,
) -> Result<Control, DataplaneError> {
    let listen_v4 = abi::LISTEN_V4_STR
        .parse::<Ipv4Addr>()
        .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?
        .octets();
    let listen_v6 = abi::LISTEN_V6_STR
        .parse::<Ipv6Addr>()
        .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?
        .octets();
    let probe_remote_v4 = abi::PROBE_REMOTE_V4_STR
        .parse::<Ipv4Addr>()
        .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?
        .octets();
    let probe_remote_v6 = abi::PROBE_REMOTE_V6_STR
        .parse::<Ipv6Addr>()
        .map_err(|error| DataplaneError::new("control_address_invalid", error.to_string()))?
        .octets();
    Ok(Control {
        abi_magic: abi::FLUX_ABI_MAGIC,
        active: 0,
        generation: generation.max(1),
        flxrs0_ifindex: host_ifindex,
        flxrs1_ifindex: peer_ifindex,
        listen_port_v4: port_v4.to_be(),
        listen_port_v6: port_v6.to_be(),
        listen_v4,
        probe_remote_v4,
        probe_remote_port: abi::PROBE_REMOTE_PORT.to_be(),
        cidr_mode: abi::CidrMode::Blacklist as u16,
        listen_v6,
        probe_remote_v6,
        selected_count: 0,
        draining_count: 0,
        bypass_v4_count: 0,
        bypass_v6_count: 0,
        policy_bank: 0,
        pad1: [0; 7],
    })
}

fn hex_tag(tag: [u8; 8]) -> String {
    tag.into_iter().map(|byte| format!("{byte:02x}")).collect()
}

fn default_kmod_dir() -> PathBuf {
    match std::env::var_os("FLUX_KMOD_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new("/data/adb/modules/Flux-rs").join(crate::kmod::DIR_NAME),
    }
}

fn kmod_load_error(error: crate::kmod::LoadError) -> DataplaneError {
    match error {
        crate::kmod::LoadError::UnknownRelease(release) => DataplaneError::new(
            format!("lkm_unknown_release:{release}"),
            "uname -r did not map to a GKI line Flux ships",
        ),
        crate::kmod::LoadError::MissingModule { line, dir } => DataplaneError::new(
            "lkm_missing_module",
            format!("no {}*.ko in {}", line.module_stem(), dir.display()),
        ),
        crate::kmod::LoadError::Finit { path, error } => {
            let errno = error
                .raw_os_error()
                .map(errno_name)
                .unwrap_or_else(|| format!("{:?}", error.kind()));
            DataplaneError::new(
                format!("lkm_finit:{errno}"),
                format!("finit_module {}: {error}", path.display()),
            )
        }
        crate::kmod::LoadError::Control(error) => DataplaneError::io("lkm_control", error),
        crate::kmod::LoadError::Io(error) => DataplaneError::io("lkm_io", error),
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

#[cfg(test)]
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
    use super::attachment::{lower_filter_snapshot, select_pref};
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
            bpf_flags: Some(1),
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
    fn lower_filter_snapshot_is_order_independent_and_identity_sensitive() {
        let one = filter(1, "oem-one");
        let mut two = filter(2, "oem-two");
        two.handle = 9;
        let forward = lower_filter_snapshot(&[one.clone(), two.clone()], 3);
        let reverse = lower_filter_snapshot(&[two.clone(), one.clone()], 3);
        assert_eq!(forward, reverse);

        two.flags_gen = Some(8);
        assert_ne!(forward, lower_filter_snapshot(&[one, two], 3));
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
    fn arphrd_none_is_only_accepted_for_the_strict_clat_shape() {
        let mut epdg = link("epdg0");
        epdg.arphrd = 0xfffe;
        epdg.kind = Some("tun".to_string());
        assert!(!is_clat_link(&epdg));

        let mut clat = link("v4-rmnet0");
        clat.arphrd = 0xfffe;
        clat.kind = Some("tun".to_string());
        assert!(is_clat_link(&clat));
        clat.kind = None;
        assert!(!is_clat_link(&clat));
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
                flags: 0,
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
    fn self_address_capacity_protects_stable_and_keeps_newest_privacy() {
        let stable = [1u8; 4];
        let old_privacy = [2u8; 4];
        let new_privacy = [3u8; 4];
        let candidates =
            BTreeMap::from([(stable, false), (old_privacy, true), (new_privacy, true)]);
        let seen = BTreeMap::from([(stable, 1), (old_privacy, 2), (new_privacy, 3)]);
        let (selected, truncated) = select_self_addresses(&candidates, &seen, 2).unwrap();
        assert!(truncated);
        assert_eq!(selected, BTreeSet::from([stable, new_privacy]));

        let stable_only = BTreeMap::from([([1u8; 4], false), ([2u8; 4], false)]);
        assert_eq!(
            select_self_addresses(&stable_only, &BTreeMap::new(), 1)
                .unwrap_err()
                .code,
            "policy_capacity:self_addr"
        );

        assert!(is_privacy_address(
            libc::AF_INET6 as u8,
            IFA_F_SECONDARY_TEMPORARY
        ));
        assert!(is_privacy_address(
            libc::AF_INET6 as u8,
            IFA_F_STABLE_PRIVACY
        ));
        assert!(
            !is_privacy_address(libc::AF_INET as u8, IFA_F_SECONDARY_TEMPORARY),
            "IPv4 secondary shares the temporary flag bit but is not a privacy address"
        );
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
