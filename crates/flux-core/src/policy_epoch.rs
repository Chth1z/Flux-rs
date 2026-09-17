//! Observable policy as one epoch, and the add-then-subtract third states.
//!
//! Blueprint §10.5: a first SYN or UDP datagram sees the maps as they are.
//! An existing TCP decision being immutable does not make a mixed epoch safe.
//! This module is the host-side model of that contract. It does not talk to
//! the kernel; `fluxd` still mutates live maps in place until the PolicyEpoch
//! commit lands.
//!
//! Two protocols are named so they cannot be confused:
//!
//! * [`epoch_commit_windows`] — only the old epoch, then the new epoch.
//! * [`add_then_subtract_windows`] — today's userspace order. Tests below
//!   prove it produces epochs equal to neither endpoint.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::abi::{BypassTag, CidrMode, DecisionMode};
use crate::cidr::{Ipv4Cidr, Ipv6Cidr};

/// One observable combination of UID modes, CIDR direction, bypass sets, and
/// self-address sets. The data plane MUST interpret exactly one of these at
/// any instant (blueprint §10.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEpoch {
    /// Direction applied to [`BypassTag::Policy`] hits.
    pub cidr_mode: CidrMode,
    /// UIDs currently `SELECTED`.
    pub selected: BTreeSet<u32>,
    /// UIDs currently `DRAINING`. Must be disjoint from [`Self::selected`].
    pub draining: BTreeSet<u32>,
    /// IPv4 LPM contents, including `RESERVED` mechanism prefixes.
    pub bypass_v4: BTreeMap<Ipv4Cidr, BypassTag>,
    /// IPv6 LPM contents, including `RESERVED` mechanism prefixes.
    pub bypass_v6: BTreeMap<Ipv6Cidr, BypassTag>,
    /// Exact local IPv4 addresses; a hit is always Direct.
    pub self_v4: BTreeSet<Ipv4Addr>,
    /// Exact local IPv6 addresses; a hit is always Direct.
    pub self_v6: BTreeSet<Ipv6Addr>,
}

/// A destination used as a probe of a new flow (no TCP decision yet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// IPv4 original destination.
    V4(Ipv4Addr),
    /// IPv6 original destination.
    V6(Ipv6Addr),
}

impl PolicyEpoch {
    /// Empty sets, no selected UIDs, the given CIDR direction.
    pub fn new(cidr_mode: CidrMode) -> Self {
        Self {
            cidr_mode,
            selected: BTreeSet::new(),
            draining: BTreeSet::new(),
            bypass_v4: BTreeMap::new(),
            bypass_v6: BTreeMap::new(),
            self_v4: BTreeSet::new(),
            self_v6: BTreeSet::new(),
        }
    }

    /// First-SYN / current-datagram outcome under this epoch, assuming
    /// `active=1` and a live listener. Matches `bypass_hit` plus E1/E4/E5:
    /// a UID miss or `DRAINING` is Direct; `RESERVED` and self-address are
    /// Direct regardless of `cidr_mode`.
    pub fn observe_new_flow(&self, uid: u32, dest: Dest) -> DecisionMode {
        if !self.selected.contains(&uid) {
            return DecisionMode::Direct;
        }
        if self.bypass_direct(dest) {
            return DecisionMode::Direct;
        }
        DecisionMode::Captured
    }

    fn bypass_direct(&self, dest: Dest) -> bool {
        match dest {
            Dest::V4(addr) => {
                if self.self_v4.contains(&addr) {
                    return true;
                }
                match lpm_v4(&self.bypass_v4, addr) {
                    Some(BypassTag::Reserved) => true,
                    Some(BypassTag::Policy) => self.cidr_mode == CidrMode::Blacklist,
                    None => self.cidr_mode == CidrMode::Whitelist,
                }
            }
            Dest::V6(addr) => {
                if self.self_v6.contains(&addr) {
                    return true;
                }
                match lpm_v6(&self.bypass_v6, addr) {
                    Some(BypassTag::Reserved) => true,
                    Some(BypassTag::Policy) => self.cidr_mode == CidrMode::Blacklist,
                    None => self.cidr_mode == CidrMode::Whitelist,
                }
            }
        }
    }
}

/// Desired epoch after a successful commit: `desired`'s sets and mode, with
/// UIDs that left `SELECTED` recorded as `DRAINING` (never deleted, §7.6).
pub fn committed(from: &PolicyEpoch, desired: &PolicyEpoch) -> PolicyEpoch {
    let mut draining = from.draining.clone();
    draining.extend(from.selected.difference(&desired.selected).copied());
    for uid in &desired.selected {
        draining.remove(uid);
    }
    PolicyEpoch {
        cidr_mode: desired.cidr_mode,
        selected: desired.selected.clone(),
        draining,
        bypass_v4: desired.bypass_v4.clone(),
        bypass_v6: desired.bypass_v6.clone(),
        self_v4: desired.self_v4.clone(),
        self_v6: desired.self_v6.clone(),
    }
}

/// Visible epochs under a true PolicyEpoch commit: old, then new. Never a mix.
pub fn epoch_commit_windows(from: &PolicyEpoch, desired: &PolicyEpoch) -> Vec<PolicyEpoch> {
    vec![from.clone(), committed(from, desired)]
}

/// Visible epochs under today's `apply_policy` order (blueprint §10.5 defect).
///
/// Additive UID / prefix / self-address writes, then `cidr_mode`, then
/// DRAINING and deletes. One snapshot is recorded after each of those six
/// phases, plus the starting epoch.
pub fn add_then_subtract_windows(from: &PolicyEpoch, desired: &PolicyEpoch) -> Vec<PolicyEpoch> {
    let mut windows = vec![from.clone()];
    let mut live = from.clone();

    for uid in &desired.selected {
        live.draining.remove(uid);
        live.selected.insert(*uid);
    }
    windows.push(live.clone());

    for (cidr, tag) in &desired.bypass_v4 {
        live.bypass_v4.insert(*cidr, *tag);
    }
    for (cidr, tag) in &desired.bypass_v6 {
        live.bypass_v6.insert(*cidr, *tag);
    }
    windows.push(live.clone());

    live.self_v4.extend(desired.self_v4.iter().copied());
    live.self_v6.extend(desired.self_v6.iter().copied());
    windows.push(live.clone());

    live.cidr_mode = desired.cidr_mode;
    windows.push(live.clone());

    let removed: Vec<u32> = live
        .selected
        .iter()
        .copied()
        .filter(|uid| !desired.selected.contains(uid))
        .collect();
    for uid in removed {
        live.selected.remove(&uid);
        live.draining.insert(uid);
    }
    windows.push(live.clone());

    live.bypass_v4
        .retain(|cidr, _| desired.bypass_v4.contains_key(cidr));
    live.bypass_v6
        .retain(|cidr, _| desired.bypass_v6.contains_key(cidr));
    live.self_v4.retain(|addr| desired.self_v4.contains(addr));
    live.self_v6.retain(|addr| desired.self_v6.contains(addr));
    windows.push(live);
    windows
}

/// Peak live LPM occupancy when adds happen before deletes.
///
/// Replacing one of `n` keys leaves `n - 1` shared, so the peak is `n + 1`.
pub fn add_then_subtract_peak_lpm(old_n: usize, new_n: usize, shared: usize) -> usize {
    old_n + new_n - shared
}

/// Peak occupancy of the live LPM under an epoch commit: the live bank is
/// untouched until the pointer swap, so the peak is `max(old, new)`.
pub fn epoch_peak_live_lpm(old_n: usize, new_n: usize) -> usize {
    old_n.max(new_n)
}

fn lpm_v4(map: &BTreeMap<Ipv4Cidr, BypassTag>, addr: Ipv4Addr) -> Option<BypassTag> {
    let mut best: Option<(u8, BypassTag)> = None;
    for (cidr, tag) in map {
        if v4_in(*cidr, addr) && best.map(|(len, _)| cidr.prefix_len > len).unwrap_or(true) {
            best = Some((cidr.prefix_len, *tag));
        }
    }
    best.map(|(_, tag)| tag)
}

fn lpm_v6(map: &BTreeMap<Ipv6Cidr, BypassTag>, addr: Ipv6Addr) -> Option<BypassTag> {
    let mut best: Option<(u8, BypassTag)> = None;
    for (cidr, tag) in map {
        if v6_in(*cidr, addr) && best.map(|(len, _)| cidr.prefix_len > len).unwrap_or(true) {
            best = Some((cidr.prefix_len, *tag));
        }
    }
    best.map(|(_, tag)| tag)
}

fn v4_in(cidr: Ipv4Cidr, addr: Ipv4Addr) -> bool {
    let bits = u32::from(addr);
    let net = u32::from(cidr.addr);
    bits & mask32(cidr.prefix_len) == net
}

fn v6_in(cidr: Ipv6Cidr, addr: Ipv6Addr) -> bool {
    let bits = u128::from(addr);
    let net = u128::from(cidr.addr);
    bits & mask128(cidr.prefix_len) == net
}

fn mask32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    }
}

fn mask128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::LPM_MAX_ENTRIES;

    const UID: u32 = 10123;
    const OTHER: u32 = 10456;

    fn policy_v4(text: &str) -> (Ipv4Cidr, BypassTag) {
        (
            Ipv4Cidr::parse(text).expect("canonical fixture"),
            BypassTag::Policy,
        )
    }

    fn reserved_v4(text: &str) -> (Ipv4Cidr, BypassTag) {
        (
            Ipv4Cidr::parse(text).expect("canonical fixture"),
            BypassTag::Reserved,
        )
    }

    fn dest(a: u8, b: u8, c: u8, d: u8) -> Dest {
        Dest::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn with_policy(mut epoch: PolicyEpoch, prefixes: &[&str]) -> PolicyEpoch {
        for text in prefixes {
            let (cidr, tag) = policy_v4(text);
            epoch.bypass_v4.insert(cidr, tag);
        }
        epoch
    }

    fn selected(mut epoch: PolicyEpoch, uids: &[u32]) -> PolicyEpoch {
        epoch.selected.extend(uids.iter().copied());
        epoch
    }

    fn third_state_verdict(
        from: &PolicyEpoch,
        desired: &PolicyEpoch,
        uid: u32,
        dest: Dest,
        windows: &[PolicyEpoch],
    ) -> Option<DecisionMode> {
        let old = from.observe_new_flow(uid, dest);
        let new = committed(from, desired).observe_new_flow(uid, dest);
        windows
            .iter()
            .map(|epoch| epoch.observe_new_flow(uid, dest))
            .find(|verdict| *verdict != old && *verdict != new)
    }

    fn endpoints_only(from: &PolicyEpoch, desired: &PolicyEpoch, windows: &[PolicyEpoch]) -> bool {
        let to = committed(from, desired);
        windows.iter().all(|epoch| epoch == from || epoch == &to)
    }

    /// Blacklist A → whitelist B: dest in A\B is Direct at both ends, Captured
    /// after the mode flip against the union.
    #[test]
    fn add_then_subtract_blacklist_to_whitelist_captures_old_prefix() {
        let from = selected(
            with_policy(PolicyEpoch::new(CidrMode::Blacklist), &["1.0.0.0/8"]),
            &[UID],
        );
        let desired = selected(
            with_policy(PolicyEpoch::new(CidrMode::Whitelist), &["2.0.0.0/8"]),
            &[UID],
        );
        let probe = dest(1, 2, 3, 4);
        assert_eq!(from.observe_new_flow(UID, probe), DecisionMode::Direct);
        assert_eq!(
            committed(&from, &desired).observe_new_flow(UID, probe),
            DecisionMode::Direct
        );

        let windows = add_then_subtract_windows(&from, &desired);
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &windows),
            Some(DecisionMode::Captured)
        );
        assert!(!endpoints_only(&from, &desired, &windows));

        let epoch_windows = epoch_commit_windows(&from, &desired);
        assert!(endpoints_only(&from, &desired, &epoch_windows));
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &epoch_windows),
            None
        );
    }

    /// Whitelist A → blacklist B: dest in A\B is Captured at both ends, Direct
    /// after the mode flip against the union.
    #[test]
    fn add_then_subtract_whitelist_to_blacklist_directs_old_prefix() {
        let from = selected(
            with_policy(PolicyEpoch::new(CidrMode::Whitelist), &["1.0.0.0/8"]),
            &[UID],
        );
        let desired = selected(
            with_policy(PolicyEpoch::new(CidrMode::Blacklist), &["2.0.0.0/8"]),
            &[UID],
        );
        let probe = dest(1, 2, 3, 4);
        assert_eq!(from.observe_new_flow(UID, probe), DecisionMode::Captured);
        assert_eq!(
            committed(&from, &desired).observe_new_flow(UID, probe),
            DecisionMode::Captured
        );

        let windows = add_then_subtract_windows(&from, &desired);
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &windows),
            Some(DecisionMode::Direct)
        );

        let epoch_windows = epoch_commit_windows(&from, &desired);
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &epoch_windows),
            None
        );
    }

    /// A newly selected UID becomes visible before its matching POLICY prefix.
    /// Both ends Direct (not selected → selected+bypassed); the window Captures.
    #[test]
    fn add_then_subtract_new_uid_before_new_bypass_captures() {
        let from = PolicyEpoch::new(CidrMode::Blacklist);
        let mut desired = selected(PolicyEpoch::new(CidrMode::Blacklist), &[UID]);
        let (cidr, tag) = policy_v4("8.8.8.0/24");
        desired.bypass_v4.insert(cidr, tag);
        let probe = dest(8, 8, 8, 8);

        assert_eq!(from.observe_new_flow(UID, probe), DecisionMode::Direct);
        assert_eq!(
            committed(&from, &desired).observe_new_flow(UID, probe),
            DecisionMode::Direct
        );

        let windows = add_then_subtract_windows(&from, &desired);
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &windows),
            Some(DecisionMode::Captured)
        );

        let epoch_windows = epoch_commit_windows(&from, &desired);
        assert_eq!(
            third_state_verdict(&from, &desired, UID, probe, &epoch_windows),
            None
        );
    }

    /// N full, replace one key: add-then-subtract needs N+1 live slots.
    #[test]
    fn add_then_subtract_replace_one_key_needs_n_plus_one() {
        let n = LPM_MAX_ENTRIES as usize;
        assert_eq!(add_then_subtract_peak_lpm(n, n, n - 1), n + 1);
        assert_eq!(epoch_peak_live_lpm(n, n), n);
        assert!(add_then_subtract_peak_lpm(n, n, n - 1) > LPM_MAX_ENTRIES as usize);
    }

    #[test]
    fn reserved_and_self_addr_are_direct_in_both_modes() {
        let mut epoch = selected(PolicyEpoch::new(CidrMode::Whitelist), &[UID]);
        let (cidr, tag) = reserved_v4("10.0.0.0/8");
        epoch.bypass_v4.insert(cidr, tag);
        epoch.self_v4.insert(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            epoch.observe_new_flow(UID, dest(10, 1, 2, 3)),
            DecisionMode::Direct
        );
        assert_eq!(
            epoch.observe_new_flow(UID, dest(192, 0, 2, 1)),
            DecisionMode::Direct
        );
        assert_eq!(
            epoch.observe_new_flow(UID, dest(1, 2, 3, 4)),
            DecisionMode::Direct
        );
        epoch.cidr_mode = CidrMode::Blacklist;
        assert_eq!(
            epoch.observe_new_flow(UID, dest(1, 2, 3, 4)),
            DecisionMode::Captured
        );
        assert_eq!(
            epoch.observe_new_flow(OTHER, dest(1, 2, 3, 4)),
            DecisionMode::Direct
        );
    }

    #[test]
    fn draining_new_flow_is_direct() {
        let mut epoch = PolicyEpoch::new(CidrMode::Blacklist);
        epoch.draining.insert(UID);
        assert_eq!(
            epoch.observe_new_flow(UID, dest(1, 2, 3, 4)),
            DecisionMode::Direct
        );
    }

    #[test]
    fn commit_moves_unselected_uids_to_draining() {
        let from = selected(PolicyEpoch::new(CidrMode::Blacklist), &[UID, OTHER]);
        let desired = selected(PolicyEpoch::new(CidrMode::Blacklist), &[UID]);
        let to = committed(&from, &desired);
        assert!(to.selected.contains(&UID));
        assert!(!to.selected.contains(&OTHER));
        assert!(to.draining.contains(&OTHER));
        assert!(!to.draining.contains(&UID));
    }
}
