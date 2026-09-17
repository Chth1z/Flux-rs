//! Explicit `BPF_MAP_CREATE` sequence over [`super::map_table::MAP_SPECS`].

use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

#[cfg(test)]
use flux_core::abi::UidStats;
use flux_core::abi::{self, Control, Counter, FaultKey, LpmV4Key, LpmV6Key, MAP_NAMES};

use super::sys::{self, MapCreate, BPF_F_NO_PREALLOC};

pub use super::map_table::{MapSpec, MAP_SPECS};

const _: () = assert!(
    super::map_table::BPF_F_NO_PREALLOC == BPF_F_NO_PREALLOC,
    "map table NO_PREALLOC must match bpf(2) BPF_F_NO_PREALLOC"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapIdentity {
    pub spec: MapSpec,
    pub id: u32,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

struct MapHandle {
    fd: OwnedFd,
    identity: MapIdentity,
}

pub struct MapSet {
    maps: Vec<MapHandle>,
    control_published: bool,
    /// Unfrozen ARRAY leaf reserved so `publish_inactive` never `MAP_CREATE`s.
    /// Freeze is irreversible on 5.15, so this is a pool slot, not a recycled
    /// live leaf. Not an ELF `.maps` object.
    spare_leaf: Option<OwnedFd>,
}

pub struct MapCreateFailure {
    pub name: &'static str,
    pub error: io::Error,
}

impl MapSet {
    pub fn create(btf_fd: RawFd) -> Result<Self, MapCreateFailure> {
        let mut pending = BTreeMap::<&'static str, OwnedFd>::new();
        let leaf = spec(abi::MAP_CONTROL_LEAF);
        let leaf_fd = create_one(leaf, btf_fd, None)?;
        pending.insert(leaf.name, leaf_fd);

        for map in MAP_SPECS
            .iter()
            .filter(|map| map.name != abi::MAP_CONTROL_LEAF && !map.needs_inner_map)
        {
            let fd = create_one(*map, btf_fd, None)?;
            pending.insert(map.name, fd);
        }

        let leaf_raw = pending
            .get(abi::MAP_CONTROL_LEAF)
            .expect("control leaf inserted")
            .as_raw_fd();
        let root = spec(abi::MAP_CONTROL_ROOT);
        let root_fd = create_one(root, btf_fd, Some(leaf_raw))?;
        pending.insert(root.name, root_fd);

        let mut maps = Vec::with_capacity(MAP_NAMES.len());
        for name in MAP_NAMES {
            let fd = pending.remove(name).ok_or_else(|| MapCreateFailure {
                name,
                error: io::Error::new(io::ErrorKind::InvalidData, "map table assembly failed"),
            })?;
            let map_spec = spec(name);
            let info =
                sys::map_info(fd.as_raw_fd()).map_err(|error| MapCreateFailure { name, error })?;
            verify_info(map_spec, &info).map_err(|error| MapCreateFailure { name, error })?;
            maps.push(MapHandle {
                fd,
                identity: MapIdentity {
                    spec: map_spec,
                    id: info.id,
                    btf_id: info.btf_id,
                    btf_key_type_id: info.btf_key_type_id,
                    btf_value_type_id: info.btf_value_type_id,
                },
            });
        }
        if !pending.is_empty() {
            return Err(MapCreateFailure {
                name: "map_table",
                error: io::Error::new(io::ErrorKind::InvalidData, "unexpected map remained"),
            });
        }
        let spare_leaf = create_one(spec(abi::MAP_CONTROL_LEAF), -1, None)?;
        Ok(Self {
            maps,
            control_published: false,
            spare_leaf: Some(spare_leaf),
        })
    }

    pub fn fd(&self, name: &str) -> Option<RawFd> {
        self.maps
            .iter()
            .find(|map| map.identity.spec.name == name)
            .map(|map| map.fd.as_raw_fd())
    }

    pub fn publish_control(&mut self, control: &Control) -> io::Result<()> {
        self.publish_leaf(control, SparePolicy::Refill)
    }

    /// Same pointer swap as [`Self::publish_control`], but never
    /// `BPF_MAP_CREATE`. An empty spare is `inactive_publish_failed`.
    pub fn publish_inactive_control(&mut self, control: &Control) -> io::Result<()> {
        self.publish_leaf(control, SparePolicy::NoCreate)
    }

    fn publish_leaf(&mut self, control: &Control, spare: SparePolicy) -> io::Result<()> {
        if control.policy_bank > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("policy_bank {} is not 0 or 1", control.policy_bank),
            ));
        }
        let leaf_index = self
            .maps
            .iter()
            .position(|map| map.identity.spec.name == abi::MAP_CONTROL_LEAF)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "control_leaf map missing"))?;
        let root_fd = self
            .fd(abi::MAP_CONTROL_ROOT)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "control_root map missing"))?;

        let replacement = if self.control_published {
            match self.spare_leaf.take() {
                Some(fd) => Some(fd),
                None if spare == SparePolicy::Refill => Some(
                    create_one(spec(abi::MAP_CONTROL_LEAF), -1, None).map_err(|failure| {
                        io::Error::new(
                            failure.error.kind(),
                            format!("{}: {}", failure.name, failure.error),
                        )
                    })?,
                ),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "inactive_publish_failed: no reserved control leaf",
                    ));
                }
            }
        } else {
            None
        };
        let leaf_fd = replacement
            .as_ref()
            .map_or(self.maps[leaf_index].fd.as_raw_fd(), AsRawFd::as_raw_fd);
        let replacement_info = replacement
            .as_ref()
            .map(|fd| sys::map_info(fd.as_raw_fd()))
            .transpose()?;
        if let Some(info) = &replacement_info {
            verify_info(spec(abi::MAP_CONTROL_LEAF), info)?;
        }
        let zero = 0u32.to_ne_bytes();
        let control_bytes = as_bytes(control);
        if control_bytes.len() != spec(abi::MAP_CONTROL_LEAF).value_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control leaf value size mismatch",
            ));
        }
        sys::update_map(leaf_fd, &zero, control_bytes, 0)?;
        sys::freeze_map(leaf_fd)?;
        sys::update_map(root_fd, &zero, &(leaf_fd as u32).to_ne_bytes(), 0)?;

        if let (Some(fd), Some(info)) = (replacement, replacement_info) {
            let map_spec = spec(abi::MAP_CONTROL_LEAF);
            self.maps[leaf_index] = MapHandle {
                fd,
                identity: MapIdentity {
                    spec: map_spec,
                    id: info.id,
                    btf_id: info.btf_id,
                    btf_key_type_id: info.btf_key_type_id,
                    btf_value_type_id: info.btf_value_type_id,
                },
            };
        }
        self.control_published = true;
        if spare == SparePolicy::Refill && self.spare_leaf.is_none() {
            self.spare_leaf = Some(create_one(spec(abi::MAP_CONTROL_LEAF), -1, None).map_err(
                |failure| {
                    io::Error::new(
                        failure.error.kind(),
                        format!("{}: {}", failure.name, failure.error),
                    )
                },
            )?);
        }
        Ok(())
    }

    pub fn counter_sum(&self, counter: Counter) -> io::Result<u64> {
        let fd = self
            .fd(abi::MAP_COUNTERS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "counters map missing"))?;
        let cpus = possible_cpu_count()?;
        let mut values = vec![0u8; cpus * size_of::<u64>()];
        sys::lookup_map(fd, &(counter as u32).to_ne_bytes(), &mut values)?;
        Ok(values
            .chunks_exact(size_of::<u64>())
            .map(|bytes| u64::from_ne_bytes(bytes.try_into().expect("u64 chunk")))
            .sum())
    }

    pub fn update_uid_mode(&self, bank: u8, uid: u32, mode: u8) -> io::Result<()> {
        let name = abi::uid_policy_map(bank);
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        sys::update_map(fd, &uid.to_ne_bytes(), &[mode], 0)
    }

    pub fn delete_uid_mode(&self, bank: u8, uid: u32) -> io::Result<()> {
        self.delete_one(abi::uid_policy_map(bank), &uid.to_ne_bytes())
    }

    pub fn uid_keys(&self, bank: u8) -> io::Result<Vec<u32>> {
        let keys = self.collect_keys(abi::uid_policy_map(bank), 4)?;
        keys.into_iter()
            .map(|key| {
                key.try_into().map(u32::from_ne_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "uid key was not 4 bytes")
                })
            })
            .collect()
    }

    pub fn update_bypass_v4(
        &self,
        bank: u8,
        key: &LpmV4Key,
        tag: abi::BypassTag,
    ) -> io::Result<()> {
        self.update_one(abi::bypass_v4_map(bank), as_bytes(key), &[tag as u8])
    }

    pub fn delete_bypass_v4(&self, bank: u8, key: &LpmV4Key) -> io::Result<()> {
        self.delete_one(abi::bypass_v4_map(bank), as_bytes(key))
    }

    pub fn bypass_v4_keys(&self, bank: u8) -> io::Result<Vec<LpmV4Key>> {
        collect_typed_keys(self.collect_keys(abi::bypass_v4_map(bank), size_of::<LpmV4Key>())?)
    }

    pub fn update_bypass_v6(
        &self,
        bank: u8,
        key: &LpmV6Key,
        tag: abi::BypassTag,
    ) -> io::Result<()> {
        self.update_one(abi::bypass_v6_map(bank), as_bytes(key), &[tag as u8])
    }

    pub fn delete_bypass_v6(&self, bank: u8, key: &LpmV6Key) -> io::Result<()> {
        self.delete_one(abi::bypass_v6_map(bank), as_bytes(key))
    }

    pub fn bypass_v6_keys(&self, bank: u8) -> io::Result<Vec<LpmV6Key>> {
        collect_typed_keys(self.collect_keys(abi::bypass_v6_map(bank), size_of::<LpmV6Key>())?)
    }

    pub fn update_self_v4(&self, bank: u8, address: &[u8; 4]) -> io::Result<()> {
        self.update_one(abi::self_addr_v4_map(bank), address, &[1])
    }

    pub fn delete_self_v4(&self, bank: u8, address: &[u8; 4]) -> io::Result<()> {
        self.delete_one(abi::self_addr_v4_map(bank), address)
    }

    pub fn self_v4_keys(&self, bank: u8) -> io::Result<Vec<[u8; 4]>> {
        collect_typed_keys(self.collect_keys(abi::self_addr_v4_map(bank), 4)?)
    }

    pub fn update_self_v6(&self, bank: u8, address: &[u8; 16]) -> io::Result<()> {
        self.update_one(abi::self_addr_v6_map(bank), address, &[1])
    }

    pub fn delete_self_v6(&self, bank: u8, address: &[u8; 16]) -> io::Result<()> {
        self.delete_one(abi::self_addr_v6_map(bank), address)
    }

    pub fn self_v6_keys(&self, bank: u8) -> io::Result<Vec<[u8; 16]>> {
        collect_typed_keys(self.collect_keys(abi::self_addr_v6_map(bank), 16)?)
    }

    pub fn clear_fault_latch(&self) -> io::Result<()> {
        let fd = self
            .fd(abi::MAP_FAULT_LATCH)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fault_latch map missing"))?;
        // active=0 prevents new latch insertions while userspace drains this
        // small map. Repeatedly ask for the first key so deletion cannot make
        // an iterator cursor stale.
        loop {
            let mut key = [0u8; size_of::<FaultKey>()];
            if !sys::next_map_key(fd, None, &mut key)? {
                return Ok(());
            }
            match sys::delete_map(fd, &key) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub fn delete_fault_latch(&self, key: &FaultKey) -> io::Result<()> {
        self.delete_one(abi::MAP_FAULT_LATCH, as_bytes(key))
    }

    /// Read by the Phase 6 device test, which includes this module; the
    /// daemon's own unit tests never call it, hence the allowance.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn uid_stats_sum(&self, uid: u32) -> io::Result<UidStats> {
        let fd = self
            .fd(abi::MAP_UID_STATS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "uid_stats map missing"))?;
        let cpus = possible_cpu_count()?;
        let mut values = vec![0u8; cpus * size_of::<UidStats>()];
        sys::lookup_map(fd, &uid.to_ne_bytes(), &mut values)?;
        let mut total = UidStats::default();
        for value in values.chunks_exact(size_of::<UidStats>()) {
            total.packets = total.packets.saturating_add(u64::from_ne_bytes(
                value[..8].try_into().expect("uid stats packet chunk"),
            ));
            total.bytes = total.bytes.saturating_add(u64::from_ne_bytes(
                value[8..16].try_into().expect("uid stats byte chunk"),
            ));
        }
        Ok(total)
    }

    fn update_one(&self, name: &str, key: &[u8], value: &[u8]) -> io::Result<()> {
        let map = spec(name);
        if !entry_fits(map, key, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name}: entry size mismatch (key {}/{}, value {}/{})",
                    key.len(),
                    map.key_size,
                    value.len(),
                    map.value_size
                ),
            ));
        }
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        sys::update_map(fd, key, value, 0)
    }

    fn delete_one(&self, name: &str, key: &[u8]) -> io::Result<()> {
        let map = spec(name);
        if key.len() != map.key_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name}: key size mismatch ({} / {})",
                    key.len(),
                    map.key_size
                ),
            ));
        }
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        match sys::delete_map(fd, key) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn collect_keys(&self, name: &str, key_len: usize) -> io::Result<Vec<Vec<u8>>> {
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        let mut keys = Vec::new();
        let mut previous: Option<Vec<u8>> = None;
        loop {
            let mut next = vec![0u8; key_len];
            if !sys::next_map_key(fd, previous.as_deref(), &mut next)? {
                return Ok(keys);
            }
            keys.push(next.clone());
            previous = Some(next);
        }
    }

    /// Backs `Runtime::maps` for the Phase 4 device test; unused by this
    /// crate's own unit tests.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn identities(&self) -> Vec<MapIdentity> {
        self.maps.iter().map(|map| map.identity.clone()).collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SparePolicy {
    Refill,
    NoCreate,
}

fn collect_typed_keys<T: Copy>(keys: Vec<Vec<u8>>) -> io::Result<Vec<T>> {
    keys.into_iter()
        .map(|key| {
            if key.len() != size_of::<T>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "map key was {} bytes, expected {}",
                        key.len(),
                        size_of::<T>()
                    ),
                ));
            }
            let mut value = std::mem::MaybeUninit::<T>::uninit();
            // SAFETY: `key` is exactly size_of::<T>() and T is a kernel ABI
            // struct (repr(C) POD). The copy is the only write before assume_init.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    key.as_ptr(),
                    value.as_mut_ptr().cast::<u8>(),
                    size_of::<T>(),
                );
                Ok(value.assume_init())
            }
        })
        .collect()
}

/// Closed set of kernel ABI records that may cross `bpf(2)` as bytes.
/// A type that is not `MapPod` cannot be passed to [`as_bytes`].
trait MapPod: Copy + 'static {}

impl MapPod for Control {}
impl MapPod for LpmV4Key {}
impl MapPod for LpmV6Key {}
impl MapPod for FaultKey {}
impl MapPod for u32 {}
impl MapPod for [u8; 4] {}
impl MapPod for [u8; 16] {}
impl MapPod for u8 {}

fn as_bytes<T: MapPod>(value: &T) -> &[u8] {
    // SAFETY: `T` is a closed POD set; `value` remains alive for the slice
    // and the byte view has exactly the size of T.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn entry_fits(map: MapSpec, key: &[u8], value: &[u8]) -> bool {
    key.len() == map.key_size as usize && value.len() == map.value_size as usize
}

fn possible_cpu_count() -> io::Result<usize> {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/possible")?;
    let mut count = 0usize;
    for item in text.trim().split(',') {
        let mut bounds = item.split('-');
        let start = bounds
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid cpu possible set")
            })?;
        let end = bounds
            .next()
            .map_or(Some(start), |value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid cpu possible range")
            })?;
        if bounds.next().is_some() || end < start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid cpu possible range",
            ));
        }
        count = count
            .checked_add(end - start + 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cpu count overflow"))?;
    }
    if count == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty cpu possible set",
        ))
    } else {
        Ok(count)
    }
}

fn create_one(
    map: MapSpec,
    btf_fd: RawFd,
    inner_map_fd: Option<RawFd>,
) -> Result<OwnedFd, MapCreateFailure> {
    sys::create_map(MapCreate {
        map_type: map.map_type,
        key_size: map.key_size,
        value_size: map.value_size,
        max_entries: map.max_entries,
        map_flags: map.map_flags,
        inner_map_fd,
        name: map.name,
        btf_fd: map.needs_btf.then_some(btf_fd),
        btf_key_type_id: if map.needs_btf {
            flux_core::btf::KEY_TYPE_ID
        } else {
            0
        },
        btf_value_type_id: if map.needs_btf {
            flux_core::btf::VALUE_TYPE_ID
        } else {
            0
        },
    })
    .map_err(|error| MapCreateFailure {
        name: map.name,
        error,
    })
}

fn verify_info(map: MapSpec, info: &sys::MapInfo) -> io::Result<()> {
    let exact = info.map_type == map.map_type
        && info.key_size == map.key_size
        && info.value_size == map.value_size
        && info.max_entries == map.max_entries
        && info.map_flags == map.map_flags
        && info.name == map.name
        && info.id != 0;
    if !exact {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kernel map identity differs: spec={map:?}, info={info:?}"),
        ));
    }
    if map.needs_btf
        && (info.btf_id == 0
            || info.btf_key_type_id != flux_core::btf::KEY_TYPE_ID
            || info.btf_value_type_id != flux_core::btf::VALUE_TYPE_ID)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SK_STORAGE BTF identity differs: {info:?}"),
        ));
    }
    Ok(())
}

fn spec(name: &str) -> MapSpec {
    *MAP_SPECS
        .iter()
        .find(|map| map.name == name)
        .expect("ABI map name must have a map spec")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_order_is_the_abi_order() {
        assert_eq!(MAP_SPECS.map(|map| map.name), MAP_NAMES);
    }

    #[test]
    fn table_contains_exactly_one_inner_and_one_btf_map() {
        assert_eq!(
            MAP_SPECS.iter().filter(|map| map.needs_inner_map).count(),
            1
        );
        assert_eq!(MAP_SPECS.iter().filter(|map| map.needs_btf).count(), 1);
        assert!(spec(abi::MAP_CONTROL_ROOT).needs_inner_map);
        assert!(spec(abi::MAP_TCP_DECISION).needs_btf);
    }

    #[test]
    fn special_map_shapes_match_the_contract() {
        assert_eq!(spec(abi::MAP_FAULT_EVENTS).max_entries, 16_384);
        assert_eq!(spec(abi::MAP_FAULT_EVENTS).key_size, 0);
        assert_eq!(spec(abi::MAP_CONTROL_LEAF).value_size, 96);
        assert_eq!(spec(abi::MAP_TCP_DECISION).value_size, 16);
        assert_eq!(spec(abi::MAP_BYPASS_V4_0).map_flags, BPF_F_NO_PREALLOC);
        assert_eq!(spec(abi::MAP_BYPASS_V4_1).map_flags, BPF_F_NO_PREALLOC);
        assert_eq!(
            spec(abi::MAP_UID_POLICY_0).max_entries,
            spec(abi::MAP_UID_POLICY_1).max_entries
        );
        assert_eq!(
            size_of::<Control>(),
            spec(abi::MAP_CONTROL_LEAF).value_size as usize
        );
        assert_eq!(
            size_of::<LpmV4Key>(),
            spec(abi::MAP_BYPASS_V4_0).key_size as usize
        );
        assert_eq!(
            size_of::<FaultKey>(),
            spec(abi::MAP_FAULT_LATCH).key_size as usize
        );
        assert_eq!(spec(abi::MAP_UID_POLICY_0).key_size, 4);
        assert_eq!(spec(abi::MAP_UID_POLICY_0).value_size, 1);
    }

    #[test]
    fn mismatched_entry_sizes_cannot_reach_bpf() {
        let control = spec(abi::MAP_CONTROL_LEAF);
        assert!(!entry_fits(control, &[0; 4], &[0u8; 8]));
        assert!(entry_fits(
            control,
            &0u32.to_ne_bytes(),
            &vec![0u8; size_of::<Control>()]
        ));
        let uid = spec(abi::MAP_UID_POLICY_0);
        assert!(!entry_fits(uid, &[0; 8], &[1]));
        assert!(entry_fits(uid, &[0; 4], &[1]));
        assert_eq!(
            size_of::<LpmV6Key>(),
            spec(abi::MAP_BYPASS_V6_0).key_size as usize
        );
    }
}
