//! Authoritative Phase 4 map table and explicit `BPF_MAP_CREATE` sequence.

use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use flux_core::abi::{self, Control, Counter, FaultKey, LpmV4Key, LpmV6Key, UidStats, MAP_NAMES};

use super::sys::{self, MapCreate, BPF_F_NO_PREALLOC};

const MAP_TYPE_HASH: u32 = 1;
const MAP_TYPE_ARRAY: u32 = 2;
const MAP_TYPE_PERCPU_HASH: u32 = 5;
const MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const MAP_TYPE_LPM_TRIE: u32 = 11;
const MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
const MAP_TYPE_SK_STORAGE: u32 = 24;
const MAP_TYPE_RINGBUF: u32 = 27;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub needs_btf: bool,
    pub needs_inner_map: bool,
}

pub const MAP_SPECS: [MapSpec; 12] = [
    MapSpec {
        name: abi::MAP_UID_POLICY,
        map_type: MAP_TYPE_HASH,
        key_size: 4,
        value_size: 1,
        max_entries: abi::UID_POLICY_MAX_ENTRIES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_BYPASS_V4,
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: size_of::<LpmV4Key>() as u32,
        value_size: 1,
        max_entries: abi::LPM_MAX_ENTRIES,
        map_flags: BPF_F_NO_PREALLOC,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_BYPASS_V6,
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: size_of::<LpmV6Key>() as u32,
        value_size: 1,
        max_entries: abi::LPM_MAX_ENTRIES,
        map_flags: BPF_F_NO_PREALLOC,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_SELF_ADDR_V4,
        map_type: MAP_TYPE_HASH,
        key_size: 4,
        value_size: 1,
        max_entries: abi::SELF_ADDR_MAX_ENTRIES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_SELF_ADDR_V6,
        map_type: MAP_TYPE_HASH,
        key_size: 16,
        value_size: 1,
        max_entries: abi::SELF_ADDR_MAX_ENTRIES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_UID_STATS,
        map_type: MAP_TYPE_PERCPU_HASH,
        key_size: 4,
        value_size: size_of::<UidStats>() as u32,
        max_entries: abi::UID_STATS_MAX_ENTRIES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_TCP_DECISION,
        map_type: MAP_TYPE_SK_STORAGE,
        key_size: 4,
        value_size: size_of::<abi::Decision>() as u32,
        max_entries: 0,
        map_flags: BPF_F_NO_PREALLOC,
        needs_btf: true,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_CONTROL_ROOT,
        map_type: MAP_TYPE_ARRAY_OF_MAPS,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: true,
    },
    MapSpec {
        name: abi::MAP_CONTROL_LEAF,
        map_type: MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: size_of::<Control>() as u32,
        max_entries: 1,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_FAULT_LATCH,
        map_type: MAP_TYPE_HASH,
        key_size: size_of::<FaultKey>() as u32,
        value_size: 1,
        max_entries: abi::FAULT_LATCH_MAX_ENTRIES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_FAULT_EVENTS,
        map_type: MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: abi::FAULT_RINGBUF_BYTES,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
    MapSpec {
        name: abi::MAP_COUNTERS,
        map_type: MAP_TYPE_PERCPU_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: abi::COUNTER_SLOTS,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    },
];

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
        Ok(Self {
            maps,
            control_published: false,
        })
    }

    pub fn fd(&self, name: &str) -> Option<RawFd> {
        self.maps
            .iter()
            .find(|map| map.identity.spec.name == name)
            .map(|map| map.fd.as_raw_fd())
    }

    pub fn publish_control(&mut self, control: &Control) -> io::Result<()> {
        let leaf_index = self
            .maps
            .iter()
            .position(|map| map.identity.spec.name == abi::MAP_CONTROL_LEAF)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "control_leaf map missing"))?;
        let root_fd = self
            .fd(abi::MAP_CONTROL_ROOT)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "control_root map missing"))?;

        let replacement = if self.control_published {
            Some(
                create_one(spec(abi::MAP_CONTROL_LEAF), -1, None).map_err(|failure| {
                    io::Error::new(
                        failure.error.kind(),
                        format!("{}: {}", failure.name, failure.error),
                    )
                })?,
            )
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
        sys::update_map(leaf_fd, &zero, as_bytes(control), 0)?;
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

    pub fn update_uid_mode(&self, uid: u32, mode: u8) -> io::Result<()> {
        let fd = self
            .fd(abi::MAP_UID_POLICY)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "uid_policy map missing"))?;
        sys::update_map(fd, &uid.to_ne_bytes(), &[mode], 0)
    }

    pub fn update_bypass_v4(&self, key: &LpmV4Key) -> io::Result<()> {
        self.update_one(abi::MAP_BYPASS_V4, as_bytes(key), &[1])
    }

    pub fn delete_bypass_v4(&self, key: &LpmV4Key) -> io::Result<()> {
        self.delete_one(abi::MAP_BYPASS_V4, as_bytes(key))
    }

    pub fn update_bypass_v6(&self, key: &LpmV6Key) -> io::Result<()> {
        self.update_one(abi::MAP_BYPASS_V6, as_bytes(key), &[1])
    }

    pub fn delete_bypass_v6(&self, key: &LpmV6Key) -> io::Result<()> {
        self.delete_one(abi::MAP_BYPASS_V6, as_bytes(key))
    }

    pub fn update_self_v4(&self, address: &[u8; 4]) -> io::Result<()> {
        self.update_one(abi::MAP_SELF_ADDR_V4, address, &[1])
    }

    pub fn delete_self_v4(&self, address: &[u8; 4]) -> io::Result<()> {
        self.delete_one(abi::MAP_SELF_ADDR_V4, address)
    }

    pub fn update_self_v6(&self, address: &[u8; 16]) -> io::Result<()> {
        self.update_one(abi::MAP_SELF_ADDR_V6, address, &[1])
    }

    pub fn delete_self_v6(&self, address: &[u8; 16]) -> io::Result<()> {
        self.delete_one(abi::MAP_SELF_ADDR_V6, address)
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
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        sys::update_map(fd, key, value, 0)
    }

    fn delete_one(&self, name: &str, key: &[u8]) -> io::Result<()> {
        let fd = self.fd(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} map missing"))
        })?;
        match sys::delete_map(fd, key) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    #[allow(dead_code)] // Read through Runtime by the Phase 4 device test.
    pub fn identities(&self) -> Vec<MapIdentity> {
        self.maps.iter().map(|map| map.identity.clone()).collect()
    }
}

fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: `value` remains alive for the returned slice and the byte view
    // has exactly the size of T. Kernel ABI structs are copied, never retained.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
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
        assert_eq!(spec(abi::MAP_BYPASS_V4).map_flags, BPF_F_NO_PREALLOC);
    }
}
