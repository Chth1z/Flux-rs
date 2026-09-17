//! Canonical BPF map parameters. `maps.rs` creates the kernel objects from
//! this table; `build.rs` emits C placeholders so clang sees the same sizes
//! and names. Do not hand-edit a second copy in `bpf/flux.bpf.c`.

use std::mem::size_of;

use flux_core::abi::{self, Control, FaultKey, LpmV4Key, LpmV6Key, UidStats};

pub const MAP_TYPE_HASH: u32 = 1;
pub const MAP_TYPE_ARRAY: u32 = 2;
pub const MAP_TYPE_PERCPU_HASH: u32 = 5;
pub const MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const MAP_TYPE_LPM_TRIE: u32 = 11;
pub const MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
pub const MAP_TYPE_SK_STORAGE: u32 = 24;
pub const MAP_TYPE_RINGBUF: u32 = 27;

/// Matches `bpf(2)` `BPF_F_NO_PREALLOC`. Duplicated from `sys.rs` so this
/// table compiles in `build.rs` without Linux headers.
pub const BPF_F_NO_PREALLOC: u32 = 1;

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

const fn hash_u8(name: &'static str, key_size: u32, max_entries: u32) -> MapSpec {
    MapSpec {
        name,
        map_type: MAP_TYPE_HASH,
        key_size,
        value_size: 1,
        max_entries,
        map_flags: 0,
        needs_btf: false,
        needs_inner_map: false,
    }
}

const fn lpm(name: &'static str, key_size: u32) -> MapSpec {
    MapSpec {
        name,
        map_type: MAP_TYPE_LPM_TRIE,
        key_size,
        value_size: 1,
        max_entries: abi::LPM_MAX_ENTRIES,
        map_flags: BPF_F_NO_PREALLOC,
        needs_btf: false,
        needs_inner_map: false,
    }
}

pub const MAP_SPECS: [MapSpec; 17] = [
    hash_u8(abi::MAP_UID_POLICY_0, 4, abi::UID_POLICY_MAX_ENTRIES),
    hash_u8(abi::MAP_UID_POLICY_1, 4, abi::UID_POLICY_MAX_ENTRIES),
    lpm(abi::MAP_BYPASS_V4_0, size_of::<LpmV4Key>() as u32),
    lpm(abi::MAP_BYPASS_V4_1, size_of::<LpmV4Key>() as u32),
    lpm(abi::MAP_BYPASS_V6_0, size_of::<LpmV6Key>() as u32),
    lpm(abi::MAP_BYPASS_V6_1, size_of::<LpmV6Key>() as u32),
    hash_u8(abi::MAP_SELF_ADDR_V4_0, 4, abi::SELF_ADDR_MAX_ENTRIES),
    hash_u8(abi::MAP_SELF_ADDR_V4_1, 4, abi::SELF_ADDR_MAX_ENTRIES),
    hash_u8(abi::MAP_SELF_ADDR_V6_0, 16, abi::SELF_ADDR_MAX_ENTRIES),
    hash_u8(abi::MAP_SELF_ADDR_V6_1, 16, abi::SELF_ADDR_MAX_ENTRIES),
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
        max_entries: abi::FAULT_LATCH_MAX_ENTRIES,
        value_size: 1,
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

#[allow(dead_code)] // build.rs emits C; the daemon only consumes MAP_SPECS.
fn bpf_map_type_name(map_type: u32) -> &'static str {
    match map_type {
        MAP_TYPE_HASH => "BPF_MAP_TYPE_HASH",
        MAP_TYPE_ARRAY => "BPF_MAP_TYPE_ARRAY",
        MAP_TYPE_PERCPU_HASH => "BPF_MAP_TYPE_PERCPU_HASH",
        MAP_TYPE_PERCPU_ARRAY => "BPF_MAP_TYPE_PERCPU_ARRAY",
        MAP_TYPE_LPM_TRIE => "BPF_MAP_TYPE_LPM_TRIE",
        MAP_TYPE_ARRAY_OF_MAPS => "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        MAP_TYPE_SK_STORAGE => "BPF_MAP_TYPE_SK_STORAGE",
        MAP_TYPE_RINGBUF => "BPF_MAP_TYPE_RINGBUF",
        other => panic!("MAP_SPECS has unknown map_type {other}"),
    }
}

#[allow(dead_code)]
fn c_key_size(spec: &MapSpec) -> String {
    match spec.name {
        abi::MAP_BYPASS_V4_0 | abi::MAP_BYPASS_V4_1 => "sizeof(struct flux_lpm_v4_key)".to_string(),
        abi::MAP_BYPASS_V6_0 | abi::MAP_BYPASS_V6_1 => "sizeof(struct flux_lpm_v6_key)".to_string(),
        abi::MAP_FAULT_LATCH => "sizeof(struct flux_fault_key)".to_string(),
        abi::MAP_TCP_DECISION => "sizeof(int)".to_string(),
        _ => spec.key_size.to_string(),
    }
}

#[allow(dead_code)]
fn c_value_size(spec: &MapSpec) -> String {
    match spec.name {
        abi::MAP_CONTROL_LEAF => "sizeof(struct flux_control)".to_string(),
        abi::MAP_TCP_DECISION => "sizeof(struct flux_decision)".to_string(),
        abi::MAP_UID_STATS => "sizeof(struct flux_uid_stats)".to_string(),
        _ => spec.value_size.to_string(),
    }
}

#[allow(dead_code)]
fn emit_fields(spec: &MapSpec) -> String {
    let mut fields = format!(
        "\t__uint(type, {});\n\t__uint(max_entries, {});",
        bpf_map_type_name(spec.map_type),
        spec.max_entries
    );
    if spec.map_flags != 0 {
        fields.push_str("\n\t__uint(map_flags, BPF_F_NO_PREALLOC);");
    }
    if spec.needs_inner_map {
        fields.push_str("\n\t__type(key, __u32);");
        fields.push_str("\n\t__array(values, struct control_leaf);");
        return fields;
    }
    if spec.map_type != MAP_TYPE_RINGBUF {
        fields.push_str(&format!("\n\t__uint(key_size, {});", c_key_size(spec)));
        fields.push_str(&format!("\n\t__uint(value_size, {});", c_value_size(spec)));
    }
    fields
}

/// C placeholders compiled into the BPF object. Symbol names are the reloc
/// keys; the loader still creates maps from [`MAP_SPECS`].
///
/// Called from `fluxd/build.rs` via `#[path]`; the daemon binary never
/// emits headers, so the helper is dead in that crate graph.
#[allow(dead_code)]
pub fn emit_c_header() -> String {
    let mut out = String::from(
        "/* Generated from crates/fluxd/src/bpf/map_table.rs MAP_SPECS. Do not edit. */\n\n",
    );
    for spec in &MAP_SPECS {
        let fields = emit_fields(spec);
        if spec.name == abi::MAP_CONTROL_LEAF {
            // Named type, not a SEC(".maps") object: control_root's inner map.
            // value_size rather than __type(value, struct flux_control) so
            // clang does not prune flux_control to a BTF FWD.
            out.push_str(&format!("struct control_leaf {{\n{fields}\n}};\n\n"));
            continue;
        }
        out.push_str(&format!(
            "struct {{\n{fields}\n}} {} SEC(\".maps\");\n\n",
            spec.name
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_c_carries_every_abi_map_name() {
        let header = emit_c_header();
        for name in abi::MAP_NAMES {
            assert!(header.contains(name), "{name} missing from generated C");
        }
        assert!(header.contains("struct control_leaf"));
        assert!(
            !header.contains("} control_leaf SEC"),
            "control_leaf must not be a named .maps object"
        );
        assert!(header.contains("control_root SEC(\".maps\")"));
        assert!(header.contains("sizeof(struct flux_control)"));
    }
}
