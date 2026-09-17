//! `cargo xtask abi-check` — the CI cross-check demanded by blueprint §6.
//!
//! `bpf/include/flux_abi.h` is the only source of truth and
//! `crates/flux-core/src/abi.rs` mirrors it by hand. This task makes the two
//! unable to drift silently:
//!
//! 1. Every struct's `sizeof` / `_Alignof` / per-field `offsetof` is asserted
//!    by **clang** against the values the Rust compiler produced for the
//!    mirror (`core::mem::offset_of!`). The generated translation unit is all
//!    `_Static_assert`s, compiled with `-fsyntax-only` for both the `bpf` and
//!    the `aarch64-unknown-linux-gnu` targets — nothing runs, so the check
//!    works on any host.
//! 2. Every numeric `#define` and enum member is asserted the same way, so
//!    expression-valued constants (`FLUX_MAX_PULL_BYTES`) are evaluated by the
//!    C preprocessor and compiler, not re-parsed here.
//! 3. String defines (map/program/section names, listener addresses) are
//!    extracted textually and compared byte-for-byte.
//! 4. The set of `FLUX_*` define names in the header must equal the set this
//!    task knows, both ways, so a constant added on one side only is an error
//!    even before its value can disagree.
//!
//! The header includes only `<linux/types.h>`, which is stubbed with the
//! fixed-width typedefs it guarantees, so the check does not depend on kernel
//! headers being installed (or on the host being Linux at all).

use crate::{cdefs, util};
use core::mem::{align_of, offset_of, size_of};
use flux_core::abi;
use std::process::Command;

struct Field {
    name: &'static str,
    offset: usize,
}

struct StructSpec {
    c_name: &'static str,
    size: usize,
    align: usize,
    fields: Vec<Field>,
}

macro_rules! struct_spec {
    ($c_name:literal, $ty:ty, [$($field:ident),+ $(,)?]) => {
        StructSpec {
            c_name: $c_name,
            size: size_of::<$ty>(),
            align: align_of::<$ty>(),
            fields: vec![$(Field {
                name: stringify!($field),
                offset: offset_of!($ty, $field),
            }),+],
        }
    };
}

fn struct_specs() -> Vec<StructSpec> {
    vec![
        struct_spec!(
            "flux_decision",
            abi::Decision,
            [magic, mode, reserved, generation]
        ),
        struct_spec!(
            "flux_control",
            abi::Control,
            [
                abi_magic,
                active,
                generation,
                flxrs0_ifindex,
                flxrs1_ifindex,
                listen_port_v4,
                listen_port_v6,
                listen_v4,
                probe_remote_v4,
                probe_remote_port,
                cidr_mode,
                listen_v6,
                probe_remote_v6,
                selected_count,
                draining_count,
                bypass_v4_count,
                bypass_v6_count,
                policy_bank,
                pad1,
            ]
        ),
        struct_spec!("flux_uid_stats", abi::UidStats, [packets, bytes]),
        struct_spec!("flux_lpm_v4_key", abi::LpmV4Key, [prefixlen, addr]),
        struct_spec!("flux_lpm_v6_key", abi::LpmV6Key, [prefixlen, addr]),
        struct_spec!(
            "flux_fault_key",
            abi::FaultKey,
            [generation, family, protocol, reason, pad0]
        ),
        struct_spec!(
            "flux_fault_event",
            abi::FaultEvent,
            [generation, family, protocol, reason, pad0, seq, pad1]
        ),
    ]
}

/// Numeric `#define`s: C name paired with the mirrored Rust value.
fn numeric_defines() -> Vec<(&'static str, u64)> {
    vec![
        ("FLUX_ABI_MAGIC", u64::from(abi::FLUX_ABI_MAGIC)),
        ("FLUX_DECISION_MAGIC", u64::from(abi::FLUX_DECISION_MAGIC)),
        ("FLUX_BYPASS_RESERVED", abi::BypassTag::Reserved as u64),
        ("FLUX_BYPASS_POLICY", abi::BypassTag::Policy as u64),
        (
            "FLUX_UID_POLICY_MAX_ENTRIES",
            u64::from(abi::UID_POLICY_MAX_ENTRIES),
        ),
        ("FLUX_UID_SELECTED_MAX", u64::from(abi::UID_SELECTED_MAX)),
        ("FLUX_LPM_MAX_ENTRIES", u64::from(abi::LPM_MAX_ENTRIES)),
        (
            "FLUX_SELF_ADDR_MAX_ENTRIES",
            u64::from(abi::SELF_ADDR_MAX_ENTRIES),
        ),
        (
            "FLUX_UID_STATS_MAX_ENTRIES",
            u64::from(abi::UID_STATS_MAX_ENTRIES),
        ),
        (
            "FLUX_FAULT_LATCH_MAX_ENTRIES",
            u64::from(abi::FAULT_LATCH_MAX_ENTRIES),
        ),
        (
            "FLUX_FAULT_RINGBUF_BYTES",
            u64::from(abi::FAULT_RINGBUF_BYTES),
        ),
        ("FLUX_COUNTER_SLOTS", u64::from(abi::COUNTER_SLOTS)),
        ("FLUX_APP_ID_MIN", u64::from(abi::APP_ID_MIN)),
        ("FLUX_APP_ID_MAX", u64::from(abi::APP_ID_MAX)),
        ("FLUX_USER_ID_STRIDE", u64::from(abi::USER_ID_STRIDE)),
        ("FLUX_USER_ID_MAX", u64::from(abi::USER_ID_MAX)),
        ("FLUX_PROBE_REMOTE_PORT", u64::from(abi::PROBE_REMOTE_PORT)),
        ("FLUX_LISTEN_PORT_MIN", u64::from(abi::LISTEN_PORT_MIN)),
        ("FLUX_LISTEN_PORT_MAX", u64::from(abi::LISTEN_PORT_MAX)),
        ("FLUX_ETH_HLEN", u64::from(abi::ETH_HLEN)),
        ("FLUX_IPV6_MAX_EXT_HDRS", u64::from(abi::IPV6_MAX_EXT_HDRS)),
        (
            "FLUX_IPV6_MAX_EXT_BYTES",
            u64::from(abi::IPV6_MAX_EXT_BYTES),
        ),
        ("FLUX_MAX_PULL_BYTES", u64::from(abi::MAX_PULL_BYTES)),
        ("FLUX_TC_CHAIN", u64::from(abi::TC_CHAIN)),
        ("FLUX_TC_HANDLE_EGRESS", u64::from(abi::TC_HANDLE_EGRESS)),
        ("FLUX_TC_HANDLE_INGRESS", u64::from(abi::TC_HANDLE_INGRESS)),
        ("FLUX_TC_HANDLE_VERIFY", u64::from(abi::TC_HANDLE_VERIFY)),
        ("FLUX_TC_PREF_PREFERRED", u64::from(abi::TC_PREF_PREFERRED)),
        ("FLUX_TC_PREF_MIN", u64::from(abi::TC_PREF_MIN)),
        ("FLUX_TC_PREF_CLAT_MAX", u64::from(abi::TC_PREF_CLAT_MAX)),
        ("FLUX_VETH_MTU", u64::from(abi::VETH_MTU)),
        ("FLUX_RULE_PRIORITY", u64::from(abi::RULE_PRIORITY)),
        ("FLUX_ROUTE_TABLE", u64::from(abi::ROUTE_TABLE)),
        ("FLUX_ROUTE_PROTO", u64::from(abi::ROUTE_PROTO)),
    ]
}

/// Enum members: not `#define`s, so they only participate in the value
/// asserts, not the name-set check.
fn enum_members() -> Vec<(&'static str, u64)> {
    use abi::Counter;
    vec![
        ("FLUX_UID_SELECTED", abi::UidMode::Selected as u64),
        ("FLUX_UID_DRAINING", abi::UidMode::Draining as u64),
        ("FLUX_DEC_DIRECT", abi::DecisionMode::Direct as u64),
        ("FLUX_DEC_CAPTURED", abi::DecisionMode::Captured as u64),
        ("FLUX_CIDR_BLACKLIST", abi::CidrMode::Blacklist as u64),
        ("FLUX_CIDR_WHITELIST", abi::CidrMode::Whitelist as u64),
        (
            "FLUX_FAULT_EGRESS_LISTENER",
            abi::FaultReason::EgressListener as u64,
        ),
        (
            "FLUX_FAULT_INGRESS_ASSIGN",
            abi::FaultReason::IngressAssign as u64,
        ),
        ("FLUX_CNT_ADMIT_TCP", Counter::AdmitTcp as u64),
        ("FLUX_CNT_DIRECT_TCP", Counter::DirectTcp as u64),
        ("FLUX_CNT_ADMIT_UDP", Counter::AdmitUdp as u64),
        ("FLUX_CNT_DROP_INACTIVE", Counter::DropInactive as u64),
        ("FLUX_CNT_DROP_STALE_GEN", Counter::DropStaleGen as u64),
        ("FLUX_CNT_DROP_HANDOFF", Counter::DropHandoff as u64),
        (
            "FLUX_CNT_DROP_SELECTED_FRAGMENT",
            Counter::DropSelectedFragment as u64,
        ),
        ("FLUX_CNT_DROP_CORRUPT", Counter::DropCorrupt as u64),
        (
            "FLUX_CNT_DECISION_ALLOC_FAIL",
            Counter::DecisionAllocFail as u64,
        ),
        (
            "FLUX_CNT_EGRESS_LISTENER_MISS",
            Counter::EgressListenerMiss as u64,
        ),
        ("FLUX_CNT_IN_ASSIGN_TCP", Counter::InAssignTcp as u64),
        ("FLUX_CNT_IN_ASSIGN_UDP", Counter::InAssignUdp as u64),
        (
            "FLUX_CNT_IN_PASS_ESTABLISHED",
            Counter::InPassEstablished as u64,
        ),
        ("FLUX_CNT_IN_PASS_FRAGMENT", Counter::InPassFragment as u64),
        (
            "FLUX_CNT_IN_DROP_NO_LISTENER",
            Counter::InDropNoListener as u64,
        ),
        ("FLUX_CNT_IN_DROP_ASSIGN", Counter::InDropAssign as u64),
        ("FLUX_CNT_IN_DROP_PARSE", Counter::InDropParse as u64),
        ("FLUX_CNT_IN_DROP_SNAPSHOT", Counter::InDropSnapshot as u64),
        ("FLUX_CNT_SAW_PACKET", Counter::SawPacket as u64),
        ("FLUX_CNT__MAX", u64::from(Counter::MAX)),
    ]
}

/// String `#define`s: C name paired with the mirrored Rust value.
fn string_defines() -> Vec<(&'static str, &'static str)> {
    vec![
        ("FLUX_MAP_UID_POLICY_0", abi::MAP_UID_POLICY_0),
        ("FLUX_MAP_UID_POLICY_1", abi::MAP_UID_POLICY_1),
        ("FLUX_MAP_BYPASS_V4_0", abi::MAP_BYPASS_V4_0),
        ("FLUX_MAP_BYPASS_V4_1", abi::MAP_BYPASS_V4_1),
        ("FLUX_MAP_BYPASS_V6_0", abi::MAP_BYPASS_V6_0),
        ("FLUX_MAP_BYPASS_V6_1", abi::MAP_BYPASS_V6_1),
        ("FLUX_MAP_SELF_ADDR_V4_0", abi::MAP_SELF_ADDR_V4_0),
        ("FLUX_MAP_SELF_ADDR_V4_1", abi::MAP_SELF_ADDR_V4_1),
        ("FLUX_MAP_SELF_ADDR_V6_0", abi::MAP_SELF_ADDR_V6_0),
        ("FLUX_MAP_SELF_ADDR_V6_1", abi::MAP_SELF_ADDR_V6_1),
        ("FLUX_MAP_UID_STATS", abi::MAP_UID_STATS),
        ("FLUX_MAP_TCP_DECISION", abi::MAP_TCP_DECISION),
        ("FLUX_MAP_CONTROL_ROOT", abi::MAP_CONTROL_ROOT),
        ("FLUX_MAP_CONTROL_LEAF", abi::MAP_CONTROL_LEAF),
        ("FLUX_MAP_FAULT_LATCH", abi::MAP_FAULT_LATCH),
        ("FLUX_MAP_FAULT_EVENTS", abi::MAP_FAULT_EVENTS),
        ("FLUX_MAP_COUNTERS", abi::MAP_COUNTERS),
        ("FLUX_LISTEN_V4_STR", abi::LISTEN_V4_STR),
        ("FLUX_LISTEN_V6_STR", abi::LISTEN_V6_STR),
        ("FLUX_PROBE_REMOTE_V4_STR", abi::PROBE_REMOTE_V4_STR),
        ("FLUX_PROBE_REMOTE_V6_STR", abi::PROBE_REMOTE_V6_STR),
        ("FLUX_PROG_CAP_L2", abi::PROG_CAP_L2),
        ("FLUX_PROG_CAP_L3", abi::PROG_CAP_L3),
        ("FLUX_PROG_IN", abi::PROG_IN),
        ("FLUX_PROG_VERIFY", abi::PROG_VERIFY),
        ("FLUX_SEC_CAP_L2", abi::SEC_CAP_L2),
        ("FLUX_SEC_CAP_L3", abi::SEC_CAP_L3),
        ("FLUX_SEC_IN", abi::SEC_IN),
        ("FLUX_SEC_VERIFY", abi::SEC_VERIFY),
        ("FLUX_VETH_HOST", abi::VETH_HOST),
        ("FLUX_VETH_PEER", abi::VETH_PEER),
        ("FLUX_VETH_HOST_ALIAS", abi::VETH_HOST_ALIAS),
        ("FLUX_VETH_PEER_ALIAS", abi::VETH_PEER_ALIAS),
    ]
}

/// Targets the assertions are compiled for: the data plane itself and the
/// device userspace that shares these structs with it.
const TARGETS: [&str; 2] = ["bpf", "aarch64-unknown-linux-gnu"];

/// The `<linux/types.h>` subset the header uses. `linux/types.h` guarantees
/// exactly these widths, so stubbing it changes nothing about layout while
/// freeing the check from installed kernel headers.
const LINUX_TYPES_STUB: &str = "\
#ifndef _XTASK_LINUX_TYPES_STUB_H
#define _XTASK_LINUX_TYPES_STUB_H
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
#endif
";

fn generate_c(structs: &[StructSpec]) -> String {
    let mut c = String::from(
        "/* Generated by `cargo xtask abi-check`. Every expected value on the\n\
          * right-hand side was produced by the Rust compiler from the mirror in\n\
          * crates/flux-core/src/abi.rs; clang computes the left-hand side from\n\
          * bpf/include/flux_abi.h. Do not edit. */\n\
         #include \"flux_abi.h\"\n\n",
    );
    for spec in structs {
        let name = spec.c_name;
        c.push_str(&format!(
            "_Static_assert(sizeof(struct {name}) == {}u, \"sizeof(struct {name}) differs from the abi.rs mirror\");\n",
            spec.size
        ));
        c.push_str(&format!(
            "_Static_assert(_Alignof(struct {name}) == {}u, \"_Alignof(struct {name}) differs from the abi.rs mirror\");\n",
            spec.align
        ));
        for field in &spec.fields {
            c.push_str(&format!(
                "_Static_assert(__builtin_offsetof(struct {name}, {field}) == {offset}u, \
                 \"offsetof({name}, {field}) differs from the abi.rs mirror\");\n",
                field = field.name,
                offset = field.offset
            ));
        }
        c.push('\n');
    }
    for (name, value) in numeric_defines().iter().chain(enum_members().iter()) {
        c.push_str(&format!(
            "_Static_assert(({name}) == {value}ULL, \"{name} differs from the abi.rs mirror\");\n"
        ));
    }
    c
}

pub fn run() -> Result<(), String> {
    let root = util::repo_root();
    let header_path = root.join("bpf/include/flux_abi.h");
    let header = util::read_text(&header_path)?;
    let defines = cdefs::parse_defines(&header);
    let mut failures: Vec<String> = Vec::new();

    // --- name-set equality: the header defines exactly what the mirror knows.
    let known: std::collections::BTreeSet<&str> = numeric_defines()
        .iter()
        .map(|(n, _)| *n)
        .chain(string_defines().iter().map(|(n, _)| *n))
        .chain(std::iter::once("FLUX_ABI_H")) // include guard
        .collect();
    let in_header: std::collections::BTreeSet<&str> =
        defines.iter().map(|d| d.name.as_str()).collect();
    for name in in_header.difference(&known) {
        failures.push(format!(
            "flux_abi.h defines `{name}` but the abi.rs mirror (via xtask) does not know it"
        ));
    }
    for name in known.difference(&in_header) {
        failures.push(format!(
            "the abi.rs mirror expects `{name}` but flux_abi.h does not define it"
        ));
    }

    // --- string values, byte for byte.
    let mut strings_checked = 0usize;
    for (name, expected) in string_defines() {
        let Some(def) = defines.iter().find(|d| d.name == name) else {
            continue; // already reported by the set check
        };
        match &def.string_value {
            Some(actual) if actual == expected => strings_checked += 1,
            Some(actual) => failures.push(format!(
                "{}:{}: {name} is \"{actual}\" in the header but \"{expected}\" in abi.rs",
                header_path.display(),
                def.line
            )),
            None => failures.push(format!(
                "{}:{}: {name} is not a string define but abi.rs mirrors it as \"{expected}\"",
                header_path.display(),
                def.line
            )),
        }
    }

    // --- sizes, alignments, offsets and numeric values, computed by clang.
    let structs = struct_specs();
    let work = crate::util::target_dir(&root)?.join("xtask/abi-check");
    util::write_bytes(
        &work.join("include/linux/types.h"),
        LINUX_TYPES_STUB.as_bytes(),
    )?;
    let c_path = work.join("abi_check.c");
    util::write_bytes(&c_path, generate_c(&structs).as_bytes())?;

    let clang = util::clang();
    for target in TARGETS {
        let output = Command::new(&clang)
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-fsyntax-only")
            .arg("-nostdinc")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(format!("--target={target}"))
            .arg("-I")
            .arg(work.join("include"))
            .arg("-I")
            .arg(root.join("bpf/include"))
            .arg(&c_path)
            .output()
            .map_err(|e| format!("failed to run `{clang}`: {e}"))?;
        if !output.status.success() {
            failures.push(format!(
                "clang ({target}) rejected the generated assertions:\n{}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("abi-check: {failure}");
        }
        return Err(format!(
            "{} mismatch(es) between flux_abi.h and abi.rs",
            failures.len()
        ));
    }

    let field_count: usize = structs.iter().map(|s| s.fields.len()).sum();
    for spec in &structs {
        println!(
            "abi-check: struct {:<18} size {:>3}  align {}  {:>2} field offsets OK",
            spec.c_name,
            spec.size,
            spec.align,
            spec.fields.len()
        );
    }
    println!(
        "abi-check: OK — {} structs / {} field offsets, {} numeric defines, {} enum members, \
         {strings_checked} string defines; clang targets: {}",
        structs.len(),
        field_count,
        numeric_defines().len(),
        enum_members().len(),
        TARGETS.join(", ")
    );
    Ok(())
}
