//! Non-attaching Phase 4 acceptance test for a rooted Android device.
//!
//! The test creates exactly twelve maps, one BTF object and four unattached
//! programs. It never attaches, pins, changes network state or sends traffic.
//! Closing all FDs must make every recorded map/program ID unavailable.

#![allow(dead_code, unused_imports)]

#[path = "../src/bpf/mod.rs"]
mod bpf;

use std::os::fd::AsRawFd;
use std::process;

use flux_core::abi::{self, MAP_NAMES, PROG_NAMES};

const BPF_OBJECT: &[u8] = include_bytes!(env!("FLUX_BPF_OBJECT"));

fn main() {
    if std::env::var_os("FLUX_PHASE4_DEVICE_TEST").is_none() {
        println!("phase4 device test: skipped (set FLUX_PHASE4_DEVICE_TEST=1)");
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("phase4 device test requires root");
        process::exit(77);
    }

    let runtime = bpf::Runtime::load_embedded(BPF_OBJECT).unwrap_or_else(|error| {
        eprintln!("phase4 loader failed: {error}");
        process::exit(1);
    });

    let maps = runtime.map_identities();
    assert_eq!(maps.len(), MAP_NAMES.len());
    assert_eq!(
        maps.iter().map(|map| map.spec.name).collect::<Vec<_>>(),
        MAP_NAMES
    );
    assert!(maps.iter().all(|map| map.id != 0));
    for map in &maps {
        println!(
            "phase4_map name={} id={} type={} key={} value={} max={} flags={}",
            map.spec.name,
            map.id,
            map.spec.map_type,
            map.spec.key_size,
            map.spec.value_size,
            map.spec.max_entries,
            map.spec.map_flags
        );
    }
    let tcp = maps
        .iter()
        .find(|map| map.spec.name == abi::MAP_TCP_DECISION)
        .expect("tcp_decision identity");
    assert_ne!(tcp.btf_id, 0);
    assert_eq!(tcp.btf_key_type_id, flux_core::btf::KEY_TYPE_ID);
    assert_eq!(tcp.btf_value_type_id, flux_core::btf::VALUE_TYPE_ID);

    let programs = runtime.programs();
    assert_eq!(programs.len(), PROG_NAMES.len());
    assert_eq!(
        programs
            .iter()
            .map(|program| program.name.as_str())
            .collect::<Vec<_>>(),
        PROG_NAMES
    );
    for program in &programs {
        assert_ne!(program.id, 0);
        assert_ne!(program.tag, [0; 8]);
        assert_ne!(program.xlated_prog_len, 0);
        assert_ne!(program.input_insn_count, 0);
        let tag = program
            .tag
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!(
            "phase4_program name={} id={} tag={} input_insns={} xlated_bytes={}",
            program.name, program.id, tag, program.input_insn_count, program.xlated_prog_len
        );
    }

    let mut ring = runtime.fault_ring().expect("map the fault ring");
    assert!(ring.as_raw_fd() >= 0);
    assert!(ring
        .drain_faults()
        .expect("drain new fault ring")
        .is_empty());

    let map_ids = maps.iter().map(|map| map.id).collect::<Vec<_>>();
    let program_ids = programs
        .iter()
        .map(|program| program.id)
        .collect::<Vec<_>>();
    drop(ring);
    drop(runtime);
    bpf::verify_unloaded(&map_ids, &program_ids).expect("all unpinned objects disappeared");

    println!(
        "phase4 device test: PASS ({} maps, {} unattached programs, ringbuf, exact unload)",
        maps.len(),
        programs.len()
    );
}
