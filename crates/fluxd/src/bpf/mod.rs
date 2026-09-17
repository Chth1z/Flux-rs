//! Minimal BPF loader: the only daemon module allowed to call `bpf(2)`.
//!
//! Blueprint §12 deliberately forbids libbpf, libelf, aya and pinning. The
//! product embeds one ELF object and this module performs the small subset it
//! needs: strict ELF64 parsing, symbol-name map relocations, explicit
//! map creations from MAP_SPECS, a hand-built BTF load and four `SCHED_CLS` program loads.
//! Phase 4 stops there: nothing in this module attaches a program or changes
//! packet flow.

#[cfg(any(target_os = "linux", target_os = "android"))]
mod btf;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod kernel;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod map_table;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod maps;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod object;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod ringbuf;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::fmt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_core::abi::{FLUX_ABI_MAGIC, PROG_SECTIONS};

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unused_imports)] // MapSpec is part of the Phase 4 device-test API.
pub use maps::{MapIdentity, MapSet, MapSpec};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use ringbuf::RingBuffer;

#[cfg(any(target_os = "linux", target_os = "android"))]
const VERIFIER_SUMMARY_LINES: usize = 24;
#[cfg(any(target_os = "linux", target_os = "android"))]
const VERIFIER_SUMMARY_BYTES: usize = 8 * 1024;

/// Stable, user-facing failure from one loader stage.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    pub code: String,
    pub detail: String,
    pub verifier_log: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl LoadError {
    fn object(detail: impl Into<String>) -> Self {
        Self {
            code: "bpf_object_invalid".to_string(),
            detail: detail.into(),
            verifier_log: None,
        }
    }

    fn syscall(stage: &str, name: Option<&str>, error: std::io::Error) -> Self {
        let suffix = error_name(&error);
        let code = if is_permission_error(&error) {
            "bpf_denied:check root manager policy".to_string()
        } else if let Some(name) = name {
            format!("{stage}:{name}:{suffix}")
        } else {
            format!("{stage}:{suffix}")
        };
        Self {
            code,
            detail: error.to_string(),
            verifier_log: None,
        }
    }

    pub(crate) fn maps(stage: &str, error: std::io::Error) -> Self {
        Self::syscall(stage, None, error)
    }

    fn program(name: &str, failure: sys::ProgramLoadFailure) -> Self {
        let summary = verifier_summary(&failure.log);
        let denied = is_permission_error(&failure.error) && summary.is_empty();
        Self {
            code: if denied {
                "bpf_denied:check root manager policy".to_string()
            } else {
                format!("prog_load:{name}:{}", error_name(&failure.error))
            },
            detail: failure.error.to_string(),
            verifier_log: (!summary.is_empty()).then_some(summary),
        }
    }

    fn verify(stage: &str, detail: impl Into<String>) -> Self {
        Self {
            code: stage.to_string(),
            detail: detail.into(),
            verifier_log: None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code, self.detail)?;
        if let Some(log) = &self.verifier_log {
            write!(f, "\nverifier log:\n{log}")?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl std::error::Error for LoadError {}

/// Identity recorded immediately after `BPF_PROG_LOAD`.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramIdentity {
    pub name: String,
    pub id: u32,
    pub tag: [u8; 8],
    pub xlated_prog_len: u32,
    pub input_insn_count: u32,
    pub map_ids: Vec<u32>,
    pub map_names: Vec<String>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct ProgramHandle {
    fd: OwnedFd,
    identity: ProgramIdentity,
}

/// Unattached Phase 4 kernel objects. Dropping this value closes every FD,
/// which removes all unpinned maps and programs.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct Runtime {
    maps: maps::MapSet,
    programs: Vec<ProgramHandle>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Runtime {
    /// Parses and loads one embedded object. No program is attached.
    pub fn load(object_bytes: &[u8], expected_abi_magic: u32) -> Result<Self, LoadError> {
        Self::load_on_kernel(object_bytes, expected_abi_magic, &kernel::release()?)
    }

    fn load_on_kernel(
        object_bytes: &[u8],
        expected_abi_magic: u32,
        release: &str,
    ) -> Result<Self, LoadError> {
        kernel::validate(release)?;
        let object = object::Object::parse(object_bytes).map_err(LoadError::object)?;
        if object.abi_magic() != expected_abi_magic {
            return Err(LoadError {
                code: "abi_magic_mismatch".to_string(),
                detail: format!(
                    "embedded object has {:#010X}, runtime expects {expected_abi_magic:#010X}",
                    object.abi_magic()
                ),
                verifier_log: None,
            });
        }

        let btf_fd = btf::load().map_err(|error| LoadError::syscall("btf_load", None, error))?;
        let maps = maps::MapSet::create(btf_fd.as_raw_fd()).map_err(|failure| {
            LoadError::syscall("map_create", Some(failure.name), failure.error)
        })?;
        // SK_STORAGE retains the BTF types; no userspace BTF FD is needed once
        // all map create calls have completed.
        drop(btf_fd);

        let mut programs = Vec::with_capacity(PROG_SECTIONS.len());
        for (name, section) in PROG_SECTIONS {
            let image = object
                .program(name, section, |symbol| maps.fd(symbol))
                .map_err(LoadError::object)?;
            let fd = sys::load_sched_cls(name, &image.instructions)
                .map_err(|failure| LoadError::program(name, failure))?;
            let info = sys::program_info(fd.as_raw_fd())
                .map_err(|error| LoadError::syscall("prog_info", Some(name), error))?;
            if info.program_type != sys::BPF_PROG_TYPE_SCHED_CLS
                || info.name != name
                || info.id == 0
            {
                return Err(LoadError::verify(
                    "prog_identity_mismatch",
                    format!("{name}: kernel returned {info:?}"),
                ));
            }
            // Checklist §12.7(6): an ID lookup is not trusted until the
            // returned FD is queried and its ID is compared again.
            let duplicate = sys::program_fd_by_id_verified(info.id)
                .map_err(|error| LoadError::syscall("prog_id_recheck", Some(name), error))?;
            drop(duplicate);
            let (map_ids, map_names) = program_maps(fd.as_raw_fd())
                .map_err(|error| LoadError::syscall("prog_map_info", Some(name), error))?;
            if map_names.as_slice() != expected_program_maps(name) {
                return Err(LoadError::verify(
                    "prog_map_set_mismatch",
                    format!("{name}: kernel returned map set {map_names:?}"),
                ));
            }
            programs.push(ProgramHandle {
                fd,
                identity: ProgramIdentity {
                    name: name.to_string(),
                    id: info.id,
                    tag: info.tag,
                    xlated_prog_len: info.xlated_prog_len,
                    input_insn_count: image.insn_count,
                    map_ids,
                    map_names,
                },
            });
        }

        Ok(Self { maps, programs })
    }

    pub fn load_embedded(object_bytes: &[u8]) -> Result<Self, LoadError> {
        Self::load(object_bytes, FLUX_ABI_MAGIC)
    }

    /// Map table owned by this runtime. Callers mutate maps through this
    /// set; Runtime does not 1:1-forward each helper.
    pub fn maps(&self) -> &maps::MapSet {
        &self.maps
    }

    pub fn maps_mut(&mut self) -> &mut maps::MapSet {
        &mut self.maps
    }

    /// The full map inventory. Only the Phase 4 device test reads it, to prove
    /// loader parity and cleanup; the daemon addresses maps by name, and this
    /// crate's own unit tests never call it — hence the allowance.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn map_identities(&self) -> Vec<MapIdentity> {
        self.maps.identities()
    }

    /// The full program inventory, for the same test and the same reason.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn programs(&self) -> Vec<ProgramIdentity> {
        self.programs
            .iter()
            .map(|program| program.identity.clone())
            .collect()
    }

    /// Opens the Phase 5 consumer over the already-created fault ring.
    pub fn fault_ring(&self) -> Result<RingBuffer, LoadError> {
        let fd = self
            .maps
            .fd(flux_core::abi::MAP_FAULT_EVENTS)
            .ok_or_else(|| LoadError::verify("fault_ring_missing", "fault_events map absent"))?;
        RingBuffer::open(fd, flux_core::abi::FAULT_RINGBUF_BYTES as usize)
            .map_err(|error| LoadError::syscall("ringbuf_mmap", None, error))
    }

    pub fn program_fd(&self, name: &str) -> Option<i32> {
        self.programs
            .iter()
            .find(|program| program.identity.name == name)
            .map(|program| program.fd.as_raw_fd())
    }

    pub fn program_identity(&self, name: &str) -> Option<ProgramIdentity> {
        self.programs
            .iter()
            .find(|program| program.identity.name == name)
            .map(|program| program.identity.clone())
    }
}

/// Re-opens an attached program and proves that the netlink-reported identity
/// and the complete map-name set still describe one of this build's entries.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn attached_program_owned(id: u32, name: &str, tag: [u8; 8]) -> Result<bool, LoadError> {
    if !PROG_SECTIONS.iter().any(|(expected, _)| *expected == name) {
        return Ok(false);
    }
    let fd = match sys::program_fd_by_id_verified(id) {
        Ok(fd) => fd,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
        Err(error) => return Err(LoadError::syscall("prog_id_recheck", Some(name), error)),
    };
    let info = sys::program_info(fd.as_raw_fd())
        .map_err(|error| LoadError::syscall("prog_info", Some(name), error))?;
    if info.program_type != sys::BPF_PROG_TYPE_SCHED_CLS
        || info.id != id
        || info.name != name
        || info.tag != tag
    {
        return Ok(false);
    }
    let (_, map_names) = program_maps(fd.as_raw_fd())
        .map_err(|error| LoadError::syscall("prog_map_info", Some(name), error))?;
    Ok(map_names.as_slice() == expected_program_maps(name))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn program_maps(fd: i32) -> std::io::Result<(Vec<u32>, Vec<String>)> {
    let mut ids = sys::program_map_ids(fd)?;
    ids.sort_unstable();
    ids.dedup();
    let mut names = Vec::with_capacity(ids.len());
    for id in &ids {
        let map_fd = sys::map_fd_by_id_verified(*id)?;
        names.push(sys::map_info(map_fd.as_raw_fd())?.name);
    }
    names.sort();
    Ok((ids, names))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn expected_program_maps(name: &str) -> &'static [String] {
    use std::sync::OnceLock;

    static CAPTURE: OnceLock<Vec<String>> = OnceLock::new();
    static INGRESS: OnceLock<Vec<String>> = OnceLock::new();
    static VERIFY: OnceLock<Vec<String>> = OnceLock::new();
    match name {
        flux_core::abi::PROG_CAP_L2 | flux_core::abi::PROG_CAP_L3 => CAPTURE.get_or_init(|| {
            sorted_names(&[
                flux_core::abi::MAP_UID_POLICY_0,
                flux_core::abi::MAP_UID_POLICY_1,
                flux_core::abi::MAP_BYPASS_V4_0,
                flux_core::abi::MAP_BYPASS_V4_1,
                flux_core::abi::MAP_BYPASS_V6_0,
                flux_core::abi::MAP_BYPASS_V6_1,
                flux_core::abi::MAP_SELF_ADDR_V4_0,
                flux_core::abi::MAP_SELF_ADDR_V4_1,
                flux_core::abi::MAP_SELF_ADDR_V6_0,
                flux_core::abi::MAP_SELF_ADDR_V6_1,
                flux_core::abi::MAP_UID_STATS,
                flux_core::abi::MAP_TCP_DECISION,
                flux_core::abi::MAP_CONTROL_ROOT,
                flux_core::abi::MAP_FAULT_LATCH,
                flux_core::abi::MAP_FAULT_EVENTS,
                flux_core::abi::MAP_COUNTERS,
            ])
        }),
        flux_core::abi::PROG_IN => INGRESS.get_or_init(|| {
            sorted_names(&[
                flux_core::abi::MAP_CONTROL_ROOT,
                flux_core::abi::MAP_FAULT_LATCH,
                flux_core::abi::MAP_FAULT_EVENTS,
                flux_core::abi::MAP_COUNTERS,
            ])
        }),
        flux_core::abi::PROG_VERIFY => {
            VERIFY.get_or_init(|| sorted_names(&[flux_core::abi::MAP_COUNTERS]))
        }
        _ => &[],
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sorted_names(names: &[&str]) -> Vec<String> {
    let mut names = names
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Confirms that a just-dropped Phase 4 runtime left no unpinned kernel
/// objects behind. This is an acceptance-test seam, not a cleanup mechanism,
/// so it exists only in test builds; the Phase 4 device test includes this
/// module and is its only caller.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[allow(dead_code)]
pub fn verify_unloaded(map_ids: &[u32], program_ids: &[u32]) -> Result<(), LoadError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let mut remaining = Vec::new();
        for id in map_ids {
            match sys::map_fd_by_id_verified(*id) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(LoadError::syscall("map_unload_check", None, error)),
                Ok(fd) => {
                    drop(fd);
                    remaining.push(format!("map:{id}"));
                }
            }
        }
        for id in program_ids {
            match sys::program_fd_by_id_verified(*id) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(LoadError::syscall("prog_unload_check", None, error)),
                Ok(fd) => {
                    drop(fd);
                    remaining.push(format!("program:{id}"));
                }
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(LoadError::verify(
                "bpf_objects_not_unloaded",
                format!(
                    "still openable after grace period: {}",
                    remaining.join(", ")
                ),
            ));
        }
        // Last-FD release is RCU-deferred on the baseline kernel. This bounded
        // polling exists only in the acceptance test seam; production never
        // polls BPF object IDs.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verifier_summary(log: &str) -> String {
    let mut out = String::new();
    for line in log.lines().take(VERIFIER_SUMMARY_LINES) {
        if !out.is_empty() {
            out.push('\n');
        }
        let remaining = VERIFIER_SUMMARY_BYTES.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        let take = line.len().min(remaining);
        out.push_str(&line[..take]);
        if take < line.len() {
            break;
        }
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_permission_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn error_name(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::E2BIG) => "E2BIG".to_string(),
        Some(libc::EACCES) => "EACCES".to_string(),
        Some(libc::EAGAIN) => "EAGAIN".to_string(),
        Some(libc::EBADF) => "EBADF".to_string(),
        Some(libc::EEXIST) => "EEXIST".to_string(),
        Some(libc::EINVAL) => "EINVAL".to_string(),
        Some(libc::ENOENT) => "ENOENT".to_string(),
        Some(libc::ENOSPC) => "ENOSPC".to_string(),
        Some(libc::ENOTSUP) => "ENOTSUP".to_string(),
        Some(libc::EPERM) => "EPERM".to_string(),
        Some(errno) => format!("errno_{errno}"),
        None => "unknown".to_string(),
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn affected_kernels_are_rejected_before_object_parsing_or_syscalls() {
        for release in ["6.6", "6.6-android99", "6.6.0-android15", "6.6.46-gki"] {
            let error = Runtime::load_on_kernel(&[], FLUX_ABI_MAGIC, release)
                .err()
                .expect("affected kernels must fail before touching BPF");
            assert_eq!(error.code, format!("unsupported_lpm_trie_kernel:{release}"));
        }
        for release in [
            "5.15.211-android14",
            "6.6.47-gki",
            "6.6.100+vendor",
            "6.12.0",
        ] {
            let error = Runtime::load_on_kernel(&[], FLUX_ABI_MAGIC, release)
                .err()
                .expect("an empty ELF must be rejected");
            assert_eq!(error.code, "bpf_object_invalid", "{release}");
        }
    }

    #[test]
    fn verifier_summary_is_bounded() {
        let input = (0..40)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let summary = verifier_summary(&input);
        assert_eq!(summary.lines().count(), VERIFIER_SUMMARY_LINES);
        assert!(summary.len() <= VERIFIER_SUMMARY_BYTES);
    }

    #[test]
    fn embedded_artifact_matches_abi_programs_and_map_bindings() {
        if crate::BPF_OBJECT.is_empty() {
            return;
        }
        let object = object::Object::parse(crate::BPF_OBJECT).unwrap();
        assert_eq!(object.abi_magic(), FLUX_ABI_MAGIC);
        for (name, section) in PROG_SECTIONS {
            let mut referenced_maps = std::collections::BTreeSet::new();
            // Instruction counts change with the compiler and program logic.
            // The loader contract is the program identity and its map bindings.
            object
                .program(name, section, |symbol| {
                    referenced_maps.insert(symbol.to_string());
                    Some(42)
                })
                .unwrap();
            assert_eq!(
                referenced_maps.into_iter().collect::<Vec<_>>(),
                expected_program_maps(name),
                "{name}/{section}"
            );
        }
    }

    #[test]
    fn abi_mismatch_is_rejected_before_any_kernel_object_is_created() {
        if crate::BPF_OBJECT.is_empty() {
            return;
        }
        let error = Runtime::load_on_kernel(crate::BPF_OBJECT, FLUX_ABI_MAGIC ^ 1, "5.15.211")
            .err()
            .expect("mismatched ABI must fail");
        assert_eq!(error.code, "abi_magic_mismatch");
    }
}
