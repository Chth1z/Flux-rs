//! Minimal BPF loader: the only place in the daemon allowed to call `bpf(2)`.
//!
//! Implements blueprint §12 and D10. We do **not** link libbpf, libelf or zlib;
//! cross-building elfutils for `aarch64-linux-android` is a known trap, we
//! author the entire ABI ourselves so CO-RE buys nothing, and the deliverable
//! stays a single pure-Rust-plus-libc binary.
//!
//! Responsibilities:
//!
//! * `sys` — raw `bpf(2)` wrappers with EINTR retry and deadlines.
//! * `btf` — hand-built BTF blob. Required because `tcp_decision` is a
//!   `SK_STORAGE` map and `bpf_sk_storage_map_alloc_check()` rejects one
//!   without a BTF type id.
//! * `object` — minimal ELF parse of the embedded object.
//! * `maps` — authoritative map parameters, relocation by symbol name.
//! * `ringbuf` — fault event consumer.
//!
//! Port candidate: `flux-platform/src/bpf/sys.rs` (661 lines) is
//! architecture-neutral and self-contained, but has **no BTF support at all**
//! (`bpf_prog_load` passes only `kern_version`), so it must be extended with
//! `btf_fd` and `BPF_BTF_LOAD` (blueprint §18.3.2).
//!
//! `flux-platform/src/bpf/sock_addr_object.rs` is a real minimal ELF parser but
//! hard-codes 11 cgroup programs and the token maps; only about 150 of its 354
//! lines are generic. Read it, do not port it.
//!
//! Not implemented yet — Phase 5 (blueprint §17).
