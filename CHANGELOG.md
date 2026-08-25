# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Design contract for 0.9.0 (`docs/blueprint.md`), the data-plane ABI
  (`bpf/include/flux_abi.h`) and its compile-time-checked Rust mirror
  (`crates/flux-core/src/abi.rs`).
- Three-crate workspace skeleton: `flux-core` (pure logic, `unsafe` forbidden),
  `fluxd` (runtime), `xtask` (build and packaging).
- Magisk / KernelSU / APatch module envelope.

### Notes

Fresh history. The repository previously implemented a different architecture;
`docs/blueprint.md` §0 records what changed and why, and §19 lists the rejected
alternatives with reasons.

The previous 385 commits are preserved in an offline bundle outside this
repository and are not part of this history.
