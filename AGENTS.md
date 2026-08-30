# AGENTS.md

Routing only. Knowledge lives in `docs/`; this file says where to look and what
you cannot infer from the code. Every line here is paid on every turn of every
session, so it stays under 80 lines (`docs/authoring.md` AUTH-0.5).

## What this is

A Magisk/KernelSU/APatch module that proxies **the traffic of apps you picked**
through an unmodified official sing-box, classifying packets in the kernel on
socket UID. No VPN, no address rewriting, nothing touched for apps not picked.
Rust daemon (`fluxd`) + hand-written BPF loader; arm64 Android, kernel 5.15+.

## Where things live

`docs/` sorts by one question: **if this document and the code disagree, which
is wrong?**

| Path | Authority | Language |
|---|---|---|
| `docs/philosophy.md` | the contract is wrong (upstream of the blueprint) | English |
| `docs/governance.md`, `docs/authoring.md` | the process is wrong | Chinese |
| `docs/spec/` | **the code is wrong** | English |
| `docs/guide/` | the document is wrong | Chinese |
| `docs/history/` | neither; it records what happened. Append only | as written |
| `docs/plan/` | it has not happened yet | Chinese |

## Read this first

| Task | Read |
|---|---|
| Proposing or reviewing a design | `docs/philosophy.md` — run its review checklist |
| Implementing anything | `docs/spec/blueprint.md` for the part you touch |
| Citing a section, allocating a number | `docs/index.md` |
| Changing user-visible behaviour | `docs/spec/interaction.md` (§27) |
| Deciding what needs the owner's approval | `docs/governance.md` GOV-1 |
| Writing or moving a document | `docs/authoring.md` AUTH-0 |
| Checking why something was rejected | `docs/history/rejected-and-deferred.md` |

## Constraints you cannot infer from the code

- **Never read or write CJK text through PowerShell.** 5.1 treats unmarked
  files as the ANSI codepage (GBK here): it mangles CJK on write, and
  `Get-Content` miscounts UTF-8 lines on read — it reported 1637 for a
  2246-line file. Use the file tools and `rg`; keep any `.ps1` pure ASCII.
- **Files are LF, no BOM.** Some editors add one; `parse_jsonc` tolerates a BOM
  but `doc-check` and the TOML parser do not. Check after scripted writes.
- **`scratch/` holds real subscription credentials.** It is gitignored. Never
  stage it, never quote its contents into a document.
- **`§` belongs to the blueprint alone.** Other documents use `PHIL-`, `GOV-`,
  `AUTH-`. Section numbers are never reused or renumbered: 318 of them are
  cited from code across 39 files under `crates bpf module xtask`.
- **`git commit -F <file>`**, because PowerShell has no heredoc.

## Gates

Host-safe, run before every commit:

```
cargo fmt --all -- --check
cargo test -p flux-core && cargo test -p xtask && cargo test -p fluxd --bin fluxd
cargo xtask doc-check
```

Linux CI additionally runs `cargo clippy --workspace --all-targets -- -D warnings`
and `cargo test --workspace`; the Phase 3–8 suites run on a device. A Windows
pass never substitutes for either (`docs/spec/blueprint.md` §15.1).

To type-check the Linux-only data plane from Windows:
`cargo clippy -p fluxd --target aarch64-linux-android --all-targets`.
