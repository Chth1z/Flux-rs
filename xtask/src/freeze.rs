//! `cargo xtask freeze` — candidate identity for a later rebuild (blueprint §13.5).
//!
//! Development packaging still resolves the current official engine. A release
//! consumes only this list and never `/releases/latest`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{engine_release, util};

const SCHEMA: i64 = 1;
const REQUIRED_ACTIONS: [&str; 4] = [
    "actions/checkout",
    "Swatinem/rust-cache",
    "actions/upload-artifact",
    "EmbarkStudios/cargo-deny-action",
];

#[derive(Debug)]
pub struct FreezeList {
    dir: PathBuf,
    manifest: toml::Table,
}

pub fn dir(root: &Path) -> PathBuf {
    root.join("dist/freeze")
}

pub fn load(root: &Path) -> Result<FreezeList, String> {
    let dir = dir(root);
    let path = dir.join("manifest.toml");
    if !path.is_file() {
        return Err(format!(
            "release consumes {}; run `cargo xtask freeze` first and keep that list with the tag",
            path.display()
        ));
    }
    let text = util::read_text(&path)?;
    let value: toml::Value =
        toml::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))?;
    let toml::Value::Table(manifest) = value else {
        return Err("freeze manifest is not a TOML table".into());
    };
    if manifest.get("schema").and_then(|value| value.as_integer()) != Some(SCHEMA) {
        return Err("freeze manifest schema is not 1".into());
    }
    let list = FreezeList { dir, manifest };
    list.verify_actions(root)?;
    Ok(list)
}

impl FreezeList {
    pub fn engine(&self) -> Result<engine_release::Release, String> {
        let engine = self
            .manifest
            .get("engine")
            .ok_or("freeze manifest has no [engine] table")?;
        engine_release::Release::from_freeze(engine)
    }

    pub fn install_lockfile(&self, root: &Path) -> Result<(), String> {
        let source = self.dir.join("Cargo.lock");
        if !source.is_file() {
            return Err(format!(
                "freeze list is missing the Cargo.lock copy at {}",
                source.display()
            ));
        }
        std::fs::copy(&source, root.join("Cargo.lock")).map_err(|error| {
            format!(
                "install frozen Cargo.lock from {}: {error}",
                source.display()
            )
        })?;
        Ok(())
    }

    fn verify_actions(&self, root: &Path) -> Result<(), String> {
        let frozen = frozen_actions(&self.manifest)?;
        let live = collect_action_pins(root)?;
        if frozen != live {
            return Err(
                "freeze [actions] does not match the pinned uses: in .github/workflows; re-run cargo xtask freeze"
                    .into(),
            );
        }
        Ok(())
    }
}

pub fn run() -> Result<(), String> {
    let root = util::repo_root();
    let dest = dir(&root);
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .map_err(|error| format!("clear {}: {error}", dest.display()))?;
    }
    std::fs::create_dir_all(&dest)
        .map_err(|error| format!("create {}: {error}", dest.display()))?;

    let source_commit = git_head(&root)?;
    generate_lockfile(&root)?;
    std::fs::copy(root.join("Cargo.lock"), dest.join("Cargo.lock"))
        .map_err(|error| format!("copy Cargo.lock into freeze list: {error}"))?;

    let rustc_verbose = command_text("rustc", &["-vV"])?;
    util::write_bytes(
        dest.join("rustc-vv.txt").as_path(),
        rustc_verbose.as_bytes(),
    )?;

    let release = engine_release::Release::resolve()?;
    let ndk = probe_ndk()?;
    let clang = probe_clang(&ndk.path)?;
    let bpftool = probe_bpftool()?;
    let actions = collect_action_pins(&root)?;
    require_actions(&actions)?;

    util::write_bytes(dest.join("ndk-revision").as_path(), ndk.revision.as_bytes())?;
    util::write_bytes(dest.join("bpftool-tag").as_path(), bpftool.tag.as_bytes())?;
    util::write_bytes(
        dest.join("source-commit").as_path(),
        source_commit.as_bytes(),
    )?;

    let manifest = toml::Value::Table(toml::Table::from_iter([
        ("schema".into(), SCHEMA.into()),
        ("source_commit".into(), source_commit.into()),
        (
            "commands".into(),
            toml::Value::Table(toml::Table::from_iter([
                ("freeze".into(), "cargo xtask freeze".into()),
                ("package".into(), "cargo xtask package".into()),
                ("release".into(), "cargo xtask release TAG".into()),
            ])),
        ),
        ("engine".into(), release.freeze_table()),
        (
            "toolchain".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "rustc_verbose".into(),
                rustc_verbose.into(),
            )])),
        ),
        (
            "ndk".into(),
            toml::Value::Table(toml::Table::from_iter([
                ("revision".into(), ndk.revision.into()),
                ("path".into(), ndk.path.display().to_string().into()),
            ])),
        ),
        (
            "clang".into(),
            toml::Value::Table(toml::Table::from_iter([
                ("host".into(), clang.host.into()),
                ("host_version".into(), clang.host_version.into()),
                ("android".into(), clang.android.into()),
                ("android_version".into(), clang.android_version.into()),
                ("bpf".into(), clang.bpf.into()),
                ("bpf_version".into(), clang.bpf_version.into()),
            ])),
        ),
        (
            "bpftool".into(),
            toml::Value::Table(toml::Table::from_iter([
                ("tag".into(), bpftool.tag.into()),
                ("commit".into(), bpftool.commit.into()),
                ("version".into(), bpftool.version.into()),
            ])),
        ),
        ("actions".into(), actions_table(&actions)),
    ]));
    let rendered = toml::to_string_pretty(&manifest)
        .map_err(|error| format!("serialize freeze manifest: {error}"))?;
    util::write_bytes(dest.join("manifest.toml").as_path(), rendered.as_bytes())?;
    println!("freeze: wrote {}", dest.display());
    Ok(())
}

pub fn collect_action_pins(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut pins = BTreeMap::new();
    let workflows = root.join(".github/workflows");
    let entries = std::fs::read_dir(&workflows)
        .map_err(|error| format!("read {}: {error}", workflows.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|error| format!("read {}: {error}", workflows.display()))?
            .path();
        if !path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            continue;
        }
        let shown = path.strip_prefix(root).unwrap_or(&path).display();
        collect_action_pins_from(&util::read_text(&path)?, &mut pins, &shown.to_string())?;
    }
    Ok(pins)
}

pub fn collect_action_pins_from(
    text: &str,
    pins: &mut BTreeMap<String, String>,
    shown: &str,
) -> Result<(), String> {
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let code = trimmed.split('#').next().unwrap_or("").trim();
        let code = code.strip_prefix('-').map(str::trim).unwrap_or(code);
        let Some(rest) = code.strip_prefix("uses:") else {
            continue;
        };
        let spec = rest.trim().trim_matches('"').trim_matches('\'');
        if spec.starts_with("./") || spec.is_empty() {
            continue;
        }
        let Some((action, rev)) = spec.rsplit_once('@') else {
            return Err(format!("{shown}:{}: action `{spec}` has no pin", idx + 1));
        };
        if rev.len() != 40 || !rev.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "{shown}:{}: `{action}@{rev}` is not a 40-character commit SHA",
                idx + 1
            ));
        }
        let rev = rev.to_ascii_lowercase();
        if let Some(existing) = pins.get(action) {
            if existing != &rev {
                return Err(format!("{action} is pinned to both {existing} and {rev}"));
            }
        } else {
            pins.insert(action.to_string(), rev);
        }
    }
    Ok(())
}

fn require_actions(pins: &BTreeMap<String, String>) -> Result<(), String> {
    for action in REQUIRED_ACTIONS {
        if !pins.contains_key(action) {
            return Err(format!(
                "freeze list is missing a pin for {action}; workflows must use a commit SHA"
            ));
        }
    }
    Ok(())
}

fn frozen_actions(manifest: &toml::Table) -> Result<BTreeMap<String, String>, String> {
    let table = manifest
        .get("actions")
        .and_then(toml::Value::as_table)
        .ok_or("freeze manifest has no [actions] table")?;
    let mut pins = BTreeMap::new();
    for (action, value) in table {
        let sha = value
            .as_str()
            .ok_or_else(|| format!("freeze action {action} is not a string"))?;
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("freeze action {action} is not a commit SHA"));
        }
        pins.insert(action.clone(), sha.to_ascii_lowercase());
    }
    require_actions(&pins)?;
    Ok(pins)
}

fn actions_table(pins: &BTreeMap<String, String>) -> toml::Value {
    toml::Value::Table(
        pins.iter()
            .map(|(action, sha)| (action.clone(), sha.clone().into()))
            .collect(),
    )
}

fn git_head(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("git rev-parse HEAD: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".into());
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| "git commit is not UTF-8".to_string())?
        .trim()
        .to_string();
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("git HEAD `{commit}` is not a 40-character SHA"));
    }
    Ok(commit)
}

fn generate_lockfile(root: &Path) -> Result<(), String> {
    util::run(
        Command::new(util::cargo())
            .current_dir(root)
            .args(["generate-lockfile"]),
        "cargo generate-lockfile",
    )
}

fn command_text(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("run `{program}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{program}` {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

struct Ndk {
    revision: String,
    path: PathBuf,
}

fn probe_ndk() -> Result<Ndk, String> {
    let path =
        PathBuf::from(std::env::var("ANDROID_NDK_HOME").map_err(|_| "ANDROID_NDK_HOME is unset")?);
    let properties = util::read_text(&path.join("source.properties"))?;
    let revision = properties
        .lines()
        .find_map(|line| {
            line.strip_prefix("Pkg.Revision")
                .and_then(|rest| rest.trim().strip_prefix('='))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("NDK source.properties has no Pkg.Revision")?
        .to_string();
    Ok(Ndk { revision, path })
}

struct Clang {
    host: String,
    host_version: String,
    android: String,
    android_version: String,
    bpf: String,
    bpf_version: String,
}

fn probe_clang(ndk: &Path) -> Result<Clang, String> {
    let host = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let host_version = first_line(&command_text(&host, &["--version"])?);
    let bpf = host.clone();
    let bpf_version = host_version.clone();
    let android = ndk
        .join("toolchains/llvm/prebuilt")
        .read_dir()
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("bin/aarch64-linux-android31-clang"))
                .find(|path| path.is_file())
        })
        .ok_or("NDK has no aarch64-linux-android31-clang")?;
    let android_version = first_line(&command_text(
        android.to_str().ok_or("android clang path is not UTF-8")?,
        &["--version"],
    )?);
    Ok(Clang {
        host,
        host_version,
        android: android.display().to_string(),
        android_version,
        bpf,
        bpf_version,
    })
}

struct Bpftool {
    tag: String,
    commit: String,
    version: String,
}

fn probe_bpftool() -> Result<Bpftool, String> {
    let metadata =
        engine_release::api_json("https://api.github.com/repos/libbpf/bpftool/releases/latest")?;
    let tag = metadata["tag_name"]
        .as_str()
        .ok_or("bpftool latest release has no tag_name")?
        .to_string();
    let commit = engine_release::api_json(&format!(
        "https://api.github.com/repos/libbpf/bpftool/commits/{tag}"
    ))?;
    let sha = commit["sha"]
        .as_str()
        .ok_or("bpftool tag did not resolve to a commit SHA")?
        .to_string();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bpftool tag did not resolve to a 40-character SHA".into());
    }
    let version = Command::new("bpftool")
        .arg("version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| first_line(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_else(|| "not-installed".to_string());
    Ok(Bpftool {
        tag,
        commit: sha,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_pins_must_be_commit_shas() {
        let mut pins = BTreeMap::new();
        collect_action_pins_from(
            "      - uses: actions/checkout@f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a\n",
            &mut pins,
            "ci.yml",
        )
        .unwrap();
        assert_eq!(
            pins.get("actions/checkout").map(String::as_str),
            Some("f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a")
        );
        assert!(collect_action_pins_from(
            "      - uses: actions/checkout@main\n",
            &mut BTreeMap::new(),
            "ci.yml",
        )
        .is_err());
        assert!(collect_action_pins_from(
            "      - uses: Swatinem/rust-cache@master\n",
            &mut BTreeMap::new(),
            "ci.yml",
        )
        .is_err());
        collect_action_pins_from(
            "    uses: ./.github/workflows/verify.yml\n",
            &mut pins,
            "release.yml",
        )
        .unwrap();
        assert!(!pins.contains_key("./.github/workflows/verify.yml"));
    }

    #[test]
    fn missing_freeze_list_is_a_release_error() {
        let work = util::work_dir(&std::env::temp_dir(), "flux-freeze-missing").unwrap();
        let error = load(&work).unwrap_err();
        assert!(error.contains("cargo xtask freeze"), "{error}");
        std::fs::remove_dir_all(&work).unwrap();
    }
}
