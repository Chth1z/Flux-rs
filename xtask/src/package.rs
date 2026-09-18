//! `cargo xtask package` / `verify-package` / `build-bpf` — blueprint §13.4.
//!
//! `package` is the only packaging entry point, local and CI alike:
//!
//! 1. Derive everything version-shaped from `[workspace.package] version`
//!    (single version source; `module.prop` is generated, never maintained).
//! 2. Resolve one official stable release, verify its archives, measure the
//!    ELF binaries and check the generated template with its host asset.
//!    Everyday `package` / `verify-package` resolve `/releases/latest`.
//!    `release` consumes `dist/freeze/` instead (§13.5).
//! 3. Cross-build `fluxd` (`aarch64-linux-android`, embedded BPF object,
//!    16 KiB max-page-size link flags) and require `p_align >= 0x4000`.
//! 4. Stage the §13.1 allowlist — never "everything except" — with LF line
//!    endings and fixed modes, then the GKI-line `kmod/fluxrs-android*.ko`
//!    files in sorted name order.
//! 5. Write a deterministic STORE ZIP in allowlist order plus `SHA256SUMS`.
//!
//! `verify-package` runs the whole pipeline twice from clean cross-build
//! state and asserts the two archives hash identically (§17.4 exit
//! criterion 4).

use crate::{elf, engine_release, freeze, sha256, util, zip};
use std::path::{Path, PathBuf};
use std::process::Command;

/// §13.1: the fixed ZIP prefix, in archive order. GKI-line modules follow.
const ALLOWLIST: [&str; 16] = [
    "module.prop",
    "skip_mount",
    "customize.sh",
    "service.sh",
    "uninstall.sh",
    "webroot/index.html",
    "bin/fluxd",
    "bin/sing-box",
    "etc/default-flux.toml",
    "etc/default-advanced.toml",
    "etc/default-template.json",
    "build-info.toml",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "licenses/sing-box-LICENSE",
    "licenses/DEPENDENCIES.md",
];

pub fn run() -> Result<(), String> {
    let target = util::target_dir(&util::repo_root())?;
    let inputs = prepare_inputs(&util::repo_root())?;
    let (zip_path, digest) = package_once(&target, &inputs)?;
    println!("package: OK — {}", zip_path.display());
    println!("package: sha256 {}", sha256::hex(&digest));
    Ok(())
}

/// Two full runs from clean cross-build state must agree byte for byte.
pub fn verify() -> Result<(), String> {
    let inputs = prepare_inputs(&util::repo_root())?;
    verify_with(&inputs)
}

fn verify_with(inputs: &Inputs) -> Result<(), String> {
    let root = util::repo_root();
    let target = util::target_dir(&root)?;
    let work = util::work_dir(&target.join("xtask"), "verify-package")?;
    println!("verify-package: clean build roots under {}", work.display());
    let (zip_path, first) = package_once(&work.join("run1"), inputs)?;
    let first_copy = zip_path.with_extension("zip.run1");
    std::fs::copy(&zip_path, &first_copy)
        .map_err(|e| format!("copy {}: {e}", zip_path.display()))?;

    let (zip_path, second) = package_once(&work.join("run2"), inputs)?;

    if first != second {
        return Err(format!(
            "NOT reproducible: run 1 {} != run 2 {} (run 1 kept at {})",
            sha256::hex(&first),
            sha256::hex(&second),
            first_copy.display()
        ));
    }
    std::fs::remove_file(&first_copy).map_err(|e| format!("remove run-1 copy: {e}"))?;
    std::fs::remove_dir_all(&work).map_err(|e| {
        format!(
            "remove owned verification directory {}: {e}",
            work.display()
        )
    })?;
    println!(
        "verify-package: OK — two clean builds of {} both hash {}",
        zip_path.display(),
        sha256::hex(&first)
    );
    Ok(())
}

/// Release preparation for one already-signed tag.
///
/// Signature verification belongs to the GitHub workflow because GitHub has
/// the authoritative verification result for both GPG- and SSH-signed tags.
/// This side owns every deterministic artifact and the single-version check.
pub fn release(tag: &str) -> Result<(), String> {
    let root = util::repo_root();
    let version = workspace_version(&root)?;
    let expected = flux_core::version::version_tag(&version);
    if tag != expected {
        return Err(format!(
            "release tag `{tag}` does not equal workspace version tag `{expected}`"
        ));
    }
    let freeze = freeze::load(&root)?;
    freeze.install_lockfile(&root)?;
    let inputs = prepare_inputs_from(&root, freeze.engine()?)?;
    let provenance = git_provenance_from_tree(&root)?;
    if provenance.ends_with("-dirty") {
        return Err("release requires a clean working tree".into());
    }
    let inputs = Inputs {
        release_name: true,
        ..inputs
    };
    verify_with(&inputs)?;
    let (source, digest) = inputs.release.corresponding_source(
        &util::target_dir(&root)?.join("xtask/source"),
        &root.join("dist"),
    )?;
    let zip_name = flux_core::version::artifact_name(&version);
    let sums = root.join("dist/SHA256SUMS");
    let module_sum = util::read_text(&sums)?;
    if !module_sum.ends_with(&format!("  {zip_name}\n")) {
        return Err("package checksum does not name the version-derived module ZIP".into());
    }
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Corresponding Source artifact name is not UTF-8".to_string())?;
    util::write_bytes(
        &sums,
        format!("{module_sum}{}  {source_name}\n", sha256::hex(&digest)).as_bytes(),
    )?;
    println!("release: OK — {tag}, {zip_name}, {source_name}, and SHA256SUMS agree");
    Ok(())
}

fn package_once(target: &Path, inputs: &Inputs) -> Result<(PathBuf, [u8; 32]), String> {
    let root = util::repo_root();

    // 1. Single version source.
    let version = workspace_version(&root)?;
    let module_prop = flux_core::version::module_prop(&version)
        .ok_or_else(|| format!("workspace version `{version}` is not representable (§13.4)"))?;
    let zip_name = if inputs.release_name {
        flux_core::version::artifact_name(&version)
    } else {
        let provenance = git_provenance(&root)?;
        let revision = provenance.strip_suffix("-dirty").unwrap_or(&provenance);
        flux_core::version::development_artifact_name(
            &version,
            revision,
            provenance.ends_with("-dirty"),
        )
        .ok_or_else(|| "invalid development artifact identity".to_string())?
    };
    println!("package: version {version} -> {zip_name}");
    if root.join("module/module.prop").exists() {
        return Err(
            "module/module.prop exists in the tree; module.prop is generated from the \
             workspace version and a checked-in copy is exactly the second version file \
             blueprint §13.4 forbids"
                .into(),
        );
    }
    validate_webroot_shape(&root)?;

    // 2. Official engine and host validation were resolved once for this operation.
    let engine = &inputs.engine;

    // 3. Cross-built daemon.
    let fluxd = build_fluxd(&root, target)?;

    // 4 + 5. Stage the allowlist and write the archive.
    let entries = collect_entries(&root, &module_prop, engine, &fluxd, &inputs.build_info)?;
    debug_assert!(
        names_follow_allowlist(&entries),
        "ZIP names must be the §13.1 prefix plus sorted kmod/*.ko"
    );

    let stage = target.join("xtask/stage");
    if stage.exists() {
        std::fs::remove_dir_all(&stage).map_err(|e| format!("clear staging: {e}"))?;
    }
    for entry in &entries {
        util::write_bytes(&stage.join(&entry.name), &entry.data)?;
    }
    println!(
        "package: staged {} allowlisted files at {}",
        entries.len(),
        stage.display()
    );

    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let (dos_date, dos_time) = zip::dos_datetime(epoch);
    let archive = zip::build(&entries, dos_date, dos_time);
    let digest = sha256::digest(&archive);

    let zip_path = root.join("dist").join(&zip_name);
    util::write_bytes(&zip_path, &archive)?;
    util::write_bytes(
        &root.join("dist/SHA256SUMS"),
        format!("{}  {}\n", sha256::hex(&digest), zip_name).as_bytes(),
    )?;
    Ok((zip_path, digest))
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let manifest: toml::Value = toml::from_str(&util::read_text(&root.join("Cargo.toml"))?)
        .map_err(|e| format!("parse Cargo.toml: {e}"))?;
    manifest
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "Cargo.toml has no [workspace.package] version".into())
}

// ------------------------------------------------------------------ engine

struct Inputs {
    release_name: bool,
    release: engine_release::Release,
    engine: engine_release::Artifact,
    build_info: Vec<u8>,
}

fn prepare_inputs(root: &Path) -> Result<Inputs, String> {
    prepare_inputs_from(root, engine_release::Release::resolve()?)
}

fn prepare_inputs_from(root: &Path, release: engine_release::Release) -> Result<Inputs, String> {
    let cache = util::target_dir(root)?
        .join("xtask/engine")
        .join(&release.tag);
    let host = release.host.acquire(&cache)?;
    check_template_with_binary(root, &host.binary, &release.version)?;
    let engine = release.android.acquire(&cache)?;
    let bytes = util::read_bytes(&engine.binary)?;
    if bytes.get(18..20) != Some(&183u16.to_le_bytes()) {
        return Err("official Android engine is not an AArch64 ELF".into());
    }
    if elf::load_aligns(&bytes)?
        .iter()
        .any(|align| *align < 0x1000)
    {
        return Err("official Android engine does not support 4 KiB load alignment".into());
    }
    let tools = build_tools()?;
    let info = toml::Value::Table(toml::Table::from_iter([
        ("engine".into(), release.evidence(&engine, &host)),
        ("tools".into(), tools),
    ]));
    let build_info = toml::to_string(&info)
        .map_err(|error| format!("serialize build evidence: {error}"))?
        .into_bytes();
    Ok(Inputs {
        release_name: false,
        release,
        engine,
        build_info,
    })
}

fn build_tools() -> Result<toml::Value, String> {
    let clang = std::env::var_os("CLANG")
        .map(PathBuf::from)
        .or_else(find_system_clang)
        .ok_or("no host clang found; set CLANG")?;
    let linker = find_in_path("aarch64-linux-android31-clang")
        .or_else(|| ndk_bin_dir().map(|bin| bin.join("aarch64-linux-android31-clang")))
        .ok_or("no Android API 31 clang found; configure ANDROID_NDK_HOME or PATH")?;
    let version = |tool: &Path| -> Result<toml::Value, String> {
        let output = Command::new(tool)
            .arg("--version")
            .output()
            .map_err(|error| format!("run {}: {error}", tool.display()))?;
        if !output.status.success() {
            return Err(format!("{} --version failed", tool.display()));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
            .into())
    };
    let ndk_root = linker
        .ancestors()
        .find(|path| path.join("source.properties").is_file())
        .ok_or("cannot locate NDK root from its compiler path")?;
    let properties = util::read_text(&ndk_root.join("source.properties"))?;
    let revision = properties
        .lines()
        .find_map(|line| {
            line.strip_prefix("Pkg.Revision")
                .and_then(|rest| rest.trim().strip_prefix('='))
        })
        .map(str::trim)
        .ok_or("NDK source.properties has no Pkg.Revision")?;
    Ok(toml::Value::Table(toml::Table::from_iter([
        ("rustc".into(), version(Path::new("rustc"))?),
        ("cargo".into(), version(Path::new(&util::cargo()))?),
        ("clang".into(), version(&clang)?),
        ("android_clang".into(), version(&linker)?),
        ("ndk".into(), revision.to_string().into()),
        ("android_api".into(), 31i64.into()),
    ])))
}

// ------------------------------------------------------------------- fluxd

/// Cross-build `fluxd` with the embedded BPF object and the 16 KiB page-size
/// link flags, then enforce `p_align >= 0x4000` on every LOAD segment.
fn build_fluxd(root: &Path, target: &Path) -> Result<PathBuf, String> {
    let provenance = git_provenance(root)?;
    let mut cmd = Command::new(util::cargo());
    cmd.current_dir(root)
        .args([
            "build",
            "--release",
            "-p",
            "fluxd",
            "--target",
            "aarch64-linux-android",
        ])
        .arg("--target-dir")
        .arg(target)
        .env("FLUX_BUILD_BPF", "1")
        .env("FLUX_COMMIT", &provenance)
        // RUSTFLAGS replaces the [target.aarch64-linux-android] rustflags from
        // .cargo/config.toml. crt-static is intentionally absent: a fully
        // static binary cannot reach netd's resolver (blueprint §13.4).
        .env(
            "RUSTFLAGS",
            format!(
                "-C link-arg=-Wl,-z,max-page-size=16384 \
                 -C link-arg=-Wl,-z,common-page-size=16384 \
                 --remap-path-prefix={}=/flux-rs \
                 --remap-path-prefix={}=/flux-target",
                root.display(),
                target.display()
            ),
        );

    // The BPF object needs a clang that can see the host's kernel headers.
    // With the NDK toolchain on PATH (typical in CI), bare `clang` resolves to
    // the NDK compiler, which has no host sysroot and fails on <linux/bpf.h> —
    // so pin CLANG for the build script to a non-NDK clang explicitly.
    if std::env::var_os("CLANG").is_none() {
        let clang = find_system_clang().ok_or(
            "no clang outside the NDK toolchain found on PATH; install clang or set CLANG",
        )?;
        cmd.env("CLANG", clang);
    }

    const LINKER: &str = "aarch64-linux-android31-clang";
    if find_in_path(LINKER).is_none() {
        let ndk_bin = ndk_bin_dir().ok_or_else(|| {
            format!(
                "`{LINKER}` is not on PATH and ANDROID_NDK_HOME is not set; configure an NDK with the API 31 driver"
            )
        })?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut parts = vec![ndk_bin];
        parts.extend(std::env::split_paths(&path));
        let joined = std::env::join_paths(parts).map_err(|e| format!("extend PATH: {e}"))?;
        cmd.env("PATH", joined);
    }

    println!(
        "package: cross-building fluxd (aarch64-linux-android, BPF object embedded, commit {provenance})"
    );
    util::run(&mut cmd, "fluxd cross build")?;

    let fluxd = target.join("aarch64-linux-android/release/fluxd");
    let bytes = util::read_bytes(&fluxd)?;
    let aligns = elf::load_aligns(&bytes)?;
    for align in &aligns {
        if *align < 0x4000 {
            return Err(format!(
                "fluxd PT_LOAD p_align {align:#x} < 0x4000: the module would break on 16 KiB \
                 base-page devices (blueprint §13.4 step 2)"
            ));
        }
    }
    println!(
        "package: fluxd built — {} LOAD segments all p_align >= 0x4000",
        aligns.len()
    );
    Ok(fluxd)
}

fn git_provenance(root: &Path) -> Result<String, String> {
    if let Ok(value) = std::env::var("FLUX_COMMIT") {
        let value = value.trim();
        if valid_provenance(value) {
            return Ok(value.to_string());
        }
        return Err("FLUX_COMMIT is not a 7-64 character hex commit provenance".into());
    }
    git_provenance_from_tree(root)
}

fn git_provenance_from_tree(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("read git commit: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed; set FLUX_COMMIT explicitly".into());
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| "git commit is not UTF-8".to_string())?
        .trim()
        .to_string();
    if !valid_provenance(&commit) {
        return Err(format!("git returned invalid commit provenance `{commit}`"));
    }
    let status = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .map_err(|error| format!("read git worktree status: {error}"))?;
    if !status.status.success() {
        return Err("git status failed while deriving build provenance".into());
    }
    Ok(if status.stdout.is_empty() {
        commit
    } else {
        format!("{commit}-dirty")
    })
}

fn valid_provenance(value: &str) -> bool {
    let commit = value.strip_suffix("-dirty").unwrap_or(value);
    (7..=64).contains(&commit.len()) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The first `clang` on PATH that is not part of an NDK toolchain. NDK bin
/// directories are recognised by the Android-target driver they contain.
fn find_system_clang() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let ndk_home = std::env::var_os("ANDROID_NDK_HOME").map(PathBuf::from);
    for dir in std::env::split_paths(&path) {
        if ndk_home.as_ref().is_some_and(|ndk| dir.starts_with(ndk))
            || dir.join("aarch64-linux-android31-clang").is_file()
        {
            continue;
        }
        for candidate in [dir.join("clang"), dir.join("clang.exe")] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in [dir.join(name), dir.join(format!("{name}.cmd"))] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn ndk_bin_dir() -> Option<PathBuf> {
    let ndk = std::env::var_os("ANDROID_NDK_HOME")?;
    let host = if cfg!(target_os = "linux") {
        "linux-x86_64"
    } else if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "windows-x86_64"
    };
    let bin = PathBuf::from(ndk)
        .join("toolchains/llvm/prebuilt")
        .join(host)
        .join("bin");
    bin.is_dir().then_some(bin)
}

// ----------------------------------------------------------------- staging

/// §13.1/§28.8: the manager button gets one redirect shell, never a bundled
/// Flux WebUI. Reject any second entry before the expensive packaging work.
fn validate_webroot_shape(root: &Path) -> Result<(), String> {
    let webroot = root.join("module/webroot");
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&webroot)
        .map_err(|error| format!("read {}: {error}", webroot.display()))?
    {
        let entry = entry.map_err(|error| format!("read {} entry: {error}", webroot.display()))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", entry.path().display()))?;
        entries.push((entry.file_name(), kind.is_file()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let valid =
        entries.len() == 1 && entries[0].0 == std::ffi::OsStr::new("index.html") && entries[0].1;
    if !valid {
        let found = if entries.is_empty() {
            "nothing".to_string()
        } else {
            entries
                .iter()
                .map(|(name, is_file)| {
                    format!(
                        "{} ({})",
                        name.to_string_lossy(),
                        if *is_file { "file" } else { "non-file" }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(format!(
            "module/webroot must contain exactly one regular file, index.html; found {found}. \
             Additional content would be the Flux WebUI deferred as C8; refusing to package"
        ));
    }
    Ok(())
}

fn collect_entries(
    root: &Path,
    module_prop: &str,
    engine: &engine_release::Artifact,
    fluxd: &Path,
    build_info: &[u8],
) -> Result<Vec<zip::Entry>, String> {
    let text = |rel: &str| -> Result<Vec<u8>, String> {
        Ok(util::normalize_lf(&util::read_bytes(&root.join(rel))?))
    };

    let mut entries = Vec::new();
    let mut push = |name: &str, mode: u32, data: Vec<u8>| {
        entries.push(zip::Entry {
            name: name.to_string(),
            mode,
            data,
        });
    };

    push("module.prop", 0o644, module_prop.as_bytes().to_vec());
    // Empty by definition: its existence tells the manager not to mount a
    // system overlay (§13.1).
    push("skip_mount", 0o644, Vec::new());
    push("customize.sh", 0o755, text("module/customize.sh")?);
    push("service.sh", 0o755, text("module/service.sh")?);
    push("uninstall.sh", 0o755, text("module/uninstall.sh")?);
    push(
        "webroot/index.html",
        0o644,
        text("module/webroot/index.html")?,
    );
    push("bin/fluxd", 0o755, util::read_bytes(fluxd)?);
    push("bin/sing-box", 0o755, util::read_bytes(&engine.binary)?);
    push("etc/default-flux.toml", 0o644, text("module/flux.toml")?);
    push(
        "etc/default-advanced.toml",
        0o644,
        text("module/advanced.toml")?,
    );
    push(
        "etc/default-template.json",
        0o644,
        text("module/template.json")?,
    );
    push("build-info.toml", 0o644, build_info.to_vec());
    push("LICENSE", 0o644, text("LICENSE")?);
    push(
        "THIRD_PARTY_NOTICES.md",
        0o644,
        text("THIRD_PARTY_NOTICES.md")?,
    );
    push(
        "licenses/sing-box-LICENSE",
        0o644,
        util::normalize_lf(&util::read_bytes(&engine.license)?),
    );
    push(
        "licenses/DEPENDENCIES.md",
        0o644,
        dependencies_md(root)?.into_bytes(),
    );
    for entry in collect_kmod_entries(root)? {
        entries.push(entry);
    }
    Ok(entries)
}

fn names_follow_allowlist(entries: &[zip::Entry]) -> bool {
    if entries.len() <= ALLOWLIST.len() {
        return false;
    }
    if !entries
        .iter()
        .map(|entry| entry.name.as_str())
        .take(ALLOWLIST.len())
        .eq(ALLOWLIST)
    {
        return false;
    }
    let kmods: Vec<&str> = entries[ALLOWLIST.len()..]
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    kmods.windows(2).all(|pair| pair[0] < pair[1])
        && kmods.iter().all(|name| {
            name.strip_prefix("kmod/")
                .and_then(flux_core::gki_line::GkiLine::from_module_filename)
                .is_some()
        })
}

fn kmod_stub_allowed() -> bool {
    matches!(
        std::env::var("FLUX_KMOD_STUB").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn kmod_input_dir(root: &Path) -> PathBuf {
    match std::env::var_os("FLUX_KMOD_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => root.join("dist/kmod"),
    }
}

fn list_kmod_files(dir: &Path) -> Result<Vec<String>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|error| format!("read {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read {}: {error}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if flux_core::gki_line::GkiLine::from_module_filename(name).is_some() {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn collect_kmod_entries(root: &Path) -> Result<Vec<zip::Entry>, String> {
    let dir = kmod_input_dir(root);
    let mut names = list_kmod_files(&dir)?;
    if names.is_empty() {
        if kmod_stub_allowed() {
            println!(
                "package: stub kmod/fluxrs-android13-5.15.ko (FLUX_KMOD_STUB); \
                 finit_module will Direct until a DDK .ko is copied into dist/kmod"
            );
            return Ok(vec![zip::Entry {
                name: "kmod/fluxrs-android13-5.15.ko".into(),
                mode: 0o644,
                data: flux_core::modinfo::stub_android13_5_15(),
            }]);
        }
        return Err(format!(
            "no fluxrs-android*.ko in {}; DDK-build and copy, set FLUX_KMOD_DIR, \
             or FLUX_KMOD_STUB=1 for an envelope-only stub",
            dir.display()
        ));
    }
    names.sort();
    let mut entries = Vec::new();
    for name in names {
        let path = dir.join(&name);
        let data = util::read_bytes(&path)?;
        flux_core::modinfo::vermagic_from_elf(&data)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        entries.push(zip::Entry {
            name: format!("kmod/{name}"),
            mode: 0o644,
            data,
        });
    }
    Ok(entries)
}

/// The Rust dependency inventory shipped under `licenses/`, generated from
/// `Cargo.lock` so it cannot drift from what was actually built. License
/// terms are audited by `cargo deny` against `deny.toml` in CI.
fn dependencies_md(root: &Path) -> Result<String, String> {
    let lock: toml::Value = toml::from_str(&util::read_text(&root.join("Cargo.lock"))?)
        .map_err(|e| format!("parse Cargo.lock: {e}"))?;
    let mut rows: Vec<(String, String)> = lock
        .get("package")
        .and_then(|p| p.as_array())
        .map(|packages| {
            packages
                .iter()
                .filter(|p| p.get("source").is_some()) // workspace members have none
                .filter_map(|p| {
                    Some((
                        p.get("name")?.as_str()?.to_string(),
                        p.get("version")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    rows.sort();

    let mut out = String::from(
        "# Rust dependencies\n\n\
         Generated by `cargo xtask package` from `Cargo.lock`. License terms are\n\
         audited in CI by `cargo deny` against `deny.toml`; run `cargo deny list`\n\
         in the source tree for the full text mapping.\n\n",
    );
    for (name, version) in &rows {
        out.push_str(&format!("- {name} {version} (crates.io)\n"));
    }
    Ok(out)
}

// ---------------------------------------------------------------- build-bpf

/// Compile the data plane object on its own, mirroring what `fluxd`'s build
/// script does when `FLUX_BUILD_BPF=1`.
pub fn build_bpf() -> Result<(), String> {
    let root = util::repo_root();
    let out = util::target_dir(&root)?.join("xtask/flux.bpf.o");
    let prefix_map = format!("{}=.", root.display());
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut command = Command::new(util::clang());
    command
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-mcpu=v3",
            "-D__TARGET_ARCH_arm64",
        ])
        .arg(format!("-ffile-prefix-map={prefix_map}"))
        .arg(format!("-fdebug-prefix-map={prefix_map}"))
        .arg(format!("-I{}", root.join("bpf/include").display()));
    if let Some(system_include) = multiarch_include() {
        command.arg(format!("-I{}", system_include.display()));
    }
    command
        .arg("-c")
        .arg(root.join("bpf/flux.bpf.c"))
        .arg("-o")
        .arg(&out);
    util::run(&mut command, "bpf compile")?;
    println!("build-bpf: OK — {}", out.display());
    Ok(())
}

/// Shape constraints on the shipped bootstrap template.
///
/// These are the properties a *default* must have, not a general validator for
/// user configs: no inbound of its own (Flux injects two), no listening control
/// surface, no credential to leak, and the two route rules the capture design
/// depends on. Everything else about the file is the user's business, so this
/// deliberately does not enumerate allowed keys (blueprint §27.2.3).
fn validate_default_template_shape(template: &str) -> Result<(), String> {
    let user = flux_core::engine_config::parse_jsonc(template)
        .map_err(|e| format!("module/template.json is invalid JSONC: {e}"))?;
    let top = user
        .as_object()
        .ok_or_else(|| "module/template.json must be a JSON object".to_string())?;

    // Flux owns the inbound side entirely; a template inbound would compete
    // with the two generated tproxy listeners.
    if top.contains_key("inbounds") {
        return Err("module/template.json must not declare inbounds: Flux injects its own".into());
    }
    // A default must never open a control port, least of all without a secret.
    // Users who want `clash_api` add it themselves, with a secret they chose.
    if user.pointer("/experimental/clash_api").is_some() {
        return Err(
            "module/template.json must not ship experimental.clash_api (§27.2.3, C10)".into(),
        );
    }

    let outbounds = user
        .get("outbounds")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "module/template.json outbounds must be an array".to_string())?;
    let has_direct = outbounds
        .iter()
        .any(|outbound| outbound.get("type").and_then(|value| value.as_str()) == Some("direct"));
    if !has_direct {
        return Err("module/template.json must contain an official direct outbound".into());
    }
    // The empty groups are the point: they are what a subscription fills
    // (§28.2). What must hold is that every member a group names exists, or the
    // engine refuses the filled configuration too.
    let tags: Vec<&str> = outbounds
        .iter()
        .filter_map(|outbound| outbound.get("tag").and_then(|value| value.as_str()))
        .collect();
    for outbound in outbounds {
        let kind = outbound.get("type").and_then(|value| value.as_str());
        if !matches!(kind, Some("selector") | Some("urltest")) {
            continue;
        }
        let members = outbound
            .get("outbounds")
            .and_then(|value| value.as_array())
            .ok_or_else(|| {
                format!(
                    "module/template.json group '{}' has no outbounds array",
                    outbound
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .unwrap_or("<untagged>")
                )
            })?;
        for member in members.iter().filter_map(|value| value.as_str()) {
            if !tags.contains(&member) {
                return Err(format!(
                    "module/template.json group '{}' names '{member}', which no outbound declares",
                    outbound
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .unwrap_or("<untagged>")
                ));
            }
        }
    }

    let rules = user
        .pointer("/route/rules")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "module/template.json route.rules must be an array".to_string())?;
    if rules
        .first()
        .and_then(|rule| rule.get("action"))
        .and_then(|value| value.as_str())
        != Some("sniff")
    {
        return Err("module/template.json must begin with the blueprint sniff rule".into());
    }
    if !flux_core::engine_config::has_dns_hijack_rule(&user) {
        return Err("module/template.json has no hijack-dns route rule".into());
    }
    validate_fakeip_outside_fixed_bypass(&user)?;

    Ok(())
}

/// A fakeip range must not land inside a prefix Flux bypasses unconditionally.
///
/// Overlap is silent and total: every fakeip address would be routed direct, so
/// IPv6 fakeip stops working with nothing logged. The v6 range is the one that
/// bites, because `fc00::/7` is a fixed bypass and `fd00::/8` is the obvious
/// place to put a private range.
///
/// This compares parsed prefixes against `flux_core::cidr::fixed_bypass`. The
/// string test it replaced — reject anything starting `fc` or `fd` — matched
/// the right addresses for the wrong reason and missed uppercase entirely.
fn validate_fakeip_outside_fixed_bypass(
    user: &flux_core::engine_config::Value,
) -> Result<(), String> {
    use flux_core::cidr::{fixed_bypass, Ipv4Cidr, Ipv6Cidr};
    use flux_core::engine_config::Value;
    let (bypass_v4, bypass_v6) = fixed_bypass();

    for fakeip in fakeip_sources(user) {
        if let Some(range) = fakeip.get("inet6_range").and_then(Value::as_str) {
            let parsed = Ipv6Cidr::parse(range)
                .map_err(|e| format!("module/template.json fakeip inet6_range `{range}`: {e:?}"))?;
            if let Some(hit) = bypass_v6
                .iter()
                .find(|entry| entry.cidr.contains_prefix(&parsed))
            {
                return Err(format!(
                    "module/template.json fakeip inet6_range {range} lies inside the fixed \
                     bypass {}; every fakeip address would be routed direct",
                    hit.cidr
                ));
            }
        }
        if let Some(range) = fakeip.get("inet4_range").and_then(Value::as_str) {
            let parsed = Ipv4Cidr::parse(range)
                .map_err(|e| format!("module/template.json fakeip inet4_range `{range}`: {e:?}"))?;
            if let Some(hit) = bypass_v4
                .iter()
                .find(|entry| entry.cidr.contains_prefix(&parsed))
            {
                return Err(format!(
                    "module/template.json fakeip inet4_range {range} lies inside the fixed \
                     bypass {}; every fakeip address would be routed direct",
                    hit.cidr
                ));
            }
        }
    }
    Ok(())
}

/// Every object in the config that carries fakeip ranges.
///
/// sing-box 1.12 moved fakeip from a `dns.fakeip` object to a `dns.servers`
/// entry of `type: "fakeip"`. Both shapes are accepted here because a user
/// config may still carry the old one, and reading only the modern path is how
/// the first version of this check silently passed everything.
fn fakeip_sources(user: &flux_core::engine_config::Value) -> Vec<&flux_core::engine_config::Value> {
    use flux_core::engine_config::Value;
    let mut found = Vec::new();
    if let Some(legacy) = user.pointer("/dns/fakeip") {
        found.push(legacy);
    }
    if let Some(servers) = user.pointer("/dns/servers").and_then(Value::as_array) {
        found.extend(
            servers
                .iter()
                .filter(|s| s.get("type").and_then(Value::as_str) == Some("fakeip")),
        );
    }
    found
}

pub fn template_check() -> Result<(), String> {
    let root = util::repo_root();
    let release = engine_release::Release::resolve()?;
    let cache = util::target_dir(&root)?
        .join("xtask/engine")
        .join(&release.tag);
    let host = release.host.acquire(&cache)?;
    check_template_with_binary(&root, &host.binary, &release.version)
}

fn check_template_with_binary(root: &Path, binary: &Path, version: &str) -> Result<(), String> {
    let cache = util::work_dir(&util::target_dir(root)?.join("xtask"), "template-check")?;
    let template = util::read_text(&root.join("module/template.json"))?;
    validate_default_template_shape(&template)?;
    let user = flux_core::engine_config::parse_jsonc(&template)
        .map_err(|e| format!("module/template.json is invalid JSONC: {e}"))?;

    // With nothing to fill its groups the template is not a configuration, and
    // generation MUST refuse rather than let the engine reject it (§28.2).
    match flux_core::engine_config::generate_from_template(&user, &[]) {
        Err(flux_core::engine_config::EngineConfigError::UnfilledGroups(tags)) => {
            println!("template-check: unsubscribed generation refused, waiting on {tags:?}");
        }
        Err(e) => return Err(format!("generate default template: {e:?}")),
        Ok(_) => {
            return Err(
                "module/template.json generated a configuration with no nodes at all; \
                 a bootstrap default's groups must be the subscription's to fill (§28.2)"
                    .into(),
            )
        }
    }

    let generated = flux_core::engine_config::generate_from_template(&user, &synthetic_nodes()?)
        .map_err(|e| format!("generate filled template: {e:?}"))?;
    let unreferenced = flux_core::engine_config::unreferenced_node_tags(&generated);
    if !unreferenced.is_empty() {
        return Err(format!(
            "module/template.json leaves filled nodes unselected: {unreferenced:?}; \
             a group tagged for each shipped region must exist"
        ));
    }
    let params = flux_core::engine_config::EngineParams {
        generation: 1,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    let effective = flux_core::engine_config::build_effective(&generated, &params)
        .map_err(|e| format!("build default effective config: {e:?}"))?;
    let config = cache.join("effective-default.json");
    util::write_bytes(&config, effective.to_string().as_bytes())?;
    let output = Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(&config)
        .output()
        .map_err(|e| format!("run {}: {e}", binary.display()))?;
    let _ = std::fs::remove_file(&config);
    if !output.status.success() {
        return Err(format!(
            "official sing-box {version} rejected the filled module/template.json: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!(
        "template-check: OK — official sing-box {version} accepted the shipped template once \
         filled, and refused to be handed it unfilled"
    );
    Ok(())
}

/// One node per region the shipped template groups by, so the check covers the
/// fill for every group the default declares.
fn synthetic_nodes() -> Result<Vec<flux_core::engine_config::RefinedNode>, String> {
    ["HK", "TW", "JP", "SG", "US"]
        .iter()
        .map(|region| {
            let outbound = flux_core::engine_config::parse_jsonc(&format!(
                "{{\"type\": \"trojan\", \"tag\": \"probe-{region}\", \
                 \"server\": \"192.0.2.1\", \"server_port\": 443, \"password\": \"probe\"}}"
            ))
            .map_err(|e| format!("build the {region} probe node: {e}"))?;
            Ok(flux_core::engine_config::RefinedNode {
                outbound,
                groups: vec![(*region).to_string()],
            })
        })
        .collect()
}

fn multiarch_include() -> Option<PathBuf> {
    let output = Command::new("cc").arg("-print-multiarch").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let triple = std::str::from_utf8(&output.stdout).ok()?.trim();
    let include = PathBuf::from("/usr/include").join(triple);
    include.is_dir().then_some(include)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webroot_remains_one_redirect_file() {
        validate_webroot_shape(&util::repo_root()).unwrap();
    }

    #[test]
    fn kmod_entries_are_sorted_gki_line_files() {
        let dir = std::env::temp_dir().join(format!("xtask-kmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("fluxrs-android14-6.1.ko"),
            flux_core::modinfo::reloc_elf_with_modinfo(b"vermagic=6.1.0-android14-stub\0"),
        )
        .unwrap();
        std::fs::write(
            dir.join("fluxrs-android13-5.15.ko"),
            flux_core::modinfo::stub_android13_5_15(),
        )
        .unwrap();
        std::fs::write(dir.join("readme.txt"), b"ignore").unwrap();
        let mut names = list_kmod_files(&dir).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                "fluxrs-android13-5.15.ko".to_string(),
                "fluxrs-android14-6.1.ko".to_string()
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_prefix_then_sorted_kmod() {
        let mut entries: Vec<zip::Entry> = ALLOWLIST
            .iter()
            .map(|name| zip::Entry {
                name: (*name).to_string(),
                mode: 0o644,
                data: Vec::new(),
            })
            .collect();
        assert!(!names_follow_allowlist(&entries));
        entries.push(zip::Entry {
            name: "kmod/fluxrs-android13-5.15.ko".into(),
            mode: 0o644,
            data: Vec::new(),
        });
        assert!(names_follow_allowlist(&entries));
    }

    #[test]
    fn shipped_template_remains_blueprint_minimal() {
        let root = util::repo_root();
        let template = util::read_text(&root.join("module/template.json")).unwrap();
        validate_default_template_shape(&template).unwrap();
    }

    /// The shipped template with its fakeip v6 range swapped for `replacement`.
    fn template_with_fakeip_v6(replacement: &str) -> String {
        let root = util::repo_root();
        let template = util::read_text(&root.join("module/template.json")).unwrap();
        let swapped = template.replace("2001:db8:f::/48", replacement);
        assert_ne!(swapped, template, "the template moved; update this test");
        swapped
    }

    #[test]
    fn fakeip_inside_the_fixed_bypass_is_rejected() {
        // fc00::/7 is bypassed unconditionally, so a fakeip range inside it
        // would be routed direct with nothing logged.
        let error = validate_default_template_shape(&template_with_fakeip_v6("fd00::/8"))
            .expect_err("a fakeip range inside fc00::/7 must not pass");
        assert!(error.contains("fixed bypass"), "{error}");
    }

    #[test]
    fn a_non_canonical_fakeip_range_is_rejected_rather_than_ignored() {
        // The string test this replaced looked for a lowercase `fc`/`fd`
        // prefix, so uppercase walked straight past it.
        let error = validate_default_template_shape(&template_with_fakeip_v6("FD00::/8"))
            .expect_err("uppercase must not be a way around the check");
        assert!(error.contains("inet6_range"), "{error}");
    }

    #[test]
    fn provenance_accepts_commits_and_explicit_dirty_suffix_only() {
        assert!(valid_provenance("0123456"));
        assert!(valid_provenance(
            "0123456789abcdef0123456789abcdef01234567-dirty"
        ));
        assert!(!valid_provenance("012345"));
        assert!(!valid_provenance("0123456-unknown"));
        assert!(!valid_provenance("not-a-commit"));
    }

    #[test]
    fn release_refuses_a_tag_that_is_not_the_workspace_version() {
        let error = release("v999.0.0").unwrap_err();
        assert!(
            error.contains("does not equal workspace version tag"),
            "{error}"
        );
    }
}
