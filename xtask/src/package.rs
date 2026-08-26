//! `cargo xtask package` / `verify-package` / `build-bpf` — blueprint §13.4.
//!
//! `package` is the only packaging entry point, local and CI alike:
//!
//! 1. Derive everything version-shaped from `[workspace.package] version`
//!    (single version source; `module.prop` is generated, never maintained).
//! 2. Obtain and verify the pinned engine: `engine.lock` size + SHA-256 for
//!    both the archive and the extracted binary, and every `PT_LOAD` still
//!    exactly at the recorded alignment. Any mismatch refuses to package.
//! 3. Cross-build `fluxd` (`aarch64-linux-android`, embedded BPF object,
//!    16 KiB max-page-size link flags) and require `p_align >= 0x4000`.
//! 4. Stage the §13.1 allowlist — never "everything except" — with LF line
//!    endings and fixed modes.
//! 5. Write a deterministic STORE ZIP in allowlist order plus `SHA256SUMS`.
//!
//! `verify-package` runs the whole pipeline twice from clean cross-build
//! state and asserts the two archives hash identically (§17.4 exit
//! criterion 4).

use crate::{elf, sha256, util, zip};
use std::path::{Path, PathBuf};
use std::process::Command;

/// §13.1: the exact ZIP contents, in archive order. Anything else is a bug.
const ALLOWLIST: [&str; 16] = [
    "module.prop",
    "skip_mount",
    "customize.sh",
    "service.sh",
    "action.sh",
    "uninstall.sh",
    "bin/fluxd",
    "bin/sing-box",
    "bin/observe.sh",
    "etc/default-flux.toml",
    "etc/default-sing-box.json",
    "engine.lock",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "licenses/sing-box-LICENSE",
    "licenses/DEPENDENCIES.md",
];

pub fn run() -> Result<(), String> {
    let (zip_path, digest) = package_once()?;
    println!("package: OK — {}", zip_path.display());
    println!("package: sha256 {}", sha256::hex(&digest));
    Ok(())
}

/// Two full runs from clean cross-build state must agree byte for byte.
pub fn verify() -> Result<(), String> {
    let root = util::repo_root();

    clean_cross_target(&root)?;
    let (zip_path, first) = package_once()?;
    let first_copy = zip_path.with_extension("zip.run1");
    std::fs::copy(&zip_path, &first_copy)
        .map_err(|e| format!("copy {}: {e}", zip_path.display()))?;

    clean_cross_target(&root)?;
    let (zip_path, second) = package_once()?;

    if first != second {
        return Err(format!(
            "NOT reproducible: run 1 {} != run 2 {} (run 1 kept at {})",
            sha256::hex(&first),
            sha256::hex(&second),
            first_copy.display()
        ));
    }
    std::fs::remove_file(&first_copy).map_err(|e| format!("remove run-1 copy: {e}"))?;
    println!(
        "verify-package: OK — two clean builds of {} both hash {}",
        zip_path.display(),
        sha256::hex(&first)
    );
    Ok(())
}

fn clean_cross_target(root: &Path) -> Result<(), String> {
    let dir = root.join("target/aarch64-linux-android");
    if dir.exists() {
        println!(
            "package: removing {} for a clean cross build",
            dir.display()
        );
        std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {e}", dir.display()))?;
    }
    Ok(())
}

fn package_once() -> Result<(PathBuf, [u8; 32]), String> {
    let root = util::repo_root();

    // 1. Single version source.
    let version = workspace_version(&root)?;
    let module_prop = flux_core::version::module_prop(&version)
        .ok_or_else(|| format!("workspace version `{version}` is not representable (§13.4)"))?;
    let zip_name = flux_core::version::artifact_name(&version);
    println!("package: version {version} -> {zip_name}");
    if root.join("module/module.prop").exists() {
        return Err(
            "module/module.prop exists in the tree; module.prop is generated from the \
             workspace version and a checked-in copy is exactly the second version file \
             blueprint §13.4 forbids"
                .into(),
        );
    }

    // 2. Engine pin.
    let engine = verify_engine(&root)?;

    // 3. Cross-built daemon.
    let fluxd = build_fluxd(&root)?;

    // 4 + 5. Stage the allowlist and write the archive.
    let entries = collect_entries(&root, &module_prop, &engine, &fluxd)?;
    debug_assert!(entries.iter().map(|e| e.name.as_str()).eq(ALLOWLIST));

    let stage = root.join("target/xtask/stage");
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
    let manifest: toml::Value = util::read_text(&root.join("Cargo.toml"))?
        .parse()
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

struct Engine {
    binary: PathBuf,
    license: PathBuf,
}

fn lock_str<'a>(lock: &'a toml::Value, key: &str) -> Result<&'a str, String> {
    lock.get("engine")
        .and_then(|e| e.get(key))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("engine.lock: missing or non-string [engine] {key}"))
}

fn lock_int(lock: &toml::Value, key: &str) -> Result<u64, String> {
    lock.get("engine")
        .and_then(|e| e.get(key))
        .and_then(|v| v.as_integer())
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| format!("engine.lock: missing or non-integer [engine] {key}"))
}

/// Download (once), then verify the pinned engine against `engine.lock`.
/// Every digest or size mismatch is a hard refusal to package (§17.4 exit
/// criterion 5); this automates the manual verification recorded in the lock.
fn verify_engine(root: &Path) -> Result<Engine, String> {
    let lock: toml::Value = util::read_text(&root.join("engine.lock"))?
        .parse()
        .map_err(|e| format!("parse engine.lock: {e}"))?;

    let version = lock_str(&lock, "version")?;
    let url = lock_str(&lock, "archive_url")?;
    let binary_in_archive = lock_str(&lock, "binary_path_in_archive")?;
    let license_in_archive = lock_str(&lock, "license_path_in_archive")?;
    let p_align = lock_str(&lock, "max_load_p_align")?;
    let expected_p_align = p_align
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .ok_or_else(|| format!("engine.lock: max_load_p_align `{p_align}` is not 0x-hex"))?;
    if !url.contains(version) || !binary_in_archive.contains(version) {
        return Err(format!(
            "engine.lock is internally inconsistent: version {version} does not appear in \
             archive_url or binary_path_in_archive"
        ));
    }

    let cache = root.join("target/xtask/engine");
    let archive_name = url
        .rsplit('/')
        .next()
        .expect("rsplit yields at least one piece");
    let archive_path = cache.join(archive_name);
    if !archive_path.is_file() {
        std::fs::create_dir_all(&cache).map_err(|e| format!("create {}: {e}", cache.display()))?;
        println!("package: downloading pinned engine {url}");
        let partial = cache.join("download.partial");
        util::run(
            Command::new("curl")
                .arg("-fsSL")
                .arg("--retry")
                .arg("3")
                .arg("-o")
                .arg(&partial)
                .arg(url),
            "engine download",
        )?;
        std::fs::rename(&partial, &archive_path).map_err(|e| format!("rename download: {e}"))?;
    }

    let archive = util::read_bytes(&archive_path)?;
    check_pin(&lock, "archive", &archive)?;

    let extract = cache.join("extract");
    let binary = extract.join(binary_in_archive);
    let license = extract.join(license_in_archive);
    if !binary.is_file() || !license.is_file() {
        std::fs::create_dir_all(&extract)
            .map_err(|e| format!("create {}: {e}", extract.display()))?;
        util::run(
            Command::new("tar")
                .arg("-xzf")
                .arg(&archive_path)
                .arg("-C")
                .arg(&extract)
                .arg(binary_in_archive)
                .arg(license_in_archive),
            "engine extraction",
        )?;
    }

    let binary_bytes = util::read_bytes(&binary)?;
    check_pin(&lock, "binary", &binary_bytes)?;

    // "Still exactly 0x1000": the 16 KiB gap is a *documented* limitation
    // (§3.8, §22.2). If a new engine build changes alignment, the lock — and
    // that documentation — must be updated deliberately, so drift is an error
    // in both directions.
    let aligns = elf::load_aligns(&binary_bytes)
        .map_err(|e| format!("engine binary is not a readable ELF: {e}"))?;
    for align in &aligns {
        if *align != expected_p_align {
            return Err(format!(
                "engine PT_LOAD p_align {align:#x} != engine.lock max_load_p_align \
                 {expected_p_align:#x}; re-measure and update engine.lock and blueprint §3.8"
            ));
        }
    }

    println!(
        "package: engine {version} verified — archive + binary sha256/size match engine.lock, \
         {} LOAD segments at {expected_p_align:#x}",
        aligns.len()
    );
    Ok(Engine { binary, license })
}

/// Verify `<what>_sha256` and `<what>_size` from `engine.lock` against bytes.
fn check_pin(lock: &toml::Value, what: &str, data: &[u8]) -> Result<(), String> {
    let expected_sha = lock_str(lock, &format!("{what}_sha256"))?;
    let expected_size = lock_int(lock, &format!("{what}_size"))?;
    if data.len() as u64 != expected_size {
        return Err(format!(
            "engine {what} is {} bytes, engine.lock pins {expected_size}; refusing to package",
            data.len()
        ));
    }
    let actual = sha256::hex(&sha256::digest(data));
    if actual != expected_sha.to_ascii_lowercase() {
        return Err(format!(
            "engine {what} sha256 {actual} != engine.lock {expected_sha}; refusing to package"
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------- fluxd

/// Cross-build `fluxd` with the embedded BPF object and the 16 KiB page-size
/// link flags, then enforce `p_align >= 0x4000` on every LOAD segment.
fn build_fluxd(root: &Path) -> Result<PathBuf, String> {
    let mut cmd = Command::new(util::cargo());
    cmd.current_dir(root)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "fluxd",
            "--target",
            "aarch64-linux-android",
        ])
        .env("FLUX_BUILD_BPF", "1")
        // RUSTFLAGS replaces the [target.aarch64-linux-android] rustflags from
        // .cargo/config.toml, so crt-static must be restated here.
        .env(
            "RUSTFLAGS",
            format!(
                "-C target-feature=+crt-static \
                 -C link-arg=-Wl,-z,max-page-size=16384 \
                 -C link-arg=-Wl,-z,common-page-size=16384 \
                 --remap-path-prefix={}=/flux-rs",
                root.display()
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
                "`{LINKER}` is not on PATH and ANDROID_NDK_HOME is not set; install the NDK \
                 pinned in .cargo/config.toml"
            )
        })?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut parts = vec![ndk_bin];
        parts.extend(std::env::split_paths(&path));
        let joined = std::env::join_paths(parts).map_err(|e| format!("extend PATH: {e}"))?;
        cmd.env("PATH", joined);
    }

    println!("package: cross-building fluxd (aarch64-linux-android, BPF object embedded)");
    util::run(&mut cmd, "fluxd cross build")?;

    let fluxd = root.join("target/aarch64-linux-android/release/fluxd");
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

fn collect_entries(
    root: &Path,
    module_prop: &str,
    engine: &Engine,
    fluxd: &Path,
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
    push("action.sh", 0o755, text("module/action.sh")?);
    push("uninstall.sh", 0o755, text("module/uninstall.sh")?);
    push("bin/fluxd", 0o755, util::read_bytes(fluxd)?);
    push("bin/sing-box", 0o755, util::read_bytes(&engine.binary)?);
    push("bin/observe.sh", 0o755, text("tools/phase0/observe.sh")?);
    push("etc/default-flux.toml", 0o644, text("module/flux.toml")?);
    push(
        "etc/default-sing-box.json",
        0o644,
        text("module/template.json")?,
    );
    push("engine.lock", 0o644, text("engine.lock")?);
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
    Ok(entries)
}

/// The Rust dependency inventory shipped under `licenses/`, generated from
/// `Cargo.lock` so it cannot drift from what was actually built. License
/// terms are audited by `cargo deny` against `deny.toml` in CI.
fn dependencies_md(root: &Path) -> Result<String, String> {
    let lock: toml::Value = util::read_text(&root.join("Cargo.lock"))?
        .parse()
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
    let out = root.join("target/xtask/flux.bpf.o");
    let prefix_map = format!("{}=.", root.display());
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut command = Command::new(util::clang());
    command
        .args([
            "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-mcpu=v3",
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

/// Runs the pinned official host binary's real `check -c` against the exact
/// shipped template after applying Flux's two generated inbounds.
pub fn template_check() -> Result<(), String> {
    let root = util::repo_root();
    let lock: toml::Value = util::read_text(&root.join("engine.lock"))?
        .parse()
        .map_err(|e| format!("parse engine.lock: {e}"))?;
    let version = lock_str(&lock, "version")?;
    let url = lock_str(&lock, "check_archive_url")?;
    let binary_in_archive = lock_str(&lock, "check_binary_path_in_archive")?;
    if !url.contains(version) || !binary_in_archive.contains(version) {
        return Err("engine.lock host-check asset does not match engine version".into());
    }

    let cache = root.join("target/xtask/engine-check");
    std::fs::create_dir_all(&cache).map_err(|e| format!("create {}: {e}", cache.display()))?;
    let archive = cache.join(
        url.rsplit('/')
            .next()
            .expect("URL has at least one path component"),
    );
    if !archive.is_file() {
        let partial = cache.join("download.partial");
        util::run(
            Command::new("curl")
                .arg("-fsSL")
                .arg("--retry")
                .arg("3")
                .arg("-o")
                .arg(&partial)
                .arg(url),
            "template-check engine download",
        )?;
        std::fs::rename(&partial, &archive).map_err(|e| format!("rename download: {e}"))?;
    }
    let archive_bytes = util::read_bytes(&archive)?;
    check_pin(&lock, "check_archive", &archive_bytes)?;

    let extract = cache.join("extract");
    let binary = extract.join(binary_in_archive);
    if !binary.is_file() {
        std::fs::create_dir_all(&extract)
            .map_err(|e| format!("create {}: {e}", extract.display()))?;
        util::run(
            Command::new("tar")
                .arg("-xzf")
                .arg(&archive)
                .arg("-C")
                .arg(&extract)
                .arg(binary_in_archive),
            "template-check engine extraction",
        )?;
    }
    check_pin(&lock, "check_binary", &util::read_bytes(&binary)?)?;

    let template = util::read_text(&root.join("module/template.json"))?;
    let user = flux_core::engine_config::parse_jsonc(&template)
        .map_err(|e| format!("module/template.json is invalid JSONC: {e}"))?;
    if !flux_core::engine_config::has_dns_hijack_rule(&user) {
        return Err("module/template.json has no hijack-dns route rule".into());
    }
    let has_sniff = user
        .get("route")
        .and_then(|route| route.get("rules"))
        .and_then(|rules| rules.as_array())
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule.get("action").and_then(|v| v.as_str()) == Some("sniff"))
        });
    if !has_sniff {
        return Err("module/template.json has no sniff route rule".into());
    }
    let params = flux_core::engine_config::EngineParams {
        generation: 1,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    let effective = flux_core::engine_config::build_effective(&user, &params)
        .map_err(|e| format!("build default effective config: {e:?}"))?;
    let config = cache.join("effective-default.json");
    util::write_bytes(&config, effective.to_string().as_bytes())?;
    let output = Command::new(&binary)
        .arg("check")
        .arg("-c")
        .arg(&config)
        .output()
        .map_err(|e| format!("run {}: {e}", binary.display()))?;
    let _ = std::fs::remove_file(&config);
    if !output.status.success() {
        return Err(format!(
            "official sing-box {version} rejected module/template.json: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!("template-check: OK — official sing-box {version} accepted the shipped template");
    Ok(())
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
