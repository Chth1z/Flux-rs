//! Read-only configuration and capability checks.
//!
//! One shared implementation behind two front doors: the `fluxd check` CLI
//! (full check, including a real `sing-box check -c` run) and the daemon's
//! `check` op (quick check — no subprocess, so a control request can never
//! occupy the reactor for the engine-check deadline).
//!
//! Nothing here mutates anything: no files are written except a throwaway
//! effective config for the engine check, which lands in a fresh temp path
//! and is removed before returning.

use std::io;
use std::path::Path;

use flux_core::config::{ConfigError, FluxConfig, MAX_CONFIG_BYTES};
use flux_core::engine_config::{self, EngineParams, MAX_ENGINE_CONFIG_BYTES};
use flux_core::selector::{PackageIndex, SelectorError};

use crate::engine::{self, EngineSpec};
use crate::layout::Layout;

/// The findings of one check pass. `errors` non-empty means the check failed
/// (CLI exit code non-zero, `ok=false` on the wire); `warnings` never fail it.
#[derive(Debug, Default)]
pub struct CheckReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// The full check: everything [`quick_check`] covers plus a real
/// `sing-box check -c` subprocess run against a throwaway effective config.
/// CLI-only; the daemon must use [`quick_check`].
pub fn full_check(layout: &Layout, spec: &EngineSpec) -> CheckReport {
    let mut report = quick_check(layout, spec);
    run_engine_check(layout, spec, &mut report);
    report
}

/// The bounded-time check: `flux.toml`, `packages.list` resolution,
/// `sing-box.json` structure and §9 constraints, clash_api hardening
/// (`docs/ux.md` §3.2), and engine binary presence. No subprocesses.
pub fn quick_check(layout: &Layout, spec: &EngineSpec) -> CheckReport {
    let mut report = CheckReport::default();
    check_flux_toml(layout, &mut report);
    check_sing_box_json(layout, &mut report);
    if !spec.binary.exists() {
        report.errors.push(format!(
            "engine_binary_missing: {} does not exist",
            spec.binary.display()
        ));
    }
    report
}

fn check_flux_toml(layout: &Layout, report: &mut CheckReport) {
    let path = layout.flux_toml();
    let bytes = match read_capped(&path, MAX_CONFIG_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            report.warnings.push(
                "config/flux.toml missing: no apps selected, nothing will be proxied".to_string(),
            );
            return;
        }
        Err(e) => {
            report
                .errors
                .push(format!("flux.toml unreadable: {e} ({})", path.display()));
            return;
        }
    };
    let config = match FluxConfig::parse(&bytes) {
        Ok(config) => config,
        Err(e) => {
            report
                .errors
                .push(format!("flux.toml: {}", describe_flux_error(&e)));
            return;
        }
    };
    if config.apps.is_empty() {
        report
            .warnings
            .push("flux.toml selects no apps: nothing will be proxied".to_string());
    }
    check_selectors(&config, report);
}

/// Resolves the selected apps against `packages.list`. An unknown package makes
/// the candidate invalid (§11.3); shared UIDs remain a warning because the
/// resulting UID is still deterministic.
fn check_selectors(config: &FluxConfig, report: &mut CheckReport) {
    if config.apps.is_empty() {
        return;
    }
    let text = match crate::packages::read() {
        Ok(text) => text,
        Err(e) => {
            report.errors.push(format!("packages_list_unreadable: {e}"));
            return;
        }
    };
    let index = PackageIndex::parse(&text);
    for selector in &config.apps {
        match index.resolve(selector) {
            Ok(selection) => {
                let shared = index.shared_with(selection.uid % 100_000);
                if shared.len() > 1 {
                    report.warnings.push(format!(
                        "{} shares its UID with {}: they are proxied together",
                        selector.canonical(),
                        shared
                            .iter()
                            .filter(|p| **p != selector.package)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            Err(SelectorError::UnknownPackage(package)) => {
                report.errors.push(format!(
                    "{}: package `{package}` is not installed",
                    selector.canonical()
                ));
            }
            Err(e) => {
                report.errors.push(format!(
                    "{}: {}",
                    selector.canonical(),
                    describe_selector_error(&e)
                ));
            }
        }
    }
}

fn check_sing_box_json(layout: &Layout, report: &mut CheckReport) {
    let path = layout.sing_box_json();
    let bytes = match read_capped(&path, MAX_ENGINE_CONFIG_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            report.errors.push(format!(
                "engine_config_missing: {} does not exist",
                path.display()
            ));
            return;
        }
        Err(e) => {
            report.errors.push(format!(
                "sing-box.json unreadable: {e} ({})",
                path.display()
            ));
            return;
        }
    };
    if bytes.len() > MAX_ENGINE_CONFIG_BYTES {
        report.errors.push(format!(
            "engine_config_too_large: {} exceeds the 8 MiB limit",
            path.display()
        ));
        return;
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            report
                .errors
                .push("engine_config_invalid: sing-box.json is not UTF-8".to_string());
            return;
        }
    };
    let user = match engine_config::parse_jsonc(&text) {
        Ok(user) => user,
        Err(e) => {
            report
                .errors
                .push(format!("engine_config_invalid: sing-box.json: {e}"));
            return;
        }
    };

    // The §9.1/§9.6 structural constraints, via the same builder the daemon
    // uses. Dummy params: the ports only shape the injected inbounds.
    let params = EngineParams {
        generation: 0,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    if let Err(e) = engine_config::build_effective(&user, &params) {
        report.errors.push(format!(
            "engine_config_invalid: {}",
            engine::describe_config_error(&e)
        ));
        return;
    }

    if !engine_config::has_dns_hijack_rule(&user) {
        report.warnings.push(
            "sing-box.json has no DNS hijack rule: selected apps' DNS may leak to the physical network"
                .to_string(),
        );
    }
    check_clash_api(&user, report);
}

/// `docs/ux.md` §3.2: with `experimental.clash_api` present, an empty `secret`
/// or a non-loopback `external_controller` is an ERROR, not a warning — either
/// one hands the proxy control plane to every app (or every Wi-Fi neighbour).
fn check_clash_api(user: &serde_json::Value, report: &mut CheckReport) {
    let Some(clash) = user
        .get("experimental")
        .and_then(|e| e.get("clash_api"))
        .and_then(|c| c.as_object())
    else {
        return;
    };
    match clash.get("secret").and_then(|s| s.as_str()) {
        Some(secret) if !secret.is_empty() => {}
        _ => {
            report.errors.push(
                "clash_api_secret_missing: experimental.clash_api.secret is empty or absent; \
                 any app could reconfigure the proxy (docs/ux.md §3.2)"
                    .to_string(),
            );
        }
    }
    if let Some(controller) = clash.get("external_controller").and_then(|c| c.as_str()) {
        let host = controller.rsplit_once(':').map_or(controller, |(h, _)| h);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(host == "localhost");
        if !loopback {
            report.errors.push(format!(
                "clash_api_not_loopback: external_controller `{controller}` is not bound to \
                 loopback; the control plane would be exposed to the network (docs/ux.md §3.2)"
            ));
        }
    }
}

/// The subprocess half of the full check: builds a real effective config with
/// dummy ports into a throwaway temp file and runs `sing-box check -c` on it,
/// under the engine-check deadline. Skipped when the prior structural checks
/// already failed (running the engine on known-bad input adds noise, not
/// information).
fn run_engine_check(layout: &Layout, spec: &EngineSpec, report: &mut CheckReport) {
    if !report.errors.is_empty() || !spec.binary.exists() {
        return;
    }
    let Ok(bytes) = read_capped(&layout.sing_box_json(), MAX_ENGINE_CONFIG_BYTES + 1) else {
        return;
    };
    if bytes.len() > MAX_ENGINE_CONFIG_BYTES {
        return;
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return;
    };
    let Ok(user) = engine_config::parse_jsonc(&text) else {
        return;
    };
    let params = EngineParams {
        generation: 0,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    let Ok(effective) = engine_config::build_effective(&user, &params) else {
        return;
    };

    let tmp = match write_check_config(&effective) {
        Ok(path) => path,
        Err(e) => {
            report.warnings.push(format!(
                "engine check skipped: cannot write temp config: {e}"
            ));
            return;
        }
    };
    let result = engine::run_check(&spec.binary, &tmp);
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = result {
        let mut message = format!("engine check: {}", e.token());
        if let Some(detail) = e.detail() {
            message.push_str(&format!(" — {detail}"));
        }
        report.errors.push(message);
    }
}

/// Writes a root-safe throwaway config in the shared temp directory. The name
/// is unpredictable and creation is `O_EXCL|O_NOFOLLOW` with mode 0600, so a
/// symlink or pre-existing path can never be overwritten by `fluxd check`.
fn write_check_config(effective: &serde_json::Value) -> io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let bytes = serde_json::to_vec_pretty(effective)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    for _ in 0..8 {
        let mut nonce = [0u8; 8];
        // SAFETY: nonce is writable for its full length.
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
            != nonce.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        let name = format!("flux-check-{}.json", u64::from_ne_bytes(nonce));
        let path = std::env::temp_dir().join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique check config",
    ))
}

/// Reads at most `cap` bytes; the caller's parser enforces its own limit, this
/// only prevents an accidentally huge file from being slurped whole.
pub(crate) fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(cap as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Human-readable rendering of [`ConfigError`]. Lives here, not in flux-core:
/// the core keeps structured errors, presentation is the daemon's job.
pub fn describe_flux_error(e: &ConfigError) -> String {
    match e {
        ConfigError::TooLarge(size) => {
            format!("file is {size} bytes, the limit is {MAX_CONFIG_BYTES}")
        }
        ConfigError::Syntax(detail) => format!("TOML syntax: {detail}"),
        ConfigError::UnknownKey { key, closest } => match closest {
            Some(hint) => format!("unknown key `{key}` (did you mean `{hint}`?)"),
            None => format!("unknown key `{key}`"),
        },
        ConfigError::WrongType(detail) => detail.clone(),
        ConfigError::TooManyApps(n) => format!("{n} apps exceed the selection limit"),
        ConfigError::TooManyBypassV4(n) => format!("{n} IPv4 bypass prefixes exceed the limit"),
        ConfigError::TooManyBypassV6(n) => format!("{n} IPv6 bypass prefixes exceed the limit"),
        ConfigError::DuplicateApp(app) => format!("app `{app}` is listed twice"),
        ConfigError::DuplicateBypass(prefix) => format!("bypass `{prefix}` is listed twice"),
        ConfigError::Selector(e) => describe_selector_error(e),
        ConfigError::Cidr(e) => describe_cidr_error(e),
    }
}

fn describe_selector_error(e: &SelectorError) -> String {
    match e {
        SelectorError::Malformed(text) => {
            format!("selector `{text}` is not `packageName` or `userId:packageName`")
        }
        SelectorError::UserIdOutOfRange(id) => format!("user id {id} is out of range"),
        SelectorError::AppIdOutOfRange(id) => format!("app id {id} is out of range"),
        SelectorError::UnknownPackage(package) => format!("package `{package}` is not installed"),
    }
}

fn describe_cidr_error(e: &flux_core::cidr::CidrError) -> String {
    use flux_core::cidr::CidrError;
    match e {
        CidrError::Malformed(text) => format!("`{text}` is not a canonical CIDR"),
        CidrError::PrefixTooLong(len) => format!("prefix length {len} exceeds the family width"),
        CidrError::HostBitsSet(text) => {
            format!("`{text}` has host bits set below the prefix length")
        }
        CidrError::CapacityExceeded => "bypass capacity exceeded".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn tmp_layout(tag: &str) -> Layout {
        let mut dir = std::env::temp_dir();
        // SAFETY: getpid has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        dir.push(format!("flux-checks-{tag}-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = Layout::at(dir);
        layout.ensure().unwrap();
        layout
    }

    fn loopback_spec(binary: std::path::PathBuf) -> EngineSpec {
        EngineSpec {
            binary,
            workdir: std::env::temp_dir(),
            listen_v4: Ipv4Addr::LOCALHOST,
            listen_v6: Ipv6Addr::LOCALHOST,
        }
    }

    #[test]
    fn missing_configs_are_error_and_warning_respectively() {
        let layout = tmp_layout("missing");
        let spec = loopback_spec(layout.root().join("no-engine"));
        let report = quick_check(&layout, &spec);
        assert!(!report.ok());
        assert!(report
            .errors
            .iter()
            .any(|e| e.starts_with("engine_config_missing")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.starts_with("engine_binary_missing")));
        // flux.toml missing is a warning, not an error: unconfigured != broken.
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("flux.toml missing")));
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn clash_api_hardening_is_an_error_not_a_warning() {
        let layout = tmp_layout("clash");
        std::fs::write(layout.flux_toml(), "apps = []\n").unwrap();
        std::fs::write(
            layout.sing_box_json(),
            serde_json::json!({
                "outbounds": [],
                "experimental": { "clash_api": {
                    "external_controller": "0.0.0.0:9090",
                    "secret": ""
                }}
            })
            .to_string(),
        )
        .unwrap();
        let engine = layout.root().join("engine");
        std::fs::write(&engine, "#!/bin/sh\nexit 0\n").unwrap();
        let report = quick_check(&layout, &loopback_spec(engine));
        assert!(report
            .errors
            .iter()
            .any(|e| e.starts_with("clash_api_secret_missing")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.starts_with("clash_api_not_loopback")));
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn loopback_controller_with_secret_passes() {
        let layout = tmp_layout("clash-ok");
        std::fs::write(
            layout.sing_box_json(),
            serde_json::json!({
                "outbounds": [],
                "experimental": { "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": "s3cr3t"
                }}
            })
            .to_string(),
        )
        .unwrap();
        let mut report = CheckReport::default();
        let user =
            engine_config::parse_jsonc(&std::fs::read_to_string(layout.sing_box_json()).unwrap())
                .unwrap();
        check_clash_api(&user, &mut report);
        assert!(report.ok(), "{:?}", report.errors);
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn bad_flux_toml_is_an_error_with_a_hint() {
        let layout = tmp_layout("toml");
        std::fs::write(layout.flux_toml(), "app = [\"org.example\"]\n").unwrap();
        let spec = loopback_spec(layout.root().join("no-engine"));
        let report = quick_check(&layout, &spec);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("unknown key `app`") && e.contains("apps")));
        std::fs::remove_dir_all(layout.root()).unwrap();
    }
}
