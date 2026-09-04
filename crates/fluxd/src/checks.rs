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

use flux_core::cidr::{Ipv4Cidr, Ipv6Cidr};
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

/// Parses flux.toml with @file names confined to this layout's config directory.
/// The core validates each name before invoking the reader, so join cannot
/// escape the watched directory (§11.2.2, §29.6).
pub(crate) fn parse_flux_config(layout: &Layout, bytes: &[u8]) -> Result<FluxConfig, ConfigError> {
    FluxConfig::parse_with_list_files(bytes, |name| {
        let path = layout.config_dir().join(name);
        read_capped(&path, MAX_CONFIG_BYTES + 1)
            .map_err(|error| format!("{error} ({})", path.display()))
    })
}

/// The full check: everything [`quick_check`] covers plus an unattached BPF
/// load and a real `sing-box check -c` subprocess run against a throwaway
/// effective config. CLI-only; the daemon must use [`quick_check`].
pub fn full_check(layout: &Layout, spec: &EngineSpec) -> CheckReport {
    let (mut report, generated) = quick_check_inner(layout, spec);
    check_bpf(&mut report);
    run_engine_check(spec, generated.as_ref(), &mut report);
    report
}

fn check_bpf(report: &mut CheckReport) {
    let runtime = match crate::bpf::Runtime::load_embedded(crate::BPF_OBJECT) {
        Ok(runtime) => runtime,
        Err(error) => {
            report.errors.push(format!("bpf: {error}"));
            return;
        }
    };
    let mut ring = match runtime.fault_ring() {
        Ok(ring) => ring,
        Err(error) => {
            report.errors.push(format!("bpf: {error}"));
            return;
        }
    };
    match ring.drain_faults() {
        Ok(events) if events.is_empty() => {}
        Ok(events) => report.errors.push(format!(
            "bpf_ringbuf_dirty: newly-created fault ring contained {} records",
            events.len()
        )),
        Err(error) => report.errors.push(format!("bpf_ringbuf_read: {error}")),
    }
    // No map or program is attached or pinned. Dropping these handles removes
    // all objects created by this capability check.
    drop(ring);
    drop(runtime);
}

/// The bounded-time check: `flux.toml`, `packages.list` resolution,
/// `template.json` generation and §9 constraints, clash_api hardening
/// (`docs/spec/interaction.md` §27.2.4), and engine binary presence. No subprocesses.
pub fn quick_check(layout: &Layout, spec: &EngineSpec) -> CheckReport {
    quick_check_inner(layout, spec).0
}

fn quick_check_inner(
    layout: &Layout,
    spec: &EngineSpec,
) -> (CheckReport, Option<serde_json::Value>) {
    let mut report = CheckReport::default();
    let flux = check_flux_toml(layout, &mut report);
    let generated = check_template_json(layout, flux.as_ref(), &mut report);
    if let (Some(flux), Some(generated)) = (flux.as_ref(), generated.as_ref()) {
        if let Err(error) = validate_fakeip_bypass(flux, generated) {
            report.errors.push(error);
        }
    }
    if !spec.binary.exists() {
        report.errors.push(format!(
            "engine_binary_missing: {} does not exist",
            spec.binary.display()
        ));
    }
    (report, generated)
}

fn check_flux_toml(layout: &Layout, report: &mut CheckReport) -> Option<FluxConfig> {
    let path = layout.flux_toml();
    let bytes = match read_capped(&path, MAX_CONFIG_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            report.warnings.push(
                "config/flux.toml missing: no apps selected, nothing will be proxied".to_string(),
            );
            return Some(FluxConfig::default());
        }
        Err(e) => {
            report
                .errors
                .push(format!("flux.toml unreadable: {e} ({})", path.display()));
            return None;
        }
    };
    let config = match parse_flux_config(layout, &bytes) {
        Ok(config) => config,
        Err(e) => {
            report
                .errors
                .push(format!("flux.toml: {}", describe_flux_error(&e)));
            return None;
        }
    };
    if config.apps_mode == flux_core::config::ListMode::Whitelist && config.apps.is_empty() {
        report
            .warnings
            .push("flux.toml selects no apps: nothing will be proxied".to_string());
    }
    check_selectors(&config, report);
    Some(config)
}

/// Resolves the selected apps against `packages.list`. An unknown package makes
/// the candidate invalid (§11.3); shared UIDs remain a warning because the
/// resulting UID is still deterministic.
pub(crate) fn check_selectors(config: &FluxConfig, report: &mut CheckReport) {
    if config.apps_mode == flux_core::config::ListMode::Whitelist && config.apps.is_empty() {
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
    if let Err(error) = config.resolve_selected_uids(&index) {
        report
            .errors
            .push(format!("flux.toml: {}", describe_flux_error(&error)));
        return;
    }
    for selector in &config.apps {
        match index.resolve(selector) {
            Ok(selection) => {
                let shared = index.shared_with(selection.uid % 100_000);
                if shared.len() > 1 {
                    let effect = match config.apps_mode {
                        flux_core::config::ListMode::Whitelist => "proxied together",
                        flux_core::config::ListMode::Blacklist => "excluded together",
                    };
                    report.warnings.push(format!(
                        "{} shares its UID with {}: they are {effect}",
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

fn check_template_json(
    layout: &Layout,
    flux: Option<&FluxConfig>,
    report: &mut CheckReport,
) -> Option<serde_json::Value> {
    let path = layout.template_json();
    let bytes = match read_capped(&path, MAX_ENGINE_CONFIG_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            report.errors.push(format!(
                "engine_config_missing: {} does not exist",
                path.display()
            ));
            return None;
        }
        Err(e) => {
            report.errors.push(format!(
                "template.json unreadable: {e} ({})",
                path.display()
            ));
            return None;
        }
    };
    if bytes.len() > MAX_ENGINE_CONFIG_BYTES {
        report.errors.push(format!(
            "engine_config_too_large: {} exceeds the 8 MiB limit",
            path.display()
        ));
        return None;
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            report
                .errors
                .push("engine_config_invalid: template.json is not UTF-8".to_string());
            return None;
        }
    };
    let user = match engine_config::parse_jsonc(&text) {
        Ok(user) => user,
        Err(e) => {
            report
                .errors
                .push(format!("engine_config_invalid: template.json: {e}"));
            return None;
        }
    };

    let nodes = match flux {
        Some(flux) => match check_subscription_nodes(layout, flux) {
            Ok(Some(nodes)) => nodes,
            Ok(None) => {
                report.warnings.push(
                    "subscription cache is missing: template checks passed, but subscribed nodes will be validated after the initial fetch"
                        .to_string(),
                );
                Vec::new()
            }
            Err(error) => {
                report.errors.push(error);
                return None;
            }
        },
        None => Vec::new(),
    };
    let generated = match engine_config::generate_from_template(&user, &nodes) {
        Ok(generated) => generated,
        Err(error) => {
            report.errors.push(format!(
                "engine_config_invalid: {}",
                engine::describe_config_error(&error)
            ));
            return None;
        }
    };

    // The §9.1/§9.6 structural constraints, via the same builder the daemon
    // uses. Dummy params: the ports only shape the injected inbounds.
    let params = EngineParams {
        generation: 0,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    if let Err(e) = engine_config::build_effective(&generated, &params) {
        report.errors.push(format!(
            "engine_config_invalid: {}",
            engine::describe_config_error(&e)
        ));
        return None;
    }

    if !engine_config::has_dns_hijack_rule(&generated) {
        report.warnings.push(
            "template.json has no DNS hijack rule: selected apps' DNS may leak to the physical network"
                .to_string(),
        );
    }
    report.warnings.extend(sing_box_warnings(&generated));
    Some(generated)
}

fn check_subscription_nodes(
    layout: &Layout,
    flux: &FluxConfig,
) -> Result<Option<Vec<engine_config::RefinedNode>>, String> {
    if flux.subscription.url.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let binding_path = layout.subscription_url_binding();
    let binding = match read_capped(
        &binding_path,
        flux_core::config::MAX_CONFIG_BYTES.saturating_add(1),
    ) {
        Ok(binding) => binding,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "subscription_fetch_failed:cache_read: {}: {error}",
                binding_path.display()
            ));
        }
    };
    if binding.len() > flux_core::config::MAX_CONFIG_BYTES {
        return Err(format!(
            "subscription_fetch_failed:cache_read: {} exceeds the Flux config limit",
            binding_path.display()
        ));
    }
    if binding != flux.subscription.url.as_bytes() {
        return Ok(None);
    }
    let path = layout.subscription_raw();
    let raw = match read_capped(&path, crate::subscription::MAX_SUBSCRIPTION_BYTES + 1) {
        Ok(raw) => raw,
        // A first-use check is read-only and may precede the initial fetch.
        // The daemon will fetch before it creates an enabled generation.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "subscription_fetch_failed:cache_read: {}: {error}",
                path.display()
            ));
        }
    };
    if raw.len() > crate::subscription::MAX_SUBSCRIPTION_BYTES {
        return Err(format!(
            "subscription_fetch_failed:too_large: {} exceeds the {}-byte limit",
            path.display(),
            crate::subscription::MAX_SUBSCRIPTION_BYTES
        ));
    }
    flux_core::subscription::parse_and_refine(&raw, &flux.subscription)
        .map(Some)
        .map_err(|error| {
            use flux_core::subscription::SubscriptionError;
            let token = match &error {
                SubscriptionError::ZeroNodes => "subscription_empty",
                SubscriptionError::InvalidExcludePattern(_)
                | SubscriptionError::InvalidRenamePattern { .. } => "flux_config_invalid",
                _ => "subscription_fetch_failed:invalid_content",
            };
            format!("{token}: {error}")
        })
}

/// Warnings required on both `check` and the normal status surface. These are
/// consequences the user may intentionally accept, so they never invalidate a
/// candidate (§9.6).
pub fn sing_box_warnings(user: &serde_json::Value) -> Vec<String> {
    let mut found_mark = false;
    let mut found_bind = false;
    if let Some(outbounds) = user.get("outbounds") {
        visit_json(outbounds, &mut |object| {
            found_mark |= object.contains_key("routing_mark");
            found_bind |= object.contains_key("bind_interface");
        });
    }
    let mut warnings = Vec::new();
    if found_mark {
        warnings.push(
            "outbound routing_mark is user-controlled: Android may interpret it as a netId/fwmark and reject the route"
                .to_string(),
        );
    }
    if found_bind {
        warnings.push(
            "outbound bind_interface is user-controlled: it may not preserve the selected app's Android network identity"
                .to_string(),
        );
    }
    if let Some(clash) = user
        .get("experimental")
        .and_then(|experimental| experimental.get("clash_api"))
        .and_then(|clash| clash.as_object())
    {
        if clash
            .get("secret")
            .and_then(|secret| secret.as_str())
            .is_none_or(str::is_empty)
        {
            warnings.push(
                "clash_api_secret_missing: clash_api secret is empty: any app on this device can reconfigure the proxy. Set experimental.clash_api.secret in config/template.json."
                    .to_string(),
            );
        }
        if let Some(controller) = clash
            .get("external_controller")
            .and_then(|controller| controller.as_str())
        {
            let host = controller
                .rsplit_once(':')
                .map_or(controller, |(host, _)| host);
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let loopback = host
                .parse::<std::net::IpAddr>()
                .map(|address| address.is_loopback())
                .unwrap_or_else(|_| host.eq_ignore_ascii_case("localhost"));
            if !loopback {
                warnings.push(format!(
                    "clash_api_not_loopback: clash_api listens on {controller}, not loopback: \
                     the control port is reachable from the network. Use 127.0.0.1:<port> \
                     unless that is what you want."
                ));
            }
        }
    }
    warnings
}

/// Cross-file constraint from §9.0. A fakeip address is meaningful only if
/// Flux captures it; placing its range in any fixed or user bypass silently
/// turns every fakeip connection into a failed direct connection.
pub fn validate_fakeip_bypass(flux: &FluxConfig, user: &serde_json::Value) -> Result<(), String> {
    let mut fake_v4 = Vec::new();
    let mut fake_v6 = Vec::new();
    collect_fakeip_ranges(user, &mut fake_v4, &mut fake_v6);
    let (fixed_v4, fixed_v6) = FluxConfig::fixed_bypass();
    let policy_v4 = if flux.cidr_mode == flux_core::config::ListMode::Blacklist {
        flux.bypass_v4.as_slice()
    } else {
        &[]
    };
    let policy_v6 = if flux.cidr_mode == flux_core::config::ListMode::Blacklist {
        flux.bypass_v6.as_slice()
    } else {
        &[]
    };

    for fake in &fake_v4 {
        for bypass in fixed_v4
            .iter()
            .map(|entry| &entry.cidr)
            .chain(policy_v4.iter())
        {
            if overlaps_v4(*fake, *bypass) {
                return Err(format!("fakeip_bypass_overlap:{fake} intersects {bypass}"));
            }
        }
    }
    for fake in &fake_v6 {
        for bypass in fixed_v6
            .iter()
            .map(|entry| &entry.cidr)
            .chain(policy_v6.iter())
        {
            if overlaps_v6(*fake, *bypass) {
                return Err(format!("fakeip_bypass_overlap:{fake} intersects {bypass}"));
            }
        }
    }
    Ok(())
}

fn collect_fakeip_ranges(
    value: &serde_json::Value,
    v4: &mut Vec<Ipv4Cidr>,
    v6: &mut Vec<Ipv6Cidr>,
) {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("type").and_then(|value| value.as_str()) == Some("fakeip") {
                if let Some(range) = object.get("inet4_range").and_then(|value| value.as_str()) {
                    if let Ok(range) = Ipv4Cidr::parse(range) {
                        v4.push(range);
                    }
                }
                if let Some(range) = object.get("inet6_range").and_then(|value| value.as_str()) {
                    if let Ok(range) = Ipv6Cidr::parse(range) {
                        v6.push(range);
                    }
                }
            }
            for child in object.values() {
                collect_fakeip_ranges(child, v4, v6);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_fakeip_ranges(child, v4, v6);
            }
        }
        _ => {}
    }
}

fn visit_json(
    value: &serde_json::Value,
    visitor: &mut impl FnMut(&serde_json::Map<String, serde_json::Value>),
) {
    match value {
        serde_json::Value::Object(object) => {
            visitor(object);
            for child in object.values() {
                visit_json(child, visitor);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                visit_json(child, visitor);
            }
        }
        _ => {}
    }
}

fn overlaps_v4(left: Ipv4Cidr, right: Ipv4Cidr) -> bool {
    let prefix = left.prefix_len.min(right.prefix_len);
    let mask = match prefix {
        0 => 0,
        32 => u32::MAX,
        bits => u32::MAX << (32 - bits),
    };
    u32::from(left.addr) & mask == u32::from(right.addr) & mask
}

fn overlaps_v6(left: Ipv6Cidr, right: Ipv6Cidr) -> bool {
    let prefix = left.prefix_len.min(right.prefix_len);
    let mask = match prefix {
        0 => 0,
        128 => u128::MAX,
        bits => u128::MAX << (128 - bits),
    };
    u128::from(left.addr) & mask == u128::from(right.addr) & mask
}

/// The subprocess half of the full check: builds a real effective config with
/// dummy ports into a throwaway temp file and runs `sing-box check -c` on it,
/// under the engine-check deadline. Skipped when the prior structural checks
/// already failed (running the engine on known-bad input adds noise, not
/// information).
fn run_engine_check(spec: &EngineSpec, user: Option<&serde_json::Value>, report: &mut CheckReport) {
    if !report.errors.is_empty() || !spec.binary.exists() {
        return;
    }
    let Some(user) = user else {
        return;
    };
    let params = EngineParams {
        generation: 0,
        port_v4: flux_core::abi::LISTEN_PORT_MIN,
        port_v6: flux_core::abi::LISTEN_PORT_MIN + 1,
    };
    let Ok(effective) = engine_config::build_effective(user, &params) else {
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
        ConfigError::InvalidValue(detail) => detail.clone(),
        ConfigError::TooManyApps(n) => format!("{n} apps exceed the selection limit"),
        ConfigError::TooManyBypassV4(n) => format!("{n} IPv4 bypass prefixes exceed the limit"),
        ConfigError::TooManyBypassV6(n) => format!("{n} IPv6 bypass prefixes exceed the limit"),
        ConfigError::DuplicateApp(app) => format!("app `{app}` is listed twice"),
        ConfigError::DuplicateBypass(prefix) => format!("CIDR `{prefix}` is listed twice"),
        ConfigError::DuplicateInterface(name) => {
            format!("interface `{name}` is listed twice")
        }
        ConfigError::DuplicateSsid(ssid) => format!("SSID `{ssid}` is listed twice"),
        ConfigError::Selector(e) => describe_selector_error(e),
        ConfigError::Cidr(e) => describe_cidr_error(e),
        ConfigError::InvalidListPath(path) => {
            format!("list reference `@{path}` must name one file inside config/")
        }
        ConfigError::ListFileUnreadable { path, detail } => {
            format!("list file `config/{path}` is unreadable: {detail}")
        }
        ConfigError::ListFileTooLarge { path, size } => {
            format!("list file `config/{path}` is {size} bytes, the limit is {MAX_CONFIG_BYTES}")
        }
        ConfigError::ListFileNotUtf8(path) => {
            format!("list file `config/{path}` is not valid UTF-8")
        }
        ConfigError::RecursiveListReference { path, line } => format!(
            "list file `config/{path}` line {line} starts with @; references cannot recurse"
        ),
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
    fn clash_api_hardening_is_a_warning_not_an_error() {
        let layout = tmp_layout("clash");
        std::fs::write(
            layout.flux_toml(),
            "[apps]\nmode = \"whitelist\"\nlist = []\n",
        )
        .unwrap();
        std::fs::write(
            layout.template_json(),
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
        assert!(report.ok(), "{:?}", report.errors);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.starts_with("clash_api_secret_missing")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.starts_with("clash_api_not_loopback")));
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn loopback_controller_with_secret_passes() {
        let user = serde_json::json!({
            "experimental": { "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": "s3cr3t"
            }}
        });
        assert!(sing_box_warnings(&user).is_empty());
    }

    #[test]
    fn clash_api_controller_warnings_distinguish_loopback_addresses() {
        for controller in ["0.0.0.0:9090", "[::]:9090"] {
            let user = serde_json::json!({
                "experimental": { "clash_api": {
                    "external_controller": controller,
                    "secret": "s3cr3t"
                }}
            });
            let warnings = sing_box_warnings(&user);
            assert!(
                warnings
                    .iter()
                    .any(|warning| warning.starts_with("clash_api_not_loopback")),
                "{controller}: {warnings:?}"
            );
        }

        for controller in ["127.0.0.1:9090", "[::1]:9090", "localhost:9090"] {
            let user = serde_json::json!({
                "experimental": { "clash_api": {
                    "external_controller": controller,
                    "secret": "s3cr3t"
                }}
            });
            let warnings = sing_box_warnings(&user);
            assert!(warnings.is_empty(), "{controller}: {warnings:?}");
        }
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

    #[test]
    fn missing_referenced_list_is_a_check_error() {
        let layout = tmp_layout("missing-list");
        std::fs::write(
            layout.flux_toml(),
            "[apps]\nmode = \"whitelist\"\nlist = [\"@missing.txt\"]\n",
        )
        .unwrap();
        std::fs::write(layout.template_json(), "{\"outbounds\": []}\n").unwrap();
        let engine = layout.root().join("engine");
        std::fs::write(&engine, "#!/bin/sh\nexit 0\n").unwrap();

        let report = quick_check(&layout, &loopback_spec(engine));
        assert!(report
            .errors
            .iter()
            .any(|error| { error.contains("list file `config/missing.txt` is unreadable") }));
        std::fs::remove_dir_all(layout.root()).unwrap();
    }

    #[test]
    fn fakeip_ranges_may_not_overlap_fixed_or_user_bypass() {
        let user = serde_json::json!({
            "dns": { "servers": [{
                "type": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "2001:db8:f::/48"
            }]}
        });
        let flux = FluxConfig::parse(b"[cidr]\nmode = \"blacklist\"\nlist = []").unwrap();
        assert!(validate_fakeip_bypass(&flux, &user).is_ok());

        let overlapping = FluxConfig::parse(
            b"[cidr]\nmode = \"blacklist\"\nlist = [\"198.18.0.0/16\", \"2001:db8:10::/48\"]",
        )
        .unwrap();
        let error = validate_fakeip_bypass(&overlapping, &user).unwrap_err();
        assert!(error.starts_with("fakeip_bypass_overlap:198.18.0.0/15"));

        let ula = serde_json::json!({
            "dns": { "servers": [{
                "type": "fakeip", "inet6_range": "fc00::/18"
            }]}
        });
        let error = validate_fakeip_bypass(&flux, &ula).unwrap_err();
        assert!(error.contains("intersects fc00::/7"));
    }

    #[test]
    fn outbound_mark_and_bind_are_warnings() {
        let user = serde_json::json!({
            "outbounds": [{
                "type": "direct",
                "routing_mark": 123,
                "dialer": { "bind_interface": "rmnet_data0" }
            }]
        });
        let warnings = sing_box_warnings(&user);
        assert_eq!(warnings.len(), 2);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("routing_mark")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("bind_interface")));
    }
}
