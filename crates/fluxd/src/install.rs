//! One-shot installation with the daemon stopped (blueprint §13.2.3).

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use flux_core::config::{FluxConfig, MAX_CONFIG_BYTES};
use flux_core::control_wire::Request;
use flux_core::engine_config::{parse_jsonc, MAX_ENGINE_CONFIG_BYTES};
use flux_core::subscription::assemble_nodes;

use crate::layout::{read_capped, write_private_replace, InstanceLock, Layout, LockError};
use crate::subscription::MAX_SUBSCRIPTION_BYTES;

/// Stops this runtime's daemon, holds its lock and installs configuration.
/// No engine execution, network access, or changes to the manager toggle occur.
/// `legacy_app_default` is true only for a positively identified installation
/// of the previous Rust module id, preserving its implicit whitelist default.
pub fn run(layout: &Layout, defaults: &Path, legacy_app_default: bool) -> Result<(), String> {
    layout.ensure().map_err(|error| error.to_string())?;
    let _lock = stop_and_lock(layout)?;
    install_locked(layout, defaults, legacy_app_default)
}

fn stop_and_lock(layout: &Layout) -> Result<InstanceLock, String> {
    match InstanceLock::acquire(layout) {
        Ok(lock) => return Ok(lock),
        Err(LockError::Io(error)) => return Err(format!("installation lock: {error}")),
        Err(LockError::Held(_)) => {}
    }
    let response = crate::control::request(
        &layout.control_socket(),
        &Request::Stop,
        Duration::from_secs(5),
    );
    // A daemon can exit between observing its lock and contacting its socket.
    // Acquiring the same lock is the authority in both cases.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match InstanceLock::acquire(layout) {
            Ok(lock) => return Ok(lock),
            Err(LockError::Io(error)) => return Err(format!("installation lock: {error}")),
            Err(LockError::Held(_)) => {}
        }
        if response.as_ref().is_ok_and(|reply| !reply.ok) {
            return Err("daemon refused the installation stop request".into());
        }
        if Instant::now() >= deadline {
            return Err("daemon still holds its lock after installation stop request; no configuration was changed".into());
        }
        // Deadline-bounded shutdown wait, not a runtime polling mechanism.
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn optional(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
        Ok(metadata) if !metadata.is_file() => {
            return Err(format!("{}: expected a regular file", path.display()));
        }
        Ok(_) => {}
    }
    let bytes =
        read_capped(path, cap + 1).map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > cap {
        return Err(format!("{}: exceeds {cap} bytes", path.display()));
    }
    Ok(Some(bytes))
}

fn required_default(defaults: &Path, name: &str) -> Result<Vec<u8>, String> {
    let cap = if name == "default-template.json" {
        MAX_ENGINE_CONFIG_BYTES
    } else {
        MAX_CONFIG_BYTES
    };
    optional(&defaults.join(name), cap)?
        .ok_or_else(|| format!("missing installation default: {name}"))
}

fn install_locked(
    layout: &Layout,
    defaults: &Path,
    legacy_app_default: bool,
) -> Result<(), String> {
    let old_main = optional(&layout.flux_toml(), MAX_CONFIG_BYTES)?;
    let old_advanced = optional(&layout.advanced_toml(), MAX_CONFIG_BYTES)?;
    let old_template = optional(&layout.template_json(), MAX_ENGINE_CONFIG_BYTES)?;
    let input_advanced = if old_main.is_none() && old_template.is_none() && old_advanced.is_none() {
        Some(required_default(defaults, "default-advanced.toml")?)
    } else {
        old_advanced.clone()
    };
    let main = match &old_main {
        Some(bytes) => bytes.clone(),
        None => required_default(defaults, "default-flux.toml")?,
    };
    let template = match &old_template {
        Some(bytes) => bytes.clone(),
        None => required_default(defaults, "default-template.json")?,
    };
    let prepared = flux_core::migration::prepare(
        &main,
        input_advanced.as_deref(),
        legacy_app_default && old_main.is_some(),
    )
    .map_err(|error| error.to_string())?;
    let (main, advanced) = prepared
        .map(|prepared| (prepared.main, prepared.advanced))
        .unwrap_or((main, input_advanced));
    let config =
        crate::configuration::parse(layout, &main, advanced.as_deref()).map_err(|error| {
            format!(
                "installation candidate: {}",
                crate::configuration::describe_flux_error(&error)
            )
        })?;

    // The complete TOML candidate is valid before any user-owned file changes.
    // Back up every changed input before publishing either document. Existing
    // original backups survive an interrupted advanced-first publication.
    for (name, before, after) in [
        ("flux.toml", old_main.as_deref(), Some(main.as_slice())),
        (
            "advanced.toml",
            old_advanced.as_deref(),
            advanced.as_deref(),
        ),
    ] {
        if before != after {
            if let Some(bytes) = before {
                backup_once(layout, name, bytes)?;
            }
        }
    }
    if advanced != old_advanced {
        if let Some(bytes) = &advanced {
            write_private_replace(&layout.advanced_toml(), bytes)
                .map_err(|error| format!("publish advanced.toml: {error}"))?;
        }
    }
    if old_main.as_deref() != Some(main.as_slice()) {
        write_private_replace(&layout.flux_toml(), &main)
            .map_err(|error| format!("publish flux.toml: {error}"))?;
    }
    if old_template.is_none() {
        write_private_replace(&layout.template_json(), &template)
            .map_err(|error| format!("install template.json: {error}"))?;
    }
    adopt_runtime_files(layout, &config, &template);
    Ok(())
}

fn backup_once(layout: &Layout, name: &str, bytes: &[u8]) -> Result<(), String> {
    let directory = layout.run_dir().join("migrations");
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create migration backups: {error}")),
    }
    let metadata =
        fs::symlink_metadata(&directory).map_err(|error| format!("migration backups: {error}"))?;
    // SAFETY: geteuid has no preconditions.
    let own_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != own_uid {
        return Err("migration backup path is not an owned directory".into());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("migration backup permissions: {error}"))?;
    let destination = directory.join(format!("{name}.original"));
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_file() && metadata.uid() == own_uid => return Ok(()),
        Ok(_) => {
            return Err(format!(
                "migration backup {name} is not an owned regular file"
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("migration backup {name}: {error}")),
    }
    write_private_replace(&destination, bytes)
        .map_err(|error| format!("migration backup {name}: {error}"))
}

fn move_if_absent(old: &Path, new: &Path) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    let own_uid = unsafe { libc::geteuid() };
    match fs::symlink_metadata(old) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(meta) if !meta.is_file() || meta.uid() != own_uid => {
            // Exact path and current ownership are required before moving it.
            return Err("legacy path is not an owned regular file".into());
        }
        Ok(_) => {}
    }
    match fs::symlink_metadata(new) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    fs::rename(old, new).map_err(|error| error.to_string())?;
    fs::set_permissions(new, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    for parent in [old.parent(), new.parent()].into_iter().flatten() {
        fs::File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn uses_default_engine_cache(template: &[u8]) -> bool {
    let Some(cache) = std::str::from_utf8(template)
        .ok()
        .and_then(|text| parse_jsonc(text).ok())
        .and_then(|value| value.pointer("/experimental/cache_file").cloned())
    else {
        return false;
    };
    cache.get("enabled").and_then(|v| v.as_bool()) == Some(true)
        && match cache.get("path") {
            None => true,
            Some(value) => value.as_str() == Some(""),
        }
}

fn adopt_runtime_files(layout: &Layout, config: &FluxConfig, template: &[u8]) {
    for name in ["fluxd.log", "fluxd.log.1"] {
        if let Err(error) = move_if_absent(&layout.root().join(name), &layout.run_dir().join(name))
        {
            eprintln!("fluxd install: retained legacy {name}: {error}");
        }
    }
    if uses_default_engine_cache(template) {
        if let Err(error) = move_if_absent(&layout.root().join("cache.db"), &layout.engine_cache())
        {
            eprintln!("fluxd install: retained legacy engine cache: {error}");
        }
    }
    if let Err(error) = adopt_subscription(layout, config) {
        eprintln!("fluxd install: retained legacy subscription cache: {error}");
    }
}

fn adopt_subscription(layout: &Layout, config: &FluxConfig) -> Result<(), String> {
    let url_path = layout.run_dir().join("subscription.url");
    let raw_path = layout.run_dir().join("subscription.raw");
    let Some(url) = optional(&url_path, MAX_CONFIG_BYTES)? else {
        return Ok(());
    };
    let Some(source) = config
        .nodes
        .remote_sources()
        .find(|source| source.url().as_bytes() == url)
    else {
        return Err("URL does not exactly match a configured source".into());
    };
    let Some(raw) = optional(&raw_path, MAX_SUBSCRIPTION_BYTES)? else {
        return Ok(());
    };
    // Validate provider cleanup and collisions with manual nodes without ever
    // starting an engine. Do not print parser details that may include secrets.
    assemble_nodes(&config.nodes, |candidate| {
        (candidate == source).then_some(raw.as_slice())
    })
    .map_err(|_| "response is incompatible with current node policy".to_string())?;
    layout
        .ensure_source_cache()
        .map_err(|error| error.to_string())?;
    let target = layout.source_cache(source);
    if let Some(existing) = optional(&target, MAX_SUBSCRIPTION_BYTES)? {
        if existing != raw {
            return Err("a different source cache already exists".into());
        }
    } else {
        write_private_replace(&target, &raw).map_err(|error| error.to_string())?;
    }
    fs::remove_file(&raw_path).map_err(|error| error.to_string())?;
    fs::remove_file(&url_path).map_err(|error| error.to_string())?;
    fs::File::open(layout.run_dir())
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        base: PathBuf,
        layout: Layout,
        defaults: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "flux-install-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            let defaults = base.join("defaults");
            fs::create_dir(&defaults).unwrap();
            fs::write(
                defaults.join("default-flux.toml"),
                b"[apps]\nmode = 'blacklist'\n[nodes]\nsources = []\n",
            )
            .unwrap();
            fs::write(
                defaults.join("default-advanced.toml"),
                b"# advanced defaults\n",
            )
            .unwrap();
            fs::write(
                defaults.join("default-template.json"),
                b"{ /* bootstrap */ }\n",
            )
            .unwrap();
            let layout = Layout::at(base.join("runtime"));
            layout.ensure().unwrap();
            Self {
                base,
                layout,
                defaults,
            }
        }
        fn install(&self) -> Result<(), String> {
            run(&self.layout, &self.defaults, false)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn fresh_installs_reference_advanced_and_exact_template() {
        let f = Fixture::new();
        f.install().unwrap();
        assert_eq!(
            fs::read(f.layout.advanced_toml()).unwrap(),
            b"# advanced defaults\n"
        );
        assert_eq!(
            fs::read(f.layout.template_json()).unwrap(),
            b"{ /* bootstrap */ }\n"
        );
        assert!(!f.layout.run_dir().join("migrations").exists());
    }

    #[test]
    fn current_upgrade_preserves_bytes_and_absent_advanced() {
        let f = Fixture::new();
        let main = b"# user formatting\n[apps]\nmode=\"blacklist\"\n[nodes]\nsources=[]\n";
        let template = b"// user bytes\n{}\n";
        fs::write(f.layout.flux_toml(), main).unwrap();
        fs::write(f.layout.template_json(), template).unwrap();
        f.install().unwrap();
        assert_eq!(fs::read(f.layout.flux_toml()).unwrap(), main);
        assert_eq!(fs::read(f.layout.template_json()).unwrap(), template);
        assert!(!f.layout.advanced_toml().exists());
        assert!(!f.layout.run_dir().join("migrations").exists());
    }

    #[test]
    fn migration_preserves_old_mode_template_and_original_backups_on_retry() {
        let f = Fixture::new();
        let main = b"# old config\n[nodes]\nlist=[]\n[subscription]\ninterval=0\n";
        let advanced = b"# user's log policy\n[log]\nretain=3\n";
        let template = b"{\"untouched\": true}\n";
        fs::write(f.layout.flux_toml(), main).unwrap();
        fs::write(f.layout.advanced_toml(), advanced).unwrap();
        fs::write(f.layout.template_json(), template).unwrap();
        f.install().unwrap();
        let parsed = crate::configuration::load(&f.layout).unwrap();
        assert_eq!(parsed.apps_mode, flux_core::config::ListMode::Whitelist);
        assert_eq!(parsed.nodes.fetch.interval, 0);
        let backup = f.layout.run_dir().join("migrations");
        assert_eq!(fs::read(backup.join("flux.toml.original")).unwrap(), main);
        assert_eq!(
            fs::read(backup.join("advanced.toml.original")).unwrap(),
            advanced
        );
        let complete = fs::read(f.layout.flux_toml()).unwrap();
        // Simulate advanced publication succeeding before main publication.
        fs::write(f.layout.flux_toml(), main).unwrap();
        f.install().unwrap();
        assert_eq!(fs::read(f.layout.flux_toml()).unwrap(), complete);
        assert_eq!(
            fs::read(backup.join("advanced.toml.original")).unwrap(),
            advanced
        );
        assert_eq!(fs::read(f.layout.template_json()).unwrap(), template);
        f.install().unwrap();
        assert_eq!(fs::read(backup.join("flux.toml.original")).unwrap(), main);
    }

    #[test]
    fn conflicts_and_invalid_candidates_leave_all_user_files_intact() {
        let f = Fixture::new();
        let main = b"[subscription]\ninterval=10\n";
        let advanced = b"[nodes.fetch]\ninterval=20\n";
        fs::write(f.layout.flux_toml(), main).unwrap();
        fs::write(f.layout.advanced_toml(), advanced).unwrap();
        assert!(f.install().unwrap_err().contains("nodes.fetch.interval"));
        assert_eq!(fs::read(f.layout.flux_toml()).unwrap(), main);
        assert_eq!(fs::read(f.layout.advanced_toml()).unwrap(), advanced);
        assert!(!f.layout.template_json().exists());
        assert!(!f.layout.run_dir().join("migrations").exists());
        fs::write(f.layout.flux_toml(), b"[subscription]\ntimeout=0\n").unwrap();
        assert!(f.install().is_err());
        assert_eq!(fs::read(f.layout.advanced_toml()).unwrap(), advanced);
        assert!(!f.layout.run_dir().join("migrations").exists());
    }

    #[test]
    fn cache_adoption_requires_exact_source_and_valid_response() {
        let f = Fixture::new();
        let main = b"[nodes]\nsources=['https://example.invalid/sub']\n";
        fs::write(f.layout.flux_toml(), main).unwrap();
        let url = f.layout.run_dir().join("subscription.url");
        let raw = f.layout.run_dir().join("subscription.raw");
        fs::write(&url, b"https://example.invalid/sub\n").unwrap();
        fs::write(&raw, b"invalid").unwrap();
        let config = crate::configuration::load(&f.layout).unwrap();
        assert!(adopt_subscription(&f.layout, &config).is_err());
        fs::write(&url, b"https://example.invalid/sub").unwrap();
        assert!(adopt_subscription(&f.layout, &config).is_err());
        let bytes = br#"{"outbounds":[{"type":"trojan","tag":"node","server":"example.invalid","server_port":443,"password":"placeholder"}]}"#;
        fs::write(&raw, bytes).unwrap();
        adopt_subscription(&f.layout, &config).unwrap();
        let source = config.nodes.remote_sources().next().unwrap();
        assert_eq!(fs::read(f.layout.source_cache(source)).unwrap(), bytes);
        assert!(!raw.exists() && !url.exists());
    }

    #[test]
    fn explicit_engine_cache_path_and_existing_destination_are_preserved() {
        assert!(uses_default_engine_cache(
            br#"{"experimental":{"cache_file":{"enabled":true}}}"#
        ));
        assert!(!uses_default_engine_cache(
            br#"{"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}"#
        ));
        let f = Fixture::new();
        let old = f.layout.root().join("fluxd.log");
        fs::write(&old, b"old").unwrap();
        fs::write(f.layout.log_file(), b"new").unwrap();
        move_if_absent(&old, &f.layout.log_file()).unwrap();
        assert_eq!(fs::read(&old).unwrap(), b"old");
        assert_eq!(fs::read(f.layout.log_file()).unwrap(), b"new");
    }

    #[test]
    fn held_lock_stop_refusal_leaves_configuration_and_socket_intact() {
        use flux_core::control_wire::{
            Counters, EngineStatus, PolicyCounts, Response, RootManagerStatus, State,
        };
        let f = Fixture::new();
        let main = b"[nodes]\nlist=[]\n";
        fs::write(f.layout.flux_toml(), main).unwrap();
        let _held = InstanceLock::acquire(&f.layout).unwrap();
        let server = crate::control::ControlServer::bind(&f.layout.control_socket()).unwrap();
        let root = f.layout.root().to_path_buf();
        let defaults = f.defaults.clone();
        let installer = std::thread::spawn(move || run(&Layout::at(root), &defaults, false));
        let deadline = Instant::now() + Duration::from_secs(5);
        let connection = loop {
            if let Some(connection) = server.accept().unwrap() {
                break connection;
            }
            assert!(
                Instant::now() < deadline,
                "installer did not contact its control socket"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(connection.recv_request().unwrap(), Request::Stop);
        connection
            .send_response(&Response {
                ok: false,
                version: flux_core::VERSION.into(),
                abi_magic: String::new(),
                state: State::Inactive,
                generation: 0,
                backoff_seconds: 0,
                root_manager: RootManagerStatus::default(),
                engine: EngineStatus {
                    running: false,
                    pid: None,
                    sockets_verified: 0,
                    effective_config: None,
                },
                policy: PolicyCounts::default(),
                ssid: None,
                ifaces: vec![],
                counters: Counters::default(),
                sysctl: Default::default(),
                warnings: vec![],
                hints: vec![],
                last_error: Some("stop_refused".into()),
            })
            .unwrap();
        assert!(installer.join().unwrap().unwrap_err().contains("refused"));
        assert_eq!(fs::read(f.layout.flux_toml()).unwrap(), main);
        assert!(!f.layout.advanced_toml().exists());
        assert!(!f.layout.template_json().exists());
        assert!(!f.layout.run_dir().join("migrations").exists());
        assert!(f.layout.control_socket().exists());
        assert!(f.layout.lock_path().exists());
    }
}
