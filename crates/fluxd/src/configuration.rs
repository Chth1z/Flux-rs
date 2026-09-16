//! Configuration I/O shared by activation, refresh, diagnostics and installation.
//! Pure parsing stays in flux-core; this boundary owns paths and bounded reads.

use crate::layout::{read_capped, Layout};
use flux_core::config::{ConfigError, FluxConfig, MAX_CONFIG_BYTES};
use flux_core::selector::SelectorError;
use std::io;

pub fn load(layout: &Layout) -> Result<FluxConfig, (String, Option<String>)> {
    let main = read_capped(&layout.flux_toml(), MAX_CONFIG_BYTES + 1).map_err(|error| {
        (
            "flux_config_unreadable".into(),
            Some(format!("flux.toml: {error}")),
        )
    })?;
    let advanced = match read_capped(&layout.advanced_toml(), MAX_CONFIG_BYTES + 1) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err((
                "flux_config_unreadable".into(),
                Some(format!("advanced.toml: {error}")),
            ))
        }
    };
    parse(layout, &main, advanced.as_deref()).map_err(|error| {
        (
            "flux_config_invalid".into(),
            Some(describe_flux_error(&error)),
        )
    })
}

pub fn parse(
    layout: &Layout,
    main: &[u8],
    advanced: Option<&[u8]>,
) -> Result<FluxConfig, ConfigError> {
    FluxConfig::parse_files(main, advanced, |name| {
        read_capped(&layout.config_dir().join(name), MAX_CONFIG_BYTES + 1)
            .map_err(|error| error.to_string())
    })
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
        ConfigError::DuplicateSsid(_) => "an SSID entry is listed twice".to_string(),
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

pub(crate) fn describe_selector_error(e: &SelectorError) -> String {
    match e {
        SelectorError::Malformed(text) => {
            format!("selector `{text}` is not `packageName` or `userId:packageName`")
        }
        SelectorError::UserIdOutOfRange(id) => {
            format!("user id {id} is above {}", flux_core::abi::USER_ID_MAX)
        }
        SelectorError::AppIdOutOfRange(0) => "it runs as root, the same user the proxy engine \
             runs as; capturing it would feed the engine's own traffic back into itself, so no \
             spelling of this entry can work"
            .to_string(),
        SelectorError::AppIdOutOfRange(id) => {
            format!("uid {id} does not fit one Android user's range")
        }
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
