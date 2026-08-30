//! `flux.toml` parsing, canonicalisation and hard limits.
//!
//! Implements blueprint §10.2 and §11.2. The parser is strict: an unknown key
//! is an error, not a warning, so a typo can never silently disable capture
//! (`docs/spec/interaction.md` §27.2.2). Over-limit input is a clear configuration error and is
//! rejected whole — never truncated, never partially applied (§11.2).
//!
//! The schema is the hand-editable flat form defined by blueprint §11.2: an
//! `apps` array of `userId:package` selectors and one mixed-family
//! `bypass_cidrs` array of canonical CIDRs. Interface, subscription and logging
//! keys belong to later phases and are not parsed here (blueprint §17.4
//! forbids pre-building for them).

use crate::abi::{LPM_MAX_ENTRIES, UID_SELECTED_MAX};
use crate::cidr::{fixed_bypass, CidrError, Ipv4Bypass, Ipv4Cidr, Ipv6Bypass, Ipv6Cidr};
use crate::selector::{AppSelector, SelectorError};

/// Largest accepted `flux.toml`, in bytes (blueprint §11.2).
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// The top-level keys the schema defines. Anything else is rejected.
const KNOWN_KEYS: &[&str] = &["apps", "bypass_cidrs"];

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file was larger than [`MAX_CONFIG_BYTES`].
    TooLarge(usize),
    /// The file was not valid UTF-8 or valid TOML.
    Syntax(String),
    /// A key the current schema does not define, with the closest legal key.
    UnknownKey {
        /// The offending key.
        key: String,
        /// The nearest legal key, offered as a hint.
        closest: Option<String>,
    },
    /// A value had the wrong TOML type (e.g. `apps` was not an array).
    WrongType(String),
    /// More app selectors than [`UID_SELECTED_MAX`].
    TooManyApps(usize),
    /// More IPv4 bypass prefixes than the trie holds (including fixed ones).
    TooManyBypassV4(usize),
    /// More IPv6 bypass prefixes than the trie holds (including fixed ones).
    TooManyBypassV6(usize),
    /// The same selector appeared twice after canonicalisation.
    DuplicateApp(String),
    /// The same prefix appeared twice after canonicalisation.
    DuplicateBypass(String),
    /// A selector could not be parsed.
    Selector(SelectorError),
    /// A CIDR could not be parsed.
    Cidr(CidrError),
}

impl From<SelectorError> for ConfigError {
    fn from(e: SelectorError) -> Self {
        ConfigError::Selector(e)
    }
}

impl From<CidrError> for ConfigError {
    fn from(e: CidrError) -> Self {
        ConfigError::Cidr(e)
    }
}

/// A validated `flux.toml`.
///
/// Everything is canonical and de-duplicated. The bypass lists hold only the
/// user's prefixes; the fixed safe set is returned separately by
/// [`FluxConfig::fixed_bypass`] and the device's own addresses are a runtime
/// input, not part of this file (blueprint §11.2, D7/D20).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FluxConfig {
    /// Selected apps, canonical and de-duplicated, at most [`UID_SELECTED_MAX`].
    pub apps: Vec<AppSelector>,
    /// User IPv4 bypass prefixes, excluding the fixed set.
    pub bypass_v4: Vec<Ipv4Cidr>,
    /// User IPv6 bypass prefixes, excluding the fixed set.
    pub bypass_v6: Vec<Ipv6Cidr>,
}

impl FluxConfig {
    /// Parses and validates `flux.toml` from raw bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge(bytes.len()));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ConfigError::Syntax("configuration is not valid UTF-8".to_string()))?;
        let value: toml::Value =
            toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let table = value
            .as_table()
            .ok_or_else(|| ConfigError::Syntax("top level must be a table".to_string()))?;

        for key in table.keys() {
            if !KNOWN_KEYS.contains(&key.as_str()) {
                return Err(ConfigError::UnknownKey {
                    key: key.clone(),
                    closest: closest_key(key),
                });
            }
        }

        let apps = parse_apps(&string_array(table, "apps")?)?;
        let (bypass_v4, bypass_v6) = parse_bypass_cidrs(&string_array(table, "bypass_cidrs")?)?;

        Ok(Self {
            apps,
            bypass_v4,
            bypass_v6,
        })
    }

    /// The fixed safe bypass and listener prefixes (blueprint §11.2, D21).
    pub fn fixed_bypass() -> (&'static [Ipv4Bypass], &'static [Ipv6Bypass]) {
        fixed_bypass()
    }
}

fn string_array(table: &toml::value::Table, key: &str) -> Result<Vec<String>, ConfigError> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().map(str::to_string).ok_or_else(|| {
                    ConfigError::WrongType(format!("{key} must be an array of strings"))
                })
            })
            .collect(),
        Some(_) => Err(ConfigError::WrongType(format!("{key} must be an array"))),
    }
}

fn parse_apps(raw: &[String]) -> Result<Vec<AppSelector>, ConfigError> {
    if raw.len() > UID_SELECTED_MAX as usize {
        return Err(ConfigError::TooManyApps(raw.len()));
    }
    let mut apps = Vec::with_capacity(raw.len());
    let mut seen = std::collections::BTreeSet::new();
    for entry in raw {
        let selector = AppSelector::parse(entry)?;
        let canonical = selector.canonical();
        if !seen.insert(canonical.clone()) {
            return Err(ConfigError::DuplicateApp(canonical));
        }
        apps.push(selector);
    }
    Ok(apps)
}

fn parse_bypass_cidrs(raw: &[String]) -> Result<(Vec<Ipv4Cidr>, Vec<Ipv6Cidr>), ConfigError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in raw {
        let address = entry
            .split_once('/')
            .map_or(entry.as_str(), |(address, _)| address);
        match address.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => {
                let cidr = Ipv4Cidr::parse(entry)?;
                let canonical = cidr.to_string();
                if !seen.insert(canonical.clone()) {
                    return Err(ConfigError::DuplicateBypass(canonical));
                }
                v4.push(cidr);
            }
            Ok(std::net::IpAddr::V6(_)) => {
                let cidr = Ipv6Cidr::parse(entry)?;
                let canonical = cidr.to_string();
                if !seen.insert(canonical.clone()) {
                    return Err(ConfigError::DuplicateBypass(canonical));
                }
                v6.push(cidr);
            }
            Err(_) => return Err(ConfigError::Cidr(CidrError::Malformed(entry.clone()))),
        }
    }

    if v4.len() + crate::cidr::fixed_bypass_v4().len() > LPM_MAX_ENTRIES as usize {
        return Err(ConfigError::TooManyBypassV4(v4.len()));
    }
    if v6.len() + crate::cidr::fixed_bypass_v6().len() > LPM_MAX_ENTRIES as usize {
        return Err(ConfigError::TooManyBypassV6(v6.len()));
    }
    Ok((v4, v6))
}

/// The legal key nearest to `key` by edit distance, for the typo hint that
/// `docs/spec/interaction.md` §27.2.2 requires ("reject unknown keys AND point at the closest
/// legal one"). A silent typo is the worst configuration failure mode, so this
/// is a contract, not a nicety.
fn closest_key(key: &str) -> Option<String> {
    KNOWN_KEYS
        .iter()
        .map(|k| (levenshtein(key, k), *k))
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, k)| k.to_string())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_a_typical_config() {
        let toml = br#"
apps = ["0:com.example.browser", "10:com.example.chat"]
bypass_cidrs = ["192.168.0.0/16", "fd00::/8"]
"#;
        let cfg = FluxConfig::parse(toml).expect("valid");
        assert_eq!(cfg.apps.len(), 2);
        assert_eq!(cfg.apps[0].canonical(), "0:com.example.browser");
        assert_eq!(cfg.apps[1].canonical(), "10:com.example.chat");
        assert_eq!(
            cfg.bypass_v4,
            vec![Ipv4Cidr {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                prefix_len: 16
            }]
        );
        assert_eq!(
            cfg.bypass_v6,
            vec![Ipv6Cidr {
                addr: "fd00::".parse::<Ipv6Addr>().unwrap(),
                prefix_len: 8
            }]
        );
    }

    #[test]
    fn empty_config_is_valid() {
        let cfg = FluxConfig::parse(b"").expect("empty is valid");
        assert_eq!(cfg, FluxConfig::default());
    }

    #[test]
    fn unknown_key_is_rejected_with_a_hint() {
        let err = FluxConfig::parse(b"app = []").unwrap_err();
        match err {
            ConfigError::UnknownKey { key, closest } => {
                assert_eq!(key, "app");
                assert_eq!(closest.as_deref(), Some("apps"));
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_selector_is_rejected() {
        // "com.x" canonicalises to "0:com.x", so this is a duplicate.
        let toml = br#"apps = ["0:com.x", "com.x"]"#;
        assert_eq!(
            FluxConfig::parse(toml),
            Err(ConfigError::DuplicateApp("0:com.x".to_string()))
        );
    }

    #[test]
    fn duplicate_bypass_is_rejected() {
        let toml = br#"bypass_cidrs = ["10.0.0.0/8", "10.0.0.0/8"]"#;
        assert_eq!(
            FluxConfig::parse(toml),
            Err(ConfigError::DuplicateBypass("10.0.0.0/8".to_string()))
        );
    }

    #[test]
    fn non_canonical_cidr_is_rejected() {
        let toml = br#"bypass_cidrs = ["10.0.0.1/8"]"#;
        assert!(matches!(
            FluxConfig::parse(toml),
            Err(ConfigError::Cidr(CidrError::HostBitsSet(_)))
        ));
    }

    #[test]
    fn too_many_apps_is_rejected() {
        let mut entries = String::from("apps = [");
        for i in 0..(UID_SELECTED_MAX as usize + 1) {
            entries.push_str(&format!("\"0:com.app{i}\","));
        }
        entries.push(']');
        assert_eq!(
            FluxConfig::parse(entries.as_bytes()),
            Err(ConfigError::TooManyApps(UID_SELECTED_MAX as usize + 1))
        );
    }

    #[test]
    fn oversize_file_is_rejected_before_parsing() {
        let big = vec![b' '; MAX_CONFIG_BYTES + 1];
        assert_eq!(
            FluxConfig::parse(&big),
            Err(ConfigError::TooLarge(MAX_CONFIG_BYTES + 1))
        );
    }

    #[test]
    fn wrong_type_is_rejected() {
        assert!(matches!(
            FluxConfig::parse(b"apps = 3"),
            Err(ConfigError::WrongType(_))
        ));
    }

    #[test]
    fn fixed_bypass_is_available_and_separate_from_user_entries() {
        let (v4, v6) = FluxConfig::fixed_bypass();
        assert!(!v4.is_empty() && !v6.is_empty());
        // The parsed config never carries the fixed set implicitly.
        let cfg = FluxConfig::parse(b"bypass_cidrs = []").unwrap();
        assert!(cfg.bypass_v4.is_empty());
    }

    #[test]
    fn split_public_bypass_keys_are_rejected() {
        let err = FluxConfig::parse(b"bypass_v4 = []").unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnknownKey {
                key: "bypass_v4".to_string(),
                closest: Some("bypass_cidrs".to_string()),
            }
        );
    }

    #[test]
    fn shipped_default_flux_toml_uses_the_live_schema() {
        let template = include_bytes!("../../../module/flux.toml");
        let config = FluxConfig::parse(template).expect("shipped default must parse");
        assert_eq!(config, FluxConfig::default());
    }
}
