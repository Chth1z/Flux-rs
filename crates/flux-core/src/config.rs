//! flux.toml parsing, canonicalisation and hard limits.
//!
//! Implements blueprint §10.2 and §11.2. Every selectable dimension uses the
//! same two modes and one list. Entries beginning with @ are expanded by a
//! caller-supplied reader, keeping this crate free of filesystem access while
//! making the path decision depend on that first character alone (§11.2.2).
//!
//! Unknown keys, non-canonical values, duplicates and capacity overruns reject
//! the whole candidate. Nothing is truncated or partially applied (§11.2.3).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::abi::{LPM_MAX_ENTRIES, UID_SELECTED_MAX};
use crate::cidr::{fixed_bypass, CidrError, Ipv4Bypass, Ipv4Cidr, Ipv6Bypass, Ipv6Cidr};
use crate::selector::{compose_uid, AppSelector, PackageIndex, SelectorError};

/// Largest accepted flux.toml or referenced list file, in bytes (§11.2.3).
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

const TOP_LEVEL_KEYS: &[&str] = &["apps", "cidr", "interfaces", "ssid", "subscription"];
const DIMENSION_KEYS: &[&str] = &["mode", "list"];
const SUBSCRIPTION_KEYS: &[&str] = &[
    "url",
    "interval",
    "timeout",
    "retries",
    "exclude_pattern",
    "rename",
    "strip_emoji",
    "max_tag_length",
];
const RENAME_KEYS: &[&str] = &["match", "replace"];

/// The two directions shared by every list dimension (§11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListMode {
    /// Listed entries participate; everything else does not.
    Whitelist,
    /// Listed entries do not participate; everything else does.
    Blacklist,
}

impl ListMode {
    /// Stable user-facing spelling used by TOML and status output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Whitelist => "whitelist",
            Self::Blacklist => "blacklist",
        }
    }

    /// Whether an entry participates after applying this direction.
    pub const fn includes(self, listed: bool) -> bool {
        match self {
            Self::Whitelist => listed,
            Self::Blacklist => !listed,
        }
    }
}

/// One tag rewrite performed during subscription refinement (§28.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameRule {
    /// Pattern matched against the node tag.
    pub match_pattern: String,
    /// Replacement text.
    pub replace: String,
}

/// Parsed subscription parameters. Fetching is implemented by Batch C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionConfig {
    /// Empty disables subscription completely.
    pub url: String,
    /// Refresh interval in seconds; zero means manual refresh only.
    pub interval: u64,
    /// Per-attempt timeout in seconds.
    pub timeout: u64,
    /// Retry count for one refresh request.
    pub retries: u32,
    /// Pattern used to discard provider announcements.
    pub exclude_pattern: String,
    /// Ordered tag rewrite rules.
    pub rename: Vec<RenameRule>,
    /// Whether emoji are stripped from refined tags.
    pub strip_emoji: bool,
    /// Maximum refined tag length.
    pub max_tag_length: usize,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            interval: 86_400,
            timeout: 10,
            retries: 2,
            exclude_pattern: concat!(
                "(expire|traffic|",
                "\u{5b98}\u{7f51}|\u{5230}\u{671f}|\u{6d41}\u{91cf}|",
                "\u{5269}\u{4f59}|\u{5957}\u{9910}|\u{91cd}\u{7f6e}|",
                "\u{8054}\u{7cfb}|\u{7fa4}\u{7ec4}|\u{901a}\u{77e5}|",
                "\u{5e73}\u{53f0}|\u{7f51}\u{7ad9}|\u{65f6}\u{95f4}|",
                "\u{5efa}\u{8bae}|\u{53cd}\u{9988}|\u{7248}\u{672c}|",
                "\u{66f4}\u{65b0})"
            )
            .to_string(),
            rename: vec![RenameRule {
                match_pattern: "【(亚洲|北美洲|欧洲|南美洲|非洲|大洋洲|南极洲)】".to_string(),
                replace: String::new(),
            }],
            strip_emoji: true,
            max_tag_length: 32,
        }
    }
}

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The main file was larger than MAX_CONFIG_BYTES.
    TooLarge(usize),
    /// The file was not valid UTF-8 or valid TOML.
    Syntax(String),
    /// A key the current schema does not define, with the closest legal key.
    UnknownKey {
        /// The offending key, including its table when nested.
        key: String,
        /// The nearest legal key, offered as a hint.
        closest: Option<String>,
    },
    /// A value had the wrong TOML type.
    WrongType(String),
    /// A value had the right type but is outside the schema.
    InvalidValue(String),
    /// More app UIDs would be selected than the ABI permits.
    TooManyApps(usize),
    /// More IPv4 policy prefixes than the trie holds, including fixed entries.
    TooManyBypassV4(usize),
    /// More IPv6 policy prefixes than the trie holds, including fixed entries.
    TooManyBypassV6(usize),
    /// The same selector appeared twice after canonicalisation.
    DuplicateApp(String),
    /// The same prefix appeared twice after canonicalisation.
    DuplicateBypass(String),
    /// The same interface appeared twice.
    DuplicateInterface(String),
    /// The same SSID appeared twice.
    DuplicateSsid(String),
    /// A selector could not be parsed or resolved.
    Selector(SelectorError),
    /// A CIDR could not be parsed.
    Cidr(CidrError),
    /// An @ reference did not name one direct child of config/.
    InvalidListPath(String),
    /// A referenced list file could not be read.
    ListFileUnreadable {
        /// The direct-child name from the @ entry.
        path: String,
        /// The caller's read failure.
        detail: String,
    },
    /// A referenced list file exceeded MAX_CONFIG_BYTES.
    ListFileTooLarge {
        /// The direct-child name from the @ entry.
        path: String,
        /// Observed byte count.
        size: usize,
    },
    /// A referenced list file was not UTF-8.
    ListFileNotUtf8(String),
    /// A referenced file tried to reference another file.
    RecursiveListReference {
        /// File containing the forbidden entry.
        path: String,
        /// One-based line number.
        line: usize,
    },
}

impl From<SelectorError> for ConfigError {
    fn from(error: SelectorError) -> Self {
        Self::Selector(error)
    }
}

impl From<CidrError> for ConfigError {
    fn from(error: CidrError) -> Self {
        Self::Cidr(error)
    }
}

/// A validated flux.toml.
///
/// Lists are expanded, canonical and de-duplicated. CIDR vectors contain only
/// user policy; fixed safety entries remain separate (§11.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluxConfig {
    /// Direction of the app list.
    pub apps_mode: ListMode,
    /// Canonical app selectors.
    pub apps: Vec<AppSelector>,
    /// Direction of the destination CIDR list.
    pub cidr_mode: ListMode,
    /// User IPv4 policy prefixes, excluding the fixed safety set.
    pub bypass_v4: Vec<Ipv4Cidr>,
    /// User IPv6 policy prefixes, excluding the fixed safety set.
    pub bypass_v6: Vec<Ipv6Cidr>,
    /// Direction of the interface-name list.
    pub interfaces_mode: ListMode,
    /// Exact interface names.
    pub interfaces: Vec<String>,
    /// Direction of the conditional-activation SSID list (§29.1).
    pub ssid_mode: ListMode,
    /// Exact SSIDs compared byte-for-byte by the daemon (§29.1).
    pub ssids: Vec<String>,
    /// Subscription parameters. Batch C consumes them.
    pub subscription: SubscriptionConfig,
}

impl Default for FluxConfig {
    fn default() -> Self {
        Self {
            apps_mode: ListMode::Whitelist,
            apps: Vec::new(),
            cidr_mode: ListMode::Blacklist,
            bypass_v4: Vec::new(),
            bypass_v6: Vec::new(),
            interfaces_mode: ListMode::Blacklist,
            interfaces: Vec::new(),
            ssid_mode: ListMode::Blacklist,
            ssids: Vec::new(),
            subscription: SubscriptionConfig::default(),
        }
    }
}

impl FluxConfig {
    /// Parses a configuration that does not use @file references.
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        Self::parse_with_list_files(bytes, |path| {
            Err(format!("no list-file reader was supplied for '{path}'"))
        })
    }

    /// Parses a configuration and expands every @file through read_file.
    ///
    /// path has already been proven to be one direct child name. Referenced
    /// files cannot recurse and use the same byte limit as flux.toml (§11.2.2).
    pub fn parse_with_list_files(
        bytes: &[u8],
        mut read_file: impl FnMut(&str) -> Result<Vec<u8>, String>,
    ) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge(bytes.len()));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ConfigError::Syntax("configuration is not valid UTF-8".to_string()))?;
        let value: toml::Value =
            toml::from_str(text).map_err(|error| ConfigError::Syntax(error.to_string()))?;
        let table = value
            .as_table()
            .ok_or_else(|| ConfigError::Syntax("top level must be a table".to_string()))?;
        reject_unknown_keys(table, "", TOP_LEVEL_KEYS)?;

        let (apps_mode, raw_apps) = dimension(table, "apps", ListMode::Whitelist, &mut read_file)?;
        let (cidr_mode, raw_cidrs) = dimension(table, "cidr", ListMode::Blacklist, &mut read_file)?;
        let (interfaces_mode, raw_interfaces) =
            dimension(table, "interfaces", ListMode::Blacklist, &mut read_file)?;
        let (ssid_mode, raw_ssids) = dimension(table, "ssid", ListMode::Blacklist, &mut read_file)?;
        let (bypass_v4, bypass_v6) = parse_cidrs(&raw_cidrs)?;

        Ok(Self {
            apps_mode,
            apps: parse_apps(&raw_apps)?,
            cidr_mode,
            bypass_v4,
            bypass_v6,
            interfaces_mode,
            interfaces: parse_interfaces(&raw_interfaces)?,
            ssid_mode,
            ssids: deduplicate_strings(&raw_ssids, true)?,
            subscription: parse_subscription(table)?,
        })
    }

    /// Resolves the app dimension to the concrete UID set installed in the map.
    ///
    /// Blacklist mode selects every third-party app ID for user 0 and for every
    /// explicitly mentioned user, then subtracts listed UIDs (§11.2.3).
    pub fn resolve_selected_uids(
        &self,
        packages: &PackageIndex,
    ) -> Result<BTreeSet<u32>, ConfigError> {
        let listed = self
            .apps
            .iter()
            .map(|selector| packages.resolve(selector).map(|selection| selection.uid))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let selected = match self.apps_mode {
            ListMode::Whitelist => listed,
            ListMode::Blacklist => {
                let mut users = self
                    .apps
                    .iter()
                    .map(|selector| selector.user_id)
                    .collect::<BTreeSet<_>>();
                users.insert(0);
                let mut selected = BTreeSet::new();
                for user_id in users {
                    for app_id in packages.application_ids() {
                        let uid = compose_uid(user_id, app_id)?;
                        if !listed.contains(&uid) {
                            selected.insert(uid);
                        }
                    }
                }
                selected
            }
        };
        if selected.len() > UID_SELECTED_MAX as usize {
            return Err(ConfigError::TooManyApps(selected.len()));
        }
        Ok(selected)
    }

    /// The fixed safe bypass and listener prefixes (blueprint §11.2.3, D21).
    pub fn fixed_bypass() -> (&'static [Ipv4Bypass], &'static [Ipv6Bypass]) {
        fixed_bypass()
    }
}

fn dimension(
    top: &toml::value::Table,
    name: &str,
    default_mode: ListMode,
    read_file: &mut impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<(ListMode, Vec<String>), ConfigError> {
    let Some(value) = top.get(name) else {
        return Ok((default_mode, Vec::new()));
    };
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::WrongType(format!("{name} must be a table")))?;
    reject_unknown_keys(table, name, DIMENSION_KEYS)?;
    let mode = match table.get("mode") {
        None => default_mode,
        Some(toml::Value::String(mode)) if mode == "whitelist" => ListMode::Whitelist,
        Some(toml::Value::String(mode)) if mode == "blacklist" => ListMode::Blacklist,
        Some(toml::Value::String(mode)) => {
            return Err(ConfigError::InvalidValue(format!(
                "{name}.mode '{mode}' must be 'whitelist' or 'blacklist'"
            )))
        }
        Some(_) => {
            return Err(ConfigError::WrongType(format!(
                "{name}.mode must be a string"
            )))
        }
    };
    let raw = match table.get("list") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    ConfigError::WrongType(format!("{name}.list must be an array of strings"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(ConfigError::WrongType(format!(
                "{name}.list must be an array"
            )))
        }
    };
    Ok((mode, expand_list(raw, read_file)?))
}

fn expand_list(
    raw: Vec<String>,
    read_file: &mut impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<String>, ConfigError> {
    let mut expanded = Vec::new();
    for entry in raw {
        let Some(path) = entry.strip_prefix('@') else {
            expanded.push(entry);
            continue;
        };
        validate_list_path(path)?;
        let bytes = read_file(path).map_err(|detail| ConfigError::ListFileUnreadable {
            path: path.to_string(),
            detail,
        })?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::ListFileTooLarge {
                path: path.to_string(),
                size: bytes.len(),
            });
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigError::ListFileNotUtf8(path.to_string()))?;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('@') {
                return Err(ConfigError::RecursiveListReference {
                    path: path.to_string(),
                    line: index + 1,
                });
            }
            expanded.push(line.to_string());
        }
    }
    Ok(expanded)
}

fn validate_list_path(path: &str) -> Result<(), ConfigError> {
    if path.is_empty()
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\\')
        || path.contains('\0')
    {
        return Err(ConfigError::InvalidListPath(path.to_string()));
    }
    Ok(())
}

fn parse_apps(raw: &[String]) -> Result<Vec<AppSelector>, ConfigError> {
    if raw.len() > UID_SELECTED_MAX as usize {
        return Err(ConfigError::TooManyApps(raw.len()));
    }
    let mut apps = Vec::with_capacity(raw.len());
    let mut seen = BTreeSet::new();
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

fn parse_cidrs(raw: &[String]) -> Result<(Vec<Ipv4Cidr>, Vec<Ipv6Cidr>), ConfigError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut seen = BTreeSet::new();
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

fn parse_interfaces(raw: &[String]) -> Result<Vec<String>, ConfigError> {
    for name in raw {
        if name.is_empty() || name.len() >= 16 || name.contains('/') || name.contains('\0') {
            return Err(ConfigError::InvalidValue(format!(
                "interface name '{name}' is not canonical"
            )));
        }
    }
    deduplicate_strings(raw, false)
}

fn deduplicate_strings(raw: &[String], ssid: bool) -> Result<Vec<String>, ConfigError> {
    let mut seen = BTreeSet::new();
    for entry in raw {
        if !seen.insert(entry.clone()) {
            return Err(if ssid {
                ConfigError::DuplicateSsid(entry.clone())
            } else {
                ConfigError::DuplicateInterface(entry.clone())
            });
        }
    }
    Ok(raw.to_vec())
}

fn parse_subscription(top: &toml::value::Table) -> Result<SubscriptionConfig, ConfigError> {
    let Some(value) = top.get("subscription") else {
        return Ok(SubscriptionConfig::default());
    };
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::WrongType("subscription must be a table".to_string()))?;
    reject_unknown_keys(table, "subscription", SUBSCRIPTION_KEYS)?;
    let defaults = SubscriptionConfig::default();
    let timeout = optional_u64(table, "timeout", defaults.timeout, "subscription")?;
    if timeout == 0 {
        return Err(ConfigError::InvalidValue(
            "subscription.timeout must be greater than zero".to_string(),
        ));
    }
    let retries = u32::try_from(optional_u64(
        table,
        "retries",
        u64::from(defaults.retries),
        "subscription",
    )?)
    .map_err(|_| ConfigError::InvalidValue("subscription.retries exceeds u32".to_string()))?;
    let max_tag_length = usize::try_from(optional_u64(
        table,
        "max_tag_length",
        defaults.max_tag_length as u64,
        "subscription",
    )?)
    .map_err(|_| {
        ConfigError::InvalidValue("subscription.max_tag_length exceeds usize".to_string())
    })?;
    if max_tag_length == 0 {
        return Err(ConfigError::InvalidValue(
            "subscription.max_tag_length must be greater than zero".to_string(),
        ));
    }
    let rename = match table.get("rename") {
        None => defaults.rename,
        Some(toml::Value::Array(rules)) => rules
            .iter()
            .enumerate()
            .map(|(index, value)| parse_rename_rule(value, index))
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(ConfigError::WrongType(
                "subscription.rename must be an array of tables".to_string(),
            ))
        }
    };
    Ok(SubscriptionConfig {
        url: optional_string(table, "url", &defaults.url, "subscription")?,
        interval: optional_u64(table, "interval", defaults.interval, "subscription")?,
        timeout,
        retries,
        exclude_pattern: optional_string(
            table,
            "exclude_pattern",
            &defaults.exclude_pattern,
            "subscription",
        )?,
        rename,
        strip_emoji: optional_bool(table, "strip_emoji", defaults.strip_emoji, "subscription")?,
        max_tag_length,
    })
}

fn parse_rename_rule(value: &toml::Value, index: usize) -> Result<RenameRule, ConfigError> {
    let table = value.as_table().ok_or_else(|| {
        ConfigError::WrongType(format!("subscription.rename[{index}] must be a table"))
    })?;
    let prefix = format!("subscription.rename[{index}]");
    reject_unknown_keys(table, &prefix, RENAME_KEYS)?;
    Ok(RenameRule {
        match_pattern: required_string(table, "match", &prefix)?,
        replace: required_string(table, "replace", &prefix)?,
    })
}

fn optional_string(
    table: &toml::value::Table,
    key: &str,
    default: &str,
    prefix: &str,
) -> Result<String, ConfigError> {
    match table.get(key) {
        None => Ok(default.to_string()),
        Some(toml::Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ConfigError::WrongType(format!(
            "{prefix}.{key} must be a string"
        ))),
    }
}

fn required_string(
    table: &toml::value::Table,
    key: &str,
    prefix: &str,
) -> Result<String, ConfigError> {
    match table.get(key) {
        Some(toml::Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ConfigError::WrongType(format!(
            "{prefix}.{key} must be a string"
        ))),
        None => Err(ConfigError::InvalidValue(format!(
            "{prefix}.{key} is required"
        ))),
    }
}

fn optional_u64(
    table: &toml::value::Table,
    key: &str,
    default: u64,
    prefix: &str,
) -> Result<u64, ConfigError> {
    match table.get(key) {
        None => Ok(default),
        Some(toml::Value::Integer(value)) => u64::try_from(*value)
            .map_err(|_| ConfigError::InvalidValue(format!("{prefix}.{key} must be non-negative"))),
        Some(_) => Err(ConfigError::WrongType(format!(
            "{prefix}.{key} must be an integer"
        ))),
    }
}

fn optional_bool(
    table: &toml::value::Table,
    key: &str,
    default: bool,
    prefix: &str,
) -> Result<bool, ConfigError> {
    match table.get(key) {
        None => Ok(default),
        Some(toml::Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(ConfigError::WrongType(format!(
            "{prefix}.{key} must be a boolean"
        ))),
    }
}

fn reject_unknown_keys(
    table: &toml::value::Table,
    prefix: &str,
    known: &[&str],
) -> Result<(), ConfigError> {
    for key in table.keys() {
        if !known.contains(&key.as_str()) {
            return Err(ConfigError::UnknownKey {
                key: if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                },
                closest: closest_key(key, known).map(str::to_string),
            });
        }
    }
    Ok(())
}

fn closest_key<'a>(key: &str, known: &'a [&str]) -> Option<&'a str> {
    known
        .iter()
        .map(|candidate| (levenshtein(key, candidate), *candidate))
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

fn levenshtein(left: &str, right: &str) -> usize {
    let left = left.chars().collect::<Vec<_>>();
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0usize; right.len() + 1];
    for (left_index, left_char) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right.iter().enumerate() {
            let cost = usize::from(left_char != right_char);
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_schema_and_safe_defaults() {
        let source = br#"
[apps]
mode = "whitelist"
list = ["0:com.example.browser"]
[cidr]
mode = "blacklist"
list = ["192.0.2.0/24", "2001:db8:10::/48"]
[interfaces]
mode = "blacklist"
list = ["tun0"]
[ssid]
mode = "whitelist"
list = ["Office"]
[subscription]
url = ""
interval = 0
timeout = 5
retries = 0
exclude_pattern = "announcement"
rename = [{ match = "old", replace = "new" }]
strip_emoji = false
max_tag_length = 48
"#;
        let config = FluxConfig::parse(source).unwrap();
        assert_eq!(config.apps[0].canonical(), "0:com.example.browser");
        assert_eq!(config.bypass_v4[0].to_string(), "192.0.2.0/24");
        assert_eq!(config.bypass_v6[0].to_string(), "2001:db8:10::/48");
        assert_eq!(config.interfaces, ["tun0"]);
        assert_eq!(config.ssid_mode, ListMode::Whitelist);
        assert_eq!(config.subscription.rename[0].replace, "new");
        assert_eq!(FluxConfig::parse(b"").unwrap(), FluxConfig::default());
    }

    #[test]
    fn unknown_keys_have_nearest_hints_and_auto_is_rejected() {
        assert_eq!(
            FluxConfig::parse(b"app = []").unwrap_err(),
            ConfigError::UnknownKey {
                key: "app".to_string(),
                closest: Some("apps".to_string()),
            }
        );
        assert_eq!(
            FluxConfig::parse(b"[apps]\nlsit = []").unwrap_err(),
            ConfigError::UnknownKey {
                key: "apps.lsit".to_string(),
                closest: Some("list".to_string()),
            }
        );
        assert!(matches!(
            FluxConfig::parse(b"[apps]\nmode = \"auto\""),
            Err(ConfigError::InvalidValue(_))
        ));
    }

    #[test]
    fn at_file_expands_without_cidr_guessing() {
        let source = b"[apps]\nlist = [\"@apps.txt\"]\n[cidr]\nlist = [\"@cidrs.txt\"]";
        let config = FluxConfig::parse_with_list_files(source, |path| match path {
            "apps.txt" => Ok(b"# comment\n0:com.example.app\n".to_vec()),
            "cidrs.txt" => Ok(b"203.0.113.0/24\n".to_vec()),
            _ => unreachable!(),
        })
        .unwrap();
        assert_eq!(config.apps[0].canonical(), "0:com.example.app");
        assert_eq!(config.bypass_v4[0].to_string(), "203.0.113.0/24");

        let mut reads = 0;
        let error =
            FluxConfig::parse_with_list_files(b"[cidr]\nlist = [\"203.0.113.1/24\"]", |_| {
                reads += 1;
                Ok(Vec::new())
            })
            .unwrap_err();
        assert_eq!(reads, 0);
        assert!(matches!(
            error,
            ConfigError::Cidr(CidrError::HostBitsSet(_))
        ));
    }

    #[test]
    fn file_references_stay_inside_config_and_do_not_recurse() {
        for path in ["", "../apps.txt", "nested/apps.txt", "nested\\apps.txt"] {
            let source = format!("[apps]\nlist = ['@{path}']");
            assert!(matches!(
                FluxConfig::parse_with_list_files(source.as_bytes(), |_| Ok(Vec::new())),
                Err(ConfigError::InvalidListPath(_))
            ));
        }
        assert!(matches!(
            FluxConfig::parse_with_list_files(b"[apps]\nlist = [\"@apps.txt\"]", |_| {
                Ok(b"@other.txt\n".to_vec())
            }),
            Err(ConfigError::RecursiveListReference { .. })
        ));
        assert!(matches!(
            FluxConfig::parse_with_list_files(b"[apps]\nlist = [\"@missing.txt\"]", |_| {
                Err("not found".to_string())
            }),
            Err(ConfigError::ListFileUnreadable { .. })
        ));
    }

    #[test]
    fn app_blacklist_expands_installed_application_ids() {
        let packages = PackageIndex::parse(
            "com.keep 10231 0 /data/user/0/com.keep default none 0\n\
             com.skip 10232 0 /data/user/0/com.skip default none 0\n\
             android 1000 0 /data/system default none 0\n",
        );
        let config =
            FluxConfig::parse(b"[apps]\nmode = \"blacklist\"\nlist = [\"0:com.skip\"]").unwrap();
        assert_eq!(
            config.resolve_selected_uids(&packages).unwrap(),
            BTreeSet::from([10_231])
        );
    }

    #[test]
    fn duplicate_noncanonical_old_and_oversize_inputs_are_rejected() {
        assert_eq!(
            FluxConfig::parse_with_list_files(
                b"[apps]\nlist = [\"com.x\", \"@apps.txt\"]",
                |_| Ok(b"0:com.x\n".to_vec()),
            ),
            Err(ConfigError::DuplicateApp("0:com.x".to_string()))
        );
        assert!(matches!(
            FluxConfig::parse(b"[cidr]\nlist = [\"10.0.0.1/8\"]"),
            Err(ConfigError::Cidr(CidrError::HostBitsSet(_)))
        ));
        assert!(matches!(
            FluxConfig::parse(b"apps = []"),
            Err(ConfigError::WrongType(_))
        ));
        let big = vec![b' '; MAX_CONFIG_BYTES + 1];
        assert_eq!(
            FluxConfig::parse(&big),
            Err(ConfigError::TooLarge(MAX_CONFIG_BYTES + 1))
        );
    }

    #[test]
    fn shipped_default_uses_the_live_schema() {
        let config = FluxConfig::parse(include_bytes!("../../../module/flux.toml"))
            .expect("shipped default must parse");
        assert_eq!(config, FluxConfig::default());
    }

    /// Over capacity is an error, never a truncation: a silently trimmed list
    /// is a policy the user never wrote and cannot see (§11.2.3).
    #[test]
    fn over_capacity_is_rejected_rather_than_truncated() {
        let apps = (0..=UID_SELECTED_MAX)
            .map(|i| format!("\"0:com.e{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            FluxConfig::parse(format!("[apps]\nlist = [{apps}]").as_bytes()),
            Err(ConfigError::TooManyApps(UID_SELECTED_MAX as usize + 1))
        );

        assert!(matches!(
            FluxConfig::parse_with_list_files(b"[cidr]\nlist = [\"@big.txt\"]", |_| Ok(vec![
                b'\n';
                MAX_CONFIG_BYTES + 1
            ])),
            Err(ConfigError::ListFileTooLarge { .. })
        ));
    }

    /// The fixed prefixes are reachable without being mixed into the user's
    /// list, and they carry RESERVED so inverting the list cannot invert them.
    #[test]
    fn fixed_bypass_is_separate_from_user_entries_and_always_reserved() {
        let config =
            FluxConfig::parse(b"[cidr]\nlist = [\"203.0.113.0/24\"]").expect("user cidr parses");
        let (v4, v6) = FluxConfig::fixed_bypass();

        assert!(!v4.is_empty() && !v6.is_empty());
        assert!(v4.iter().all(|e| e.tag == crate::abi::BypassTag::Reserved));
        assert!(v6.iter().all(|e| e.tag == crate::abi::BypassTag::Reserved));
        assert!(
            !config
                .bypass_v4
                .iter()
                .any(|u| v4.iter().any(|f| f.cidr == *u)),
            "the user list must not absorb the fixed prefixes"
        );
    }
}
