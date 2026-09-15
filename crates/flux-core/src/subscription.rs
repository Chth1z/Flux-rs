//! Pure subscription parsing and node refinement (blueprint §28.3-§28.4).
//!
//! Network access and cache ownership stay in `fluxd`. This module accepts the
//! bytes already fetched from a provider, converts either supported input
//! representation into official sing-box outbound objects, and applies the
//! fixed refinement pipeline without performing I/O.

use std::fmt;

use base64::{
    engine::general_purpose::{
        STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD,
        URL_SAFE as BASE64_URL_SAFE, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
    },
    Engine as _,
};
use regex_lite::{Regex, RegexBuilder};
use serde_json::{Map, Number, Value};
use url::{form_urlencoded, Host, Url};

use crate::config::{FluxConfig, RefinementConfig};
use crate::engine_config::RefinedNode;

const INFRASTRUCTURE_TYPES: &[&str] = &["selector", "urltest", "direct", "block", "dns"];

// Keep the order and expressions aligned with Flux-original's
// scripts/updater.sh UPDATER_COUNTRY_MAP. A tag may intentionally belong to
// more than one group.
const COUNTRY_PATTERNS: &[(&str, &str)] = &[
    ("HK", "香港|港|hk|hongkong|hong kong"),
    ("TW", "台湾|台|tw|taiwan"),
    ("JP", "日本|日|jp|japan"),
    ("SG", "新加坡|新|sg|singapore"),
    ("US", "美国|美|us|usa|united states|america"),
    ("KR", "韩国|韩|kr|korea|south korea"),
    ("UK", "英国|英|uk|gb|united kingdom|britain"),
    ("DE", "德国|德|de|germany"),
    ("FR", "法国|法|fr|france"),
    ("CA", "加拿大|加|ca|canada"),
    ("AU", "澳大利亚|澳洲|澳|au|australia"),
    ("RU", "俄罗斯|俄|ru|russia"),
    ("NL", "荷兰|荷|nl|netherlands"),
    ("IN", "印度|印|in|india"),
    ("TR", "土耳其|土|tr|turkey|turkiye"),
    ("IT", "意大利|意|it|italy"),
    ("CH", "瑞士|ch|switzerland"),
    ("SE", "瑞典|se|sweden"),
    ("BR", "巴西|br|brazil"),
    ("AR", "阿根廷|ar|argentina"),
    ("VN", "越南|vn|vietnam"),
    ("TH", "泰国|th|thailand"),
    ("PH", "菲律宾|菲|ph|philippines"),
    ("MY", "马来西亚|马来|my|malaysia"),
    ("ID", "印尼|印度尼西亚|id|indonesia"),
    ("ES", "西班牙|西|es|spain"),
    ("PL", "波兰|pl|poland"),
    ("FI", "芬兰|fi|finland"),
    ("NO", "挪威|no|norway"),
    ("DK", "丹麦|dk|denmark"),
];

/// Why subscription bytes could not become a non-empty refined node set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    /// A JSON-looking response was not syntactically valid JSON.
    JsonSyntax(String),
    /// A JSON response was not a top-level object.
    JsonNotObject,
    /// A JSON response did not contain `outbounds`.
    JsonOutboundsMissing,
    /// The JSON `outbounds` member was not an array.
    JsonOutboundsNotArray,
    /// A non-JSON response was not supported base64.
    InvalidBase64(String),
    /// A decoded URI list was not UTF-8.
    DecodedListNotUtf8,
    /// One non-empty, non-comment URI line was invalid.
    InvalidUri {
        /// One-based decoded-list line number.
        line: usize,
        /// Protocol-specific reason for rejection.
        reason: String,
    },
    /// `exclude_pattern` was not a valid regex-lite expression.
    InvalidExcludePattern(String),
    /// One configured rename expression was invalid.
    InvalidRenamePattern {
        /// Zero-based index in `subscription.rename`.
        index: usize,
        /// regex-lite compiler diagnostic.
        reason: String,
    },
    /// One sing-box JSON outbound could not enter the fixed refinement
    /// pipeline without silently changing the provider's node set.
    InvalidOutbound {
        /// Zero-based index in the provider's `.outbounds` array.
        index: usize,
        /// Shape error safe to expose in diagnostics.
        reason: String,
    },
    /// Refinement discarded every usable proxy node.
    ZeroNodes,
}

impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonSyntax(reason) => write!(f, "subscription JSON is invalid: {reason}"),
            Self::JsonNotObject => write!(f, "subscription JSON must be a top-level object"),
            Self::JsonOutboundsMissing => {
                write!(f, "subscription JSON has no outbounds member")
            }
            Self::JsonOutboundsNotArray => {
                write!(f, "subscription JSON outbounds member is not an array")
            }
            Self::InvalidBase64(reason) => {
                write!(
                    f,
                    "subscription response is neither sing-box JSON nor base64: {reason}"
                )
            }
            Self::DecodedListNotUtf8 => write!(f, "decoded subscription list is not UTF-8"),
            Self::InvalidUri { line, reason } => {
                write!(f, "invalid subscription URI on line {line}: {reason}")
            }
            Self::InvalidExcludePattern(reason) => {
                write!(f, "invalid subscription exclude_pattern: {reason}")
            }
            Self::InvalidRenamePattern { index, reason } => {
                write!(f, "invalid subscription rename[{index}] pattern: {reason}")
            }
            Self::InvalidOutbound { index, reason } => {
                write!(f, "invalid subscription outbound[{index}]: {reason}")
            }
            Self::ZeroNodes => write!(f, "subscription produced zero proxy nodes"),
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// Parses provider bytes and runs all seven refinement steps.
///
/// This is the integration seam used by `fluxd`: its output can be passed
/// directly to [`crate::engine_config::generate_from_template`].
pub fn parse_and_refine(
    response: &[u8],
    config: &RefinementConfig,
) -> Result<Vec<RefinedNode>, SubscriptionError> {
    refine_nodes(parse_subscription(response)?, config)
}

/// Builds the available input pool: explicit nodes first, then one accepted
/// provider snapshot. Missing remote input never hides a usable manual node.
pub fn assemble_nodes(
    config: &FluxConfig,
    response: Option<&[u8]>,
) -> Result<Vec<RefinedNode>, SubscriptionError> {
    let mut nodes = config.nodes.clone();
    if let Some(response) = response {
        nodes.extend(parse_and_refine(response, &config.subscription.refine)?);
    }
    Ok(nodes)
}

/// Parses one explicit sharing URI, retaining its name and protocol settings.
/// Errors describe the field without reproducing credentials or the URI.
pub fn parse_manual_node(uri: &str) -> Result<RefinedNode, String> {
    let outbound = parse_uri(uri)?;
    let tag = outbound["tag"]
        .as_str()
        .expect("URI parser always supplies a tag");
    let groups = compile_regions()
        .iter()
        .filter(|(_, pattern)| pattern.is_match(tag))
        .map(|(group, _)| (*group).to_string())
        .collect();
    Ok(RefinedNode { outbound, groups })
}

/// Detects the provider format by content and returns unrefined outbounds.
///
/// Valid sing-box JSON contributes its `.outbounds` array. Any other content
/// must be a standard- or URL-safe-base64 encoded URI list.
pub fn parse_subscription(response: &[u8]) -> Result<Vec<Value>, SubscriptionError> {
    let response = strip_utf8_bom(response);
    match serde_json::from_slice::<Value>(response) {
        Ok(value) => return json_outbounds(value),
        Err(error) if looks_like_json(response) => {
            return Err(SubscriptionError::JsonSyntax(error.to_string()));
        }
        Err(_) => {}
    }

    let decoded = decode_base64(response).map_err(SubscriptionError::InvalidBase64)?;
    let decoded = strip_utf8_bom(&decoded);
    let list = std::str::from_utf8(decoded).map_err(|_| SubscriptionError::DecodedListNotUtf8)?;
    let mut outbounds = Vec::new();
    for (index, raw_line) in list.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let outbound = parse_uri(line).map_err(|reason| SubscriptionError::InvalidUri {
            line: index + 1,
            reason,
        })?;
        outbounds.push(outbound);
    }
    Ok(outbounds)
}

/// Applies the fixed refinement order and attaches Flux-original region keys.
pub fn refine_nodes(
    outbounds: Vec<Value>,
    config: &RefinementConfig,
) -> Result<Vec<RefinedNode>, SubscriptionError> {
    let exclude = if config.exclude_pattern.is_empty() {
        None
    } else {
        Some(
            RegexBuilder::new(&config.exclude_pattern)
                .case_insensitive(true)
                .build()
                .map_err(|error| SubscriptionError::InvalidExcludePattern(error.to_string()))?,
        )
    };
    let renames = config
        .rename
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            Regex::new(&rule.match_pattern)
                .map(|regex| (regex, rule.replace.as_str()))
                .map_err(|error| SubscriptionError::InvalidRenamePattern {
                    index,
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let regions = compile_regions();

    let mut refined = Vec::new();
    for (index, mut outbound) in outbounds.into_iter().enumerate() {
        let object =
            outbound
                .as_object_mut()
                .ok_or_else(|| SubscriptionError::InvalidOutbound {
                    index,
                    reason: "entry is not an object".to_string(),
                })?;
        let kind = object.get("type").and_then(Value::as_str).ok_or_else(|| {
            SubscriptionError::InvalidOutbound {
                index,
                reason: "type is missing or is not a string".to_string(),
            }
        })?;

        // 1. Infrastructure never becomes a selectable provider node.
        if INFRASTRUCTURE_TYPES.contains(&kind) {
            continue;
        }
        let original_tag = object.get("tag").and_then(Value::as_str).ok_or_else(|| {
            SubscriptionError::InvalidOutbound {
                index,
                reason: "tag is missing or is not a string".to_string(),
            }
        })?;

        // 2. Exclusion deliberately observes the provider's original tag.
        if exclude
            .as_ref()
            .is_some_and(|pattern| pattern.is_match(original_tag))
        {
            continue;
        }

        // 3. Rename rules are ordered global substitutions.
        let mut tag = original_tag.to_string();
        for (pattern, replacement) in &renames {
            tag = pattern.replace_all(&tag, *replacement).into_owned();
        }

        // 4. Emoji removal precedes multiplier normalisation.
        if config.strip_emoji {
            tag = strip_emoji(&tag);
        }

        // 5. Canonical multiplier notation and whitespace. Flux-original uses
        // the protocol type if cleanup leaves an empty tag.
        tag = normalise_tag(&tag);
        if tag.is_empty() {
            tag = kind.to_string();
        }

        // 6. Match jq's character-counted ellipsis truncation.
        tag = truncate_tag(&tag, config.max_tag_length);
        object.insert("tag".to_string(), Value::String(tag.clone()));

        // 7. Group only the final user-visible tag.
        let groups = regions
            .iter()
            .filter(|(_, pattern)| pattern.is_match(&tag))
            .map(|(group, _)| (*group).to_string())
            .collect();
        refined.push(RefinedNode { outbound, groups });
    }

    if refined.is_empty() {
        return Err(SubscriptionError::ZeroNodes);
    }
    Ok(refined)
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

fn looks_like_json(bytes: &[u8]) -> bool {
    matches!(
        bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

fn json_outbounds(value: Value) -> Result<Vec<Value>, SubscriptionError> {
    let object = value.as_object().ok_or(SubscriptionError::JsonNotObject)?;
    object
        .get("outbounds")
        .ok_or(SubscriptionError::JsonOutboundsMissing)?
        .as_array()
        .cloned()
        .ok_or(SubscriptionError::JsonOutboundsNotArray)
}

fn decode_base64(input: &[u8]) -> Result<Vec<u8>, String> {
    let compact = input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    BASE64_STANDARD
        .decode(&compact)
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| BASE64_URL_SAFE.decode(&compact))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|error| error.to_string())
}

fn decode_base64_text(input: &str, what: &str) -> Result<String, String> {
    let bytes =
        decode_base64(input.as_bytes()).map_err(|error| format!("invalid {what}: {error}"))?;
    String::from_utf8(bytes).map_err(|_| format!("decoded {what} is not UTF-8"))
}

fn parse_uri(line: &str) -> Result<Value, String> {
    let scheme = line
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| "URI has no scheme separator".to_string())?;
    match scheme.as_str() {
        "vmess" => parse_vmess(line),
        "ss" => parse_shadowsocks(line),
        "hy2" => parse_url_outbound(line, "hysteria2"),
        "vless" | "trojan" | "hysteria" | "hysteria2" | "tuic" | "socks" | "http" => {
            parse_url_outbound(line, &scheme)
        }
        _ => Err(format!("unsupported URI scheme '{scheme}'")),
    }
}

fn parse_vmess(line: &str) -> Result<Value, String> {
    let encoded = line
        .split_once("://")
        .map(|(_, encoded)| encoded)
        .ok_or_else(|| "invalid vmess scheme".to_string())?;
    let text = decode_base64_text(encoded.trim(), "vmess payload")?;
    let source: Value =
        serde_json::from_str(&text).map_err(|error| format!("invalid vmess JSON: {error}"))?;
    let source = source
        .as_object()
        .ok_or_else(|| "vmess payload must be a JSON object".to_string())?;

    let server = required_json_string(source, "add", "vmess server")?;
    let port = required_json_port(source, "port")?;
    let uuid = required_json_string(source, "id", "vmess UUID")?;
    let tag = json_string(source, "ps")
        .filter(|tag| !tag.is_empty())
        .unwrap_or_else(|| "VMess".to_string());
    let mut outbound = base_outbound("vmess", tag, server, port);
    outbound.insert("uuid".to_string(), Value::String(uuid));

    let alter_id = json_u64(source, "aid").unwrap_or(0);
    if alter_id != 0 {
        outbound.insert("alter_id".to_string(), Value::Number(alter_id.into()));
    }
    let security = json_string(source, "scy")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "auto".to_string());
    outbound.insert("security".to_string(), Value::String(security));

    let network = json_string(source, "net").unwrap_or_default();
    if let Some(transport) = vmess_transport(source, &network)? {
        outbound.insert("transport".to_string(), Value::Object(transport));
    }
    if json_string(source, "tls").is_some_and(|tls| tls.eq_ignore_ascii_case("tls")) {
        let mut tls = Map::new();
        tls.insert("enabled".to_string(), Value::Bool(true));
        let server_name = json_string(source, "sni")
            .filter(|name| !name.is_empty())
            .or_else(|| json_string(source, "host").filter(|name| !name.is_empty()));
        if let Some(server_name) = server_name {
            tls.insert("server_name".to_string(), Value::String(server_name));
        }
        if let Some(fingerprint) = json_string(source, "fp").filter(|value| !value.is_empty()) {
            tls.insert("utls".to_string(), utls(fingerprint));
        }
        outbound.insert("tls".to_string(), Value::Object(tls));
    }
    Ok(Value::Object(outbound))
}

fn vmess_transport(
    source: &Map<String, Value>,
    network: &str,
) -> Result<Option<Map<String, Value>>, String> {
    let mut transport = Map::new();
    match network {
        "ws" => {
            transport.insert("type".to_string(), Value::String("ws".to_string()));
            insert_json_string(&mut transport, "path", source, "path");
            if let Some(host) = json_string(source, "host").filter(|host| !host.is_empty()) {
                transport.insert(
                    "headers".to_string(),
                    Value::Object(Map::from_iter([("Host".to_string(), Value::String(host))])),
                );
            }
        }
        "grpc" => {
            transport.insert("type".to_string(), Value::String("grpc".to_string()));
            if let Some(service_name) = json_string(source, "path").filter(|path| !path.is_empty())
            {
                transport.insert("service_name".to_string(), Value::String(service_name));
            }
        }
        "h2" | "http" => {
            transport.insert("type".to_string(), Value::String("http".to_string()));
            insert_json_string(&mut transport, "path", source, "path");
            if let Some(host) = json_string(source, "host").filter(|host| !host.is_empty()) {
                transport.insert("host".to_string(), Value::Array(vec![Value::String(host)]));
            }
        }
        "quic" => {
            transport.insert("type".to_string(), Value::String("quic".to_string()));
        }
        "" | "tcp" | "none" => return Ok(None),
        _ => return Err("unsupported vmess transport".to_string()),
    }
    Ok(Some(transport))
}

fn parse_url_outbound(line: &str, scheme: &str) -> Result<Value, String> {
    let url = Url::parse(line).map_err(|error| format!("invalid {scheme} URI: {error}"))?;
    let (server, port) = endpoint(&url, scheme)?;
    let tag = uri_tag(&url, scheme);
    let kind = if scheme == "ss" {
        "shadowsocks"
    } else {
        scheme
    };
    let mut outbound = base_outbound(kind, tag, server, port);

    match scheme {
        "vless" => {
            if query_value(&url, &["encryption"])
                .is_some_and(|value| !value.is_empty() && value != "none")
            {
                return Err("unsupported vless encryption".to_string());
            }
            outbound.insert(
                "uuid".to_string(),
                Value::String(required_username(&url, "vless UUID")?),
            );
            insert_query_string(&mut outbound, "flow", &url, &["flow"]);
            insert_query_string(
                &mut outbound,
                "packet_encoding",
                &url,
                &["packetEncoding", "packet_encoding"],
            );
            apply_transport(&mut outbound, &url)?;
            apply_tls(&mut outbound, &url, false);
        }
        "trojan" => {
            outbound.insert(
                "password".to_string(),
                Value::String(required_userinfo(&url, "trojan password")?),
            );
            apply_transport(&mut outbound, &url)?;
            apply_tls(&mut outbound, &url, true);
        }
        "hysteria" => parse_hysteria_fields(&mut outbound, &url)?,
        "hysteria2" => parse_hysteria2_fields(&mut outbound, &url)?,
        "tuic" => parse_tuic_fields(&mut outbound, &url)?,
        "socks" => parse_proxy_auth(&mut outbound, &url),
        "http" => parse_proxy_auth(&mut outbound, &url),
        _ => return Err(format!("unsupported URI scheme '{scheme}'")),
    }
    Ok(Value::Object(outbound))
}

fn parse_shadowsocks(line: &str) -> Result<Value, String> {
    let raw = line
        .split_once("://")
        .map(|(_, raw)| raw)
        .ok_or_else(|| "invalid ss scheme".to_string())?;
    let (without_fragment, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let tag = if fragment.is_empty() {
        "shadowsocks".to_string()
    } else {
        decode_url_component(fragment)
    };

    let (credentials, endpoint_text) = if let Some(at) = without_fragment.rfind('@') {
        let userinfo = decode_url_component(&without_fragment[..at]);
        let credentials = if userinfo.contains(':') {
            userinfo
        } else {
            decode_base64_text(&userinfo, "shadowsocks userinfo")?
        };
        (credentials, without_fragment[at + 1..].to_string())
    } else {
        let (encoded, suffix) = without_fragment
            .split_once('?')
            .map_or((without_fragment, ""), |(encoded, query)| (encoded, query));
        let legacy = decode_base64_text(encoded, "legacy shadowsocks payload")?;
        let (credentials, endpoint) = legacy
            .rsplit_once('@')
            .ok_or_else(|| "legacy shadowsocks payload has no endpoint".to_string())?;
        let endpoint = if suffix.is_empty() {
            endpoint.to_string()
        } else {
            format!("{endpoint}?{suffix}")
        };
        (credentials.to_string(), endpoint)
    };
    let (method, password) = credentials
        .split_once(':')
        .ok_or_else(|| "shadowsocks credentials have no method separator".to_string())?;
    if method.is_empty() || password.is_empty() {
        return Err("shadowsocks method and password must be non-empty".to_string());
    }

    let endpoint_url = Url::parse(&format!("ss://placeholder@{endpoint_text}"))
        .map_err(|error| format!("invalid shadowsocks endpoint: {error}"))?;
    let (server, port) = endpoint(&endpoint_url, "ss")?;
    let mut outbound = base_outbound("shadowsocks", tag, server, port);
    outbound.insert("method".to_string(), Value::String(method.to_string()));
    outbound.insert("password".to_string(), Value::String(password.to_string()));
    if let Some(plugin_spec) = query_value(&endpoint_url, &["plugin"]) {
        let (plugin, options) = plugin_spec
            .split_once(';')
            .map_or((plugin_spec.as_str(), ""), |parts| parts);
        if !plugin.is_empty() {
            outbound.insert("plugin".to_string(), Value::String(plugin.to_string()));
        }
        if !options.is_empty() {
            outbound.insert(
                "plugin_opts".to_string(),
                Value::String(options.to_string()),
            );
        }
    }
    Ok(Value::Object(outbound))
}

fn parse_hysteria_fields(outbound: &mut Map<String, Value>, url: &Url) -> Result<(), String> {
    let auth = query_value(url, &["auth", "auth_str"])
        .or_else(|| userinfo(url))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "hysteria URI has no authentication value".to_string())?;
    outbound.insert("auth_str".to_string(), Value::String(auth));
    insert_query_u64(outbound, "up_mbps", url, &["upmbps", "up_mbps", "up"])?;
    insert_query_u64(
        outbound,
        "down_mbps",
        url,
        &["downmbps", "down_mbps", "down"],
    )?;
    insert_query_string(outbound, "obfs", url, &["obfs", "obfsParam", "obfs_param"]);
    apply_tls(outbound, url, true);
    Ok(())
}

fn parse_hysteria2_fields(outbound: &mut Map<String, Value>, url: &Url) -> Result<(), String> {
    for field in ["pinSHA256", "mport"] {
        if query_value(url, &[field]).is_some() {
            return Err(format!("unsupported hysteria2 query parameter '{field}'"));
        }
    }
    let password = userinfo(url)
        .or_else(|| query_value(url, &["password", "auth"]))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "hysteria2 URI has no password".to_string())?;
    outbound.insert("password".to_string(), Value::String(password));
    insert_query_u64(outbound, "up_mbps", url, &["upmbps", "up_mbps", "up"])?;
    insert_query_u64(
        outbound,
        "down_mbps",
        url,
        &["downmbps", "down_mbps", "down"],
    )?;
    if let Some(obfs_type) = query_value(url, &["obfs"]).filter(|value| !value.is_empty()) {
        let mut obfs = Map::new();
        obfs.insert("type".to_string(), Value::String(obfs_type));
        if let Some(password) =
            query_value(url, &["obfs-password", "obfs_password", "obfsPassword"])
        {
            obfs.insert("password".to_string(), Value::String(password));
        }
        outbound.insert("obfs".to_string(), Value::Object(obfs));
    }
    apply_tls(outbound, url, true);
    Ok(())
}

fn parse_tuic_fields(outbound: &mut Map<String, Value>, url: &Url) -> Result<(), String> {
    outbound.insert(
        "uuid".to_string(),
        Value::String(required_username(url, "tuic UUID")?),
    );
    let password = url
        .password()
        .map(decode_url_component)
        .or_else(|| query_value(url, &["password"]))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "tuic URI has no password".to_string())?;
    outbound.insert("password".to_string(), Value::String(password));
    insert_query_string(
        outbound,
        "congestion_control",
        url,
        &["congestion_control", "congestion-controller"],
    );
    insert_query_string(
        outbound,
        "udp_relay_mode",
        url,
        &["udp_relay_mode", "udp-relay-mode"],
    );
    insert_query_bool(
        outbound,
        "zero_rtt_handshake",
        url,
        &["zero_rtt_handshake", "zero-rtt-handshake"],
    );
    insert_query_string(outbound, "heartbeat", url, &["heartbeat"]);
    apply_tls(outbound, url, true);
    Ok(())
}

fn parse_proxy_auth(outbound: &mut Map<String, Value>, url: &Url) {
    let username = decode_url_component(url.username());
    if !username.is_empty() {
        outbound.insert("username".to_string(), Value::String(username));
    }
    if let Some(password) = url.password().map(decode_url_component) {
        outbound.insert("password".to_string(), Value::String(password));
    }
}

fn base_outbound(kind: &str, tag: String, server: String, port: u16) -> Map<String, Value> {
    Map::from_iter([
        ("type".to_string(), Value::String(kind.to_string())),
        ("tag".to_string(), Value::String(tag)),
        ("server".to_string(), Value::String(server)),
        ("server_port".to_string(), Value::Number(Number::from(port))),
    ])
}

fn endpoint(url: &Url, scheme: &str) -> Result<(String, u16), String> {
    let server = match url.host() {
        Some(Host::Domain(server)) if !server.is_empty() => server.to_string(),
        Some(Host::Ipv4(server)) => server.to_string(),
        Some(Host::Ipv6(server)) => server.to_string(),
        _ => return Err(format!("{scheme} URI has no server")),
    };
    let default_port = match scheme {
        "http" => 80,
        "socks" => 1080,
        _ => 443,
    };
    Ok((server, url.port_or_known_default().unwrap_or(default_port)))
}

fn uri_tag(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(decode_url_component)
        .filter(|tag| !tag.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn decode_url_component(raw: &str) -> String {
    // `url` intentionally exposes parsed components in encoded form. Feed an
    // isolated value through its form decoder while protecting delimiters and
    // literal plus signs; percent decoding remains wholly library-owned.
    let protected = raw
        .replace('+', "%2B")
        .replace('&', "%26")
        .replace('=', "%3D");
    let pair = format!("value={protected}");
    form_urlencoded::parse(pair.as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn required_username(url: &Url, what: &str) -> Result<String, String> {
    let username = decode_url_component(url.username());
    if username.is_empty() {
        Err(format!("URI has no {what}"))
    } else {
        Ok(username)
    }
}

fn userinfo(url: &Url) -> Option<String> {
    let username = decode_url_component(url.username());
    if username.is_empty() && url.password().is_none() {
        return None;
    }
    Some(match url.password() {
        Some(password) => format!("{username}:{}", decode_url_component(password)),
        None => username,
    })
}

fn required_userinfo(url: &Url, what: &str) -> Result<String, String> {
    userinfo(url).ok_or_else(|| format!("URI has no {what}"))
}

fn query_value(url: &Url, names: &[&str]) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| names.iter().any(|name| key.eq_ignore_ascii_case(name)))
        .map(|(_, value)| value.into_owned())
}

fn insert_query_string(object: &mut Map<String, Value>, field: &str, url: &Url, names: &[&str]) {
    if let Some(value) = query_value(url, names).filter(|value| !value.is_empty()) {
        object.insert(field.to_string(), Value::String(value));
    }
}

fn insert_query_u64(
    object: &mut Map<String, Value>,
    field: &str,
    url: &Url,
    names: &[&str],
) -> Result<(), String> {
    let Some(value) = query_value(url, names) else {
        return Ok(());
    };
    let number = value
        .parse::<u64>()
        .map_err(|_| format!("query parameter '{field}' is not an unsigned integer"))?;
    object.insert(field.to_string(), Value::Number(number.into()));
    Ok(())
}

fn insert_query_bool(object: &mut Map<String, Value>, field: &str, url: &Url, names: &[&str]) {
    if let Some(value) = query_value(url, names) {
        object.insert(field.to_string(), Value::Bool(query_bool(&value)));
    }
}

fn query_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn apply_transport(outbound: &mut Map<String, Value>, url: &Url) -> Result<(), String> {
    let Some(kind) = query_value(url, &["type", "network", "net"])
        .filter(|kind| !matches!(kind.as_str(), "" | "tcp" | "none"))
    else {
        return Ok(());
    };
    let mut transport = Map::new();
    match kind.as_str() {
        "ws" => {
            transport.insert("type".to_string(), Value::String("ws".to_string()));
            insert_query_string(&mut transport, "path", url, &["path"]);
            if let Some(host) = query_value(url, &["host"]).filter(|host| !host.is_empty()) {
                transport.insert(
                    "headers".to_string(),
                    Value::Object(Map::from_iter([("Host".to_string(), Value::String(host))])),
                );
            }
            insert_query_u64_lossless(
                &mut transport,
                "max_early_data",
                url,
                &["ed", "max_early_data"],
            );
            insert_query_string(
                &mut transport,
                "early_data_header_name",
                url,
                &["eh", "early_data_header_name"],
            );
        }
        "grpc" => {
            transport.insert("type".to_string(), Value::String("grpc".to_string()));
            insert_query_string(
                &mut transport,
                "service_name",
                url,
                &["serviceName", "service_name"],
            );
        }
        "http" | "h2" => {
            transport.insert("type".to_string(), Value::String("http".to_string()));
            insert_query_string(&mut transport, "path", url, &["path"]);
            if let Some(host) = query_value(url, &["host"]).filter(|host| !host.is_empty()) {
                transport.insert("host".to_string(), Value::Array(vec![Value::String(host)]));
            }
        }
        "httpupgrade" => {
            transport.insert("type".to_string(), Value::String("httpupgrade".to_string()));
            insert_query_string(&mut transport, "path", url, &["path"]);
            insert_query_string(&mut transport, "host", url, &["host"]);
        }
        "quic" => {
            transport.insert("type".to_string(), Value::String("quic".to_string()));
        }
        _ => return Err("unsupported URI transport".to_string()),
    }
    outbound.insert("transport".to_string(), Value::Object(transport));
    Ok(())
}

fn insert_query_u64_lossless(
    object: &mut Map<String, Value>,
    field: &str,
    url: &Url,
    names: &[&str],
) {
    if let Some(number) = query_value(url, names).and_then(|value| value.parse::<u64>().ok()) {
        object.insert(field.to_string(), Value::Number(number.into()));
    }
}

fn apply_tls(outbound: &mut Map<String, Value>, url: &Url, default_enabled: bool) {
    let security = query_value(url, &["security"]);
    let enabled = default_enabled
        || security
            .as_deref()
            .is_some_and(|value| matches!(value, "tls" | "reality"));
    if !enabled {
        return;
    }

    let mut tls = Map::new();
    tls.insert("enabled".to_string(), Value::Bool(true));
    if let Some(server_name) =
        query_value(url, &["sni", "peer", "server_name"]).filter(|value| !value.is_empty())
    {
        tls.insert("server_name".to_string(), Value::String(server_name));
    }
    if let Some(insecure) = query_value(url, &["allowInsecure", "allow_insecure", "insecure"]) {
        tls.insert("insecure".to_string(), Value::Bool(query_bool(&insecure)));
    }
    if let Some(alpn) = query_value(url, &["alpn"]).filter(|value| !value.is_empty()) {
        tls.insert(
            "alpn".to_string(),
            Value::Array(
                alpn.split(',')
                    .filter(|item| !item.is_empty())
                    .map(|item| Value::String(item.to_string()))
                    .collect(),
            ),
        );
    }
    if let Some(fingerprint) =
        query_value(url, &["fp", "fingerprint"]).filter(|value| !value.is_empty())
    {
        tls.insert("utls".to_string(), utls(fingerprint));
    }
    if security.as_deref() == Some("reality") {
        let mut reality = Map::new();
        reality.insert("enabled".to_string(), Value::Bool(true));
        insert_query_string(&mut reality, "public_key", url, &["pbk", "public_key"]);
        insert_query_string(&mut reality, "short_id", url, &["sid", "short_id"]);
        tls.insert("reality".to_string(), Value::Object(reality));
    }
    outbound.insert("tls".to_string(), Value::Object(tls));
}

fn utls(fingerprint: String) -> Value {
    Value::Object(Map::from_iter([
        ("enabled".to_string(), Value::Bool(true)),
        ("fingerprint".to_string(), Value::String(fingerprint)),
    ]))
}

fn json_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

fn required_json_string(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<String, String> {
    json_string(object, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("vmess payload has no {what}"))
}

fn json_u64(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    })
}

fn required_json_port(object: &Map<String, Value>, key: &str) -> Result<u16, String> {
    let port =
        json_u64(object, key).ok_or_else(|| "vmess payload has no valid port".to_string())?;
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "vmess port is outside 1..=65535".to_string())
}

fn insert_json_string(
    destination: &mut Map<String, Value>,
    destination_key: &str,
    source: &Map<String, Value>,
    source_key: &str,
) {
    if let Some(value) = json_string(source, source_key).filter(|value| !value.is_empty()) {
        destination.insert(destination_key.to_string(), Value::String(value));
    }
}

fn compile_regions() -> Vec<(&'static str, Regex)> {
    COUNTRY_PATTERNS
        .iter()
        .map(|(group, pattern)| {
            let regex = RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .expect("Flux-original country patterns are valid regex-lite expressions");
            (*group, regex)
        })
        .collect()
}

fn strip_emoji(tag: &str) -> String {
    tag.chars()
        .filter(|character| {
            let scalar = u32::from(*character);
            !matches!(
                scalar,
                0x1F1E6..=0x1F1FF
                    | 0x1F300..=0x1F5FF
                    | 0x1F600..=0x1F64F
                    | 0x1F680..=0x1F6FF
                    | 0x1F700..=0x1FAFF
                    | 0x20E3
                    | 0x2600..=0x27BF
                    | 0x2E80..=0x2EFF
                    | 0xFE0F
                    | 0x200D
            )
        })
        .collect()
}

fn normalise_tag(tag: &str) -> String {
    let currency = Regex::new(r"[$¥]([0-9]+(\.[0-9]+)?)[ \t]*([xX]|倍率?)?")
        .expect("constant multiplier regex is valid");
    let suffix = Regex::new(r"([0-9]+(\.[0-9]+)?)[ \t]*(倍率?|[xX])")
        .expect("constant multiplier regex is valid");
    let tag = currency.replace_all(tag, "${1}x");
    let tag = suffix.replace_all(&tag, "${1}x");
    tag.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_tag(tag: &str, max_length: usize) -> String {
    if tag.chars().count() <= max_length {
        return tag.to_string();
    }
    if max_length <= 3 {
        return ".".repeat(max_length);
    }
    let mut truncated = tag.chars().take(max_length - 3).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;

    use super::*;
    use crate::config::RenameRule;

    #[test]
    fn manual_and_remote_pool_preserves_source_order_and_cleanup_boundary() {
        let refinement = config();
        let mut config = FluxConfig::default();
        config.nodes.push(
            parse_manual_node("trojan://placeholder@example.invalid:443#traffic%20node").unwrap(),
        );
        config.subscription.refine = refinement;
        config.subscription.refine.rename = vec![RenameRule {
            match_pattern: "old".to_string(),
            replace: "remote".to_string(),
        }];
        let raw = br#"{"outbounds":[{"type":"trojan","tag":"old","server":"example.invalid","server_port":443,"password":"placeholder"}]}"#;
        assert_eq!(assemble_nodes(&config, None).unwrap(), config.nodes);
        let pool = assemble_nodes(&config, Some(raw)).unwrap();
        assert_eq!(pool[0].outbound["tag"], "traffic node");
        assert_eq!(pool[1].outbound["tag"], "remote");
        let template = json!({"outbounds":[{"type":"selector","tag":"AUTO","outbounds":[]}]});
        let generated = crate::engine_config::generate_from_template(&template, &pool).unwrap();
        assert_eq!(
            generated["outbounds"][0]["outbounds"],
            json!(["traffic node", "remote"])
        );
    }

    #[test]
    fn unsupported_uri_semantics_are_not_downgraded() {
        for query in ["type=xhttp", "type=kcp", "encryption=mlkem768x25519plus"] {
            let error =
                parse_manual_node(&format!("vless://placeholder@example.invalid:443?{query}"))
                    .unwrap_err();
            assert!(error.contains("unsupported"));
            assert!(!error.contains("placeholder"));
        }
        let payload = STANDARD.encode(
            json!({"add":"example.invalid","port":443,"id":"placeholder","net":"kcp"}).to_string(),
        );
        assert!(parse_manual_node(&format!("vmess://{payload}"))
            .unwrap_err()
            .contains("transport"));
        for field in ["pinSHA256", "mport"] {
            let error = parse_manual_node(&format!(
                "hy2://placeholder@example.invalid:443?{field}=private-placeholder"
            ))
            .unwrap_err();
            assert!(error.contains(field));
            assert!(!error.contains("private-placeholder"));
        }
    }

    #[test]
    fn hysteria2_alias_preserves_complete_decoded_userinfo() {
        for scheme in ["hy2", "hysteria2"] {
            let leading_colon =
                parse_manual_node(&format!("{scheme}://:password@example.invalid:443")).unwrap();
            assert_eq!(leading_colon.outbound["password"], ":password");
            let node = parse_manual_node(&format!("{scheme}://user%3Aname:pass%3Aword@example.invalid:443?sni=front.example.invalid#name")).unwrap();
            assert_eq!(node.outbound["type"], "hysteria2");
            assert_eq!(node.outbound["password"], "user:name:pass:word");
            assert_eq!(node.outbound["tls"]["server_name"], "front.example.invalid");
        }
    }

    fn parse_one(uri: &str) -> Value {
        let response = STANDARD.encode(format!("{uri}\n"));
        parse_subscription(response.as_bytes())
            .expect("valid subscription")
            .pop()
            .expect("one outbound")
    }

    fn config() -> RefinementConfig {
        RefinementConfig {
            exclude_pattern: String::new(),
            rename: Vec::new(),
            strip_emoji: false,
            max_tag_length: 64,
        }
    }

    fn node(kind: &str, tag: &str) -> Value {
        json!({
            "type": kind,
            "tag": tag,
            "server": "example.com",
            "server_port": 443
        })
    }

    #[test]
    fn parses_vmess_uri() {
        let payload = STANDARD.encode(
            json!({
                "v": "2", "ps": "VMess JP", "add": "vmess.example", "port": "443",
                "id": "00000000-0000-0000-0000-000000000001", "aid": "0",
                "scy": "auto", "net": "ws", "host": "cdn.example", "path": "/ws",
                "tls": "tls", "sni": "origin.example"
            })
            .to_string(),
        );
        let outbound = parse_one(&format!("vmess://{payload}"));
        assert_eq!(outbound["transport"]["type"], "ws");
    }

    #[test]
    fn parses_vless_uri() {
        let outbound = parse_one(concat!(
            "vless://00000000-0000-0000-0000-000000000002@vless.example:8443?",
            "security=reality&sni=front.example&pbk=public-key&sid=abcd&type=grpc&",
            "serviceName=flux#VLESS%20US"
        ));
        assert_eq!(outbound["tls"]["reality"]["public_key"], "public-key");
    }

    #[test]
    fn parses_trojan_uri() {
        let outbound =
            parse_one("trojan://secret%3Avalue@trojan.example:443?sni=front.example#Trojan%20UK");
        assert_eq!(outbound["password"], "secret:value");
    }

    #[test]
    fn parses_hysteria_uri() {
        let outbound = parse_one(concat!(
            "hysteria://token@hy.example:443?upmbps=20&downmbps=80&",
            "peer=front.example#Hysteria%20SG"
        ));
        assert_eq!(outbound["down_mbps"], 80);
    }

    #[test]
    fn parses_hysteria2_uri() {
        let outbound = parse_one(concat!(
            "hysteria2://password@hy2.example:443?obfs=salamander&",
            "obfs-password=mask&sni=front.example#HY2%20HK"
        ));
        assert_eq!(outbound["obfs"]["password"], "mask");
    }

    #[test]
    fn parses_tuic_uri() {
        let outbound = parse_one(concat!(
            "tuic://00000000-0000-0000-0000-000000000003:secret@tuic.example:443?",
            "congestion_control=bbr&udp_relay_mode=native#TUIC%20TW"
        ));
        assert_eq!(outbound["password"], "secret");
    }

    #[test]
    fn parses_shadowsocks_uri() {
        let credentials = STANDARD.encode("aes-256-gcm:password");
        let outbound = parse_one(&format!(
            "ss://{credentials}@ss.example:8388#Shadowsocks%20JP"
        ));
        assert_eq!(outbound["type"], "shadowsocks");
    }

    #[test]
    fn parses_socks_uri() {
        let outbound = parse_one("socks://user:pass@socks.example:1080#SOCKS%20DE");
        assert_eq!(outbound["username"], "user");
    }

    #[test]
    fn uri_ipv6_server_has_no_url_brackets() {
        let outbound = parse_one("socks://user:pass@[2001:db8::1]:1080#IPv6");
        assert_eq!(outbound["server"], "2001:db8::1");
    }

    #[test]
    fn parses_http_uri() {
        let outbound = parse_one("http://user:pass@http.example:8080#HTTP%20FR");
        assert_eq!(outbound["server_port"], 8080);
    }

    /// snell is Surge-proprietary and absent from sing-box, so parsing one
    /// would build a candidate that can only fail the official check (§28.3).
    #[test]
    fn snell_is_unsupported_because_the_engine_cannot_run_it() {
        let response = STANDARD.encode("snell://shared-key@snell.example:443?version=3#Snell\n");
        let error = parse_subscription(response.as_bytes()).expect_err("snell must not parse");
        assert!(
            matches!(&error, SubscriptionError::InvalidUri { line, reason }
                if *line == 1 && reason.contains("snell")),
            "{error}"
        );
    }

    #[test]
    fn content_detection_prefers_json_outbounds() {
        let source = json!({
            "outbounds": [{"type": "trojan", "tag": "json", "server": "example"}],
            "other": "is not copied"
        });
        assert_eq!(
            parse_subscription(source.to_string().as_bytes())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn content_detection_decodes_base64_uri_list() {
        let response = STANDARD.encode("http://proxy.example:8080#base64\n");
        assert_eq!(
            parse_subscription(response.as_bytes()).unwrap()[0]["tag"],
            "base64"
        );
    }

    #[test]
    fn refinement_step_one_drops_infrastructure() {
        let refined = refine_nodes(
            vec![node("selector", "HK"), node("trojan", "JP")],
            &config(),
        )
        .unwrap();
        assert_eq!(refined.len(), 1);
    }

    #[test]
    fn exclusion_runs_before_rename() {
        let mut config = config();
        config.exclude_pattern = "announcement".to_string();
        config.rename = vec![RenameRule {
            match_pattern: "announcement".to_string(),
            replace: "usable".to_string(),
        }];
        assert_eq!(
            refine_nodes(vec![node("trojan", "announcement")], &config),
            Err(SubscriptionError::ZeroNodes)
        );
    }

    #[test]
    fn rename_runs_before_emoji_stripping() {
        let mut config = config();
        config.rename = vec![RenameRule {
            match_pattern: "old".to_string(),
            replace: "🚀 new".to_string(),
        }];
        config.strip_emoji = true;
        let refined = refine_nodes(vec![node("trojan", "old")], &config).unwrap();
        assert_eq!(refined[0].outbound["tag"], "new");
    }

    #[test]
    fn emoji_stripping_runs_before_multiplier_normalisation() {
        let mut config = config();
        config.strip_emoji = true;
        let refined = refine_nodes(vec![node("trojan", "$🚀2.0X")], &config).unwrap();
        assert_eq!(refined[0].outbound["tag"], "2.0x");
    }

    #[test]
    fn emoji_stripping_covers_modern_pictographs() {
        let mut config = config();
        config.strip_emoji = true;
        let refined = refine_nodes(vec![node("trojan", "🤖 node")], &config).unwrap();
        assert_eq!(refined[0].outbound["tag"], "node");
    }

    #[test]
    fn multiplier_normalisation_runs_before_truncation() {
        let mut config = config();
        config.max_tag_length = 4;
        let refined = refine_nodes(vec![node("trojan", "$2.0倍率")], &config).unwrap();
        assert_eq!(refined[0].outbound["tag"], "2.0x");
    }

    #[test]
    fn truncation_runs_before_region_grouping() {
        let mut config = config();
        config.max_tag_length = 5;
        let refined = refine_nodes(vec![node("trojan", "abcdef Japan")], &config).unwrap();
        assert!(refined[0].groups.is_empty());
    }

    #[test]
    fn region_grouping_uses_flux_original_country_keys() {
        let refined = refine_nodes(vec![node("trojan", "Hong Kong 01")], &config()).unwrap();
        assert!(refined[0].groups.iter().any(|group| group == "HK"));
    }

    #[test]
    fn zero_refined_nodes_is_a_hard_error() {
        assert_eq!(
            refine_nodes(vec![node("direct", "DIRECT")], &config()),
            Err(SubscriptionError::ZeroNodes)
        );
    }

    #[test]
    fn malformed_outbound_is_not_silently_dropped() {
        assert_eq!(
            refine_nodes(vec![node("trojan", "valid"), json!(null)], &config()),
            Err(SubscriptionError::InvalidOutbound {
                index: 1,
                reason: "entry is not an object".to_string(),
            })
        );
    }
}
