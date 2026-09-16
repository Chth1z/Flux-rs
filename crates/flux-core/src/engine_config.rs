//! Generation and validation of the user's `template.json`.
//!
//! Implements blueprint §9.0, §9.1 and §9.6. Three invariants the generator
//! enforces:
//!
//! * The user config may not declare any `inbound`. Flux injects exactly two
//!   tproxy inbounds (one per family) and owns their addresses and ports.
//! * The injected inbounds carry ONLY `type`, `tag`, `listen`, `listen_port`.
//!   No `sniff*`, `domain_strategy`, `udp_disable_domain_unmapping`,
//!   `bind_interface`, `routing_mark` or `reuse_addr` (blueprint §9.1–§9.3).
//! * Template generation changes only `outbounds`: it fills empty groups and
//!   appends refined nodes. Replacing that field with the template field must
//!   recover a deeply equal value (§28.2).
//! * Inbound injection never touches `dns` / `outbounds` / `route` / `log` /
//!   `experimental`, and nothing else in the config may carry one of the two
//!   injected inbound tags (§9.6). Only those exact tags are reserved: the
//!   mechanism needs its two inbounds to be unambiguous, and nothing wider.
//!
//! Everything here is a pure function of a parsed [`serde_json::Value`], so it
//! is fully testable on any host. Running `sing-box check` is the daemon's job
//! (blueprint §9.4); this module produces the JSON that check then validates.

use serde_json::json;
#[cfg(test)]
use serde_json::Map;
/// Re-exported because [`parse_jsonc`] returns it: without this a caller
/// outside the crate cannot name the type it is handed.
pub use serde_json::Value;

use crate::abi::{LISTEN_V4_STR, LISTEN_V6_STR};

/// Largest accepted user `template.json`, in bytes (blueprint §9.6).
pub const MAX_ENGINE_CONFIG_BYTES: usize = 8 * 1024 * 1024;

/// Tag of the injected IPv4 tproxy inbound.
pub const INBOUND_TAG_V4: &str = "flux-in-v4";
/// Tag of the injected IPv6 tproxy inbound.
pub const INBOUND_TAG_V6: &str = "flux-in-v6";
/// The only tags a user config may not use: the two the injected inbounds
/// carry. An earlier draft reserved the whole `flux-` prefix, which let a
/// provider naming a node `flux-hk` invalidate the entire generated config.
pub const RESERVED_TAGS: [&str; 2] = [INBOUND_TAG_V4, INBOUND_TAG_V6];

/// Parameters that vary per engine generation (blueprint §9.1, §9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineParams {
    /// Monotonic within a boot, never reused (blueprint §6.5).
    pub generation: u64,
    /// Randomly drawn IPv4 listener port for this generation.
    pub port_v4: u16,
    /// Randomly drawn IPv6 listener port for this generation.
    pub port_v6: u16,
}

/// One subscription node after Batch C refinement and region grouping.
///
/// Batch B feeds an empty slice. Keeping the already-refined outbound and its
/// group names together makes generation a pure fill-and-append operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedNode {
    /// Official sing-box outbound object, including its unique tag.
    pub outbound: Value,
    /// Template group tags this node belongs to.
    pub groups: Vec<String>,
}

/// Why a user engine configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineConfigError {
    /// The value was not a JSON object.
    NotAnObject,
    /// `inbounds` was present and non-empty; Flux owns inbounds exclusively.
    UserSuppliedInbound,
    /// `inbounds` was present but was not an array.
    InboundsNotArray,
    /// The config carries one of the injected inbound tags ([`RESERVED_TAGS`]).
    ReservedTag(String),
    /// The template's top-level `outbounds` was absent or not an array.
    OutboundsNotArray,
    /// A refined node was not an outbound object.
    NodeNotAnObject,
    /// A refined node had no non-empty string tag.
    NodeTagMissing,
    /// Groups were still empty after the fill and there was no node to put in
    /// them. The template is not a runnable configuration yet, and the engine
    /// rejects an empty group outright, so the candidate never reaches it.
    UnfilledGroups(Vec<String>),
}

/// Generates the engine-owned configuration from a user-owned template.
///
/// Exactly two mutations are permitted (§28.2): fill an empty selector/urltest
/// group from the refined node tags, then append the refined outbound objects.
/// `PROXY`, `GLOBAL` and `AUTO` receive every node; other groups receive nodes
/// carrying that exact group name. Every other value is cloned unchanged.
///
/// An empty group is fatal to the engine, so a group the subscription cannot
/// fill becomes `DIRECT` — selectable, and visibly not a proxy. With no nodes
/// at all there is nothing to build from and the whole candidate is refused as
/// [`EngineConfigError::UnfilledGroups`]: a template is not a runnable
/// configuration, and handing one to sing-box would only produce a crash loop
/// (§28.2).
pub fn generate_from_template(
    template: &Value,
    nodes: &[RefinedNode],
) -> Result<Value, EngineConfigError> {
    let template_object = template.as_object().ok_or(EngineConfigError::NotAnObject)?;
    template_object
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or(EngineConfigError::OutboundsNotArray)?;

    let node_tags = nodes
        .iter()
        .map(|node| {
            let object = node
                .outbound
                .as_object()
                .ok_or(EngineConfigError::NodeNotAnObject)?;
            object
                .get("tag")
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
                .map(str::to_string)
                .ok_or(EngineConfigError::NodeTagMissing)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut generated = template.clone();
    let mut unfilled = Vec::new();
    let outbounds = generated
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .expect("template outbounds was checked");
    for group in outbounds.iter_mut() {
        let Some(object) = group.as_object_mut() else {
            continue;
        };
        let kind = object.get("type").and_then(Value::as_str);
        if !matches!(kind, Some("selector") | Some("urltest")) {
            continue;
        }
        let Some(members) = object.get("outbounds").and_then(Value::as_array) else {
            continue;
        };
        if !members.is_empty() {
            continue;
        }
        let Some(group_tag) = object.get("tag").and_then(Value::as_str) else {
            continue;
        };
        if nodes.is_empty() {
            unfilled.push(group_tag.to_string());
            continue;
        }
        let all_nodes = matches!(group_tag, "PROXY" | "GLOBAL" | "AUTO");
        let mut filled: Vec<Value> = nodes
            .iter()
            .zip(node_tags.iter())
            .filter(|(node, _)| all_nodes || node.groups.iter().any(|group| group == group_tag))
            .map(|(_, node_tag)| Value::String(node_tag.clone()))
            .collect();
        if filled.is_empty() {
            filled.push(Value::String(DIRECT_TAG.to_string()));
        }
        object.insert("outbounds".to_string(), Value::Array(filled));
    }
    if !unfilled.is_empty() {
        return Err(EngineConfigError::UnfilledGroups(unfilled));
    }
    outbounds.extend(nodes.iter().map(|node| node.outbound.clone()));
    Ok(generated)
}

/// The official direct outbound every supported template carries; what a group
/// with no matching node falls back to.
const DIRECT_TAG: &str = "DIRECT";

/// Node tags a generated configuration carries that no group selects.
///
/// The engine would run such a configuration happily and proxy nothing through
/// those nodes, so `check` and `status` say so rather than reporting a clean
/// Active (§17.1).
pub fn unreferenced_node_tags(generated: &Value) -> Vec<String> {
    let Some(outbounds) = generated.get("outbounds").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut node_tags = Vec::new();
    let mut selected = Vec::new();
    for outbound in outbounds {
        let Some(object) = outbound.as_object() else {
            continue;
        };
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(kind, "selector" | "urltest") {
            selected.extend(
                object
                    .get("outbounds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
            continue;
        }
        if matches!(kind, "direct" | "block" | "dns" | "") {
            continue;
        }
        if let Some(tag) = object.get("tag").and_then(Value::as_str) {
            node_tags.push(tag.to_string());
        }
    }
    node_tags.retain(|tag| !selected.iter().any(|member| member == tag));
    node_tags
}

/// Injects Flux-owned inbounds into one generated engine configuration.
///
/// Deep-copies the generated config, asserts it declares no inbound and no reserved
/// tag, then writes exactly the two tproxy inbounds. Nothing else is altered:
/// routing and DNS are the user's authority (blueprint §9.6).
pub fn build_effective(user: &Value, params: &EngineParams) -> Result<Value, EngineConfigError> {
    let user_obj = user.as_object().ok_or(EngineConfigError::NotAnObject)?;

    match user_obj.get("inbounds") {
        None => {}
        Some(Value::Array(items)) if items.is_empty() => {}
        Some(Value::Array(_)) => return Err(EngineConfigError::UserSuppliedInbound),
        Some(_) => return Err(EngineConfigError::InboundsNotArray),
    }

    if let Some(tag) = first_reserved_tag(user) {
        return Err(EngineConfigError::ReservedTag(tag));
    }

    let mut effective = user_obj.clone();
    effective.insert("inbounds".to_string(), injected_inbounds(params));
    Ok(Value::Object(effective))
}

/// Supplies the engine's default cache destination only when enabled and not
/// explicitly set (§9.6). All native explicit paths retain their meaning.
pub fn complete_cache_path(generated: &mut Value, path: &str) {
    let Some(cache) = generated
        .pointer_mut("/experimental/cache_file")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if cache.get("enabled") == Some(&Value::Bool(true))
        && (cache.get("path").is_none() || cache.get("path") == Some(&Value::String(String::new())))
    {
        cache.insert("path".into(), Value::String(path.into()));
    }
}

/// The two tproxy inbounds Flux injects, each with only the four allowed keys.
fn injected_inbounds(params: &EngineParams) -> Value {
    json!([
        {
            "type": "tproxy",
            "tag": INBOUND_TAG_V4,
            "listen": LISTEN_V4_STR,
            "listen_port": params.port_v4,
        },
        {
            "type": "tproxy",
            "tag": INBOUND_TAG_V6,
            "listen": LISTEN_V6_STR,
            "listen_port": params.port_v6,
        },
    ])
}

/// Finds the first `"tag"` anywhere in the config equal to one of the injected
/// inbound tags, so nothing can shadow them. Any other tag is the user's or
/// the provider's business.
fn first_reserved_tag(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(tag)) = map.get("tag") {
                if RESERVED_TAGS.contains(&tag.as_str()) {
                    return Some(tag.clone());
                }
            }
            map.values().find_map(first_reserved_tag)
        }
        Value::Array(items) => items.iter().find_map(first_reserved_tag),
        _ => None,
    }
}

/// Whether the config already handles captured :53 traffic with a `hijack-dns`
/// route action (blueprint §1.3.4, §9.6).
///
/// A false result means `fluxd check` must WARN, not reject: the user may
/// deliberately want DNS forwarded verbatim (§9.6).
pub fn has_dns_hijack_rule(config: &Value) -> bool {
    route_rules(config)
        .is_some_and(|rules| rules.iter().any(|rule| rule_action_is(rule, "hijack-dns")))
}

/// Whether the config has a `sniff` route action, which the shipped default
/// must carry (blueprint §1.3.4, §9.6).
pub fn has_sniff_rule(config: &Value) -> bool {
    route_rules(config).is_some_and(|rules| rules.iter().any(|rule| rule_action_is(rule, "sniff")))
}

fn route_rules(config: &Value) -> Option<&Vec<Value>> {
    config.get("route")?.get("rules")?.as_array()
}

fn rule_action_is(rule: &Value, action: &str) -> bool {
    rule.get("action").and_then(Value::as_str) == Some(action)
}

/// Masks JSONC comments with whitespace, preserving token boundaries and error
/// positions. String contents are untouched; an unterminated block comment is
/// left for the JSON parser to reject (§9.6). Trailing commas are not accepted.
pub fn strip_jsonc_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = bytes.to_vec();
    let mut offset = 0;
    let mut in_string = false;
    let mut escaped = false;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'/' {
            let end = match bytes.get(offset + 1) {
                Some(b'/') => bytes[offset..]
                    .iter()
                    .position(|byte| matches!(byte, b'\r' | b'\n'))
                    .map_or(bytes.len(), |length| offset + length),
                Some(b'*') => {
                    let Some(length) = bytes[offset + 2..]
                        .windows(2)
                        .position(|pair| pair == b"*/")
                    else {
                        break;
                    };
                    offset + 2 + length + 2
                }
                _ => {
                    offset += 1;
                    continue;
                }
            };
            for byte in &mut out[offset..end] {
                if !matches!(byte, b'\r' | b'\n') {
                    *byte = b' ';
                }
            }
            offset = end;
            continue;
        }
        offset += 1;
    }
    // Complete comment spans are replaced with ASCII; all other UTF-8 bytes
    // retain their original sequence.
    String::from_utf8(out).expect("masking complete comments preserves UTF-8")
}

/// Parses a JSONC document (comments allowed) into a value.
///
/// A leading UTF-8 BOM is skipped. Editors on Windows add one routinely, and
/// the resulting `serde_json` message ("expected value at line 1 column 1")
/// points at a byte the user cannot see, which makes a trivial problem look
/// like a corrupt config.
pub fn parse_jsonc(text: &str) -> Result<Value, serde_json::Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    serde_json::from_str(&strip_jsonc_comments(text))
}

/// Asserts the injected inbound object carries only the four allowed keys.
#[cfg(test)]
fn injected_keys_are_minimal(inbound: &Map<String, Value>) -> bool {
    const ALLOWED: [&str; 4] = ["type", "tag", "listen", "listen_port"];
    inbound.len() == ALLOWED.len() && ALLOWED.iter().all(|k| inbound.contains_key(*k))
}

/// The sing-box config template shipped with the module, embedded at build time
/// so the §15.2 test 4 assertion travels with the crate.
pub const DEFAULT_TEMPLATE_JSONC: &str = include_str!("../../../module/template.json");

#[cfg(test)]
mod tests {
    #[test]
    fn only_an_enabled_implicit_cache_path_is_completed() {
        for cache in [
            json!({"enabled": true}),
            json!({"enabled": true, "path": ""}),
        ] {
            let mut config =
                json!({"experimental": {"cache_file": cache}, "route": {"final": "DIRECT"}});
            complete_cache_path(&mut config, "/state/run/cache/sing-box.db");
            assert_eq!(
                config["experimental"]["cache_file"]["path"],
                "/state/run/cache/sing-box.db"
            );
            assert_eq!(config["route"]["final"], "DIRECT");
        }
        for cache in [
            json!({"enabled": false}),
            json!({"enabled": true, "path": "user.db"}),
            json!({"enabled": true, "path": null}),
        ] {
            let mut config = json!({"experimental": {"cache_file": cache}});
            let original = config.clone();
            complete_cache_path(&mut config, "/state/run/cache/sing-box.db");
            assert_eq!(config, original);
        }
    }
    use super::*;

    #[test]
    fn jsonc_comments_do_not_join_tokens_or_hide_unterminated_input() {
        for text in [
            r#"{"n": 1/* comment */2}"#,
            "tr/* comment */ue",
            "{} /* unfinished",
        ] {
            assert!(parse_jsonc(text).is_err(), "accepted invalid JSONC: {text}");
        }
    }

    #[test]
    fn jsonc_comments_preserve_error_positions_and_string_content() {
        let text = "{\n/* first\n second */\n\"n\": @\n}";
        let error = parse_jsonc(text).unwrap_err();
        assert_eq!((error.line(), error.column()), (4, 6));
        let text = "{\"url\":\"https://example.invalid/a/*b*/\",/* \u{6ce8}\u{91ca} */\"n\":1}";
        let masked = strip_jsonc_comments(text);
        assert_eq!(masked.len(), text.len());
        assert_eq!(
            parse_jsonc(text).unwrap()["url"],
            "https://example.invalid/a/*b*/"
        );
    }

    fn params() -> EngineParams {
        EngineParams {
            generation: 7,
            port_v4: 61_001,
            port_v6: 61_002,
        }
    }

    #[test]
    fn generation_changes_only_outbounds_and_is_pure() {
        let template = json!({
            "log": { "level": "warn", "timestamp": true },
            "dns": { "strategy": "prefer_ipv6" },
            "outbounds": [
                { "type": "direct", "tag": "DIRECT", "custom": 1.25 },
                { "type": "selector", "tag": "PROXY", "outbounds": [] },
                { "type": "urltest", "tag": "EUROPE", "outbounds": [] },
                { "type": "selector", "tag": "PINNED", "outbounds": ["DIRECT"] }
            ],
            "route": { "rules": [{ "action": "sniff", "preserve": [1, 2, 3] }] },
            "experimental": { "cache_file": { "enabled": false } },
            "unknown_future_field": { "must_survive": null }
        });
        let nodes = vec![
            RefinedNode {
                outbound: json!({ "type": "shadowsocks", "tag": "Paris", "server": "example" }),
                groups: vec!["EUROPE".to_string()],
            },
            RefinedNode {
                outbound: json!({ "type": "trojan", "tag": "Tokyo", "server": "example" }),
                groups: vec!["ASIA".to_string()],
            },
        ];

        let generated = generate_from_template(&template, &nodes).expect("generation");
        assert_eq!(
            generated["outbounds"][1]["outbounds"],
            json!(["Paris", "Tokyo"])
        );
        assert_eq!(generated["outbounds"][2]["outbounds"], json!(["Paris"]));
        assert_eq!(generated["outbounds"][3], template["outbounds"][3]);
        assert_eq!(generated["outbounds"].as_array().unwrap().len(), 6);

        // §28.2's required host test: restoring the template outbounds must
        // recover the complete template, including fields unknown to Flux.
        let mut restored = generated;
        restored["outbounds"] = template["outbounds"].clone();
        assert_eq!(restored, template);

        // Value equality ignores key order, so compare the serialised text too:
        // §28.2 fails an implementation that reorders keys, and the user reads
        // the generated file next to the template they wrote.
        assert_eq!(
            serde_json::to_string_pretty(&restored).unwrap(),
            serde_json::to_string_pretty(&template).unwrap()
        );
    }

    /// The shipped shape: `PROXY` as a written menu over empty regional
    /// groups. A region the provider has no node for becomes `DIRECT`, because
    /// the engine rejects an empty group outright.
    #[test]
    fn a_region_without_nodes_becomes_direct() {
        let template = json!({
            "outbounds": [
                { "type": "direct", "tag": "DIRECT" },
                { "type": "selector", "tag": "PROXY", "outbounds": ["JP", "US"] },
                { "type": "selector", "tag": "JP", "outbounds": [] },
                { "type": "selector", "tag": "US", "outbounds": [] }
            ]
        });
        let nodes = vec![RefinedNode {
            outbound: json!({ "type": "trojan", "tag": "Tokyo", "server": "example" }),
            groups: vec!["JP".to_string()],
        }];

        let generated = generate_from_template(&template, &nodes).expect("generation");
        assert_eq!(generated["outbounds"][1], template["outbounds"][1]);
        assert_eq!(generated["outbounds"][2]["outbounds"], json!(["Tokyo"]));
        assert_eq!(generated["outbounds"][3]["outbounds"], json!(["DIRECT"]));
        assert_eq!(generated["outbounds"].as_array().unwrap().len(), 5);

        let mut restored = generated;
        restored["outbounds"] = template["outbounds"].clone();
        assert_eq!(restored, template);
    }

    /// A template is not a configuration: with no node to fill its groups the
    /// whole candidate is refused, naming them, instead of being handed to an
    /// engine that rejects an empty group and would then crash-restart.
    #[test]
    fn no_nodes_refuses_the_candidate_and_names_the_groups() {
        let template = json!({
            "outbounds": [
                { "type": "selector", "tag": "PROXY", "outbounds": ["HK"] },
                { "type": "selector", "tag": "HK", "outbounds": [] }
            ]
        });
        assert_eq!(
            generate_from_template(&template, &[]),
            Err(EngineConfigError::UnfilledGroups(vec!["HK".to_string()]))
        );
    }

    /// A finished configuration the user wrote themselves has no empty group,
    /// so it runs with no subscription at all.
    #[test]
    fn a_complete_user_config_needs_no_nodes() {
        let template = json!({
            "outbounds": [
                { "type": "direct", "tag": "DIRECT" },
                { "type": "trojan", "tag": "mine", "server": "example" },
                { "type": "selector", "tag": "PROXY", "outbounds": ["mine"] }
            ]
        });
        assert_eq!(generate_from_template(&template, &[]).unwrap(), template);
    }

    #[test]
    fn nodes_no_group_selects_are_reported() {
        let generated = json!({
            "outbounds": [
                { "type": "direct", "tag": "DIRECT" },
                { "type": "selector", "tag": "PROXY", "outbounds": ["DIRECT"] },
                { "type": "trojan", "tag": "Paris", "server": "example" },
                { "type": "trojan", "tag": "Tokyo", "server": "example" }
            ]
        });
        assert_eq!(unreferenced_node_tags(&generated), ["Paris", "Tokyo"]);

        let selected = json!({
            "outbounds": [
                { "type": "selector", "tag": "PROXY", "outbounds": ["Paris"] },
                { "type": "trojan", "tag": "Paris", "server": "example" }
            ]
        });
        assert!(unreferenced_node_tags(&selected).is_empty());
    }

    /// A group with members and no node to add keeps exactly what it had:
    /// generation is only ever fill plus append.
    #[test]
    fn nothing_to_add_leaves_the_template_untouched() {
        let template = json!({
            "outbounds": [
                { "type": "direct", "tag": "DIRECT" },
                { "type": "selector", "tag": "PROXY", "outbounds": ["DIRECT"] }
            ],
            "route": { "final": "PROXY" }
        });
        assert_eq!(generate_from_template(&template, &[]).unwrap(), template);
    }

    // Blueprint §15.2 test 3: user JSON forbids its own inbound; effective JSON
    // injects exactly two tproxy inbounds without any forbidden key.

    #[test]
    fn injects_exactly_two_tproxy_inbounds() {
        let user = json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "rules": [{ "action": "sniff" }] }
        });
        let effective = build_effective(&user, &params()).expect("valid");

        let inbounds = effective["inbounds"].as_array().expect("array");
        assert_eq!(inbounds.len(), 2);

        assert_eq!(inbounds[0]["type"], "tproxy");
        assert_eq!(inbounds[0]["tag"], INBOUND_TAG_V4);
        assert_eq!(inbounds[0]["listen"], LISTEN_V4_STR);
        assert_eq!(inbounds[0]["listen_port"], 61_001);

        assert_eq!(inbounds[1]["tag"], INBOUND_TAG_V6);
        assert_eq!(inbounds[1]["listen"], LISTEN_V6_STR);
        assert_eq!(inbounds[1]["listen_port"], 61_002);

        for inbound in inbounds {
            let obj = inbound.as_object().unwrap();
            assert!(
                injected_keys_are_minimal(obj),
                "injected inbound has a forbidden key: {obj:?}"
            );
            for forbidden in [
                "sniff",
                "sniff_override_destination",
                "domain_strategy",
                "udp_disable_domain_unmapping",
                "bind_interface",
                "routing_mark",
                "reuse_addr",
            ] {
                assert!(
                    !obj.contains_key(forbidden),
                    "{forbidden} must not be injected"
                );
            }
        }

        // The user's route and outbounds are untouched.
        assert_eq!(effective["route"], user["route"]);
        assert_eq!(effective["outbounds"], user["outbounds"]);
    }

    #[test]
    fn empty_inbounds_array_is_accepted() {
        let user = json!({ "inbounds": [], "outbounds": [] });
        assert!(build_effective(&user, &params()).is_ok());
    }

    #[test]
    fn package_name_rules_survive_effective_config_injection_byte_for_byte() {
        let user = json!({
            "route": {
                "rules": [{
                    "package_name": ["com.example.browser"],
                    "outbound": "direct"
                }]
            },
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        });
        let effective = build_effective(&user, &params()).expect("valid package rule");
        assert_eq!(effective["route"], user["route"]);
    }

    #[test]
    fn null_inbounds_is_rejected_as_the_wrong_type() {
        let user = json!({ "inbounds": null, "outbounds": [] });
        assert_eq!(
            build_effective(&user, &params()),
            Err(EngineConfigError::InboundsNotArray)
        );
    }

    #[test]
    fn user_supplied_inbound_is_rejected() {
        let user = json!({ "inbounds": [{ "type": "mixed", "listen_port": 2080 }] });
        assert_eq!(
            build_effective(&user, &params()),
            Err(EngineConfigError::UserSuppliedInbound)
        );
    }

    #[test]
    fn an_injected_inbound_tag_is_rejected_anywhere_in_the_config() {
        let user = json!({
            "outbounds": [{ "type": "direct", "tag": "DIRECT" }],
            "dns": { "servers": [{ "type": "udp", "tag": INBOUND_TAG_V6, "server": "1.1.1.1" }] }
        });
        assert_eq!(
            build_effective(&user, &params()),
            Err(EngineConfigError::ReservedTag(INBOUND_TAG_V6.to_string()))
        );
    }

    /// Only the two exact tags are reserved. A provider that names a node
    /// `flux-hk` must not be able to invalidate the whole generated config.
    #[test]
    fn other_flux_prefixed_tags_are_the_users_business() {
        let user = json!({ "outbounds": [{ "type": "direct", "tag": "flux-sneaky" }] });
        let effective = build_effective(&user, &params()).expect("prefix alone is not reserved");
        assert_eq!(effective["outbounds"][0]["tag"], "flux-sneaky");
    }

    #[test]
    fn non_object_is_rejected() {
        assert_eq!(
            build_effective(&json!([]), &params()),
            Err(EngineConfigError::NotAnObject)
        );
    }

    // Blueprint §15.2 test 4: the shipped default sing-box config parses, has
    // no inbound, carries both the sniff and hijack-dns route rules, and a
    // config missing :53 handling warns rather than errors.

    #[test]
    fn default_template_is_valid_with_sniff_and_hijack_dns() {
        let config = parse_jsonc(DEFAULT_TEMPLATE_JSONC).expect("template parses as JSONC");

        // No inbound, so Flux can inject its own.
        let top = config.as_object().expect("template is an object");
        assert!(
            !top.contains_key("inbounds"),
            "the template must leave the inbound side to Flux"
        );
        assert!(build_effective(&config, &params()).is_ok());

        // Both route rules remain present (blueprint §1.3.4).
        assert!(
            has_sniff_rule(&config),
            "default template lacks a sniff rule"
        );
        assert!(
            has_dns_hijack_rule(&config),
            "default template lacks a hijack-dns rule"
        );

        // A shipped default must never open a control port (§27.2.3, C10).
        assert!(
            config.pointer("/experimental/clash_api").is_none(),
            "the template must not ship a clash_api listener"
        );

        // The regional groups ship empty: they are the subscription's to fill,
        // and until it has a node the candidate is refused rather than run.
        let empty: Vec<&str> = config["outbounds"]
            .as_array()
            .expect("outbounds array")
            .iter()
            .filter(|outbound| {
                matches!(
                    outbound["type"].as_str().unwrap_or_default(),
                    "selector" | "urltest"
                ) && outbound["outbounds"]
                    .as_array()
                    .is_some_and(|list| list.is_empty())
            })
            .map(|outbound| outbound["tag"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(empty, ["HK", "TW", "JP", "SG", "US"]);
        assert_eq!(
            generate_from_template(&config, &[]),
            Err(EngineConfigError::UnfilledGroups(
                empty.iter().map(|tag| (*tag).to_string()).collect()
            ))
        );

        // The IPv6 fakeip range must stay out of fc00::/7: Flux bypasses ULA as
        // private space, so a fakeip inside it would be sent direct and every
        // IPv6 fakeip connection would fail silently (D21).
        for server in config["dns"]["servers"].as_array().expect("dns servers") {
            if server["type"] == "fakeip" {
                let range = server["inet6_range"].as_str().unwrap_or_default();
                assert!(
                    !range.starts_with("fc") && !range.starts_with("fd"),
                    "fakeip inet6_range {range} lies inside the fixed ULA bypass"
                );
            }
        }
    }

    #[test]
    fn a_leading_byte_order_mark_is_not_a_syntax_error() {
        // Editing template.json on Windows routinely adds one, and the raw
        // serde message points at an invisible byte.
        let value = parse_jsonc("\u{feff}{\"outbounds\": []}").expect("BOM is skipped");
        assert_eq!(value["outbounds"], json!([]));
    }

    #[test]
    fn missing_dns_handling_is_a_warning_not_an_error() {
        // A config with no hijack-dns rule is still valid to build; the caller
        // (fluxd check) only warns (blueprint §9.6).
        let user = json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "rules": [{ "action": "sniff" }] }
        });
        assert!(!has_dns_hijack_rule(&user));
        assert!(build_effective(&user, &params()).is_ok());
    }

    #[test]
    fn comment_stripper_preserves_urls_inside_strings() {
        let src = r#"{
            // a line comment
            "url": "https://example.com/path", /* trailing block */
            "note": "not // a comment"
        }"#;
        let value: Value = parse_jsonc(src).expect("parses");
        assert_eq!(value["url"], "https://example.com/path");
        assert_eq!(value["note"], "not // a comment");
    }
}
