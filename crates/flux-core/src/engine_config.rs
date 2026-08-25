//! Validation of the user's `sing-box.json` and generation of the effective
//! configuration.
//!
//! Implements blueprint §9.0, §9.1 and §9.6. Three invariants the generator
//! enforces:
//!
//! * The user config may not declare any `inbound`. Flux injects exactly two
//!   tproxy inbounds (one per family) and owns their addresses and ports.
//! * The injected inbounds carry ONLY `type`, `tag`, `listen`, `listen_port`.
//!   No `sniff*`, `domain_strategy`, `udp_disable_domain_unmapping`,
//!   `bind_interface`, `routing_mark` or `reuse_addr` (blueprint §9.1–§9.3).
//! * Flux never touches the user's `dns` / `outbounds` / `route` / `log` /
//!   `experimental`, and the user may not use a `flux-` prefixed tag (§9.6).
//!
//! Everything here is a pure function of a parsed [`serde_json::Value`], so it
//! is fully testable on any host. Running `sing-box check` is the daemon's job
//! (blueprint §9.4); this module produces the JSON that check then validates.

use serde_json::{json, Map, Value};

use crate::abi::{LISTEN_V4_STR, LISTEN_V6_STR};

/// Tag of the injected IPv4 tproxy inbound.
pub const INBOUND_TAG_V4: &str = "flux-in-v4";
/// Tag of the injected IPv6 tproxy inbound.
pub const INBOUND_TAG_V6: &str = "flux-in-v6";
/// Prefix reserved for Flux-owned tags; a user config may not use it.
pub const RESERVED_TAG_PREFIX: &str = "flux-";

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

/// Why a user engine configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineConfigError {
    /// The value was not a JSON object.
    NotAnObject,
    /// `inbounds` was present and non-empty; Flux owns inbounds exclusively.
    UserSuppliedInbound,
    /// `inbounds` was present but was not an array.
    InboundsNotArray,
    /// The user used a `flux-` prefixed tag, which Flux reserves.
    ReservedTag(String),
}

/// Builds the effective sing-box configuration for one generation.
///
/// Deep-copies the user config, asserts it declares no inbound and no reserved
/// tag, then writes exactly the two tproxy inbounds. Nothing else is altered:
/// routing and DNS are the user's authority (blueprint §9.6).
pub fn build_effective(user: &Value, params: &EngineParams) -> Result<Value, EngineConfigError> {
    let user_obj = user.as_object().ok_or(EngineConfigError::NotAnObject)?;

    match user_obj.get("inbounds") {
        None | Some(Value::Null) => {}
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

/// Finds the first `"tag"` anywhere in the config whose value starts with the
/// reserved prefix, so a user cannot shadow the injected inbounds.
fn first_reserved_tag(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(tag)) = map.get("tag") {
                if tag.starts_with(RESERVED_TAG_PREFIX) {
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
    route_rules(config).is_some_and(|rules| {
        rules
            .iter()
            .any(|rule| rule_action_is(rule, "hijack-dns"))
    })
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

/// Removes `//` line comments and `/* */` block comments from a JSONC document,
/// preserving comment-like sequences that appear inside string literals
/// (the shipped template mixes `//` comments with `https://` URLs, so a naive
/// strip would corrupt the URLs). Trailing commas are not handled: the shipped
/// default has none, and full JSONC leniency is sing-box's own parser's job.
pub fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for next in chars.by_ref() {
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parses a JSONC document (comments allowed) into a value.
pub fn parse_jsonc(text: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(&strip_jsonc_comments(text))
}

/// Asserts the injected inbound object carries only the four allowed keys.
fn injected_keys_are_minimal(inbound: &Map<String, Value>) -> bool {
    const ALLOWED: [&str; 4] = ["type", "tag", "listen", "listen_port"];
    inbound.len() == ALLOWED.len() && ALLOWED.iter().all(|k| inbound.contains_key(*k))
}

/// The sing-box config template shipped with the module, embedded at build time
/// so the §15.2 test 4 assertion travels with the crate.
pub const DEFAULT_SING_BOX_JSONC: &str = include_str!("../../../module/template.json");

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> EngineParams {
        EngineParams {
            generation: 7,
            port_v4: 61_001,
            port_v6: 61_002,
        }
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
                assert!(!obj.contains_key(forbidden), "{forbidden} must not be injected");
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
    fn user_supplied_inbound_is_rejected() {
        let user = json!({ "inbounds": [{ "type": "mixed", "listen_port": 2080 }] });
        assert_eq!(
            build_effective(&user, &params()),
            Err(EngineConfigError::UserSuppliedInbound)
        );
    }

    #[test]
    fn reserved_tag_is_rejected() {
        let user = json!({ "outbounds": [{ "type": "direct", "tag": "flux-sneaky" }] });
        assert_eq!(
            build_effective(&user, &params()),
            Err(EngineConfigError::ReservedTag("flux-sneaky".to_string()))
        );
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
        let config = parse_jsonc(DEFAULT_SING_BOX_JSONC).expect("template parses as JSONC");

        // No inbound, so Flux can inject its own.
        assert!(build_effective(&config, &params()).is_ok());

        // Both route rules present (blueprint §1.3.4).
        assert!(has_sniff_rule(&config), "default template lacks a sniff rule");
        assert!(
            has_dns_hijack_rule(&config),
            "default template lacks a hijack-dns rule"
        );
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
