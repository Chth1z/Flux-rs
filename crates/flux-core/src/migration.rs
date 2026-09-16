//! Pure, install-only configuration migration (blueprint §13.2.3).
//!
//! Preparation never performs I/O. The caller validates the complete candidate,
//! backs up original bytes, then publishes advanced first and main last.

use toml_edit::{DocumentMut, Item, Table};

/// Documents prepared for publication. An absent advanced file stays absent
/// when migration has no advanced settings to move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMigration {
    /// New main configuration bytes, the completion marker.
    pub main: Vec<u8>,
    /// New advanced configuration bytes, or no advanced file.
    pub advanced: Option<Vec<u8>>,
}

/// A field-specific preparation error. Values are deliberately not included:
/// source URLs and node URIs may contain credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationError(pub String);

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MigrationError {}

fn parse(bytes: &[u8], name: &str) -> Result<DocumentMut, MigrationError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| MigrationError(format!("{name}: invalid UTF-8")))?;
    text.parse()
        .map_err(|_| MigrationError(format!("{name}: invalid TOML")))
}

fn table<'a>(
    parent: &'a mut Table,
    key: &str,
    path: &str,
) -> Result<&'a mut Table, MigrationError> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    if parent[key].as_inline_table().is_some() {
        let Item::Value(toml_edit::Value::InlineTable(inline)) = parent.remove(key).unwrap() else {
            unreachable!();
        };
        parent.insert(key, Item::Table(inline.into_table()));
    }
    parent[key]
        .as_table_mut()
        .ok_or_else(|| MigrationError(format!("{path}: expected a table")))
}

fn semantic(item: &Item) -> Result<toml::Value, MigrationError> {
    let mut doc = DocumentMut::new();
    doc.insert("value", item.clone());
    let value: toml::Value = toml::from_str(&doc.to_string())
        .map_err(|_| MigrationError("cannot compare migrated value".into()))?;
    Ok(value["value"].clone())
}

fn merge(dest: &mut Table, key: &str, value: Item, path: &str) -> Result<(), MigrationError> {
    if let Some(existing) = dest.get(key) {
        if semantic(existing)? != semantic(&value)? {
            return Err(MigrationError(format!(
                "{path}: conflicting explicit values"
            )));
        }
    } else {
        dest.insert(key, value);
    }
    Ok(())
}

/// Prepare a structural migration, returning `None` for already-current files.
///
/// Explicit destination values are reused only when equal, permitting retries
/// after the advanced file was published but before the main file was replaced.
/// This checks TOML structure; callers must validate the final candidate against
/// the current schema and referenced files before writing either output.
/// `legacy_app_default` must come from positively identified prior Rust-module
/// installation metadata. It preserves the old whitelist default for old files
/// without structural legacy keys. An existing `nodes.sources` completion
/// marker takes precedence over this provenance on an interrupted-install retry.
pub fn prepare(
    main: &[u8],
    advanced: Option<&[u8]>,
    legacy_app_default: bool,
) -> Result<Option<PreparedMigration>, MigrationError> {
    let mut main_doc = parse(main, "flux.toml")?;
    let mut advanced_doc = advanced
        .map(|b| parse(b, "advanced.toml"))
        .transpose()?
        .unwrap_or_default();
    let has_completion_marker = main_doc
        .get("nodes")
        .and_then(Item::as_table_like)
        .is_some_and(|table| table.contains_key("sources"));
    let legacy = (legacy_app_default && !has_completion_marker)
        || main_doc.contains_key("subscription")
        || main_doc
            .get("nodes")
            .and_then(Item::as_table_like)
            .is_some_and(|t| t.contains_key("list"));
    if !legacy {
        return Ok(None);
    }
    let old_subscription = main_doc.remove("subscription");
    let mut subscription = match old_subscription {
        None => Table::new(),
        Some(Item::Table(t)) => t,
        Some(Item::Value(toml_edit::Value::InlineTable(t))) => t.into_table(),
        Some(_) => return Err(MigrationError("subscription: expected a table".into())),
    };
    let nodes = table(main_doc.as_table_mut(), "nodes", "nodes")?;
    let mut sources = match nodes.remove("list") {
        None => toml_edit::Array::new(),
        Some(Item::Value(toml_edit::Value::Array(a))) => a,
        Some(_) => return Err(MigrationError("nodes.list: expected an array".into())),
    };
    if sources.iter().any(|v| v.as_str().is_none()) {
        return Err(MigrationError("nodes.list: expected strings".into()));
    }
    if let Some(url) = subscription.remove("url") {
        let url = url
            .as_str()
            .ok_or_else(|| MigrationError("subscription.url: expected a string".into()))?;
        if !url.is_empty() && !sources.iter().any(|v| v.as_str() == Some(url)) {
            sources.push(url);
        }
    }
    merge(
        nodes,
        "sources",
        Item::Value(sources.into()),
        "nodes.sources",
    )?;

    let mut moved_advanced = false;
    for (section, keys) in [
        ("fetch", &["interval", "timeout", "retries"][..]),
        (
            "refine",
            &["exclude_pattern", "rename", "strip_emoji", "max_tag_length"][..],
        ),
    ] {
        for key in keys {
            if let Some(value) = subscription.remove(key) {
                let nodes = table(advanced_doc.as_table_mut(), "nodes", "nodes")?;
                let dest = table(nodes, section, &format!("nodes.{section}"))?;
                merge(dest, key, value, &format!("nodes.{section}.{key}"))?;
                moved_advanced = true;
            }
        }
    }
    if let Some(refine) = subscription.remove("refine") {
        let refine = refine
            .as_table_like()
            .ok_or_else(|| MigrationError("subscription.refine: expected a table".into()))?;
        for (key, value) in refine.iter() {
            let nodes = table(advanced_doc.as_table_mut(), "nodes", "nodes")?;
            let dest = table(nodes, "refine", "nodes.refine")?;
            merge(dest, key, value.clone(), &format!("nodes.refine.{key}"))?;
            moved_advanced = true;
        }
    }
    if let Some((key, _)) = subscription.iter().next() {
        return Err(MigrationError(format!(
            "subscription.{key}: unsupported legacy field"
        )));
    }
    let apps = table(main_doc.as_table_mut(), "apps", "apps")?;
    if !apps.contains_key("mode") {
        apps.insert("mode", toml_edit::value("whitelist"));
    }
    Ok(Some(PreparedMigration {
        main: main_doc.to_string().into_bytes(),
        advanced: if moved_advanced {
            Some(advanced_doc.to_string().into_bytes())
        } else {
            advanced.map(<[u8]>::to_vec)
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepare(
        main: &[u8],
        advanced: Option<&[u8]>,
    ) -> Result<Option<PreparedMigration>, MigrationError> {
        super::prepare(main, advanced, false)
    }

    fn value(bytes: &[u8]) -> toml::Value {
        toml::from_str(std::str::from_utf8(bytes).unwrap()).unwrap()
    }

    #[test]
    fn current_configuration_is_byte_exact_noop() {
        for main in [
            b"# current\n[nodes]\nsources = []\n".as_slice(),
            b"# explicitly empty\n",
        ] {
            assert_eq!(prepare(main, Some(b"# advanced\n")).unwrap(), None);
        }
    }

    #[test]
    fn moves_both_refinement_forms_and_preserves_selection_and_comments() {
        let main = b"# user heading\n[apps]\nlist = ['org.example'] # retain\n[nodes]\nlist = ['@nodes.txt']\n[subscription]\nurl = 'https://example.invalid/sub'\ninterval = 0 # manual\nstrip_emoji = false\n[subscription.refine]\nmax_tag_length = 64\n";
        let output = prepare(main, None).unwrap().unwrap();
        let m = value(&output.main);
        assert_eq!(m["apps"]["mode"].as_str(), Some("whitelist"));
        assert_eq!(m["nodes"]["sources"].as_array().unwrap().len(), 2);
        assert!(String::from_utf8_lossy(&output.main).contains("# retain"));
        assert!(String::from_utf8_lossy(&output.main).contains("# user heading"));
        let a = value(output.advanced.as_ref().unwrap());
        assert_eq!(a["nodes"]["fetch"]["interval"].as_integer(), Some(0));
        assert_eq!(a["nodes"]["refine"]["strip_emoji"].as_bool(), Some(false));
        assert_eq!(
            a["nodes"]["refine"]["max_tag_length"].as_integer(),
            Some(64)
        );
        assert_eq!(
            prepare(&output.main, output.advanced.as_deref()).unwrap(),
            None
        );
        assert_eq!(
            prepare(main, output.advanced.as_deref()).unwrap().unwrap(),
            output
        );
    }

    #[test]
    fn conflicts_reject_entire_preparation() {
        let main = b"[subscription]\ninterval = 20\n";
        let advanced = b"[nodes.fetch]\ninterval = 10\n";
        assert!(prepare(main, Some(advanced))
            .unwrap_err()
            .0
            .contains("nodes.fetch.interval"));
        assert!(prepare(b"[nodes]\nlist = ['@a']\nsources = ['@b']\n", None)
            .unwrap_err()
            .0
            .contains("nodes.sources"));
        assert!(prepare(
            b"[subscription]\nstrip_emoji = true\n[subscription.refine]\nstrip_emoji = false\n",
            None
        )
        .unwrap_err()
        .0
        .contains("nodes.refine.strip_emoji"));
    }

    #[test]
    fn explicit_mode_and_unrelated_advanced_bytes_survive() {
        let output = prepare(
            b"[apps]\nmode = 'blacklist'\n[nodes]\nlist = []\n",
            Some(b"# untouched\n[log]\nretain=3\n"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            value(&output.main)["apps"]["mode"].as_str(),
            Some("blacklist")
        );
        assert_eq!(
            output.advanced.as_deref(),
            Some(b"# untouched\n[log]\nretain=3\n".as_slice())
        );
    }

    #[test]
    fn inline_tables_and_ordered_rename_rules_migrate() {
        let main = b"apps = { list = [] }\nnodes = { list = ['@nodes.txt'] }\nsubscription = { refine = { rename = [{ match = 'first', replace = 'second' }, { match = 'second', replace = 'third' }] } }\n";
        let output = prepare(main, None).unwrap().unwrap();
        let advanced = value(output.advanced.as_ref().unwrap());
        let rules = advanced["nodes"]["refine"]["rename"].as_array().unwrap();
        assert_eq!(rules[0]["match"].as_str(), Some("first"));
        assert_eq!(rules[1]["match"].as_str(), Some("second"));
        assert_eq!(
            prepare(main, output.advanced.as_deref()).unwrap().unwrap(),
            output
        );
    }

    #[test]
    fn legacy_unknown_fields_and_wrong_shapes_are_not_discarded() {
        for main in [
            b"[subscription]\nunknown = 1\n".as_slice(),
            b"subscription = 1\n",
            b"[nodes]\nlist = [1]\n",
            b"[subscription]\nurl = false\n",
        ] {
            assert!(prepare(main, None).is_err());
        }
    }

    #[test]
    fn installation_provenance_preserves_unmarked_legacy_app_default_once() {
        for main in [b"# legacy empty\n".as_slice(), b"[apps]\nlist=[]\n"] {
            assert_eq!(super::prepare(main, None, false).unwrap(), None);
            let output = super::prepare(main, None, true).unwrap().unwrap();
            let parsed = value(&output.main);
            assert_eq!(parsed["apps"]["mode"].as_str(), Some("whitelist"));
            assert!(parsed["nodes"]["sources"].as_array().unwrap().is_empty());
            assert_eq!(
                super::prepare(&output.main, output.advanced.as_deref(), true).unwrap(),
                None
            );
        }
        let current = b"# completed schema\n[nodes]\nsources=[]\n";
        assert_eq!(super::prepare(current, None, true).unwrap(), None);
    }
}
