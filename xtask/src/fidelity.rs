//! Compares the load-bearing content of two revisions of one document.
//!
//! Re-issuing a document — translating it, folding revisions into it,
//! reorganising it — regenerates prose wholesale, and wholesale regeneration
//! loses the refinements that earlier rounds paid for. The result reads well,
//! which is exactly why the loss is hard to see.
//!
//! Prose cannot be compared mechanically, but four things in it can, and they
//! are the four that took the most work to get right:
//!
//! 1. evidence citations (`FileSystem.kt:524-625`),
//! 2. cross-references (`§8.5.3`),
//! 3. decision identifiers (`D18`, `C9`, `Q10`, `R091-05`),
//! 4. numeric and address constants (`65536`, `198.51.100.1`, `0x4000`).
//!
//! A re-issue may deliberately drop or add any of these. The tool reports the
//! difference and lets the author account for it; it is not a gate.

use std::collections::BTreeSet;
use std::path::Path;

use crate::util;

/// One comparable dimension of a document.
struct Facet {
    name: &'static str,
    extract: fn(&str) -> BTreeSet<String>,
}

const FACETS: [Facet; 4] = [
    Facet {
        name: "evidence citations",
        extract: citations,
    },
    Facet {
        name: "cross-references",
        extract: sections,
    },
    Facet {
        name: "identifiers",
        extract: identifiers,
    },
    Facet {
        name: "constants",
        extract: constants,
    },
];

pub fn run(before: &str, after: &str) -> Result<(), String> {
    let root = util::repo_root();
    let old = util::read_text(&resolve(&root, before))?;
    let new = util::read_text(&resolve(&root, after))?;

    let mut total_lost = 0usize;
    for facet in &FACETS {
        let old_set = (facet.extract)(&old);
        let new_set = (facet.extract)(&new);
        let lost: Vec<&String> = old_set.difference(&new_set).collect();
        let gained = new_set.difference(&old_set).count();

        println!(
            "fidelity: {:<20} {} before, {} after, {} dropped, {} added",
            facet.name,
            old_set.len(),
            new_set.len(),
            lost.len(),
            gained
        );
        for item in &lost {
            println!("  dropped: {item}");
        }
        total_lost += lost.len();
    }

    if total_lost == 0 {
        println!("fidelity: nothing dropped");
    } else {
        println!(
            "fidelity: {total_lost} item(s) present in {before} and absent from {after} — \
             account for each one"
        );
    }
    Ok(())
}

fn resolve(root: &Path, arg: &str) -> std::path::PathBuf {
    let direct = Path::new(arg);
    if direct.is_absolute() {
        direct.to_path_buf()
    } else {
        root.join(arg)
    }
}

/// `tproxy.sh:980-1012`, `FileSystem.kt:524`: a source file and a line span.
/// Requires an extension so that `20260:100` style numbers do not qualify.
fn citations(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for token in tokens(text) {
        let Some((file, lines)) = token.rsplit_once(':') else {
            continue;
        };
        let is_span = !lines.is_empty()
            && lines
                .chars()
                .all(|c| c.is_ascii_digit() || c == '-' || c == '\u{2013}');
        let has_ext = file
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && ext.chars().all(|c| c.is_ascii_alphabetic()));
        if is_span && has_ext && lines.chars().any(|c| c.is_ascii_digit()) {
            found.insert(token.to_string());
        }
    }
    found
}

/// `§8.5.3`, `§16`. Normalised to the number alone so that a re-issue may
/// change the sigil without registering as a loss.
fn sections(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find('\u{a7}') {
        let after = &rest[at + '\u{a7}'.len_utf8()..];
        let number: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let number = number.trim_end_matches('.');
        if !number.is_empty() {
            found.insert(number.to_string());
        }
        rest = after;
    }
    found
}

/// `D18`, `C9`, `Q10`, `PHIL-4`, `GOV-7.1`, `AUTH-6`, `R091-05`.
fn identifiers(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for token in tokens(text) {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let head: String = token.chars().take_while(char::is_ascii_alphabetic).collect();
        let tail = &token[head.len()..];
        let is_id = match head.as_str() {
            "D" | "C" | "Q" => tail.chars().all(|c| c.is_ascii_digit()) && !tail.is_empty(),
            "PHIL" | "GOV" | "AUTH" | "R" => {
                tail.starts_with('-') || tail.starts_with(|c: char| c.is_ascii_digit())
            }
            _ => false,
        };
        if is_id && head != "R" {
            found.insert(token.to_string());
        } else if head == "R" && token.starts_with("R09") {
            found.insert(token.to_string());
        }
    }
    found
}

/// Numbers that a re-issue must not quietly change: capacities, ports,
/// addresses, hex constants. Small integers carry no such weight and are
/// skipped, or every "two" and "three" in the prose would drown the signal.
fn constants(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for token in tokens(text) {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if token.starts_with("0x") && token.len() > 2 {
            found.insert(token.to_ascii_lowercase());
            continue;
        }
        // Dotted quads and prefix lengths keep their punctuation; bare integers
        // must be four digits or more to count.
        let looks_addressy = token.contains('.') && token.split('.').count() == 4;
        let digits_only = !token.is_empty() && token.chars().all(|c| c.is_ascii_digit());
        if looks_addressy && token.split('.').all(|p| p.parse::<u16>().is_ok()) {
            found.insert(token.to_string());
        } else if digits_only && token.len() >= 4 {
            found.insert(token.to_string());
        }
    }
    found
}

/// Split on whitespace and markdown furniture, keeping `:`, `.`, `-` and `/`
/// because the facets above are built out of them.
fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        c.is_whitespace() || matches!(c, '`' | '|' | '(' | ')' | '[' | ']' | '*' | '"' | ',' | '，')
    })
    .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn citations_need_a_file_extension_and_a_line_span() {
        let found = citations("see `tproxy.sh:980-1012` and FileSystem.kt:524 but not 20260:100");
        assert!(found.contains("tproxy.sh:980-1012"));
        assert!(found.contains("FileSystem.kt:524"));
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn sections_normalise_away_the_sigil() {
        let found = sections("§8.5.3 and §16, plus §22.2.1");
        assert!(found.contains("8.5.3"));
        assert!(found.contains("16"));
        assert!(found.contains("22.2.1"));
    }

    #[test]
    fn identifiers_cover_every_namespace() {
        let found = identifiers("D18 C9 Q10 PHIL-4 GOV-7.1 AUTH-6 R091-05 and Rust");
        for id in ["D18", "C9", "Q10", "PHIL-4", "GOV-7.1", "AUTH-6", "R091-05"] {
            assert!(found.contains(id), "missing {id} in {found:?}");
        }
        assert!(!found.contains("Rust"));
    }

    #[test]
    fn constants_skip_small_integers() {
        let found = constants("65536 and 198.51.100.1 and 0x4000, but not 53 or 20");
        assert!(found.contains("65536"));
        assert!(found.contains("198.51.100.1"));
        assert!(found.contains("0x4000"));
        assert!(!found.contains("53"));
    }

    #[test]
    fn a_faithful_reissue_drops_nothing() {
        let before = "§8.5 cites `tproxy.sh:980-1012`, overturned by D18, cap 65536.";
        let after = "Section §8.5 rests on `tproxy.sh:980-1012` (D18); the cap is 65536 entries.";
        for facet in &FACETS {
            let old = (facet.extract)(before);
            let new = (facet.extract)(after);
            assert!(
                old.difference(&new).next().is_none(),
                "{} lost {:?}",
                facet.name,
                old.difference(&new).collect::<Vec<_>>()
            );
        }
    }
}
