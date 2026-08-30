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
//! 4. numeric constants (`65536`, `198.51.100.1/24`, `0x4000`, `16 KiB`).
//!
//! Everything here scans for a pattern and checks that its neighbours are
//! boundaries, rather than splitting the text into tokens first. Splitting is
//! what an English-language draft of this file did, and it made the tool blind
//! on the documents it exists to protect: these are Chinese, `、` is the
//! ordinary list separator, and `D20、D21` is one token to any splitter that
//! only knows ASCII. Since no CJK character is ASCII-alphanumeric, scanning
//! gets that case right without enumerating punctuation.
//!
//! False positives are cheap here and false negatives are not. A year like
//! `2026` counts as a constant, but it appears on both sides of a faithful
//! re-issue and so cancels; a dropped capacity that goes unreported does not.
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

/// A match may start or end here. Every CJK character and every piece of CJK
/// punctuation satisfies this, which is the whole point.
fn boundary(text: &[char], at: usize) -> bool {
    match text.get(at) {
        None => true,
        Some(c) => !c.is_ascii_alphanumeric(),
    }
}

fn run_of(text: &[char], from: usize, accept: impl Fn(char) -> bool) -> usize {
    let mut end = from;
    while end < text.len() && accept(text[end]) {
        end += 1;
    }
    end
}

fn slice(text: &[char], from: usize, to: usize) -> String {
    text[from..to].iter().collect()
}

/// `tproxy.sh:980-1012`, `net/core/skbuff.c:5518-5523`: a source file and a
/// line span. Requires an extension so that `20260:100` does not qualify, and
/// tolerates whatever punctuation follows, since these usually sit mid-sentence
/// in Chinese prose where the terminator is `。` or `、`.
fn citations(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = BTreeSet::new();

    for colon in 0..chars.len() {
        if chars[colon] != ':' {
            continue;
        }
        let first = run_of(&chars, colon + 1, |c| c.is_ascii_digit());
        if first == colon + 1 {
            continue;
        }
        // Optional `-1012` or `–1012` continuation of the span.
        let mut end = first;
        if matches!(chars.get(end), Some('-' | '\u{2013}')) {
            let tail = run_of(&chars, end + 1, |c| c.is_ascii_digit());
            if tail > end + 1 {
                end = tail;
            }
        }

        let mut start = colon;
        while start > 0
            && (chars[start - 1].is_ascii_alphanumeric()
                || matches!(chars[start - 1], '.' | '_' | '-' | '/'))
        {
            start -= 1;
        }
        let path = slice(&chars, start, colon);
        if has_source_extension(&path) {
            found.insert(format!("{path}{}", slice(&chars, colon, end)));
        }
    }
    found
}

/// A trailing `.ext` of one to four ASCII letters, on a non-empty stem.
fn has_source_extension(path: &str) -> bool {
    match path.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && !ext.is_empty()
                && ext.len() <= 4
                && ext.chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    }
}

/// `§8.5.3`, `§16`. Normalised to the number alone so that a re-issue may
/// change the sigil, and de-escaped so that `§8\.5\.3` — which appears inside
/// `rg` examples — reads the same as the plain form.
fn sections(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = BTreeSet::new();

    for at in 0..chars.len() {
        if chars[at] != '\u{a7}' {
            continue;
        }
        let mut number = String::new();
        let mut cursor = at + 1;
        while let Some(&c) = chars.get(cursor) {
            match c {
                '\\' => cursor += 1, // escape before `.`; drop it and keep going
                c if c.is_ascii_digit() || c == '.' => {
                    number.push(c);
                    cursor += 1;
                }
                _ => break,
            }
        }
        let number = number.trim_end_matches('.');
        if !number.is_empty() {
            found.insert(number.to_string());
        }
    }
    found
}

/// `D18`, `C9`, `Q10`, `PHIL-4`, `GOV-7.1`, `AUTH-6`, `R091-05`.
///
/// Scanning rather than splitting is what makes `D20、D21` and `C8/C10/C11`
/// two and three matches respectively instead of one unrecognisable token.
fn identifiers(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = BTreeSet::new();

    for at in 0..chars.len() {
        if !boundary(&chars, at.wrapping_sub(1)) && at > 0 {
            continue;
        }
        let letters = run_of(&chars, at, |c| c.is_ascii_uppercase());
        if letters == at {
            continue;
        }
        let head = slice(&chars, at, letters);
        let digits = run_of(&chars, letters, |c| c.is_ascii_digit());

        let end = match head.as_str() {
            // `D18`, `C9`, `Q10`: letter then a small number, nothing else.
            "D" | "C" | "Q" if digits > letters && digits - letters <= 3 => digits,
            // `R091-05`: the version-scoped revision namespace.
            "R" if digits - letters == 3 && slice(&chars, letters, digits).starts_with("09") => {
                match chars.get(digits) {
                    Some('-') => {
                        let tail = run_of(&chars, digits + 1, |c| c.is_ascii_digit());
                        if tail > digits + 1 {
                            tail
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                }
            }
            // `PHIL-4`, `GOV-7.1`, `AUTH-6`: dash, then a dotted number.
            "PHIL" | "GOV" | "AUTH" if chars.get(letters) == Some(&'-') => {
                let tail = run_of(&chars, letters + 1, |c| c.is_ascii_digit() || c == '.');
                if tail > letters + 1 {
                    tail
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        if boundary(&chars, end) {
            found.insert(slice(&chars, at, end).trim_end_matches('.').to_string());
        }
    }
    found
}

/// Numbers a re-issue must not quietly change: capacities, ports, addresses,
/// prefixes, hex constants, and sizes carrying a unit.
///
/// The unit case is why small integers are not simply skipped. `16 KiB`
/// silently becoming `4 KiB` would be the most consequential single-character
/// change possible in this project — it is the base-page-size boundary the
/// whole packaging gate exists to defend — and both numbers are too small to
/// survive a naive digit-count filter.
fn constants(text: &str) -> BTreeSet<String> {
    const UNITS: [&str; 8] = ["KiB", "MiB", "GiB", "KB", "MB", "GB", "ms", "µs"];
    let chars: Vec<char> = text.chars().collect();
    let mut found = BTreeSet::new();

    let mut at = 0;
    while at < chars.len() {
        if !(at == 0 || boundary(&chars, at - 1)) || !chars[at].is_ascii_digit() {
            at += 1;
            continue;
        }

        // `0x4000`
        if chars[at] == '0' && matches!(chars.get(at + 1), Some('x' | 'X')) {
            let end = run_of(&chars, at + 2, |c| c.is_ascii_hexdigit());
            if end > at + 2 {
                found.insert(slice(&chars, at, end).to_ascii_lowercase());
                at = end;
                continue;
            }
        }

        let digits = run_of(&chars, at, |c| c.is_ascii_digit());
        let mut end = digits;
        let mut kind = Kind::Bare;

        // `198.51.100.1`, optionally `/24`
        if chars.get(digits) == Some(&'.') {
            let dotted = run_of(&chars, at, |c| c.is_ascii_digit() || c == '.');
            let body = slice(&chars, at, dotted);
            if body.split('.').count() == 4 && body.split('.').all(|p| p.parse::<u8>().is_ok()) {
                end = dotted;
                kind = Kind::Address;
            }
        } else if chars.get(digits) == Some(&':') {
            // `2001:db8::/48` — hex groups and colons, needing at least one colon.
            let v6 = run_of(&chars, at, |c| c.is_ascii_hexdigit() || c == ':');
            let body = slice(&chars, at, v6);
            if body.contains(':') && !body.ends_with(':') || body.contains("::") {
                end = v6;
                kind = Kind::Address;
            }
        }

        if kind == Kind::Address && chars.get(end) == Some(&'/') {
            let prefix = run_of(&chars, end + 1, |c| c.is_ascii_digit());
            if prefix > end + 1 {
                end = prefix;
            }
        }

        // `16 KiB`, `4 KiB` — a unit makes any magnitude load-bearing.
        if kind == Kind::Bare {
            let after_space = if chars.get(end) == Some(&' ') {
                end + 1
            } else {
                end
            };
            let word = run_of(&chars, after_space, |c| {
                c.is_ascii_alphabetic() || c == '\u{b5}'
            });
            let unit = slice(&chars, after_space, word);
            if UNITS.contains(&unit.as_str()) {
                found.insert(format!("{} {unit}", slice(&chars, at, digits)));
                at = word;
                continue;
            }
        }

        match kind {
            Kind::Address => {
                found.insert(slice(&chars, at, end));
            }
            // A bare number is only worth tracking once it is big enough to be
            // a capacity or a port rather than a count in the prose.
            Kind::Bare if digits - at >= 4 && boundary(&chars, end) => {
                found.insert(slice(&chars, at, end));
            }
            Kind::Bare => {}
        }
        at = end.max(at + 1);
    }
    found
}

#[derive(PartialEq)]
enum Kind {
    Bare,
    Address,
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
    fn citations_survive_chinese_punctuation() {
        let found = citations("依据 net/core/skbuff.c:5518-5523、FileSystem.kt:524-625。");
        assert!(found.contains("net/core/skbuff.c:5518-5523"), "{found:?}");
        assert!(found.contains("FileSystem.kt:524-625"), "{found:?}");
    }

    #[test]
    fn sections_normalise_the_sigil_and_escapes() {
        let found = sections("§8.5.3 和 §16，还有 §22.2.1 与 rg 例子里的 §8\\.5\\.3");
        assert!(found.contains("8.5.3"));
        assert!(found.contains("16"));
        assert!(found.contains("22.2.1"));
        assert_eq!(found.len(), 3, "escaped form must fold into the plain one");
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
    fn identifiers_split_on_chinese_and_ascii_separators() {
        let found = identifiers("随后被 D20、D21 覆盖；C8/C10/C11 已延期，见 R091-03。");
        for id in ["D20", "D21", "C8", "C10", "C11", "R091-03"] {
            assert!(found.contains(id), "missing {id} in {found:?}");
        }
    }

    #[test]
    fn constants_cover_addresses_prefixes_and_units() {
        let found = constants("65536 与 198.51.100.1，段 198.18.0.0/15 和 2001:db8:f::/48，0x4000，对齐 16 KiB，端口 61000");
        for c in [
            "65536",
            "198.51.100.1",
            "198.18.0.0/15",
            "2001:db8:f::/48",
            "0x4000",
            "16 KiB",
            "61000",
        ] {
            assert!(found.contains(c), "missing {c} in {found:?}");
        }
    }

    #[test]
    fn a_page_size_regression_is_visible() {
        let before = constants("每个 LOAD 段必须 16 KiB 对齐");
        let after = constants("每个 LOAD 段必须 4 KiB 对齐");
        assert!(
            before.difference(&after).next().is_some(),
            "16 KiB becoming 4 KiB must register as a loss"
        );
    }

    #[test]
    fn a_faithful_reissue_drops_nothing() {
        let before = "§8.5 引用 `tproxy.sh:980-1012`，被 D18 推翻，容量 65536，对齐 16 KiB。";
        let after = "Section §8.5 rests on `tproxy.sh:980-1012` (D18); the cap is 65536 and \
                     alignment is 16 KiB.";
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
