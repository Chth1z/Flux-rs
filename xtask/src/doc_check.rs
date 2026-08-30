//! `cargo xtask doc-check` — the seven mechanical documentation checks of
//! `docs/plan/implementation.md` §17.4 (exit criterion 6).
//!
//! Each one has caught a real defect before it was automated, which is why it
//! exists (that section, closing paragraph):
//!
//! 1. The chapter map in `docs/index.md` points at files that exist and that
//!    really carry the `# 第 N 部分` heading (the map once pointed at files
//!    that had been moved out).
//! 2. Every relative markdown link under `docs/` resolves.
//! 3. Every identifier cited anywhere resolves, and no document outside the
//!    blueprint claims a `§` number. Both halves were violated on the day the
//!    rule was written: `ux.md` numbered itself §1–§8 against the blueprint's
//!    §1–§8, `philosophy.md` did the same, and a citation to a philosophy §8
//!    outlived the section it named.
//! 4. `flux_abi.h`'s `FLUX_SEC_*` and `abi.rs`'s `SEC_*` agree byte-for-byte
//!    and every section name is in the set measured usable on the baseline
//!    device (`docs/history/phase0.md` §16.8.2).
//! 5. The overturn numbering in `docs/history/review-log.md` is continuous
//!    and consistent with the total the blueprint claims (the count once
//!    existed in three contradictory versions: 5, 7 and 8).

use crate::{cdefs, util};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run() -> Result<(), String> {
    let root = util::repo_root();
    let mut failures: Vec<String> = Vec::new();

    let map = check_chapter_map(&root, &mut failures)?;
    check_links(&root, &mut failures)?;
    check_identifiers(&root, &map, &mut failures)?;
    check_sections(&root, &mut failures)?;
    check_overturns(&root, &mut failures)?;
    let commands = check_xtask_commands(&root, &mut failures)?;
    println!("doc-check: commands — {commands} `cargo xtask` citations resolved");

    if failures.is_empty() {
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("doc-check: {failure}");
        }
        Err(format!("{} documentation defect(s)", failures.len()))
    }
}

// --------------------------------------------------------- 1. chapter map

/// Parse the `## 章节编号 → 文件` table in `docs/index.md` and verify each
/// row: the file exists and carries a level-1 `# 第 N 部分：<title>` heading
/// for that part number. The 内容 column is a description, not the heading
/// text, so the mechanical anchor is the globally stable part number
/// (AUTH-1.1), not a string comparison against prose.
fn check_chapter_map(root: &Path, failures: &mut Vec<String>) -> Result<Vec<u32>, String> {
    let readme_path = root.join("docs/index.md");
    let readme = util::read_text(&readme_path)?;

    let mut rows: Vec<(u32, String, usize)> = Vec::new();
    let mut in_table_section = false;
    for (idx, line) in readme.lines().enumerate() {
        if line.starts_with("## ") {
            in_table_section = line.trim().ends_with("章节编号 → 文件");
            continue;
        }
        if !in_table_section || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // ["", "§0", "内容", "`file`", ""] — skip the header and ruler rows.
        if cells.len() < 5 {
            continue;
        }
        let Some(number) = cells[1].strip_prefix('§') else {
            continue;
        };
        let Ok(number) = number.trim().parse::<u32>() else {
            failures.push(format!(
                "docs/index.md:{}: chapter row `{}` has an unparsable part number",
                idx + 1,
                cells[1]
            ));
            continue;
        };
        rows.push((number, cells[3].trim_matches('`').to_string(), idx + 1));
    }

    if rows.is_empty() {
        failures.push("docs/index.md: chapter map table not found".into());
        return Ok(Vec::new());
    }

    // Numbering must be dense: every part number exactly once, no gaps.
    for pair in rows.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if next.0 != prev.0 + 1 {
            failures.push(format!(
                "docs/index.md:{}: chapter map jumps from §{} to §{}",
                next.2, prev.0, next.0
            ));
        }
    }

    let mut file_cache: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut checked = 0usize;
    for (number, file, line) in &rows {
        let path = root.join("docs").join(file);
        if !path.is_file() {
            failures.push(format!(
                "docs/index.md:{line}: §{number} maps to `{file}`, which does not exist"
            ));
            continue;
        }
        let text = match file_cache.entry(path.clone()) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(util::read_text(&path)?),
        };
        if heading_for_part(text, *number) {
            checked += 1;
        } else {
            failures.push(format!(
                "docs/index.md:{line}: §{number} maps to `{file}`, but that file has no \
                 `# 第 {number} 部分：…` heading"
            ));
        }
    }
    println!(
        "doc-check: chapter map — {} rows (§{}–§{}), {checked} headings verified",
        rows.len(),
        rows.first().map(|r| r.0).unwrap_or(0),
        rows.last().map(|r| r.0).unwrap_or(0),
    );
    Ok(rows.iter().map(|r| r.0).collect())
}

// ---------------------------------------------------- 2. identifier registry

/// Every prefix registered in `docs/index.md` §1, and the heading pattern that
/// defines one of its identifiers.
const NAMESPACES: [(&str, &str); 3] = [
    ("PHIL", "docs/philosophy.md"),
    ("GOV", "docs/governance.md"),
    ("AUTH", "docs/authoring.md"),
];

/// Two properties the identifier system promises and cannot enforce by hand:
///
/// 1. every `PREFIX-N` cited anywhere resolves to a heading that exists;
/// 2. no document outside the blueprint namespace claims a `§` number.
///
/// Both were violated the day the rule was written: `philosophy.md` numbered
/// its own sections §0–§7, colliding with the blueprint, and a citation to its
/// §8 outlived the section itself.
fn check_identifiers(root: &Path, parts: &[u32], failures: &mut Vec<String>) -> Result<(), String> {
    // Which identifiers actually exist, per namespace.
    let mut defined: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (prefix, file) in NAMESPACES {
        let text = util::read_text(&root.join(file))?;
        let mut ids = Vec::new();
        for line in text.lines() {
            let Some(rest) = line
                .strip_prefix("## ")
                .or_else(|| line.strip_prefix("### "))
            else {
                continue;
            };
            let Some(tail) = rest.strip_prefix(prefix).and_then(|t| t.strip_prefix('-')) else {
                continue;
            };
            let id: String = tail
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !id.is_empty() {
                ids.push(id);
            }
        }
        if ids.is_empty() {
            failures.push(format!("{file}: defines no {prefix}-N headings at all"));
        }
        defined.insert(prefix, ids);
    }

    let files = collect_checked_markdown(root)?;

    // A meta document must not use the section sign for its own sections.
    for (_, file) in NAMESPACES {
        let path = root.join(file);
        let text = util::read_text(&path)?;
        for (idx, line) in text.lines().enumerate() {
            if line.starts_with("## ") || line.starts_with("### ") {
                if let Some(rest) = line.trim_start_matches('#').trim_start().strip_prefix('§') {
                    failures.push(format!(
                        "{file}:{}: heading claims §{} — the section sign belongs to the \
                         blueprint alone (index.md §1)",
                        idx + 1,
                        rest.split_whitespace().next().unwrap_or("?")
                    ));
                }
            }
        }
    }

    // Every cited identifier must resolve.
    let mut checked = 0usize;
    for file in &files {
        let text = util::read_text(file)?;
        let shown = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string();
        for (idx, line) in text.lines().enumerate() {
            for (prefix, ids) in &defined {
                for cited in cited_ids(line, prefix) {
                    checked += 1;
                    if !ids.contains(&cited) {
                        failures.push(format!(
                            "{shown}:{}: {prefix}-{cited} does not exist",
                            idx + 1
                        ));
                    }
                }
            }
            // Blueprint parts: only the top-level number is registered.
            for cited in cited_sections(line) {
                checked += 1;
                if !parts.contains(&cited) {
                    failures.push(format!(
                        "{shown}:{}: §{cited} is not a registered part (index.md §4)",
                        idx + 1
                    ));
                }
            }
        }
    }
    check_decision_status(root, failures)?;

    println!(
        "doc-check: identifiers — {} namespaces registered, {checked} references resolved",
        defined.len() + 1
    );
    Ok(())
}

/// Each decision namespace: its prefix, the document that defines it, and the
/// heading of that document's status registry.
const DECISION_REGISTRIES: [(&str, &str, &str); 2] = [
    ("D", "docs/history/review-log.md", "D 条目状态登记"),
    (
        "C",
        "docs/history/rejected-and-deferred.md",
        "C 条目状态登记",
    ),
];

/// The only statuses a decision may carry.
const DECISION_STATUSES: [&str; 4] = ["current", "superseded", "deferred", "executed"];

/// The set of decisions a document defines must equal the set its status
/// registry covers, every status must come from the fixed vocabulary, and
/// anything superseded must name what replaced it.
///
/// Without this, a decision that has been replaced reads exactly like one that
/// still binds. That is how settled questions get re-litigated: R092-03 was
/// decided, reversed, and reversed back inside one day.
///
/// Both directions of the equality matter, and an earlier version of this
/// check asserted only one. It also treated the status vocabulary as a filter
/// for deciding which rows were status rows, so a misspelled status made a row
/// invisible rather than wrong, and a single `| D1-D99 | current |` row could
/// silently claim every decision was current. The registry is now delimited by
/// its heading: inside that section every table row is a status row and must
/// parse, which leaves a typo nowhere to hide.
fn check_decision_status(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    for (prefix, file, heading) in DECISION_REGISTRIES {
        let text = util::read_text(&root.join(file))?;
        let Some((first, last)) = registry_bounds(&text, heading) else {
            failures.push(format!("{file}: has no `{heading}` section"));
            continue;
        };

        let lines: Vec<&str> = text.lines().collect();
        let mut covered: Vec<u32> = Vec::new();

        for (offset, line) in lines[first..last].iter().enumerate() {
            let number = first + offset + 1;
            let Some(cells) = table_row(line) else {
                continue;
            };
            if cells.len() < 3 || cells[0].starts_with("---") || !cells[0].starts_with(prefix) {
                continue; // header row, alignment row, or prose
            }
            let Some(range) = parse_id_range(cells[0], prefix) else {
                failures.push(format!(
                    "{file}:{number}: `{}` is not a {prefix} identifier or range",
                    cells[0]
                ));
                continue;
            };
            let status = cells[1];
            if !DECISION_STATUSES.contains(&status) {
                failures.push(format!(
                    "{file}:{number}: `{status}` is not one of {}",
                    DECISION_STATUSES.join(" / ")
                ));
            }
            // A replacement has to be something you can look up, so require at
            // least one alphanumeric: an em dash or a stray `？` is not one.
            if status == "superseded" && !cells[2].chars().any(|c| c.is_alphanumeric()) {
                failures.push(format!(
                    "{file}:{number}: {} is superseded but names no replacement",
                    cells[0]
                ));
            }
            for id in range {
                if covered.contains(&id) {
                    failures.push(format!(
                        "{file}:{number}: {prefix}{id} appears twice in the status registry"
                    ));
                }
                covered.push(id);
            }
        }

        let defined = defined_decisions(&lines, prefix, first, last);
        for id in &defined {
            if !covered.contains(id) {
                failures.push(format!(
                    "{file}: {prefix}{id} is defined but missing from the status registry"
                ));
            }
        }
        for id in &covered {
            if !defined.contains(id) {
                failures.push(format!(
                    "{file}: the status registry covers {prefix}{id}, which is never defined"
                ));
            }
        }
    }
    Ok(())
}

/// Line range of the registry section: from its heading to the next heading of
/// the same or higher level.
fn registry_bounds(text: &str, heading: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with('#') && l.contains(heading))?;
    let depth = lines[start].chars().take_while(|c| *c == '#').count();
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.starts_with('#') && l.chars().take_while(|c| *c == '#').count() <= depth)
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some((start, end))
}

/// Cells of a markdown table row, without the leading and trailing empties.
fn table_row(line: &str) -> Option<Vec<&str>> {
    let line = line.trim();
    if !line.starts_with('|') {
        return None;
    }
    Some(
        line.trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('*').trim())
            .collect(),
    )
}

/// Decisions the document defines, which is to say those appearing in the first
/// cell of a table row outside the registry.
///
/// Restricting this to the first cell matters in both directions: bold text is
/// used for emphasis throughout these documents, so scanning for `**D24**`
/// anywhere invented definitions out of ordinary prose, while requiring the
/// bold markers meant an unemphasised `| D18 |` row went unseen.
fn defined_decisions(lines: &[&str], prefix: &str, skip_from: usize, skip_to: usize) -> Vec<u32> {
    let mut defined = Vec::new();
    for (number, line) in lines.iter().enumerate() {
        if (skip_from..skip_to).contains(&number) {
            continue;
        }
        let Some(cells) = table_row(line) else {
            continue;
        };
        let Some(first) = cells.first() else {
            continue;
        };
        let Some(body) = first.strip_prefix(prefix) else {
            continue;
        };
        if !body.is_empty() && body.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(id) = body.parse() {
                if !defined.contains(&id) {
                    defined.push(id);
                }
            }
        }
    }
    defined.sort_unstable();
    defined
}

/// Every run of ASCII digits in `text`, in order.
fn integers_in(text: &str) -> Vec<u64> {
    let mut found = Vec::new();
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if !digits.is_empty() {
            if let Ok(n) = digits.parse() {
                found.push(n);
            }
            digits.clear();
        }
    }
    if let Ok(n) = digits.parse() {
        found.push(n);
    }
    found
}

/// `D7` or `D1–D6` (any dash) into the numbers it covers.
fn parse_id_range(cell: &str, prefix: &str) -> Option<Vec<u32>> {
    let cell = cell.trim_matches('*').trim();
    let body = cell.strip_prefix(prefix)?;
    let sep = ['–', '—', '-'];
    match body.split_once(|c| sep.contains(&c)) {
        None => body.parse().ok().map(|n| vec![n]),
        Some((lo, hi)) => {
            let lo: u32 = lo.trim().parse().ok()?;
            let hi: u32 = hi.trim().trim_start_matches(prefix).trim().parse().ok()?;
            (lo <= hi).then(|| (lo..=hi).collect())
        }
    }
}

/// `PREFIX-1.2` occurrences in one line, returned as `1.2`.
fn cited_ids(line: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{prefix}-");
    let mut rest = line;
    while let Some(at) = rest.find(&needle) {
        let after = &rest[at + needle.len()..];
        let raw: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let consumed = raw.len();
        let id = raw.trim_end_matches('.').to_string();
        if !id.is_empty() {
            out.push(id);
        }
        rest = &after[consumed.min(after.len())..];
    }
    out
}

/// The top-level part number of every `§N…` in one line. `§8.5.3` yields 8.
/// Escaped forms inside `rg` examples (`§8\.5\.3`) are read the same way.
fn cited_sections(line: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find('§') {
        let after = &rest[at + '§'.len_utf8()..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<u32>() {
            out.push(n);
        }
        rest = &after[digits.len().min(after.len())..];
    }
    out
}

/// Does `text` contain a level-1 heading `# 第 <numbers> 部分：<title>` whose
/// number list (`、`-separated) contains `part` and whose title is non-empty?
fn heading_for_part(text: &str, part: u32) -> bool {
    for line in text.lines() {
        let Some(rest) = line.trim_end().strip_prefix("# 第 ") else {
            continue;
        };
        let Some((numbers, tail)) = rest.split_once(" 部分") else {
            continue;
        };
        if !numbers
            .split('、')
            .any(|n| n.trim().parse::<u32>() == Ok(part))
        {
            continue;
        }
        let title = tail.trim_start_matches(['：', ':']).trim();
        if !title.is_empty() {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------- 3. links

/// Every `[text](target)` in `docs/**/*.md` with a relative target must
/// resolve to an existing path. External URLs and same-file anchors are out
/// of scope; fenced code blocks are skipped.
fn check_links(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let files = collect_checked_markdown(root)?;

    let mut checked = 0usize;
    for file in &files {
        let text = util::read_text(file)?;
        let dir = file.parent().expect("every markdown file has a parent");
        let mut in_fence = false;
        for (idx, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            for target in link_targets(line) {
                let target = target.split('#').next().unwrap_or("");
                if target.is_empty()
                    || target.starts_with("http://")
                    || target.starts_with("https://")
                    || target.starts_with("mailto:")
                {
                    continue;
                }
                checked += 1;
                if !dir.join(target).exists() {
                    failures.push(format!(
                        "{}:{}: link target `{target}` does not resolve",
                        file.strip_prefix(root).unwrap_or(file).display(),
                        idx + 1
                    ));
                }
            }
        }
    }
    println!(
        "doc-check: links — {} markdown files, {checked} relative links resolved",
        files.len()
    );
    Ok(())
}

/// Every `cargo xtask <sub>` named in a document or a workflow must be a task
/// that still exists.
///
/// Blueprint §15.4 rule 3 orders this check by name. It was written after an
/// audit found CI calling a task that had been deleted while documents listed
/// others that had been retired — the kind of drift that stays invisible until
/// someone copies the command.
fn check_xtask_commands(root: &Path, failures: &mut Vec<String>) -> Result<usize, String> {
    let mut sources = collect_checked_markdown(root)?;
    let workflows = root.join(".github/workflows");
    if workflows.is_dir() {
        let entries = std::fs::read_dir(&workflows).map_err(|e| format!("read workflows: {e}"))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("read workflows: {e}"))?.path();
            if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                sources.push(path);
            }
        }
    }

    let mut checked = 0usize;
    for source in &sources {
        let text = util::read_text(source)?;
        let shown = source.strip_prefix(root).unwrap_or(source).display();
        for (idx, line) in text.lines().enumerate() {
            for name in cited_xtask_tasks(line) {
                checked += 1;
                if !crate::TASKS.contains(&name.as_str()) {
                    failures.push(format!(
                        "{shown}:{}: `cargo xtask {name}` is not a task",
                        idx + 1
                    ));
                }
            }
        }
    }
    Ok(checked)
}

/// Task names following `cargo xtask` on one line.
fn cited_xtask_tasks(line: &str) -> Vec<String> {
    const MARKER: &str = "cargo xtask ";
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(MARKER) {
        let after = &rest[at + MARKER.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !name.is_empty() {
            found.push(name);
        }
        let Some(next) = after.get(1..) else { break };
        rest = next;
    }
    found
}

/// Every markdown file the checks apply to: all of `docs/`, plus the
/// repository-root documents and `tools/`.
///
/// The root files were outside the walk until they were found to be carrying
/// three drifted claims at once. `AGENTS.md` in particular is read at the start
/// of every session, so an unchecked stale line there is more expensive than
/// the same line buried in `docs/`.
fn collect_checked_markdown(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_markdown(&root.join("docs"), &mut files)?;
    collect_markdown(&root.join("tools"), &mut files)?;
    for name in [
        "AGENTS.md",
        "README.md",
        "CHANGELOG.md",
        "THIRD_PARTY_NOTICES.md",
    ] {
        let path = root.join(name);
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
}

/// The targets of every `](target)` occurrence in one line. A ` "title"`
/// suffix is dropped.
fn link_targets(line: &str) -> Vec<&str> {
    let mut targets = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find("](") {
        let after = &rest[open + 2..];
        let Some(close) = after.find(')') else {
            break;
        };
        let target = after[..close].trim();
        targets.push(target.split(' ').next().unwrap_or(target));
        rest = &after[close + 1..];
    }
    targets
}

// ------------------------------------------------- 4. ELF section names

/// The section names measured loadable AND attachable via legacy `tc` on the
/// baseline device (`docs/history/phase0.md` §16.8.2). `action` loads
/// but selects `SCHED_ACT` and cannot attach, so it is deliberately absent.
const USABLE_SECTIONS: [&str; 5] = ["tc", "classifier", "tc/ingress", "tc/egress", "tcx/egress"];

/// `FLUX_SEC_<X>` in the header and `SEC_<X>` in `abi.rs` must be the same
/// set of suffixes with byte-identical values, all inside [`USABLE_SECTIONS`].
fn check_sections(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let header_path = root.join("bpf/include/flux_abi.h");
    let header = util::read_text(&header_path)?;
    let mut c_side: BTreeMap<String, String> = BTreeMap::new();
    for define in cdefs::parse_defines(&header) {
        if let Some(suffix) = define.name.strip_prefix("FLUX_SEC_") {
            match define.string_value {
                Some(value) => {
                    c_side.insert(suffix.to_string(), value);
                }
                None => failures.push(format!(
                    "flux_abi.h:{}: {} is not a string define",
                    define.line, define.name
                )),
            }
        }
    }

    let abi_path = root.join("crates/flux-core/src/abi.rs");
    let abi = util::read_text(&abi_path)?;
    let mut rust_side: BTreeMap<String, String> = BTreeMap::new();
    for (idx, line) in abi.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("pub const SEC_") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let value = tail
            .split_once('"')
            .and_then(|(_, v)| v.split('"').next())
            .map(str::to_string);
        match value {
            Some(value) => {
                rust_side.insert(name.trim().to_string(), value);
            }
            None => failures.push(format!(
                "crates/flux-core/src/abi.rs:{}: SEC_{rest} has no string literal",
                idx + 1
            )),
        }
    }

    for (suffix, value) in &c_side {
        match rust_side.get(suffix) {
            None => failures.push(format!(
                "flux_abi.h has FLUX_SEC_{suffix} but abi.rs has no SEC_{suffix}"
            )),
            Some(rust_value) if rust_value != value => failures.push(format!(
                "FLUX_SEC_{suffix} is \"{value}\" in flux_abi.h but SEC_{suffix} is \
                 \"{rust_value}\" in abi.rs"
            )),
            Some(_) => {}
        }
        if !USABLE_SECTIONS.contains(&value.as_str()) {
            failures.push(format!(
                "FLUX_SEC_{suffix} = \"{value}\" is outside the measured-usable set \
                 {USABLE_SECTIONS:?} (phase0.md §16.8.2)"
            ));
        }
    }
    for suffix in rust_side.keys() {
        if !c_side.contains_key(suffix) {
            failures.push(format!(
                "abi.rs has SEC_{suffix} but flux_abi.h has no FLUX_SEC_{suffix}"
            ));
        }
    }
    if c_side.is_empty() {
        failures.push("flux_abi.h contains no FLUX_SEC_* defines at all".into());
    }
    println!(
        "doc-check: sections — {} FLUX_SEC_*/SEC_* pairs identical and inside the usable set",
        c_side.len()
    );
    Ok(())
}

// ------------------------------------------------ 5. overturn numbering

/// Cross-check every overturn count the documentation states:
///
/// * review-log §0.6 heading: how many overturns the measurement round added;
/// * review-log §0.6 body: how many existed before measurement;
/// * the §0.6 table: one row per measurement-round overturn, numbered
///   continuously from (before + 1);
/// * the blueprint's claim `共推翻自己**N次**——M次在实测前，K次在…`.
///
/// All of N == M + K, M == before, K == added, and the table numbering must
/// hold simultaneously.
fn check_overturns(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let log_path = root.join("docs/history/review-log.md");
    let log = util::read_text(&log_path)?;

    // Locate §0.6 and its extent (up to the next heading of any level).
    let mut heading: Option<(usize, &str)> = None;
    let mut body_lines: Vec<(usize, &str)> = Vec::new();
    for (idx, line) in log.lines().enumerate() {
        if heading.is_none() {
            if line.starts_with("## 0.6 ") {
                heading = Some((idx + 1, line));
            }
            continue;
        }
        if line.starts_with("## ") || line.starts_with("### ") {
            break;
        }
        body_lines.push((idx + 1, line));
    }
    let Some((heading_line, heading_text)) = heading else {
        failures.push("review-log.md: §0.6 heading not found".into());
        return Ok(());
    };

    let added = match count_after(heading_text, "推翻了", '条') {
        Some(n) => n,
        None => {
            failures.push(format!(
                "review-log.md:{heading_line}: cannot parse the overturn count from the §0.6 \
                 heading"
            ));
            return Ok(());
        }
    };

    let before = body_lines
        .iter()
        .find_map(|(_, line)| count_after(line, "实测前的", '条'));
    let Some(before) = before else {
        failures.push(
            "review-log.md §0.6: cannot find the pre-measurement count (`实测前的N条`)".into(),
        );
        return Ok(());
    };

    let mut table_numbers: Vec<(usize, u64)> = Vec::new();
    for (line_no, line) in &body_lines {
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() >= 3 {
            if let Ok(n) = cells[1].parse::<u64>() {
                table_numbers.push((*line_no, n));
            }
        }
    }

    if table_numbers.len() as u64 != added {
        failures.push(format!(
            "review-log.md §0.6: the heading says the measurement round overturned {added}, \
             but the table has {} numbered rows",
            table_numbers.len()
        ));
    }
    let mut expected = before + 1;
    for (line_no, n) in &table_numbers {
        if *n != expected {
            failures.push(format!(
                "review-log.md:{line_no}: overturn #{n} breaks the numbering \
                 (expected #{expected}, continuing from the {before} pre-measurement entries)"
            ));
        }
        expected = n + 1;
    }
    let log_total = before + table_numbers.len() as u64;

    // The blueprint's claim.
    let blueprint_path = root.join("docs/spec/blueprint.md");
    let blueprint = util::read_text(&blueprint_path)?;
    const CLAIM: &str = "overturned itself";
    let Some(claim_at) = blueprint.find(CLAIM) else {
        failures.push(format!(
            "blueprint.md: the overturn-total claim (`{CLAIM} N times — M before …`) is gone"
        ));
        return Ok(());
    };
    let claim_tail = &blueprint[claim_at + CLAIM.len()..];
    let claim_line = blueprint[..claim_at].lines().count();

    // `**8 times** — 5 before measurement, 3 during the …`: the first three
    // integers of the sentence, in that order. Reading them positionally rather
    // than by surrounding words keeps the check from breaking every time the
    // sentence is reworded, which is how it broke when this document was
    // re-issued in English.
    let sentence = claim_tail.split(['.', '\u{3002}']).next().unwrap_or("");
    let numbers = integers_in(sentence);
    let [total, claimed_before, claimed_added] = numbers[..] else {
        failures.push(format!(
            "blueprint.md:{claim_line}: the overturn claim must contain exactly three \
             numbers (total, before measurement, during measurement); found {}",
            numbers.len()
        ));
        return Ok(());
    };

    if claimed_before + claimed_added != total {
        failures.push(format!(
            "blueprint.md:{claim_line}: claims {total} overturns total but \
             {claimed_before} + {claimed_added} in the breakdown"
        ));
    }
    if claimed_before != before {
        failures.push(format!(
            "blueprint.md:{claim_line}: claims {claimed_before} pre-measurement overturns, \
             review-log.md §0.6 counts {before}"
        ));
    }
    if claimed_added != added {
        failures.push(format!(
            "blueprint.md:{claim_line}: claims {claimed_added} measurement-round overturns, \
             review-log.md §0.6 counts {added}"
        ));
    }
    if total != log_total {
        failures.push(format!(
            "blueprint.md:{claim_line}: claims {total} overturns total, review-log.md §0.6 \
             accounts for {log_total}"
        ));
    }
    println!(
        "doc-check: overturns — {before} before + {added} during measurement = {log_total}, \
         numbering continuous, blueprint claims {total}"
    );
    Ok(())
}

// ------------------------------------------------------- numeral parsing

/// Parse a small Chinese or ASCII numeral (`八`, `十二`, `42`). These counts
/// are written in prose, so the checker must read prose; supporting 0–99
/// covers any plausible overturn count.
fn parse_count(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    let digit = |c: char| {
        "零一二三四五六七八九"
            .chars()
            .position(|d| d == c)
            .map(|p| p as u64)
    };
    let chars: Vec<char> = s.chars().collect();
    match chars.as_slice() {
        [c] if *c == '十' => Some(10),
        [c] => digit(*c),
        ['十', c] => Some(10 + digit(*c)?),
        [c, '十'] => Some(digit(*c)? * 10),
        [c, '十', d] => Some(digit(*c)? * 10 + digit(*d)?),
        _ => None,
    }
}

/// The numeral that appears immediately after `marker` and runs up to
/// `terminator`. E.g. `count_after("实测又推翻了三条，…", "推翻了", '条')` is 3.
fn count_after(text: &str, marker: &str, terminator: char) -> Option<u64> {
    let after = &text[text.find(marker)? + marker.len()..];
    parse_count(after.split(terminator).next()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numerals_parse() {
        assert_eq!(parse_count("八"), Some(8));
        assert_eq!(parse_count("五"), Some(5));
        assert_eq!(parse_count("十"), Some(10));
        assert_eq!(parse_count("十二"), Some(12));
        assert_eq!(parse_count("二十一"), Some(21));
        assert_eq!(parse_count("42"), Some(42));
        assert_eq!(parse_count("x"), None);
        assert_eq!(parse_count(""), None);
    }

    #[test]
    fn counts_extract_from_prose() {
        let heading = "## 0.6 2026-08-25 下半场：实测又推翻了三条，其中两条是我自己写的";
        assert_eq!(count_after(heading, "推翻了", '条'), Some(3));
        let body = "实测前的五条分布在：§0.2 一条…";
        assert_eq!(count_after(body, "实测前的", '条'), Some(5));
    }

    #[test]
    fn the_overturn_claim_reads_positionally() {
        // Read as the first three integers of the sentence, so that rewording
        // it does not break the check — which is exactly what happened when the
        // blueprint was re-issued in English.
        let claim = " **8 times** — 5 before measurement, 3 during the measurement round";
        assert_eq!(integers_in(claim), vec![8, 5, 3]);
    }

    #[test]
    fn a_stray_number_in_the_claim_is_visible() {
        // `Phase 0` used to sit in this sentence and silently became a fourth
        // number; the check must notice rather than mis-assign the positions.
        let claim = " **8 times** — 5 before, 3 during the Phase 0 round";
        assert_ne!(integers_in(claim).len(), 3);
    }

    #[test]
    fn identifier_citations_extract() {
        assert_eq!(cited_ids("see PHIL-1 and PHIL-10", "PHIL"), ["1", "10"]);
        assert_eq!(cited_ids("(GOV-1.2) and GOV-6.2.", "GOV"), ["1.2", "6.2"]);
        // A trailing full stop is punctuation, not part of the identifier.
        assert_eq!(cited_ids("per AUTH-0.", "AUTH"), ["0"]);
        assert!(cited_ids("PHILOSOPHY is not a citation", "PHIL").is_empty());
        assert!(cited_ids("nothing here", "PHIL").is_empty());
    }

    #[test]
    fn section_citations_yield_the_part_number() {
        assert_eq!(cited_sections("§8.5.3 depends on §14.1"), [8, 14]);
        assert_eq!(cited_sections("the escaped form §8\\.5\\.3"), [8]);
        assert_eq!(cited_sections("§0 and §27"), [0, 27]);
        assert!(cited_sections("no sections").is_empty());
        // A lone sign with no number is prose, not a citation.
        assert!(cited_sections("the § symbol").is_empty());
    }

    #[test]
    fn link_targets_extract() {
        assert_eq!(
            link_targets("see [a](x.md) and [b](../y.md#frag) and [c](https://e.com)"),
            ["x.md", "../y.md#frag", "https://e.com"]
        );
        assert!(link_targets("no links here").is_empty());
    }

    #[test]
    fn part_headings_match() {
        assert!(heading_for_part("# 第 16 部分：Phase 0 —— 编码之前", 16));
        assert!(heading_for_part("# 第 21 部分：需要确认的事项", 21));
        assert!(!heading_for_part("# 第 21 部分：需要确认的事项", 22));
        assert!(!heading_for_part("## 第 21 部分：不是一级标题", 21));
        assert!(!heading_for_part("# 第 21 部分：", 21));
    }
}
