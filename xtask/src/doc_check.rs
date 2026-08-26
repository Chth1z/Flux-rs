//! `cargo xtask doc-check` — the four mechanical documentation checks of
//! `docs/plan/implementation.md` §17.4 (exit criterion 6).
//!
//! Each one has caught a real defect before it was automated, which is why it
//! exists (that section, closing paragraph):
//!
//! 1. The chapter map in `docs/README.md` points at files that exist and that
//!    really carry the `# 第 N 部分` heading (the map once pointed at files
//!    that had been moved out).
//! 2. Every relative markdown link under `docs/` resolves.
//! 3. `flux_abi.h`'s `FLUX_SEC_*` and `abi.rs`'s `SEC_*` agree byte-for-byte
//!    and every section name is in the set measured usable on the baseline
//!    device (`docs/verification/phase0.md` §16.8.2).
//! 4. The overturn numbering in `docs/evidence/review-log.md` is continuous
//!    and consistent with the total the blueprint claims (the count once
//!    existed in three contradictory versions: 5, 7 and 8).

use crate::{cdefs, util};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run() -> Result<(), String> {
    let root = util::repo_root();
    let mut failures: Vec<String> = Vec::new();

    check_chapter_map(&root, &mut failures)?;
    check_links(&root, &mut failures)?;
    check_sections(&root, &mut failures)?;
    check_overturns(&root, &mut failures)?;

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

/// Parse the `## 章节编号 → 文件` table in `docs/README.md` and verify each
/// row: the file exists and carries a level-1 `# 第 N 部分：<title>` heading
/// for that part number. The 内容 column is a description, not the heading
/// text, so the mechanical anchor is the globally stable part number
/// (`authoring.md` §1.1), not a string comparison against prose.
fn check_chapter_map(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let readme_path = root.join("docs/README.md");
    let readme = util::read_text(&readme_path)?;

    let mut rows: Vec<(u32, String, usize)> = Vec::new();
    let mut in_table_section = false;
    for (idx, line) in readme.lines().enumerate() {
        if line.starts_with("## ") {
            in_table_section = line.trim() == "## 章节编号 → 文件";
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
                "docs/README.md:{}: chapter row `{}` has an unparsable part number",
                idx + 1,
                cells[1]
            ));
            continue;
        };
        rows.push((number, cells[3].trim_matches('`').to_string(), idx + 1));
    }

    if rows.is_empty() {
        failures.push("docs/README.md: chapter map table not found".into());
        return Ok(());
    }

    // Numbering must be dense: every part number exactly once, no gaps.
    for pair in rows.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if next.0 != prev.0 + 1 {
            failures.push(format!(
                "docs/README.md:{}: chapter map jumps from §{} to §{}",
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
                "docs/README.md:{line}: §{number} maps to `{file}`, which does not exist"
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
                "docs/README.md:{line}: §{number} maps to `{file}`, but that file has no \
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
    Ok(())
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

// --------------------------------------------------------------- 2. links

/// Every `[text](target)` in `docs/**/*.md` with a relative target must
/// resolve to an existing path. External URLs and same-file anchors are out
/// of scope; fenced code blocks are skipped.
fn check_links(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let mut files = Vec::new();
    collect_markdown(&root.join("docs"), &mut files)?;
    files.sort();

    let mut checked = 0usize;
    for file in &files {
        let text = util::read_text(file)?;
        let dir = file.parent().expect("markdown files live inside docs/");
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

// ------------------------------------------------- 3. ELF section names

/// The section names measured loadable AND attachable via legacy `tc` on the
/// baseline device (`docs/verification/phase0.md` §16.8.2). `action` loads
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

// ------------------------------------------------ 4. overturn numbering

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
    let log_path = root.join("docs/evidence/review-log.md");
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
    let blueprint_path = root.join("docs/blueprint.md");
    let blueprint = util::read_text(&blueprint_path)?;
    let Some(claim_at) = blueprint.find("共推翻自己") else {
        failures.push("blueprint.md: the overturn-total claim (`共推翻自己…次`) is gone".into());
        return Ok(());
    };
    let claim_tail = &blueprint[claim_at + "共推翻自己".len()..];
    let claim_line = blueprint[..claim_at].lines().count();

    let total = claim_tail
        .trim_start_matches(['*', ' '])
        .split('次')
        .next()
        .and_then(parse_count);
    let claimed_before = count_before(claim_tail, "次在实测前");
    let claimed_added = claim_tail
        .find("实测前，")
        .and_then(|at| count_after(&claim_tail[at..], "实测前，", '次'));
    let (Some(total), Some(claimed_before), Some(claimed_added)) =
        (total, claimed_before, claimed_added)
    else {
        failures.push(format!(
            "blueprint.md:{claim_line}: cannot parse the overturn claim \
             (`共推翻自己N次——M次在实测前，K次在…`)"
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

/// The numeral whose last character sits immediately before `marker`.
/// E.g. `count_before("——五次在实测前，…", "次在实测前")` is 5.
fn count_before(text: &str, marker: &str) -> Option<u64> {
    let before = &text[..text.find(marker)?];
    let is_numeral = |c: &char| c.is_ascii_digit() || "零一二三四五六七八九十".contains(*c);
    let run: String = before.chars().rev().take_while(is_numeral).collect();
    parse_count(&run.chars().rev().collect::<String>())
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
        let claim = "**八次**——五次在实测前，三次在 2026-08-25 的实测中";
        assert_eq!(
            claim
                .trim_start_matches(['*', ' '])
                .split('次')
                .next()
                .and_then(parse_count),
            Some(8)
        );
        assert_eq!(count_before(claim, "次在实测前"), Some(5));
        assert_eq!(count_after(claim, "实测前，", '次'), Some(3));
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
