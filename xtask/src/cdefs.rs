//! Mechanical `#define` extraction from `bpf/include/flux_abi.h`.
//!
//! Only two shapes matter: string defines (`#define NAME "value"`), whose
//! values are compared byte-for-byte against the Rust mirror, and everything
//! else, whose *names* participate in the set-equality check while the values
//! are compared by clang (they may be arbitrary constant expressions).

/// One `#define` in the header.
pub struct Define {
    pub name: String,
    /// `Some` when the body starts with a string literal.
    pub string_value: Option<String>,
    /// 1-based line number, for error messages.
    pub line: usize,
}

/// Every object-like `#define` in `text`, in order of appearance.
pub fn parse_defines(text: &str) -> Vec<Define> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        let Some(rest) = line.strip_prefix("#define") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let body = rest[name.len()..].trim_start();
        let string_value = body.strip_prefix('"').and_then(|tail| {
            // No escape sequences exist in this header; a bare closing quote
            // terminates the literal.
            tail.find('"').map(|end| tail[..end].to_string())
        });
        out.push(Define {
            name,
            string_value,
            line: idx + 1,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_strings_and_names() {
        let header = "\
#ifndef X_H
#define X_H
#define X_MAGIC 0xF10C0903u
#define X_MAP   \"uid_policy\"    /* HASH */
#define X_EXPR (A + 40)
";
        let defines = parse_defines(header);
        let names: Vec<&str> = defines.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["X_H", "X_MAGIC", "X_MAP", "X_EXPR"]);
        assert_eq!(defines[2].string_value.as_deref(), Some("uid_policy"));
        assert_eq!(defines[1].string_value, None);
    }
}
