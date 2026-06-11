//! Minimal `.env` file parsing for `evs import`.
//!
//! Supported syntax: `KEY=VALUE` lines, blank lines, full-line `#` comments,
//! and an optional `export ` prefix. A value wrapped in matching single or
//! double quotes has them stripped; no escape sequences, variable expansion,
//! or inline comments are processed. Duplicate keys keep their file order,
//! so the last occurrence wins once inserted into the vault.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DotenvError {
    // The offending line is not echoed: it may contain a secret value.
    #[error("line {0}: expected `KEY=VALUE`")]
    Malformed(usize),
    #[error("line {0}: invalid variable name `{1}`")]
    InvalidKey(usize, String),
}

/// Parses `.env` content into `(key, value)` pairs in file order.
pub fn parse(content: &str) -> Result<Vec<(String, String)>, DotenvError> {
    let mut entries = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else {
            return Err(DotenvError::Malformed(line_no));
        };
        let key = key.trim_end();
        if key.is_empty() || key.contains(char::is_whitespace) || key.contains('\0') {
            return Err(DotenvError::InvalidKey(line_no, key.to_string()));
        }
        let value = unquote(value.trim());
        entries.push((key.to_string(), value.to_string()));
    }
    Ok(entries)
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if first == last && (first == b'"' || first == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_pairs() {
        let entries = parse("FOO=bar\nBAZ=qux\n").unwrap();
        assert_eq!(
            entries,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
            ]
        );
    }

    #[test]
    fn skips_blanks_and_comments() {
        let entries = parse("\n# comment\n  \nFOO=bar\n").unwrap();
        assert_eq!(entries, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn strips_export_prefix_and_quotes() {
        let entries = parse("export A=\"with spaces\"\nB='single'\nC=\"unbalanced'\n").unwrap();
        assert_eq!(
            entries,
            vec![
                ("A".to_string(), "with spaces".to_string()),
                ("B".to_string(), "single".to_string()),
                ("C".to_string(), "\"unbalanced'".to_string()),
            ]
        );
    }

    #[test]
    fn keeps_equals_signs_in_values() {
        let entries = parse("URL=postgres://u:p@h/db?sslmode=require\n").unwrap();
        assert_eq!(entries[0].1, "postgres://u:p@h/db?sslmode=require");
    }

    #[test]
    fn duplicate_keys_keep_file_order() {
        let entries = parse("A=first\nA=second\n").unwrap();
        assert_eq!(
            entries,
            vec![
                ("A".to_string(), "first".to_string()),
                ("A".to_string(), "second".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_line_without_equals() {
        assert!(matches!(parse("FOO\n"), Err(DotenvError::Malformed(1))));
    }

    #[test]
    fn rejects_invalid_key() {
        assert!(matches!(
            parse("FOO=ok\n=value\n"),
            Err(DotenvError::InvalidKey(2, _))
        ));
        assert!(matches!(
            parse("BAD KEY=value\n"),
            Err(DotenvError::InvalidKey(1, _))
        ));
    }

    #[test]
    fn empty_value_is_allowed() {
        let entries = parse("EMPTY=\n").unwrap();
        assert_eq!(entries, vec![("EMPTY".to_string(), String::new())]);
    }
}
