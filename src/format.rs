//! CLI output formatting module.
//!
//! All writers take a `&mut dyn Write` so output can go to stdout or a file
//! (`--output`). Text output sanitizes control characters in paths and matched
//! values to prevent terminal / CI-log injection from hostile filenames; the
//! structured JSON/SARIF formats rely on JSON escaping instead.

use std::io::{self, Write};

use serde_json::json;

use crate::safe_display::sanitize_display;
use secrets_scanner::Finding;

/// Human-readable text output. Control characters in `file`/`matched` are
/// escaped so a hostile filename cannot inject terminal/CI-log control sequences.
pub fn write_text(w: &mut dyn Write, findings: &[Finding], show_context: bool) -> io::Result<()> {
    if findings.is_empty() {
        writeln!(w, "✅ No secrets found.")?;
        return Ok(());
    }
    writeln!(w, "🚨 Found {} potential secret(s):\n", findings.len())?;
    for f in findings {
        // Text output reports the byte column (`f.col`) to match `grep`/editor
        // byte offsets; SARIF emits UTF-16 columns (`col_utf16`) for GitHub.
        writeln!(
            w,
            "  {}:{}:{} | rule={} entropy={:.2} | {}",
            sanitize_display(&f.file),
            f.line,
            f.col,
            f.rule_id,
            f.entropy,
            sanitize_display(&f.matched),
        )?;
        if !f.rule_description.is_empty() {
            writeln!(w, "    └─ {}", sanitize_display(&f.rule_description))?;
        }
        if show_context && !f.context_lines.is_empty() {
            for (ctx_line, ctx_text) in &f.context_lines {
                let marker = if *ctx_line == f.line { ">" } else { " " };
                writeln!(
                    w,
                    "     {marker} {ctx_line:>4} | {}",
                    sanitize_display(ctx_text)
                )?;
            }
        }
    }
    Ok(())
}

/// Minimal JSON serialisation of a finding without requiring serde derive on the wire shape.
fn finding_to_json(f: &Finding, show_context: bool) -> String {
    let context_json: String = if !show_context || f.context_lines.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = f
            .context_lines
            .iter()
            .map(|(ln, txt)| format!(r#"{{"line":{},"content":{}}}"#, ln, json_string(txt)))
            .collect();
        format!(r#","context":[{}]"#, items.join(","))
    };
    format!(
        r#"{{"rule_id":{},"description":{},"file":{},"line":{},"col":{},"matched":{},"entropy":{:.6}{}}}"#,
        json_string(&f.rule_id),
        json_string(&f.rule_description),
        json_string(&f.file),
        f.line,
        f.col,
        json_string(&f.matched),
        f.entropy,
        context_json,
    )
}

/// Escape a string for embedding in a JSON document.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// JSON array output.
pub fn write_json(w: &mut dyn Write, findings: &[Finding], show_context: bool) -> io::Result<()> {
    if findings.is_empty() {
        writeln!(w, "[]")?;
        return Ok(());
    }
    let items: Vec<String> = findings
        .iter()
        .map(|f| finding_to_json(f, show_context))
        .collect();
    writeln!(w, "[{}]", items.join(",\n "))?;
    Ok(())
}

/// Newline-delimited JSON output (one object per line).
pub fn write_jsonl(w: &mut dyn Write, findings: &[Finding], show_context: bool) -> io::Result<()> {
    for f in findings {
        writeln!(w, "{}", finding_to_json(f, show_context))?;
    }
    Ok(())
}

/// SARIF 2.1.0 output for GitHub code scanning.
///
/// `base` is the scan root used to make `artifactLocation.uri` repository-relative
/// (paired with `uriBaseId: "SRCROOT"`). Messages are generic and never include
/// the matched value (even a redacted prefix can be sensitive in a public alert).
pub fn write_sarif(w: &mut dyn Write, findings: &[Finding], base: &str) -> io::Result<()> {
    use std::collections::HashMap;

    // Stable rule list + index map (deduped by rule id, in first-seen order).
    let mut rules = Vec::new();
    let mut rule_index: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        if !rule_index.contains_key(f.rule_id.as_str()) {
            rule_index.insert(f.rule_id.as_str(), rules.len());
            rules.push(json!({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": { "text": f.rule_description },
            }));
        }
    }

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let uri = relativize(&f.file, base);
            let (start_line, start_col, end_line, end_col) = sarif_region(f);
            let fingerprint = sarif_fingerprint(f, &uri);
            json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id.as_str()],
                "level": "error",
                "message": {
                    "text": format!(
                        "Potential secret detected by rule {} (entropy {:.2})",
                        f.rule_id, f.entropy
                    )
                },
                "partialFingerprints": {
                    "secretsScanner/v1": fingerprint
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri, "uriBaseId": "SRCROOT" },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_col,
                            "endLine": end_line,
                            "endColumn": end_col,
                        }
                    }
                }],
            })
        })
        .collect();

    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "secrets-scanner",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/whit3rabbit/secrets-scanner",
                "rules": rules,
            }},
            "automationDetails": { "id": "secrets-scanner/scan" },
            "results": results,
        }],
    });

    serde_json::to_writer(&mut *w, &doc)?;
    writeln!(w)?;
    Ok(())
}

/// Make a finding path repository-relative for SARIF `artifactLocation.uri`.
fn relativize(file: &str, base: &str) -> String {
    let f = file.replace('\\', "/");
    let f = f.strip_prefix("./").unwrap_or(&f);
    let base_norm = base.replace('\\', "/");
    let base_norm = base_norm.trim_end_matches('/');
    if !base_norm.is_empty() && base_norm != "." {
        if let Some(rest) = f.strip_prefix(base_norm) {
            return rest.trim_start_matches('/').to_string();
        }
    }
    f.to_string()
}

/// SARIF tracking fingerprint. Prefer the scanner-computed fingerprint, which
/// is derived before redaction, so SARIF alert identity does not change when
/// users toggle redaction. Older/deserialized findings without that field fall
/// back to non-secret location metadata.
fn sarif_fingerprint(f: &Finding, uri: &str) -> String {
    if !f.fingerprint.is_empty() {
        return f.fingerprint.clone();
    }
    secrets_scanner::location_fingerprint(&f.rule_id, uri, f.start_offset, f.end_offset)
}

/// SARIF region in UTF-16 code units (SARIF's default `columnKind`, which GitHub
/// code scanning assumes) with a 1-based, non-empty guarantee.
///
/// Returns `(startLine, startColumn, endLine, endColumn)`, every field clamped
/// to `>= 1` so a `line == 0` finding (e.g. a hand-built or deserialized one)
/// never emits an invalid SARIF region. Columns fall back to byte columns when
/// the UTF-16 ones are unset (0) — e.g. path-only findings or a pre-UTF-16
/// baseline. Path-only / zero-width regions are widened by one column so SARIF
/// never sees `endColumn == startColumn`.
fn sarif_region(f: &Finding) -> (usize, usize, usize, usize) {
    let start_line = f.line.max(1);
    let start_col = nonzero_or(f.col_utf16, f.col).max(1);
    let end_line = f.end_line.max(start_line);
    let mut end_col = nonzero_or(f.end_col_utf16, f.end_col).max(1);
    if end_line == start_line && end_col <= start_col {
        end_col = start_col + 1;
    }
    (start_line, start_col, end_line, end_col)
}

/// `primary` if non-zero, otherwise `fallback`.
fn nonzero_or(primary: usize, fallback: usize) -> usize {
    if primary > 0 {
        primary
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Finding` from a JSON value (serde defaults fill optional fields).
    fn finding(v: serde_json::Value) -> Finding {
        serde_json::from_value(v).expect("finding")
    }

    #[test]
    fn json_string_escapes_special_chars() {
        assert_eq!(json_string("hello"), "\"hello\"");
        assert_eq!(json_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(json_string("new\nline"), "\"new\\nline\"");
        assert_eq!(json_string("tab\there"), "\"tab\\there\"");
    }

    #[test]
    fn relativize_strips_base_and_normalizes_separators() {
        assert_eq!(relativize("./src/a.rs", "."), "src/a.rs");
        assert_eq!(relativize("repo/src/a.rs", "repo"), "src/a.rs");
        assert_eq!(relativize("a\\b.rs", "."), "a/b.rs");
    }

    #[test]
    fn nonzero_or_prefers_nonzero_primary() {
        assert_eq!(nonzero_or(5, 9), 5);
        assert_eq!(nonzero_or(0, 9), 9);
    }

    #[test]
    fn sarif_region_uses_utf16_columns_when_present() {
        // Byte columns (10/18) differ from UTF-16 columns (6/14): SARIF must use
        // the UTF-16 ones so a multibyte-prefixed line highlights correctly.
        let f = finding(json!({
            "file": "a", "line": 3, "end_line": 3,
            "col": 10, "end_col": 18, "col_utf16": 6, "end_col_utf16": 14,
            "rule_id": "r", "description": "d", "matched": "m", "entropy": 0.0
        }));
        let (_start_line, start_col, end_line, end_col) = sarif_region(&f);
        assert_eq!(start_col, 6);
        assert_eq!(end_col, 14);
        assert_eq!(end_line, 3);
    }

    #[test]
    fn sarif_region_clamps_zero_line_to_one() {
        // A finding with line == 0 (hand-built / deserialized) must not emit an
        // invalid SARIF startLine of 0.
        let f = finding(json!({
            "file": "a", "line": 0, "end_line": 0, "col": 1, "end_col": 5,
            "rule_id": "r", "description": "d", "matched": "m", "entropy": 0.0
        }));
        let (start_line, _start_col, end_line, _end_col) = sarif_region(&f);
        assert_eq!(start_line, 1, "startLine must be clamped to >= 1");
        assert!(end_line >= start_line);
    }

    #[test]
    fn sarif_region_falls_back_to_byte_columns() {
        let f = finding(json!({
            "file": "a", "line": 1, "end_line": 1, "col": 4, "end_col": 9,
            "rule_id": "r", "description": "d", "matched": "m", "entropy": 0.0
        }));
        let (_start_line, start_col, _end_line, end_col) = sarif_region(&f);
        assert_eq!(start_col, 4, "utf16 unset -> byte column fallback");
        assert_eq!(end_col, 9);
    }

    #[test]
    fn sarif_region_widens_zero_width_region() {
        let f = finding(json!({
            "file": "a", "line": 1, "end_line": 1,
            "col": 1, "end_col": 1, "col_utf16": 1, "end_col_utf16": 1,
            "rule_id": "r", "description": "d", "matched": "m", "entropy": 0.0
        }));
        let (_start_line, start_col, _end_line, end_col) = sarif_region(&f);
        assert!(end_col > start_col, "zero-width region must be widened");
    }

    #[test]
    fn sarif_fingerprint_uses_finding_fingerprint_not_display_match() {
        let a = finding(json!({
            "file": "a", "line": 1, "end_line": 1, "col": 1, "end_col": 7,
            "rule_id": "r", "description": "d", "matched": "[redacted]",
            "entropy": 0.0, "fingerprint": "stable-raw-fingerprint"
        }));
        let mut b = a.clone();
        b.matched = "raw-secret-value".to_string();

        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        write_sarif(&mut out_a, &[a], ".").expect("sarif a");
        write_sarif(&mut out_b, &[b], ".").expect("sarif b");

        let doc_a: serde_json::Value = serde_json::from_slice(&out_a).expect("json a");
        let doc_b: serde_json::Value = serde_json::from_slice(&out_b).expect("json b");
        let fp_a = &doc_a["runs"][0]["results"][0]["partialFingerprints"]["secretsScanner/v1"];
        let fp_b = &doc_b["runs"][0]["results"][0]["partialFingerprints"]["secretsScanner/v1"];

        assert_eq!(fp_a, "stable-raw-fingerprint");
        assert_eq!(fp_a, fp_b);
    }
}
