//! CLI output formatting module.
//!
//! All writers take a `&mut dyn Write` so output can go to stdout or a file
//! (`--output`). Text output sanitizes control/bidi characters in paths and
//! matched values to prevent terminal / CI-log injection from hostile filenames;
//! the structured JSON/SARIF formats rely on JSON escaping instead.

use std::io::{self, Write};

use serde_json::json;

use crate::safe_display::sanitize_display;
use secrets_scanner::Finding;

/// Human-readable text output. Control/bidi characters in `file`/`matched` are
/// escaped so a hostile filename cannot spoof terminal/CI-log output.
pub fn write_text(w: &mut dyn Write, findings: &[Finding], show_context: bool) -> io::Result<()> {
    if findings.is_empty() {
        writeln!(w, "✅ No secrets found.")?;
        return Ok(());
    }
    writeln!(w, "🚨 Found {} potential secret(s):\n", findings.len())?;
    for f in findings {
        // Text output reports the byte column (`f.col`) to match `grep`/editor
        // byte offsets; SARIF emits UTF-16 columns (`col_utf16`) for GitHub.
        // `--git-history` findings carry the commit that introduced them.
        let commit = match &f.commit {
            // Char-safe truncation: a deserialized `Finding.commit` is unvalidated,
            // so byte-slicing `&sha[..12]` could split a multibyte char and panic.
            Some(sha) => format!(" commit={}", sha.chars().take(12).collect::<String>()),
            None => String::new(),
        };
        writeln!(
            w,
            "  {}:{}:{} | rule={} entropy={:.2}{} | {}",
            sanitize_display(&f.file),
            f.line,
            f.col,
            f.rule_id,
            f.entropy,
            commit,
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

/// JSON serialization of a finding that keeps the existing wire names and
/// context shape while including baseline/SARIF location metadata.
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
    // `--git-history` findings carry the introducing commit; omitted otherwise
    // so working-tree/staged output is byte-for-byte unchanged.
    let commit_json = match &f.commit {
        Some(sha) => format!(r#","commit":{}"#, json_string(sha)),
        None => String::new(),
    };
    format!(
        r#"{{"rule_id":{},"description":{},"file":{},"line":{},"col":{},"end_line":{},"end_col":{},"col_utf16":{},"end_col_utf16":{},"matched":{},"entropy":{:.6},"start_offset":{},"end_offset":{},"secret_start_offset":{},"secret_end_offset":{},"fingerprint":{}{}{}}}"#,
        json_string(&f.rule_id),
        json_string(&f.rule_description),
        json_string(&f.file),
        f.line,
        f.col,
        f.end_line,
        f.end_col,
        f.col_utf16,
        f.end_col_utf16,
        json_string(&f.matched),
        f.entropy,
        f.start_offset,
        f.end_offset,
        f.secret_start_offset,
        f.secret_end_offset,
        json_string(&f.fingerprint),
        commit_json,
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
            // `--git-history` findings carry the introducing commit in a
            // properties bag (never in `message.text`, which stays secret-free).
            let properties = match &f.commit {
                Some(sha) => json!({ "commit": sha }),
                None => json!({}),
            };
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
                // v2 marks the fingerprint scheme switch from FNV-1a hex to
                // `sha256:`-prefixed values; bumping the key (not just the value)
                // keeps the scheme change explicit for code-scanning consumers.
                "partialFingerprints": {
                    "secretsScanner/v2": fingerprint
                },
                "properties": properties,
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
        // Require a path-separator boundary so a sibling whose name merely shares
        // a prefix with the scan root (e.g. base "src" vs file "src2/foo.rs") is
        // not corrupted into "2/foo.rs". Strip "<base>/", not just "<base>".
        let prefix = format!("{base_norm}/");
        if let Some(rest) = f.strip_prefix(&prefix) {
            return rest.to_string();
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
#[path = "format_tests.rs"]
mod tests;
