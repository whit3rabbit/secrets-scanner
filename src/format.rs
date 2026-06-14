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
            let (end_line, end_col) = safe_region_end(f);
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
                    "secretsScanner/v1": fingerprint(&f.rule_id, &uri, &f.matched)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri, "uriBaseId": "SRCROOT" },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col.max(1),
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

/// SARIF requires a non-empty region. Path-only / zero-width findings would
/// otherwise emit `endColumn == startColumn`; widen them by one column.
fn safe_region_end(f: &Finding) -> (usize, usize) {
    let start_line = f.line.max(1);
    let start_col = f.col.max(1);
    let end_line = f.end_line.max(start_line);
    let mut end_col = f.end_col.max(1);
    if end_line == start_line && end_col <= start_col {
        end_col = start_col + 1;
    }
    (end_line, end_col)
}

/// Stable 64-bit FNV-1a fingerprint over `rule_id|uri|matched`, hex-encoded.
///
/// Used for SARIF `partialFingerprints` to track logically-identical alerts
/// across line moves. Inlined (no `sha2`) so it works in the lean default build.
fn fingerprint(rule_id: &str, uri: &str, matched: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [rule_id, "\u{0}", uri, "\u{0}", matched] {
        for &b in part.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}
