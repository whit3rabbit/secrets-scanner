//! CLI output formatting module.

/// Human-readable text output.
pub fn print_text(findings: &[secrets_scanner::Finding]) {
    if findings.is_empty() {
        println!("✅ No secrets found.");
        return;
    }
    println!("🚨 Found {} potential secret(s):\n", findings.len());
    for f in findings {
        println!(
            "  {}:{}:{} | rule={} entropy={:.2} | {}",
            f.file, f.line, f.col, f.rule_id, f.entropy, f.matched
        );
        if !f.rule_description.is_empty() {
            println!("    └─ {}", f.rule_description);
        }
        // Print context lines if available
        if !f.context_lines.is_empty() {
            for (ctx_line, ctx_text) in &f.context_lines {
                let marker = if *ctx_line == f.line { ">" } else { " " };
                println!("     {marker} {ctx_line:>4} | {ctx_text}");
            }
        }
    }
}

/// Minimal JSON serialisation without requiring `serde_json`.
pub fn finding_to_json(f: &secrets_scanner::Finding) -> String {
    let context_json: String = if f.context_lines.is_empty() {
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
pub fn print_json(findings: &[secrets_scanner::Finding]) {
    if findings.is_empty() {
        println!("[]");
        return;
    }
    let items: Vec<String> = findings.iter().map(finding_to_json).collect();
    println!("[{}]", items.join(",\n "));
}

/// Newline-delimited JSON output (one object per line).
pub fn print_jsonl(findings: &[secrets_scanner::Finding]) {
    for f in findings {
        println!("{}", finding_to_json(f));
    }
}

/// SARIF 2.1.0 output (for GitHub Code Scanning).
pub fn print_sarif(findings: &[secrets_scanner::Finding]) {
    let version = env!("CARGO_PKG_VERSION");

    let rules_json: Vec<String> = {
        // Collect unique rule IDs seen in findings.
        let mut seen = std::collections::HashSet::new();
        findings
            .iter()
            .filter(|f| seen.insert(f.rule_id.clone()))
            .map(|f| {
                format!(
                    r#"{{"id":{},"name":{},"shortDescription":{{"text":{}}}}}"#,
                    json_string(&f.rule_id),
                    json_string(&f.rule_id),
                    json_string(&f.rule_description),
                )
            })
            .collect()
    };

    let results_json: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                r#"{{"ruleId":{},"level":"error","message":{{"text":{}}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":{}}},"region":{{"startLine":{},"startColumn":{}}}}}}}]}}"#,
                json_string(&f.rule_id),
                json_string(&format!("{} (entropy {:.2})", f.matched, f.entropy)),
                json_string(&f.file),
                f.line,
                f.col,
            )
        })
        .collect();

    println!(
        r#"{{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{{"tool":{{"driver":{{"name":"secrets-scanner","version":{},"rules":[{}]}}}},"results":[{}]}}]}}"#,
        json_string(version),
        rules_json.join(","),
        results_json.join(","),
    );
}
