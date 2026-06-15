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
fn json_output_includes_baseline_metadata() {
    let f = finding(json!({
        "file": "a", "line": 2, "end_line": 2,
        "col": 5, "end_col": 21, "col_utf16": 5, "end_col_utf16": 21,
        "rule_id": "r", "description": "d", "matched": "[redacted]",
        "entropy": 4.0, "start_offset": 10, "end_offset": 26,
        "secret_start_offset": 14, "secret_end_offset": 26,
        "fingerprint": "stable-fp",
        "context_lines": [[2, "k=[REDACTED_SECRET]"]]
    }));

    let mut out = Vec::new();
    write_json(&mut out, &[f], true).expect("json");
    let parsed: Vec<Finding> = serde_json::from_slice(&out).expect("finding json");

    assert_eq!(parsed[0].fingerprint, "stable-fp");
    assert_eq!(parsed[0].start_offset, 10);
    assert_eq!(parsed[0].end_offset, 26);
    assert_eq!(parsed[0].secret_start_offset, 14);
    assert_eq!(parsed[0].secret_end_offset, 26);
}

#[test]
fn relativize_strips_base_and_normalizes_separators() {
    assert_eq!(relativize("./src/a.rs", "."), "src/a.rs");
    assert_eq!(relativize("repo/src/a.rs", "repo"), "src/a.rs");
    assert_eq!(relativize("a\\b.rs", "."), "a/b.rs");
}

#[test]
fn relativize_requires_separator_boundary() {
    // A sibling sharing a prefix with the base must not be truncated: base
    // "src" against "src2/foo.rs" stays whole (regression for the prefix bug
    // that produced "2/foo.rs" and corrupted SARIF artifactLocation.uri).
    assert_eq!(relativize("src2/foo.rs", "src"), "src2/foo.rs");
    assert_eq!(
        relativize("/home/u/project-other/x.rs", "/home/u/project"),
        "/home/u/project-other/x.rs"
    );
    // Exact match (base == file) does not strip to empty; the full path is kept.
    assert_eq!(relativize("src/a.rs", "src/a.rs"), "src/a.rs");
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
    let fp_a = &doc_a["runs"][0]["results"][0]["partialFingerprints"]["secretsScanner/v2"];
    let fp_b = &doc_b["runs"][0]["results"][0]["partialFingerprints"]["secretsScanner/v2"];

    assert_eq!(fp_a, "stable-raw-fingerprint");
    assert_eq!(fp_a, fp_b);
}
