use secrets_scanner::{Finding, ScanConfig, Scanner};

/// A finding with raw `matched` and a context line that also contains the
/// raw secret (the shape `scan_bytes` produces under `--no-redact`).
fn finding_with_raw_context() -> Finding {
    serde_json::from_value(serde_json::json!({
        "file": "app.env", "line": 2, "end_line": 2, "col": 5, "end_col": 28,
        "rule_id": "test-token", "description": "Test token",
        "matched": "tok_RAWSECRETVALUE", "entropy": 4.2,
        "fingerprint": "fp-abc",
        "context_lines": [[1, "# config"], [2, "API=tok_RAWSECRETVALUE"]]
    }))
    .expect("finding")
}

#[test]
fn baseline_drops_context_and_redacts_under_no_redact() {
    let findings = vec![finding_with_raw_context()];
    let out = super::baseline_findings(true, &findings);
    let json = serde_json::to_string(&out).expect("serialize");

    assert!(out[0].context_lines.is_empty(), "context must be dropped");
    assert!(
        !json.contains("tok_RAWSECRETVALUE"),
        "no raw secret may survive in the baseline JSON: {json}"
    );
    // Fingerprint (the suppression key) is preserved.
    assert_eq!(out[0].fingerprint, "fp-abc");
}

#[test]
fn baseline_drops_context_when_redacted() {
    // Even with redaction on, context is dropped (it is never a suppression
    // key, so carrying it only risks leaking redaction-marker-adjacent data).
    let findings = vec![finding_with_raw_context()];
    let out = super::baseline_findings(false, &findings);
    assert!(out[0].context_lines.is_empty());
}

/// Build a finding carrying a specific fingerprint at a given location.
fn finding_at(fingerprint: &str, file: &str, line: usize, rule: &str) -> Finding {
    serde_json::from_value(serde_json::json!({
        "file": file, "line": line, "end_line": line, "col": 1, "end_col": 2,
        "rule_id": rule, "description": "Test", "matched": "[REDACTED_SECRET]",
        "entropy": 4.2, "fingerprint": fingerprint, "context_lines": []
    }))
    .expect("finding")
}

#[test]
fn legacy_fnv_baseline_suppresses_by_location() {
    // A baseline written by an older build carries a non-empty FNV hex
    // fingerprint (no `sha256:` prefix). It must suppress a current finding
    // at the same (file, line, rule) even though the new finding's `sha256:`
    // fingerprint differs — otherwise every old baseline silently breaks.
    let baseline = vec![finding_at("a1b2c3d4e5f60718", "app.env", 7, "test-token")];
    let mut current = vec![finding_at("sha256:deadbeef", "app.env", 7, "test-token")];
    let suppressed = super::suppress_baseline(baseline, &mut current);
    assert_eq!(
        suppressed, 1,
        "legacy FNV baseline must suppress by location"
    );
    assert!(current.is_empty());
}

#[test]
fn empty_fingerprint_baseline_suppresses_by_location() {
    let baseline = vec![finding_at("", "app.env", 7, "test-token")];
    let mut current = vec![finding_at("sha256:deadbeef", "app.env", 7, "test-token")];
    assert_eq!(super::suppress_baseline(baseline, &mut current), 1);
}

#[test]
fn sha256_baseline_suppresses_by_fingerprint_line_tolerant() {
    // sha256 fingerprints suppress by value (line-independent): same
    // fingerprint at a different line is still suppressed; a different
    // fingerprint at the same line is not.
    let baseline = vec![finding_at("sha256:aaaa", "app.env", 7, "test-token")];
    let mut current = vec![
        finding_at("sha256:aaaa", "app.env", 99, "test-token"), // moved line, same fp
        finding_at("sha256:bbbb", "app.env", 7, "test-token"),  // diff fp, same line
    ];
    let suppressed = super::suppress_baseline(baseline, &mut current);
    assert_eq!(suppressed, 1, "only the matching fingerprint is suppressed");
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].fingerprint, "sha256:bbbb");
}

#[test]
fn scanner_loads_from_bundled() {
    let scanner = Scanner::from_bundled().expect("should load bundled rules");
    assert!(scanner.engine().rule_count() > 100);
}

#[test]
fn scanner_detects_planted_secret() {
    let scanner = Scanner::from_bundled()
        .expect("should load")
        .with_config(ScanConfig {
            redact: false,
            ..Default::default()
        });

    let content = "export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("deploy.sh", content);
    assert!(!findings.is_empty(), "should detect GitHub PAT");
    assert_eq!(findings[0].rule_id, "github-pat");
}
