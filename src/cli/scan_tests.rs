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
fn baseline_uses_fixed_marker_and_drops_context() {
    // A generated baseline must carry no secret material: context is dropped and
    // `matched` becomes the fixed marker regardless of CLI redaction mode. The
    // fingerprint (the suppression key) is preserved.
    let findings = vec![finding_with_raw_context()];
    let out = super::baseline::baseline_findings(&findings);
    let json = serde_json::to_string(&out).expect("serialize");

    assert!(out[0].context_lines.is_empty(), "context must be dropped");
    assert_eq!(out[0].matched, "[REDACTED_SECRET]");
    assert!(
        !json.contains("tok_RAWSECRETVALUE"),
        "no raw secret may survive in the baseline JSON: {json}"
    );
    assert_eq!(out[0].fingerprint, "fp-abc");
}

#[test]
fn baseline_marker_hides_partial_redaction_structure() {
    // Even when the scanner already partially redacted `matched` (default mode,
    // keeping first/last 4 chars + length), the baseline must not preserve that
    // structure. It is replaced wholesale by the fixed marker.
    let mut f = finding_with_raw_context();
    f.matched = "tok_****************VALUE".to_string();
    let out = super::baseline::baseline_findings(&[f]);
    assert_eq!(
        out[0].matched, "[REDACTED_SECRET]",
        "partial-redaction structure must not survive into the baseline"
    );
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
    let suppressed = super::baseline::suppress_baseline(baseline, &mut current);
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
    assert_eq!(
        super::baseline::suppress_baseline(baseline, &mut current),
        1
    );
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
    let suppressed = super::baseline::suppress_baseline(baseline, &mut current);
    assert_eq!(suppressed, 1, "only the matching fingerprint is suppressed");
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].fingerprint, "sha256:bbbb");
}

#[cfg(unix)]
#[test]
fn create_private_file_rejects_symlink_and_sets_mode() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"DO NOT TRUNCATE").expect("write victim");

    // A symlink planted at the output path must NOT be followed/truncated.
    let link = dir.path().join("out.sarif");
    std::os::unix::fs::symlink(&victim, &link).expect("symlink");
    let link_str = link.to_str().expect("utf8");
    assert!(
        super::create_private_file(link_str).is_err(),
        "must refuse to write through a symlink"
    );
    assert_eq!(
        std::fs::read(&victim).expect("victim still readable"),
        b"DO NOT TRUNCATE",
        "symlink target must be untouched"
    );

    // A plain new path succeeds and is owner-only (0600).
    let fresh = dir.path().join("fresh.json");
    let mut f = super::create_private_file(fresh.to_str().expect("utf8")).expect("create fresh");
    f.write_all(b"{}").expect("write fresh");
    let mode = std::fs::metadata(&fresh)
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "output file must be 0600");
}

#[cfg(unix)]
#[test]
fn create_private_file_rejects_non_regular_descriptor() {
    assert!(
        super::create_private_file("/dev/null").is_err(),
        "scanner output must not be written to non-regular files"
    );
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
