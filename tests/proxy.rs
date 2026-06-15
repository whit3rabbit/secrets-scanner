//! Tests for the hardened in-memory proxy scan path (`Scanner::scan_proxy`,
//! `ScanConfig::proxy()`), which treats content as fully attacker-controlled.

use secrets_scanner::{ProxyError, ScanConfig, Scanner};

/// Inline ruleset: one keyworded rule with an unbounded quantifier (so a single
/// match can span the whole payload) and no entropy/allowlist gating, keeping
/// matches deterministic.
const TOML: &str = r#"
title = "proxy-test"

[[rules]]
id = "test-token"
description = "Test token"
regex = '''tok_[A-Za-z0-9]+'''
keywords = ["tok_"]
"#;

fn proxy_scanner(config: ScanConfig) -> Scanner {
    Scanner::from_toml(TOML)
        .expect("inline TOML should parse")
        .with_config(config)
}

fn as_str(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("redacted output is valid utf-8")
}

#[test]
fn allow_marker_honored_by_default_but_ignored_in_proxy() {
    let content = "tok_ABCDEFGHIJKLMNOPQRST secrets-scanner:allow";

    // Default posture: the inline marker suppresses the finding (gitleaks compat).
    let default = Scanner::from_toml(TOML).expect("parse");
    assert!(
        default.scan_content("note.txt", content).is_empty(),
        "allow marker should suppress the finding under default config"
    );

    // Proxy posture: the attacker-supplied marker is ignored.
    let proxy = proxy_scanner(ScanConfig::proxy());
    let out = proxy
        .scan_proxy(content.as_bytes())
        .expect("within size cap");
    assert_eq!(out.findings.len(), 1, "proxy must ignore the allow marker");
    let redacted = as_str(&out.redacted);
    assert!(redacted.contains("[REDACTED_SECRET]"));
    assert!(
        !redacted.contains("tok_ABCDEFGHIJKLMNOPQRST"),
        "secret must not be forwarded in the clear"
    );
}

#[test]
fn scan_proxy_fails_closed_on_oversize() {
    let config = ScanConfig {
        max_file_size: 8,
        ..ScanConfig::proxy()
    };
    let scanner = proxy_scanner(config);
    let content = b"tok_ABCDEFGHIJKLMNOPQRST"; // 24 bytes > 8

    match scanner.scan_proxy(content) {
        Err(ProxyError::InputTooLarge { size, max }) => {
            assert_eq!(size, content.len());
            assert_eq!(max, 8);
        }
        other => panic!("expected InputTooLarge, got {other:?}"),
    }
}

#[test]
fn per_file_finding_cap_enforced_in_scan_bytes() {
    // Three distinct (non-overlapping) matches, cap at 2.
    let content = "tok_AAAAAAAAAA tok_BBBBBBBBBB tok_CCCCCCCCCC";
    let config = ScanConfig {
        max_findings_per_file: Some(2),
        ..ScanConfig::proxy()
    };
    let scanner = proxy_scanner(config);
    let out = scanner
        .scan_proxy(content.as_bytes())
        .expect("within size cap");
    assert_eq!(
        out.findings.len(),
        2,
        "scan_bytes must enforce the per-content cap, not just the walk"
    );
}

#[test]
fn long_match_is_omitted_not_amplified() {
    // One match longer than the proxy `max_matched_len` (256).
    let token = format!("tok_{}", "A".repeat(400));
    let scanner = proxy_scanner(ScanConfig::proxy());
    let out = scanner
        .scan_proxy(token.as_bytes())
        .expect("within size cap");

    assert_eq!(out.findings.len(), 1);
    let matched = &out.findings[0].matched;
    assert!(
        matched.starts_with("[MATCH OMITTED:"),
        "long match should be summarized, not turned into a payload-length string: {matched}"
    );
    // Forwarded content is still redacted with the fixed marker.
    let redacted = as_str(&out.redacted);
    assert!(redacted.contains("[REDACTED_SECRET]"));
    assert!(!redacted.contains(&token));
}

#[test]
fn context_not_captured_in_proxy_but_captured_by_default() {
    let content = "line one\ntok_ABCDEFGHIJKLMNOPQRST\nline three";

    let default = Scanner::from_toml(TOML).expect("parse");
    let default_findings = default.scan_content("note.txt", content);
    assert_eq!(default_findings.len(), 1);
    assert!(
        !default_findings[0].context_lines.is_empty(),
        "default config captures context"
    );

    let proxy = proxy_scanner(ScanConfig::proxy());
    let out = proxy
        .scan_proxy(content.as_bytes())
        .expect("within size cap");
    assert_eq!(out.findings.len(), 1);
    assert!(
        out.findings[0].context_lines.is_empty(),
        "proxy config skips context capture"
    );
}
