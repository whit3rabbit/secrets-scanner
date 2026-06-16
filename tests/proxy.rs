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
fn scan_proxy_fails_closed_on_unhardened_config() {
    // A scanner left on the default (soft) config must not be usable as a proxy:
    // it would honor attacker allow markers, capture whole-payload context, and
    // leave findings/`matched` uncapped. scan_proxy rejects it before scanning.
    let scanner = Scanner::from_toml(TOML).expect("parse"); // default config
    match scanner.scan_proxy(b"tok_ABCDEFGHIJKLMNOPQRST") {
        Err(ProxyError::NotHardened) => {}
        other => panic!("expected NotHardened, got {other:?}"),
    }

    // The hardened preset is accepted. Raising a cap via with_config still passes
    // (presence, not exact value, is what is required).
    let raised = ScanConfig {
        max_matched_len: Some(4096),
        ..ScanConfig::proxy()
    };
    assert!(
        proxy_scanner(raised)
            .scan_proxy(b"tok_ABCDEFGHIJKLMNOPQRST")
            .is_ok(),
        "a hardened config with a raised cap must still be accepted"
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
fn proxy_findings_use_full_matched_redaction() {
    let secret = "tok_ABCDEFGHIJKLMNOPQRST";
    let scanner = proxy_scanner(ScanConfig::proxy());
    let out = scanner
        .scan_proxy(secret.as_bytes())
        .expect("within size cap");

    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].matched, "[REDACTED]");
}

#[test]
fn redaction_covers_secrets_past_the_finding_cap() {
    // Regression: redaction must run on the full pre-cap finding set. With the
    // per-content cap below the number of distinct secrets, the findings list is
    // truncated to the cap, but every detected secret must still be redacted out
    // of the forwarded payload. Redacting off the post-cap list would forward the
    // secrets past the cap in the clear (the fail-open hazard).
    let content = "tok_AAAAAAAAAA tok_BBBBBBBBBB tok_CCCCCCCCCC";
    let config = ScanConfig {
        max_findings_per_file: Some(1),
        ..ScanConfig::proxy()
    };
    let scanner = proxy_scanner(config);
    let out = scanner
        .scan_proxy(content.as_bytes())
        .expect("within size cap");

    assert_eq!(out.findings.len(), 1, "findings list is capped at 1");
    let redacted = as_str(&out.redacted);
    for secret in ["tok_AAAAAAAAAA", "tok_BBBBBBBBBB", "tok_CCCCCCCCCC"] {
        assert!(
            !redacted.contains(secret),
            "a secret past the finding cap must still be redacted, not forwarded: {redacted}"
        );
    }
    assert_eq!(
        redacted.matches("[REDACTED_SECRET]").count(),
        3,
        "all three secrets must be redacted even though findings are capped at 1"
    );
}

#[test]
fn proxy_redacts_all_matches_while_reporting_only_capped_findings() {
    let content = (0..150)
        .map(|idx| format!("tok_{idx:010}"))
        .collect::<Vec<_>>()
        .join(" ");
    let config = ScanConfig {
        max_findings_per_file: Some(3),
        ..ScanConfig::proxy()
    };
    let scanner = proxy_scanner(config);
    let out = scanner
        .scan_proxy(content.as_bytes())
        .expect("within size cap");

    assert_eq!(out.findings.len(), 3, "returned findings are capped");
    assert!(out.findings_truncated, "cap should be surfaced");
    let redacted = as_str(&out.redacted);
    assert!(
        !redacted.contains("tok_"),
        "all token prefixes must be redacted out of the forwarded payload"
    );
    assert_eq!(
        redacted.matches("[REDACTED_SECRET]").count(),
        150,
        "every detected secret should be redacted"
    );
}

#[test]
fn detailed_scan_reports_per_content_truncation() {
    let content = "tok_AAAAAAAAAA tok_BBBBBBBBBB";
    let config = ScanConfig {
        max_findings_per_file: Some(1),
        ..ScanConfig::proxy()
    };
    let scanner = proxy_scanner(config);

    let detailed = scanner.scan_content_detailed("input.env", content);
    assert!(detailed.has_findings());
    assert_eq!(detailed.findings.len(), 1);
    assert!(detailed.findings_truncated);

    let redacted = scanner.scan_and_redact_content("input.env", content);
    assert_eq!(redacted.findings.len(), 1);
    assert!(redacted.findings_truncated);
    assert!(!redacted.redacted.contains("tok_AAAAAAAAAA"));
    assert!(!redacted.redacted.contains("tok_BBBBBBBBBB"));
}

#[test]
fn path_stats_report_finding_truncation() {
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("input.env");
    std::fs::write(&file, "tok_AAAAAAAAAA tok_BBBBBBBBBB").expect("write");
    let config = ScanConfig {
        max_findings_per_file: Some(1),
        ..Default::default()
    };
    let scanner = proxy_scanner(config);

    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));
    assert_eq!(stats.files_scanned, 1);
    assert_eq!(findings.len(), 1);
    assert!(stats.findings_truncated);
}

#[test]
fn path_stats_report_total_finding_cap_truncation() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("a.env"), "tok_AAAAAAAAAA").expect("write a");
    std::fs::write(dir.path().join("b.env"), "tok_BBBBBBBBBB").expect("write b");
    let config = ScanConfig {
        max_findings: Some(1),
        ..Default::default()
    };
    let scanner = proxy_scanner(config);

    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert!(stats.findings_truncated);
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

#[test]
fn scan_proxy_rejects_partial_redaction_override() {
    use secrets_scanner::RedactionMode;

    // The proxy preset hard-codes Full (length-hiding) redaction. A caller that
    // keeps the rest of the preset but overrides to Partial would leak the
    // first/last 4 chars and length of every secret in the finding's `matched`
    // field. `is_hardened()` must reject it so `scan_proxy` fails closed.
    let cfg = ScanConfig {
        redaction_mode: RedactionMode::Partial,
        ..ScanConfig::proxy()
    };
    assert!(
        !cfg.is_hardened(),
        "Partial redaction must not count as a hardened posture"
    );

    let scanner = proxy_scanner(cfg);
    match scanner.scan_proxy(b"tok_ABCDEFGHIJKLMNOPQRST") {
        Err(ProxyError::NotHardened) => {}
        other => panic!("expected NotHardened for Partial-redaction proxy, got {other:?}"),
    }
}
