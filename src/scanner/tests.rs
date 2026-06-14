use super::*;

fn test_scanner() -> Scanner {
    let toml = r#"
title = "test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b(AKIA[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia"]

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]

[[rules]]
id = "pem-private-key"
description = "PEM private key"
regex = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
keywords = ["-----begin"]
"#;
    Scanner::from_toml(toml).expect("should build test scanner")
}

#[test]
fn detects_aws_key() {
    let scanner = test_scanner();
    // A fake AWS key with high entropy: AKIA + exactly 16 chars in [A-Z2-7].
    let content = r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#;
    let findings = scanner.scan_content("test.env", content);

    assert!(!findings.is_empty(), "should detect AWS access key");
    assert_eq!(findings[0].rule_id, "aws-access-token");
    assert_eq!(findings[0].line, 1);
}

#[test]
fn detects_github_pat() {
    let scanner = test_scanner();
    let content = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    let findings = scanner.scan_content("config.yml", content);

    assert!(!findings.is_empty(), "should detect GitHub PAT");
    assert_eq!(findings[0].rule_id, "github-pat");
}

#[test]
fn detects_pem_key() {
    let scanner = test_scanner();
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
    let findings = scanner.scan_content("key.pem", content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert_eq!(findings[0].rule_id, "pem-private-key");
}

#[test]
fn skips_low_entropy() {
    let scanner = test_scanner();
    // AKIA followed by low-entropy chars
    let content = r#"key = "AKIAAAAAAAAAAAAAAAAA""#;
    let findings = scanner.scan_content("test.env", content);
    // Should be empty due to low entropy
    assert!(
        findings.is_empty(),
        "low-entropy AKIA should be filtered out"
    );
}

#[test]
fn redacts_by_default() {
    let scanner = test_scanner();
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
    let findings = scanner.scan_content("key.pem", content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert!(
        findings[0].matched.contains('*'),
        "should redact matched text"
    );
}

#[test]
fn respects_no_redact_config() {
    let scanner = test_scanner().with_config(ScanConfig {
        redact: false,
        ..Default::default()
    });
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
    let findings = scanner.scan_content("key.pem", content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert!(
        !findings[0].matched.contains('*'),
        "should not redact when config says no"
    );
}

#[test]
fn loads_bundled_and_scans() {
    // Smoke test: load the real bundled rules and scan a known secret
    let scanner = Scanner::from_bundled().expect("bundled rules should load");
    assert!(scanner.engine().rule_count() > 100);

    // Scan content with a planted GitHub PAT (avoid contiguous alphabet to bypass global stopwords allowlist)
    let content = "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("deploy.sh", content);
    // Should find at least one hit (github-pat or generic-api-key)
    assert!(
        !findings.is_empty(),
        "bundled scanner should detect planted GitHub PAT"
    );
}

#[test]
fn detects_match_outside_keyword_window() {
    let toml = r#"
title = "window-test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b(AKIA[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia"]
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    // Place keyword "akia" at the start, and the actual match AKIAIOSFODNN7EXAMPLE far down.
    // 300 spaces are more than enough to push it way past the 120-byte window.
    let content = format!("akia {}\n\n{}", " ".repeat(300), "AKIAIOSFODNN7EXAMPLE");
    let findings = scanner.scan_content("test.env", &content);
    assert!(
        !findings.is_empty(),
        "should detect match outside of keyword window"
    );
    assert_eq!(findings[0].rule_id, "aws-access-token");
    assert!(findings[0].start_offset > 300);
}

#[test]
fn detects_secret_with_fallback_rule_no_keywords() {
    let toml = r#"
title = "fallback-test"

[[rules]]
id = "slack-webhook"
description = "Slack Webhook"
regex = 'https://hooks\.slack\.com/services/[T|B][A-Za-z0-9_]{8}/[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}'
# no keywords defined
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    let content = "slack_url = \"https://hooks.slack.com/services/T12345678/B1234567/A12345678901234567890123\"";
    let findings = scanner.scan_content("config.py", content);
    assert!(
        !findings.is_empty(),
        "fallback rule with no keywords should run and detect secret"
    );
    assert_eq!(findings[0].rule_id, "slack-webhook");
}

#[test]
fn unkeyworded_scan_time_is_benchmarked() {
    let toml = r#"
title = "benchmarking-test"

[[rules]]
id = "no-keyword-rule"
regex = 'secret-[0-9]+'
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    assert_eq!(scanner.unkeyworded_scan_time_ns(), 0);

    let content = "my secret key is secret-12345";
    let findings = scanner.scan_content("secrets.txt", content);
    assert!(!findings.is_empty());

    let time_ns = scanner.unkeyworded_scan_time_ns();
    assert!(
        time_ns > 0,
        "unkeyworded scan time should be recorded and non-zero"
    );

    scanner.reset_unkeyworded_scan_time();
    assert_eq!(
        scanner.unkeyworded_scan_time_ns(),
        0,
        "reset should set time to 0"
    );
}

#[test]
fn min_entropy_override_keeps_structural_rules() {
    // A structural rule with NO entropy threshold (a fixed PEM header).
    let toml = r#"
title = "structural"

[[rules]]
id = "pem-private-key"
description = "PEM private key"
regex = '-----BEGIN (RSA |EC )?PRIVATE KEY-----'
keywords = ["-----begin"]
"#;
    // A high global --min-entropy floor must NOT impose entropy gating on a rule
    // that defines no threshold (otherwise real private keys would be missed).
    let scanner = Scanner::from_toml(toml)
        .expect("build")
        .with_config(ScanConfig {
            min_entropy_override: Some(7.0),
            ..Default::default()
        });
    let content = "-----BEGIN RSA PRIVATE KEY-----";
    let findings = scanner.scan_content("id_rsa", content);
    assert!(
        !findings.is_empty(),
        "structural rule (no entropy threshold) must survive a high --min-entropy floor"
    );
    assert_eq!(findings[0].rule_id, "pem-private-key");
}

#[test]
fn distinct_rules_matching_same_span_are_both_reported() {
    // Two rules whose regexes match the EXACT same span; both should be reported
    // (position-only dedup would drop the second rule's finding). Distinct
    // keywords ensure both rules become candidates and actually run.
    let toml = r#"
title = "overlap"

[[rules]]
id = "rule-a"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]

[[rules]]
id = "rule-b"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["key"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "key = AKIA1234567890ABCDEF";
    let findings = scanner.scan_content("test.env", content);
    let ids: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains("rule-a"), "rule-a should report");
    assert!(
        ids.contains("rule-b"),
        "rule-b should report — identical spans from different rules must not be deduped"
    );
}

#[test]
fn context_lines_span_two_lines_each_side() {
    let toml = r#"
title = "ctx"

[[rules]]
id = "github-pat"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    // Secret on line 3; expect ±2 lines of context (lines 1..=5), excluding line 6.
    let content =
        "line1\nline2\nTOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde\nline4\nline5\nline6";
    let findings = scanner.scan_content("c.txt", content);
    assert!(!findings.is_empty());
    let f = &findings[0];
    assert_eq!(f.line, 3);
    let nums: Vec<usize> = f.context_lines.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        nums,
        vec![1, 2, 3, 4, 5],
        "context should span 2 lines on each side of the match"
    );
}
