use super::*;

fn test_scanner() -> Scanner {
    let toml = r#"
title = "test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    Scanner::from_toml(toml).expect("should build test scanner")
}

#[test]
fn scan_and_redact_content_replaces_one_secret() {
    let scanner = test_scanner();
    let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    let content = format!("GITHUB_TOKEN={secret}");

    let output = scanner.scan_and_redact_content("config.yml", &content);

    assert!(output.has_findings(), "proxy scan should report findings");
    assert_eq!(output.findings[0].rule_id, "github-pat");
    assert_eq!(output.redacted, "GITHUB_TOKEN=[REDACTED_SECRET]");
    assert!(
        !output.redacted.contains(secret),
        "redacted content must not contain the original secret"
    );
}

#[test]
fn per_file_cap_does_not_leave_dropped_secret_in_survivor_context() {
    // Two secrets on adjacent lines: each falls inside the other's context
    // window. With the per-file cap dropping one finding, the survivor's context
    // must still have the dropped secret redacted (context redaction runs over
    // the full finding set BEFORE the cap truncates). Regression for the cap
    // ordering bug that left the dropped secret raw in the survivor's context.
    let scanner = test_scanner().with_config(ScanConfig {
        redact: true,
        capture_context: true,
        max_findings_per_file: Some(1),
        ..Default::default()
    });
    let secret_a = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let secret_b = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let content = format!("A={secret_a}\nB={secret_b}");

    let findings = scanner.scan_content("dense.env", &content);
    assert_eq!(findings.len(), 1, "cap should keep exactly one finding");

    for (_, line_text) in &findings[0].context_lines {
        assert!(
            !line_text.contains(secret_a) && !line_text.contains(secret_b),
            "no raw secret may survive in the kept finding's context: {line_text}"
        );
    }
}

#[test]
fn context_redaction_expands_to_utf8_boundaries() {
    let toml = r#"
title = "utf8-boundary"

[[rules]]
id = "single-byte-secret"
regex = 'KEY=(.)'
secretGroup = 1
keywords = ["key="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let findings = scanner.scan_content("unicode.env", "KEY=é");

    assert_eq!(findings.len(), 1);
    let line = &findings[0].context_lines[0].1;
    assert_eq!(line, "KEY=[REDACTED_SECRET]");
    assert!(
        !line.contains('\u{fffd}'),
        "context redaction must not bisect UTF-8: {line}"
    );
}

#[test]
fn proxy_redaction_expands_to_utf8_boundaries() {
    // A `(?-u)` rule matches a single byte, so against a multibyte char the match
    // ends mid-codepoint. `redact_content_bytes` must widen the range to char
    // boundaries; otherwise the trailing continuation byte becomes invalid UTF-8
    // and `from_utf8_lossy` mangles the forwarded tail into U+FFFD.
    let toml = r#"
title = "byte-boundary"

[[rules]]
id = "byte-boundary-secret"
regex = '(?-u)KEY=.'
keywords = ["key="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "KEY=é tail";

    let output = scanner.scan_and_redact_content("unicode.env", content);

    assert_eq!(output.findings.len(), 1);
    assert_eq!(
        output.redacted, "[REDACTED_SECRET] tail",
        "boundary-expanded redaction should cover the whole char and keep the tail"
    );
    assert!(
        !output.redacted.contains('\u{fffd}'),
        "proxy redaction must not bisect UTF-8: {}",
        output.redacted
    );
}

#[test]
fn proxy_redaction_coalesces_adjacent_markers_across_split_char() {
    // Two separate secrets sit on either side of a multibyte char that `(?-u)`
    // byte rules split. Their merged ranges have a one-byte gap (the `é`
    // continuation byte) that boundary expansion closes, making the ranges touch.
    // The redactor must extend the first marker, not emit an adjacent duplicate.
    let toml = r#"
title = "coalesce"

[[rules]]
id = "head"
regex = '(?-u)KEY=.'
keywords = ["key="]

[[rules]]
id = "tail"
regex = '(?-u) Z'
keywords = [" z"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    // bytes: K E Y = C3 A9 ' ' Z — `head` matches `KEY=\xC3`, `tail` matches ` Z`,
    // and the `\xA9` continuation byte between them is the gap expansion closes.
    let content = "KEY=é Z";

    let output = scanner.scan_and_redact_content("unicode.env", content);

    assert_eq!(output.findings.len(), 2);
    assert_eq!(
        output.redacted, "[REDACTED_SECRET]",
        "touching expanded ranges must coalesce into one marker, not a duplicate: {}",
        output.redacted
    );
}

#[test]
fn scan_and_redact_content_replaces_multiple_secrets() {
    let toml = r#"
title = "multi-redact"

[[rules]]
id = "api-token"
regex = 'sk_[A-Za-z0-9]{10,}'
keywords = ["sk_"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "a=sk_ABCDEFGHIJ b=sk_KLMNOPQRST";

    let output = scanner.scan_and_redact_content("tokens.env", content);

    assert_eq!(output.findings.len(), 2);
    assert_eq!(output.redacted, "a=[REDACTED_SECRET] b=[REDACTED_SECRET]");
}

#[test]
fn scan_and_redact_content_merges_overlapping_findings() {
    let toml = r#"
title = "overlap-redact"

[[rules]]
id = "secret-value"
regex = 'SECRET_[A-Z0-9]{10}'
keywords = ["secret_"]

[[rules]]
id = "assignment"
regex = 'TOKEN=SECRET_[A-Z0-9]{10}'
keywords = ["token="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "before TOKEN=SECRET_ABC1234567 after";

    let output = scanner.scan_and_redact_content("tokens.env", content);

    assert_eq!(output.findings.len(), 2);
    assert_eq!(output.redacted, "before [REDACTED_SECRET] after");
}

#[test]
fn scan_and_redact_content_preserves_clean_content() {
    let scanner = test_scanner();
    let content = "regular_setting=not_a_secret";

    let output = scanner.scan_and_redact_content("config.yml", content);

    assert!(!output.has_findings());
    assert_eq!(output.redacted, content);
}

#[test]
fn scan_and_redact_content_reports_path_only_without_mutation() {
    let toml = r#"
title = "path-only"

[[rules]]
id = "sensitive-path"
description = "Sensitive path"
path = 'secret\.txt$'
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "nothing secret in the file body";

    let output = scanner.scan_and_redact_content("config/secret.txt", content);

    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].rule_id, "sensitive-path");
    assert_eq!(output.redacted, content);
}

#[test]
fn scan_and_redact_bytes_replaces_secret_bytes() {
    let scanner = test_scanner();
    let content = b"GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";

    let output = scanner.scan_and_redact_bytes("config.yml", content);

    assert_eq!(output.redacted, b"GITHUB_TOKEN=[REDACTED_SECRET]".to_vec());
}

#[test]
fn scan_and_redact_content_uses_secret_group_range() {
    let toml = r#"
title = "secret-group-redact"

[[rules]]
id = "pat-with-prefix"
regex = 'KEY=(ghp_[A-Za-z0-9_]{36,})'
secretGroup = 1
keywords = ["key="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let secret = "ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let content = format!("KEY={secret}");

    let output = scanner.scan_and_redact_content("tokens.env", &content);

    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.redacted, "KEY=[REDACTED_SECRET]");
    assert_eq!(output.findings[0].start_offset, 0);
    assert_eq!(output.findings[0].end_offset, content.len());
    assert_eq!(output.findings[0].secret_start_offset, "KEY=".len());
    assert_eq!(output.findings[0].secret_end_offset, content.len());
}

#[test]
fn scan_and_redact_content_falls_back_when_secret_group_is_empty() {
    let toml = r#"
title = "empty-secret-group-redact"

[[rules]]
id = "pat-with-empty-group"
regex = 'TOKEN=(ghp_[A-Za-z0-9_]{36,})()'
secretGroup = 2
keywords = ["token="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let secret = "ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let content = format!("TOKEN={secret}");

    let output = scanner.scan_and_redact_content("tokens.env", &content);

    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.redacted, "[REDACTED_SECRET]");
    assert!(!output.redacted.contains(secret));
    assert_eq!(output.findings[0].secret_start_offset, 0);
    assert_eq!(output.findings[0].secret_end_offset, content.len());
}

#[test]
fn scan_and_redact_content_keeps_findings_redacted_by_default() {
    let scanner = test_scanner();
    let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    let content = format!("GITHUB_TOKEN={secret}");

    let output = scanner.scan_and_redact_content("config.yml", &content);

    assert!(!output.findings[0].matched.contains(secret));
    assert!(
        output.findings[0].matched.contains('*'),
        "finding display should keep existing default redaction"
    );
}

#[test]
fn scan_path_runs_unkeyworded_rules_without_keyword_first_byte() {
    use std::io::Write;

    let toml = r#"
title = "unkeyworded-file-scan"

[[rules]]
id = "keyworded-rule"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]

[[rules]]
id = "unkeyworded-rule"
regex = 'UNKEYED_SECRET_[0-9]{4}'
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let mut tmp = tempfile::NamedTempFile::new().expect("tmpfile");
    writeln!(tmp, "UNKEYED_SECRET_1234").expect("write");

    let path = tmp.path().to_str().expect("path str");
    let findings = scanner.scan_path(path);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "unkeyworded-rule");
}
