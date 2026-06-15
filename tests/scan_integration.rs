//! Integration tests for the secrets-scanner scan pipeline.
//!
//! These tests create temporary files (or use in-memory content) to exercise
//! the full scan path, including entropy gating, path and content allowlists,
//! and output redaction.

use secrets_scanner::{ScanConfig, Scanner};

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// Build a scanner from the bundled ruleset.
fn bundled_scanner() -> Scanner {
    Scanner::from_bundled().expect("bundled rules should load")
}

/// Build a scanner from an inline TOML snippet (for isolated rule tests).
fn scanner_from_toml(toml: &str) -> Scanner {
    Scanner::from_toml(toml).expect("inline TOML should parse")
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {:?} failed", args);
}

// ─────────────────────────────────────────────
// Bundled-ruleset smoke tests
// ─────────────────────────────────────────────

// Snapshot fixtures for the bundled ruleset. Bump these deliberately when rules
// are added/removed; a DROP signals accidental rule deletion (TODO Testing item 12).
// A simple `> 100` threshold would not catch deleting, say, 100 rules.
// Lean bundled ruleset after manifest-driven merge + detection-equivalent dedup
// (gitleaks + local + kingfisher; 1217 raw rules -> 1136 after dedup -> 987 compile
// under Rust's regex engine, the rest using unsupported look-around). The
// all-features build enables `full-ruleset`, adding secrets-patterns-db.
#[cfg(not(feature = "full-ruleset"))]
const EXPECTED_RULE_COUNT: usize = 987;
#[cfg(feature = "full-ruleset")]
const EXPECTED_RULE_COUNT: usize = 2586;
#[cfg(not(feature = "full-ruleset"))]
const EXPECTED_KEYWORD_COUNT: usize = 750;
#[cfg(feature = "full-ruleset")]
const EXPECTED_KEYWORD_COUNT: usize = 1500;

#[test]
fn bundled_rules_match_snapshot_counts() {
    let scanner = bundled_scanner();
    assert_eq!(
        scanner.engine().rule_count(),
        EXPECTED_RULE_COUNT,
        "bundled rule count changed; update EXPECTED_RULE_COUNT if intentional, \
         otherwise investigate accidental rule deletion"
    );
    assert_eq!(
        scanner.engine().keyword_count(),
        EXPECTED_KEYWORD_COUNT,
        "bundled keyword count changed; update EXPECTED_KEYWORD_COUNT if intentional, \
         otherwise investigate accidental rule deletion"
    );
}

// ─────────────────────────────────────────────
// Planted secrets
// ─────────────────────────────────────────────

#[test]
fn detects_github_pat_in_content() {
    let scanner = bundled_scanner();
    // Use a realistic token: random-ish suffix to pass entropy gate
    let content = "export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("deploy.sh", content);
    assert!(
        !findings.is_empty(),
        "should detect GitHub PAT; got zero findings for: {content}"
    );
    assert_eq!(findings[0].rule_id, "github-pat");
}

#[test]
fn detects_github_pat_line_number_is_accurate() {
    let scanner = bundled_scanner();
    // The secret is on line 3.
    let content = "# config\n# production\nexport TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde\n";
    let findings = scanner.scan_content("config.sh", content);
    assert!(!findings.is_empty(), "should detect GitHub PAT");
    assert_eq!(findings[0].line, 3, "line number should be 3");
}

#[test]
fn finding_col_is_accurate() {
    let scanner = bundled_scanner();
    // The secret sits on line 2, after a known-width prefix. The github-pat
    // regex matches starting at `ghp_`, so the 1-based column is prefix.len() + 1.
    let prefix = "export TOKEN=";
    let token = "ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let content = format!("# header\n{prefix}{token}");
    let findings = scanner.scan_content("config.sh", &content);
    assert!(!findings.is_empty(), "should detect GitHub PAT");
    assert_eq!(findings[0].line, 2, "secret is on line 2");
    assert_eq!(
        findings[0].col,
        prefix.len() + 1,
        "col should be the 1-based byte offset of the match within its line"
    );
}

#[test]
fn detects_pem_private_key_in_content() {
    // Use an inline ruleset so this test is independent of which bundled rules
    // happen to be loaded (many bundled rules use look-around and are skipped).
    let toml = r#"
title = "pem-test"

[[rules]]
id = "pem-private-key"
description = "PEM private key header"
regex = '-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----'
keywords = ["-----begin"]
"#;
    let scanner = scanner_from_toml(toml);
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF\n-----END RSA PRIVATE KEY-----\n";
    let findings = scanner.scan_content("id_rsa", content);
    assert!(!findings.is_empty(), "should detect PEM private key");
    assert_eq!(findings[0].rule_id, "pem-private-key");
}

// ─────────────────────────────────────────────
// Entropy gate
// ─────────────────────────────────────────────

#[test]
fn entropy_gate_suppresses_low_entropy_matches() {
    // A rule-isolated scanner with entropy threshold so we can test precisely.
    let toml = r#"
title = "entropy-test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b((?:AKIA|ASIA)[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia", "asia"]
"#;
    let scanner = scanner_from_toml(toml);
    // All-same-char suffix → near-zero entropy.
    let content = r#"key = "AKIAAAAAAAAAAAAAAAAA""#;
    let findings = scanner.scan_content("test.env", content);
    assert!(
        findings.is_empty(),
        "low-entropy AKIA should be filtered out by entropy gate"
    );
}

#[test]
fn entropy_gate_passes_high_entropy_matches() {
    let toml = r#"
title = "entropy-test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b((?:AKIA|ASIA)[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia", "asia"]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        redact: false,
        ..Default::default()
    });
    // Mixed-case/digit suffix → entropy above the 3.0 threshold.
    let content = r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#;
    let findings = scanner.scan_content("test.env", content);
    assert!(
        !findings.is_empty(),
        "high-entropy AKIA key should pass the entropy gate"
    );
    assert_eq!(findings[0].rule_id, "aws-access-token");
    assert!(
        findings[0].entropy > 3.0,
        "secret entropy should exceed the 3.0 threshold, got {}",
        findings[0].entropy
    );
}

// ─────────────────────────────────────────────
// Global allowlist — path suppression
// ─────────────────────────────────────────────

#[test]
fn global_allowlist_path_suppresses_entire_file() {
    let toml = r#"
title = "allowlist-test"

[allowlist]
description = "skip test fixtures"
paths = ['test_fixtures/']

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = scanner_from_toml(toml);
    // Path matches the global allowlist → should produce no findings.
    let content = "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("test_fixtures/config.sh", content);
    assert!(
        findings.is_empty(),
        "file in globally allowlisted path should produce no findings"
    );
}

#[test]
fn global_allowlist_path_does_not_suppress_other_files() {
    let toml = r#"
title = "allowlist-test"

[allowlist]
description = "skip test fixtures"
paths = ['test_fixtures/']

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = scanner_from_toml(toml);
    // Different path → should still find the secret.
    let content = "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("src/config.sh", content);
    assert!(
        !findings.is_empty(),
        "file not in allowlisted path should still produce findings"
    );
}

// ─────────────────────────────────────────────
// Global allowlist — content (stopwords / regex)
// ─────────────────────────────────────────────

#[test]
fn global_stopword_suppresses_finding() {
    let toml = r#"
title = "stopword-test"

[allowlist]
stopwords = ["placeholder"]

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = scanner_from_toml(toml);
    // The matched text itself won't contain "placeholder", but the secret part won't.
    // Test that a match whose secret *is* the stopword gets suppressed.
    // For this we use a direct content match where stopword appears in the match.
    let content = "export TOKEN=ghp_placeholderplaceholderplaceholde";
    let findings = scanner.scan_content("src/config.sh", content);
    // The match contains "placeholder" → suppressed.
    assert!(
        findings.is_empty(),
        "finding containing global stopword should be suppressed"
    );
}

// ─────────────────────────────────────────────
// Per-rule allowlist — stopwords
// ─────────────────────────────────────────────

#[test]
fn per_rule_stopword_suppresses_finding() {
    let toml = r#"
title = "per-rule-stopword-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
allowlists = [
    { stopwords = ["example", "sample"] }
]
"#;
    let scanner = scanner_from_toml(toml);
    let content = "GITHUB_TOKEN=ghp_exampleexampleexampleexampleexampleexam";
    let findings = scanner.scan_content("config.yml", content);
    assert!(
        findings.is_empty(),
        "per-rule stopword should suppress the finding"
    );
}

#[test]
fn per_rule_stopword_does_not_suppress_real_secret() {
    let toml = r#"
title = "per-rule-stopword-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
allowlists = [
    { stopwords = ["example"] }
]
"#;
    let scanner = scanner_from_toml(toml);
    // This token doesn't contain "example".
    let content = "GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("config.yml", content);
    assert!(
        !findings.is_empty(),
        "real secret not containing stopword should still be detected"
    );
}

// ─────────────────────────────────────────────
// Redaction
// ─────────────────────────────────────────────

#[test]
fn redacts_matched_secret_by_default() {
    let toml = r#"
title = "redact-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = scanner_from_toml(toml); // redact = true by default
    let content = "TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("config.yml", content);
    assert!(!findings.is_empty(), "should find secret");
    assert!(
        findings[0].matched.contains('*'),
        "matched field should be redacted by default"
    );
}

#[test]
fn no_redact_config_shows_full_secret() {
    let toml = r#"
title = "redact-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        redact: false,
        ..Default::default()
    });
    let content = "TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("config.yml", content);
    assert!(!findings.is_empty(), "should find secret");
    assert!(
        !findings[0].matched.contains('*'),
        "matched field should NOT be redacted when redact=false"
    );
}

// ─────────────────────────────────────────────
// secretGroup capture
// ─────────────────────────────────────────────

#[test]
fn secret_group_extracts_correct_capture_group() {
    // Rule with secretGroup=1, so entropy check and redaction use group 1.
    let toml = r#"
title = "secret-group-test"

[[rules]]
id = "pat-with-prefix"
description = "PAT with KEY= prefix"
regex = 'KEY=(ghp_[A-Za-z0-9_]{36,})'
secretGroup = 1
keywords = ["key="]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        redact: false,
        ..Default::default()
    });
    let content = "KEY=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    let findings = scanner.scan_content("test.sh", content);
    assert!(!findings.is_empty(), "secretGroup rule should fire");
    assert_eq!(findings[0].rule_id, "pat-with-prefix");
    // The displayed match is the whole regex match (group 0), with redaction off.
    assert_eq!(findings[0].matched, content);
    // The entropy is computed on the secret capture group (the token), which is
    // high-entropy, so it must be well above zero.
    assert!(
        findings[0].entropy > 3.0,
        "entropy should be computed on the high-entropy group-1 token, got {}",
        findings[0].entropy
    );
}

// ─────────────────────────────────────────────
// Per-rule allowlist — path entries
// ─────────────────────────────────────────────

#[test]
fn per_rule_allowlist_path_suppresses_finding_for_matching_file() {
    let toml = r#"
title = "per-rule-path-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
allowlists = [
    { paths = ['test_fixtures/'] }
]
"#;
    let scanner = scanner_from_toml(toml);
    let content = "GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    // File path matches the allowlist path → suppressed.
    let findings = scanner.scan_content("test_fixtures/config.sh", content);
    assert!(
        findings.is_empty(),
        "per-rule allowlist path should suppress finding for matching file path"
    );
}

#[test]
fn per_rule_allowlist_path_does_not_suppress_non_matching_file() {
    let toml = r#"
title = "per-rule-path-test"

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
allowlists = [
    { paths = ['test_fixtures/'] }
]
"#;
    let scanner = scanner_from_toml(toml);
    let content = "GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
    // File path does NOT match the allowlist path → should still fire.
    let findings = scanner.scan_content("src/config.sh", content);
    assert!(
        !findings.is_empty(),
        "per-rule allowlist path should not suppress finding for non-matching file path"
    );
}

#[test]
fn scan_path_detects_secret_in_temp_file() {
    use std::io::Write;

    let scanner = bundled_scanner();
    let mut tmp = tempfile::NamedTempFile::new().expect("tmpfile");
    writeln!(tmp, "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde").expect("write");

    let path = tmp.path().to_str().expect("path str");
    let findings = scanner.scan_path(path);
    assert!(
        !findings.is_empty(),
        "scan_path should detect a GitHub PAT in a temp file"
    );
}

#[test]
fn scan_path_skips_files_exceeding_max_size() {
    use std::io::Write;

    // Set a very small max_file_size so the file is skipped.
    let scanner = bundled_scanner().with_config(ScanConfig {
        max_file_size: 10, // 10 bytes
        ..Default::default()
    });

    let mut tmp = tempfile::NamedTempFile::new().expect("tmpfile");
    writeln!(tmp, "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde").expect("write");

    let path = tmp.path().to_str().expect("path str");
    let findings = scanner.scan_path(path);
    assert!(
        findings.is_empty(),
        "files exceeding max_file_size should be skipped"
    );
}

#[test]
fn integration_test_allowlist_conditions_and_targets() {
    let toml = r#"
title = "Modern allowlists integration test"

[[allowlists]]
id = "comment-lines"
condition = "and"
regexTarget = "line"
regexes = ['^//.*$']
targetRules = ["aws-token"]

[[rules]]
id = "aws-token"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]
"#;
    let scanner = scanner_from_toml(toml);

    // Line starting with // contains the secret. It should be allowlisted.
    let content_comment = "// My key is AKIA1234567890ABCDEF\n";
    let findings = scanner.scan_content("test.rs", content_comment);
    assert!(
        findings.is_empty(),
        "Comment line with key should be allowlisted"
    );

    // Line that doesn't start with // contains the secret. It should NOT be allowlisted.
    let content_code = "let key = \"AKIA1234567890ABCDEF\";\n";
    let findings = scanner.scan_content("test.rs", content_code);
    assert!(
        !findings.is_empty(),
        "Code line with key should NOT be allowlisted"
    );
}

#[test]
fn git_mode_handles_paths_containing_newlines() {
    let toml = r#"
title = "git-nul-path-test"

[[rules]]
id = "secret"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        git: true,
        ..Default::default()
    });
    let repo = tempfile::tempdir().expect("repo");
    git(repo.path(), &["init", "-q"]);
    std::fs::write(repo.path().join("line\nbreak.txt"), "SECRET123456").expect("write secret");
    git(repo.path(), &["add", "."]);

    let findings = scanner.scan_path(repo.path().to_str().expect("repo path"));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "secret");
}

#[test]
fn git_diff_mode_preserves_tracked_only_scope() {
    let toml = r#"
title = "git-diff-scope-test"

[[rules]]
id = "secret"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        git_diff: true,
        ..Default::default()
    });
    let repo = tempfile::tempdir().expect("repo");
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "Test User"]);
    std::fs::write(repo.path().join("tracked.txt"), "clean").expect("write tracked");
    git(repo.path(), &["add", "tracked.txt"]);
    git(repo.path(), &["commit", "-q", "-m", "initial"]);
    std::fs::write(repo.path().join("tracked.txt"), "SECRET123456").expect("modify tracked");
    std::fs::write(repo.path().join("untracked.txt"), "SECRET654321").expect("write untracked");

    let findings = scanner.scan_path(repo.path().to_str().expect("repo path"));

    assert_eq!(findings.len(), 1);
    assert!(findings[0].file.ends_with("tracked.txt"));
}

#[cfg(unix)]
#[test]
fn git_mode_skips_tracked_symlink_targets() {
    let toml = r#"
title = "git-symlink-test"

[[rules]]
id = "secret"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;
    let scanner = scanner_from_toml(toml).with_config(ScanConfig {
        git: true,
        ..Default::default()
    });
    let temp = tempfile::tempdir().expect("temp");
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).expect("repo dir");
    git(&repo, &["init", "-q"]);
    let outside = temp.path().join("outside.txt");
    std::fs::write(&outside, "SECRET654321").expect("outside secret");
    std::os::unix::fs::symlink(&outside, repo.join("link.txt")).expect("symlink");
    git(&repo, &["add", "link.txt"]);

    let findings = scanner.scan_path(repo.to_str().expect("repo path"));

    assert!(
        findings.is_empty(),
        "git mode must not follow tracked symlinks"
    );
}
