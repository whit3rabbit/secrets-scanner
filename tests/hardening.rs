//! Hardening tests for hostile / adversarial repository content.
//!
//! Covers content-based binary detection, scan stats, result caps, diff-base and
//! untracked git scanning at the library level, plus CLI-level SARIF shape, exit
//! codes, and hostile-filename sanitization via the compiled binary.

use std::path::Path;
use std::process::Command;

use secrets_scanner::{BinaryPolicy, ScanConfig, Scanner};

/// A minimal inline ruleset used across these tests.
const SECRET_RULE: &str = r#"
title = "hardening-test"

[[rules]]
id = "secret"
description = "Test secret"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;

fn scanner(config: ScanConfig) -> Scanner {
    Scanner::from_toml(SECRET_RULE)
        .expect("inline TOML should parse")
        .with_config(config)
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn init_repo(repo: &Path) {
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    git(repo, &["config", "user.name", "Test User"]);
}

// ─────────────────────────────────────────────
// Content-based binary detection
// ─────────────────────────────────────────────

#[test]
fn binary_auto_skips_nul_byte_file() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("blob.dat"), b"SECRET123456\x00\x01\x02junk").expect("write");

    let scanner = scanner(ScanConfig::default()); // Auto
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert!(
        findings.is_empty(),
        "binary file should be skipped under Auto"
    );
    assert_eq!(stats.binary_skipped, 1);
    assert_eq!(stats.files_scanned, 0);
}

#[test]
fn binary_scan_policy_scans_binary_file() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("blob.dat"), b"SECRET123456\x00\x01\x02junk").expect("write");

    let scanner = scanner(ScanConfig {
        binary_policy: BinaryPolicy::Scan,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(findings.len(), 1, "Scan policy must scan binary content");
    assert_eq!(stats.binary_skipped, 0);
}

#[test]
fn binary_auto_scans_source_allowlisted_file() {
    let dir = tempfile::tempdir().expect("dir");
    // `.pem` is on the source/secret-bearing allowlist, so Auto scans it even
    // though the NUL byte makes it look binary.
    std::fs::write(dir.path().join("key.pem"), b"SECRET123456\x00\x01\x02junk").expect("write");

    let scanner = scanner(ScanConfig::default()); // Auto
    let (findings, _) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(
        findings.len(),
        1,
        "allowlisted file should be scanned under Auto"
    );
}

#[test]
fn binary_skip_policy_ignores_allowlist() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("key.pem"), b"SECRET123456\x00\x01\x02junk").expect("write");

    let scanner = scanner(ScanConfig {
        binary_policy: BinaryPolicy::Skip,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert!(findings.is_empty(), "Skip must not honor the allowlist");
    assert_eq!(stats.binary_skipped, 1);
}

// ─────────────────────────────────────────────
// Oversized files & stats
// ─────────────────────────────────────────────

#[test]
fn oversized_file_is_skipped_and_counted() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("big.txt"), "SECRET123456 padding padding").expect("write");

    let scanner = scanner(ScanConfig {
        max_file_size: 10,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert!(findings.is_empty(), "oversized file should be skipped");
    assert_eq!(stats.oversized_skipped, 1);
}

// ─────────────────────────────────────────────
// Result caps
// ─────────────────────────────────────────────

#[test]
fn max_files_caps_and_records_dropped() {
    let dir = tempfile::tempdir().expect("dir");
    for i in 0..3 {
        std::fs::write(dir.path().join(format!("f{i}.txt")), "SECRET123456").expect("write");
    }

    let scanner = scanner(ScanConfig {
        max_files: Some(1),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(stats.files_scanned, 1);
    assert_eq!(stats.files_over_cap, 2);
    assert_eq!(findings.len(), 1);
}

#[test]
fn max_findings_per_file_caps_findings() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(
        dir.path().join("many.txt"),
        "SECRET111111 SECRET222222 SECRET333333",
    )
    .expect("write");

    let scanner = scanner(ScanConfig {
        max_findings_per_file: Some(2),
        ..Default::default()
    });
    let (findings, _) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(findings.len(), 2, "per-file cap should truncate to 2");
}

// ─────────────────────────────────────────────
// Git diff-base & untracked
// ─────────────────────────────────────────────

#[test]
fn diff_base_scans_range_against_base() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("clean.txt"), "nothing here").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    std::fs::write(repo.path().join("secret.txt"), "SECRET123456").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add secret"]);

    let scanner = scanner(ScanConfig {
        git_diff: true,
        diff_base: Some("HEAD~1".to_string()),
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));

    assert_eq!(findings.len(), 1);
    assert!(findings[0].file.ends_with("secret.txt"));
}

#[test]
fn include_untracked_scans_untracked_files() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("tracked.txt"), "clean").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    // Untracked-but-not-ignored file with a secret.
    std::fs::write(repo.path().join("new.txt"), "SECRET123456").expect("write");

    // Without --include-untracked, ls-files won't see it.
    let tracked_only = scanner(ScanConfig {
        git: true,
        ..Default::default()
    });
    assert!(
        tracked_only
            .scan_path(repo.path().to_str().expect("path"))
            .is_empty(),
        "untracked file must be invisible without include_untracked"
    );

    let with_untracked = scanner(ScanConfig {
        git: true,
        include_untracked: true,
        ..Default::default()
    });
    let findings = with_untracked.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert!(findings[0].file.ends_with("new.txt"));
}

// ─────────────────────────────────────────────
// CLI: SARIF shape, exit codes, sanitization
// ─────────────────────────────────────────────

const BIN: &str = env!("CARGO_BIN_EXE_secrets-scanner");

/// Write an inline rules file detecting a high-entropy GitHub-PAT-like token.
fn write_pat_rules(dir: &Path) -> std::path::PathBuf {
    let rules = dir.join("rules.toml");
    std::fs::write(
        &rules,
        r#"
title = "pat"
[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#,
    )
    .expect("write rules");
    rules
}

const PAT: &str = "ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";

#[test]
fn cli_sarif_is_valid_and_omits_secret() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    std::fs::write(dir.path().join("app.txt"), format!("TOKEN={PAT}")).expect("write");
    let sarif = dir.path().join("out.sarif");

    let status = Command::new(BIN)
        .args(["scan", dir.path().to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--format", "sarif"])
        .args(["--output", sarif.to_str().expect("sarif")])
        .args(["--no-context", "--no-fail"])
        .status()
        .expect("run scanner");
    assert!(status.success(), "should exit 0 with --no-fail");

    let raw = std::fs::read_to_string(&sarif).expect("read sarif");
    assert!(
        !raw.contains(PAT) && !raw.contains("n0tArEaL"),
        "SARIF must not contain the secret value"
    );

    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid SARIF JSON");
    assert_eq!(doc["version"], "2.1.0");
    let result = &doc["runs"][0]["results"][0];
    let msg = result["message"]["text"].as_str().expect("message text");
    assert!(msg.starts_with("Potential secret detected by rule"));
    assert!(result["partialFingerprints"]["secretsScanner/v1"].is_string());
    let region = &result["locations"][0]["physicalLocation"]["region"];
    assert!(region["endColumn"].is_number());
    let loc = &result["locations"][0]["physicalLocation"]["artifactLocation"];
    assert_eq!(loc["uri"], "app.txt", "uri should be repo-relative");
    assert_eq!(loc["uriBaseId"], "SRCROOT");
}

#[test]
fn cli_exit_codes() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    let target = dir.path().join("app.txt");
    std::fs::write(&target, format!("TOKEN={PAT}")).expect("write");
    let t = target.to_str().expect("target");
    let r = rules.to_str().expect("rules");

    let code = |args: &[&str]| {
        Command::new(BIN)
            .args(args)
            .status()
            .expect("run")
            .code()
            .expect("exit code")
    };

    assert_eq!(
        code(&["scan", t, "--rules", r, "--format", "json"]),
        1,
        "findings → 1"
    );
    assert_eq!(
        code(&["scan", t, "--rules", r, "--format", "json", "--no-fail"]),
        0,
        "--no-fail → 0"
    );
    assert_eq!(
        code(&["scan", t, "--rules", "/no/such/rules.toml"]),
        3,
        "invalid rules → 3"
    );
}

#[cfg(unix)]
#[test]
fn cli_text_output_sanitizes_control_chars_in_filename() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    // Filename containing an ESC byte (would inject ANSI if printed raw).
    let evil = dir.path().join("a\x1bb.txt");
    std::fs::write(&evil, format!("TOKEN={PAT}")).expect("write");

    let out = Command::new(BIN)
        .args(["scan", evil.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--format", "text", "--no-fail"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("\\x1b"),
        "ESC should be escaped in text output"
    );
    assert!(
        !stdout.contains('\x1b'),
        "raw ESC must not reach the terminal"
    );
}
