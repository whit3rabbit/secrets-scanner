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
fn binary_scan_policy_scans_text_in_skipped_extension() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("archive.zip"), b"SECRET123456").expect("write");

    let default_scanner = scanner(ScanConfig::default());
    let (default_findings, default_stats) =
        default_scanner.scan_path_with_stats(dir.path().to_str().expect("path"));
    assert!(
        default_findings.is_empty(),
        "default policy should still skip configured extensions"
    );
    assert_eq!(default_stats.files_scanned, 0);

    let scan_scanner = scanner(ScanConfig {
        binary_policy: BinaryPolicy::Scan,
        ..Default::default()
    });
    let (scan_findings, scan_stats) =
        scan_scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(
        scan_findings.len(),
        1,
        "Scan policy must bypass extension skips"
    );
    assert_eq!(scan_stats.files_scanned, 1);
}

#[test]
fn binary_scan_policy_still_skips_noisy_directories() {
    let dir = tempfile::tempdir().expect("dir");
    let nested = dir.path().join("node_modules/pkg");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::write(nested.join("archive.zip"), b"SECRET123456").expect("write");

    let scanner = scanner(ScanConfig {
        binary_policy: BinaryPolicy::Scan,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert!(findings.is_empty(), "noisy directories must stay skipped");
    assert_eq!(stats.files_scanned, 0);
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

#[test]
fn max_findings_caps_total_scan_results() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(
        dir.path().join("many.txt"),
        "SECRET111111 SECRET222222 SECRET333333",
    )
    .expect("write");

    let scanner = scanner(ScanConfig {
        max_findings: Some(1),
        ..Default::default()
    });
    let (findings, _) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(findings.len(), 1, "global cap should truncate to 1");
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
fn diff_base_rejects_dash_led_git_option() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("clean.txt"), "nothing here").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    std::fs::write(repo.path().join("secret.txt"), "SECRET123456").expect("write");
    let injected_output = repo.path().join("git-diff-output");

    let scanner = scanner(ScanConfig {
        git_diff: true,
        diff_base: Some(format!("--output={}", injected_output.display())),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(repo.path().to_str().expect("path"));

    assert!(
        stats.git_fallback,
        "invalid diff-base should fall back instead of trusting an empty git diff"
    );
    assert_eq!(
        findings.len(),
        1,
        "fallback directory walk should still report the working-tree secret"
    );
    assert!(
        !injected_output.exists()
            && !Path::new(&format!("{}...HEAD", injected_output.display())).exists(),
        "dash-led diff-base must not be parsed by git as --output"
    );
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

#[test]
fn cli_invalid_custom_regex_exits_3_without_scan() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = dir.path().join("bad.toml");
    std::fs::write(
        &rules,
        r#"
title = "bad"

[[rules]]
id = "bad-lookahead"
regex = '(?=TOKEN)TOKEN[0-9]+'
keywords = ["token"]
"#,
    )
    .expect("write bad rules");
    let target = dir.path().join("app.txt");
    std::fs::write(&target, "TOKEN123456").expect("write target");

    let out = Command::new(BIN)
        .args(["scan", target.to_str().expect("target")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--no-fail"])
        .output()
        .expect("run scanner");

    assert_eq!(out.status.code(), Some(3), "invalid custom rules → 3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("No secrets found"),
        "invalid custom rules must fail before scan output is written"
    );
}

#[cfg(unix)]
#[test]
fn cli_output_and_baseline_files_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    let target = dir.path().join("app.txt");
    std::fs::write(&target, format!("TOKEN={PAT}")).expect("write");
    let out_file = dir.path().join("findings.json");
    let baseline = dir.path().join("baseline.json");

    let scan = Command::new(BIN)
        .args(["scan", target.to_str().expect("target")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args([
            "--format",
            "json",
            "--output",
            out_file.to_str().expect("out"),
        ])
        .args(["--no-fail"])
        .status()
        .expect("run scan");
    assert!(scan.success(), "scan output should be written");

    let gen = Command::new(BIN)
        .args(["scan", target.to_str().expect("target")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--generate-baseline", baseline.to_str().expect("baseline")])
        .status()
        .expect("run baseline");
    assert!(gen.success(), "baseline should be written");

    for path in [&out_file, &baseline] {
        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{} should be owner-only", path.display());
    }
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

// ─────────────────────────────────────────────
// Staged-changes mode (pre-commit)
// ─────────────────────────────────────────────

#[test]
fn staged_mode_scans_only_staged_files() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("tracked.txt"), "clean").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);

    // Stage a new file with a secret.
    std::fs::write(repo.path().join("staged.txt"), "SECRET123456").expect("write");
    git(repo.path(), &["add", "staged.txt"]);
    // Modify a tracked file but DO NOT stage it — must be invisible to --staged.
    std::fs::write(repo.path().join("tracked.txt"), "SECRET654321").expect("write");

    let scanner = scanner(ScanConfig {
        git_staged: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));

    assert_eq!(findings.len(), 1, "only the staged file should be scanned");
    assert!(findings[0].file.ends_with("staged.txt"));
}

#[test]
fn staged_mode_reads_index_blob_not_working_tree() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("seed.txt"), "clean").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);

    // Stage a secret, then edit the WORKING TREE to remove it. The secret now
    // lives only in the index. A working-tree scan would miss it; --staged must
    // scan the index blob and still find it.
    let app = repo.path().join("app.txt");
    std::fs::write(&app, "key = SECRET123456").expect("stage secret");
    git(repo.path(), &["add", "app.txt"]);
    std::fs::write(&app, "key = (removed)").expect("scrub working tree");

    // A second file whose secret exists ONLY in the working tree (never staged)
    // must NOT be reported by --staged.
    std::fs::write(repo.path().join("untracked.txt"), "SECRET999999").expect("write");

    let scanner = scanner(ScanConfig {
        git_staged: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));

    assert_eq!(
        findings.len(),
        1,
        "only the staged index blob should be scanned: {findings:?}"
    );
    assert!(
        findings[0].file.ends_with("app.txt"),
        "the staged secret (present only in the index) must be found"
    );
}

#[test]
fn staged_mode_reads_paths_that_look_like_stage_selectors() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("foo"), "clean").expect("write clean");
    std::fs::write(repo.path().join("0:foo"), "SECRET123456").expect("write secret");
    git(repo.path(), &["add", "foo", "0:foo"]);

    let scanner = scanner(ScanConfig {
        git_staged: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));

    assert_eq!(
        findings.len(),
        1,
        "staged path named 0:foo must read that path, not stage-0 foo"
    );
    assert!(findings[0].file.ends_with("0:foo"));
}

// ─────────────────────────────────────────────
// Honest coverage: unreadable files are counted
// ─────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn unreadable_file_is_counted_as_errored() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("ok.txt"), "SECRET123456").expect("write");
    let locked = dir.path().join("locked.txt");
    std::fs::write(&locked, "SECRET999999").expect("write");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // Skip under root (where 000 is still readable) to avoid a flaky assertion.
    if std::fs::read(&locked).is_ok() {
        return;
    }

    let scanner = scanner(ScanConfig::default());
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(stats.files_scanned, 1, "only the readable file is scanned");
    assert_eq!(stats.errored, 1, "the unreadable file must be counted");
    assert_eq!(findings.len(), 1, "secret in the readable file is reported");
}

// ─────────────────────────────────────────────
// Non-git symlink rejection
// ─────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn non_git_symlink_target_is_not_scanned() {
    let dir = tempfile::tempdir().expect("dir");
    let outside = tempfile::tempdir().expect("outside");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "SECRET123456").expect("write");
    std::os::unix::fs::symlink(&secret, dir.path().join("link.txt")).expect("symlink");

    let scanner = scanner(ScanConfig::default());
    let findings = scanner.scan_path(dir.path().to_str().expect("path"));

    assert!(
        findings.is_empty(),
        "a symlink to an outside secret must not be followed"
    );
}

// ─────────────────────────────────────────────
// Inline suppression
// ─────────────────────────────────────────────

#[test]
fn inline_allow_marker_suppresses_finding() {
    let scanner = scanner(ScanConfig::default());

    let plain = scanner.scan_content("a.txt", "key = SECRET123456");
    assert_eq!(plain.len(), 1, "unmarked secret should be found");

    for marker in ["# gitleaks:allow", "// secrets-scanner:allow"] {
        let content = format!("key = SECRET123456 {marker}");
        let suppressed = scanner.scan_content("a.txt", &content);
        assert!(
            suppressed.is_empty(),
            "marker {marker:?} should suppress the finding"
        );
    }
}

// ─────────────────────────────────────────────
// CLI: baseline generate + line-tolerant suppression
// ─────────────────────────────────────────────

#[test]
fn cli_baseline_is_line_tolerant_and_reports_new_secrets() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    let app = dir.path().join("app.txt");
    std::fs::write(&app, format!("line1\nTOKEN={PAT}\n")).expect("write");
    let baseline = dir.path().join("baseline.json");

    // Generate a baseline of the existing finding; exits 0 even with findings.
    let gen = Command::new(BIN)
        .args(["scan", app.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--generate-baseline", baseline.to_str().expect("baseline")])
        .output()
        .expect("run");
    assert!(gen.status.success(), "generate-baseline should exit 0");
    assert!(baseline.exists(), "baseline file should be written");
    let baseline_json = std::fs::read_to_string(&baseline).expect("read baseline");
    assert!(
        baseline_json.contains("\"fingerprint\": \"sha256:"),
        "new baselines must store SHA v2 fingerprints: {baseline_json}"
    );

    // Move the known secret down a line and add a brand-new one above it.
    let new_pat = "ghp_BRAND0New0Secret0Token0123456789abcd";
    std::fs::write(
        &app,
        format!("line1\nline2\nTOKEN2={new_pat}\nTOKEN={PAT}\n"),
    )
    .expect("rewrite");

    // --no-context so the suppressed secret cannot appear merely as an adjacent
    // context line of the new finding; we assert on reported matches only.
    let scan = Command::new(BIN)
        .args(["scan", app.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--baseline", baseline.to_str().expect("baseline")])
        .args(["--format", "json", "--no-redact", "--no-context"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&scan.stdout);

    assert!(
        stdout.contains(new_pat),
        "the newly added secret must be reported"
    );
    assert!(
        !stdout.contains(PAT),
        "the moved, baselined secret must stay suppressed: {stdout}"
    );
}

#[test]
fn cli_json_output_can_be_used_as_line_tolerant_baseline() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    let app = dir.path().join("app.txt");
    std::fs::write(&app, format!("TOKEN={PAT}\n")).expect("write");
    let baseline = dir.path().join("findings.json");

    let write_json = Command::new(BIN)
        .args(["scan", app.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--format", "json", "--no-context", "--no-fail"])
        .args(["--output", baseline.to_str().expect("baseline")])
        .output()
        .expect("run");
    assert!(write_json.status.success(), "json output should be written");

    let baseline_json = std::fs::read_to_string(&baseline).expect("baseline");
    assert!(
        baseline_json.contains("\"fingerprint\""),
        "normal JSON output must carry fingerprint metadata"
    );

    std::fs::write(&app, format!("\nTOKEN={PAT}\n")).expect("move secret");

    let scan = Command::new(BIN)
        .args(["scan", app.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--baseline", baseline.to_str().expect("baseline")])
        .args(["--format", "json", "--no-redact", "--no-context"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&scan.stdout);

    assert!(
        !stdout.contains(PAT),
        "the moved finding from normal JSON output must be suppressed: {stdout}"
    );
    assert_eq!(stdout.trim(), "[]");
}
