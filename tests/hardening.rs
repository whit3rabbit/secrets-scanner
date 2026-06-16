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
        changed_files: true,
        base: Some("HEAD~1".to_string()),
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
        changed_files: true,
        base: Some(format!("--output={}", injected_output.display())),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(repo.path().to_str().expect("path"));

    // Fail closed by default: an unresolvable base must not silently scan the
    // working tree. Nothing is scanned and `git_failed` (mapped to CLI exit 2)
    // is set, rather than the secret being reported from a fallback walk.
    assert!(
        stats.git_failed,
        "invalid base should fail closed, not fall back to a directory walk"
    );
    assert!(
        !stats.git_fallback,
        "no fallback walk should happen without --git-fallback=walk"
    );
    assert!(findings.is_empty(), "fail-closed mode must scan nothing");
    assert!(
        !injected_output.exists()
            && !Path::new(&format!("{}...HEAD", injected_output.display())).exists(),
        "dash-led base must not be parsed by git as --output"
    );
}

#[test]
fn diff_base_dash_led_with_fallback_walk() {
    // With --git-fallback=walk, an unresolvable base restores the legacy
    // behavior: fall back to a directory walk (recording git_fallback) and still
    // report the working-tree secret, while never letting git parse the dash-led
    // value as an option.
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("clean.txt"), "nothing here").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    std::fs::write(repo.path().join("secret.txt"), "SECRET123456").expect("write");
    let injected_output = repo.path().join("git-diff-output");

    let scanner = scanner(ScanConfig {
        changed_files: true,
        base: Some(format!("--output={}", injected_output.display())),
        git_fallback_walk: true,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(repo.path().to_str().expect("path"));

    assert!(stats.git_fallback, "opt-in should fall back to a walk");
    assert!(
        !stats.git_failed,
        "fallback walk is not a fail-closed error"
    );
    assert_eq!(
        findings.len(),
        1,
        "fallback walk reports the working-tree secret"
    );
    assert!(
        !injected_output.exists(),
        "dash-led base must not be parsed by git as --output"
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
        git_tracked: true,
        ..Default::default()
    });
    assert!(
        tracked_only
            .scan_path(repo.path().to_str().expect("path"))
            .is_empty(),
        "untracked file must be invisible without include_untracked"
    );

    let with_untracked = scanner(ScanConfig {
        git_tracked: true,
        include_untracked: true,
        ..Default::default()
    });
    let findings = with_untracked.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert!(findings[0].file.ends_with("new.txt"));
}

#[cfg(unix)]
#[test]
fn git_tracked_non_utf8_filename_scanned() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    let name = OsString::from_vec(vec![b't', 0xff, b'.', b't', b'x', b't']);
    if std::fs::write(repo.path().join(&name), "SECRET123456").is_err() {
        return;
    }
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "add non-utf8"]);

    let scanner = scanner(ScanConfig {
        git_tracked: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(
        findings.len(),
        1,
        "non-UTF-8 tracked path must be opened byte-exact: {findings:?}"
    );
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
    assert!(result["partialFingerprints"]["secretsScanner/v2"].is_string());
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

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn staged_type_change_is_scanned() {
    // `--diff-filter=ACMRT` now includes type-changes (T). Replacing a tracked
    // regular file with a symlink stages a type-change whose blob is the link
    // target text; it must be scanned (ACMR would have excluded it).
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    let f = repo.path().join("f");
    std::fs::write(&f, "clean").expect("write regular");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);

    std::fs::remove_file(&f).expect("rm regular");
    std::os::unix::fs::symlink("SECRET123456", &f).expect("symlink");
    git(repo.path(), &["add", "f"]);

    let scanner = scanner(ScanConfig {
        git_staged: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1, "type-changed blob must be scanned");
    assert!(findings[0].file.ends_with("f"));
}

#[cfg(unix)]
#[test]
fn staged_non_utf8_filename_scanned() {
    // Git pathnames are arbitrary bytes on Unix. The pathspec must reach git
    // byte-exact; a lossy String conversion would corrupt the name so `cat-file`
    // could not find it and the staged secret would be missed.
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    let name = OsString::from_vec(vec![b'a', 0xff, b'.', b't', b'x', b't']);
    // Some filesystems (e.g. APFS on macOS) enforce valid UTF-8 filenames and
    // reject the byte sequence. The byte-exact path handling only matters where
    // such names are allowed (e.g. Linux ext4), so skip where they are not.
    if std::fs::write(repo.path().join(&name), "SECRET123456").is_err() {
        return;
    }
    git(repo.path(), &["add", "-A"]);

    let scanner = scanner(ScanConfig {
        git_staged: true,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(
        findings.len(),
        1,
        "non-UTF-8 staged path must be read byte-exact: {findings:?}"
    );
}

// ─────────────────────────────────────────────
// Git-history (`--git-history`) patch scanning
// ─────────────────────────────────────────────

/// Run git and return trimmed stdout (for reading commit SHAs in tests).
fn git_out(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

fn history_scanner() -> Scanner {
    scanner(ScanConfig {
        git_history: true,
        history_full: true,
        ..Default::default()
    })
}

#[test]
fn history_finds_secret_removed_from_tree() {
    // A secret committed then deleted is gone from the working tree but lives in
    // history. `--git-tracked` would miss it; `--git-history` must catch it.
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("seed.txt"), "clean").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);

    let secret = repo.path().join("leak.txt");
    std::fs::write(&secret, "key = SECRET123456").expect("write secret");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add secret"]);

    std::fs::remove_file(&secret).expect("rm");
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "remove secret"]);

    // Sanity: the working tree is clean now.
    let tracked = scanner(ScanConfig {
        git_tracked: true,
        ..Default::default()
    });
    assert!(
        tracked
            .scan_path(repo.path().to_str().expect("path"))
            .is_empty(),
        "working tree must be clean after removal"
    );

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1, "history must find the removed secret");
    assert!(findings[0].file.ends_with("leak.txt"));
}

#[test]
fn history_with_generous_timeout_still_finds_secret() {
    // Exercises the wall-clock-budget branch (deadline set) without flakiness: a
    // large timeout never trips, so history scanning must behave normally. A real
    // trip is intentionally not asserted (timing-dependent and flaky).
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("a.txt"), "key = SECRET123456").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add secret"]);

    let scanner = scanner(ScanConfig {
        git_history: true,
        history_full: true,
        history_timeout_secs: 600,
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1, "generous timeout must not drop findings");
}

#[test]
fn history_attributes_commit_sha() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("a.txt"), "SECRET123456").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add secret"]);
    let adding = git_out(repo.path(), &["rev-parse", "HEAD"]);
    // A later, unrelated commit so HEAD is not the adding commit.
    std::fs::write(repo.path().join("b.txt"), "clean").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "unrelated"]);

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].commit.as_deref(),
        Some(adding.as_str()),
        "finding must be attributed to the commit that added it"
    );
}

#[test]
fn history_reports_added_line_number() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    // Secret on the 3rd line of the file.
    std::fs::write(
        repo.path().join("c.txt"),
        "one\ntwo\nkey=SECRET123456\nfour\n",
    )
    .expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add"]);

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].line, 3,
        "line number must map to the new-file line"
    );
}

#[test]
fn history_log_opts_limit_commits() {
    // Each `--log-opts` value is spliced into `git log` as one verbatim argv
    // entry. `--max-count=1` restricts scanning to the most recent commit.
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("a.txt"), "SECRET111111").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "first"]);
    std::fs::write(repo.path().join("b.txt"), "SECRET222222").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "second"]);

    let scanner = scanner(ScanConfig {
        git_history: true,
        history_log_opts: vec!["--max-count=1".to_string()],
        ..Default::default()
    });
    let findings = scanner.scan_path(repo.path().to_str().expect("path"));
    assert_eq!(
        findings.len(),
        1,
        "only the latest commit should be scanned"
    );
    assert!(findings[0].file.ends_with("b.txt"));
}

#[test]
fn history_finds_secret_after_plusplus_content_line() {
    // Regression: an added line whose text begins with "++ " renders as "+++ " in
    // the `-U0` patch. The parser must treat it as hunk content (because a hunk is
    // already open), NOT as a "+++ b/path" file header — otherwise it would drop
    // the rest of the hunk and miss the secret on the following added line.
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(
        repo.path().join("notes.txt"),
        "++ heading line\nkey=SECRET123456\n",
    )
    .expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add"]);

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(
        findings.len(),
        1,
        "secret after a '++ ' content line must still be found"
    );
    assert_eq!(findings[0].line, 2, "secret is on the 2nd new-file line");
    assert!(findings[0].file.ends_with("notes.txt"));
}

#[test]
fn history_context_line_number_matches_reported_line() {
    // Regression: across multiple hunks of one file diff, a finding's reported
    // line and its context-line numbers must both be real new-file lines (not
    // relative to the reconstructed patch buffer). One commit edits line 1 and
    // adds a secret on line 5, producing two separate `-U0` hunks.
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    std::fs::write(repo.path().join("d.txt"), "a\nb\nc\nd\ne\n").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);

    std::fs::write(repo.path().join("d.txt"), "A\nb\nc\nd\nkey=SECRET123456\n").expect("write");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "edit"]);

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 5, "secret is on new-file line 5");
    assert!(
        findings[0]
            .context_lines
            .iter()
            .any(|(ln, _)| *ln == findings[0].line),
        "context lines must use real file line numbers, not buffer-relative ones: {:?}",
        findings[0].context_lines
    );
}

#[test]
fn history_finds_merge_resolution_secret_once() {
    let repo = tempfile::tempdir().expect("repo");
    init_repo(repo.path());
    let path = repo.path().join("conflict.txt");
    std::fs::write(&path, "value=base\n").expect("write base");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    let default_branch = git_out(repo.path(), &["branch", "--show-current"]);

    git(repo.path(), &["checkout", "-q", "-b", "left"]);
    std::fs::write(&path, "value=left\n").expect("write left");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "left"]);

    git(repo.path(), &["checkout", "-q", &default_branch]);
    std::fs::write(&path, "value=right\n").expect("write right");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "right"]);

    let merge = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["merge", "left"])
        .status()
        .expect("run merge");
    assert!(
        !merge.success(),
        "merge should conflict so the resolution can introduce the secret"
    );
    std::fs::write(&path, "value=SECRET123456\n").expect("resolve with secret");
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
        &["commit", "-q", "-m", "merge introduces secret"],
    );
    let merge_sha = git_out(repo.path(), &["rev-parse", "HEAD"]);

    let findings = history_scanner().scan_path(repo.path().to_str().expect("path"));
    assert_eq!(
        findings.len(),
        1,
        "merge-introduced secret should be reported once: {findings:?}"
    );
    assert_eq!(findings[0].commit.as_deref(), Some(merge_sha.as_str()));
    assert!(findings[0].file.ends_with("conflict.txt"));
}

#[test]
fn history_mode_outside_repo_fails_closed() {
    // History mode always fails closed (no walk fallback), even with
    // git_fallback_walk set — a directory walk cannot approximate history.
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("leak.txt"), "SECRET123456").expect("write");

    let scanner = scanner(ScanConfig {
        git_history: true,
        git_fallback_walk: true,
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));
    assert!(stats.git_failed, "non-repo history scan must fail closed");
    assert!(findings.is_empty(), "history mode must not walk the tree");
}

#[test]
fn history_mode_zero_finding_cap_outside_repo_still_fails_closed() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("leak.txt"), "SECRET123456").expect("write");

    let scanner = scanner(ScanConfig {
        git_history: true,
        max_findings: Some(0),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert!(
        stats.git_failed,
        "zero finding cap must still validate git-history mode"
    );
    assert!(findings.is_empty(), "history mode must not walk the tree");
}

// ─────────────────────────────────────────────
// CLI: git modes fail closed (exit 2)
// ─────────────────────────────────────────────

#[test]
fn cli_git_mode_failure_exits_2() {
    // `--git-tracked` outside a git repo fails closed: exit 2, nothing scanned,
    // rather than silently walking the directory.
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    std::fs::write(dir.path().join("app.txt"), format!("TOKEN={PAT}")).expect("write");
    let d = dir.path().to_str().expect("dir");
    let r = rules.to_str().expect("rules");

    let run = |args: &[&str]| Command::new(BIN).args(args).output().expect("run");
    let assert_git_failed = |args: &[&str]| {
        let output = run(args);
        assert_eq!(
            output.status.code().expect("code"),
            2,
            "git failure must fail closed with exit 2"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("No secrets found"),
            "fatal git failure must not emit clean output: {stdout}"
        );
        output
    };

    assert_git_failed(&["scan", d, "--rules", r, "--git-tracked"]);
    // Even --no-fail does not mask a fail-closed git error.
    assert_git_failed(&["scan", d, "--rules", r, "--git-tracked", "--no-fail"]);

    let out_file = dir.path().join("findings.json");
    std::fs::write(&out_file, "sentinel").expect("write sentinel");
    assert_git_failed(&[
        "scan",
        d,
        "--rules",
        r,
        "--git-tracked",
        "--format",
        "json",
        "--output",
        out_file.to_str().expect("out"),
    ]);
    assert_eq!(
        std::fs::read_to_string(&out_file).expect("read output"),
        "sentinel",
        "fatal git failure must not truncate/write normal output artifacts"
    );

    let baseline = dir.path().join("baseline.json");
    assert_git_failed(&[
        "scan",
        d,
        "--rules",
        r,
        "--git-tracked",
        "--generate-baseline",
        baseline.to_str().expect("baseline"),
    ]);
    assert!(
        !baseline.exists(),
        "fatal git failure must not write an empty baseline"
    );

    // Opting into the walk fallback restores scanning (finds the PAT -> exit 1).
    assert_eq!(
        run(&[
            "scan",
            d,
            "--rules",
            r,
            "--git-tracked",
            "--git-fallback",
            "walk"
        ])
        .status
        .code()
        .expect("code"),
        1,
        "--git-fallback=walk restores the directory walk"
    );
}

#[test]
fn cli_history_zero_cap_outside_repo_fails_closed() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    std::fs::write(dir.path().join("app.txt"), format!("TOKEN={PAT}")).expect("write");
    let output = Command::new(BIN)
        .args([
            "scan",
            dir.path().to_str().expect("dir"),
            "--rules",
            rules.to_str().expect("rules"),
            "--git-history",
            "--max-findings",
            "0",
        ])
        .output()
        .expect("run");

    assert_eq!(
        output.status.code().expect("code"),
        2,
        "git-history with zero cap must still fail closed outside a repo"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("No secrets found"),
        "fatal git-history failure must not emit clean output: {stdout}"
    );
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

    let mixed = scanner.scan_content(
        "a.txt",
        "SECRET123456 SECRET654321 // gitleaks:allow\nkey = SECRET111111",
    );
    assert_eq!(
        mixed.len(),
        1,
        "same-line marker should suppress both first-line findings only"
    );
    assert_eq!(mixed[0].line, 2);
}

#[test]
fn inline_allow_marker_is_line_level_not_trailing_only() {
    // Documents the deliberate broad (gitleaks-compatible) behavior: the marker
    // suppresses when it appears ANYWHERE on the secret's line, not only as a
    // trailing comment. If a future change narrows this, these cases break on
    // purpose. See `line_has_allow_marker`.
    let scanner = scanner(ScanConfig::default());

    // Marker before the secret.
    assert!(
        scanner
            .scan_content("a.txt", "# gitleaks:allow test fixture: SECRET123456")
            .is_empty(),
        "marker before the secret still suppresses (line-level)"
    );
    // Marker inside a string value elsewhere on the line.
    assert!(
        scanner
            .scan_content("a.txt", "token = SECRET123456; note = \"gitleaks:allow\"")
            .is_empty(),
        "marker inside a same-line string still suppresses (line-level)"
    );
    // A marker on a DIFFERENT line does not suppress.
    assert_eq!(
        scanner
            .scan_content("a.txt", "# gitleaks:allow\nkey = SECRET123456")
            .len(),
        1,
        "marker on another line must not suppress"
    );
}

#[test]
fn cli_summary_reports_per_file_truncation() {
    // A per-file cap (`--max-findings-per-file`) truncates findings; the CLI must
    // surface that in its stderr summary even when the global `--max-findings`
    // never fires. Regression for the aggregate that dropped per-path
    // `findings_truncated`.
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());
    let app = dir.path().join("app.txt");
    std::fs::write(&app, format!("A={PAT}\nB={PAT}\n")).expect("write");

    let out = Command::new(BIN)
        .args(["scan", app.to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--max-findings-per-file", "1", "--no-fail", "--no-context"])
        .env("RUST_LOG", "info")
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("findings truncated"),
        "summary must flag per-file truncation: {stderr}"
    );
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

// ─────────────────────────────────────────────
// Single-file scan (scan_file) coverage honesty
// ─────────────────────────────────────────────

#[test]
fn scan_file_scans_named_file_and_reports_coverage() {
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("app.env");
    std::fs::write(&file, "KEY=SECRET123456").expect("write");

    let scanner = scanner(ScanConfig::default());
    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));

    assert_eq!(findings.len(), 1, "the named file's secret is found");
    assert_eq!(stats.files_scanned, 1);
    assert_eq!(stats.errored, 0);
}

#[test]
fn scan_file_respects_total_max_findings_cap() {
    // Regression: the single-file path must honor the total `max_findings` cap,
    // not only the per-file cap (it previously called scan_one_file directly and
    // bypassed the capped scan).
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("app.env");
    std::fs::write(&file, "A=SECRET111111 B=SECRET222222 C=SECRET333333").expect("write");

    let scanner = scanner(ScanConfig {
        max_findings: Some(1),
        ..ScanConfig::default()
    });
    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));

    assert_eq!(
        findings.len(),
        1,
        "total max_findings cap applies to scan_file"
    );
    assert!(stats.findings_truncated);
}

#[test]
fn scan_file_history_mode_fails_closed() {
    // git_history changes WHICH content is scanned (commit patches) and cannot be
    // reproduced from one working-tree file, so scan_file fails closed instead of
    // silently scanning the working-tree bytes and looking like a complete scan.
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("app.env");
    std::fs::write(&file, "KEY=SECRET123456").expect("write");

    let scanner = scanner(ScanConfig {
        git_history: true,
        ..ScanConfig::default()
    });
    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));

    assert!(findings.is_empty(), "history mode is not scanned per-file");
    assert!(
        stats.git_failed,
        "a content-changing git mode on a single file must fail closed"
    );
}

#[test]
fn scan_file_extension_filtered_named_file_is_coverage_gap() {
    // A file the caller explicitly named but that the skip-extension policy
    // excludes was NOT scanned: it must be surfaced as a coverage gap (errored),
    // never reported with all-zero stats that read as scanned-and-clean.
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("blob.bin"); // .bin is a skip extension under Auto
    std::fs::write(&file, "SECRET123456").expect("write");

    let scanner = scanner(ScanConfig::default());
    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));

    assert!(findings.is_empty());
    assert_eq!(stats.files_scanned, 0);
    assert_eq!(
        stats.errored, 1,
        "an explicitly named but filtered file is a coverage gap"
    );
}

#[cfg(unix)]
#[test]
fn scan_file_symlink_is_coverage_gap() {
    // The symlink is correctly NOT followed (hardening), but for an explicitly
    // named single file the silent skip is a coverage gap, not a clean scan.
    let dir = tempfile::tempdir().expect("dir");
    let target = dir.path().join("real.env");
    std::fs::write(&target, "KEY=SECRET123456").expect("write");
    let link = dir.path().join("link.env");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let scanner = scanner(ScanConfig::default());
    let (findings, stats) = scanner.scan_file_with_stats(link.to_str().expect("path"));

    assert!(findings.is_empty(), "a symlink must not be followed");
    assert_eq!(
        stats.errored, 1,
        "a skipped symlink is a coverage gap, not a scanned-clean file"
    );
}

#[test]
fn scan_file_empty_file_stays_clean() {
    // A genuinely empty (zero-length) regular file is clean, not a coverage gap.
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("empty.env");
    std::fs::write(&file, "").expect("write");

    let scanner = scanner(ScanConfig::default());
    let (findings, stats) = scanner.scan_file_with_stats(file.to_str().expect("path"));

    assert!(findings.is_empty());
    assert_eq!(stats.errored, 0, "an empty regular file is genuinely clean");
}

// ─────────────────────────────────────────────
// CLI: multi-path git failure preserves real findings
// ─────────────────────────────────────────────

#[test]
fn cli_multipath_git_failure_preserves_real_findings() {
    // `scan repoA repoB --git-tracked` where repoA is a healthy repo with a
    // tracked secret and repoB is not a git repo. The run still fails closed
    // (exit 2, coverage incomplete), but the real finding from repoA must be
    // WRITTEN to --output, not discarded behind the generic git error.
    let base = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(base.path());

    let repo_a = base.path().join("a");
    std::fs::create_dir(&repo_a).expect("mkdir a");
    init_repo(&repo_a);
    std::fs::write(repo_a.join("app.txt"), format!("TOKEN={PAT}")).expect("write");
    git(&repo_a, &["add", "."]);

    let repo_b = base.path().join("b"); // deliberately NOT a git repo
    std::fs::create_dir(&repo_b).expect("mkdir b");

    let out_file = base.path().join("out.json");
    std::fs::write(&out_file, "SENTINEL").expect("write sentinel");

    let output = Command::new(BIN)
        .args([
            "scan",
            repo_a.to_str().expect("a"),
            repo_b.to_str().expect("b"),
            "--rules",
            rules.to_str().expect("rules"),
            "--git-tracked",
            "--format",
            "json",
            "--output",
            out_file.to_str().expect("out"),
        ])
        .output()
        .expect("run");

    assert_eq!(
        output.status.code().expect("code"),
        2,
        "a mixed multi-path git failure still fails closed (exit 2)"
    );
    let written = std::fs::read_to_string(&out_file).expect("output file should be written");
    assert_ne!(
        written, "SENTINEL",
        "the real finding from the healthy repo must be written, not discarded"
    );
    assert!(
        written.contains("app.txt"),
        "the preserved output must contain the healthy repo's finding: {written}"
    );
}

// ─────────────────────────────────────────────
// CLI: --include-untracked requires a git path mode
// ─────────────────────────────────────────────

#[test]
fn cli_include_untracked_requires_git_path_mode() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_pat_rules(dir.path());

    let output = Command::new(BIN)
        .args([
            "scan",
            dir.path().to_str().expect("dir"),
            "--rules",
            rules.to_str().expect("rules"),
            "--include-untracked",
        ])
        .output()
        .expect("run");

    assert_eq!(
        output.status.code().expect("code"),
        2,
        "bare --include-untracked is a usage error, not a silent no-op"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("include-untracked") || stderr.contains("required"),
        "error should explain the missing git path mode: {stderr}"
    );
}

// ─────────────────────────────────────────────
// CLI: zero scan caps rejected (#4)
// ─────────────────────────────────────────────

/// Write the inline `SECRET_RULE` ruleset to a file and return its path.
fn write_secret_rules(dir: &Path) -> std::path::PathBuf {
    let rules = dir.join("rules.toml");
    std::fs::write(&rules, SECRET_RULE).expect("write rules");
    rules
}

/// A zero cap turns a scan into an empty (clean-looking) result, almost always a
/// caller error in a security tool. The three caps must be rejected at parse time
/// with a clap usage error (exit 2) rather than silently scanning nothing.
fn assert_zero_cap_rejected(flag: &str) {
    let dir = tempfile::tempdir().expect("dir");
    let output = Command::new(BIN)
        .args(["scan", dir.path().to_str().expect("path")])
        .args([flag, "0"])
        .output()
        .expect("run");

    assert_eq!(
        output.status.code().expect("code"),
        2,
        "{flag} 0 must be a usage error, not a silent no-scan"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("positive"),
        "error should explain a positive value is required: {stderr}"
    );
}

#[test]
fn cli_rejects_zero_max_findings() {
    assert_zero_cap_rejected("--max-findings");
}

#[test]
fn cli_rejects_zero_max_files() {
    assert_zero_cap_rejected("--max-files");
}

#[test]
fn cli_rejects_zero_max_findings_per_file() {
    assert_zero_cap_rejected("--max-findings-per-file");
}

// ─────────────────────────────────────────────
// CLI: --no-allow-markers (#9)
// ─────────────────────────────────────────────

#[test]
fn cli_no_allow_markers_overrides_inline_suppression() {
    let dir = tempfile::tempdir().expect("dir");
    let rules = write_secret_rules(dir.path());
    // The marker on the match's line suppresses the finding by default.
    std::fs::write(
        dir.path().join("app.txt"),
        "key = SECRET123456 // secrets-scanner:allow\n",
    )
    .expect("write");

    // Default: the inline allow marker suppresses → clean scan (exit 0).
    let suppressed = Command::new(BIN)
        .args(["scan", dir.path().to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--no-context"])
        .output()
        .expect("run");
    assert_eq!(
        suppressed.status.code().expect("code"),
        0,
        "inline allow marker should suppress by default"
    );

    // --no-allow-markers: the marker is ignored → finding present (exit 1).
    let reported = Command::new(BIN)
        .args(["scan", dir.path().to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--no-context", "--no-allow-markers"])
        .output()
        .expect("run");
    assert_eq!(
        reported.status.code().expect("code"),
        1,
        "--no-allow-markers must report the otherwise-suppressed finding"
    );
}

// ─────────────────────────────────────────────
// CLI: incomplete scans never write a baseline (#5)
// ─────────────────────────────────────────────

#[test]
#[cfg(unix)]
fn cli_refuses_baseline_from_incomplete_scan() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("dir");
    let rules = write_secret_rules(dir.path());
    std::fs::write(dir.path().join("ok.txt"), "key = SECRET123456\n").expect("write");
    let locked = dir.path().join("locked.txt");
    std::fs::write(&locked, "key = SECRET999999\n").expect("write");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // Skip under root (where 000 is still readable) to avoid a flaky assertion.
    if std::fs::read(&locked).is_ok() {
        return;
    }

    let baseline = dir.path().join("baseline.json");
    let output = Command::new(BIN)
        .args(["scan", dir.path().to_str().expect("path")])
        .args(["--rules", rules.to_str().expect("rules")])
        .args(["--generate-baseline", baseline.to_str().expect("baseline")])
        .args(["--no-context"])
        .output()
        .expect("run");

    assert_eq!(
        output.status.code().expect("code"),
        2,
        "an unreadable file makes coverage incomplete; baseline generation must fail closed"
    );
    assert!(
        !baseline.exists(),
        "no baseline file may be written from an incomplete scan"
    );
}
