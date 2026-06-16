//! Unit tests for `walk.rs` internals (git path safety, bounded reads, binary
//! gating). Kept in a sibling file so `walk.rs` stays under the 400-line limit.

use super::{append_git_paths, is_binary_skipped, read_bounded};
use crate::scanner::{BinaryPolicy, ScanConfig, Scanner};

const SECRET_RULE: &str = r#"
title = "walk-test"

[[rules]]
id = "secret"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;

fn scanner(config: ScanConfig) -> Scanner {
    Scanner::from_toml(SECRET_RULE)
        .expect("inline TOML should parse")
        .with_config(config)
}

#[test]
fn append_git_paths_rejects_parent_dir_components() {
    let dir = tempfile::tempdir().expect("dir");
    let safe = dir.path().join("safe.txt");
    std::fs::write(&safe, "clean").expect("write safe");
    let outside = dir.path().parent().expect("parent").join("outside.txt");
    std::fs::write(&outside, "SECRET123456").expect("write outside");

    let mut paths = Vec::new();
    append_git_paths(
        dir.path().to_str().expect("root"),
        b"safe.txt\0../outside.txt\0",
        &mut paths,
    );

    assert_eq!(paths.len(), 1, "safe git path should be kept");
    assert!(paths[0].ends_with("safe.txt"));
    assert!(
        paths
            .iter()
            .all(|path| !path.to_string_lossy().contains("outside.txt")),
        "git paths containing parent components must be dropped"
    );
}

#[cfg(unix)]
#[test]
fn append_git_paths_rejects_intermediate_symlink_escape() {
    let dir = tempfile::tempdir().expect("dir");
    let outside_dir = tempfile::tempdir().expect("outside");
    let outside_file = outside_dir.path().join("secret.txt");
    std::fs::write(&outside_file, "SECRET123456").expect("write outside");
    std::os::unix::fs::symlink(outside_dir.path(), dir.path().join("link")).expect("symlink");

    let mut paths = Vec::new();
    append_git_paths(
        dir.path().to_str().expect("root"),
        b"link/secret.txt\0",
        &mut paths,
    );

    assert!(
        paths.is_empty(),
        "git paths resolving outside the root through symlink directories must be dropped"
    );
}

#[test]
fn read_bounded_returns_none_for_oversized_file() {
    let file = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(file.path(), vec![b'a'; 100]).expect("write");

    // Cap below the file size: the one-byte overshoot detects it as oversized.
    assert!(
        read_bounded(file.path(), 50, 100).expect("read").is_none(),
        "a file larger than the cap must read as None"
    );
}

#[test]
fn read_bounded_accepts_file_at_exact_cap() {
    let file = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(file.path(), vec![b'a'; 64]).expect("write");

    let bytes = read_bounded(file.path(), 64, 64)
        .expect("read")
        .expect("some");
    assert_eq!(bytes.len(), 64, "a file at exactly the cap must be read");
}

#[cfg(unix)]
#[test]
fn read_bounded_rejects_symlink() {
    let dir = tempfile::tempdir().expect("dir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&target, "SECRET123456").expect("write");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    assert!(
        read_bounded(&link, 100, 12).is_err(),
        "O_NOFOLLOW must reject symlinks even if the caller raced after stat"
    );
}

#[cfg(unix)]
#[test]
fn read_bounded_rejects_non_regular_descriptor() {
    assert!(
        read_bounded(std::path::Path::new("/dev/null"), 100, 0).is_err(),
        "opened descriptors must be verified as regular files before reading"
    );
}

#[test]
fn is_binary_skipped_honors_policy() {
    let binary = b"abc\x00\x01\x02def";
    let text = b"plain text content";

    // Auto skips a non-allowlisted binary, but not a text file.
    assert!(is_binary_skipped(BinaryPolicy::Auto, "blob.dat", binary));
    assert!(!is_binary_skipped(BinaryPolicy::Auto, "blob.dat", text));
    // Auto keeps a binary-looking but source-allowlisted path (e.g. .env).
    assert!(!is_binary_skipped(BinaryPolicy::Auto, ".env", binary));
    // Skip ignores the allowlist; Scan never skips.
    assert!(is_binary_skipped(BinaryPolicy::Skip, ".env", binary));
    assert!(!is_binary_skipped(BinaryPolicy::Scan, "blob.dat", binary));
}

#[test]
fn max_files_uses_sorted_path_order() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("z.txt"), "SECRET999999").expect("write z");
    std::fs::write(dir.path().join("a.txt"), "SECRET111111").expect("write a");

    let scanner = scanner(ScanConfig {
        max_files: Some(1),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(stats.files_scanned, 1);
    assert_eq!(stats.files_over_cap, 1);
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].file.ends_with("a.txt"),
        "sorted max-files should keep a.txt first: {:?}",
        findings
    );
}

#[test]
fn findings_are_sorted_by_file_and_offset() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("z.txt"), "SECRET999999").expect("write z");
    std::fs::write(dir.path().join("a.txt"), "SECRET111111").expect("write a");

    let scanner = scanner(ScanConfig::default());
    let findings = scanner.scan_path(dir.path().to_str().expect("path"));

    assert_eq!(findings.len(), 2);
    assert!(findings[0].file.ends_with("a.txt"));
    assert!(findings[1].file.ends_with("z.txt"));
}

#[test]
fn max_findings_stops_after_cap_without_scanning_later_files() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("a.txt"), "SECRET111111").expect("write a");
    std::fs::write(dir.path().join("b.txt"), "SECRET222222").expect("write b");

    let scanner = scanner(ScanConfig {
        max_findings: Some(1),
        ..Default::default()
    });
    let (findings, stats) = scanner.scan_path_with_stats(dir.path().to_str().expect("path"));

    assert_eq!(findings.len(), 1);
    assert_eq!(
        stats.files_scanned, 1,
        "global finding cap should stop before scanning later sorted files"
    );
    assert!(findings[0].file.ends_with("a.txt"));
}
