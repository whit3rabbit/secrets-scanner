//! Unit tests for `walk.rs` internals (git path safety, bounded reads, binary
//! gating). Kept in a sibling file so `walk.rs` stays under the 400-line limit.

use super::{append_git_paths, is_binary_skipped, read_bounded};
use crate::scanner::BinaryPolicy;

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
        paths.iter().all(|path| !path.contains("outside.txt")),
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
    let path = file.path().to_str().expect("path");

    // Cap below the file size: the one-byte overshoot detects it as oversized.
    assert!(
        read_bounded(path, 50).expect("read").is_none(),
        "a file larger than the cap must read as None"
    );
}

#[test]
fn read_bounded_accepts_file_at_exact_cap() {
    let file = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(file.path(), vec![b'a'; 64]).expect("write");
    let path = file.path().to_str().expect("path");

    let bytes = read_bounded(path, 64).expect("read").expect("some");
    assert_eq!(bytes.len(), 64, "a file at exactly the cap must be read");
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
