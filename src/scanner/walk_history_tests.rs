//! Unit tests for the `git log -p` patch parser's pure helpers. End-to-end
//! history scanning (real `git log` output) is covered by `tests/hardening.rs`.

use super::{parse_commit_sha, parse_hunk_new_start};

#[test]
fn commit_sha_accepts_sha1_and_sha256() {
    let sha1 = b"commit 0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
        parse_commit_sha(sha1).as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    let sha256 = [b"commit ".as_slice(), &[b'a'; 64]].concat();
    assert_eq!(parse_commit_sha(&sha256).map(|s| s.len()), Some(64));
}

#[test]
fn commit_sha_ignores_non_header_and_short_hex() {
    // A diff content line that merely contains the word, and a too-short token.
    assert_eq!(parse_commit_sha(b"+commit abc123"), None);
    assert_eq!(parse_commit_sha(b"commit abc123"), None);
    assert_eq!(parse_commit_sha(b"    commit message body"), None);
}

#[test]
fn commit_sha_takes_first_token_only() {
    // Decorated logs (`--decorate`) append refs; only the leading hex counts.
    let decorated = b"commit 0123456789abcdef0123456789abcdef01234567 (HEAD -> main)";
    assert_eq!(
        parse_commit_sha(decorated).as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
}

#[test]
fn hunk_new_start_parses_ranges() {
    assert_eq!(parse_hunk_new_start(b"@@ -1,2 +3,4 @@"), Some(3));
    // Single-count form (`+c` with implicit count 1).
    assert_eq!(parse_hunk_new_start(b"@@ -5 +7 @@"), Some(7));
    // New-file hunk and a trailing section heading.
    assert_eq!(
        parse_hunk_new_start(b"@@ -0,0 +1,5 @@ fn main() {"),
        Some(1)
    );
}

#[test]
fn hunk_new_start_rejects_garbage() {
    assert_eq!(parse_hunk_new_start(b"not a hunk"), None);
    assert_eq!(parse_hunk_new_start(b"@@ -1,2 @@"), None);
}
