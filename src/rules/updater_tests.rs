use super::*;
use std::ffi::OsString;
use std::sync::{Mutex, OnceLock};

#[test]
fn atomic_cache_write_writes_rules_and_sha_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_path = dir.path().join("secrets-scanner.toml");
    let sha_path = dir.path().join("secrets-scanner.toml.sha256");
    let cache_sha_path = dir.path().join("secrets-scanner.toml.cache.sha256");
    let local_sha_path = dir.path().join("secrets-scanner.toml.local.sha256");

    write_cache_atomically(
        &rules_path,
        "rules-v1",
        &sha_path,
        "remote-sha",
        &cache_sha_path,
        "cache-sha",
        &local_sha_path,
        "local-sha",
    )
    .expect("atomic write");

    assert_eq!(
        std::fs::read_to_string(&rules_path).expect("rules"),
        "rules-v1"
    );
    assert_eq!(
        std::fs::read_to_string(&sha_path).expect("sha"),
        "remote-sha"
    );
    assert_eq!(
        std::fs::read_to_string(&cache_sha_path).expect("cache sha"),
        "cache-sha"
    );
    assert_eq!(
        std::fs::read_to_string(&local_sha_path).expect("local sha"),
        "local-sha"
    );
    assert!(!temp_path_for(&rules_path).exists());
    assert!(!temp_path_for(&sha_path).exists());
    assert!(!temp_path_for(&cache_sha_path).exists());
    assert!(!temp_path_for(&local_sha_path).exists());
}

#[test]
fn update_url_validation_accepts_https() {
    validate_update_url("https://example.com/rules.toml").expect("https is allowed");
}

#[test]
fn update_url_validation_rejects_http() {
    assert!(matches!(
        validate_update_url("http://example.com/rules.toml"),
        Err(UpdateError::NonHttpsUrl)
    ));
}

#[test]
fn content_length_over_cap_is_rejected() {
    let max = 5;
    let err = reject_large_content_length(Some("6"), max).expect_err("over cap");
    assert!(matches!(
        err,
        UpdateError::DownloadTooLarge { actual: 6, max: 5 }
    ));
}

#[test]
fn capped_body_reader_rejects_stream_over_cap() {
    let err = read_capped_body(std::io::Cursor::new(vec![b'a'; 6]), 5).expect_err("over cap");
    assert!(matches!(
        err,
        UpdateError::DownloadTooLarge { actual: 6, max: 5 }
    ));
}

#[test]
fn capped_body_reader_accepts_stream_at_cap() {
    let body = read_capped_body(std::io::Cursor::new(vec![b'a'; 5]), 5).expect("at cap");
    assert_eq!(body, b"aaaaa");
}

fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct CwdGuard {
    original: OsString,
}

impl CwdGuard {
    fn enter(path: &std::path::Path) -> Self {
        let original = std::env::current_dir()
            .expect("current dir")
            .into_os_string();
        std::env::set_current_dir(path).expect("set current dir");
        Self { original }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).expect("restore current dir");
    }
}

#[test]
fn existing_unreadable_local_rules_fail_instead_of_falling_back() {
    let _lock = cwd_lock().lock().expect("cwd lock");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("local.toml")).expect("local.toml dir");
    let _guard = CwdGuard::enter(dir.path());

    let err = crate::rules::load_local_rules_for_merge().expect_err("strict local rules");

    assert!(matches!(
        err,
        crate::rules::LocalRulesError::Unreadable { .. }
    ));
}

#[test]
fn existing_invalid_local_rules_fail_instead_of_falling_back() {
    let _lock = cwd_lock().lock().expect("cwd lock");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("local.toml"), "not valid toml = [")
        .expect("invalid local rules");
    let _guard = CwdGuard::enter(dir.path());

    let err = crate::rules::load_local_rules_for_merge().expect_err("strict local rules");

    assert!(matches!(err, crate::rules::LocalRulesError::Invalid { .. }));
}
