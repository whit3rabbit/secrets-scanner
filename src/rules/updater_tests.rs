use super::*;

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
    assert!(validate_update_url("http://example.com/rules.toml").is_err());
}

#[test]
fn content_length_over_cap_is_rejected() {
    let max = 5;
    let err = reject_large_content_length(Some("6"), max).expect_err("over cap");
    assert!(err.to_string().contains("Content-Length 6 exceeds 5"));
}

#[test]
fn capped_body_reader_rejects_stream_over_cap() {
    let err = read_capped_body(std::io::Cursor::new(vec![b'a'; 6]), 5).expect_err("over cap");
    assert!(err.to_string().contains("body exceeds 5 bytes"));
}

#[test]
fn capped_body_reader_accepts_stream_at_cap() {
    let body = read_capped_body(std::io::Cursor::new(vec![b'a'; 5]), 5).expect("at cap");
    assert_eq!(body, b"aaaaa");
}
