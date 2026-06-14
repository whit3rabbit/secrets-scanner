// Test code legitimately asserts on error paths via `unwrap_err`; opt out of the
// crate-wide `deny(clippy::unwrap_used)` here rather than peppering each assertion.
#![allow(clippy::unwrap_used)]

use super::*;

const VALID_TOML: &str = r#"
title = "Valid ruleset"

[allowlist]
description = "Global allow"
paths = ['\.md$', '\.txt$']
regexes = ['^dummy_key$']

[[rules]]
id = "rule-1"
description = "A valid rule"
regex = 'ghp_[A-Za-z0-9_]{36}'
keywords = ["ghp_"]

[[rules]]
id = "rule-2"
description = "Another valid rule"
regex = '(?i)aws'
keywords = ["aws"]
path = 'aws_config\.json'
allowlists = [
    { description = "allow tests", regexes = ['test_key'] }
]
"#;

#[test]
fn test_valid_ruleset() {
    assert!(validate_rules_toml(VALID_TOML).is_ok());
}

#[test]
fn test_invalid_toml() {
    let invalid = "this is not TOML";
    let res = validate_rules_toml(invalid);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("TOML deserialization failed"));
}

#[test]
fn test_empty_ruleset() {
    let empty = "title = \"empty\"";
    let res = validate_rules_toml(empty);
    assert!(res.is_ok());
}

#[test]
fn test_duplicate_rule_ids() {
    let duplicate = r#"
[[rules]]
id = "rule-1"
regex = 'a'
keywords = ["a"]

[[rules]]
id = "rule-1"
regex = 'b'
keywords = ["b"]
"#;
    let res = validate_rules_toml(duplicate);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err()[0], "Duplicate rule ID found: 'rule-1'");
}

#[test]
fn test_invalid_regex_in_rule() {
    let bad_regex = r#"
[[rules]]
id = "bad-rule"
regex = '[unclosed-class'
keywords = ["bad"]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("has invalid detection regex"));
}

#[test]
fn test_unsupported_detection_regex_is_invalid() {
    let bad_regex = r#"
[[rules]]
id = "lookahead-rule"
regex = 'foo(?=bar)'
keywords = ["foo"]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("has invalid detection regex"));
}

#[test]
fn test_invalid_regex_in_allowlist() {
    let bad_regex = r#"
[[rules]]
id = "bad-rule"
regex = 'good'
keywords = ["good"]
allowlists = [
    { regexes = ['(unclosed-group'] }
]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("allowlist at index 0 has invalid regex"));
}

#[test]
fn test_unsupported_rule_allowlist_regex_is_invalid() {
    let bad_regex = r#"
[[rules]]
id = "bad-rule"
regex = 'good'
keywords = ["good"]
allowlists = [
    { regexes = ['foo(?=bar)'] }
]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("allowlist at index 0 has invalid regex"));
}

#[test]
fn test_unsupported_global_allowlist_regex_is_invalid() {
    let bad_regex = r#"
[allowlist]
regexes = ['foo(?=bar)']

[[rules]]
id = "good-rule"
regex = 'good'
keywords = ["good"]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("regex pattern at index 0 is invalid"));
}

#[test]
fn test_invalid_regex_in_global_allowlist() {
    let bad_regex = r#"
[allowlist]
regexes = ['*invalid-star-regex']

[[rules]]
id = "good-rule"
regex = 'good'
keywords = ["good"]
"#;
    let errors = validate_rules_toml(bad_regex).unwrap_err();
    assert!(
        errors[0].contains("Global allowlist path pattern at index 0 is invalid")
            || errors[0]
                .contains("Global allowlist at index 0 regex pattern at index 0 is invalid")
            || errors[0].contains("Global allowlist 'legacy-global-allowlist'")
            || errors[0].contains("is invalid")
    );
}

#[test]
fn test_modern_allowlist_syntax() {
    let toml_content = r#"
title = "Modern Config"

[[allowlists]]
id = "allow-tests"
description = "Skip test files"
paths = ['test_fixtures/']
targetRules = ["rule-1"]

[[allowlists]]
id = "allow-safe"
condition = "and"
regexTarget = "match"
regexes = ['safe-token']

[[rules]]
id = "rule-1"
regex = 'secret-[a-z]+'
keywords = ["secret-"]
allowlists = [
    { condition = "AND", regexTarget = "line", regexes = ['ok-token'] }
]
"#;
    let res = validate_rules_toml(toml_content);
    assert!(
        res.is_ok(),
        "Should parse modern allowlist syntax: {:?}",
        res
    );
}

#[test]
fn test_invalid_regex_in_modern_global_allowlist() {
    let bad_regex = r#"
[[allowlists]]
id = "bad-al"
regexes = ['*invalid']

[[rules]]
id = "good-rule"
regex = 'good'
keywords = ["good"]
"#;
    let res = validate_rules_toml(bad_regex);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0]
        .contains("Global allowlist 'bad-al' regex pattern at index 0 is invalid"));
}

#[test]
fn test_invalid_path_in_rule_allowlist() {
    // Per-rule allowlist `paths` are compiled at load time, so they must be
    // validated too (not just `regexes`).
    let bad = r#"
[[rules]]
id = "r"
regex = 'good'
keywords = ["good"]
allowlists = [
    { paths = ['(unclosed'] }
]
"#;
    let res = validate_rules_toml(bad);
    assert!(res.is_err());
    assert!(res.unwrap_err()[0].contains("invalid path regex"));
}
