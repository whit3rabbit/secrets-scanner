use super::*;

const MINIMAL_TOML: &str = r#"
title = "test config"

[allowlist]
description = "global allow"
paths = ['\.test$']
regexes = ['^test_value$']
stopwords = ["placeholder"]

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b((?:AKIA|ASIA)[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia", "asia"]

[[rules]]
id = "github-pat"
description = "GitHub personal access token"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;

#[test]
fn parses_minimal_toml() {
    let engine = RuleEngine::from_toml(MINIMAL_TOML).expect("should parse");
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.keyword_count(), 3); // akia, asia, ghp_
}

#[test]
fn maps_keywords_to_rules() {
    let engine = RuleEngine::from_toml(MINIMAL_TOML).expect("should parse");
    // First two keywords (akia, asia) map to rule 0
    assert_eq!(engine.rules_for_keyword(0), &[0]);
    assert_eq!(engine.rules_for_keyword(1), &[0]);
    // Third keyword (ghp_) maps to rule 1
    assert_eq!(engine.rules_for_keyword(2), &[1]);
}

#[test]
fn duplicate_normalized_keywords_map_rule_once() {
    let toml = r#"
title = "dupe keywords"

[[rules]]
id = "case-dupe"
regex = 'secret[0-9]+'
keywords = ["SECRET", "secret"]
"#;
    let engine = RuleEngine::from_toml(toml).expect("should parse");

    assert_eq!(engine.keyword_count(), 1);
    assert_eq!(
        engine.rules_for_keyword(0),
        &[0],
        "same rule should be mapped once per normalized keyword"
    );
}

#[test]
fn compiles_global_allowlist() {
    let engine = RuleEngine::from_toml(MINIMAL_TOML).expect("should parse");
    assert!(engine.is_path_globally_allowlisted("file.test"));
    assert!(!engine.is_path_globally_allowlisted("file.rs"));
}

#[test]
fn checks_global_match_allowlist() {
    let engine = RuleEngine::from_toml(MINIMAL_TOML).expect("should parse");
    assert!(engine.is_match_globally_allowlisted("", "", &[], b"test_value", b"test_value"));
    assert!(engine.is_match_globally_allowlisted(
        "",
        "",
        &[],
        b"some placeholder text",
        b"some placeholder text"
    ));
    assert!(!engine.is_match_globally_allowlisted(
        "",
        "",
        &[],
        b"AKIAIOSFODNN7EXAMPLEX",
        b"AKIAIOSFODNN7EXAMPLEX"
    ));
}

#[test]
fn validates_secret_group_bounds() {
    let bad_group_toml = r#"
title = "bad group"
[[rules]]
id = "bad-group-rule"
regex = 'abc([0-9]+)'
secretGroup = 2
keywords = ["abc"]
"#;
    let engine = RuleEngine::from_toml(bad_group_toml).expect("should parse");
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules()[0].secret_group, None);
}

#[test]
fn strict_load_rejects_out_of_range_secret_group() {
    // The lenient path (above) downgrades to default group selection. The strict
    // gate `Scanner::from_toml` / `from_file` (explicit `--rules`) must instead
    // reject: an out-of-range group silently shifts the entropy/redaction/
    // fingerprint span.
    let bad_group_toml = r#"
title = "bad group"
[[rules]]
id = "bad-group-rule"
regex = 'abc([0-9]+)'
secretGroup = 2
keywords = ["abc"]
"#;
    let msg = match crate::Scanner::from_toml(bad_group_toml) {
        Ok(_) => panic!("strict load must reject an out-of-range secret_group"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("secret_group") && msg.contains("bad-group-rule"),
        "error should name the rule and the bad secret_group: {msg}"
    );
}

#[test]
fn has_keyword_first_bytes() {
    let engine = RuleEngine::from_toml(MINIMAL_TOML).expect("should parse");
    let bytes = engine.keyword_first_bytes();
    assert!(!bytes.is_empty());
    // 'a' for akia/asia, 'g' for ghp_
    assert!(bytes.contains(&b'a'));
    assert!(bytes.contains(&b'g'));
}

#[test]
fn skips_rules_with_invalid_regex() {
    let bad_toml = r#"
title = "bad"
[[rules]]
id = "bad-rule"
regex = '[invalid('
keywords = ["bad"]

[[rules]]
id = "good-rule"
description = "valid"
regex = 'good_[a-z]+'
keywords = ["good"]
"#;
    let engine = RuleEngine::from_toml(bad_toml).expect("should parse despite bad regex");
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules()[0].id, "good-rule");
}

#[test]
fn from_toml_reporting_clean_ruleset_has_no_issues() {
    let (engine, issues) = RuleEngine::from_toml_reporting(MINIMAL_TOML).expect("should parse");
    assert_eq!(engine.rule_count(), 2);
    assert!(issues.is_empty(), "unexpected issues: {issues:?}");
}

#[test]
fn from_toml_reporting_flags_invalid_detection_regex() {
    let bad_toml = r#"
title = "bad"
[[rules]]
id = "bad-rule"
regex = '[invalid('
keywords = ["bad"]

[[rules]]
id = "good-rule"
regex = 'good_[a-z]+'
keywords = ["good"]
"#;
    let (engine, issues) = RuleEngine::from_toml_reporting(bad_toml).expect("should parse");
    // The engine still builds leniently (good rule survives)...
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules()[0].id, "good-rule");
    // ...but the report names the dropped rule so strict callers can reject.
    assert!(
        issues.iter().any(|i| i.contains("bad-rule")),
        "issues should name the dropped rule: {issues:?}"
    );
}

#[test]
fn from_toml_reporting_flags_duplicate_and_empty_ids() {
    let toml = r#"
title = "ids"
[[rules]]
id = "dup"
regex = 'a[0-9]+'
keywords = ["a"]

[[rules]]
id = "dup"
regex = 'b[0-9]+'
keywords = ["b"]

[[rules]]
id = "   "
regex = 'c[0-9]+'
keywords = ["c"]
"#;
    let (_engine, issues) = RuleEngine::from_toml_reporting(toml).expect("should parse");
    assert!(
        issues
            .iter()
            .any(|i| i.to_lowercase().contains("duplicate")),
        "expected a duplicate-id issue: {issues:?}"
    );
    assert!(
        issues.iter().any(|i| i.to_lowercase().contains("empty")),
        "expected an empty-id issue: {issues:?}"
    );
}

#[test]
fn from_toml_reporting_flags_empty_keywords_and_inert_rules() {
    let toml = r#"
title = "structural"

[[rules]]
id = "empty-keyword"
regex = 'secret[0-9]+'
keywords = ["secret", "   "]

[[rules]]
id = "inert"
keywords = ["inert"]
"#;
    let (_engine, issues) = RuleEngine::from_toml_reporting(toml).expect("should parse");
    assert!(
        issues
            .iter()
            .any(|i| i.contains("empty-keyword") && i.contains("empty keyword")),
        "expected an empty-keyword issue: {issues:?}"
    );
    assert!(
        issues
            .iter()
            .any(|i| i.contains("inert") && i.contains("regex") && i.contains("path")),
        "expected an inert-rule issue: {issues:?}"
    );
}

#[test]
fn from_toml_reporting_flags_invalid_path_and_allowlist_regex() {
    let toml = r#"
title = "filters"
[[rules]]
id = "bad-path"
regex = 'a[0-9]+'
path = '[invalid('
keywords = ["a"]

[[rules]]
id = "bad-allowlist"
regex = 'b[0-9]+'
keywords = ["b"]
allowlists = [ { regexes = ['[invalid('] } ]
"#;
    let (_engine, issues) = RuleEngine::from_toml_reporting(toml).expect("should parse");
    assert!(
        issues
            .iter()
            .any(|i| i.contains("bad-path") && i.contains("path")),
        "expected an invalid path-regex issue: {issues:?}"
    );
    assert!(
        issues
            .iter()
            .any(|i| i.contains("bad-allowlist") && i.contains("allowlist")),
        "expected an invalid allowlist-regex issue: {issues:?}"
    );
}

#[test]
fn from_toml_reporting_flags_invalid_global_allowlist_regex() {
    let toml = r#"
title = "global"
[allowlist]
regexes = ['[invalid(']

[[rules]]
id = "r"
regex = 'a[0-9]+'
keywords = ["a"]
"#;
    let (_engine, issues) = RuleEngine::from_toml_reporting(toml).expect("should parse");
    assert!(
        issues.iter().any(|i| i.contains("global allowlist")),
        "expected an invalid global-allowlist issue: {issues:?}"
    );
}

#[test]
fn partitions_keyworded_and_unkeyworded_rules() {
    let toml = r#"
title = "test partition"

[[rules]]
id = "rule-with-keywords"
regex = 'kw-[0-9]+'
keywords = ["kw"]

[[rules]]
id = "rule-without-keywords"
regex = 'nokw-[0-9]+'
"#;
    let engine = RuleEngine::from_toml(toml).expect("should parse");
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.keyworded_rules().len(), 1);
    assert_eq!(engine.unkeyworded_rules().len(), 1);
    assert_eq!(engine.keyworded_rules()[0].id, "rule-with-keywords");
    assert_eq!(engine.unkeyworded_rules()[0].id, "rule-without-keywords");
}

#[test]
fn builds_unkeyworded_regex_set_for_content_rules() {
    let toml = r#"
title = "test unkeyworded set"

[[rules]]
id = "unkeyworded-content"
regex = 'nokw-[0-9]+'

[[rules]]
id = "path-only"
path = 'secret\.env$'
"#;
    let engine = RuleEngine::from_toml(toml).expect("should parse");

    assert!(engine.unkeyworded_regex_set().is_some());
    assert_eq!(engine.unkeyworded_regex_set_rule_indices(), &[0]);
    let path_only: Vec<&CompiledRule> = engine.path_only_rules().collect();
    assert_eq!(path_only.len(), 1);
    assert_eq!(path_only[0].id, "path-only");
}

#[test]
fn loads_bundled_rules() {
    // This tests against the actual bundled rules to ensure they parse
    let engine =
        RuleEngine::from_toml(crate::rules::BUNDLED_RULES).expect("bundled rules should parse");
    assert!(
        engine.rule_count() > 100,
        "expected >100 rules, got {}",
        engine.rule_count()
    );
    assert!(
        engine.keyword_count() > 100,
        "expected >100 keywords, got {}",
        engine.keyword_count()
    );
}

#[test]
fn test_allowlist_conditions_and_targets() {
    let toml = r#"
title = "test allowlist conditions and targets"

[[allowlists]]
id = "global-and-match"
condition = "and"
regexTarget = "match"
paths = ['safe_dir/']
regexes = ['safe-match']

[[allowlists]]
id = "targeted-rule"
targetRules = ["aws-token"]
regexTarget = "line"
regexes = ['^//.*$']

[[rules]]
id = "aws-token"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]
allowlists = [
    { condition = "or", regexTarget = "secret", regexes = ['1234567890'] }
]
"#;
    let engine = RuleEngine::from_toml(toml).expect("should parse");
    assert_eq!(engine.rule_count(), 1);

    // Test the targeted rules global allowlist
    // aws-token matching line: "// AKIA1234567890" is comment -> allowlisted.
    assert!(engine.is_match_globally_allowlisted(
        "aws-token",
        "file.rs",
        b"// AKIA1234567890",
        b"AKIA1234567890",
        b"AKIA1234567890"
    ));

    // other-rule -> targetRules doesn't match -> not allowlisted
    assert!(!engine.is_match_globally_allowlisted(
        "other-rule",
        "file.rs",
        b"// AKIA1234567890",
        b"AKIA1234567890",
        b"AKIA1234567890"
    ));

    // Test the "and" condition allowlist "global-and-match" (applies to all rules)
    // Both path matches AND content matches:
    assert!(engine.is_match_globally_allowlisted(
        "aws-token",
        "safe_dir/file.rs",
        b"some safe-match content",
        b"safe-match",
        b"safe-match"
    ));
    // Path matches but content does NOT match:
    assert!(!engine.is_match_globally_allowlisted(
        "aws-token",
        "safe_dir/file.rs",
        b"some other content",
        b"other",
        b"other"
    ));

    // Test the per-rule allowlist for aws-token (secret matching '1234567890')
    let rule = &engine.rules()[0];
    assert!(RuleEngine::is_rule_allowlisted(
        rule,
        "file.rs",
        b"AKIA1234567890",
        b"AKIA1234567890",
        b"1234567890"
    ));
}

#[test]
fn allowlist_stopword_cache_is_separate_per_regex_target() {
    let toml = r#"
title = "target cache"

[[allowlists]]
id = "secret-miss"
targetRules = ["token"]
regexTarget = "secret"
stopwords = ["missing"]

[[allowlists]]
id = "line-hit"
targetRules = ["token"]
regexTarget = "line"
stopwords = ["lineonly"]

[[rules]]
id = "token"
regex = 'token=([A-Za-z0-9]+)'
secretGroup = 1
keywords = ["token="]
"#;
    let engine = RuleEngine::from_toml(toml).expect("should parse");

    assert!(
        engine.is_match_globally_allowlisted(
            "token",
            "file.rs",
            b"lineonly token=ABC123",
            b"token=ABC123",
            b"ABC123"
        ),
        "line-target stopword should not reuse the previous secret-target lowercase cache"
    );
}
