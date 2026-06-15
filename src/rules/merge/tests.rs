//! Tests for `rules/merge.rs` — split out to keep the source file under the
//! 400-line guideline.

use super::*;

#[test]
fn override_allowlist_stays_independent_not_fused() {
    // Base [allowlist] is OR over a path; override sets AND with a regex.
    // They must remain independent (override appended as its own entry),
    // not concatenated under a single condition.
    let base = r#"
title = "base"
[allowlist]
paths = ['testdata/']
condition = "OR"
[[rules]]
id = "r"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]
"#;
    let over = r#"
[allowlist]
condition = "AND"
regexes = ['DUMMY']
"#;
    let merged = merge_toml_rules(base, over).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    // Base singular [allowlist] preserved with its own OR condition.
    assert_eq!(val["allowlist"]["condition"].as_str(), Some("OR"));
    // Override allowlist appended as an independent entry keeping AND.
    let arr = val["allowlists"].as_array().expect("allowlists array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["condition"].as_str(), Some("AND"));
}

#[test]
fn override_allowlist_replaces_base_entry_with_same_id() {
    let base = r#"
title = "base"
[[allowlists]]
id = "shared"
paths = ['old/']
[[rules]]
id = "r"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]
"#;
    let over = r#"
[[allowlists]]
id = "shared"
paths = ['new/']
"#;
    let merged = merge_toml_rules(base, over).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let arr = val["allowlists"].as_array().expect("array");
    // The base 'shared' entry is replaced, not duplicated.
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["paths"][0].as_str(), Some("new/"));
}

fn src(name: &str, priority: i64, toml: &str) -> MergeSource {
    MergeSource {
        name: name.to_string(),
        priority,
        toml: toml.to_string(),
    }
}

#[test]
fn level1_id_collision_higher_priority_wins() {
    let low = r#"
[[rules]]
id = "dup"
description = "low"
regex = 'AAAA'
"#;
    let high = r#"
[[rules]]
id = "dup"
description = "high"
regex = 'BBBB'
"#;
    let (merged, report) =
        merge_sources(vec![src("low", 10, low), src("high", 100, high)]).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["description"].as_str(), Some("high"));
    assert_eq!(report.id_collisions.len(), 1);
    assert!(report.id_collisions[0].dropped);
    assert_eq!(report.id_collisions[0].dropped_source, "low");
}

#[test]
fn level2_exact_regex_drops_lower_priority() {
    let low = r#"
[[rules]]
id = "a"
regex = 'gho_[0-9A-Za-z]{36}'
"#;
    let high = r#"
[[rules]]
id = "b"
regex = 'gho_[0-9A-Za-z]{36}'
"#;
    let (merged, report) =
        merge_sources(vec![src("low", 10, low), src("high", 100, high)]).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"].as_str(), Some("b")); // higher priority kept
    assert_eq!(report.exact_regex_dups.len(), 1);
    assert_eq!(report.exact_regex_dups[0].dropped_id, "a");
}

#[test]
fn level2_same_regex_different_keywords_keeps_both() {
    // Same regex but different keywords => the two rules fire in different
    // situations (keyword pre-filter). Both MUST survive.
    let low = r#"
[[rules]]
id = "palantir-jwt"
regex = 'eyJ[A-Za-z0-9_-]{6,}'
keywords = ["palantir"]
"#;
    let high = r#"
[[rules]]
id = "supabase-service-key"
regex = 'eyJ[A-Za-z0-9_-]{6,}'
keywords = ["supabase"]
"#;
    let (merged, report) =
        merge_sources(vec![src("low", 10, low), src("high", 100, high)]).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 2, "different-keyword rules must both survive");
    assert_eq!(report.exact_regex_dups.len(), 1);
    assert!(
        !report.exact_regex_dups[0].dropped,
        "recorded as a conflict, not dropped"
    );
}

#[test]
fn level2_same_regex_different_allowlists_keeps_both() {
    let low = r#"
[[rules]]
id = "unsuppressed"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
"#;
    let high = r#"
[[rules]]
id = "allowlisted"
regex = 'SECRET[0-9]{6}'
keywords = ["secret"]
allowlists = [
    { paths = ['allowed/'] }
]
"#;
    let (merged, report) =
        merge_sources(vec![src("low", 10, low), src("high", 100, high)]).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");

    assert_eq!(
        rules.len(),
        2,
        "different allowlists change suppression behavior"
    );
    assert_eq!(report.exact_regex_dups.len(), 1);
    assert!(!report.exact_regex_dups[0].dropped);
}

#[test]
fn level2_same_regex_compares_against_all_kept_variants() {
    let highest = r#"
[[rules]]
id = "variant-a"
regex = 'SECRET[0-9]{6}'
keywords = ["a"]
"#;
    let middle = r#"
[[rules]]
id = "variant-b"
regex = 'SECRET[0-9]{6}'
keywords = ["b"]
"#;
    let lowest = r#"
[[rules]]
id = "variant-b-copy"
regex = 'SECRET[0-9]{6}'
keywords = ["b"]
"#;
    let (merged, report) = merge_sources(vec![
        src("lowest", 10, lowest),
        src("middle", 50, middle),
        src("highest", 100, highest),
    ])
    .expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");

    assert_eq!(rules.len(), 2);
    assert_eq!(report.exact_regex_dups.len(), 2);
    assert!(report
        .exact_regex_dups
        .iter()
        .any(|record| record.dropped_id == "variant-b-copy" && record.dropped));
}

#[test]
fn level3_normalized_near_dup_kept_but_recorded() {
    // Differ only by inline flag + anchors + word boundary.
    let low = r#"
[[rules]]
id = "a"
regex = '\bAKIA[A-Z0-9]{16}\b'
"#;
    let high = r#"
[[rules]]
id = "b"
regex = '(?i)^AKIA[A-Z0-9]{16}$'
"#;
    let (merged, report) =
        merge_sources(vec![src("low", 10, low), src("high", 100, high)]).expect("merge");
    let val: toml::Value = toml::from_str(&merged).expect("parse");
    let rules = val["rules"].as_array().expect("rules");
    // Both rules survive — near-dups are advisory only.
    assert_eq!(rules.len(), 2);
    assert_eq!(report.near_dups.len(), 1);
    assert!(!report.near_dups[0].dropped);
}

#[test]
fn normalize_regex_matches_python_normalizer() {
    // Parity with scripts/import_secrets_patterns_db.py::normalize_regex.
    assert_eq!(
        normalize_regex(r"(?i)\bAKIA[0-9A-Z]{16}\b$"),
        "akia[0-9a-z]{16}"
    );
    assert_eq!(
        normalize_regex(r"^gho_[0-9A-Za-z]{36}$"),
        "gho_[0-9a-za-z]{36}"
    );
    assert_eq!(normalize_regex(r"(?-i) A B "), "ab");
}

#[test]
fn normalize_regex_strips_escaped_anchors_for_parity() {
    // The strip pattern's `\^`/`\$` alternatives match the anchor char even when
    // it is backslash-escaped (a literal caret/dollar), leaving a dangling `\`.
    // This is a known quirk shared with the Python normalizer; normalize_regex
    // only feeds advisory near-dup detection (never drops a rule), so the
    // behavior is harmless. Pin it so the two implementations cannot drift apart
    // unnoticed: if this ever changes, the Python side must change in lockstep.
    assert_eq!(normalize_regex(r"foo\^bar"), r"foo\bar");
    assert_eq!(normalize_regex(r"foo\$bar"), r"foo\bar");
}
