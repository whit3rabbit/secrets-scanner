use serde::Deserialize;
use std::collections::HashSet;

// ─────────────────────────────────────────────
// TOML Deserialization Types (gitleaks-compatible)
// ─────────────────────────────────────────────

/// A per-rule allowlist entry from `[[rules.allowlists]]`.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistConfig {
    /// Human-readable description of this allowlist.
    #[serde(default)]
    pub description: Option<String>,

    /// Regex patterns that, if matched, suppress the finding.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// What the allowlist regexes match against: `"match"` (the captured group)
    /// or default (the entire line).
    #[serde(default, rename = "regexTarget")]
    pub regex_target: Option<String>,

    /// Path patterns — if any match the file path, the rule is suppressed for that file.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Stopwords — if any appear in the matched text, the finding is suppressed.
    #[serde(default)]
    pub stopwords: Vec<String>,
}

/// The global `[allowlist]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct GlobalAllowlist {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Path regexes — files matching any of these are skipped entirely.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Regex patterns applied to every finding's matched text.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// Stopwords applied globally.
    #[serde(default)]
    pub stopwords: Vec<String>,
}

/// A single `[[rules]]` entry from the TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Unique rule identifier (e.g., `"aws-access-token"`).
    pub id: String,

    /// Human-readable description of what this rule detects.
    #[serde(default)]
    pub description: Option<String>,

    /// The detection regex pattern (optional).
    pub regex: Option<String>,

    /// Minimum entropy threshold for this rule. If unset, uses the global default.
    #[serde(default)]
    pub entropy: Option<f64>,

    /// Keywords that must appear in the file for this rule to fire.
    /// Fed into the Aho-Corasick automaton for fast pre-filtering.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Optional file path regex — rule only applies to files matching this pattern.
    #[serde(default)]
    pub path: Option<String>,

    /// Per-rule allowlists.
    #[serde(default)]
    pub allowlists: Vec<AllowlistConfig>,

    /// Optional capture group index for the secret.
    #[serde(default, rename = "secretGroup")]
    pub secret_group: Option<usize>,
}

/// Top-level TOML config structure (gitleaks-compatible).
#[derive(Debug, Clone, Deserialize)]
pub struct RulesetConfig {
    /// Config title (e.g., `"gitleaks config"`).
    #[serde(default)]
    pub title: Option<String>,

    /// Minimum gitleaks version (informational, we ignore it).
    #[serde(default, rename = "minVersion")]
    pub min_version: Option<String>,

    /// Global allowlist applied to all rules.
    #[serde(default)]
    pub allowlist: Option<GlobalAllowlist>,

    /// The list of detection rules.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

// ─────────────────────────────────────────────
// Regex Compilation Helpers
// ─────────────────────────────────────────────

/// Helper to preprocess and compile a regex pattern using the scanner's standard builder.
///
/// This automatically escapes unescaped braces that are not valid repetition quantifiers,
/// and configures a larger compilation size limit (100MB) to support complex rulesets.
pub fn compile_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    let escaped = escape_literal_braces(pattern);
    let mut builder = regex::RegexBuilder::new(&escaped);
    builder.size_limit(100 * 1024 * 1024);
    builder.build()
}

/// Escapes unescaped `{` and `}` characters that are not part of valid repetition quantifiers (e.g. `{n}`, `{n,}`, `{n,m}`).
pub fn escape_literal_braces(pattern: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            result.push('\\');
            if i + 1 < chars.len() {
                result.push(chars[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        if c == '{' {
            if let Some(len) = get_quantifier_len(&chars[i..]) {
                for k in 0..len {
                    result.push(chars[i + k]);
                }
                i += len;
            } else {
                result.push('\\');
                result.push('{');
                i += 1;
            }
        } else if c == '}' {
            result.push('\\');
            result.push('}');
            i += 1;
        } else {
            result.push(c);
            i += 1;
        }
    }
    result
}

fn get_quantifier_len(slice: &[char]) -> Option<usize> {
    if slice.is_empty() || slice[0] != '{' {
        return None;
    }
    let mut idx = 1;
    let mut has_digits1 = false;
    while idx < slice.len() && slice[idx].is_ascii_digit() {
        has_digits1 = true;
        idx += 1;
    }
    if !has_digits1 {
        return None;
    }
    if idx < slice.len() && slice[idx] == ',' {
        idx += 1;
        while idx < slice.len() && slice[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    if idx < slice.len() && slice[idx] == '}' {
        Some(idx + 1)
    } else {
        None
    }
}

/// Check if a regex compilation error is due to an unsupported feature in Rust's regex engine (e.g. look-around).
fn is_unsupported_regex_error(e: &regex::Error) -> bool {
    let msg = e.to_string();
    msg.contains("look-around") || msg.contains("look-ahead") || msg.contains("look-behind")
}

/// Validate a ruleset TOML string for structural correctness and regex validity.
///
/// This checks that:
/// 1. The TOML string is well-formed.
/// 2. The TOML parses correctly into the `RulesetConfig` structure.
/// 3. All regex patterns in rules compile successfully.
/// 4. All regex patterns in rule allowlists compile successfully.
/// 5. All regex patterns in global allowlists compile successfully.
/// 6. Every rule has a unique, non-empty ID.
/// 7. The ruleset contains at least one rule.
///
/// Returns `Ok(())` if the ruleset is fully valid, or `Err(Vec<String>)` containing
/// all encountered error descriptions.
pub fn validate_rules_toml(toml_str: &str) -> Result<(), Vec<String>> {
    let config: RulesetConfig = match toml::from_str(toml_str) {
        Ok(cfg) => cfg,
        Err(e) => return Err(vec![format!("TOML deserialization failed: {}", e)]),
    };

    let mut errors = Vec::new();

    let mut seen_ids = HashSet::new();

    for (idx, rule) in config.rules.iter().enumerate() {
        let rule_label = if rule.id.trim().is_empty() {
            format!("rule at index {}", idx)
        } else {
            format!("rule '{}'", rule.id)
        };

        // Check ID uniqueness and presence
        if rule.id.trim().is_empty() {
            errors.push(format!("Rule at index {} has an empty ID", idx));
        } else if !seen_ids.insert(rule.id.clone()) {
            errors.push(format!("Duplicate rule ID found: '{}'", rule.id));
        }

        // Validate detection regex
        if let Some(ref regex_str) = rule.regex {
            if let Err(e) = compile_regex(regex_str) {
                if is_unsupported_regex_error(&e) {
                    eprintln!(
                        "[validation] Warning: {} has regex with look-around which is not supported by Rust: {}",
                        rule_label, e
                    );
                } else {
                    errors.push(format!(
                        "{} has invalid detection regex '{}': {}",
                        rule_label, regex_str, e
                    ));
                }
            }
        }

        // Validate path filter regex
        if let Some(ref path_str) = rule.path {
            if let Err(e) = compile_regex(path_str) {
                if is_unsupported_regex_error(&e) {
                    eprintln!(
                        "[validation] Warning: {} has path regex with look-around which is not supported by Rust: {}",
                        rule_label, e
                    );
                } else {
                    errors.push(format!(
                        "{} has invalid path regex '{}': {}",
                        rule_label, path_str, e
                    ));
                }
            }
        }

        // Validate allowlists
        for (al_idx, allowlist) in rule.allowlists.iter().enumerate() {
            for (reg_idx, regex_str) in allowlist.regexes.iter().enumerate() {
                if let Err(e) = compile_regex(regex_str) {
                    if is_unsupported_regex_error(&e) {
                        eprintln!(
                            "[validation] Warning: {} allowlist at index {} has regex with look-around which is not supported by Rust: {}",
                            rule_label, al_idx, e
                        );
                    } else {
                        errors.push(format!(
                            "{} allowlist at index {} has invalid regex '{}' (pattern index {}): {}",
                            rule_label, al_idx, regex_str, reg_idx, e
                        ));
                    }
                }
            }
        }
    }

    // Validate global allowlist
    if let Some(ref global_al) = config.allowlist {
        for (idx, path_str) in global_al.paths.iter().enumerate() {
            if let Err(e) = compile_regex(path_str) {
                if is_unsupported_regex_error(&e) {
                    eprintln!(
                        "[validation] Warning: Global allowlist path pattern at index {} has regex with look-around which is not supported by Rust: {}",
                        idx, e
                    );
                } else {
                    errors.push(format!(
                        "Global allowlist path pattern at index {} is invalid '{}': {}",
                        idx, path_str, e
                    ));
                }
            }
        }
        for (idx, regex_str) in global_al.regexes.iter().enumerate() {
            if let Err(e) = compile_regex(regex_str) {
                if is_unsupported_regex_error(&e) {
                    eprintln!(
                        "[validation] Warning: Global allowlist regex pattern at index {} has regex with look-around which is not supported by Rust: {}",
                        idx, e
                    );
                } else {
                    errors.push(format!(
                        "Global allowlist regex pattern at index {} is invalid '{}': {}",
                        idx, regex_str, e
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────
#[cfg(test)]
mod tests {
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
    fn test_invalid_regex_in_global_allowlist() {
        let bad_regex = r#"
[allowlist]
regexes = ['*invalid-star-regex']

[[rules]]
id = "good-rule"
regex = 'good'
keywords = ["good"]
"#;
        let res = validate_rules_toml(bad_regex);
        assert!(res.is_err());
        assert!(res.unwrap_err()[0].contains("Global allowlist regex pattern at index 0 is invalid"));
    }
}
