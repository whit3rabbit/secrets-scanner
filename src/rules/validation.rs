#[path = "validation/config.rs"]
pub mod config;

#[path = "validation/helpers.rs"]
pub mod helpers;

#[allow(unused_imports)]
pub use config::{
    AllowlistCondition, AllowlistConfig, GlobalAllowlist, RegexTarget, RuleConfig, RulesetConfig,
};
#[allow(unused_imports)]
pub use helpers::{
    compile_bytes_regex, compile_bytes_regex_set, compile_regex, escape_literal_braces,
    is_unsupported_regex_error,
};

use std::collections::HashSet;

/// Validate a ruleset TOML string for structural correctness and regex validity.
///
/// This checks that:
/// 1. The TOML string is well-formed.
/// 2. The TOML parses correctly into the `RulesetConfig` structure.
/// 3. All regex patterns in rules compile successfully.
/// 4. All regex patterns in rule allowlists compile successfully.
/// 5. All regex patterns in global allowlists compile successfully.
/// 6. Every rule has a unique, non-empty ID.
///
/// An empty ruleset is considered structurally valid (a `local.toml` may add
/// only allowlists); callers that require rules should check `rules` separately.
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

        if rule.regex.is_none() && rule.path.is_none() {
            errors.push(format!(
                "{} must define at least one detection predicate: regex or path",
                rule_label
            ));
        }

        for (kw_idx, keyword) in rule.keywords.iter().enumerate() {
            if keyword.trim().is_empty() {
                errors.push(format!(
                    "{} has an empty keyword at index {}",
                    rule_label, kw_idx
                ));
            }
        }

        // Detection regexes run on raw bytes at scan time, so validation must
        // use the same regex engine and reject anything runtime would skip.
        if let Some(ref regex_str) = rule.regex {
            if let Err(e) = compile_bytes_regex(regex_str) {
                errors.push(format!(
                    "{} has invalid detection regex '{}': {}",
                    rule_label, regex_str, e
                ));
            }
        }

        // Validate path filter regex
        if let Some(ref path_str) = rule.path {
            if let Err(e) = compile_regex(path_str) {
                errors.push(format!(
                    "{} has invalid path regex '{}': {}",
                    rule_label, path_str, e
                ));
            }
        }

        // Validate allowlists
        for (al_idx, allowlist) in rule.allowlists.iter().enumerate() {
            for (reg_idx, regex_str) in allowlist.regexes.iter().enumerate() {
                if let Err(e) = compile_bytes_regex(regex_str) {
                    errors.push(format!(
                        "{} allowlist at index {} has invalid regex '{}' (pattern index {}): {}",
                        rule_label, al_idx, regex_str, reg_idx, e
                    ));
                }
            }
            // Path patterns are also regexes and are compiled at load time, so
            // validate them here too (otherwise an invalid path silently drops
            // the allowlist's file-suppression at runtime).
            for (path_idx, path_str) in allowlist.paths.iter().enumerate() {
                if let Err(e) = compile_regex(path_str) {
                    errors.push(format!(
                        "{} allowlist at index {} has invalid path regex '{}' (pattern index {}): {}",
                        rule_label, al_idx, path_str, path_idx, e
                    ));
                }
            }
        }
    }

    // Validate global allowlists (both config.allowlist and config.allowlists)
    let mut all_global_allowlists = Vec::new();
    if let Some(ref al) = config.allowlist {
        all_global_allowlists.push(al);
    }
    for al in &config.allowlists {
        all_global_allowlists.push(al);
    }

    for (al_idx, global_al) in all_global_allowlists.iter().enumerate() {
        let al_label = if let Some(ref id) = global_al.id {
            format!("Global allowlist '{}'", id)
        } else {
            format!("Global allowlist at index {}", al_idx)
        };

        for (idx, path_str) in global_al.paths.iter().enumerate() {
            if let Err(e) = compile_regex(path_str) {
                errors.push(format!(
                    "{} path pattern at index {} is invalid '{}': {}",
                    al_label, idx, path_str, e
                ));
            }
        }
        for (idx, regex_str) in global_al.regexes.iter().enumerate() {
            if let Err(e) = compile_bytes_regex(regex_str) {
                errors.push(format!(
                    "{} regex pattern at index {} is invalid '{}': {}",
                    al_label, idx, regex_str, e
                ));
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
#[path = "validation/tests.rs"]
mod tests;
