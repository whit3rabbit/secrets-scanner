use aho_corasick::AhoCorasick;
use log::{debug, info, warn};

use super::{CompiledRule, RuleEngine, RuleRef};
use crate::error::ScannerError;
use crate::rules::allowlist::CompiledAllowlist;
use crate::rules::validation::{
    compile_bytes_regex, compile_bytes_regex_set, compile_regex, RulesetConfig,
};

/// Decoupled builder function that parses TOML rules and constructs the compiled `RuleEngine`.
pub(super) fn build_from_toml(toml_str: &str) -> Result<(RuleEngine, Vec<String>), ScannerError> {
    let config: RulesetConfig = toml::from_str(toml_str)?;

    let mut keyworded_rules = Vec::new();
    let mut unkeyworded_rules = Vec::new();
    let mut unkeyworded_set_patterns = Vec::new();
    let mut unkeyworded_set_rule_indices = Vec::new();
    let mut path_only_rules = Vec::new();
    let mut unique_keywords: Vec<String> = Vec::new();
    let mut keyword_to_rules: Vec<Vec<usize>> = Vec::new();
    let mut keyword_map = std::collections::HashMap::new();
    let mut skipped = 0usize;
    // Strict-validation report. Collected alongside the lenient build so a
    // strict caller can reject without a second pass; the build itself is
    // unaffected by what lands here.
    let mut issues: Vec<String> = Vec::new();

    // Structural ID checks (cheap, no regex) — mirror `validate_rules_toml`.
    let mut seen_ids = std::collections::HashSet::new();
    for rule_config in &config.rules {
        if rule_config.id.trim().is_empty() {
            issues.push("a rule has an empty ID".to_string());
        } else if !seen_ids.insert(rule_config.id.as_str()) {
            issues.push(format!("duplicate rule ID: '{}'", rule_config.id));
        }
    }

    for rule_config in &config.rules {
        // Compile the detection regex if present — skip rules with invalid patterns
        let regex = if let Some(ref reg_str) = rule_config.regex {
            match compile_bytes_regex(reg_str) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!(
                        "[engine] Warning: skipping rule '{}' — invalid regex: {}",
                        rule_config.id, e
                    );
                    issues.push(format!(
                        "rule '{}' has an invalid detection regex: {}",
                        rule_config.id, e
                    ));
                    skipped += 1;
                    continue;
                }
            }
        } else {
            None
        };

        // Validate that secret_group index is within bounds of the regex's capture groups
        let mut secret_group = rule_config.secret_group;
        if let (Some(ref re), Some(g)) = (&regex, secret_group) {
            if g >= re.captures_len() {
                warn!(
                    "[engine] Warning: rule '{}' has secret_group {} but regex only has {} capture groups. Falling back to default group selection.",
                    rule_config.id, g, re.captures_len()
                );
                secret_group = None;
            }
        }

        // Compile path filter
        let path_filter = match &rule_config.path {
            Some(p) => match compile_regex(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!(
                        "[engine] Warning: rule '{}' has invalid path regex: {}",
                        rule_config.id, e
                    );
                    issues.push(format!(
                        "rule '{}' has an invalid path regex: {}",
                        rule_config.id, e
                    ));
                    None
                }
            },
            None => None,
        };

        // Compile per-rule allowlists. A compiled allowlist that ends up with
        // fewer paths/regexes than the source had means one failed to compile
        // (logged inside the compile fn); surface it in the strict report.
        let mut allowlists = Vec::new();
        for al in &rule_config.allowlists {
            let compiled = CompiledAllowlist::compile_rule_allowlist(al, &rule_config.id);
            if compiled.paths.len() < al.paths.len() || compiled.regexes.len() < al.regexes.len() {
                issues.push(format!(
                    "rule '{}' has an invalid allowlist regex",
                    rule_config.id
                ));
            }
            allowlists.push(compiled);
        }

        let compiled_rule = CompiledRule {
            id: rule_config.id.clone(),
            description: rule_config.description.clone().unwrap_or_default(),
            regex,
            entropy_threshold: rule_config.entropy,
            keywords: rule_config
                .keywords
                .iter()
                .map(|k| k.to_lowercase())
                .collect(),
            path_filter,
            allowlists,
            secret_group,
        };

        let is_path_only = compiled_rule.regex.is_none() && compiled_rule.path_filter.is_some();

        if rule_config.keywords.is_empty() {
            let rule_idx = unkeyworded_rules.len();
            if is_path_only {
                path_only_rules.push(RuleRef::Unkeyworded(rule_idx));
            } else if let Some(ref reg_str) = rule_config.regex {
                unkeyworded_set_patterns.push(reg_str.clone());
                unkeyworded_set_rule_indices.push(rule_idx);
            }
            unkeyworded_rules.push(compiled_rule);
        } else {
            let rule_idx = keyworded_rules.len();
            if is_path_only {
                path_only_rules.push(RuleRef::Keyworded(rule_idx));
            }
            for kw in &rule_config.keywords {
                let kw_lower = kw.to_lowercase();
                let idx = *keyword_map.entry(kw_lower.clone()).or_insert_with(|| {
                    unique_keywords.push(kw_lower);
                    keyword_to_rules.push(Vec::new());
                    unique_keywords.len() - 1
                });
                keyword_to_rules[idx].push(rule_idx);
            }
            keyworded_rules.push(compiled_rule);
        }
    }

    if skipped > 0 {
        warn!("[engine] Skipped {skipped} rules with invalid regex patterns");
    }

    let unkeyworded_regex_set = if unkeyworded_set_patterns.is_empty() {
        None
    } else {
        match compile_bytes_regex_set(&unkeyworded_set_patterns) {
            Ok(set) => Some(set),
            Err(e) => {
                warn!(
                    "[engine] Warning: unkeyworded RegexSet prefilter disabled; falling back to per-rule scans: {e}"
                );
                unkeyworded_set_rule_indices.clear();
                None
            }
        }
    };

    // Compute unique first bytes for memchr pre-filter
    let mut first_bytes: Vec<u8> = unique_keywords
        .iter()
        .filter_map(|kw| kw.as_bytes().first().copied())
        .collect();
    first_bytes.sort_unstable();
    first_bytes.dedup();

    // Build Aho-Corasick automaton (case-insensitive for keywords, DFA for speed)
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .kind(Some(aho_corasick::AhoCorasickKind::DFA))
        .build(&unique_keywords)?;
    debug!(
        "[engine] Aho-Corasick DFA built for {} unique keywords",
        unique_keywords.len()
    );

    // Compile global allowlists (same drop-detection as per-rule allowlists).
    let mut global_allowlists = Vec::new();
    if let Some(ref al) = config.allowlist {
        let compiled = CompiledAllowlist::compile_global_allowlist(al);
        if compiled.paths.len() < al.paths.len() || compiled.regexes.len() < al.regexes.len() {
            issues.push("global allowlist has an invalid regex".to_string());
        }
        global_allowlists.push(compiled);
    }
    for al in &config.allowlists {
        let compiled = CompiledAllowlist::compile_global_allowlist(al);
        if compiled.paths.len() < al.paths.len() || compiled.regexes.len() < al.regexes.len() {
            let label = al.id.as_deref().unwrap_or("(unnamed)");
            issues.push(format!("global allowlist '{label}' has an invalid regex"));
        }
        global_allowlists.push(compiled);
    }

    info!(
        "[engine] Loaded {} rules ({} keyworded, {} unkeyworded, {} unique keywords, {} first-bytes for memchr)",
        keyworded_rules.len() + unkeyworded_rules.len(),
        keyworded_rules.len(),
        unkeyworded_rules.len(),
        unique_keywords.len(),
        first_bytes.len(),
    );

    Ok((
        RuleEngine {
            ac,
            keyword_to_rules,
            keyworded_rules,
            unkeyworded_rules,
            unkeyworded_regex_set,
            unkeyworded_set_rule_indices,
            path_only_rules,
            global_allowlists,
            keyword_first_bytes: first_bytes,
        },
        issues,
    ))
}
