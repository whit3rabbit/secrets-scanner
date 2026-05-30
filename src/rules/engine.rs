/// rules/engine.rs — Parse gitleaks-compatible TOML rules into a compiled scan engine.
///
/// The engine deserializes the TOML ruleset into typed structs, compiles all
/// regexes once at startup, and builds a single Aho-Corasick automaton from
/// the union of all rule keywords. This enables O(n) scanning of file content
/// regardless of how many rules exist.
///
/// # Architecture
///
/// ```text
/// TOML string → RulesetConfig (serde) → RuleEngine (compiled)
///                                          ├── AhoCorasick (all keywords)
///                                          ├── keyword_map[ac_idx] → rule_idx
///                                          └── Vec<CompiledRule> (regex + metadata)
/// ```

use aho_corasick::AhoCorasick;
use regex::Regex;
use crate::rules::validation::{RulesetConfig, GlobalAllowlist, compile_regex};

// ─────────────────────────────────────────────
// Compiled Rule Engine
// ─────────────────────────────────────────────

/// A compiled rule ready for scanning. All regexes are pre-compiled.
#[derive(Debug)]
pub struct CompiledRule {
    /// Unique rule ID from the TOML config.
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// Compiled detection regex.
    pub regex: Option<Regex>,

    /// Minimum entropy threshold (from rule config, or `None` to use global default).
    pub entropy_threshold: Option<f64>,

    /// Keywords (lowercase) for this rule.
    pub keywords: Vec<String>,

    /// Compiled file-path filter regex (if the rule has a `path` field).
    pub path_filter: Option<Regex>,

    /// Compiled per-rule allowlist regexes.
    pub allowlist_regexes: Vec<Regex>,

    /// Per-rule allowlist regex target: `true` if regexes match against
    /// the full match line, `false` (default) if against the captured group.
    pub allowlist_match_target: bool,

    /// Per-rule stopwords (lowercase).
    pub stopwords: Vec<String>,

    /// Optional capture group index for the secret.
    pub secret_group: Option<usize>,
}

/// Compiled global allowlist.
#[derive(Debug)]
pub struct CompiledGlobalAllowlist {
    /// Compiled path regexes — files matching any are skipped.
    pub path_regexes: Vec<Regex>,

    /// Compiled content regexes — findings matching any are suppressed.
    pub content_regexes: Vec<Regex>,

    /// Global stopwords (lowercase).
    pub stopwords: Vec<String>,
}

/// The compiled rule engine. Owns the Aho-Corasick automaton and all compiled rules.
///
/// # Usage
///
/// ```no_run
/// use secrets_scanner::rules::engine::RuleEngine;
///
/// let toml_str = std::fs::read_to_string("assets/secrets-scanner.toml").unwrap();
/// let engine = RuleEngine::from_toml(&toml_str).unwrap();
/// println!("Loaded {} rules with {} keywords", engine.rule_count(), engine.keyword_count());
/// ```
pub struct RuleEngine {
    /// Aho-Corasick automaton built from ALL keywords across all rules.
    ac: AhoCorasick,

    /// Maps AC pattern index → rule index. Multiple keywords can map to the same rule.
    keyword_to_rule: Vec<usize>,

    /// All compiled rules.
    rules: Vec<CompiledRule>,

    /// Compiled global allowlist.
    global_allowlist: CompiledGlobalAllowlist,

    /// Pre-computed set of unique first bytes from all keywords,
    /// used for the memchr SIMD pre-filter.
    keyword_first_bytes: Vec<u8>,
}

impl RuleEngine {
    /// Parse a TOML ruleset string and compile into a scan-ready engine.
    ///
    /// This is the main constructor. It:
    /// 1. Deserializes the TOML into `RulesetConfig`
    /// 2. Compiles all rule regexes (skipping rules with invalid regex)
    /// 3. Collects all keywords and builds a single Aho-Corasick automaton
    /// 4. Compiles global and per-rule allowlists
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or if the Aho-Corasick
    /// automaton cannot be built.
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: RulesetConfig = toml::from_str(toml_str)?;

        let mut compiled_rules = Vec::with_capacity(config.rules.len());
        let mut all_keywords: Vec<String> = Vec::new();
        let mut keyword_to_rule: Vec<usize> = Vec::new();
        let mut skipped = 0usize;

        for rule_config in &config.rules {
            // Compile the detection regex if present — skip rules with invalid patterns
            let regex = if let Some(ref reg_str) = rule_config.regex {
                match compile_regex(reg_str) {
                    Ok(re) => Some(re),
                    Err(e) => {
                        eprintln!(
                            "[engine] Warning: skipping rule '{}' — invalid regex: {}",
                            rule_config.id, e
                        );
                        skipped += 1;
                        continue;
                    }
                }
            } else {
                None
            };

            // Compile path filter
            let path_filter = rule_config.path.as_ref().and_then(|p| {
                compile_regex(p)
                    .map_err(|e| {
                        eprintln!(
                            "[engine] Warning: rule '{}' has invalid path regex: {}",
                            rule_config.id, e
                        );
                        e
                    })
                    .ok()
            });

            // Compile per-rule allowlist regexes
            let mut allowlist_regexes = Vec::new();
            let mut allowlist_match_target = false;
            let mut stopwords = Vec::new();

            for al in &rule_config.allowlists {
                if al.regex_target.as_deref() == Some("match") {
                    allowlist_match_target = true;
                }
                for pattern in &al.regexes {
                    match compile_regex(pattern) {
                        Ok(re) => allowlist_regexes.push(re),
                        Err(e) => {
                            eprintln!(
                                "[engine] Warning: rule '{}' has invalid allowlist regex: {}",
                                rule_config.id, e
                            );
                        }
                    }
                }
                for sw in &al.stopwords {
                    stopwords.push(sw.to_lowercase());
                }
            }

            let rule_idx = compiled_rules.len();

            // Register keywords for the AC automaton
            for kw in &rule_config.keywords {
                all_keywords.push(kw.to_lowercase());
                keyword_to_rule.push(rule_idx);
            }

            compiled_rules.push(CompiledRule {
                id: rule_config.id.clone(),
                description: rule_config
                    .description
                    .clone()
                    .unwrap_or_default(),
                regex,
                entropy_threshold: rule_config.entropy,
                keywords: rule_config.keywords.iter().map(|k| k.to_lowercase()).collect(),
                path_filter,
                allowlist_regexes,
                allowlist_match_target,
                stopwords,
                secret_group: rule_config.secret_group,
            });
        }

        if skipped > 0 {
            eprintln!("[engine] Skipped {skipped} rules with invalid regex patterns");
        }

        // Compute unique first bytes for memchr pre-filter
        let mut first_bytes: Vec<u8> = all_keywords
            .iter()
            .filter_map(|kw| kw.as_bytes().first().copied())
            .collect();
        first_bytes.sort_unstable();
        first_bytes.dedup();

        // Build Aho-Corasick automaton (case-insensitive for keywords)
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&all_keywords)?;

        // Compile global allowlist
        let global_allowlist = Self::compile_global_allowlist(&config.allowlist);

        eprintln!(
            "[engine] Loaded {} rules ({} keywords, {} first-bytes for memchr)",
            compiled_rules.len(),
            all_keywords.len(),
            first_bytes.len(),
        );

        Ok(Self {
            ac,
            keyword_to_rule,
            rules: compiled_rules,
            global_allowlist,
            keyword_first_bytes: first_bytes,
        })
    }

    /// Compile the global allowlist section.
    fn compile_global_allowlist(allowlist: &Option<GlobalAllowlist>) -> CompiledGlobalAllowlist {
        let Some(al) = allowlist else {
            return CompiledGlobalAllowlist {
                path_regexes: Vec::new(),
                content_regexes: Vec::new(),
                stopwords: Vec::new(),
            };
        };

        let path_regexes = al
            .paths
            .iter()
            .filter_map(|p| {
                compile_regex(p)
                    .map_err(|e| {
                        eprintln!("[engine] Warning: invalid global allowlist path regex: {e}");
                        e
                    })
                    .ok()
            })
            .collect();

        let content_regexes = al
            .regexes
            .iter()
            .filter_map(|r| {
                compile_regex(r)
                    .map_err(|e| {
                        eprintln!("[engine] Warning: invalid global allowlist regex: {e}");
                        e
                    })
                    .ok()
            })
            .collect();

        let stopwords = al.stopwords.iter().map(|s| s.to_lowercase()).collect();

        CompiledGlobalAllowlist {
            path_regexes,
            content_regexes,
            stopwords,
        }
    }

    /// Returns a reference to the Aho-Corasick automaton.
    pub fn ac(&self) -> &AhoCorasick {
        &self.ac
    }

    /// Returns the compiled rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Look up which rule index a keyword AC match belongs to.
    pub fn rule_for_keyword(&self, ac_pattern_index: usize) -> usize {
        self.keyword_to_rule[ac_pattern_index]
    }

    /// Returns the global allowlist.
    pub fn global_allowlist(&self) -> &CompiledGlobalAllowlist {
        &self.global_allowlist
    }

    /// The set of unique first bytes from all keywords (for memchr pre-filter).
    pub fn keyword_first_bytes(&self) -> &[u8] {
        &self.keyword_first_bytes
    }

    /// Total number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Total number of keywords in the AC automaton.
    pub fn keyword_count(&self) -> usize {
        self.keyword_to_rule.len()
    }

    /// Check if a file path is globally allowlisted (should be skipped).
    pub fn is_path_globally_allowlisted(&self, path: &str) -> bool {
        self.global_allowlist
            .path_regexes
            .iter()
            .any(|re| re.is_match(path))
    }

    /// Check if a matched string is globally allowlisted.
    pub fn is_match_globally_allowlisted(&self, matched: &str) -> bool {
        let lower = matched.to_lowercase();

        // Check stopwords
        if self
            .global_allowlist
            .stopwords
            .iter()
            .any(|sw| lower.contains(sw.as_str()))
        {
            return true;
        }

        // Check content regexes
        self.global_allowlist
            .content_regexes
            .iter()
            .any(|re| re.is_match(matched))
    }

    /// Check if a finding is suppressed by a specific rule's allowlist.
    pub fn is_rule_allowlisted(rule: &CompiledRule, matched: &str, _file_path: &str) -> bool {
        // Check per-rule stopwords
        let lower = matched.to_lowercase();
        if rule.stopwords.iter().any(|sw| lower.contains(sw.as_str())) {
            return true;
        }

        // Check per-rule allowlist regexes
        if rule.allowlist_regexes.iter().any(|re| re.is_match(matched)) {
            return true;
        }

        // Check per-rule path allowlists (inside allowlist entries)
        // Note: path filtering is handled separately via path_filter
        false
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(engine.rule_for_keyword(0), 0);
        assert_eq!(engine.rule_for_keyword(1), 0);
        // Third keyword (ghp_) maps to rule 1
        assert_eq!(engine.rule_for_keyword(2), 1);
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
        assert!(engine.is_match_globally_allowlisted("test_value"));
        assert!(engine.is_match_globally_allowlisted("some placeholder text"));
        assert!(!engine.is_match_globally_allowlisted("AKIAIOSFODNN7EXAMPLEX"));
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
    fn loads_bundled_rules() {
        // This tests against the actual bundled rules to ensure they parse
        let toml_str = include_str!("../../assets/secrets-scanner.toml");
        let engine = RuleEngine::from_toml(toml_str).expect("bundled rules should parse");
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
}
