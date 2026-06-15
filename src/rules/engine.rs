//! rules/engine.rs — Parse gitleaks-compatible TOML rules into a compiled scan engine.
//!
//! The engine deserializes the TOML ruleset into typed structs, compiles all
//! regexes once at startup, and builds a single Aho-Corasick automaton from
//! the union of all rule keywords. This enables O(n) scanning of file content
//! regardless of how many rules exist.
//!
//! # Architecture
//!
//! ```text
//! TOML string → RulesetConfig (serde) → RuleEngine (compiled)
//!                                          ├── AhoCorasick (all keywords)
//!                                          ├── keyword_map[ac_idx] → rule_idx
//!                                          └── Vec<CompiledRule> (regex + metadata)
//! ```

use crate::rules::validation::{compile_bytes_regex, compile_regex, RulesetConfig};
use aho_corasick::AhoCorasick;
use log::{debug, info, warn};
use regex::Regex;

pub use crate::rules::allowlist::CompiledAllowlist;

/// A compiled rule ready for scanning. All regexes are pre-compiled.
#[derive(Debug)]
pub struct CompiledRule {
    /// Unique rule ID from the TOML config.
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// Compiled detection regex.
    pub regex: Option<regex::bytes::Regex>,

    /// Minimum entropy threshold. `None` disables entropy gating for this rule.
    pub entropy_threshold: Option<f64>,

    /// Keywords (lowercase) for this rule.
    pub keywords: Vec<String>,

    /// Compiled file-path filter regex (if the rule has a `path` field).
    pub path_filter: Option<Regex>,

    /// Per-rule allowlists.
    pub allowlists: Vec<CompiledAllowlist>,

    /// Optional capture group index for the secret.
    pub secret_group: Option<usize>,
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
    /// Aho-Corasick automaton built from ALL keywords across all rules that have keywords.
    ac: AhoCorasick,

    /// Maps AC pattern index → list of rule indices. Multiple keywords map to different rules.
    keyword_to_rules: Vec<Vec<usize>>,

    /// Compiled rules that have keywords.
    keyworded_rules: Vec<CompiledRule>,

    /// Compiled rules that do NOT have keywords.
    unkeyworded_rules: Vec<CompiledRule>,

    /// Compiled global allowlists.
    global_allowlists: Vec<CompiledAllowlist>,

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
    pub fn from_toml(toml_str: &str) -> Result<Self, crate::error::ScannerError> {
        Ok(Self::from_toml_reporting(toml_str)?.0)
    }

    /// Like [`from_toml`], but also returns a list of human-readable issues
    /// describing everything the lenient build had to drop or that is
    /// structurally invalid: rules with an uncompilable detection regex,
    /// invalid path/allowlist/global-allowlist regexes, and empty/duplicate
    /// rule IDs. An empty `Vec` means the ruleset compiled cleanly with nothing
    /// skipped.
    ///
    /// This lets a strict caller (`Scanner::from_toml`) fail loudly on an
    /// explicit `--rules` file using the *same single* parse+compile pass that
    /// builds the engine, instead of paying for a separate full validation pass
    /// that re-parses the TOML and re-compiles every regex.
    ///
    /// [`from_toml`]: RuleEngine::from_toml
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or if the Aho-Corasick
    /// automaton cannot be built.
    pub fn from_toml_reporting(
        toml_str: &str,
    ) -> Result<(Self, Vec<String>), crate::error::ScannerError> {
        let config: RulesetConfig = toml::from_str(toml_str)?;

        let mut keyworded_rules = Vec::new();
        let mut unkeyworded_rules = Vec::new();
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
                if compiled.paths.len() < al.paths.len()
                    || compiled.regexes.len() < al.regexes.len()
                {
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

            if rule_config.keywords.is_empty() {
                unkeyworded_rules.push(compiled_rule);
            } else {
                let rule_idx = keyworded_rules.len();
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
            Self {
                ac,
                keyword_to_rules,
                keyworded_rules,
                unkeyworded_rules,
                global_allowlists,
                keyword_first_bytes: first_bytes,
            },
            issues,
        ))
    }

    /// Returns a reference to the Aho-Corasick automaton.
    pub fn ac(&self) -> &AhoCorasick {
        &self.ac
    }

    /// Returns a list of references to all compiled rules (both keyworded and unkeyworded).
    pub fn rules(&self) -> Vec<&CompiledRule> {
        self.keyworded_rules
            .iter()
            .chain(self.unkeyworded_rules.iter())
            .collect()
    }

    /// Returns the compiled rules that have keywords.
    pub fn keyworded_rules(&self) -> &[CompiledRule] {
        &self.keyworded_rules
    }

    /// Returns the compiled rules that do NOT have keywords.
    pub fn unkeyworded_rules(&self) -> &[CompiledRule] {
        &self.unkeyworded_rules
    }

    /// Look up which rule indices a keyword AC match belongs to.
    pub fn rules_for_keyword(&self, ac_pattern_index: usize) -> &[usize] {
        &self.keyword_to_rules[ac_pattern_index]
    }

    /// Returns the global allowlists.
    pub fn global_allowlists(&self) -> &[CompiledAllowlist] {
        &self.global_allowlists
    }

    /// The set of unique first bytes from all keywords (for memchr pre-filter).
    pub fn keyword_first_bytes(&self) -> &[u8] {
        &self.keyword_first_bytes
    }

    /// Total number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.keyworded_rules.len() + self.unkeyworded_rules.len()
    }

    /// Total number of unique keywords in the AC automaton.
    pub fn keyword_count(&self) -> usize {
        self.keyword_to_rules.len()
    }

    /// Check if a file path is globally allowlisted (should be skipped).
    pub fn is_path_globally_allowlisted(&self, path: &str) -> bool {
        crate::rules::allowlist::is_path_globally_allowlisted(&self.global_allowlists, path)
    }

    /// Check if a matched byte slice is globally allowlisted.
    pub fn is_match_globally_allowlisted(
        &self,
        rule_id: &str,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        crate::rules::allowlist::is_match_globally_allowlisted(
            &self.global_allowlists,
            rule_id,
            file_path,
            line_bytes,
            matched_bytes,
            secret_bytes,
        )
    }

    /// Check if a finding is suppressed by a specific rule's allowlist.
    pub fn is_rule_allowlisted(
        rule: &CompiledRule,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        crate::rules::allowlist::is_rule_allowlisted(
            rule,
            file_path,
            line_bytes,
            matched_bytes,
            secret_bytes,
        )
    }
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod tests;
