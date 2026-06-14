//! rules/allowlist.rs — Compiled allowlist logic and evaluation.

use crate::rules::engine::CompiledRule;
use crate::rules::validation::{
    compile_bytes_regex, compile_regex, AllowlistCondition, AllowlistConfig, GlobalAllowlist,
    RegexTarget,
};
use regex::Regex;

/// A compiled allowlist rule.
#[derive(Debug)]
pub struct CompiledAllowlist {
    /// Human-readable description.
    pub description: Option<String>,

    /// Compiled path regexes — files matching any of these are skipped/suppressed.
    pub paths: Vec<Regex>,

    /// Compiled content regexes — findings matching any are suppressed.
    pub regexes: Vec<regex::bytes::Regex>,

    /// Stopwords (lowercase) — findings containing any of these are suppressed.
    pub stopwords: Vec<String>,

    /// The condition defining how the criteria are evaluated.
    pub condition: AllowlistCondition,

    /// What the allowlist regexes and stopwords match against.
    pub regex_target: RegexTarget,

    /// Rule IDs that this allowlist applies to. If empty, it applies globally/to all rules.
    pub target_rules: Vec<String>,
}

impl CompiledAllowlist {
    /// Compile a rule allowlist configuration.
    pub fn compile_rule_allowlist(al: &AllowlistConfig, rule_id: &str) -> Self {
        let mut paths = Vec::new();
        for pattern in &al.paths {
            match compile_regex(pattern) {
                Ok(re) => paths.push(re),
                Err(e) => {
                    log::warn!("rule '{}' has invalid allowlist path regex: {}", rule_id, e);
                }
            }
        }

        let mut regexes = Vec::new();
        for pattern in &al.regexes {
            match compile_bytes_regex(pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => {
                    log::warn!(
                        "rule '{}' has invalid allowlist content regex: {}",
                        rule_id,
                        e
                    );
                }
            }
        }

        let stopwords = al.stopwords.iter().map(|sw| sw.to_lowercase()).collect();
        let condition = al.condition.unwrap_or(AllowlistCondition::Or);
        let regex_target = al.regex_target.unwrap_or(RegexTarget::Secret);

        Self {
            description: al.description.clone(),
            paths,
            regexes,
            stopwords,
            condition,
            regex_target,
            target_rules: Vec::new(),
        }
    }

    /// Compile the global allowlist section.
    pub fn compile_global_allowlist(al: &GlobalAllowlist) -> Self {
        let mut paths = Vec::new();
        for pattern in &al.paths {
            match compile_regex(pattern) {
                Ok(re) => paths.push(re),
                Err(e) => {
                    log::warn!("global allowlist has invalid path regex: {}", e);
                }
            }
        }

        let mut regexes = Vec::new();
        for pattern in &al.regexes {
            match compile_bytes_regex(pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => {
                    log::warn!("global allowlist has invalid content regex: {}", e);
                }
            }
        }

        let stopwords = al.stopwords.iter().map(|sw| sw.to_lowercase()).collect();
        let condition = al.condition.unwrap_or(AllowlistCondition::Or);
        let regex_target = al.regex_target.unwrap_or(RegexTarget::Secret);

        Self {
            description: al.description.clone(),
            paths,
            regexes,
            stopwords,
            condition,
            regex_target,
            target_rules: al.target_rules.clone(),
        }
    }

    /// Evaluate allowlist criteria on a finding.
    pub fn evaluate(
        &self,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        if self.paths.is_empty() && self.regexes.is_empty() && self.stopwords.is_empty() {
            return false;
        }

        let path_matched =
            !self.paths.is_empty() && self.paths.iter().any(|re| re.is_match(file_path));

        let target_bytes = match self.regex_target {
            RegexTarget::Secret => secret_bytes,
            RegexTarget::Match => matched_bytes,
            RegexTarget::Line => line_bytes,
        };

        let regex_matched =
            !self.regexes.is_empty() && self.regexes.iter().any(|re| re.is_match(target_bytes));

        let stopword_matched = if self.stopwords.is_empty() {
            false
        } else {
            let target_str = String::from_utf8_lossy(target_bytes);
            let target_lower = target_str.to_lowercase();
            self.stopwords.iter().any(|sw| target_lower.contains(sw))
        };

        match self.condition {
            AllowlistCondition::Or => path_matched || regex_matched || stopword_matched,
            AllowlistCondition::And => {
                if !self.paths.is_empty() && !path_matched {
                    return false;
                }
                if !self.regexes.is_empty() && !regex_matched {
                    return false;
                }
                if !self.stopwords.is_empty() && !stopword_matched {
                    return false;
                }
                true
            }
        }
    }
}

/// Check if a file path is globally allowlisted (should be skipped).
pub fn is_path_globally_allowlisted(global_allowlists: &[CompiledAllowlist], path: &str) -> bool {
    global_allowlists.iter().any(|al| {
        if !al.target_rules.is_empty() {
            return false;
        }
        let matches_path = al.paths.iter().any(|re| re.is_match(path));
        if matches_path {
            match al.condition {
                AllowlistCondition::Or => true,
                AllowlistCondition::And => al.regexes.is_empty() && al.stopwords.is_empty(),
            }
        } else {
            false
        }
    })
}

/// Check if a matched byte slice is globally allowlisted.
pub fn is_match_globally_allowlisted(
    global_allowlists: &[CompiledAllowlist],
    rule_id: &str,
    file_path: &str,
    line_bytes: &[u8],
    matched_bytes: &[u8],
    secret_bytes: &[u8],
) -> bool {
    global_allowlists.iter().any(|al| {
        if !al.target_rules.is_empty() && !al.target_rules.iter().any(|r| r == rule_id) {
            return false;
        }

        al.evaluate(file_path, line_bytes, matched_bytes, secret_bytes)
    })
}

/// Check if a finding is suppressed by a specific rule's allowlist.
pub fn is_rule_allowlisted(
    rule: &CompiledRule,
    file_path: &str,
    line_bytes: &[u8],
    matched_bytes: &[u8],
    secret_bytes: &[u8],
) -> bool {
    rule.allowlists
        .iter()
        .any(|al| al.evaluate(file_path, line_bytes, matched_bytes, secret_bytes))
}
