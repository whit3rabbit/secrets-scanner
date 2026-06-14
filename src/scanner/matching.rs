//! Rule match evaluation for scanner content.

use std::collections::HashSet;

use crate::rules::engine::{CompiledRule, RuleEngine};
use crate::{entropy, filters};

use super::{Finding, Scanner};

/// Minimum token length for entropy checking. Tokens shorter than this
/// are likely not secrets and would produce unreliable entropy scores.
const MIN_TOKEN_LEN: usize = 8;

/// Number of context lines captured on each side of a matched line.
const CONTEXT_LINES: usize = 2;

/// Evaluates a single compiled rule regex over the content and populates findings.
///
/// `rule_seq` is a per-scan unique id for the rule; it is part of the dedup
/// key so that distinct rules matching the same span are both reported.
pub(super) fn check_rule_match(
    scanner: &Scanner,
    rule_seq: usize,
    rule: &CompiledRule,
    path: &str,
    content: &[u8],
    seen_positions: &mut HashSet<(usize, usize, usize)>,
    findings: &mut Vec<Finding>,
) {
    let regex_re = match &rule.regex {
        Some(re) => re,
        None => return,
    };

    if let Some(ref path_re) = rule.path_filter {
        if !path_re.is_match(path) {
            return;
        }
    }

    for captures in regex_re.captures_iter(content) {
        let m = match captures.get(0) {
            Some(m) => m,
            None => continue,
        };

        let matched_bytes = m.as_bytes();
        let match_start_in_file = m.start();
        let match_end_in_file = m.end();

        if match_start_in_file == match_end_in_file {
            continue;
        }

        if !seen_positions.insert((rule_seq, match_start_in_file, match_end_in_file)) {
            continue;
        }

        let secret_group_idx =
            rule.secret_group
                .unwrap_or_else(|| if regex_re.captures_len() > 1 { 1 } else { 0 });

        let secret_part = captures
            .get(secret_group_idx)
            .map(|g| g.as_bytes())
            .unwrap_or(matched_bytes);

        let secret_part_str = String::from_utf8_lossy(secret_part);
        let ent = entropy::shannon_entropy(&secret_part_str);
        if let Some(rule_threshold) = rule.entropy_threshold {
            let threshold = scanner
                .config
                .min_entropy_override
                .unwrap_or(rule_threshold);
            if secret_part.len() < MIN_TOKEN_LEN || ent < threshold {
                continue;
            }
        }

        let line_start = content[..match_start_in_file]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|pos| pos + 1)
            .unwrap_or(0);
        let line_end = content[match_start_in_file..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|pos| match_start_in_file + pos)
            .unwrap_or(content.len());
        let line_bytes = &content[line_start..line_end];

        if scanner.engine.is_match_globally_allowlisted(
            &rule.id,
            path,
            line_bytes,
            matched_bytes,
            secret_part,
        ) {
            continue;
        }

        if RuleEngine::is_rule_allowlisted(rule, path, line_bytes, matched_bytes, secret_part) {
            continue;
        }

        let line = content[..match_start_in_file]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1;
        // 1-based byte column of the match within its line.
        let col = match_start_in_file - line_start + 1;
        let context_lines = context_lines(content, line_start, line_end);

        let matched_str = String::from_utf8_lossy(matched_bytes);
        let display_match = if scanner.config.redact {
            filters::redact(&matched_str)
        } else {
            matched_str.to_string()
        };

        findings.push(Finding {
            file: path.to_string(),
            line,
            col,
            rule_id: rule.id.clone(),
            rule_description: rule.description.clone(),
            matched: display_match,
            entropy: ent,
            start_offset: match_start_in_file,
            end_offset: match_end_in_file,
            context_lines,
        });
    }
}

/// Extract surrounding context lines for a finding.
fn context_lines(content: &[u8], line_start: usize, line_end: usize) -> Vec<(usize, String)> {
    let mut ctx_start = line_start;
    for _ in 0..CONTEXT_LINES {
        if ctx_start == 0 {
            break;
        }
        match content[..ctx_start - 1].iter().rposition(|&b| b == b'\n') {
            Some(p) => ctx_start = p + 1,
            None => {
                ctx_start = 0;
                break;
            }
        }
    }

    let mut ctx_end = line_end;
    for _ in 0..CONTEXT_LINES {
        if ctx_end >= content.len() {
            break;
        }
        match content[ctx_end + 1..].iter().position(|&b| b == b'\n') {
            Some(p) => ctx_end += 1 + p,
            None => {
                ctx_end = content.len();
                break;
            }
        }
    }

    let mut context_lines = Vec::new();
    if ctx_start < ctx_end {
        let first_line_num = content[..ctx_start].iter().filter(|&&b| b == b'\n').count() + 1;
        for (offset, line_bytes) in content[ctx_start..ctx_end]
            .split(|&b| b == b'\n')
            .enumerate()
        {
            let line_text = String::from_utf8_lossy(line_bytes);
            context_lines.push((first_line_num + offset, line_text.trim_end().to_string()));
        }
    }

    context_lines
}
