//! Rule match evaluation for scanner content.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::rules::engine::{CompiledRule, RuleEngine};
use crate::{entropy, filters};

use super::{Finding, Scanner};

/// Minimum token length for entropy checking. Tokens shorter than this
/// are likely not secrets and would produce unreliable entropy scores.
const MIN_TOKEN_LEN: usize = 8;

/// Number of context lines captured on each side of a matched line.
const CONTEXT_LINES: usize = 2;

/// Marker used when redacting secrets from display context.
const CONTEXT_REDACTION_MARKER: &str = "[REDACTED_SECRET]";

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

        let secret_match = match rule.secret_group {
            Some(secret_group_idx) => captures
                .get(secret_group_idx)
                .filter(|group| group.start() < group.end())
                .unwrap_or(m),
            None => m,
        };
        let secret_part = secret_match.as_bytes();
        let secret_start_in_file = secret_match.start();
        let secret_end_in_file = secret_match.end();

        let ent = entropy::shannon_entropy_bytes(secret_part);
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
        // End position of the full match. `end_col` is exclusive (SARIF-style):
        // it points just past the last matched byte on `end_line`.
        let newlines_before_end = content[..match_end_in_file]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        let end_line = newlines_before_end + 1;
        let end_line_start = content[..match_end_in_file]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|pos| pos + 1)
            .unwrap_or(0);
        let end_col = match_end_in_file - end_line_start + 1;
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
            end_line,
            end_col,
            rule_id: rule.id.clone(),
            rule_description: rule.description.clone(),
            matched: display_match,
            entropy: ent,
            start_offset: match_start_in_file,
            end_offset: match_end_in_file,
            secret_start_offset: secret_start_in_file,
            secret_end_offset: secret_end_in_file,
            context_lines,
        });
    }
}

/// Redact every finding's context with all secret byte ranges from this file.
pub(super) fn redact_context_lines(content: &[u8], findings: &mut [Finding]) {
    if findings.is_empty() {
        return;
    }

    let secret_ranges = merged_secret_ranges(findings, content.len());
    if secret_ranges.is_empty() {
        return;
    }

    let line_ranges = line_ranges(content);
    let context_line_nums: BTreeSet<usize> = findings
        .iter()
        .flat_map(|finding| finding.context_lines.iter().map(|(line_num, _)| *line_num))
        .collect();
    let mut redacted_by_line = HashMap::with_capacity(context_line_nums.len());
    let mut range_idx = 0;
    for line_num in context_line_nums {
        let Some((line_start, line_end)) = line_ranges.get(line_num.saturating_sub(1)) else {
            continue;
        };
        while range_idx < secret_ranges.len() && secret_ranges[range_idx].1 <= *line_start {
            range_idx += 1;
        }
        redacted_by_line.insert(
            line_num,
            redact_line(content, *line_start, *line_end, &secret_ranges[range_idx..]),
        );
    }

    for finding in findings {
        for (line_num, line_text) in &mut finding.context_lines {
            if let Some(redacted) = redacted_by_line.get(line_num) {
                *line_text = redacted.clone();
            }
        }
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

fn merged_secret_ranges(findings: &[Finding], content_len: usize) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = findings
        .iter()
        .filter_map(|finding| {
            let start = finding.secret_start_offset;
            let end = finding.secret_end_offset;
            if start < end && end <= content_len {
                Some((start, end))
            } else {
                None
            }
        })
        .collect();

    ranges.sort_unstable_by_key(|&(start, end)| (start, end));

    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some((_, current_end)) if start <= *current_end => {
                *current_end = (*current_end).max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn line_ranges(content: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for (idx, &b) in content.iter().enumerate() {
        if b == b'\n' {
            ranges.push((start, idx));
            start = idx + 1;
        }
    }
    ranges.push((start, content.len()));
    ranges
}

fn redact_line(
    content: &[u8],
    line_start: usize,
    line_end: usize,
    secret_ranges: &[(usize, usize)],
) -> String {
    let mut redacted = String::new();
    let mut cursor = line_start;
    for &(secret_start, secret_end) in secret_ranges {
        if secret_start >= line_end {
            break;
        }
        if secret_end <= line_start {
            continue;
        }

        let start = secret_start.max(line_start);
        let end = secret_end.min(line_end);
        if start > cursor {
            redacted.push_str(&String::from_utf8_lossy(&content[cursor..start]));
        }
        if end > cursor {
            redacted.push_str(CONTEXT_REDACTION_MARKER);
            cursor = end;
        }
    }

    if cursor < line_end {
        redacted.push_str(&String::from_utf8_lossy(&content[cursor..line_end]));
    }
    redacted.trim_end().to_string()
}
