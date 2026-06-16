//! Context extraction and context-line redaction for matched findings.

use std::collections::{BTreeSet, HashMap};

use super::Finding;

const CONTEXT_LINES: usize = 2;
const CONTEXT_REDACTION_MARKER: &str = "[REDACTED_SECRET]";

/// Redact every finding's context with all secret byte ranges from this file.
pub fn redact_context_lines(content: &[u8], findings: &mut [Finding]) {
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
pub fn context_lines(
    content: &[u8],
    line: usize,
    line_start: usize,
    line_end: usize,
) -> Vec<(usize, String)> {
    let mut ctx_start = line_start;
    let mut first_line_num = line;
    for _ in 0..CONTEXT_LINES {
        if ctx_start == 0 {
            break;
        }
        match content[..ctx_start - 1].iter().rposition(|&b| b == b'\n') {
            Some(p) => {
                ctx_start = p + 1;
                first_line_num -= 1;
            }
            None => {
                ctx_start = 0;
                first_line_num = 1;
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

/// Sorted, merged secret byte ranges (`secret_start_offset..secret_end_offset`)
/// across `findings`, clamped to `content_len`. Shared by context-line redaction
/// here and full-content redaction in [`super::redaction`].
pub fn merged_secret_ranges(findings: &[Finding], content_len: usize) -> Vec<(usize, usize)> {
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
    let valid_utf8_line = std::str::from_utf8(&content[line_start..line_end]).is_ok();
    let mut redacted = String::new();
    let mut cursor = line_start;
    for &(secret_start, secret_end) in secret_ranges {
        if secret_start >= line_end {
            break;
        }
        if secret_end <= line_start {
            continue;
        }

        let (start, end) = if valid_utf8_line {
            expand_to_utf8_boundaries(
                content,
                secret_start.max(line_start),
                secret_end.min(line_end),
            )
        } else {
            (secret_start.max(line_start), secret_end.min(line_end))
        };
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

/// Widen `[start, end)` outward to the nearest UTF-8 char boundaries.
///
/// Rules compile as `regex::bytes`, so a match can begin or end mid-codepoint.
/// Slicing on such a range yields invalid UTF-8; expanding first keeps the
/// surrounding bytes valid. Shared with the proxy redaction path
/// (`redaction::redact_content_bytes`) so both redactors are boundary-consistent.
pub fn expand_to_utf8_boundaries(
    content: &[u8],
    mut start: usize,
    mut end: usize,
) -> (usize, usize) {
    while start > 0 && !is_utf8_boundary_byte(content[start]) {
        start -= 1;
    }
    while end < content.len() && !is_utf8_boundary_byte(content[end]) {
        end += 1;
    }
    (start, end)
}

fn is_utf8_boundary_byte(byte: u8) -> bool {
    (byte as i8) >= -0x40
}

#[cfg(test)]
#[path = "matching_context_tests.rs"]
mod tests;
