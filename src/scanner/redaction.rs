//! Content redaction helpers for scanner findings.

use super::Finding;

/// Replacement text used by proxy-oriented redaction helpers.
const REDACTION_MARKER: &[u8] = b"[REDACTED_SECRET]";

/// Redact detected secret byte ranges in content.
pub(super) fn redact_content_bytes(content: &[u8], findings: &[Finding]) -> Vec<u8> {
    let ranges = merged_redaction_ranges(findings, content.len());
    if ranges.is_empty() {
        return content.to_vec();
    }

    let mut redacted = Vec::with_capacity(content.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        redacted.extend_from_slice(&content[cursor..start]);
        redacted.extend_from_slice(REDACTION_MARKER);
        cursor = end;
    }
    redacted.extend_from_slice(&content[cursor..]);
    redacted
}

/// Return sorted, merged secret byte ranges that are safe to redact.
fn merged_redaction_ranges(findings: &[Finding], content_len: usize) -> Vec<(usize, usize)> {
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
