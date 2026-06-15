//! Content redaction helpers for scanner findings.

use super::Finding;

/// Replacement text used by proxy-oriented redaction helpers.
const REDACTION_MARKER: &[u8] = b"[REDACTED_SECRET]";

/// Redact detected secret byte ranges in content.
pub(super) fn redact_content_bytes(content: &[u8], findings: &[Finding]) -> Vec<u8> {
    let ranges = super::matching::merged_secret_ranges(findings, content.len());
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
