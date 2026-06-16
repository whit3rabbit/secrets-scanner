//! Content redaction helpers for scanner findings.

use super::Finding;

/// Replacement text used by proxy-oriented redaction helpers.
const REDACTION_MARKER: &[u8] = b"[REDACTED_SECRET]";

/// Redact detected secret byte ranges in content.
pub(super) fn redact_content_bytes(content: &[u8], findings: &[Finding]) -> Vec<u8> {
    let ranges = super::matching::merged_secret_ranges(findings, content.len());
    redact_content_ranges(content, &ranges)
}

pub(super) fn redact_content_ranges(content: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
    if ranges.is_empty() {
        return content.to_vec();
    }

    let mut redacted = Vec::with_capacity(content.len());
    let mut cursor = 0;
    let mut open_marker = false;
    for &(start, end) in ranges {
        // Widen each range to UTF-8 char boundaries so a `regex::bytes` match that
        // begins/ends mid-codepoint cannot leave a split char in the forwarded
        // bytes (which `scan_and_redact_content`'s `from_utf8_lossy` would then
        // mangle into U+FFFD). Mirrors the context-line redactor. Expansion only
        // ever grows a range, so `cursor` stays monotonic.
        let (start, end) = super::matching::expand_to_utf8_boundaries(content, start, end);
        if end <= cursor {
            // Fully inside the previous (expanded) redaction; nothing to add.
            continue;
        }
        if open_marker && start <= cursor {
            // Boundary expansion closed the gap between this range and the previous
            // one: extend that marker instead of emitting an adjacent duplicate
            // `[REDACTED_SECRET][REDACTED_SECRET]`. Merged input ranges always have
            // a gap, so this only fires when expansion grows two ranges into contact.
            cursor = end;
            continue;
        }
        redacted.extend_from_slice(&content[cursor..start]);
        redacted.extend_from_slice(REDACTION_MARKER);
        cursor = end;
        open_marker = true;
    }
    redacted.extend_from_slice(&content[cursor..]);
    redacted
}
