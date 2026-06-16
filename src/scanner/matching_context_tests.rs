//! Direct unit tests for the pure context/redaction helpers in
//! `matching_context.rs`. These functions are exercised end-to-end through the
//! scanner in `redaction_tests.rs`, but the byte-range merging and UTF-8
//! boundary logic have nasty edge cases (overlap/adjacency, mid-codepoint
//! expansion, non-UTF-8 lines) where a regression silently UNDER-redacts and
//! leaks secret bytes. Test them in isolation so the failure mode is obvious.

use super::*;

/// Build a `Finding` carrying only the secret byte range the range-merging
/// logic reads; all other fields are inert. `Finding` has no `Default`, so the
/// helper keeps the per-test noise down.
fn finding_with_secret(start: usize, end: usize) -> Finding {
    Finding {
        file: String::new(),
        line: 0,
        col: 0,
        end_line: 0,
        end_col: 0,
        col_utf16: 0,
        end_col_utf16: 0,
        rule_id: String::new(),
        rule_description: String::new(),
        matched: String::new(),
        entropy: 0.0,
        start_offset: start,
        end_offset: end,
        secret_start_offset: start,
        secret_end_offset: end,
        fingerprint: String::new(),
        commit: None,
        context_lines: Vec::new(),
    }
}

// --- merged_secret_ranges -------------------------------------------------

#[test]
fn merges_overlapping_ranges() {
    let findings = [finding_with_secret(0, 5), finding_with_secret(3, 8)];
    assert_eq!(merged_secret_ranges(&findings, 100), vec![(0, 8)]);
}

#[test]
fn merges_adjacent_ranges_touching_at_a_point() {
    // start == current_end (4 <= 4) must merge: adjacent secrets share no gap, so
    // a single redaction span is correct and avoids an un-redacted seam.
    let findings = [finding_with_secret(0, 4), finding_with_secret(4, 8)];
    assert_eq!(merged_secret_ranges(&findings, 100), vec![(0, 8)]);
}

#[test]
fn keeps_disjoint_ranges_and_sorts_them() {
    // Supplied out of order; output must be sorted and unmerged across the gap.
    let findings = [finding_with_secret(10, 12), finding_with_secret(0, 3)];
    assert_eq!(merged_secret_ranges(&findings, 100), vec![(0, 3), (10, 12)]);
}

#[test]
fn merge_keeps_the_larger_end_and_does_not_shrink() {
    // A fully-contained later range must not pull current_end backwards.
    let findings = [finding_with_secret(0, 10), finding_with_secret(2, 4)];
    assert_eq!(merged_secret_ranges(&findings, 100), vec![(0, 10)]);
}

#[test]
fn drops_empty_and_inverted_ranges() {
    // start == end (empty) and start > end (inverted) are invalid and dropped,
    // not redacted as zero-width or panicked on.
    let findings = [finding_with_secret(5, 5), finding_with_secret(8, 4)];
    assert!(merged_secret_ranges(&findings, 100).is_empty());
}

#[test]
fn drops_ranges_past_content_len_but_keeps_those_at_the_boundary() {
    // end > content_len is a stale offset against this buffer and is dropped;
    // end == content_len is in-bounds and kept.
    let past = [finding_with_secret(0, 4)];
    assert!(merged_secret_ranges(&past, 3).is_empty());

    let at_boundary = [finding_with_secret(0, 3)];
    assert_eq!(merged_secret_ranges(&at_boundary, 3), vec![(0, 3)]);
}

// --- is_utf8_boundary_byte ------------------------------------------------

#[test]
fn boundary_byte_threshold() {
    // ASCII and UTF-8 lead bytes (>= -0x40 as i8) are boundaries;
    // continuation bytes (0x80..=0xBF) are not.
    for b in [0x00u8, 0x7F, 0xC0, 0xC2, 0xF0] {
        assert!(is_utf8_boundary_byte(b), "0x{b:02X} should be a boundary");
    }
    for b in [0x80u8, 0xA9, 0xBF] {
        assert!(
            !is_utf8_boundary_byte(b),
            "0x{b:02X} should not be a boundary"
        );
    }
}

// --- expand_to_utf8_boundaries --------------------------------------------

#[test]
fn expands_start_backwards_off_a_continuation_byte() {
    // "aéb" = [a, 0xC3, 0xA9, b]. A start at index 2 (the é continuation byte)
    // must move back to 1 so the whole codepoint is covered.
    let content = "aéb".as_bytes();
    assert_eq!(expand_to_utf8_boundaries(content, 2, 3), (1, 3));
}

#[test]
fn expands_end_forward_off_a_continuation_byte() {
    // An end landing mid-codepoint (index 2) must advance to the next boundary.
    let content = "aéb".as_bytes();
    assert_eq!(expand_to_utf8_boundaries(content, 0, 2), (0, 3));
}

// --- redact_line ----------------------------------------------------------

#[test]
fn redacts_multiple_secrets_on_one_line() {
    let content = b"A=aaaa B=bbbb";
    let out = redact_line(content, 0, content.len(), &[(2, 6), (9, 13)]);
    assert_eq!(out, "A=[REDACTED_SECRET] B=[REDACTED_SECRET]");
}

#[test]
fn redacting_a_mid_codepoint_range_expands_and_leaks_no_replacement_char() {
    // Range (2,3) starts inside é's continuation byte. The UTF-8 expansion must
    // grow it to the full codepoint so no lone U+FFFD replacement char (a
    // partial-secret tell) leaks into the output.
    let content = "aéb".as_bytes();
    let out = redact_line(content, 0, content.len(), &[(2, 3)]);
    assert_eq!(out, "a[REDACTED_SECRET]b");
    assert!(
        !out.contains('\u{FFFD}'),
        "no replacement char may leak: {out}"
    );
}

#[test]
fn clamps_a_secret_range_to_the_line_bounds() {
    // A range running past line_end (a multi-line match crossing into this
    // context line) is clamped to the line and must not redact trailing bytes
    // that belong to the next line.
    let content = b"abcdefgh";
    let out = redact_line(content, 0, 4, &[(2, 8)]);
    assert_eq!(out, "ab[REDACTED_SECRET]");
}

#[test]
fn non_utf8_line_uses_the_byte_exact_path() {
    // Invalid UTF-8 in the line forces the byte-exact branch (no boundary
    // expansion). The secret must still be fully removed.
    let content = b"pre\xFF=SECRETXY";
    let out = redact_line(content, 0, content.len(), &[(5, content.len())]);
    assert!(out.contains("[REDACTED_SECRET]"), "marker present: {out}");
    assert!(!out.contains("SECRETXY"), "raw secret must be gone: {out}");
}

// --- context_lines (±2 window truncation at file edges) -------------------

#[test]
fn context_window_truncates_at_file_start_without_underflow() {
    // Line 1 has no lines above it: first_line_num must clamp to 1, not wrap.
    let content = b"l1\nl2\nl3\nl4\nl5";
    let ctx = context_lines(content, 1, 0, 2);
    let nums: Vec<usize> = ctx.iter().map(|(n, _)| *n).collect();
    let text: Vec<&str> = ctx.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(nums, vec![1, 2, 3]);
    assert_eq!(text, vec!["l1", "l2", "l3"]);
}

#[test]
fn context_window_truncates_at_file_end() {
    // Line 5 is the last line: the window reaches back to line 3 and stops at EOF.
    let content = b"l1\nl2\nl3\nl4\nl5";
    let ctx = context_lines(content, 5, 12, 14);
    let nums: Vec<usize> = ctx.iter().map(|(n, _)| *n).collect();
    let text: Vec<&str> = ctx.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(nums, vec![3, 4, 5]);
    assert_eq!(text, vec!["l3", "l4", "l5"]);
}
