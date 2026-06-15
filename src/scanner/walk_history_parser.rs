use std::path::Path;
use std::sync::atomic::Ordering;

use log::warn;

use super::super::{is_binary_skipped, is_unsafe_rel_path, should_collect_path, StatsAcc};
use crate::safe_display::sanitize_display;
use crate::scanner::{Finding, Scanner};

/// Accumulated added lines for the current file diff (all hunks of one file in
/// one commit), scanned as a single unit.
pub(super) struct FileDiff {
    /// Display path (root-joined) used as the finding's `file`.
    pub(super) path: String,
    /// Added-line content of every hunk, each line followed by `\n`.
    pub(super) buf: Vec<u8>,
    /// Real new-file line number of each line in `buf` (parallel to its lines),
    /// so finding/context line numbers map back across non-contiguous hunks.
    pub(super) line_map: Vec<usize>,
    /// True once `buf` hit `max_file_size` and further lines were dropped; the
    /// whole oversized diff is then skipped (parity with working-tree mode).
    pub(super) oversized: bool,
}

/// Streaming state machine over `git log -p -U0` output.
pub(crate) struct Parser<'a> {
    scanner: &'a Scanner,
    root: &'a str,
    stats: &'a StatsAcc,
    max_file_size: u64,
    /// `--max-findings` total cap.
    cap: Option<usize>,
    /// `--max-files` cap, applied as the number of file diffs scanned.
    max_files: Option<usize>,
    findings: Vec<Finding>,
    /// Number of file diffs actually scanned (for `max_files`).
    files_scanned: usize,
    cap_warned: bool,
    files_over_cap_warned: bool,
    current_commit: Option<String>,
    /// True while inside a combined/merge diff (`diff --cc`/`@@@`), which we do
    /// not attribute (merge-introduced content is caught on a non-merge parent).
    in_combined: bool,
    /// True once a `@@` hunk has begun in the current file diff; while true a
    /// `+`-prefixed line is added content, never a `+++` file header.
    in_hunk: bool,
    /// New-file line number of the next added line in the current hunk.
    hunk_next_line: usize,
    diff: Option<FileDiff>,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(scanner: &'a Scanner, root: &'a str, stats: &'a StatsAcc) -> Self {
        Parser {
            scanner,
            root,
            stats,
            max_file_size: scanner.config.max_file_size,
            cap: scanner.config.max_findings,
            max_files: scanner.config.max_files,
            findings: Vec::new(),
            files_scanned: 0,
            cap_warned: false,
            files_over_cap_warned: false,
            current_commit: None,
            in_combined: false,
            in_hunk: false,
            hunk_next_line: 0,
            diff: None,
        }
    }

    pub(crate) fn reached_cap(&self) -> bool {
        self.cap.is_some_and(|c| self.findings.len() >= c)
    }

    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    pub(crate) fn finish(&mut self) {
        self.flush_diff();
    }

    pub(crate) fn feed(&mut self, line: &[u8]) {
        if let Some(sha) = parse_commit_sha(line) {
            self.flush_diff();
            self.current_commit = Some(sha);
            self.in_combined = false;
            self.in_hunk = false;
            return;
        }
        if line.starts_with(b"diff --cc ") || line.starts_with(b"diff --combined ") {
            self.flush_diff();
            self.in_combined = true;
            self.in_hunk = false;
            return;
        }
        if line.starts_with(b"diff --git ") {
            self.flush_diff();
            self.in_combined = false;
            self.in_hunk = false;
            return;
        }
        if self.in_combined {
            return;
        }
        if line.starts_with(b"@@@ ") {
            // Combined-diff hunk (merge): not attributed.
            self.flush_diff();
            self.in_combined = true;
            self.in_hunk = false;
            return;
        }
        if line.starts_with(b"@@ ") {
            // A new hunk continues the SAME file diff; only the per-hunk line
            // counter resets. A malformed header stops attribution (in_hunk
            // false) so added lines are not mis-numbered.
            match parse_hunk_new_start(line) {
                Some(start) => {
                    self.in_hunk = true;
                    self.hunk_next_line = start;
                }
                None => self.in_hunk = false,
            }
            return;
        }
        // The `+++ b/path` file header is only valid before the first hunk of a
        // file diff. Guarding on `!in_hunk` is what prevents an added content
        // line beginning with `++ ` (patch form `+++ `) from being misread as a
        // header and silently dropping the rest of the hunk.
        if !self.in_hunk {
            if let Some(rest) = line.strip_prefix(b"+++ ") {
                self.flush_diff();
                self.start_diff_from_header(rest);
            }
            // Other header lines (`--- `, `index`, mode changes) are ignored.
            return;
        }
        // In-hunk content. Only added lines feed the buffer; removed/context
        // lines need no tracking because new-file line numbers come from the
        // hunk header (added lines are contiguous within a hunk).
        if line.first() == Some(&b'+') {
            self.push_added_line(&line[1..]);
        }
    }

    /// Resolve the new-file path from a `+++ ` header and begin a file diff,
    /// applying path containment and the extension/allowlist filters. Leaves
    /// `self.diff` as `None` when the path is filtered out, a deletion
    /// (`/dev/null`), or unsafe.
    fn start_diff_from_header(&mut self, rest: &[u8]) {
        self.diff = None;
        let rel_bytes = match rest.strip_prefix(b"b/") {
            Some(p) => p,
            // `/dev/null` (deletion) or an unexpected form: nothing to scan.
            None => return,
        };
        let rel = String::from_utf8_lossy(rel_bytes);
        let candidate = Path::new(rel.as_ref());
        if is_unsafe_rel_path(candidate) {
            warn!(
                "[scanner] Warning: dropping unsafe path from git history: {}",
                sanitize_display(&rel)
            );
            return;
        }
        let rel = rel.strip_prefix("./").unwrap_or(&rel);
        if !should_collect_path(self.scanner, rel)
            || self.scanner.engine.is_path_globally_allowlisted(rel)
        {
            return;
        }
        self.diff = Some(FileDiff {
            path: Path::new(self.root)
                .join(rel)
                .to_string_lossy()
                .into_owned(),
            buf: Vec::new(),
            line_map: Vec::new(),
            oversized: false,
        });
    }

    /// Append one added line to the current file diff's buffer, recording its
    /// real new-file line number. Stops appending (and records the diff as
    /// oversized) once the buffer would exceed `max_file_size`.
    fn push_added_line(&mut self, content: &[u8]) {
        let line_no = self.hunk_next_line;
        self.hunk_next_line = self.hunk_next_line.saturating_add(1);
        let max = self.max_file_size;
        let Some(diff) = self.diff.as_mut() else {
            return;
        };
        if diff.oversized {
            return;
        }
        // +1 for the '\n' appended after the line content.
        let projected = diff.buf.len() as u64 + content.len() as u64 + 1;
        if projected > max {
            diff.oversized = true;
            self.stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        diff.buf.extend_from_slice(content);
        diff.buf.push(b'\n');
        diff.line_map.push(line_no);
    }

    /// Scan the accumulated file diff (if any) as one unit and attribute its
    /// findings to the current commit.
    fn flush_diff(&mut self) {
        let Some(diff) = self.diff.take() else {
            return;
        };
        if diff.buf.is_empty() {
            return;
        }
        // Oversized diffs are skipped wholesale (already counted in
        // push_added_line), matching working-tree/staged modes.
        if diff.oversized {
            return;
        }
        // `--max-files`: cap the number of file diffs scanned. Excess diffs are
        // counted (never silently dropped) and skipped before the expensive rule
        // scan, so the cap bounds work while the summary stays honest.
        if let Some(maxf) = self.max_files {
            if self.files_scanned >= maxf {
                self.stats.files_over_cap.fetch_add(1, Ordering::Relaxed);
                if !self.files_over_cap_warned {
                    self.files_over_cap_warned = true;
                    warn!(
                        "[scanner] Warning: reached --max-files ({maxf}); remaining \
                         history file diffs not scanned."
                    );
                }
                return;
            }
        }
        // Binary gate on the reconstructed added content, matching the other
        // scan modes (a patch over a text-to-git-but-binary-to-us blob is skipped
        // consistently).
        if is_binary_skipped(self.scanner.config.binary_policy, &diff.path, &diff.buf) {
            self.stats.binary_skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.files_scanned += 1;
        self.stats.files_scanned.fetch_add(1, Ordering::Relaxed);

        // `scan_bytes_detailed` enforces `max_findings_per_file` (per file diff)
        // and logs its own truncation, exactly like working-tree/staged leaves.
        let scan_result = self.scanner.scan_bytes_detailed(&diff.path, &diff.buf);
        if scan_result.findings_truncated {
            self.stats.findings_truncated.store(true, Ordering::Relaxed);
        }
        let mut found = scan_result.findings;
        for f in &mut found {
            remap_finding(f, &diff.line_map);
            f.commit = self.current_commit.clone();
        }

        // `--max-findings` total cap with a one-time notice (parity with
        // walk_caps::scan_capped, which the other modes route through).
        if let Some(cap) = self.cap {
            let remaining = cap.saturating_sub(self.findings.len());
            if found.len() > remaining {
                found.truncate(remaining);
                self.stats.findings_truncated.store(true, Ordering::Relaxed);
            }
            self.findings.extend(found);
            if self.findings.len() >= cap && !self.cap_warned {
                self.cap_warned = true;
                self.stats.findings_truncated.store(true, Ordering::Relaxed);
                warn!(
                    "[scanner] Warning: reached --max-findings ({cap}); history scan \
                     stopped early."
                );
            }
        } else {
            self.findings.extend(found);
        }
    }
}

/// Map a finding's line numbers (and context-line numbers) from the
/// reconstructed buffer back to real new-file lines via `line_map`.
///
/// Byte offsets (`start_offset`/`end_offset`/`secret_*_offset`) are intentionally
/// left relative to the scanned buffer: a patch has no single real-file byte
/// offset (removed/context bytes are absent), and the relative values keep
/// `sort_findings` ordering stable within a file diff.
fn remap_finding(f: &mut Finding, line_map: &[usize]) {
    f.line = map_line(f.line, line_map);
    f.end_line = if f.end_line == 0 {
        f.line
    } else {
        map_line(f.end_line, line_map)
    };
    for (ln, _text) in &mut f.context_lines {
        *ln = map_line(*ln, line_map);
    }
}

/// Translate a 1-based buffer line number to its real new-file line via
/// `line_map`, falling back to the input if out of range (defensive; should not
/// happen since `line_map` has one entry per buffer line).
fn map_line(buf_line: usize, line_map: &[usize]) -> usize {
    if buf_line == 0 {
        return 0;
    }
    line_map.get(buf_line - 1).copied().unwrap_or(buf_line)
}

/// Parse a `commit <sha>` log header, returning the SHA only when it is a valid
/// 40-hex (sha1) or 64-hex (sha256) object id. Patch content lines are prefixed
/// (`+`/`-`/` `) and commit-message lines are indented, so a column-0 `commit `
/// here is the log header, not file content; the hex check is belt-and-suspenders.
pub(crate) fn parse_commit_sha(line: &[u8]) -> Option<String> {
    let rest = line.strip_prefix(b"commit ")?;
    let token = rest.split(|&b| b == b' ').next()?;
    if (token.len() == 40 || token.len() == 64) && token.iter().all(u8::is_ascii_hexdigit) {
        Some(String::from_utf8_lossy(token).into_owned())
    } else {
        None
    }
}

/// Parse the new-file start line from a unified hunk header
/// `@@ -a,b +c,d @@ ...` (or the single-count `@@ -a +c @@` form), returning `c`.
pub(crate) fn parse_hunk_new_start(line: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(line).ok()?;
    let after_plus = s.split('+').nth(1)?;
    let token = after_plus.split([' ', ',']).next()?;
    token.parse::<usize>().ok()
}
