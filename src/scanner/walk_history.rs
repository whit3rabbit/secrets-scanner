//! scanner/walk_history.rs — `--git-history` mode: scan `git log -p` patches.
//!
//! Unlike `git_tracked`/`changed_files` (which scan current working-tree file
//! content), history mode scans the full commit history as unified patches and
//! attributes each finding to the commit that ADDED the matched line. This
//! catches secrets that were committed and later removed from the tree — the
//! main capability gap versus `gitleaks git`.
//!
//! It is a child module of `walk`, so it reuses walk's private helpers
//! (`StatsAcc`, `should_collect_path`, `is_unsafe_rel_path`, `is_binary_skipped`)
//! through `super::`.
//!
//! ## Scan unit and shared posture
//!
//! The scan unit is one *file diff*: all hunks of a single file within a single
//! commit. Their added (`+`) lines are reconstructed into one buffer that is
//! handed to `Scanner::scan_bytes` exactly like a working-tree file, so the same
//! per-file finding cap (`max_findings_per_file`), binary detection, and
//! redaction apply uniformly — history is not a parallel scan path that
//! re-derives those guards per hunk. A `line_map` records the real new-file line
//! of each buffered line so findings report file-accurate line numbers even
//! across non-contiguous hunks.
//!
//! Parsing: `git log -p -U0` is streamed line-by-line over bytes (paths/content
//! may be non-UTF-8). With `-U0` there are no context lines, so within a hunk the
//! added (`+`) lines are exactly the new-file lines and are contiguous in
//! new-file numbering starting at the hunk header's `+` start. The `+++ b/path`
//! file header is recognised only BEFORE the first hunk of a file diff, so an
//! added content line whose text begins with `++ ` (rendered `+++ ` in the patch)
//! is never mistaken for a header.
//!
//! Trust model: `history_log_opts` is operator-controlled (legitimate `git log`
//! options). Each option is passed as one argv entry verbatim (so a value may
//! contain spaces) — never split or run through a shell — and the invocation is
//! terminated with `--`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;

use log::warn;

use crate::scanner::{Finding, Scanner};

use super::StatsAcc;

/// Scan the repository's git history. Always fails closed: on any git error the
/// `git_failed` stat is set (mapping to CLI exit 2) and no findings are
/// returned, so an unscannable history request is never mistaken for a clean
/// scan. A directory-walk fallback is deliberately not offered (it cannot
/// approximate history).
pub(super) fn scan_history(scanner: &Scanner, root: &str, stats: &StatsAcc) -> Vec<Finding> {
    if scanner.config.max_findings == Some(0) {
        return scan_history_zero_cap(scanner, root, stats);
    }

    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.args(["log", "-p", "-U0", "--no-color", "--no-ext-diff"]);
    append_history_options(&mut cmd, scanner);
    // Terminate options so an operator-supplied value cannot be reinterpreted as
    // a pathspec beyond git's own option parsing.
    cmd.arg("--");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!("[scanner] git-history mode could not run git: {e}.");
            stats.git_failed.store(true, Ordering::Relaxed);
            return Vec::new();
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.wait();
            stats.git_failed.store(true, Ordering::Relaxed);
            return Vec::new();
        }
    };

    // Optional wall-clock budget: stop the `git log` stream once the deadline
    // passes so a huge history cannot keep a scan running unbounded. `0` (the
    // default) disables it. A trip is reported as truncated coverage, not failure.
    // `checked_add` guards against an absurdly large operator timeout overflowing
    // the platform clock representation (which would panic on `Instant + Duration`):
    // such a value collapses to "no deadline" (effectively unlimited, which is what
    // a near-`u64::MAX` timeout means anyway) instead of crashing the scan.
    let deadline = if scanner.config.history_timeout_secs > 0 {
        std::time::Instant::now().checked_add(std::time::Duration::from_secs(
            scanner.config.history_timeout_secs,
        ))
    } else {
        None
    };

    let mut parser = Parser::new(scanner, root, stats);
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    let mut read_error = false;
    let mut timed_out = false;
    // Check the clock only every N lines: an Instant::now() per patch line would
    // add measurable overhead on a large history.
    let mut since_check: u32 = 0;
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                // Strip only the trailing newline; a preceding '\r' may be real
                // CRLF file content and is preserved for fidelity.
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                parser.feed(&line);
                if parser.reached_cap() {
                    break;
                }
                if let Some(dl) = deadline {
                    since_check += 1;
                    if since_check >= 1024 {
                        since_check = 0;
                        if std::time::Instant::now() >= dl {
                            timed_out = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                read_error = true;
                break;
            }
        }
    }
    parser.finish();

    // A timeout is an intentional early stop (like the finding cap), so the
    // resulting non-success exit status is expected, not a git failure.
    let killed_early = parser.reached_cap() || timed_out;
    if killed_early || read_error {
        let _ = child.kill();
    }
    let status = child.wait();

    if read_error {
        warn!("[scanner] git-history mode: error reading `git log` output.");
        stats.git_failed.store(true, Ordering::Relaxed);
        return Vec::new();
    }
    if timed_out {
        // Surface the partial coverage via the existing truncation signal (same
        // one the zero-cap path uses), which the CLI summary and Node binding
        // already report. Also set `history_timed_out`: unlike a finding cap, an
        // expired timeout left commits unscanned, so it counts as incomplete
        // coverage (a strict Node scan throws INCOMPLETE_SCAN on it).
        stats.findings_truncated.store(true, Ordering::Relaxed);
        stats.history_timed_out.store(true, Ordering::Relaxed);
        warn!(
            "[scanner] git-history mode: --history-timeout budget exceeded; \
             scan stopped early (coverage incomplete)."
        );
    }
    // A clean (non-killed) run that exits non-zero means git failed (e.g. not a
    // repository). Killing the child ourselves to honor --max-findings yields a
    // non-success status that is expected, so it is not treated as failure.
    if !killed_early {
        match status {
            Ok(s) if s.success() => {}
            _ => {
                warn!("[scanner] git-history mode: `git log` failed (not a repository?).");
                stats.git_failed.store(true, Ordering::Relaxed);
                return Vec::new();
            }
        }
    }
    parser.into_findings()
}

fn scan_history_zero_cap(scanner: &Scanner, root: &str, stats: &StatsAcc) -> Vec<Finding> {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.arg("log");
    append_history_options(&mut cmd, scanner);
    cmd.arg("--max-count=0");
    cmd.arg("--");
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    match cmd.status() {
        Ok(status) if status.success() => {
            stats.findings_truncated.store(true, Ordering::Relaxed);
            warn!("[scanner] Warning: --max-findings is 0; no history scanned.");
        }
        Ok(_) => {
            warn!("[scanner] git-history mode: `git log` failed (not a repository?).");
            stats.git_failed.store(true, Ordering::Relaxed);
        }
        Err(e) => {
            warn!("[scanner] git-history mode could not run git: {e}.");
            stats.git_failed.store(true, Ordering::Relaxed);
        }
    }
    Vec::new()
}

fn append_history_options(cmd: &mut Command, scanner: &Scanner) {
    if scanner.config.history_full {
        cmd.arg("--full-history");
    }
    if scanner.config.history_all {
        cmd.arg("--all");
    }
    // Each operator-supplied option is one argv entry verbatim (no whitespace
    // re-tokenization), so a value containing spaces (e.g. `--since=2 weeks ago`)
    // reaches git intact.
    for opt in &scanner.config.history_log_opts {
        cmd.arg(opt);
    }
}

#[path = "walk_history_parser.rs"]
mod parser;

pub(super) use parser::Parser;
#[cfg(test)]
pub(super) use parser::{parse_commit_sha, parse_hunk_new_start};

#[cfg(test)]
#[path = "walk_history_tests.rs"]
mod tests;
