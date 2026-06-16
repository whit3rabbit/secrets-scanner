//! Deterministic path/finding ordering and scan caps for directory walks.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use log::warn;
use rayon::prelude::*;

use crate::scanner::{Finding, Scanner};

use super::{scan_one_file, staged, StatsAcc};

/// Run `scan_one` over every item, applying the `--max-findings` total cap.
///
/// With no cap, scans in parallel via rayon. With a cap, the scan deliberately
/// drops to a serial walk so the running total can early-exit deterministically
/// once the cap is reached: this trades multi-core throughput on capped scans for
/// a bounded, reproducible result set (the previous parallel-then-truncate path
/// scanned every file before discarding the overflow). `noun`/`scan_label` only
/// shape the warning text, keeping it identical to the per-mode messages.
fn scan_capped<T: Sync>(
    scanner: &Scanner,
    items: &[T],
    stats: &StatsAcc,
    noun: &str,
    scan_label: &str,
    scan_one: impl Fn(&T) -> Vec<Finding> + Sync,
) -> Vec<Finding> {
    let Some(cap) = scanner.config.max_findings else {
        return items.par_iter().flat_map(&scan_one).collect();
    };

    if cap == 0 {
        if !items.is_empty() {
            stats.findings_truncated.store(true, Ordering::Relaxed);
            warn!("[scanner] Warning: --max-findings is 0; no {noun} scanned.");
        }
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (idx, it) in items.iter().enumerate() {
        // `saturating_sub` is defensive: the `break` below keeps `findings.len() <
        // cap` on re-entry today, but a future edit must not be able to underflow.
        let remaining = cap.saturating_sub(findings.len());
        let mut item_findings = scan_one(it);
        let truncated_current = item_findings.len() > remaining;
        item_findings.truncate(remaining);
        findings.extend(item_findings);

        if findings.len() >= cap {
            if truncated_current || idx + 1 < items.len() {
                stats.findings_truncated.store(true, Ordering::Relaxed);
                warn!(
                    "[scanner] Warning: reached --max-findings ({cap}); {scan_label} stopped early."
                );
            }
            break;
        }
    }
    findings
}

pub(super) fn scan_file_paths(
    scanner: &Scanner,
    paths: &[PathBuf],
    stats: &StatsAcc,
) -> Vec<Finding> {
    scan_capped(scanner, paths, stats, "files", "scan", |path| {
        scan_one_file(scanner, path, stats)
    })
}

pub(super) fn scan_staged_entries(
    scanner: &Scanner,
    root: &str,
    entries: &[staged::StagedEntry],
    stats: &StatsAcc,
) -> Vec<Finding> {
    scan_capped(
        scanner,
        entries,
        stats,
        "staged files",
        "staged scan",
        |entry| staged::scan_one_staged(scanner, root, entry, stats),
    )
}

pub(super) fn sort_findings(findings: &mut [Finding]) {
    // `commit` and `line` are part of the key so history-mode output is
    // deterministic: offsets there are buffer-relative, so two findings in the
    // same file from different commits can share (file, offsets, rule). Without
    // commit/line in the key the unstable sort would order those arbitrarily.
    findings.sort_unstable_by(|a, b| {
        (
            a.file.as_str(),
            a.start_offset,
            a.end_offset,
            a.rule_id.as_str(),
            a.commit.as_deref(),
            a.line,
        )
            .cmp(&(
                b.file.as_str(),
                b.start_offset,
                b.end_offset,
                b.rule_id.as_str(),
                b.commit.as_deref(),
                b.line,
            ))
    });
}

#[cfg(test)]
#[path = "walk_caps_tests.rs"]
mod tests;

/// Apply the `--max-files` cap, recording the drop so the summary cannot read as full coverage.
pub(super) fn apply_max_files<T>(items: &mut Vec<T>, scanner: &Scanner, stats: &StatsAcc) {
    if let Some(cap) = scanner.config.max_files {
        if items.len() > cap {
            let dropped = items.len() - cap;
            stats.files_over_cap.store(dropped, Ordering::Relaxed);
            warn!(
                "[scanner] Warning: file count ({}) exceeds --max-files ({cap}); \
                 {dropped} file(s) not scanned.",
                items.len()
            );
            items.truncate(cap);
        }
    }
}
