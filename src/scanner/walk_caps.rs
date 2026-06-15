//! Deterministic path/finding ordering and scan caps for directory walks.

use std::sync::atomic::Ordering;

use log::warn;
use rayon::prelude::*;

use crate::scanner::{Finding, Scanner};

use super::{scan_one_file, staged, StatsAcc};

pub(super) fn scan_file_paths(
    scanner: &Scanner,
    paths: &[String],
    stats: &StatsAcc,
) -> Vec<Finding> {
    let Some(cap) = scanner.config.max_findings else {
        return paths
            .par_iter()
            .flat_map(|path| scan_one_file(scanner, path, stats))
            .collect();
    };

    if cap == 0 {
        if !paths.is_empty() {
            warn!("[scanner] Warning: --max-findings is 0; no files scanned.");
        }
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (idx, path) in paths.iter().enumerate() {
        let remaining = cap - findings.len();
        let mut file_findings = scan_one_file(scanner, path, stats);
        let truncated_current = file_findings.len() > remaining;
        file_findings.truncate(remaining);
        findings.extend(file_findings);

        if findings.len() >= cap {
            if truncated_current || idx + 1 < paths.len() {
                warn!("[scanner] Warning: reached --max-findings ({cap}); scan stopped early.");
            }
            break;
        }
    }
    findings
}

pub(super) fn scan_staged_entries(
    scanner: &Scanner,
    root: &str,
    entries: &[staged::StagedEntry],
    stats: &StatsAcc,
) -> Vec<Finding> {
    let Some(cap) = scanner.config.max_findings else {
        return entries
            .par_iter()
            .flat_map(|entry| staged::scan_one_staged(scanner, root, entry, stats))
            .collect();
    };

    if cap == 0 {
        if !entries.is_empty() {
            warn!("[scanner] Warning: --max-findings is 0; no staged files scanned.");
        }
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        let remaining = cap - findings.len();
        let mut entry_findings = staged::scan_one_staged(scanner, root, entry, stats);
        let truncated_current = entry_findings.len() > remaining;
        entry_findings.truncate(remaining);
        findings.extend(entry_findings);

        if findings.len() >= cap {
            if truncated_current || idx + 1 < entries.len() {
                warn!(
                    "[scanner] Warning: reached --max-findings ({cap}); staged scan stopped early."
                );
            }
            break;
        }
    }
    findings
}

pub(super) fn sort_findings(findings: &mut [Finding]) {
    findings.sort_unstable_by(|a, b| {
        (
            a.file.as_str(),
            a.start_offset,
            a.end_offset,
            a.rule_id.as_str(),
        )
            .cmp(&(
                b.file.as_str(),
                b.start_offset,
                b.end_offset,
                b.rule_id.as_str(),
            ))
    });
}

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
