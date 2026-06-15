//! scanner/walk_staged.rs — `--staged` mode: scan the git index, not the tree.
//!
//! For pre-commit hooks the bytes that matter are the ones staged in the index,
//! which can differ from the working tree (`git add -p`, or staging then editing
//! the file). Reading working-tree files would miss a staged secret (or falsely
//! flag an unstaged one), so this module reads each staged blob via
//! `git cat-file` and scans those bytes.
//!
//! It is a child module of `walk`, so it reuses walk's private helpers
//! (`run_git`, `run_git_quiet`, `is_binary_skipped`, `apply_max_findings_per_file`,
//! `StatsAcc`) through `super::`.

use std::path::{Component, Path};
use std::sync::atomic::Ordering;

use log::warn;

use crate::filters;
use crate::safe_display::sanitize_display;
use crate::scanner::{Finding, Scanner};

use super::{
    apply_max_findings_per_file, is_binary_skipped, run_git, run_git_blob_bounded, run_git_quiet,
    BlobRead, StatsAcc,
};

/// A staged file: its repo-relative index path (for the `:path` pathspec) and
/// the joined display path used as the finding's `file` (matching other git
/// modes, so SARIF relativization is consistent).
pub(super) struct StagedEntry {
    rel: String,
    display: String,
}

/// Collect staged (index) paths, applying the same extension/allowlist filters
/// as other modes. Returns `None` when git is unavailable so the caller can fall
/// back to a directory walk.
///
/// `--diff-filter=ACMR` excludes deletions (`D`): a deleted path has no staged
/// blob to scan, and trying to read it would otherwise inflate the errored count.
pub(super) fn collect_staged_paths(scanner: &Scanner, root: &str) -> Option<Vec<StagedEntry>> {
    let out = run_git(
        root,
        &[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
        ],
    )?;

    let mut entries = Vec::new();
    for rel in out.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        let rel = String::from_utf8_lossy(rel);
        let candidate = Path::new(rel.as_ref());
        // Lexical containment: index paths are always repo-relative; reject
        // absolute / parent-escaping paths defensively (git resolves the `:path`
        // pathspec inside the repo, so this is belt-and-suspenders).
        if candidate.is_absolute()
            || candidate
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            warn!(
                "[scanner] Warning: dropping unsafe staged path: {}",
                sanitize_display(&rel)
            );
            continue;
        }

        let rel = rel.strip_prefix("./").unwrap_or(&rel).to_string();
        if !filters::should_scan(&rel) || scanner.engine.is_path_globally_allowlisted(&rel) {
            continue;
        }

        let display = Path::new(root).join(&rel).to_string_lossy().to_string();
        entries.push(StagedEntry { rel, display });
    }
    Some(entries)
}

/// Read one staged blob and scan it. The blob size is checked with `cat-file -s`
/// before the content is read, preserving the bounded-read posture: an oversized
/// staged blob is recorded as oversized and never loaded into memory.
pub(super) fn scan_one_staged(
    scanner: &Scanner,
    root: &str,
    entry: &StagedEntry,
    stats: &StatsAcc,
) -> Vec<Finding> {
    let spec = format!(":./{}", entry.rel);

    let size = run_git_quiet(root, &["cat-file", "-s", &spec])
        .and_then(|out| std::str::from_utf8(&out).ok().map(str::to_owned))
        .and_then(|s| s.trim().parse::<u64>().ok());
    let size = match size {
        Some(n) => n,
        // The index entry vanished or is unreadable between listing and read:
        // count it as errored (incomplete coverage), not a clean skip.
        None => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
    };
    if size == 0 {
        return Vec::new();
    }
    if size > scanner.config.max_file_size {
        stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
        return Vec::new();
    }

    // Bounded read: re-checks the cap as the blob is read, closing the TOCTOU
    // window where the index entry could grow between the size check above and
    // this read (e.g. a concurrent `git add`).
    let bytes = match run_git_blob_bounded(root, &spec, scanner.config.max_file_size) {
        BlobRead::Ok(b) => b,
        BlobRead::Oversized => {
            stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        BlobRead::Error => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
    };

    if is_binary_skipped(scanner.config.binary_policy, &entry.display, &bytes) {
        stats.binary_skipped.fetch_add(1, Ordering::Relaxed);
        return Vec::new();
    }

    stats.files_scanned.fetch_add(1, Ordering::Relaxed);
    let mut findings = scanner.scan_bytes(&entry.display, &bytes);
    apply_max_findings_per_file(&mut findings, scanner, &entry.display);
    findings
}
