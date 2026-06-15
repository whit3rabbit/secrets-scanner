//! scanner/walk.rs — Directory walking and path filtering.
//!
//! Path-discovery modes:
//! * Default — uses `walkdir` recursively.
//! * `git_tracked` / `changed_files` — uses `git ls-files` or
//!   `git diff --name-only` to scan the current working-tree content of tracked
//!   or changed files.
//! * `git_staged` (`walk_staged.rs`) — scans index blobs for pre-commit.
//! * `git_history` (`walk_history.rs`) — scans `git log -p` patches.
//!
//! Explicit git modes fail closed on git error by default (the CLI exits 2);
//! they fall back to a directory walk only when `git_fallback_walk` is set
//! (history mode never falls back).
//!
//! Hardening for hostile repositories: reads are bounded (the file cannot grow
//! past `max_file_size` between the metadata check and the read), symlinks are
//! rejected, git output is NUL-delimited and absolute paths from git are dropped,
//! and binary content is detected by inspection rather than extension alone.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use walkdir::WalkDir;

use crate::filters;
use crate::scanner::{BinaryPolicy, Finding, ScanStats, Scanner};

#[path = "walk_caps.rs"]
mod caps;
use caps::{apply_max_files, scan_file_paths, scan_staged_entries, sort_findings};

#[path = "walk_file.rs"]
mod file;
#[cfg(test)]
use file::read_bounded;
use file::{is_binary_skipped, scan_one_file};

/// Thread-safe accumulator for scan statistics during the parallel walk.
#[derive(Default)]
struct StatsAcc {
    files_scanned: AtomicUsize,
    binary_skipped: AtomicUsize,
    oversized_skipped: AtomicUsize,
    files_over_cap: AtomicUsize,
    errored: AtomicUsize,
    git_fallback: AtomicBool,
    git_failed: AtomicBool,
    findings_truncated: AtomicBool,
}

impl StatsAcc {
    fn snapshot(&self) -> ScanStats {
        ScanStats {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            binary_skipped: self.binary_skipped.load(Ordering::Relaxed),
            oversized_skipped: self.oversized_skipped.load(Ordering::Relaxed),
            files_over_cap: self.files_over_cap.load(Ordering::Relaxed),
            errored: self.errored.load(Ordering::Relaxed),
            git_fallback: self.git_fallback.load(Ordering::Relaxed),
            git_failed: self.git_failed.load(Ordering::Relaxed),
            findings_truncated: self.findings_truncated.load(Ordering::Relaxed),
        }
    }
}

/// Walk a path, filter files, and scan them in parallel using Rayon.
///
/// Returns the findings plus file-level [`ScanStats`].
pub fn scan_path(scanner: &Scanner, root: &str) -> (Vec<Finding>, ScanStats) {
    let stats = StatsAcc::default();

    // History mode scans `git log -p` patches, attributing findings to the
    // commit that added them. It is its own git mode and always fails closed
    // (a directory walk cannot approximate history), so `git_fallback_walk`
    // does not apply here.
    if scanner.config.git_history {
        let mut findings = history::scan_history(scanner, root, &stats);
        sort_findings(&mut findings);
        return (findings, stats.snapshot());
    }

    // Staged mode scans index-blob content (`git cat-file`), NOT working-tree
    // files, so the bytes examined are exactly what is about to be committed.
    if scanner.config.git_staged {
        if let Some(mut entries) = staged::collect_staged_paths(scanner, root) {
            staged::sort_entries(&mut entries);
            apply_max_files(&mut entries, scanner, &stats);
            let mut findings = scan_staged_entries(scanner, root, &entries, &stats);
            sort_findings(&mut findings);
            return (findings, stats.snapshot());
        }
        // Git unavailable / not a repo. Fail closed by default (nothing scanned,
        // CLI exits 2); only walk the tree if the caller opted in.
        if !git_failure_falls_back(scanner, &stats) {
            return (Vec::new(), stats.snapshot());
        }
    }

    let want_git = (scanner.config.git_tracked || scanner.config.changed_files)
        && !stats.git_fallback.load(Ordering::Relaxed);
    let mut paths = if want_git {
        match collect_git_paths(root, &scanner.config) {
            Some(git_paths) => filter_git_paths(scanner, git_paths),
            // Git failed (not a repo, git missing, file path arg, …). Fail
            // closed by default rather than silently scanning the whole working
            // tree (which would widen scope to untracked/ignored files); only
            // fall back to a directory walk when `git_fallback_walk` is set.
            None => {
                if !git_failure_falls_back(scanner, &stats) {
                    return (Vec::new(), stats.snapshot());
                }
                collect_walkdir_paths(scanner, root, &stats)
            }
        }
    } else if stats.git_failed.load(Ordering::Relaxed) {
        // A failed staged mode already decided to fail closed above.
        return (Vec::new(), stats.snapshot());
    } else {
        collect_walkdir_paths(scanner, root, &stats)
    };

    paths.sort_unstable();
    apply_max_files(&mut paths, scanner, &stats);

    let mut findings = scan_file_paths(scanner, &paths, &stats);
    sort_findings(&mut findings);

    (findings, stats.snapshot())
}

/// Scan exactly one file through the hardened file-read path.
pub fn scan_file(scanner: &Scanner, path: &str) -> (Vec<Finding>, ScanStats) {
    let stats = StatsAcc::default();
    if !should_collect_path(scanner, path) || scanner.engine.is_path_globally_allowlisted(path) {
        return (Vec::new(), stats.snapshot());
    }
    let mut findings = scan_one_file(scanner, path, &stats);
    sort_findings(&mut findings);
    (findings, stats.snapshot())
}

/// Decide what happens when an explicit git mode fails. Returns `true` when the
/// caller should fall back to a directory walk (records `git_fallback`); returns
/// `false` to fail closed (records `git_failed`, so the CLI exits 2 and the
/// failed git request is never mistaken for a clean scan).
fn git_failure_falls_back(scanner: &Scanner, stats: &StatsAcc) -> bool {
    if scanner.config.git_fallback_walk {
        stats.git_fallback.store(true, Ordering::Relaxed);
        true
    } else {
        stats.git_failed.store(true, Ordering::Relaxed);
        false
    }
}

/// Collect paths via recursive directory walk, applying filters.
fn collect_walkdir_paths(scanner: &Scanner, root: &str, stats: &StatsAcc) -> Vec<String> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| match e {
            Ok(entry) => Some(entry),
            // A traversal error (e.g. an unreadable directory) is a coverage gap:
            // count it as errored so an unreadable subtree is not mistaken for an
            // empty, scanned-and-clean one.
            Err(_) => {
                stats.errored.fetch_add(1, Ordering::Relaxed);
                None
            }
        })
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let path_str = e.path().to_str().unwrap_or("");
            // Basic extension/directory filter. `BinaryPolicy::Scan` widens only
            // the extension side of this filter; noisy directories stay skipped.
            if !should_collect_path(scanner, path_str) {
                return false;
            }
            // Size filter (also rechecked in scan_one_file for git-collected paths).
            if let Ok(meta) = e.metadata() {
                if meta.len() > scanner.config.max_file_size {
                    stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            // Global path allowlist
            if scanner.engine.is_path_globally_allowlisted(path_str) {
                return false;
            }
            true
        })
        .map(|e| e.path().to_string_lossy().to_string())
        .collect()
}

/// Apply the same extension/allowlist filters to git-collected paths that the
/// directory walk applies, so `--git-tracked` mode does not scan binaries or
/// globally-allowlisted files that the default mode would skip.
fn filter_git_paths(scanner: &Scanner, paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| {
            should_collect_path(scanner, p) && !scanner.engine.is_path_globally_allowlisted(p)
        })
        .collect()
}

fn should_collect_path(scanner: &Scanner, path: &str) -> bool {
    filters::should_scan_with_extension_filter(
        path,
        scanner.config.binary_policy != BinaryPolicy::Scan,
    )
}

#[path = "walk_git.rs"]
mod walk_git;

pub(super) use walk_git::{
    collect_git_paths, is_unsafe_rel_path, run_git, run_git_blob_bounded, BlobRead,
};

// Staged-index (`--staged`) scanning lives in a sibling file; as a child module
// it reuses walk's private helpers via `super::`.
#[path = "walk_staged.rs"]
mod staged;

// Git-history (`--git-history`) patch scanning lives in a sibling file; as a
// child module it reuses walk's private helpers (`StatsAcc`, path filters) via
// `super::`.
#[path = "walk_history.rs"]
mod history;

// Tests live in a sibling file (explicit `#[path]`) to keep walk.rs ≤ 400 lines.
#[cfg(test)]
#[path = "walk_tests.rs"]
mod tests;
