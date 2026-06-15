//! scanner/walk.rs — Directory walking and path filtering.
//!
//! Two path-discovery modes:
//! * Default — uses `walkdir` recursively.
//! * Git mode — uses `git ls-files` or `git diff --name-only` for git-aware scanning.
//!   On any git failure it falls back to the recursive directory walk.
//!
//! Hardening for hostile repositories: reads are bounded (the file cannot grow
//! past `max_file_size` between the metadata check and the read), symlinks are
//! rejected, git output is NUL-delimited and absolute paths from git are dropped,
//! and binary content is detected by inspection rather than extension alone.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use log::warn;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::filters;
use crate::safe_display::sanitize_display;
use crate::scanner::{BinaryPolicy, Finding, ScanStats, Scanner};

/// Thread-safe accumulator for scan statistics during the parallel walk.
#[derive(Default)]
struct StatsAcc {
    files_scanned: AtomicUsize,
    binary_skipped: AtomicUsize,
    oversized_skipped: AtomicUsize,
    files_over_cap: AtomicUsize,
    errored: AtomicUsize,
    git_fallback: AtomicBool,
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
        }
    }
}

/// Walk a path, filter files, and scan them in parallel using Rayon.
///
/// Returns the findings plus file-level [`ScanStats`].
pub fn scan_path(scanner: &Scanner, root: &str) -> (Vec<Finding>, ScanStats) {
    let stats = StatsAcc::default();

    // Staged mode scans index-blob content (`git cat-file`), NOT working-tree
    // files, so the bytes examined are exactly what is about to be committed.
    if scanner.config.git_staged {
        if let Some(mut entries) = staged::collect_staged_paths(scanner, root) {
            apply_max_files(&mut entries, scanner, &stats);
            let mut findings: Vec<Finding> = entries
                .par_iter()
                .flat_map(|entry| staged::scan_one_staged(scanner, root, entry, &stats))
                .collect();
            apply_max_findings(&mut findings, scanner);
            return (findings, stats.snapshot());
        }
        // Git unavailable / not a repo: fall back to a directory walk below.
        stats.git_fallback.store(true, Ordering::Relaxed);
    }

    let want_git = (scanner.config.git || scanner.config.git_diff)
        && !stats.git_fallback.load(Ordering::Relaxed);
    let mut paths = if want_git {
        match collect_git_paths(root, &scanner.config) {
            Some(git_paths) => filter_git_paths(scanner, git_paths),
            // Git failed (not a repo, git missing, file path arg, …) — fall back
            // to the directory walk rather than silently scanning nothing. Record
            // the fallback: it widens scope (may include untracked/ignored files).
            None => {
                stats.git_fallback.store(true, Ordering::Relaxed);
                collect_walkdir_paths(scanner, root, &stats)
            }
        }
    } else {
        collect_walkdir_paths(scanner, root, &stats)
    };

    apply_max_files(&mut paths, scanner, &stats);

    let mut findings: Vec<Finding> = paths
        .par_iter()
        .flat_map(|path| scan_one_file(scanner, path, &stats))
        .collect();

    apply_max_findings(&mut findings, scanner);

    (findings, stats.snapshot())
}

/// Apply the `--max-files` cap, recording the drop so the summary cannot read as
/// full coverage. Generic so working-tree paths and staged entries share it.
fn apply_max_files<T>(items: &mut Vec<T>, scanner: &Scanner, stats: &StatsAcc) {
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

/// Apply the global `--max-findings` cap, logging truncation so it stays visible.
fn apply_max_findings(findings: &mut Vec<Finding>, scanner: &Scanner) {
    if let Some(cap) = scanner.config.max_findings {
        if findings.len() > cap {
            warn!(
                "[scanner] Warning: finding count ({}) exceeds --max-findings ({cap}); \
                 results truncated.",
                findings.len()
            );
            findings.truncate(cap);
        }
    }
}

/// Apply the per-file `--max-findings-per-file` cap, logging the truncation.
fn apply_max_findings_per_file(findings: &mut Vec<Finding>, scanner: &Scanner, path: &str) {
    if let Some(cap) = scanner.config.max_findings_per_file {
        if findings.len() > cap {
            warn!(
                "[scanner] Warning: {} finding(s) in '{}' truncated to \
                 --max-findings-per-file ({cap}).",
                findings.len(),
                sanitize_display(path),
            );
            findings.truncate(cap);
        }
    }
}

/// Read and scan a single file after applying metadata, size, and binary filters.
fn scan_one_file(scanner: &Scanner, path: &str, stats: &StatsAcc) -> Vec<Finding> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        // Could not stat the file: count it as errored (incomplete coverage),
        // not as a silent skip.
        Err(_) => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return vec![];
        }
    };
    // Reject symlinks (incl. git-tracked ones) and non-regular files: a symlink's
    // file_type is not `is_file()`, so this also prevents reads outside the tree.
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return vec![];
    }
    if metadata.len() > scanner.config.max_file_size {
        stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
        return vec![];
    }

    // Bounded owned read (not mmap): a memory-mapped file truncated by another
    // process mid-scan would SIGBUS, which is uncatchable. The `take` bound also
    // closes the TOCTOU window — a file that grew after the metadata check above
    // still cannot be read past `max_file_size`.
    let bytes = match read_bounded(path, scanner.config.max_file_size) {
        Ok(Some(b)) => b,
        // None = grew past the cap between stat and read; count as oversized.
        Ok(None) => {
            stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
            return vec![];
        }
        // Read failed after the stat succeeded (perms, race, I/O): errored, not
        // a clean scan — surface it so coverage is not silently overstated.
        Err(_) => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return vec![];
        }
    };

    // Content-based binary gate (independent of extension).
    if is_binary_skipped(scanner.config.binary_policy, path, &bytes) {
        stats.binary_skipped.fetch_add(1, Ordering::Relaxed);
        return vec![];
    }

    stats.files_scanned.fetch_add(1, Ordering::Relaxed);
    let mut findings = scanner.scan_bytes(path, &bytes);
    apply_max_findings_per_file(&mut findings, scanner, path);
    findings
}

/// Decide whether `bytes` should be skipped as binary under `policy`.
///
/// * `Scan` — never skip.
/// * `Auto` — skip if binary, unless the path is source/secret-bearing.
/// * `Skip` — skip if binary, with no allowlist exception (strictest).
fn is_binary_skipped(policy: BinaryPolicy, path: &str, bytes: &[u8]) -> bool {
    if policy == BinaryPolicy::Scan {
        return false;
    }
    let sniff = &bytes[..bytes.len().min(filters::BINARY_SNIFF_LEN)];
    if !filters::is_probably_binary(sniff) {
        return false;
    }
    match policy {
        BinaryPolicy::Auto => !filters::is_source_allowlisted(path),
        BinaryPolicy::Skip => true,
        BinaryPolicy::Scan => false,
    }
}

/// Bounded read: returns `Ok(None)` if the file exceeds `max` bytes (read with
/// a one-byte overshoot so an over-limit file is detected, not silently cut).
fn read_bounded(path: &str, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let mut reader = file.take(max.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(bytes))
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
            // Basic extension/directory filter
            if !filters::should_scan(path_str) {
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
/// directory walk applies, so `--git` mode does not scan binaries or
/// globally-allowlisted files that the default mode would skip.
fn filter_git_paths(scanner: &Scanner, paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| filters::should_scan(p) && !scanner.engine.is_path_globally_allowlisted(p))
        .collect()
}

/// Collect paths via git commands (`git ls-files` / `git diff --name-only`,
/// plus untracked files when configured).
///
/// Returns `None` if git is unavailable, the directory is not a repository, or
/// a command fails, signalling the caller to fall back to a directory walk.
/// Returns `Some(paths)` (possibly empty) on success.
fn collect_git_paths(root: &str, config: &crate::scanner::ScanConfig) -> Option<Vec<String>> {
    let mut paths = Vec::new();

    // Staged mode is handled separately in `scan_path` (it reads index blobs,
    // not working-tree files), so it never reaches here.
    if config.git_diff {
        // diff against the configured base (e.g. origin/main) or HEAD.
        let range = match &config.diff_base {
            Some(base) => format!("{base}...HEAD"),
            None => "HEAD".to_string(),
        };
        let out = run_git(root, &["diff", "--name-only", "-z", &range])?;
        append_git_paths(root, &out, &mut paths);
    } else {
        let out = run_git(root, &["ls-files", "-z"])?;
        append_git_paths(root, &out, &mut paths);
    }

    // Optionally include untracked-but-not-ignored files.
    if config.include_untracked {
        let out = run_git(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
        append_git_paths(root, &out, &mut paths);
    }

    Some(paths)
}

/// Run a git command rooted at `root` with path-quoting disabled. Returns the
/// raw stdout bytes on success, or `None` (with a warning) on any failure.
fn run_git(root: &str, args: &[&str]) -> Option<Vec<u8>> {
    let mut cmd = Command::new("git");
    // Disable path quoting so non-ASCII / special filenames are emitted
    // verbatim (UTF-8) instead of octal-escaped and double-quoted.
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.args(args);

    match cmd.output() {
        Ok(o) if o.status.success() => Some(o.stdout),
        Ok(_) => {
            warn!("[scanner] Warning: git command failed. Falling back to directory walk.");
            None
        }
        Err(e) => {
            warn!("[scanner] Warning: could not run git: {e}. Falling back to directory walk.");
            None
        }
    }
}

/// Like [`run_git`] but silent on failure: used for per-file index reads where
/// the caller records the file as errored rather than falling back to a walk.
fn run_git_quiet(root: &str, args: &[&str]) -> Option<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.args(args);
    match cmd.output() {
        Ok(o) if o.status.success() => Some(o.stdout),
        _ => None,
    }
}

/// Outcome of a bounded staged-blob read.
pub(super) enum BlobRead {
    /// Blob content, within the size cap.
    Ok(Vec<u8>),
    /// Blob exceeded the cap (detected with a one-byte overshoot).
    Oversized,
    /// git failed, or the blob could not be read.
    Error,
}

/// Read a staged blob (`git cat-file blob <spec>`) with the same bounded-memory
/// posture as [`read_bounded`]: stdout is capped at `max + 1` bytes so a blob that
/// grew past the cap between the `cat-file -s` size check and this read (a TOCTOU
/// window under a concurrent `git add`) is reported as oversized, never loaded in
/// full. The child is killed before `wait` so stopping the read early cannot
/// deadlock against git blocking on a full stdout pipe (a no-op if it already
/// exited, e.g. the normal in-cap case).
pub(super) fn run_git_blob_bounded(root: &str, spec: &str, max: u64) -> BlobRead {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.args(["cat-file", "blob", spec]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return BlobRead::Error,
    };

    let mut bytes = Vec::new();
    let read_result = match child.stdout.take() {
        Some(mut stdout) => stdout
            .by_ref()
            .take(max.saturating_add(1))
            .read_to_end(&mut bytes),
        None => {
            let _ = child.wait();
            return BlobRead::Error;
        }
    };

    // Kill first (no-op if git already exited) so an early-stopped read of an
    // oversized blob cannot leave git blocked on the pipe, then reap.
    let _ = child.kill();
    let status = child.wait();

    match read_result {
        // Oversized is decided by byte count: we deliberately stopped reading, so
        // git's (likely killed) exit status is irrelevant here.
        Ok(_) if bytes.len() as u64 > max => BlobRead::Oversized,
        Ok(_) => match status {
            Ok(s) if s.success() => BlobRead::Ok(bytes),
            _ => BlobRead::Error,
        },
        Err(_) => BlobRead::Error,
    }
}

/// Parse NUL-delimited git output and append resolved, contained paths to `out`.
///
/// Absolute paths from git are dropped: tracked files are always repo-relative,
/// so an absolute path would be a path-containment risk in a hostile repo.
fn append_git_paths(root: &str, stdout: &[u8], out: &mut Vec<String>) {
    let root_canonical = match Path::new(root).canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };

    for path in stdout.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        let path = String::from_utf8_lossy(path);
        let candidate = Path::new(path.as_ref());
        if candidate.is_absolute()
            || candidate
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            warn!(
                "[scanner] Warning: dropping unsafe path from git output: {}",
                sanitize_display(&path)
            );
            continue;
        }
        let trimmed = path.strip_prefix("./").unwrap_or(&path);
        let joined = Path::new(root).join(trimmed);
        match joined.canonicalize() {
            Ok(canonical) if canonical.starts_with(&root_canonical) => {
                out.push(joined.to_string_lossy().to_string());
            }
            Ok(_) => {
                warn!(
                    "[scanner] Warning: dropping path outside scan root from git output: {}",
                    sanitize_display(&path)
                );
            }
            Err(_) => {}
        }
    }
}

// Staged-index (`--staged`) scanning lives in a sibling file; as a child module
// it reuses walk's private helpers via `super::`.
#[path = "walk_staged.rs"]
mod staged;

// Tests live in a sibling file (explicit `#[path]`) to keep walk.rs ≤ 400 lines.
#[cfg(test)]
#[path = "walk_tests.rs"]
mod tests;
