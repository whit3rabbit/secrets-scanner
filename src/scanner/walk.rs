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

use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use log::warn;
use walkdir::WalkDir;

use crate::filters;
use crate::safe_display::sanitize_display;
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
            staged::sort_entries(&mut entries);
            apply_max_files(&mut entries, scanner, &stats);
            let mut findings = scan_staged_entries(scanner, root, &entries, &stats);
            sort_findings(&mut findings);
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

    paths.sort_unstable();
    apply_max_files(&mut paths, scanner, &stats);

    let mut findings = scan_file_paths(scanner, &paths, &stats);
    sort_findings(&mut findings);

    (findings, stats.snapshot())
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
/// directory walk applies, so `--git` mode does not scan binaries or
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
            Some(base) => format!("{}...HEAD", resolve_diff_base(root, base)?),
            None => "HEAD".to_string(),
        };
        let out = run_git(root, &["diff", "--name-only", "-z", &range, "--"])?;
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

fn resolve_diff_base(root: &str, base: &str) -> Option<String> {
    let base = base.trim();
    if base.is_empty() || base.starts_with('-') {
        warn!(
            "[scanner] Warning: invalid --diff-base '{}'. Falling back to directory walk.",
            sanitize_display(base)
        );
        return None;
    }

    let rev = format!("{base}^{{commit}}");
    let out = run_git_quiet(
        root,
        &["rev-parse", "--verify", "--quiet", "--end-of-options", &rev],
    );
    let resolved = out
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
        .filter(|commit| !commit.is_empty());
    match resolved {
        Some(commit) => Some(commit.to_string()),
        None => {
            warn!(
                "[scanner] Warning: --diff-base '{}' did not resolve to a commit. Falling back to directory walk.",
                sanitize_display(base)
            );
            None
        }
    }
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
