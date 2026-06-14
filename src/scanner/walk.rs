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
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

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
}

impl StatsAcc {
    fn snapshot(&self) -> ScanStats {
        ScanStats {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            binary_skipped: self.binary_skipped.load(Ordering::Relaxed),
            oversized_skipped: self.oversized_skipped.load(Ordering::Relaxed),
            files_over_cap: self.files_over_cap.load(Ordering::Relaxed),
        }
    }
}

/// Walk a path, filter files, and scan them in parallel using Rayon.
///
/// Returns the findings plus file-level [`ScanStats`].
pub fn scan_path(scanner: &Scanner, root: &str) -> (Vec<Finding>, ScanStats) {
    let stats = StatsAcc::default();

    let mut paths = if scanner.config.git || scanner.config.git_diff {
        match collect_git_paths(root, &scanner.config) {
            Some(git_paths) => filter_git_paths(scanner, git_paths),
            // Git failed (not a repo, git missing, file path arg, …) — fall back
            // to the directory walk rather than silently scanning nothing.
            None => collect_walkdir_paths(scanner, root, &stats),
        }
    } else {
        collect_walkdir_paths(scanner, root, &stats)
    };

    // Cap the number of files scanned. Record the drop so the summary cannot
    // read as full coverage when results were truncated.
    if let Some(cap) = scanner.config.max_files {
        if paths.len() > cap {
            let dropped = paths.len() - cap;
            stats.files_over_cap.store(dropped, Ordering::Relaxed);
            eprintln!(
                "[scanner] Warning: file count ({}) exceeds --max-files ({cap}); \
                 {dropped} file(s) not scanned.",
                paths.len()
            );
            paths.truncate(cap);
        }
    }

    let mut findings: Vec<Finding> = paths
        .par_iter()
        .flat_map(|path| scan_one_file(scanner, path, &stats))
        .collect();

    // Global findings cap for library callers. Truncation is logged so it is
    // never mistaken for complete coverage.
    if let Some(cap) = scanner.config.max_findings {
        if findings.len() > cap {
            eprintln!(
                "[scanner] Warning: finding count ({}) exceeds --max-findings ({cap}); \
                 results truncated.",
                findings.len()
            );
            findings.truncate(cap);
        }
    }

    (findings, stats.snapshot())
}

/// Read and scan a single file after applying metadata, size, and binary filters.
fn scan_one_file(scanner: &Scanner, path: &str, stats: &StatsAcc) -> Vec<Finding> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return vec![],
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
        Err(_) => return vec![],
    };

    // Content-based binary gate (independent of extension).
    if is_binary_skipped(scanner.config.binary_policy, path, &bytes) {
        stats.binary_skipped.fetch_add(1, Ordering::Relaxed);
        return vec![];
    }

    stats.files_scanned.fetch_add(1, Ordering::Relaxed);
    let mut findings = scanner.scan_bytes(path, &bytes);

    // Per-file findings cap. Truncation is logged so it is never silent.
    if let Some(cap) = scanner.config.max_findings_per_file {
        if findings.len() > cap {
            let safe_path = sanitize_display(path);
            eprintln!(
                "[scanner] Warning: {} finding(s) in '{}' truncated to \
                 --max-findings-per-file ({cap}).",
                findings.len(),
                safe_path,
            );
            findings.truncate(cap);
        }
    }
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
        .filter_map(|e| e.ok())
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
            eprintln!("[scanner] Warning: git command failed. Falling back to directory walk.");
            None
        }
        Err(e) => {
            eprintln!("[scanner] Warning: could not run git: {e}. Falling back to directory walk.");
            None
        }
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
            eprintln!(
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
                eprintln!(
                    "[scanner] Warning: dropping path outside scan root from git output: {}",
                    sanitize_display(&path)
                );
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::append_git_paths;

    #[test]
    fn append_git_paths_rejects_parent_dir_components() {
        let dir = tempfile::tempdir().expect("dir");
        let safe = dir.path().join("safe.txt");
        std::fs::write(&safe, "clean").expect("write safe");
        let outside = dir.path().parent().expect("parent").join("outside.txt");
        std::fs::write(&outside, "SECRET123456").expect("write outside");

        let mut paths = Vec::new();
        append_git_paths(
            dir.path().to_str().expect("root"),
            b"safe.txt\0../outside.txt\0",
            &mut paths,
        );

        assert_eq!(paths.len(), 1, "safe git path should be kept");
        assert!(paths[0].ends_with("safe.txt"));
        assert!(
            paths.iter().all(|path| !path.contains("outside.txt")),
            "git paths containing parent components must be dropped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_git_paths_rejects_intermediate_symlink_escape() {
        let dir = tempfile::tempdir().expect("dir");
        let outside_dir = tempfile::tempdir().expect("outside");
        let outside_file = outside_dir.path().join("secret.txt");
        std::fs::write(&outside_file, "SECRET123456").expect("write outside");
        std::os::unix::fs::symlink(outside_dir.path(), dir.path().join("link")).expect("symlink");

        let mut paths = Vec::new();
        append_git_paths(
            dir.path().to_str().expect("root"),
            b"link/secret.txt\0",
            &mut paths,
        );

        assert!(
            paths.is_empty(),
            "git paths resolving outside the root through symlink directories must be dropped"
        );
    }
}
