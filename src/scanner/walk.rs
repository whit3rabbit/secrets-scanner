//! scanner/walk.rs — Directory walking and path filtering.
//!
//! Two path-discovery modes:
//! * Default — uses `walkdir` recursively.
//! * Git mode — uses `git ls-files` or `git diff --name-only` for git-aware scanning.
//!   On any git failure it falls back to the recursive directory walk.

use std::process::Command;

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::filters;
use crate::scanner::{Finding, Scanner};

/// Walk a path, filter files, and scan them in parallel using Rayon.
pub fn scan_path(scanner: &Scanner, root: &str) -> Vec<Finding> {
    let paths = if scanner.config.git || scanner.config.git_diff {
        match collect_git_paths(root, scanner.config.git_diff) {
            Some(git_paths) => filter_git_paths(scanner, git_paths),
            // Git failed (not a repo, git missing, file path arg, …) — fall back
            // to the directory walk rather than silently scanning nothing.
            None => collect_walkdir_paths(scanner, root),
        }
    } else {
        collect_walkdir_paths(scanner, root)
    };

    // Scan in parallel
    paths
        .par_iter()
        .flat_map(|path| scan_one_file(scanner, path))
        .collect()
}

/// Read and scan a single file after applying metadata-based filters.
fn scan_one_file(scanner: &Scanner, path: &str) -> Vec<Finding> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return vec![],
    };
    // Skip empty files and oversized files (the size filter is also applied in
    // collect_walkdir_paths, but git-collected paths are only checked here).
    if metadata.len() == 0 || metadata.len() > scanner.config.max_file_size {
        return vec![];
    }

    // Owned read (not mmap): a memory-mapped file truncated by another process
    // mid-scan would SIGBUS, which is uncatchable. An owned read is immune.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    scanner.scan_bytes(path, &bytes)
}

/// Collect paths via recursive directory walk, applying filters.
fn collect_walkdir_paths(scanner: &Scanner, root: &str) -> Vec<String> {
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
            // Size filter
            if let Ok(meta) = e.metadata() {
                if meta.len() > scanner.config.max_file_size {
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

/// Collect paths via git commands (`git ls-files` or `git diff --name-only`).
///
/// Returns `None` if git is unavailable, the directory is not a repository, or
/// the command otherwise fails, signalling the caller to fall back to a
/// directory walk. Returns `Some(paths)` (possibly empty) on success.
fn collect_git_paths(root: &str, diff: bool) -> Option<Vec<String>> {
    let mut cmd = Command::new("git");
    // Disable path quoting so non-ASCII / special filenames are emitted
    // verbatim (UTF-8) instead of octal-escaped and double-quoted.
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    if diff {
        cmd.arg("diff").arg("--name-only").arg("HEAD");
    } else {
        cmd.arg("ls-files");
    }

    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        Ok(_) => {
            eprintln!("[scanner] Warning: git command failed. Falling back to directory walk.");
            return None;
        }
        Err(e) => {
            eprintln!("[scanner] Warning: could not run git: {e}. Falling back to directory walk.");
            return None;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let paths = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            // Resolve relative git paths against the scan root
            if std::path::Path::new(l).is_absolute() {
                l.to_string()
            } else {
                let trimmed = l.strip_prefix("./").unwrap_or(l);
                format!("{}/{}", root.trim_end_matches('/'), trimmed)
            }
        })
        .collect();
    Some(paths)
}
