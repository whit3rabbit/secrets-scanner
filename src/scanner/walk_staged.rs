//! scanner/walk_staged.rs — `--staged` mode: scan the git index, not the tree.
//!
//! For pre-commit hooks the bytes that matter are the ones staged in the index,
//! which can differ from the working tree (`git add -p`, or staging then editing
//! the file). Reading working-tree files would miss a staged secret (or falsely
//! flag an unstaged one), so this module reads each staged blob via
//! `git cat-file` and scans those bytes.
//!
//! It is a child module of `walk`, so it reuses walk's private helpers
//! (`run_git`, `run_git_blob_bounded`, `is_binary_skipped`, `StatsAcc`) through
//! `super::`.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::Ordering;

use log::warn;

use crate::safe_display::sanitize_display;
use crate::scanner::{Finding, Scanner};

use super::{
    is_binary_skipped, is_unsafe_rel_path, run_git, run_git_blob_bounded, should_collect_path,
    BlobRead, StatsAcc,
};

/// A staged file: the `git cat-file` pathspec (`:./<path>`, kept as `OsString`
/// so a non-UTF-8 path reaches git byte-exact instead of being mangled by a
/// lossy conversion) and the joined display path used as the finding's `file`
/// (matching other git modes, so SARIF relativization is consistent).
pub(super) struct StagedEntry {
    spec: OsString,
    display: String,
}

pub(super) fn sort_entries(entries: &mut [StagedEntry]) {
    entries.sort_unstable_by(|a, b| a.display.cmp(&b.display));
}

/// Convert raw git path bytes to an `OsString` without loss on Unix (where
/// pathnames are arbitrary bytes); fall back to a lossy conversion elsewhere.
#[cfg(unix)]
fn bytes_to_os(b: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStrExt;
    OsStr::from_bytes(b).to_os_string()
}
#[cfg(not(unix))]
fn bytes_to_os(b: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(b).into_owned())
}

/// Run `git cat-file <flag> <spec>` for index metadata, passing the pathspec as
/// raw `OsStr` so non-UTF-8 paths are byte-exact. Returns stdout on success.
fn cat_file_meta(root: &str, flag: &str, spec: &OsStr) -> Option<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.arg("cat-file").arg(flag).arg(spec);
    match cmd.output() {
        Ok(o) if o.status.success() => Some(o.stdout),
        _ => None,
    }
}

/// Collect staged (index) paths, applying the same extension/allowlist filters
/// as other modes. Returns `None` when git is unavailable so the caller can
/// decide between fail-closed and a directory-walk fallback.
///
/// `--diff-filter=ACMRT` selects added/copied/modified/renamed/type-changed
/// entries and excludes deletions (`D`): a deleted path has no staged blob to
/// scan. Type-changes (`T`) are included but each staged object is verified to
/// be a blob in [`scan_one_staged`] (a `T` change can stage a gitlink or tree,
/// which has no scannable content).
pub(super) fn collect_staged_paths(scanner: &Scanner, root: &str) -> Option<Vec<StagedEntry>> {
    let out = run_git(
        root,
        &[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMRT",
        ],
    )?;

    let mut entries = Vec::new();
    for rel in out.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        if let Some(entry) = make_staged_entry(scanner, root, rel) {
            entries.push(entry);
        }
    }
    Some(entries)
}

/// Build a [`StagedEntry`] from raw git path bytes, applying lexical containment
/// and the extension/allowlist filters. Returns `None` to drop the path.
fn make_staged_entry(scanner: &Scanner, root: &str, rel_bytes: &[u8]) -> Option<StagedEntry> {
    let rel_os_full = bytes_to_os(rel_bytes);
    let candidate = Path::new(&rel_os_full);
    // Lexical containment: index paths are always repo-relative; reject
    // absolute / parent-escaping paths defensively (git resolves the `:./path`
    // pathspec inside the repo, so this is belt-and-suspenders).
    if is_unsafe_rel_path(candidate) {
        warn!(
            "[scanner] Warning: dropping unsafe staged path: {}",
            sanitize_display(&rel_os_full.to_string_lossy())
        );
        return None;
    }

    let rel_bytes = rel_bytes.strip_prefix(b"./").unwrap_or(rel_bytes);
    let rel_os = bytes_to_os(rel_bytes);
    let rel_lossy = rel_os.to_string_lossy();
    if !should_collect_path(scanner, &rel_lossy)
        || scanner.engine.is_path_globally_allowlisted(&rel_lossy)
    {
        return None;
    }

    // Pathspec `:./<path>` with the raw path bytes appended verbatim.
    let mut spec = OsString::from(":./");
    spec.push(&rel_os);
    let display = Path::new(root).join(&rel_os).to_string_lossy().into_owned();
    Some(StagedEntry { spec, display })
}

/// Read one staged blob and scan it. The object type is verified to be a blob
/// (type-changes may stage a gitlink/tree) and the blob size is checked with
/// `cat-file -s` before the content is read, preserving the bounded-read
/// posture: an oversized staged blob is recorded as oversized and never loaded.
pub(super) fn scan_one_staged(
    scanner: &Scanner,
    root: &str,
    entry: &StagedEntry,
    stats: &StatsAcc,
) -> Vec<Finding> {
    // Verify the staged object is a blob. A type-change (`T`) can stage a
    // gitlink (`commit`) or tree, which has no scannable content; skip those
    // without inflating the errored count. A missing object (`-t` fails) is a
    // coverage gap, so count it as errored.
    match cat_file_meta(root, "-t", &entry.spec).and_then(|o| String::from_utf8(o).ok()) {
        Some(t) if t.trim() == "blob" => {}
        Some(_) => return Vec::new(),
        None => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
    }

    let size = cat_file_meta(root, "-s", &entry.spec)
        .and_then(|out| String::from_utf8(out).ok())
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
    let bytes = match run_git_blob_bounded(root, &entry.spec, scanner.config.max_file_size) {
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
    // `scan_bytes_detailed` already enforces `max_findings_per_file` (and logs
    // the truncation), so no second cap pass is needed here.
    let result = scanner.scan_bytes_detailed(&entry.display, &bytes);
    if result.findings_truncated {
        stats.findings_truncated.store(true, Ordering::Relaxed);
    }
    result.findings
}
