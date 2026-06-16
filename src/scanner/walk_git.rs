use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

use log::warn;

use crate::safe_display::sanitize_display;
use crate::scanner::ScanConfig;

/// Outcome of a bounded staged-blob read.
pub(crate) enum BlobRead {
    /// Blob content, within the size cap.
    Ok(Vec<u8>),
    /// Blob exceeded the cap (detected with a one-byte overshoot).
    Oversized,
    /// git failed, or the blob could not be read.
    Error,
}

/// Collect paths via git commands (`git ls-files` / `git diff --name-only`,
/// plus untracked files when configured).
///
/// Returns `None` if git is unavailable, the directory is not a repository, or
/// a command fails, signalling the caller to fall back to a directory walk.
/// Returns `Some(paths)` (possibly empty) on success.
pub(crate) fn collect_git_paths(root: &str, config: &ScanConfig) -> Option<Vec<String>> {
    let mut paths = Vec::new();

    // Staged mode is handled separately in `scan_path` (it reads index blobs,
    // not working-tree files), so it never reaches here.
    if config.changed_files {
        // diff against the configured base (e.g. origin/main) or HEAD.
        let range = match &config.base {
            Some(base) => format!("{}...HEAD", resolve_base(root, base)?),
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

fn resolve_base(root: &str, base: &str) -> Option<String> {
    let base = base.trim();
    if base.is_empty() || base.starts_with('-') {
        warn!(
            "[scanner] Warning: invalid --base '{}'.",
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
                "[scanner] Warning: --base '{}' did not resolve to a commit.",
                sanitize_display(base)
            );
            None
        }
    }
}

/// Run a git command rooted at `root` with path-quoting disabled. Returns the
/// raw stdout bytes on success, or `None` (with a warning) on any failure.
pub(crate) fn run_git(root: &str, args: &[&str]) -> Option<Vec<u8>> {
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

/// Read a staged blob (`git cat-file blob <spec>`) with the same bounded-memory
/// posture as [`read_bounded`]: stdout is capped at `max + 1` bytes so a blob that
/// grew past the cap between the `cat-file -s` size check and this read (a TOCTOU
/// window under a concurrent `git add`) is reported as oversized, never loaded in
/// full. The child is killed **only on the oversized path**, where we stopped
/// reading early and git may be blocked writing to a full stdout pipe. On the
/// in-cap path the read reached EOF because git already closed stdout as it exits;
/// killing there would race git's own exit and could mark a correctly-read blob as
/// a signal death (`status.success() == false`), turning a clean read into a
/// spurious `BlobRead::Error` (a phantom coverage gap in staged mode).
pub(crate) fn run_git_blob_bounded(root: &str, spec: &std::ffi::OsStr, max: u64) -> BlobRead {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.quotePath=false");
    cmd.arg("-C").arg(root);
    cmd.arg("cat-file").arg("blob").arg(spec);
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

    // Kill ONLY when we stopped reading early (oversized): there git may still be
    // blocked writing to the now-full pipe and would never exit on its own. On the
    // in-cap path the read already hit EOF (git closed stdout as it exits), so a
    // kill would only race git's exit and risk a spurious signal-death status.
    let oversized = bytes.len() as u64 > max;
    if oversized {
        let _ = child.kill();
    }
    let status = child.wait();

    match read_result {
        // Oversized is decided by byte count: we deliberately stopped reading, so
        // git's (killed) exit status is irrelevant here.
        Ok(_) if oversized => BlobRead::Oversized,
        Ok(_) => match status {
            Ok(s) if s.success() => BlobRead::Ok(bytes),
            _ => BlobRead::Error,
        },
        Err(_) => BlobRead::Error,
    }
}

/// Lexical containment check for a repo-relative path emitted by git: returns
/// `true` when the path is absolute or contains a `..` component, either of which
/// is a containment risk in a hostile repository.
///
/// Shared by every git mode so the guard lives in one place: callers that open
/// the file (`append_git_paths`) additionally canonicalize and verify the result
/// stays under the scan root, while index- and patch-content readers
/// (`walk_staged`, `walk_history`), which never open the file, rely on this
/// lexical check alone.
pub(crate) fn is_unsafe_rel_path(candidate: &Path) -> bool {
    candidate.is_absolute()
        || candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

/// Parse NUL-delimited git output and append resolved, contained paths to `out`.
///
/// Absolute paths from git are dropped: tracked files are always repo-relative,
/// so an absolute path would be a path-containment risk in a hostile repo.
pub(crate) fn append_git_paths(root: &str, stdout: &[u8], out: &mut Vec<String>) {
    let root_canonical = match Path::new(root).canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };

    for path in stdout.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        let path = String::from_utf8_lossy(path);
        let candidate = Path::new(path.as_ref());
        if is_unsafe_rel_path(candidate) {
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
