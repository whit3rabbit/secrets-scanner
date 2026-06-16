//! Per-file read, binary gating, and scan helpers for directory walks.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::Ordering;

use crate::filters;
use crate::scanner::{BinaryPolicy, Finding, Scanner};

use super::StatsAcc;

/// Read and scan a single file after applying metadata, size, and binary filters.
pub(super) fn scan_one_file(scanner: &Scanner, path: &Path, stats: &StatsAcc) -> Vec<Finding> {
    let display_path = path.to_string_lossy();
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
    // closes the TOCTOU window if a file grows after the metadata check above.
    let bytes = match read_bounded(path, scanner.config.max_file_size, metadata.len()) {
        Ok(Some(b)) => b,
        Ok(None) => {
            stats.oversized_skipped.fetch_add(1, Ordering::Relaxed);
            return vec![];
        }
        Err(_) => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            return vec![];
        }
    };

    if is_binary_skipped(scanner.config.binary_policy, &display_path, &bytes) {
        stats.binary_skipped.fetch_add(1, Ordering::Relaxed);
        return vec![];
    }

    stats.files_scanned.fetch_add(1, Ordering::Relaxed);
    let result = scanner.scan_bytes_detailed(&display_path, &bytes);
    if result.findings_truncated {
        stats.findings_truncated.store(true, Ordering::Relaxed);
    }
    result.findings
}

/// Decide whether `bytes` should be skipped as binary under `policy`.
pub(super) fn is_binary_skipped(policy: BinaryPolicy, path: &str, bytes: &[u8]) -> bool {
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

/// Bounded read: returns `Ok(None)` if the file exceeds `max` bytes.
pub(super) fn read_bounded(
    path: &Path,
    max: u64,
    expected_len: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    // Clamp the prealloc hint: `expected_len` comes from (attacker-influenceable)
    // file metadata, so with an absurdly high `max` a bogus length could drive a
    // huge `with_capacity` before the bounded read rejects the file. The `take`
    // below still bounds the actual bytes, so capping the hint only avoids the
    // up-front over-allocation; it never changes what is read.
    const READ_CAPACITY_HINT_MAX: u64 = 8 * 1024 * 1024;
    let file = open_no_follow(path)?;
    let mut reader = file.take(max.saturating_add(1));
    let cap = expected_len
        .saturating_add(1)
        .min(max.saturating_add(1))
        .min(READ_CAPACITY_HINT_MAX);
    let mut bytes = Vec::with_capacity(usize::try_from(cap).unwrap_or(usize::MAX));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure_regular_file_descriptor(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn ensure_regular_file_descriptor(file: &std::fs::File, path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Descriptor metadata closes the race between pre-open `symlink_metadata`
    // and the actual object now being read.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to read non-regular file: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}
