use std::io::{self, Write};

use log::{error, info, warn};
use secrets_scanner::{Finding, ScanConfig, ScanStats, Scanner};

use super::args::{GitFallbackArg, OutputFormat, ScanArgs};

#[path = "scan_baseline.rs"]
mod baseline;

/// Whether to run in changed-files mode. `--base` implies it: clap does not
/// auto-imply, so a base ref passed alone must still scan `<base>...HEAD` rather
/// than silently falling back to a full directory walk.
pub(super) fn resolve_changed_files(args: &ScanArgs) -> bool {
    args.changed_files || args.base.is_some()
}

/// Handle the `scan` subcommand.
pub(super) fn handle(args: ScanArgs) {
    let changed_files = resolve_changed_files(&args);
    let early_max_findings = if args.generate_baseline.is_none()
        && args.baseline.is_none()
        && args.ignore_rules.is_empty()
    {
        args.max_findings
    } else {
        None
    };
    let config = ScanConfig {
        redact: !args.no_redact,
        capture_context: !args.no_context && !matches!(args.format, OutputFormat::Sarif),
        min_entropy_override: args.min_entropy,
        max_file_size: args.max_file_size,
        git_tracked: args.git_tracked,
        changed_files,
        base: args.base.clone(),
        git_history: args.git_history,
        history_all: args.all,
        // History mode always uses --full-history (gitleaks-like full traversal).
        // It is intentionally NOT coupled to --log-opts: narrowing traversal via
        // --log-opts must never also silently drop --full-history and reduce
        // coverage (a missed-secret hazard in a security tool).
        history_full: args.git_history || args.full_history,
        history_log_opts: args.log_opts.clone(),
        history_timeout_secs: args.history_timeout,
        git_staged: args.staged,
        include_untracked: args.include_untracked,
        git_fallback_walk: matches!(args.git_fallback, Some(GitFallbackArg::Walk)),
        binary_policy: args.binary_policy.into(),
        max_files: args.max_files,
        max_findings: early_max_findings,
        max_findings_per_file: args.max_findings_per_file,
        honor_allow_markers: true,
        redaction_mode: args.redaction.into(),
        max_matched_len: None,
    };

    let scanner = if let Some(ref rules_path) = args.rules {
        match Scanner::from_file(rules_path) {
            Ok(s) => s.with_config(config),
            Err(e) => {
                error!("Failed to load rules from {rules_path}: {e}");
                std::process::exit(3);
            }
        }
    } else {
        match Scanner::new() {
            Ok(s) => s.with_config(config),
            Err(e) => {
                error!("Failed to load rules: {e}");
                std::process::exit(3);
            }
        }
    };

    info!(
        "[scanner] Loaded {} rules ({} keywords)",
        scanner.engine().rule_count(),
        scanner.engine().keyword_count(),
    );

    let start = std::time::Instant::now();
    let mut all_findings = Vec::new();
    let mut stats = ScanStats::default();
    let mut findings_truncated = false;

    for (idx, path) in args.paths.iter().enumerate() {
        let (mut findings, s) = scanner.scan_path_with_stats(path);
        stats.files_scanned += s.files_scanned;
        stats.binary_skipped += s.binary_skipped;
        stats.oversized_skipped += s.oversized_skipped;
        stats.files_over_cap += s.files_over_cap;
        stats.errored += s.errored;
        stats.git_fallback |= s.git_fallback;
        stats.git_failed |= s.git_failed;
        // Per-file/per-path truncation (e.g. `--max-findings-per-file`, or the
        // history wall-clock budget) is otherwise invisible unless the CLI-level
        // `--max-findings` also fires. Fold it into both the aggregate stat and
        // the local that drives the summary suffix.
        stats.findings_truncated |= s.findings_truncated;
        findings_truncated |= s.findings_truncated;
        if !args.ignore_rules.is_empty() {
            findings.retain(|f| !args.ignore_rules.contains(&f.rule_id));
        }

        if let Some(cap) = early_max_findings {
            let remaining = cap.saturating_sub(all_findings.len());
            if remaining == 0 {
                findings_truncated = true;
                break;
            }
            if findings.len() > remaining {
                findings.truncate(remaining);
                findings_truncated = true;
            }
        }
        all_findings.extend(findings);

        if let Some(cap) = early_max_findings {
            if all_findings.len() >= cap {
                if idx + 1 < args.paths.len() {
                    findings_truncated = true;
                    info!(
                        "[scanner] Reached --max-findings ({cap}); remaining input paths were not scanned."
                    );
                }
                break;
            }
        }
    }

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    let base = if args.paths.len() == 1 {
        args.paths.first().map(String::as_str).unwrap_or(".")
    } else {
        cwd.as_str()
    };
    let show_context = !args.no_context;

    // Fail closed: an explicit git mode could not run for one or more paths and
    // the caller did not opt into `--git-fallback=walk`. Coverage is incomplete,
    // so exit 2 (takes precedence over the findings exit and ignores `--no-fail`,
    // which only governs the findings-present case, not a scan that could not
    // run). When some paths DID succeed and produced findings — a multi-path run
    // where only one path is a non-repo — those real findings are still written
    // first so a secret found in a healthy repo is not discarded behind the
    // generic git error. A baseline is never written from an incomplete scan, and
    // when nothing was found there is nothing to write and we must not emit a
    // clean-looking empty artifact (preserving the fail-closed posture for the
    // single-path / all-failed case).
    if stats.git_failed {
        error!(
            "[scanner] git mode failed for one or more paths and --git-fallback=walk \
             was not set; failing closed (exit 2): coverage is incomplete."
        );
        if !all_findings.is_empty() {
            if let Some(ref baseline_path) = args.baseline {
                baseline::apply_baseline_or_exit(baseline_path, &mut all_findings);
            }
            if !all_findings.is_empty() {
                if let Err(e) = write_output(&args, &all_findings, base, show_context) {
                    error!("Failed to write output: {e}");
                }
            }
        }
        std::process::exit(2);
    }

    if let Some(ref out_path) = args.generate_baseline {
        baseline::write_baseline_or_exit(out_path, &all_findings);
        return;
    }

    if let Some(ref baseline_path) = args.baseline {
        baseline::apply_baseline_or_exit(baseline_path, &mut all_findings);
    }

    if early_max_findings.is_none() {
        if let Some(cap) = args.max_findings {
            if all_findings.len() > cap {
                info!(
                    "[scanner] Findings ({}) exceed --max-findings ({cap}); results truncated.",
                    all_findings.len()
                );
                all_findings.truncate(cap);
                findings_truncated = true;
            }
        }
    }

    let elapsed = start.elapsed();

    #[cfg(feature = "bench")]
    {
        let unkeyworded_time = std::time::Duration::from_nanos(scanner.unkeyworded_scan_time_ns());
        if unkeyworded_time.as_nanos() > 0 {
            info!(
                "[scanner] Unkeyworded regex rules evaluation time: {:.2?}",
                unkeyworded_time
            );
        }
    }

    if let Err(e) = write_output(&args, &all_findings, base, show_context) {
        error!("Failed to write output: {e}");
        std::process::exit(2);
    }

    info!(
        "[scanner] Scanned {} path(s) in {:.2?} — {} file(s), {} finding(s); \
         skipped {} binary, {} oversized; {} unreadable; {} over file-cap{}",
        args.paths.len(),
        elapsed,
        stats.files_scanned,
        all_findings.len(),
        stats.binary_skipped,
        stats.oversized_skipped,
        stats.errored,
        stats.files_over_cap,
        if findings_truncated {
            " (findings truncated)"
        } else {
            ""
        },
    );
    if stats.git_fallback {
        warn!(
            "[scanner] git path discovery failed for one or more paths; scanned the \
             working tree instead (scope may include untracked/ignored files)."
        );
    }

    // Fail on incomplete coverage when requested. Exit 2 (coverage/runtime) takes
    // precedence over the findings exit 1, and is independent of `--no-fail`
    // (which governs only the findings-present case). Output is already written so
    // a SARIF upload still happens. `--generate-baseline` returned earlier, so
    // this never blocks baseline generation.
    if args.error_on_unreadable && stats.errored > 0 {
        error!(
            "[scanner] {} file(s) could not be read; failing on incomplete coverage \
             (--error-on-unreadable).",
            stats.errored
        );
        std::process::exit(2);
    }

    // Same incomplete-coverage posture for policy-skipped files. A binary- or
    // size-skipped file is "not scanned", not "scanned clean"; a strict caller
    // can opt into failing on that gap. Exit 2 takes precedence over the findings
    // exit 1, like --error-on-unreadable.
    if args.error_on_skipped && (stats.binary_skipped + stats.oversized_skipped) > 0 {
        error!(
            "[scanner] {} file(s) skipped by policy ({} binary, {} oversized); failing \
             on incomplete coverage (--error-on-skipped).",
            stats.binary_skipped + stats.oversized_skipped,
            stats.binary_skipped,
            stats.oversized_skipped,
        );
        std::process::exit(2);
    }

    if !all_findings.is_empty() && !args.no_fail {
        std::process::exit(1);
    }
}

/// Write findings in the requested format to a file (`--output`) or stdout.
fn write_output(
    args: &ScanArgs,
    findings: &[Finding],
    base: &str,
    show_context: bool,
) -> io::Result<()> {
    match &args.output {
        Some(path) => {
            let mut f = create_private_file(path)?;
            dispatch_format(&mut f, args.format, findings, base, show_context)
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            dispatch_format(&mut lock, args.format, findings, base, show_context)
        }
    }
}

/// Create or truncate a file intended to hold scanner output.
///
/// On Unix, force owner-only (0600) permissions because JSON/text output may
/// contain raw secrets when `--no-redact` is used. To match the read-side
/// hardening, the open is `O_NOFOLLOW` (so an attacker-planted symlink at the
/// output path is not followed — `open` fails with `ELOOP`) and `O_CLOEXEC`, and
/// the opened descriptor is verified to be a regular file (rejecting a
/// pre-existing fifo/device/dir that we would otherwise truncate/chmod). On
/// non-Unix platforms no permission restriction is applied (the file inherits the
/// default ACL), so secret-bearing output there relies on the caller's directory
/// permissions; generated baselines are redacted regardless for this reason.
fn create_private_file(path: &str) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        // O_NOFOLLOW: refuse to follow a symlink at the final path component, so a
        // hostile checkout cannot redirect our truncating write to another file.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        // Reject a non-regular target (fifo/device/dir): O_NOFOLLOW stops a
        // symlink, this stops the other types we should never truncate or chmod.
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to write output to non-regular file: {path}"),
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

/// Write scanner-owned output with private file permissions where supported.
fn write_private_file(path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)
}

/// Dispatch to the format writer matching `format`.
fn dispatch_format(
    w: &mut dyn Write,
    format: OutputFormat,
    findings: &[Finding],
    base: &str,
    show_context: bool,
) -> io::Result<()> {
    match format {
        OutputFormat::Text => crate::format::write_text(w, findings, show_context),
        OutputFormat::Json => crate::format::write_json(w, findings, show_context),
        OutputFormat::Jsonl => crate::format::write_jsonl(w, findings, show_context),
        OutputFormat::Sarif => crate::format::write_sarif(w, findings, base),
    }
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
