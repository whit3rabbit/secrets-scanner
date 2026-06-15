use std::collections::HashSet;
use std::io::{self, Write};

use log::{error, info, warn};
use secrets_scanner::{Finding, ScanConfig, ScanStats, Scanner};

use super::args::{GitFallbackArg, OutputFormat, ScanArgs};

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

    // Fail closed: an explicit git mode could not run and the caller did not opt
    // into `--git-fallback=walk`, so nothing was scanned. Exit 2 (runtime error)
    // before writing any normal output or baseline that could be mistaken for a
    // clean scan. This takes precedence over the findings exit and ignores
    // `--no-fail` (which only governs the findings-present case, not a scan that
    // never happened).
    if stats.git_failed {
        error!(
            "[scanner] git mode failed and --git-fallback=walk was not set; \
             refusing to silently scan the working tree (nothing was scanned)."
        );
        std::process::exit(2);
    }

    if let Some(ref out_path) = args.generate_baseline {
        write_baseline_or_exit(out_path, args.no_redact, &all_findings);
        return;
    }

    if let Some(ref baseline_path) = args.baseline {
        apply_baseline_or_exit(baseline_path, &mut all_findings);
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

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    let base = if args.paths.len() == 1 {
        args.paths.first().map(String::as_str).unwrap_or(".")
    } else {
        cwd.as_str()
    };
    let show_context = !args.no_context;
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

    if !all_findings.is_empty() && !args.no_fail {
        std::process::exit(1);
    }
}

/// Build the findings to serialize into a `--generate-baseline` file.
///
/// Strips `context_lines` from every finding (baselines suppress on
/// `fingerprint`, or the legacy (file,line,rule) tuple, never on context) and
/// force-redacts `matched` under `--no-redact`. Both guard the same hazard: a
/// committed/uploaded baseline must never carry raw secret material. Under
/// `--no-redact`, `scan_bytes` redacts neither `matched` nor the context, so
/// without this the surrounding source (including the secret) would leak.
fn baseline_findings(no_redact: bool, all_findings: &[Finding]) -> Vec<Finding> {
    all_findings
        .iter()
        .map(|f| {
            let mut f = f.clone();
            f.context_lines = Vec::new();
            if no_redact {
                f.matched = secrets_scanner::filters::redact(&f.matched);
            }
            f
        })
        .collect()
}

fn write_baseline_or_exit(out_path: &str, no_redact: bool, all_findings: &[Finding]) {
    let baseline_findings = baseline_findings(no_redact, all_findings);
    match serde_json::to_string_pretty(&baseline_findings) {
        Ok(json) => {
            if let Err(e) = write_private_file(out_path, json.as_bytes()) {
                error!("Failed to write baseline '{out_path}': {e}");
                std::process::exit(2);
            }
            info!(
                "[scanner] Wrote baseline with {} finding(s) to {out_path}",
                all_findings.len()
            );
        }
        Err(e) => {
            error!("Failed to serialize baseline: {e}");
            std::process::exit(2);
        }
    }
}

/// Suppress findings present in `baseline` from `all_findings`, returning the
/// number suppressed.
///
/// Baseline entries are matched by fingerprint scheme: a `sha256:`- or
/// `hmac-sha256:`-prefixed fingerprint (the current unkeyed/keyed schemes)
/// suppresses by exact fingerprint, which is line-tolerant. Anything else — an
/// empty fingerprint, or a legacy FNV hex fingerprint written by an older build
/// — falls back to the `(file, line, rule)` tuple. Without the prefix check a
/// legacy FNV fingerprint would land in the fingerprint set, never equal a new
/// value, and silently re-surface every previously-suppressed finding. Old
/// baselines suppress by exact location until regenerated. A keyed baseline only
/// matches when scanning with the same `SECRETS_SCANNER_FINGERPRINT_KEY`.
fn suppress_baseline(baseline: Vec<Finding>, all_findings: &mut Vec<Finding>) -> usize {
    let mut known_fps: HashSet<String> = HashSet::new();
    let mut known_legacy: HashSet<(String, usize, String)> = HashSet::new();
    for f in baseline {
        // Both the unkeyed (`sha256:`) and keyed (`hmac-sha256:`) schemes are
        // line-tolerant fingerprints. Anything else (empty, or a legacy FNV hex)
        // routes to the location-tuple fallback. Omitting `hmac-sha256:` here
        // would mis-route a keyed baseline to the legacy set and re-surface every
        // suppressed finding.
        if f.fingerprint.starts_with("sha256:") || f.fingerprint.starts_with("hmac-sha256:") {
            known_fps.insert(f.fingerprint);
        } else {
            known_legacy.insert((f.file, f.line, f.rule_id));
        }
    }
    let before = all_findings.len();
    all_findings.retain(|f| {
        !known_fps.contains(&f.fingerprint)
            && !known_legacy.contains(&(f.file.clone(), f.line, f.rule_id.clone()))
    });
    before - all_findings.len()
}

fn apply_baseline_or_exit(baseline_path: &str, all_findings: &mut Vec<Finding>) {
    match std::fs::read_to_string(baseline_path) {
        Ok(content) => {
            let baseline: Vec<Finding> = match serde_json::from_str(&content) {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to parse baseline JSON '{baseline_path}': {e}");
                    std::process::exit(2);
                }
            };
            let suppressed = suppress_baseline(baseline, all_findings);
            if suppressed > 0 {
                info!("[scanner] Baseline suppressed {suppressed} known finding(s)");
            }
        }
        Err(e) => {
            error!("Failed to read baseline file '{baseline_path}': {e}");
            std::process::exit(2);
        }
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
/// contain raw secrets when `--no-redact` is used. On non-Unix platforms no
/// permission restriction is applied (the file inherits the default ACL), so
/// secret-bearing output on those platforms relies on the caller's directory
/// permissions; generated baselines are redacted regardless for this reason.
fn create_private_file(path: &str) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
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
