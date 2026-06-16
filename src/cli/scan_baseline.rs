use std::collections::HashSet;

use log::{error, info};
use secrets_scanner::Finding;

use super::write_private_file;

/// Build the findings to serialize into a `--generate-baseline` file.
///
/// Strips `context_lines` from every finding and replaces `matched` with the
/// fixed `[REDACTED_SECRET]` marker for ALL findings, regardless of the CLI
/// redaction mode (`--no-redact` or the default partial redaction). A baseline
/// is meant to be committed/uploaded, so it must carry no secret material — not
/// even the length or first/last characters that partial redaction preserves.
/// This is safe because baselines suppress on `fingerprint` (computed pre-
/// redaction over the raw secret) or the legacy `(file,line,rule)` tuple, never
/// on `matched`.
pub(super) fn baseline_findings(all_findings: &[Finding]) -> Vec<Finding> {
    all_findings
        .iter()
        .map(|f| {
            let mut f = f.clone();
            f.context_lines = Vec::new();
            f.matched = "[REDACTED_SECRET]".to_string();
            f
        })
        .collect()
}

/// Write a generated baseline file or terminate with the scan runtime-error exit.
pub(super) fn write_baseline_or_exit(out_path: &str, all_findings: &[Finding]) {
    let baseline_findings = baseline_findings(all_findings);
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
pub(super) fn suppress_baseline(baseline: Vec<Finding>, all_findings: &mut Vec<Finding>) -> usize {
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
    // Short-circuit the legacy-tuple probe when there are no legacy entries (the
    // common case once baselines carry fingerprints): it skips a per-finding
    // `file`/`rule_id` clone that the `contains` lookup would otherwise force.
    let has_legacy = !known_legacy.is_empty();
    all_findings.retain(|f| {
        if known_fps.contains(&f.fingerprint) {
            return false;
        }
        // Only build the legacy tuple (cloning file/rule_id) when the baseline
        // actually has legacy entries — the common post-fingerprint case skips it.
        !(has_legacy && known_legacy.contains(&(f.file.clone(), f.line, f.rule_id.clone())))
    });
    before - all_findings.len()
}

/// Apply a baseline file to the current findings or terminate with the scan runtime-error exit.
pub(super) fn apply_baseline_or_exit(baseline_path: &str, all_findings: &mut Vec<Finding>) {
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
