//! Detailed scan output and redaction helpers.

use super::{redaction, ScanOutput, ScanResult, Scanner};

impl Scanner {
    /// Scan string content and report whether finding caps truncated the result.
    pub fn scan_content_detailed(&self, path: &str, content: &str) -> ScanResult {
        self.scan_bytes_detailed(path, content.as_bytes())
    }

    /// Scan string content and return both findings and redacted content.
    ///
    /// This is intended for proxy-style use cases where callers need a safe
    /// payload to forward after inspecting the findings.
    pub fn scan_and_redact_content(&self, path: &str, content: &str) -> ScanOutput<String> {
        let output = self.scan_and_redact_bytes(path, content.as_bytes());
        let redacted = match String::from_utf8(output.redacted) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };

        ScanOutput {
            findings: output.findings,
            redacted,
            findings_truncated: output.findings_truncated,
        }
    }

    /// Scan a byte slice and report whether finding caps truncated the result.
    ///
    /// This operates directly on raw bytes to avoid heap allocations.
    pub fn scan_bytes_detailed(&self, path: &str, content: &[u8]) -> ScanResult {
        let mut findings = self.scan_bytes_uncapped(path, content);
        let findings_truncated = self.apply_findings_cap(path, &mut findings);
        ScanResult {
            findings,
            findings_truncated,
        }
    }

    /// Scan bytes and return both findings and redacted bytes.
    ///
    /// Secret byte spans are replaced with `[REDACTED_SECRET]`. Path-only and
    /// zero-length findings are reported but do not mutate the returned bytes.
    ///
    /// Redaction runs against the **full pre-cap** finding set so a payload with
    /// more than `max_findings_per_file` distinct secrets still has every secret
    /// redacted; only the returned `findings` list is then truncated to the cap.
    /// Redacting off the post-cap list would forward secrets past the cap in the
    /// clear — the fail-open hazard this ordering closes.
    pub fn scan_and_redact_bytes(&self, path: &str, content: &[u8]) -> ScanOutput<Vec<u8>> {
        if !self.config.capture_context && self.config.max_findings_per_file.is_some() {
            let (findings, ranges, findings_truncated) =
                self.scan_bytes_for_bounded_redaction(path, content);
            let redacted = redaction::redact_content_ranges(content, &ranges);
            return ScanOutput {
                findings,
                redacted,
                findings_truncated,
            };
        }

        let mut findings = self.scan_bytes_uncapped(path, content);
        let redacted = redaction::redact_content_bytes(content, &findings);
        let findings_truncated = self.apply_findings_cap(path, &mut findings);
        ScanOutput {
            findings,
            redacted,
            findings_truncated,
        }
    }
}
