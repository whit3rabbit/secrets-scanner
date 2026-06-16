use super::types::ScanStats;
use crate::error::CoverageError;

impl ScanStats {
    /// Return typed reasons this scan has incomplete coverage.
    ///
    /// Finding truncation alone is deliberately excluded: finding caps drop
    /// reported findings after content was scanned, while these reasons mean
    /// requested files or commits were not scanned at all.
    pub fn incomplete_coverage_reasons(&self) -> Vec<CoverageError> {
        let mut out = Vec::new();

        if self.git_failed {
            out.push(CoverageError::GitFailed);
        }
        if self.history_timed_out {
            out.push(CoverageError::HistoryTimedOut);
        }
        if self.errored > 0 {
            out.push(CoverageError::UnreadableFiles {
                count: self.errored,
            });
        }
        let policy_skipped = self.binary_skipped + self.oversized_skipped;
        if policy_skipped > 0 {
            out.push(CoverageError::PolicySkipped {
                count: policy_skipped,
                binary: self.binary_skipped,
                oversized: self.oversized_skipped,
            });
        }
        if self.files_over_cap > 0 {
            out.push(CoverageError::FileCapReached {
                count: self.files_over_cap,
            });
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_coverage_reasons_reports_all_coverage_gaps() {
        let stats = ScanStats {
            errored: 2,
            binary_skipped: 3,
            oversized_skipped: 5,
            files_over_cap: 7,
            git_failed: true,
            history_timed_out: true,
            findings_truncated: true,
            ..ScanStats::default()
        };

        assert_eq!(
            stats.incomplete_coverage_reasons(),
            vec![
                CoverageError::GitFailed,
                CoverageError::HistoryTimedOut,
                CoverageError::UnreadableFiles { count: 2 },
                CoverageError::PolicySkipped {
                    count: 8,
                    binary: 3,
                    oversized: 5,
                },
                CoverageError::FileCapReached { count: 7 },
            ]
        );
    }

    #[test]
    fn incomplete_coverage_reasons_ignores_finding_truncation_only() {
        let stats = ScanStats {
            findings_truncated: true,
            ..ScanStats::default()
        };

        assert!(stats.incomplete_coverage_reasons().is_empty());
    }
}
