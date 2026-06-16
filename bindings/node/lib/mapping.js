"use strict";

const { ERROR_MESSAGES } = require("./errors");

function mapScanResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
    findingsTruncated: Boolean(
      result.findingsTruncated ?? result.findings_truncated
    ),
  };
}

function mapStringRedactionResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    redacted: result.redacted,
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
    findingsTruncated: Boolean(
      result.findingsTruncated ?? result.findings_truncated
    ),
  };
}

function mapByteRedactionResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    redacted: new Uint8Array(result.redacted),
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
    findingsTruncated: Boolean(
      result.findingsTruncated ?? result.findings_truncated
    ),
  };
}

function mapPathScanResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    stats: mapStats(result.stats),
    incomplete: Boolean(result.incomplete),
    skippedByPolicy: Boolean(
      result.skippedByPolicy ?? result.skipped_by_policy
    ),
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
    findingsTruncated: Boolean(
      result.findingsTruncated ?? result.findings_truncated
    ),
  };
}

function requireCompleteScan(result) {
  if (!result.incomplete) {
    return result;
  }

  const error = new Error(ERROR_MESSAGES.INCOMPLETE_SCAN);
  error.code = "INCOMPLETE_SCAN";
  error.details = { stats: result.stats };
  throw error;
}

function mapStats(stats) {
  return {
    filesScanned: stats.filesScanned ?? stats.files_scanned,
    binarySkipped: stats.binarySkipped ?? stats.binary_skipped,
    oversizedSkipped: stats.oversizedSkipped ?? stats.oversized_skipped,
    filesOverCap: stats.filesOverCap ?? stats.files_over_cap,
    errored: stats.errored,
    gitFallback: Boolean(stats.gitFallback ?? stats.git_fallback),
    gitFailed: Boolean(stats.gitFailed ?? stats.git_failed),
    historyTimedOut: Boolean(
      stats.historyTimedOut ?? stats.history_timed_out
    ),
    findingsTruncated: Boolean(
      stats.findingsTruncated ?? stats.findings_truncated
    ),
  };
}

function mapFinding(finding) {
  const contextLines = finding.contextLines ?? finding.context_lines ?? [];

  return {
    file: finding.file,
    line: finding.line,
    col: finding.col,
    endLine: finding.endLine ?? finding.end_line,
    endCol: finding.endCol ?? finding.end_col,
    colUtf16: finding.colUtf16 ?? finding.col_utf16,
    endColUtf16: finding.endColUtf16 ?? finding.end_col_utf16,
    ruleId: finding.ruleId ?? finding.rule_id,
    description: finding.description,
    matched: finding.matched,
    entropy: finding.entropy,
    startOffset: finding.startOffset ?? finding.start_offset,
    endOffset: finding.endOffset ?? finding.end_offset,
    secretStartOffset: finding.secretStartOffset ?? finding.secret_start_offset,
    secretEndOffset: finding.secretEndOffset ?? finding.secret_end_offset,
    fingerprint: finding.fingerprint,
    commit: finding.commit,
    contextLines: contextLines.map(mapContextLine),
  };
}

function mapContextLine(contextLine) {
  if (Array.isArray(contextLine)) {
    return {
      line: contextLine[0],
      content: contextLine[1],
    };
  }

  return {
    line: contextLine.line,
    content: contextLine.content,
  };
}

module.exports = {
  mapScanResult,
  mapStringRedactionResult,
  mapByteRedactionResult,
  mapPathScanResult,
  requireCompleteScan,
  mapFinding,
  mapStats,
};
