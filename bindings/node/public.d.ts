export type ScannerErrorCode =
  | "ENGINE_BUILD"
  | "INPUT_TOO_LARGE"
  | "NOT_HARDENED"
  | "POSITION_OVERFLOW"
  | "INVALID_CONFIG"
  | "INVALID_RULES"
  | "INVALID_RULES_TOML"
  | "IO"
  | "INCOMPLETE_SCAN"
  | "NATIVE_ERROR"
  | "NATIVE_BINDING_NOT_FOUND"
  | "INVALID_ARGUMENT";

export interface ScannerError extends Error {
  code: ScannerErrorCode;
  details?: unknown;
  cause?: unknown;
  nativeMessage?: string;
}

export type BinaryPolicy = "auto" | "skip" | "scan";

/**
 * How the `matched` field of a finding is redacted when `redact` is enabled.
 * `"partial"` (default) keeps the first/last 4 chars; `"full"` replaces the
 * whole match with a fixed marker that leaks neither the value nor its length.
 * Ignored when `redact` is false.
 */
export type RedactionMode = "partial" | "full";

export interface NormalScanConfig {
  proxy?: false;
  redact?: boolean;
  redactionMode?: RedactionMode;
  minEntropy?: number;
  maxFileSize?: number;
  maxFindingsPerFile?: number;
  maxMatchedLen?: number;
  binaryPolicy?: BinaryPolicy;
  maxFiles?: number;
  /**
   * Total finding cap for path, git, staged, and history scans. In-memory
   * scanContent and scanBytes calls use maxFindingsPerFile.
   */
  maxFindings?: number;
  gitTracked?: boolean;
  changedFiles?: boolean;
  base?: string;
  gitHistory?: boolean;
  historyAll?: boolean;
  historyFull?: boolean;
  historyLogOpts?: string[];
  historyTimeoutSecs?: number;
  gitStaged?: boolean;
  includeUntracked?: boolean;
  gitFallbackWalk?: boolean;
  captureContext?: boolean;
}

export interface DirectProxyScanConfig {
  /**
   * Use the hardened proxy preset: redaction enabled, inline allow markers
   * ignored, context capture disabled, and proxy-safe caps applied.
   */
  proxy: true;
  minEntropy?: number;
  maxFileSize?: number;
  maxFindingsPerFile?: number;
  maxMatchedLen?: number;
  redact?: never;
  redactionMode?: never;
  binaryPolicy?: never;
  maxFiles?: never;
  maxFindings?: never;
  gitTracked?: never;
  changedFiles?: never;
  base?: never;
  gitHistory?: never;
  historyAll?: never;
  historyFull?: never;
  historyLogOpts?: never;
  historyTimeoutSecs?: never;
  gitStaged?: never;
  includeUntracked?: never;
  gitFallbackWalk?: never;
  captureContext?: never;
}

export type ScanConfig = NormalScanConfig | DirectProxyScanConfig;

export interface ProxyScanConfig {
  minEntropy?: number;
  maxFileSize?: number;
  maxFindingsPerFile?: number;
  maxMatchedLen?: number;
  proxy?: never;
  redact?: never;
  redactionMode?: never;
  binaryPolicy?: never;
  maxFiles?: never;
  maxFindings?: never;
  gitTracked?: never;
  changedFiles?: never;
  base?: never;
  gitHistory?: never;
  historyAll?: never;
  historyFull?: never;
  historyLogOpts?: never;
  historyTimeoutSecs?: never;
  gitStaged?: never;
  includeUntracked?: never;
  gitFallbackWalk?: never;
  captureContext?: never;
}

export interface ContextLine {
  line: number;
  content: string;
}

export interface Finding {
  file: string;
  line: number;
  col: number;
  endLine: number;
  endCol: number;
  colUtf16: number;
  endColUtf16: number;
  ruleId: string;
  description: string;
  matched: string;
  entropy: number;
  startOffset: number;
  endOffset: number;
  secretStartOffset: number;
  secretEndOffset: number;
  fingerprint: string;
  commit?: string;
  contextLines: ContextLine[];
}

export interface ScanResult {
  findings: Finding[];
  hasFindings: boolean;
  findingsTruncated: boolean;
}

export interface RedactionResult<T> extends ScanResult {
  redacted: T;
}

export type StringRedactionResult = RedactionResult<string>;
export type BytesRedactionResult = RedactionResult<Uint8Array>;

export interface ScanStats {
  filesScanned: number;
  binarySkipped: number;
  oversizedSkipped: number;
  filesOverCap: number;
  errored: number;
  gitFallback: boolean;
  gitFailed: boolean;
  historyTimedOut: boolean;
  findingsTruncated: boolean;
}

export interface PathScanResult extends ScanResult {
  stats: ScanStats;
  /**
   * True when coverage is incomplete: unreadable files, oversized skips,
   * `maxFiles` cap, git failure, git fallback, or history timeout. Strict scans
   * throw on this.
   */
  incomplete: boolean;
  /**
   * True when any file was skipped by policy (binary or oversized). Unlike
   * `incomplete`, a binary skip is intentional policy and does not make a strict
   * scan throw; inspect this to treat policy skips as a coverage gap. Mirrors the
   * CLI `--error-on-skipped` flag.
   */
  skippedByPolicy: boolean;
}

export class Scanner {
  private constructor(nativeScanner: unknown);

  static bundled(config?: ScanConfig): Scanner;
  static proxy(config?: ProxyScanConfig): Scanner;
  static fromDefaultRules(config?: ScanConfig): Scanner;
  static fromRulesFile(path: string, config?: ScanConfig): Scanner;
  static fromToml(toml: string, config?: ScanConfig): Scanner;

  scanContent(path: string, content: string): Finding[];
  scanContentDetailed(path: string, content: string): ScanResult;
  scanAndRedactContent(path: string, content: string): StringRedactionResult;
  scanBytes(path: string, content: Uint8Array): Finding[];
  scanBytesDetailed(path: string, content: Uint8Array): ScanResult;
  scanAndRedactBytes(path: string, content: Uint8Array): BytesRedactionResult;
  scanProxy(content: Uint8Array): BytesRedactionResult;
  scanFile(path: string): PathScanResult;
  scanFileStrict(path: string): PathScanResult;
  scanPath(path: string): PathScanResult;
  scanPathStrict(path: string): PathScanResult;

  scanContentAsync(path: string, content: string): Promise<Finding[]>;
  scanContentDetailedAsync(path: string, content: string): Promise<ScanResult>;
  scanAndRedactContentAsync(
    path: string,
    content: string
  ): Promise<StringRedactionResult>;
  scanBytesAsync(path: string, content: Uint8Array): Promise<Finding[]>;
  scanBytesDetailedAsync(path: string, content: Uint8Array): Promise<ScanResult>;
  scanAndRedactBytesAsync(
    path: string,
    content: Uint8Array
  ): Promise<BytesRedactionResult>;
  scanProxyAsync(content: Uint8Array): Promise<BytesRedactionResult>;
  scanFileAsync(path: string): Promise<PathScanResult>;
  scanFileStrictAsync(path: string): Promise<PathScanResult>;
  scanPathAsync(path: string): Promise<PathScanResult>;
  scanPathStrictAsync(path: string): Promise<PathScanResult>;
}
