export type ScannerErrorCode =
  | "ENGINE_BUILD"
  | "INPUT_TOO_LARGE"
  | "NOT_HARDENED"
  | "POSITION_OVERFLOW"
  | "INVALID_CONFIG"
  | "INVALID_RULES"
  | "INVALID_RULES_TOML"
  | "IO"
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

export interface ScanConfig {
  /**
   * Use the hardened proxy preset: redaction enabled, inline allow markers
   * ignored, context capture disabled, and proxy-safe caps applied.
   */
  proxy?: boolean;

  redact?: boolean;
  minEntropy?: number;
  maxFileSize?: number;
  maxFindingsPerFile?: number;
  maxMatchedLen?: number;
  binaryPolicy?: BinaryPolicy;
  maxFiles?: number;
  maxFindings?: number;
  gitTracked?: boolean;
  changedFiles?: boolean;
  base?: string;
  gitHistory?: boolean;
  historyAll?: boolean;
  historyFull?: boolean;
  historyLogOpts?: string[];
  gitStaged?: boolean;
  includeUntracked?: boolean;
  gitFallbackWalk?: boolean;
}

export interface ProxyScanConfig {
  minEntropy?: number;
  maxFileSize?: number;
  maxFindingsPerFile?: number;
  maxMatchedLen?: number;
  proxy?: never;
  redact?: never;
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
  gitStaged?: never;
  includeUntracked?: never;
  gitFallbackWalk?: never;
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
  findingsTruncated: boolean;
}

export interface PathScanResult extends ScanResult {
  stats: ScanStats;
  incomplete: boolean;
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
  scanPath(path: string): PathScanResult;

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
  scanPathAsync(path: string): Promise<PathScanResult>;
}
