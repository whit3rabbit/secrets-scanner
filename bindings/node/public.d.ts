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
}

export type ProxyScanConfig = Omit<ScanConfig, "proxy">;

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
  contextLines: ContextLine[];
}

export interface RedactionResult<T> {
  findings: Finding[];
  redacted: T;
  hasFindings: boolean;
}

export type StringRedactionResult = RedactionResult<string>;
export type BytesRedactionResult = RedactionResult<Uint8Array>;

export class Scanner {
  private constructor(nativeScanner: unknown);

  static bundled(config?: ScanConfig): Scanner;
  static proxy(config?: ProxyScanConfig): Scanner;
  static fromDefaultRules(config?: ScanConfig): Scanner;
  static fromRulesFile(path: string, config?: ScanConfig): Scanner;
  static fromToml(toml: string, config?: ScanConfig): Scanner;

  scanContent(path: string, content: string): Finding[];
  scanAndRedactContent(path: string, content: string): StringRedactionResult;
  scanBytes(path: string, content: Uint8Array): Finding[];
  scanAndRedactBytes(path: string, content: Uint8Array): BytesRedactionResult;
  scanProxy(content: Uint8Array): BytesRedactionResult;
}
