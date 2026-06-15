export interface ScanConfig {
  redact?: boolean;
  minEntropy?: number;
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
  static fromDefaultRules(config?: ScanConfig): Scanner;
  static fromRulesFile(path: string, config?: ScanConfig): Scanner;
  static fromToml(toml: string, config?: ScanConfig): Scanner;

  scanContent(path: string, content: string): Finding[];
  scanAndRedactContent(path: string, content: string): StringRedactionResult;
  scanBytes(path: string, content: Uint8Array): Finding[];
  scanAndRedactBytes(path: string, content: Uint8Array): BytesRedactionResult;
}
