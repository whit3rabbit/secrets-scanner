import {
  type BinaryPolicy,
  Scanner,
  type BytesRedactionResult,
  type Finding,
  type PathScanResult,
  type ProxyScanConfig,
  type ScanConfig,
  type ScannerError,
  type ScanResult,
  type ScanStats,
  type StringRedactionResult,
} from "..";

const policy: BinaryPolicy = "auto";
const config: ScanConfig = {
  redact: true,
  minEntropy: 3.5,
  binaryPolicy: policy,
  maxFiles: 10,
  maxFindings: 20,
  gitTracked: true,
};
const proxyConfig: ProxyScanConfig = {
  maxFileSize: 1024,
  maxFindingsPerFile: 10,
  maxMatchedLen: 128,
};
// @ts-expect-error proxy scans always redact.
Scanner.proxy({ redact: false });
// @ts-expect-error proxy scans do not accept path scan options.
Scanner.proxy({ gitHistory: true });

const scanner = Scanner.fromToml("title = \"empty\"\n", config);
const proxyScanner = Scanner.proxy(proxyConfig);
const customProxyScanner = Scanner.fromToml("title = \"empty\"\n", {
  proxy: true,
  maxFileSize: 1024,
});

const findings: Finding[] = scanner.scanContent("input.txt", "content");
const firstRuleId: string | undefined = findings[0]?.ruleId;
const maybeCommit: string | undefined = findings[0]?.commit;
const detailed: ScanResult = scanner.scanContentDetailed("input.txt", "content");
const detailedFlag: boolean = detailed.findingsTruncated;

const textResult: StringRedactionResult = scanner.scanAndRedactContent(
  "input.txt",
  "content"
);
const redactedText: string = textResult.redacted;
const textTruncated: boolean = textResult.findingsTruncated;

const bytesResult: BytesRedactionResult = scanner.scanAndRedactBytes(
  "input.bin",
  new Uint8Array([1, 2, 3])
);
const redactedBytes: Uint8Array = bytesResult.redacted;
const proxyResult: BytesRedactionResult = proxyScanner.scanProxy(
  new Uint8Array([1, 2, 3])
);
const stats: ScanStats = scanner.scanPath(".").stats;
const pathResult: PathScanResult = scanner.scanFile("input.txt");
const asyncFindings: Promise<Finding[]> = scanner.scanContentAsync("input.txt", "content");
const asyncDetailed: Promise<ScanResult> = scanner.scanBytesDetailedAsync(
  "input.bin",
  new Uint8Array([1, 2, 3])
);
const asyncRedacted: Promise<StringRedactionResult> =
  scanner.scanAndRedactContentAsync("input.txt", "content");
const asyncProxy: Promise<BytesRedactionResult> = proxyScanner.scanProxyAsync(
  new Uint8Array([1, 2, 3])
);
const asyncPath: Promise<PathScanResult> = scanner.scanPathAsync(".");
const scannerError = new Error("x") as ScannerError;
const scannerErrorCode: string = scannerError.code;

void firstRuleId;
void maybeCommit;
void detailedFlag;
void redactedText;
void textTruncated;
void redactedBytes;
void proxyResult;
void stats;
void pathResult;
void asyncFindings;
void asyncDetailed;
void asyncRedacted;
void asyncProxy;
void asyncPath;
void scannerErrorCode;
void customProxyScanner;
