import {
  Scanner,
  type BytesRedactionResult,
  type Finding,
  type ProxyScanConfig,
  type ScanConfig,
  type StringRedactionResult,
} from "..";

const config: ScanConfig = { redact: true, minEntropy: 3.5 };
const proxyConfig: ProxyScanConfig = {
  maxFileSize: 1024,
  maxFindingsPerFile: 10,
  maxMatchedLen: 128,
};
const scanner = Scanner.fromToml("title = \"empty\"\n", config);
const proxyScanner = Scanner.proxy(proxyConfig);
const customProxyScanner = Scanner.fromToml("title = \"empty\"\n", {
  proxy: true,
  maxFileSize: 1024,
});

const findings: Finding[] = scanner.scanContent("input.txt", "content");
const firstRuleId: string | undefined = findings[0]?.ruleId;

const textResult: StringRedactionResult = scanner.scanAndRedactContent(
  "input.txt",
  "content"
);
const redactedText: string = textResult.redacted;

const bytesResult: BytesRedactionResult = scanner.scanAndRedactBytes(
  "input.bin",
  new Uint8Array([1, 2, 3])
);
const redactedBytes: Uint8Array = bytesResult.redacted;
const proxyResult: BytesRedactionResult = proxyScanner.scanProxy(
  new Uint8Array([1, 2, 3])
);

void firstRuleId;
void redactedText;
void redactedBytes;
void proxyResult;
void customProxyScanner;
