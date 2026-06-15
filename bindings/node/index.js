"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ERROR_MESSAGES = {
  ENGINE_BUILD: "scanner engine could not be built",
  INPUT_TOO_LARGE: "input exceeds configured maxFileSize",
  NOT_HARDENED: "scanner is not hardened for proxy use",
  POSITION_OVERFLOW: "native finding position exceeds JavaScript number precision",
  INVALID_CONFIG: "scan config is invalid",
  INVALID_RULES: "scanner rules are invalid",
  INVALID_RULES_TOML: "scanner rules TOML is invalid",
  IO: "scanner rules could not be read",
  INCOMPLETE_SCAN: "path scan did not fully cover the requested scope",
  NATIVE_ERROR: "native scanner call failed",
  NATIVE_BINDING_NOT_FOUND: "native binding not found",
  INVALID_ARGUMENT: "scanner argument is invalid",
};

const CONFIG_FIELDS = new Set([
  "proxy",
  "redact",
  "minEntropy",
  "maxFileSize",
  "maxFindingsPerFile",
  "maxMatchedLen",
  "binaryPolicy",
  "maxFiles",
  "maxFindings",
  "gitTracked",
  "changedFiles",
  "base",
  "gitHistory",
  "historyAll",
  "historyFull",
  "historyLogOpts",
  "gitStaged",
  "includeUntracked",
  "gitFallbackWalk",
]);

const PROXY_FORBIDDEN_FIELDS = [
  "proxy",
  "redact",
  "binaryPolicy",
  "maxFiles",
  "maxFindings",
  "gitTracked",
  "changedFiles",
  "base",
  "gitHistory",
  "historyAll",
  "historyFull",
  "historyLogOpts",
  "gitStaged",
  "includeUntracked",
  "gitFallbackWalk",
];
const DIRECT_PROXY_FORBIDDEN_FIELDS = PROXY_FORBIDDEN_FIELDS.filter(
  (field) => field !== "proxy"
);

const native = loadNative();

class Scanner {
  constructor(nativeScanner) {
    if (!nativeScanner) {
      throw invalidArgument("nativeScanner", "must be a native scanner");
    }
    this.nativeScanner = nativeScanner;
  }

  static bundled(config) {
    return wrapNative(() => new Scanner(native.NativeScanner.bundled(toNativeConfig(config))));
  }

  static proxy(config) {
    validateProxyConfig(config);
    return Scanner.bundled({ ...(config ?? {}), proxy: true });
  }

  static fromDefaultRules(config) {
    return wrapNative(() =>
      new Scanner(native.NativeScanner.fromDefaultRules(toNativeConfig(config)))
    );
  }

  static fromRulesFile(rulesPath, config) {
    return wrapNative(() =>
      new Scanner(
        native.NativeScanner.fromRulesFile(
          requireString("rulesPath", rulesPath),
          toNativeConfig(config)
        )
      )
    );
  }

  static fromToml(toml, config) {
    return wrapNative(() =>
      new Scanner(
        native.NativeScanner.fromToml(requireString("toml", toml), toNativeConfig(config))
      )
    );
  }

  scanContent(filePath, content) {
    return wrapNative(() =>
      this.nativeScanner
        .scanContent(requireString("path", filePath), requireString("content", content))
        .map(mapFinding)
    );
  }

  scanContentDetailed(filePath, content) {
    return wrapNative(() =>
      mapScanResult(
        this.nativeScanner.scanContentDetailed(
          requireString("path", filePath),
          requireString("content", content)
        )
      )
    );
  }

  scanAndRedactContent(filePath, content) {
    return wrapNative(() =>
      mapStringRedactionResult(
        this.nativeScanner.scanAndRedactContent(
          requireString("path", filePath),
          requireString("content", content)
        )
      )
    );
  }

  scanBytes(filePath, content) {
    return wrapNative(() =>
      this.nativeScanner
        .scanBytes(requireString("path", filePath), toBuffer(content))
        .map(mapFinding)
    );
  }

  scanBytesDetailed(filePath, content) {
    return wrapNative(() =>
      mapScanResult(
        this.nativeScanner.scanBytesDetailed(requireString("path", filePath), toBuffer(content))
      )
    );
  }

  scanAndRedactBytes(filePath, content) {
    return wrapNative(() =>
      mapByteRedactionResult(
        this.nativeScanner.scanAndRedactBytes(requireString("path", filePath), toBuffer(content))
      )
    );
  }

  scanProxy(content) {
    return wrapNative(() =>
      mapByteRedactionResult(this.nativeScanner.scanProxy(toBuffer(content)))
    );
  }

  scanFile(filePath) {
    return wrapNative(() =>
      mapPathScanResult(this.nativeScanner.scanFile(requireString("path", filePath)))
    );
  }

  scanFileStrict(filePath) {
    return requireCompleteScan(this.scanFile(filePath));
  }

  scanPath(scanPath) {
    return wrapNative(() =>
      mapPathScanResult(this.nativeScanner.scanPath(requireString("path", scanPath)))
    );
  }

  scanPathStrict(scanPath) {
    return requireCompleteScan(this.scanPath(scanPath));
  }

  scanContentAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      (await this.nativeScanner.scanContentAsync(
        requireString("path", filePath),
        requireString("content", content)
      )).map(mapFinding)
    );
  }

  scanContentDetailedAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapScanResult(
        await this.nativeScanner.scanContentDetailedAsync(
          requireString("path", filePath),
          requireString("content", content)
        )
      )
    );
  }

  scanAndRedactContentAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapStringRedactionResult(
        await this.nativeScanner.scanAndRedactContentAsync(
          requireString("path", filePath),
          requireString("content", content)
        )
      )
    );
  }

  scanBytesAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      (await this.nativeScanner.scanBytesAsync(requireString("path", filePath), toBuffer(content)))
        .map(mapFinding)
    );
  }

  scanBytesDetailedAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapScanResult(
        await this.nativeScanner.scanBytesDetailedAsync(
          requireString("path", filePath),
          toBuffer(content)
        )
      )
    );
  }

  scanAndRedactBytesAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapByteRedactionResult(
        await this.nativeScanner.scanAndRedactBytesAsync(
          requireString("path", filePath),
          toBuffer(content)
        )
      )
    );
  }

  scanProxyAsync(content) {
    return wrapNativeAsync(async () =>
      mapByteRedactionResult(await this.nativeScanner.scanProxyAsync(toBuffer(content)))
    );
  }

  scanFileAsync(filePath) {
    return wrapNativeAsync(async () =>
      mapPathScanResult(await this.nativeScanner.scanFileAsync(requireString("path", filePath)))
    );
  }

  async scanFileStrictAsync(filePath) {
    return requireCompleteScan(await this.scanFileAsync(filePath));
  }

  scanPathAsync(scanPath) {
    return wrapNativeAsync(async () =>
      mapPathScanResult(await this.nativeScanner.scanPathAsync(requireString("path", scanPath)))
    );
  }

  async scanPathStrictAsync(scanPath) {
    return requireCompleteScan(await this.scanPathAsync(scanPath));
  }
}

function loadNative() {
  const candidates = nativeCandidates();
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return require(candidate);
    }
  }

  try {
    return require("secrets_scanner_core");
  } catch {
    const error = new Error(
      `native binding not found; run npm run build in ${__dirname}`
    );
    error.code = "NATIVE_BINDING_NOT_FOUND";
    throw error;
  }
}

function nativeCandidates() {
  const platformArch = `${process.platform}-${process.arch}`;
  return [
    path.join(__dirname, "secrets_scanner_core.node"),
    path.join(__dirname, `secrets_scanner_core.${platformArch}.node`),
    path.join(__dirname, `secrets_scanner_core.${process.platform}.node`),
  ];
}

function toNativeConfig(config) {
  if (config == null) {
    return undefined;
  }
  requirePlainObject("config", config);
  rejectUnknownConfigFields(config);
  const proxy = optionalBoolean(config, "proxy");
  if (proxy === true) {
    validateDirectProxyConfig(config);
  }

  return {
    proxy,
    redact: optionalBoolean(config, "redact"),
    minEntropy: optionalNumber(config, "minEntropy"),
    maxFileSize: optionalNumber(config, "maxFileSize"),
    maxFindingsPerFile: optionalNumber(config, "maxFindingsPerFile"),
    maxMatchedLen: optionalNumber(config, "maxMatchedLen"),
    binaryPolicy: optionalString(config, "binaryPolicy"),
    maxFiles: optionalNumber(config, "maxFiles"),
    maxFindings: optionalNumber(config, "maxFindings"),
    gitTracked: optionalBoolean(config, "gitTracked"),
    changedFiles: optionalBoolean(config, "changedFiles"),
    base: optionalString(config, "base"),
    gitHistory: optionalBoolean(config, "gitHistory"),
    historyAll: optionalBoolean(config, "historyAll"),
    historyFull: optionalBoolean(config, "historyFull"),
    historyLogOpts: optionalStringArray(config, "historyLogOpts"),
    gitStaged: optionalBoolean(config, "gitStaged"),
    includeUntracked: optionalBoolean(config, "includeUntracked"),
    gitFallbackWalk: optionalBoolean(config, "gitFallbackWalk"),
  };
}

function validateDirectProxyConfig(config) {
  for (const field of DIRECT_PROXY_FORBIDDEN_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(config, field)) {
      throw invalidConfig(`proxy scan config does not accept ${field}`);
    }
  }
}

function validateProxyConfig(config) {
  if (config == null) {
    return;
  }
  requirePlainObject("config", config);
  rejectUnknownConfigFields(config);
  for (const field of PROXY_FORBIDDEN_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(config, field)) {
      throw invalidConfig(`Scanner.proxy() does not accept ${field}`);
    }
  }
}

function rejectUnknownConfigFields(config) {
  for (const field of Object.keys(config)) {
    if (!CONFIG_FIELDS.has(field)) {
      throw invalidConfig(`unknown scan config field: ${field}`);
    }
  }
}

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

function requireString(name, value) {
  if (typeof value !== "string") {
    throw invalidArgument(name, "must be a string");
  }
  return value;
}

function requirePlainObject(name, value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw invalidArgument(name, "must be a plain object");
  }
  return value;
}

function optionalBoolean(config, field) {
  if (!Object.prototype.hasOwnProperty.call(config, field)) {
    return undefined;
  }
  if (typeof config[field] !== "boolean") {
    throw invalidConfig(`${field} must be a boolean`);
  }
  return config[field];
}

function optionalNumber(config, field) {
  if (!Object.prototype.hasOwnProperty.call(config, field)) {
    return undefined;
  }
  if (typeof config[field] !== "number") {
    throw invalidConfig(`${field} must be a number`);
  }
  return config[field];
}

function optionalString(config, field) {
  if (!Object.prototype.hasOwnProperty.call(config, field)) {
    return undefined;
  }
  return requireString(field, config[field]);
}

function optionalStringArray(config, field) {
  if (!Object.prototype.hasOwnProperty.call(config, field)) {
    return undefined;
  }
  if (!Array.isArray(config[field]) || config[field].some((v) => typeof v !== "string")) {
    throw invalidConfig(`${field} must be an array of strings`);
  }
  return config[field];
}

function toBuffer(content) {
  if (!(content instanceof Uint8Array)) {
    throw invalidArgument("content", "must be a Uint8Array");
  }

  return Buffer.from(content);
}

function invalidArgument(name, message) {
  const error = new TypeError(`${name} ${message}`);
  error.code = "INVALID_ARGUMENT";
  return error;
}

function invalidConfig(message) {
  const error = new TypeError(message);
  error.code = "INVALID_CONFIG";
  return error;
}

function wrapNative(fn) {
  try {
    return fn();
  } catch (error) {
    throw normalizeNativeError(error);
  }
}

async function wrapNativeAsync(fn) {
  try {
    return await fn();
  } catch (error) {
    throw normalizeNativeError(error);
  }
}

function normalizeNativeError(error) {
  if (
    error &&
    typeof error === "object" &&
    error.code &&
    ERROR_MESSAGES[error.code]
  ) {
    return error;
  }

  const message = error && error.message ? String(error.message) : String(error);
  const match =
    /^(ENGINE_BUILD|INPUT_TOO_LARGE|NOT_HARDENED|POSITION_OVERFLOW|INVALID_CONFIG|INVALID_RULES_TOML|INVALID_RULES|IO|INCOMPLETE_SCAN):\s*([\s\S]*?)(?:;\s*details=([\s\S]+))?$/.exec(
      message
    );
  const code = match ? match[1] : "NATIVE_ERROR";
  const wrapped = new Error(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.NATIVE_ERROR);
  wrapped.code = code;
  wrapped.cause = error;
  if (match && match[2]) {
    wrapped.nativeMessage = match[2];
  }
  if (match && match[3]) {
    try {
      wrapped.details = JSON.parse(match[3]);
    } catch {
      wrapped.details = match[3];
    }
  }
  return wrapped;
}

module.exports = {
  Scanner,
};
