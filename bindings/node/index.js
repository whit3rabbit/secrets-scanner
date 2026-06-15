"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ERROR_MESSAGES = {
  ENGINE_BUILD: "scanner engine could not be built",
  INPUT_TOO_LARGE: "proxy input exceeds configured maxFileSize",
  NOT_HARDENED: "scanner is not hardened for proxy use",
  POSITION_OVERFLOW: "native finding position exceeds JavaScript number precision",
  INVALID_CONFIG: "scan config is invalid",
  INVALID_RULES: "scanner rules are invalid",
  INVALID_RULES_TOML: "scanner rules TOML is invalid",
  IO: "scanner rules could not be read",
  NATIVE_ERROR: "native scanner call failed",
};

const native = loadNative();

class Scanner {
  constructor(nativeScanner) {
    if (!nativeScanner) {
      throw new TypeError("Scanner must be constructed with a native scanner");
    }
    this.nativeScanner = nativeScanner;
  }

  static bundled(config) {
    return wrapNative(() => new Scanner(native.NativeScanner.bundled(toNativeConfig(config))));
  }

  static proxy(config) {
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
        native.NativeScanner.fromRulesFile(String(rulesPath), toNativeConfig(config))
      )
    );
  }

  static fromToml(toml, config) {
    return wrapNative(() =>
      new Scanner(native.NativeScanner.fromToml(String(toml), toNativeConfig(config)))
    );
  }

  scanContent(filePath, content) {
    return wrapNative(() =>
      this.nativeScanner
        .scanContent(String(filePath), String(content))
        .map(mapFinding)
    );
  }

  scanAndRedactContent(filePath, content) {
    return wrapNative(() =>
      mapStringRedactionResult(
        this.nativeScanner.scanAndRedactContent(String(filePath), String(content))
      )
    );
  }

  scanBytes(filePath, content) {
    return wrapNative(() =>
      this.nativeScanner
        .scanBytes(String(filePath), toBuffer(content))
        .map(mapFinding)
    );
  }

  scanAndRedactBytes(filePath, content) {
    return wrapNative(() =>
      mapByteRedactionResult(
        this.nativeScanner.scanAndRedactBytes(String(filePath), toBuffer(content))
      )
    );
  }

  scanProxy(content) {
    return wrapNative(() =>
      mapByteRedactionResult(this.nativeScanner.scanProxy(toBuffer(content)))
    );
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

  return {
    proxy: config.proxy,
    minEntropy: config.minEntropy,
    maxFileSize: config.maxFileSize,
    maxFindingsPerFile: config.maxFindingsPerFile,
    maxMatchedLen: config.maxMatchedLen,
    redact: config.redact,
  };
}

function mapStringRedactionResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    redacted: result.redacted,
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
  };
}

function mapByteRedactionResult(result) {
  return {
    findings: result.findings.map(mapFinding),
    redacted: new Uint8Array(result.redacted),
    hasFindings: Boolean(result.hasFindings ?? result.has_findings),
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

function toBuffer(content) {
  if (!(content instanceof Uint8Array)) {
    throw new TypeError("content must be a Uint8Array");
  }

  return Buffer.from(content.buffer, content.byteOffset, content.byteLength);
}

function wrapNative(fn) {
  try {
    return fn();
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
    /^(ENGINE_BUILD|INPUT_TOO_LARGE|NOT_HARDENED|POSITION_OVERFLOW|INVALID_CONFIG|INVALID_RULES_TOML|INVALID_RULES|IO):/.exec(
      message
    );
  const code = match ? match[1] : "NATIVE_ERROR";
  const wrapped = new Error(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.NATIVE_ERROR);
  wrapped.code = code;
  wrapped.cause = error;
  return wrapped;
}

module.exports = {
  Scanner,
};
