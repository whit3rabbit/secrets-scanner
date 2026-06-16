"use strict";

const { loadNative } = require("./lib/loader");
const { wrapNative, wrapNativeAsync, invalidArgument } = require("./lib/errors");
const { toNativeConfig, validateProxyConfig, requireString, toBuffer } = require("./lib/config");
const {
  mapScanResult,
  mapStringRedactionResult,
  mapByteRedactionResult,
  mapPathScanResult,
  requireCompleteScan,
  mapFinding,
} = require("./lib/mapping");

const native = loadNative();
const CONSTRUCTOR_TOKEN = Symbol("Scanner.constructor");

const REQUIRED_NATIVE_METHODS = [
  "maxFileSize",
  "scanContent",
  "scanContentDetailed",
  "scanAndRedactContent",
  "scanBytes",
  "scanBytesDetailed",
  "scanAndRedactBytes",
  "scanProxy",
  "scanFile",
  "scanPath",
  "scanContentAsync",
  "scanContentDetailedAsync",
  "scanAndRedactContentAsync",
  "scanBytesAsync",
  "scanBytesDetailedAsync",
  "scanAndRedactBytesAsync",
  "scanProxyAsync",
  "scanFileAsync",
  "scanPathAsync",
];

class Scanner {
  constructor(nativeScanner, token) {
    if (token !== CONSTRUCTOR_TOKEN) {
      throw invalidArgument("Scanner", "must be created by a factory method");
    }
    assertNativeScanner(nativeScanner);
    this.nativeScanner = nativeScanner;
    this.maxFileSize = nativeScanner.maxFileSize();
    if (
      typeof this.maxFileSize !== "number" ||
      !Number.isFinite(this.maxFileSize) ||
      this.maxFileSize < 0
    ) {
      throw invalidArgument("nativeScanner", "must expose a valid maxFileSize");
    }
  }

  static bundled(config) {
    return wrapNative(
      () => new Scanner(native.NativeScanner.bundled(toNativeConfig(config)), CONSTRUCTOR_TOKEN)
    );
  }

  static proxy(config) {
    validateProxyConfig(config);
    return Scanner.bundled({ ...(config ?? {}), proxy: true });
  }

  static fromDefaultRules(config) {
    return wrapNative(() =>
      new Scanner(native.NativeScanner.fromDefaultRules(toNativeConfig(config)), CONSTRUCTOR_TOKEN)
    );
  }

  static fromRulesFile(rulesPath, config) {
    return wrapNative(() =>
      new Scanner(
        native.NativeScanner.fromRulesFile(
          requireString("rulesPath", rulesPath),
          toNativeConfig(config)
        ),
        CONSTRUCTOR_TOKEN
      )
    );
  }

  static fromToml(toml, config) {
    return wrapNative(() =>
      new Scanner(
        native.NativeScanner.fromToml(requireString("toml", toml), toNativeConfig(config)),
        CONSTRUCTOR_TOKEN
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
        .scanBytes(requireString("path", filePath), toBuffer(content, this.maxFileSize))
        .map(mapFinding)
    );
  }

  scanBytesDetailed(filePath, content) {
    return wrapNative(() =>
      mapScanResult(
        this.nativeScanner.scanBytesDetailed(
          requireString("path", filePath),
          toBuffer(content, this.maxFileSize)
        )
      )
    );
  }

  scanAndRedactBytes(filePath, content) {
    return wrapNative(() =>
      mapByteRedactionResult(
        this.nativeScanner.scanAndRedactBytes(
          requireString("path", filePath),
          toBuffer(content, this.maxFileSize)
        )
      )
    );
  }

  scanProxy(content) {
    return wrapNative(() =>
      mapByteRedactionResult(this.nativeScanner.scanProxy(toBuffer(content, this.maxFileSize)))
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
      (await this.nativeScanner.scanBytesAsync(
        requireString("path", filePath),
        toBuffer(content, this.maxFileSize)
      ))
        .map(mapFinding)
    );
  }

  scanBytesDetailedAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapScanResult(
        await this.nativeScanner.scanBytesDetailedAsync(
          requireString("path", filePath),
          toBuffer(content, this.maxFileSize)
        )
      )
    );
  }

  scanAndRedactBytesAsync(filePath, content) {
    return wrapNativeAsync(async () =>
      mapByteRedactionResult(
        await this.nativeScanner.scanAndRedactBytesAsync(
          requireString("path", filePath),
          toBuffer(content, this.maxFileSize)
        )
      )
    );
  }

  scanProxyAsync(content) {
    return wrapNativeAsync(async () =>
      mapByteRedactionResult(
        await this.nativeScanner.scanProxyAsync(toBuffer(content, this.maxFileSize))
      )
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

function assertNativeScanner(nativeScanner) {
  if (!nativeScanner || typeof nativeScanner !== "object") {
    throw invalidArgument("nativeScanner", "must be a native scanner");
  }
  for (const method of REQUIRED_NATIVE_METHODS) {
    if (typeof nativeScanner[method] !== "function") {
      throw invalidArgument("nativeScanner", "must be a native scanner");
    }
  }
}

module.exports = {
  Scanner,
};
