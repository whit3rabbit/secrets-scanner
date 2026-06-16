"use strict";

const { invalidConfig, invalidArgument, inputTooLarge } = require("./errors");

const CONFIG_FIELDS = new Set([
  "proxy",
  "redact",
  "redactionMode",
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
  "historyTimeoutSecs",
  "gitStaged",
  "includeUntracked",
  "gitFallbackWalk",
  "captureContext",
]);

const PROXY_FORBIDDEN_FIELDS = [
  "proxy",
  "redact",
  "redactionMode",
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
  "historyTimeoutSecs",
  "gitStaged",
  "includeUntracked",
  "gitFallbackWalk",
  "captureContext",
];

const DIRECT_PROXY_FORBIDDEN_FIELDS = PROXY_FORBIDDEN_FIELDS.filter(
  (field) => field !== "proxy"
);

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
  validateGitModeConfig(config);

  return {
    proxy,
    redact: optionalBoolean(config, "redact"),
    redactionMode: optionalString(config, "redactionMode"),
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
    historyTimeoutSecs: optionalNumber(config, "historyTimeoutSecs"),
    gitStaged: optionalBoolean(config, "gitStaged"),
    includeUntracked: optionalBoolean(config, "includeUntracked"),
    gitFallbackWalk: optionalBoolean(config, "gitFallbackWalk"),
    captureContext: optionalBoolean(config, "captureContext"),
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

function validateGitModeConfig(config) {
  const gitHistory = config.gitHistory === true;
  const gitStaged = config.gitStaged === true;
  const gitTracked = config.gitTracked === true;
  const changedFiles = config.changedFiles === true;
  const hasBase = Object.prototype.hasOwnProperty.call(config, "base");
  const includeUntracked = config.includeUntracked === true;
  const hasHistoryOptions =
    config.historyAll === true ||
    config.historyFull === true ||
    Object.prototype.hasOwnProperty.call(config, "historyTimeoutSecs") ||
    (Array.isArray(config.historyLogOpts) && config.historyLogOpts.length > 0);

  if (hasHistoryOptions && !gitHistory) {
    throw invalidConfig("history options require gitHistory");
  }
  if (gitHistory && (gitTracked || changedFiles || hasBase || gitStaged || includeUntracked)) {
    throw invalidConfig("gitHistory conflicts with other git scan modes");
  }
  if (gitStaged && (gitTracked || changedFiles || hasBase || includeUntracked)) {
    throw invalidConfig("gitStaged conflicts with other git scan modes");
  }
  if (gitTracked && (changedFiles || hasBase)) {
    throw invalidConfig("gitTracked conflicts with changedFiles and base");
  }
  if (includeUntracked && !(gitTracked || changedFiles || hasBase)) {
    throw invalidConfig("includeUntracked requires gitTracked, changedFiles, or base");
  }
}

function rejectUnknownConfigFields(config) {
  for (const field of Object.keys(config)) {
    if (!CONFIG_FIELDS.has(field)) {
      throw invalidConfig(`unknown scan config field: ${field}`);
    }
  }
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

function toBuffer(content, maxFileSize) {
  if (!(content instanceof Uint8Array)) {
    throw invalidArgument("content", "must be a Uint8Array");
  }
  if (maxFileSize != null && content.byteLength > maxFileSize) {
    throw inputTooLarge(content.byteLength, maxFileSize);
  }

  // Zero-copy view over the same memory: the synchronous native scan methods
  // only borrow `&[u8]` while the caller's Uint8Array is alive, so a full
  // `Buffer.from(content)` copy buys nothing and doubles peak memory on large
  // inputs. (Async byte paths copy into an owned Vec on the Rust side anyway.)
  return Buffer.from(content.buffer, content.byteOffset, content.byteLength);
}

module.exports = {
  toNativeConfig,
  validateProxyConfig,
  requireString,
  toBuffer,
};
