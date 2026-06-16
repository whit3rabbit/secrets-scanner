"use strict";

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

function inputTooLarge(size, maxFileSize) {
  const error = new Error(ERROR_MESSAGES.INPUT_TOO_LARGE);
  error.code = "INPUT_TOO_LARGE";
  error.details = { size, maxFileSize };
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
  ERROR_MESSAGES,
  invalidArgument,
  invalidConfig,
  inputTooLarge,
  wrapNative,
  wrapNativeAsync,
  normalizeNativeError,
};
