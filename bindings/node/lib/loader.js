"use strict";

const fs = require("node:fs");
const path = require("node:path");

function loadNative() {
  const candidates = nativeCandidates();
  let loadError;
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        return require(candidate);
      } catch (error) {
        loadError = error;
        break;
      }
    }
  }

  try {
    return require("secrets_scanner_core");
  } catch (error) {
    throw nativeBindingNotFound(candidates, loadError ?? error);
  }
}

function nativeCandidates(
  parentDir = path.join(__dirname, ".."),
  platform = process.platform,
  arch = process.arch
) {
  const platformArch = `${platform}-${arch}`;
  return [
    path.join(parentDir, `secrets_scanner_core.${platformArch}.node`),
    path.join(parentDir, `secrets_scanner_core.${platform}.node`),
    path.join(parentDir, "secrets_scanner_core.node"),
  ];
}

function nativeBindingNotFound(candidates, cause) {
  const error = new Error(
    `native binding not found; run npm run build in ${path.join(__dirname, "..")}`
  );
  error.code = "NATIVE_BINDING_NOT_FOUND";
  error.details = { candidates };
  if (cause) {
    error.cause = cause;
  }
  return error;
}

module.exports = {
  loadNative,
  nativeCandidates,
  nativeBindingNotFound,
};
