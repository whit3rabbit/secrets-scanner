"use strict";

const fs = require("node:fs");
const path = require("node:path");

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
      `native binding not found; run npm run build in ${path.join(__dirname, "..")}`
    );
    error.code = "NATIVE_BINDING_NOT_FOUND";
    throw error;
  }
}

function nativeCandidates() {
  const platformArch = `${process.platform}-${process.arch}`;
  const parentDir = path.join(__dirname, "..");
  return [
    path.join(parentDir, "secrets_scanner_core.node"),
    path.join(parentDir, `secrets_scanner_core.${platformArch}.node`),
    path.join(parentDir, `secrets_scanner_core.${process.platform}.node`),
  ];
}

module.exports = {
  loadNative,
};
