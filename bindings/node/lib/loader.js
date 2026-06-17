"use strict";

const fs = require("node:fs");
const path = require("node:path");

// Scope of the per-platform optionalDependency packages published alongside the
// main package (e.g. @whit3rabbit/rsecrets-scanner-darwin-arm64).
const PLATFORM_PACKAGE_SCOPE = "@whit3rabbit/rsecrets-scanner";

function loadNative() {
  const candidates = nativeCandidates();
  let loadError;

  // 1. Local artifact (dev builds / `npm run build` in this directory).
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

  // 2. Published install: the platform-specific optionalDependency package
  //    that npm selected for this host (os/cpu gated).
  const platformPackage = platformPackageName();
  if (platformPackage) {
    try {
      return require(platformPackage);
    } catch (error) {
      loadError = loadError ?? error;
    }
  }

  // 3. Legacy fallback (a sibling package literally named secrets_scanner_core).
  try {
    return require("secrets_scanner_core");
  } catch (error) {
    throw nativeBindingNotFound(candidates, platformPackage, loadError ?? error);
  }
}

function nativeCandidates(
  parentDir = path.join(__dirname, ".."),
  platform = process.platform,
  arch = process.arch,
  libc = detectLibc(platform)
) {
  const suffix = platformArtifactSuffix(platform, arch, libc);
  const names = [];
  // napi emits the abi-suffixed artifact name (e.g. linux-x64-gnu,
  // win32-x64-msvc; darwin has no abi suffix). Try it first so a locally built
  // `napi build --platform` artifact is found on every platform.
  if (suffix) {
    names.push(`secrets_scanner_core.${suffix}.node`);
  }
  names.push(`secrets_scanner_core.${platform}-${arch}.node`);
  names.push(`secrets_scanner_core.${platform}.node`);
  names.push("secrets_scanner_core.node");
  return [...new Set(names)].map((name) => path.join(parentDir, name));
}

// Suffix napi appends to per-platform artifacts and package names
// (`<platform>-<arch>[-<abi>]`): `darwin-arm64`, `linux-x64-gnu`,
// `win32-x64-msvc`, etc. Returns null for a platform we do not publish.
function platformArtifactSuffix(
  platform = process.platform,
  arch = process.arch,
  libc = detectLibc(platform)
) {
  switch (platform) {
    case "darwin":
      return `darwin-${arch}`;
    case "win32":
      return `win32-${arch}-msvc`;
    case "linux":
      return `linux-${arch}-${libc || "gnu"}`;
    default:
      return null;
  }
}

// Compute the scoped per-platform package name for the current host, matching
// the NAPI-RS publishing convention (`<scope>-<platform>-<arch>[-<abi>]`).
// Returns null for a platform/arch we do not publish. `libc` is only relevant
// on Linux; when omitted it is detected (glibc vs musl). We ship gnu builds, so
// a musl host resolves to a `-musl` name that is intentionally absent, yielding
// a clear NATIVE_BINDING_NOT_FOUND rather than loading an incompatible binary.
function platformPackageName(
  platform = process.platform,
  arch = process.arch,
  libc = detectLibc(platform)
) {
  const suffix = platformArtifactSuffix(platform, arch, libc);
  return suffix ? `${PLATFORM_PACKAGE_SCOPE}-${suffix}` : null;
}

// Detect the active C standard library on Linux. glibc exposes
// `glibcVersionRuntime` in the process report header; musl does not. Returns
// "gnu" or "musl" on Linux, and null elsewhere.
function detectLibc(platform = process.platform) {
  if (platform !== "linux") {
    return null;
  }
  try {
    const report =
      typeof process.report?.getReport === "function" ? process.report.getReport() : null;
    const header = report && typeof report === "object" ? report.header : null;
    if (header && header.glibcVersionRuntime) {
      return "gnu";
    }
    const sharedObjects = report && Array.isArray(report.sharedObjects) ? report.sharedObjects : [];
    if (sharedObjects.some((so) => typeof so === "string" && /(?:^|\/)ld-musl|libc\.musl/.test(so))) {
      return "musl";
    }
  } catch {
    // Fall through to the gnu default below.
  }
  // Default to gnu: it is the common case and matches what we publish.
  return "gnu";
}

function nativeBindingNotFound(candidates, platformPackage, cause) {
  // Back-compat: older callers pass (candidates, cause) with no package name.
  if (cause === undefined && platformPackage instanceof Error) {
    cause = platformPackage;
    platformPackage = undefined;
  }
  const error = new Error(
    `native binding not found; run npm run build in ${path.join(__dirname, "..")}`
  );
  error.code = "NATIVE_BINDING_NOT_FOUND";
  error.details = { candidates };
  if (platformPackage) {
    error.details.platformPackage = platformPackage;
  }
  if (cause) {
    error.cause = cause;
  }
  return error;
}

module.exports = {
  loadNative,
  nativeCandidates,
  platformPackageName,
  platformArtifactSuffix,
  detectLibc,
  nativeBindingNotFound,
};
