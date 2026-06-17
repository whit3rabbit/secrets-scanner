const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { test } = require("node:test");

test("wasm dependency graph excludes native-only crates", () => {
  const manifest = path.join(__dirname, "..", "Cargo.toml");
  const tree = execFileSync(
    "cargo",
    [
      "tree",
      "--manifest-path",
      manifest,
      "--target",
      "wasm32-unknown-unknown",
      "-e",
      "normal",
      "--prefix",
      "none",
    ],
    { encoding: "utf8" }
  );

  for (const crateName of [
    "agent-config",
    "clap",
    "clap_complete",
    "env_logger",
    "libc",
    "rayon",
    "serde_json",
    "ureq",
    "walkdir",
  ]) {
    assert.equal(
      tree.includes(`${crateName} v`),
      false,
      `${crateName} should not be in the WASM dependency graph`
    );
  }
});
