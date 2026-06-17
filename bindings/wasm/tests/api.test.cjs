const assert = require("node:assert/strict");
const { test } = require("node:test");

const { Scanner } = require("../pkg-node/rsecrets_scanner_wasm.js");

const GITHUB_PAT = "ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
const CUSTOM_RULES = `
title = "wasm test rules"

[[rules]]
id = "demo-token"
description = "Demo token"
regex = '''DEMO_[A-Z0-9]{16}'''
keywords = ["DEMO_"]
`;

test("bundled scanner detects a fake secret", () => {
  const scanner = Scanner.bundled();
  const findings = scanner.scanContent("input.env", `TOKEN=${GITHUB_PAT}`);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "github-pat");
  assert.equal(findings[0].file, "input.env");
  assert.equal(findings[0].matched.includes(GITHUB_PAT), false);
});

test("fromToml accepts custom rules and scanBytes returns findings", () => {
  const scanner = Scanner.fromToml(CUSTOM_RULES);
  const findings = scanner.scanBytes("custom.env", Buffer.from("DEMO_ABCDEFGHIJKLMNOP"));

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "demo-token");
});

test("scanContentDetailed reports truncation metadata", () => {
  const scanner = Scanner.fromToml(CUSTOM_RULES, { maxFindingsPerFile: 1 });
  const result = scanner.scanContentDetailed(
    "custom.env",
    "DEMO_ABCDEFGHIJKLMNOP\nDEMO_QRSTUVWXYZABCDEF"
  );

  assert.equal(result.hasFindings, true);
  assert.equal(result.findingsTruncated, true);
  assert.equal(result.findings.length, 1);
});

test("scanAndRedactContent redacts detected secrets", () => {
  const scanner = Scanner.fromToml(CUSTOM_RULES);
  const result = scanner.scanAndRedactContent("custom.env", "value=DEMO_ABCDEFGHIJKLMNOP");

  assert.equal(result.hasFindings, true);
  assert.equal(result.redacted.includes("DEMO_ABCDEFGHIJKLMNOP"), false);
  assert.equal(result.redacted.includes("[REDACTED_SECRET]"), true);
});

test("scanProxy redacts without leaking raw secret material", () => {
  const scanner = Scanner.proxy();
  const result = scanner.scanProxy(Buffer.from(`TOKEN=${GITHUB_PAT}`));
  const redacted = Buffer.from(result.redacted).toString("utf8");

  assert.equal(result.hasFindings, true);
  assert.equal(redacted.includes(GITHUB_PAT), false);
  assert.equal(redacted.includes("[REDACTED_SECRET]"), true);
  assert.equal(result.findings[0].matched.includes(GITHUB_PAT), false);
});

test("in-memory APIs reject oversized input with stable error codes", () => {
  const scanner = Scanner.fromToml(CUSTOM_RULES, { maxFileSize: 8 });
  const proxy = Scanner.proxy({ maxFileSize: 8 });

  for (const call of [
    () => scanner.scanContent("input.env", "123456789"),
    () => scanner.scanContentDetailed("input.env", "123456789"),
    () => scanner.scanAndRedactContent("input.env", "123456789"),
    () => scanner.scanBytes("input.bin", Buffer.alloc(9)),
    () => proxy.scanProxy(Buffer.alloc(9)),
  ]) {
    assert.throws(call, (error) => error.code === "INPUT_TOO_LARGE");
  }
});

test("invalid TOML throws a stable error code", () => {
  assert.throws(
    () => Scanner.fromToml("not valid toml = ["),
    (error) => error.code === "INVALID_RULES_TOML"
  );
});

test("unicode locations include byte and UTF-16 columns", () => {
  const scanner = Scanner.fromToml(CUSTOM_RULES);
  const finding = scanner.scanContent("unicode.env", "☃key=DEMO_ABCDEFGHIJKLMNOP")[0];

  assert.equal(finding.col, 8);
  assert.equal(finding.colUtf16, 6);
});
