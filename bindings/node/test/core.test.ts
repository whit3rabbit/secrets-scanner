import { describe, expect, it } from "vitest";

import { Scanner } from "../index.js";

const RULES = String.raw`
title = "node binding tests"

[[rules]]
id = "fake-token"
description = "Fake token"
regex = 'tok_[A-Za-z0-9]{12,}'
keywords = ["tok_"]
`;

const INVALID_REGEX_RULES = String.raw`
title = "invalid"

[[rules]]
id = "lookahead"
description = "Unsupported lookahead"
regex = '(?=SECRET)SECRET[0-9]+'
keywords = ["secret"]
`;

const SECRET = "tok_ABCDEFGHIJKL";

describe("@secrets-scanner/core", () => {
  it("constructs from bundled rules", () => {
    expect(() => Scanner.bundled()).not.toThrow();
  });

  it("constructs from bundled rules with proxy defaults", () => {
    expect(() => Scanner.proxy()).not.toThrow();
  });

  it("detects a planted token from inline TOML", () => {
    const scanner = Scanner.fromToml(RULES);
    const findings = scanner.scanContent("input.env", `API_TOKEN=${SECRET}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("fake-token");
    expect(findings[0]?.description).toBe("Fake token");
  });

  it("redacts content and reports hasFindings", () => {
    const scanner = Scanner.fromToml(RULES);
    const result = scanner.scanAndRedactContent("input.env", `API_TOKEN=${SECRET}`);

    expect(result.hasFindings).toBe(true);
    expect(result.redacted).toBe("API_TOKEN=[REDACTED_SECRET]");
    expect(result.redacted).not.toContain(SECRET);
  });

  it("does not expose raw matched text by default", () => {
    const scanner = Scanner.fromToml(RULES);
    const findings = scanner.scanContent("input.env", `API_TOKEN=${SECRET}`);

    expect(findings[0]?.matched).not.toBe(SECRET);
    expect(findings[0]?.matched).not.toContain(SECRET);
  });

  it("can expose raw findings while still returning redacted forwardable content", () => {
    const scanner = Scanner.fromToml(RULES, { redact: false });
    const result = scanner.scanAndRedactContent("input.env", `API_TOKEN=${SECRET}`);

    expect(result.findings[0]?.matched).toBe(SECRET);
    expect(result.redacted).toBe("API_TOKEN=[REDACTED_SECRET]");
    expect(result.redacted).not.toContain(SECRET);
  });

  it("rejects invalid TOML and invalid rules with stable codes", () => {
    expect(() => Scanner.fromToml("not = [")).toThrowError(
      expect.objectContaining({ code: "INVALID_RULES_TOML" })
    );
    expect(() => Scanner.fromToml(INVALID_REGEX_RULES)).toThrowError(
      expect.objectContaining({ code: "INVALID_RULES" })
    );
  });

  it("scans and redacts bytes", () => {
    const scanner = Scanner.fromToml(RULES);
    const input = Buffer.from(`API_TOKEN=${SECRET}`, "utf8");

    const findings = scanner.scanBytes("input.env", input);
    const result = scanner.scanAndRedactBytes("input.env", input);

    expect(findings).toHaveLength(1);
    expect(result.hasFindings).toBe(true);
    expect(Buffer.from(result.redacted).toString("utf8")).toBe(
      "API_TOKEN=[REDACTED_SECRET]"
    );
  });

  it("exposes hardened proxy scans to TypeScript", () => {
    const content = `API_TOKEN=${SECRET} secrets-scanner:allow`;
    const defaultScanner = Scanner.fromToml(RULES);
    const proxyScanner = Scanner.fromToml(RULES, { proxy: true });

    expect(defaultScanner.scanContent("input.env", content)).toHaveLength(0);

    const result = proxyScanner.scanProxy(Buffer.from(content, "utf8"));
    const redacted = Buffer.from(result.redacted).toString("utf8");

    expect(result.hasFindings).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.file).toBe("<proxy>");
    expect(result.findings[0]?.contextLines).toEqual([]);
    expect(redacted).toBe("API_TOKEN=[REDACTED_SECRET] secrets-scanner:allow");
    expect(redacted).not.toContain(SECRET);
  });

  it("reports proxy oversize failures with a stable code", () => {
    const scanner = Scanner.fromToml(RULES, { proxy: true, maxFileSize: 8 });

    expect(() => scanner.scanProxy(Buffer.from(SECRET, "utf8"))).toThrowError(
      expect.objectContaining({ code: "INPUT_TOO_LARGE" })
    );
  });

  it("returns numeric position fields for unicode input", () => {
    const scanner = Scanner.fromToml(RULES);
    const findings = scanner.scanContent("unicode.env", `snowman=☃\nkey=${SECRET}`);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(typeof finding?.line).toBe("number");
    expect(typeof finding?.col).toBe("number");
    expect(typeof finding?.endLine).toBe("number");
    expect(typeof finding?.endCol).toBe("number");
    expect(typeof finding?.startOffset).toBe("number");
    expect(typeof finding?.endOffset).toBe("number");
    expect(Array.isArray(finding?.contextLines)).toBe(true);
  });
});
