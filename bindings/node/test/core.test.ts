import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
const OTHER_SECRET = "tok_MNOPQRSTUVWX";

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

  it("returns only the public camelCase finding shape", () => {
    const scanner = Scanner.fromToml(RULES);
    const finding = scanner.scanContent("input.env", `API_TOKEN=${SECRET}`)[0] as
      | Record<string, unknown>
      | undefined;

    expect(finding).toBeDefined();
    expect(finding).toHaveProperty("ruleId");
    expect(finding).toHaveProperty("startOffset");
    expect(finding).not.toHaveProperty("rule_id");
    expect(finding).not.toHaveProperty("start_offset");
  });

  it("redacts content and reports hasFindings", () => {
    const scanner = Scanner.fromToml(RULES);
    const result = scanner.scanAndRedactContent("input.env", `API_TOKEN=${SECRET}`);

    expect(result.hasFindings).toBe(true);
    expect(result.findingsTruncated).toBe(false);
    expect(result.redacted).toBe("API_TOKEN=[REDACTED_SECRET]");
    expect(result.redacted).not.toContain(SECRET);
  });

  it("reports truncation without leaking redacted content past the cap", () => {
    const scanner = Scanner.fromToml(RULES, { maxFindingsPerFile: 1 });
    const content = `A=${SECRET}\nB=${OTHER_SECRET}`;

    const detailed = scanner.scanContentDetailed("input.env", content);
    const redacted = scanner.scanAndRedactContent("input.env", content);

    expect(detailed.findings).toHaveLength(1);
    expect(detailed.findingsTruncated).toBe(true);
    expect(redacted.findings).toHaveLength(1);
    expect(redacted.findingsTruncated).toBe(true);
    expect(redacted.redacted).not.toContain(SECRET);
    expect(redacted.redacted).not.toContain(OTHER_SECRET);
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
      expect.objectContaining({
        code: "INPUT_TOO_LARGE",
        details: { size: Buffer.byteLength(SECRET), maxFileSize: 8 },
      })
    );
  });

  it("enforces maxFileSize for all in-memory entry points", () => {
    const scanner = Scanner.fromToml(RULES, { maxFileSize: 8 });
    const proxyScanner = Scanner.fromToml(RULES, { proxy: true, maxFileSize: 8 });
    const bytes = Buffer.from(SECRET, "utf8");

    for (const call of [
      () => scanner.scanContent("input.env", SECRET),
      () => scanner.scanContentDetailed("input.env", SECRET),
      () => scanner.scanAndRedactContent("input.env", SECRET),
      () => scanner.scanBytes("input.env", bytes),
      () => scanner.scanBytesDetailed("input.env", bytes),
      () => scanner.scanAndRedactBytes("input.env", bytes),
      () => proxyScanner.scanProxy(bytes),
    ]) {
      expect(call).toThrowError(expect.objectContaining({ code: "INPUT_TOO_LARGE" }));
    }
  });

  it("rejects unsafe config numbers and proxy config fields", () => {
    expect(() =>
      Scanner.proxy({ maxFileSize: Number.MAX_SAFE_INTEGER + 1 })
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIG" }));
    expect(() => Scanner.proxy({ redact: false } as never)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIG" })
    );
    expect(() => Scanner.proxy({ gitHistory: true } as never)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIG" })
    );
  });

  it("rejects string coercion for public arguments", () => {
    const scanner = Scanner.fromToml(RULES);

    expect(() => Scanner.fromToml(undefined as unknown as string)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARGUMENT" })
    );
    expect(() => scanner.scanContent("input.env", null as unknown as string)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARGUMENT" })
    );
    expect(() => scanner.scanBytes({} as unknown as string, Buffer.from(SECRET))).toThrowError(
      expect.objectContaining({ code: "INVALID_ARGUMENT" })
    );
  });

  it("refuses scanProxy on a non-hardened scanner", () => {
    // A scanner without the proxy config must fail closed: scanning untrusted
    // content with the soft posture would honor attacker allow markers, capture
    // whole-payload context, and leave findings/matched uncapped.
    const scanner = Scanner.fromToml(RULES);

    expect(() => scanner.scanProxy(Buffer.from(SECRET, "utf8"))).toThrowError(
      expect.objectContaining({ code: "NOT_HARDENED" })
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

  it("supports async scan APIs and normalizes async rejections", async () => {
    const scanner = Scanner.fromToml(RULES, { maxFindingsPerFile: 1 });
    const content = `A=${SECRET}\nB=${OTHER_SECRET}`;

    await expect(scanner.scanContentAsync("input.env", content)).resolves.toHaveLength(1);
    await expect(
      scanner.scanContentDetailedAsync("input.env", content)
    ).resolves.toMatchObject({ hasFindings: true, findingsTruncated: true });
    await expect(
      scanner.scanAndRedactContentAsync("input.env", content)
    ).resolves.toMatchObject({ hasFindings: true, findingsTruncated: true });
    await expect(
      scanner.scanBytesAsync("input.env", Buffer.from(content))
    ).resolves.toHaveLength(1);
    await expect(
      scanner.scanBytesDetailedAsync("input.env", Buffer.from(content))
    ).resolves.toMatchObject({ hasFindings: true, findingsTruncated: true });
    await expect(
      scanner.scanAndRedactBytesAsync("input.env", Buffer.from(content))
    ).resolves.toMatchObject({ hasFindings: true, findingsTruncated: true });

    const proxy = Scanner.fromToml(RULES, { proxy: true, maxFileSize: 8 });
    await expect(proxy.scanProxyAsync(Buffer.from(SECRET))).rejects.toMatchObject({
      code: "INPUT_TOO_LARGE",
      details: { size: Buffer.byteLength(SECRET), maxFileSize: 8 },
    });
  });

  it("scans files and paths with stats", async () => {
    const dir = mkdtempSync(join(tmpdir(), "secrets-scanner-node-"));
    try {
      const file = join(dir, "input.env");
      writeFileSync(file, `A=${SECRET}\nB=${OTHER_SECRET}`);
      const scanner = Scanner.fromToml(RULES, { maxFindingsPerFile: 1 });

      const fileResult = scanner.scanFile(file);
      expect(fileResult.hasFindings).toBe(true);
      expect(fileResult.findings).toHaveLength(1);
      expect(fileResult.findingsTruncated).toBe(true);
      expect(fileResult.stats.filesScanned).toBe(1);
      expect(fileResult.stats.findingsTruncated).toBe(true);
      expect(fileResult.incomplete).toBe(false);

      const pathResult = await scanner.scanPathAsync(dir);
      expect(pathResult.hasFindings).toBe(true);
      expect(pathResult.stats.filesScanned).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
