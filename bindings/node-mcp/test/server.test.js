import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterEach, describe, expect, it } from "vitest";

import {
  mergeCaps,
  parseArgs,
  resolveInsideRoot,
  safeFinding,
} from "../src/server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN_PATH = path.resolve(__dirname, "../bin/rsecrets-scanner-mcp.js");

const RULES = String.raw`
title = "mcp tests"

[[rules]]
id = "fake-token"
description = "Fake token"
regex = 'tok_[A-Za-z0-9]{12,}'
keywords = ["tok_"]
`;

const SECRET = "tok_ABCDEFGHIJKL";

const clients = [];
const tempDirs = [];

afterEach(async () => {
  while (clients.length > 0) {
    await clients.pop().close();
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe("@whit3rabbit/rsecrets-scanner-mcp", () => {
  it("parses startup args and clamps requested caps to startup limits", () => {
    const parsed = parseArgs([
      "--root",
      "/tmp/project",
      "--enable-history",
      "--history-log-opt",
      "--since=1 week ago",
      "--max-file-size",
      "128",
    ]);

    expect(parsed).toMatchObject({
      root: "/tmp/project",
      enableHistory: true,
      historyLogOpts: ["--since=1 week ago"],
      maxFileSize: 128,
    });
    expect(
      mergeCaps(
        { maxFileSize: 128, maxFindings: 10 },
        { maxFileSize: 4096, maxFindings: 3 },
        ["maxFileSize", "maxFindings"]
      )
    ).toEqual({ maxFileSize: 128, maxFindings: 3 });
  });

  it("rejects paths outside the configured root", () => {
    const root = makeTempDir();

    expect(() => resolveInsideRoot(root, "../outside.txt")).toThrowError(
      expect.objectContaining({ code: "PATH_OUTSIDE_ROOT" })
    );
  });

  it("serializes findings without raw matches or context lines", () => {
    const finding = safeFinding(
      {
        file: path.join("/tmp/root", "secret.env"),
        line: 1,
        col: 5,
        endLine: 1,
        endCol: 21,
        colUtf16: 5,
        endColUtf16: 21,
        ruleId: "fake-token",
        description: "Fake token",
        matched: SECRET,
        entropy: 3.5,
        startOffset: 4,
        endOffset: 20,
        secretStartOffset: 4,
        secretEndOffset: 20,
        fingerprint: "sha256:test",
        contextLines: [{ line: 1, content: `x=${SECRET}` }],
      },
      { root: "/tmp/root" }
    );

    expect(finding.file).toBe("secret.env");
    expect(finding).not.toHaveProperty("matched");
    expect(finding).not.toHaveProperty("contextLines");
    expect(JSON.stringify(finding)).not.toContain(SECRET);
  });

  it("lists tools and redacts text over stdio", async () => {
    const { client } = await startClient();

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "redact_text",
      "scan_file",
      "scan_git_history",
      "scan_text",
      "scan_workspace",
    ]);

    const result = await client.callTool({
      name: "redact_text",
      arguments: { content: `API_TOKEN=${SECRET}` },
    });
    const payload = parsePayload(result);

    expect(result.isError).toBeFalsy();
    expect(payload.hasFindings).toBe(true);
    expect(payload.redacted).toBe("API_TOKEN=[REDACTED_SECRET]");
    expect(JSON.stringify(payload)).not.toContain(SECRET);
    expect(payload.findings[0]).not.toHaveProperty("matched");
  });

  it("scans a file under root and rejects git history when disabled", async () => {
    const { client, root } = await startClient();
    writeFileSync(path.join(root, "input.env"), `API_TOKEN=${SECRET}`);

    const scan = await client.callTool({
      name: "scan_file",
      arguments: { path: "input.env" },
    });
    const scanPayload = parsePayload(scan);

    expect(scan.isError).toBeFalsy();
    expect(scanPayload.hasFindings).toBe(true);
    expect(scanPayload.findings[0]).toMatchObject({
      file: "input.env",
      ruleId: "fake-token",
    });
    expect(JSON.stringify(scanPayload)).not.toContain(SECRET);

    const history = await client.callTool({
      name: "scan_git_history",
      arguments: { path: "." },
    });
    const historyPayload = parsePayload(history);

    expect(history.isError).toBe(true);
    expect(historyPayload).toMatchObject({
      status: "disabled",
      code: "HISTORY_DISABLED",
    });
  });

  it("returns tool errors for incomplete file coverage", async () => {
    const { client, root } = await startClient(["--max-file-size", "1"]);
    writeFileSync(path.join(root, "input.env"), `API_TOKEN=${SECRET}`);

    const result = await client.callTool({
      name: "scan_file",
      arguments: { path: "input.env" },
    });
    const payload = parsePayload(result);

    expect(result.isError).toBe(true);
    expect(payload).toMatchObject({
      status: "incomplete",
      code: "INCOMPLETE_SCAN",
      incomplete: true,
      skippedByPolicy: true,
    });
    expect(payload.stats).toMatchObject({ oversizedSkipped: 1 });
  });
});

async function startClient(extraArgs = []) {
  const root = makeTempDir();
  const rulesFile = path.join(root, "rules.toml");
  writeFileSync(rulesFile, RULES);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN_PATH, "--root", root, "--rules-file", rulesFile, ...extraArgs],
    stderr: "pipe",
  });
  const client = new Client({ name: "mcp-test", version: "0.1.0" });
  await client.connect(transport);
  clients.push(client);
  return { client, root };
}

function makeTempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "rsecrets-mcp-"));
  tempDirs.push(dir);
  return dir;
}

function parsePayload(result) {
  const text = result.content.find((item) => item.type === "text")?.text;
  return JSON.parse(text);
}
