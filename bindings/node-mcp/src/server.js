import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const DEFAULT_LIMITS = Object.freeze({
  maxFileSize: 2 * 1024 * 1024,
  maxFiles: 5000,
  maxFindings: 1000,
  maxFindingsPerFile: 100,
  maxMatchedLen: 256,
  historyTimeoutSecs: 30,
});

const BINARY_POLICIES = ["auto", "skip", "scan"];
const WORKSPACE_MODES = ["walk", "git-tracked", "changed-files", "staged"];

const nonNegativeSafeInteger = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);

const capInputSchema = {
  maxFileSize: nonNegativeSafeInteger.optional(),
  maxFiles: nonNegativeSafeInteger.optional(),
  maxFindings: nonNegativeSafeInteger.optional(),
  maxFindingsPerFile: nonNegativeSafeInteger.optional(),
};

const binaryPolicySchema = z.enum(BINARY_POLICIES);

export function parseArgs(argv, cwd = process.cwd(), env = process.env) {
  const parsed = {
    root: cwd,
    enableHistory: false,
    historyLogOpts: [],
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "--root":
        parsed.root = readValue(argv, ++index, arg);
        break;
      case "--rules-file":
        parsed.rulesFile = readValue(argv, ++index, arg);
        break;
      case "--enable-history":
        parsed.enableHistory = true;
        break;
      case "--history-log-opt":
        parsed.historyLogOpts.push(readValue(argv, ++index, arg, { allowHyphen: true }));
        break;
      case "--max-file-size":
        parsed.maxFileSize = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--max-files":
        parsed.maxFiles = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--max-findings":
        parsed.maxFindings = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--max-findings-per-file":
        parsed.maxFindingsPerFile = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--max-matched-len":
        parsed.maxMatchedLen = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--history-timeout-secs":
        parsed.historyTimeoutSecs = parseLimit(readValue(argv, ++index, arg), arg);
        break;
      case "--help":
      case "-h":
        parsed.help = true;
        break;
      default:
        throw new Error(`unknown option: ${arg}`);
    }
  }

  parsed.maxFileSize ??= envLimit(env.RSECRETS_MAX_FILE_SIZE, "RSECRETS_MAX_FILE_SIZE");
  parsed.maxFiles ??= envLimit(env.RSECRETS_MAX_FILES, "RSECRETS_MAX_FILES");
  parsed.maxFindings ??= envLimit(env.RSECRETS_MAX_FINDINGS, "RSECRETS_MAX_FINDINGS");
  parsed.maxFindingsPerFile ??= envLimit(
    env.RSECRETS_MAX_FINDINGS_PER_FILE,
    "RSECRETS_MAX_FINDINGS_PER_FILE"
  );
  parsed.maxMatchedLen ??= envLimit(env.RSECRETS_MAX_MATCHED_LEN, "RSECRETS_MAX_MATCHED_LEN");
  parsed.historyTimeoutSecs ??= envLimit(
    env.RSECRETS_HISTORY_TIMEOUT_SECS,
    "RSECRETS_HISTORY_TIMEOUT_SECS"
  );

  return parsed;
}

export function normalizeOptions(options = {}) {
  const rawRoot = path.resolve(options.root ?? process.cwd());
  if (!fs.existsSync(rawRoot)) {
    throw new Error(`root does not exist: ${rawRoot}`);
  }
  const root = realpathIfExists(rawRoot);
  if (!fs.existsSync(root)) {
    throw new Error(`root does not exist: ${root}`);
  }

  return {
    root,
    rulesFile: options.rulesFile ? path.resolve(options.rulesFile) : undefined,
    enableHistory: Boolean(options.enableHistory),
    historyLogOpts: [...(options.historyLogOpts ?? [])],
    limits: {
      maxFileSize: options.maxFileSize ?? DEFAULT_LIMITS.maxFileSize,
      maxFiles: options.maxFiles ?? DEFAULT_LIMITS.maxFiles,
      maxFindings: options.maxFindings ?? DEFAULT_LIMITS.maxFindings,
      maxFindingsPerFile:
        options.maxFindingsPerFile ?? DEFAULT_LIMITS.maxFindingsPerFile,
      maxMatchedLen: options.maxMatchedLen ?? DEFAULT_LIMITS.maxMatchedLen,
      historyTimeoutSecs:
        options.historyTimeoutSecs ?? DEFAULT_LIMITS.historyTimeoutSecs,
    },
  };
}

export function createServer(rawOptions = {}) {
  const options = normalizeOptions(rawOptions);
  const server = new McpServer({
    name: "rsecrets-scanner",
    version: "0.1.0",
  });

  server.registerTool(
    "redact_text",
    {
      description: "Detect and redact secrets in untrusted text.",
      inputSchema: {
        content: z.string(),
        pathHint: z.string().optional(),
        maxFileSize: nonNegativeSafeInteger.optional(),
        maxFindingsPerFile: nonNegativeSafeInteger.optional(),
      },
    },
    async (input) => runTextTool(options, input, { includeRedacted: true })
  );

  server.registerTool(
    "scan_text",
    {
      description: "Detect secrets in untrusted text and return safe metadata only.",
      inputSchema: {
        content: z.string(),
        pathHint: z.string().optional(),
        maxFileSize: nonNegativeSafeInteger.optional(),
        maxFindingsPerFile: nonNegativeSafeInteger.optional(),
      },
    },
    async (input) => runTextTool(options, input, { includeRedacted: false })
  );

  server.registerTool(
    "scan_file",
    {
      description: "Scan one file under the configured root.",
      inputSchema: {
        path: z.string(),
        binaryPolicy: binaryPolicySchema.optional(),
        ...capInputSchema,
      },
    },
    async (input) => runPathTool(options, input, { fileOnly: true })
  );

  server.registerTool(
    "scan_workspace",
    {
      description: "Scan a workspace path under the configured root.",
      inputSchema: {
        path: z.string().optional(),
        mode: z.enum(WORKSPACE_MODES).optional(),
        base: z.string().optional(),
        includeUntracked: z.boolean().optional(),
        binaryPolicy: binaryPolicySchema.optional(),
        ...capInputSchema,
      },
    },
    async (input) => runPathTool(options, input, { fileOnly: false })
  );

  server.registerTool(
    "scan_git_history",
    {
      description: "Scan git history under the configured root when enabled at startup.",
      inputSchema: {
        path: z.string().optional(),
        all: z.boolean().optional(),
        binaryPolicy: binaryPolicySchema.optional(),
        historyTimeoutSecs: nonNegativeSafeInteger.optional(),
        ...capInputSchema,
      },
    },
    async (input) => runHistoryTool(options, input)
  );

  return server;
}

export async function main(argv = process.argv.slice(2)) {
  const parsed = parseArgs(argv);
  if (parsed.help) {
    process.stdout.write(helpText());
    return;
  }

  const server = createServer(parsed);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

export function helpText() {
  return `Usage: rsecrets-scanner-mcp --root <path> [options]

Options:
  --root <path>                   Root directory tools may scan.
  --rules-file <path>             Operator-controlled rules file.
  --enable-history                Enable the scan_git_history tool.
  --history-log-opt <opt>         Operator-controlled git log option, repeatable.
  --history-timeout-secs <n>      Max history scan seconds.
  --max-file-size <n>             Startup cap for scanned input bytes.
  --max-files <n>                 Startup cap for scanned files.
  --max-findings <n>              Startup cap for total findings.
  --max-findings-per-file <n>     Startup cap for findings per file.
  --max-matched-len <n>           Startup cap for returned matched length.
`;
}

async function runTextTool(options, input, { includeRedacted }) {
  try {
    const caps = mergeCaps(options.limits, input, [
      "maxFileSize",
      "maxFindingsPerFile",
      "maxMatchedLen",
    ]);
    const scanner = buildScanner(options, {
      proxy: true,
      maxFileSize: caps.maxFileSize,
      maxFindingsPerFile: caps.maxFindingsPerFile,
      maxMatchedLen: caps.maxMatchedLen,
    });
    const result = await scanner.scanProxyAsync(Buffer.from(input.content, "utf8"));
    const payload = {
      status: "ok",
      hasFindings: result.hasFindings,
      findingsTruncated: result.findingsTruncated,
      pathHint: input.pathHint ?? "<proxy>",
      findings: result.findings.map((finding) => safeFinding(finding, options)),
    };
    if (includeRedacted) {
      payload.redacted = Buffer.from(result.redacted).toString("utf8");
    }
    return jsonToolResult(payload);
  } catch (error) {
    return scannerErrorResult(error);
  }
}

async function runPathTool(options, input, { fileOnly }) {
  try {
    const scanPath = resolveInsideRoot(options.root, input.path ?? ".");
    const config = normalScanConfig(
      options,
      input,
      fileOnly ? {} : workspaceModeConfig(input)
    );
    const scanner = buildScanner(options, config);
    const result = fileOnly
      ? await scanner.scanFileStrictAsync(scanPath)
      : await scanner.scanPathStrictAsync(scanPath);

    return pathToolResult(result, options);
  } catch (error) {
    return scannerErrorResult(error);
  }
}

async function runHistoryTool(options, input) {
  if (!options.enableHistory) {
    return jsonToolResult(
      {
        status: "disabled",
        code: "HISTORY_DISABLED",
        message: "scan_git_history requires --enable-history at server startup",
      },
      true
    );
  }

  try {
    const scanPath = resolveInsideRoot(options.root, input.path ?? ".");
    const historyTimeoutSecs = clampLimit(
      input.historyTimeoutSecs,
      options.limits.historyTimeoutSecs
    );
    const config = normalScanConfig(options, input, {
      gitHistory: true,
      historyAll: input.all === true,
      historyFull: true,
      historyLogOpts: options.historyLogOpts,
      historyTimeoutSecs,
    });
    const scanner = buildScanner(options, config);
    const result = await scanner.scanPathStrictAsync(scanPath);

    return pathToolResult(result, options);
  } catch (error) {
    return scannerErrorResult(error);
  }
}

function buildScanner(options, config) {
  if (options.rulesFile) {
    return Scanner.fromRulesFile(options.rulesFile, config);
  }
  return Scanner.fromDefaultRules(config);
}

function normalScanConfig(options, input, modeConfig) {
  const caps = mergeCaps(options.limits, input, [
    "maxFileSize",
    "maxFiles",
    "maxFindings",
    "maxFindingsPerFile",
  ]);

  return {
    redact: true,
    captureContext: false,
    binaryPolicy: input.binaryPolicy ?? "auto",
    maxFileSize: caps.maxFileSize,
    maxFiles: caps.maxFiles,
    maxFindings: caps.maxFindings,
    maxFindingsPerFile: caps.maxFindingsPerFile,
    ...modeConfig,
  };
}

function workspaceModeConfig(input) {
  const mode = input.mode ?? "git-tracked";
  if (input.base && mode !== "changed-files") {
    throw scannerToolError(
      "INVALID_ARGUMENT",
      "base is only valid with mode changed-files"
    );
  }
  if (input.includeUntracked && mode !== "git-tracked" && mode !== "changed-files") {
    throw scannerToolError(
      "INVALID_ARGUMENT",
      "includeUntracked requires mode git-tracked or changed-files"
    );
  }

  switch (mode) {
    case "walk":
      return {};
    case "git-tracked":
      return {
        gitTracked: true,
        includeUntracked: input.includeUntracked === true,
      };
    case "changed-files":
      return {
        changedFiles: true,
        base: input.base,
        includeUntracked: input.includeUntracked === true,
      };
    case "staged":
      return { gitStaged: true };
    default:
      throw scannerToolError("INVALID_ARGUMENT", `unsupported workspace mode: ${mode}`);
  }
}

export function resolveInsideRoot(root, userPath = ".") {
  const resolved = path.resolve(root, userPath);
  const rel = path.relative(root, resolved);
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw scannerToolError("PATH_OUTSIDE_ROOT", "path escapes configured root");
  }

  if (fs.existsSync(resolved)) {
    const realRoot = realpathIfExists(root);
    const realResolved = realpathIfExists(resolved);
    const realRel = path.relative(realRoot, realResolved);
    if (
      realRel === ".." ||
      realRel.startsWith(`..${path.sep}`) ||
      path.isAbsolute(realRel)
    ) {
      throw scannerToolError("PATH_OUTSIDE_ROOT", "path escapes configured root");
    }
    return realResolved;
  }

  return resolved;
}

export function safeFinding(finding, options = {}) {
  return {
    file: safeFilePath(finding.file, options.root),
    line: finding.line,
    col: finding.col,
    endLine: finding.endLine,
    endCol: finding.endCol,
    colUtf16: finding.colUtf16,
    endColUtf16: finding.endColUtf16,
    ruleId: finding.ruleId,
    description: finding.description,
    entropy: finding.entropy,
    startOffset: finding.startOffset,
    endOffset: finding.endOffset,
    secretStartOffset: finding.secretStartOffset,
    secretEndOffset: finding.secretEndOffset,
    fingerprint: finding.fingerprint,
    commit: finding.commit,
  };
}

export function mergeCaps(limits, input, fields) {
  const merged = {};
  for (const field of fields) {
    merged[field] = clampLimit(input[field], limits[field]);
  }
  return merged;
}

function pathToolResult(result, options) {
  const payload = {
    status: result.findingsTruncated ? "truncated" : "ok",
    hasFindings: result.hasFindings,
    findingsTruncated: result.findingsTruncated,
    stats: result.stats,
    incomplete: result.incomplete,
    skippedByPolicy: result.skippedByPolicy,
    findings: result.findings.map((finding) => safeFinding(finding, options)),
  };
  const isError = result.incomplete || result.findingsTruncated;
  if (result.incomplete) {
    payload.status = "incomplete";
  }
  return jsonToolResult(payload, isError);
}

function scannerErrorResult(error) {
  const code = error && error.code ? error.code : "MCP_TOOL_ERROR";
  const stats = error && error.details && error.details.stats;
  return jsonToolResult(
    {
      status: code === "INCOMPLETE_SCAN" ? "incomplete" : "error",
      code,
      message: safeErrorMessage(code),
      stats,
      incomplete: code === "INCOMPLETE_SCAN",
      skippedByPolicy: stats
        ? (stats.binarySkipped ?? 0) + (stats.oversizedSkipped ?? 0) > 0
        : false,
    },
    true
  );
}

function jsonToolResult(payload, isError = false) {
  return {
    isError,
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function safeErrorMessage(code) {
  switch (code) {
    case "INPUT_TOO_LARGE":
      return "input exceeds configured maxFileSize";
    case "NOT_HARDENED":
      return "scanner is not hardened for proxy use";
    case "INCOMPLETE_SCAN":
      return "scan coverage is incomplete";
    case "PATH_OUTSIDE_ROOT":
      return "path escapes configured root";
    case "INVALID_ARGUMENT":
    case "INVALID_CONFIG":
      return "tool arguments are invalid";
    default:
      return "scanner tool failed";
  }
}

function safeFilePath(filePath, root) {
  if (!root || !filePath || filePath.startsWith("<")) {
    return filePath;
  }
  const rel = path.relative(root, path.resolve(filePath));
  if (rel && !rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel)) {
    return rel;
  }
  return filePath;
}

function scannerToolError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function clampLimit(requested, max) {
  if (requested == null) {
    return max;
  }
  return Math.min(requested, max);
}

function readValue(argv, index, flag, { allowHyphen = false } = {}) {
  const value = argv[index];
  if (value == null || (!allowHyphen && value.startsWith("--"))) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseLimit(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return parsed;
}

function envLimit(value, name) {
  if (value == null || value === "") {
    return undefined;
  }
  return parseLimit(value, name);
}

function realpathIfExists(value) {
  return fs.realpathSync.native ? fs.realpathSync.native(value) : fs.realpathSync(value);
}
