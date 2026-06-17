# @whit3rabbit/rsecrets-scanner

Native Node.js bindings for the Rust
[`secrets_scanner`](https://github.com/whit3rabbit/secrets-scanner) crate.

Use this package when a Node.js or TypeScript app needs in-process secret
scanning, redaction, or proxy filtering. Use the
[`secrets-scanner`](https://github.com/whit3rabbit/secrets-scanner) CLI when you
need a command-line tool or git hook.

For MCP clients, use the separate same-repo package:

```bash
npx -y @whit3rabbit/rsecrets-scanner-mcp --root /path/to/project
```

## Links

- Rust repository: <https://github.com/whit3rabbit/secrets-scanner>
- Rust scanner docs and CLI guide:
  <https://github.com/whit3rabbit/secrets-scanner#readme>
- Node binding source:
  <https://github.com/whit3rabbit/secrets-scanner/tree/main/bindings/node>
- Public TypeScript API:
  <https://github.com/whit3rabbit/secrets-scanner/blob/main/bindings/node/public.d.ts>
- Node.js CommonJS modules:
  <https://nodejs.org/api/modules.html>
- Node.js buffers and binary data:
  <https://nodejs.org/api/buffer.html>
- Node.js HTTP servers:
  <https://nodejs.org/api/http.html>
- TypeScript Node.js guide:
  <https://www.typescriptlang.org/docs/handbook/modules/reference.html>
- NAPI-RS, the native addon layer:
  <https://napi.rs/>

## Install

```bash
npm install @whit3rabbit/rsecrets-scanner
```

Requirements:

- Node.js 18 or newer.
- A supported platform: macOS (arm64 or x64), Linux glibc (x64 or arm64), or
  Windows (x64).

The package bundles a prebuilt native addon for every supported platform and
loads the matching one at runtime — no optional packages and no post-install
build step.

If no bundled artifact matches your platform (for example musl/Alpine Linux),
build from source:

```bash
git clone https://github.com/whit3rabbit/secrets-scanner.git
cd secrets-scanner/bindings/node
npm install
npm run build
npm test
```

`npm run build` emits `secrets_scanner_core.node`, which `index.js` loads at
runtime. If loading fails, the package throws `NATIVE_BINDING_NOT_FOUND` with
candidate paths in `error.details`.

## Package Shape

This package is CommonJS at runtime and ships hand-written TypeScript types in
`public.d.ts`.

CommonJS:

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");
```

TypeScript compiled to CommonJS:

```ts
import { Scanner, type ScanResult } from "@whit3rabbit/rsecrets-scanner";

const scanner = Scanner.bundled();
const result: ScanResult = scanner.scanContentDetailed("input.txt", "hello");
```

Native ESM projects can load the CommonJS package with `createRequire`:

```ts
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Scanner } = require("@whit3rabbit/rsecrets-scanner") as typeof import(
  "@whit3rabbit/rsecrets-scanner"
);
```

## Choose A Scanner

| Factory | Use when |
|---|---|
| `Scanner.bundled(config?)` | You want deterministic compile-time bundled rules. |
| `Scanner.fromDefaultRules(config?)` | You want the same rule lookup as the CLI: `SECRETS_SCANNER_RULES`, then OS data-dir cache, then bundled rules. |
| `Scanner.fromRulesFile(path, config?)` | You want to load a TOML rules file from disk. |
| `Scanner.fromToml(toml, config?)` | You want to load custom TOML rules from a string. |
| `Scanner.proxy(config?)` | You are scanning attacker-controlled in-memory content before forwarding it. |

`Scanner.proxy()` is the safe default for request bodies, tool payloads, LLM
messages, and other untrusted buffers. It ignores inline allow markers, disables
context capture, caps findings, and fully redacts `matched`.

## Choose A Method

| Method | Input | Output |
|---|---|---|
| `scanContent(path, text)` | String content | `Finding[]` |
| `scanContentDetailed(path, text)` | String content | `ScanResult` with `hasFindings` and `findingsTruncated` |
| `scanAndRedactContent(path, text)` | String content | `StringRedactionResult` |
| `scanBytes(path, bytes)` | `Uint8Array` content | `Finding[]` |
| `scanBytesDetailed(path, bytes)` | `Uint8Array` content | `ScanResult` |
| `scanAndRedactBytes(path, bytes)` | `Uint8Array` content | `BytesRedactionResult` |
| `scanProxy(bytes)` | Hardened proxy `Uint8Array` | `BytesRedactionResult` |
| `scanFile(path)` | One filesystem path | `PathScanResult` |
| `scanPath(path)` | File or directory path | `PathScanResult` |
| `scanFileStrict(path)` | One filesystem path | Throws `INCOMPLETE_SCAN` if coverage is incomplete |
| `scanPathStrict(path)` | File or directory path | Throws `INCOMPLETE_SCAN` if coverage is incomplete |

Every scan method also has an async form with an `Async` suffix. Use async
methods in servers and CLIs that may scan large inputs or directories.

## Basic Redaction

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.bundled();
const result = scanner.scanAndRedactContent(
  "prompt.txt",
  "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567"
);

if (result.hasFindings) {
  console.log(result.redacted);
}
```

Returned findings are redacted by default. The `scanAndRedact*` methods always
return forwardable redacted content.

Redaction is built from the full pre-cap finding set. If
`findingsTruncated: true`, only the returned finding list was capped. The
redacted payload still covers every detected secret.

## Hardened Proxy Scans

Use proxy scans for untrusted in-memory content. This is the right posture for
LLM prompts, agent tool input, webhooks, and API requests that may contain
attacker-controlled allow markers.

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.proxy({
  maxFileSize: 1024 * 1024,
  maxFindingsPerFile: 20,
  maxMatchedLen: 256,
});

const result = await scanner.scanProxyAsync(
  Buffer.from("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567")
);

if (result.hasFindings) {
  const safePayload = Buffer.from(result.redacted).toString("utf8");
  // Forward safePayload, reject the request, or audit without raw secrets.
}
```

`scanProxy()` throws `NOT_HARDENED` unless the scanner was created with
`Scanner.proxy()` or `{ proxy: true }`. It throws `INPUT_TOO_LARGE` when input
exceeds `maxFileSize`.

Custom rules can use the same hardened mode:

```js
const customRulesToml = `
title = "custom"

[[rules]]
id = "demo-token"
description = "Demo token"
regex = 'demo_[A-Za-z0-9]{16,}'
keywords = ["demo_"]
`;

const scanner = Scanner.fromToml(customRulesToml, { proxy: true });
```

## Path And Git Scans

Path scans return findings plus coverage stats:

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.fromDefaultRules({
  gitTracked: true,
  captureContext: false,
});

const result = await scanner.scanPathStrictAsync(".");

if (result.hasFindings) {
  process.exitCode = 1;
}
```

Use strict path methods when partial coverage should fail the call. Non-strict
methods return `result.incomplete` and `result.skippedByPolicy` so callers can
make their own policy decision.

Common git modes:

```js
Scanner.fromDefaultRules({ gitTracked: true }).scanPath(".");
Scanner.fromDefaultRules({ gitStaged: true }).scanPath(".");
Scanner.fromDefaultRules({ changedFiles: true, base: "origin/main" }).scanPath(".");
Scanner.fromDefaultRules({ gitHistory: true, historyAll: true }).scanPath(".");
```

`gitHistory` can be expensive. Set `historyTimeoutSecs` when scanning large
repositories from a server or CI job.

## Express Middleware

```ts
import express from "express";
import { Scanner } from "@whit3rabbit/rsecrets-scanner";

const app = express();
const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });

app.use(express.text({ type: "*/*", limit: "1mb" }));

app.post("/proxy", async (req, res, next) => {
  try {
    const result = await scanner.scanProxyAsync(Buffer.from(req.body, "utf8"));

    if (result.hasFindings) {
      return res.status(400).json({ error: "request contains a secret" });
    }

    res.locals.safeBody = Buffer.from(result.redacted).toString("utf8");
    return next();
  } catch (error) {
    return next(error);
  }
});
```

This example uses `express.text()` so the scanner sees the raw request body. If
you use `express.json()`, scan `Buffer.from(JSON.stringify(req.body))`.

## Fastify Hook

```ts
import Fastify from "fastify";
import { Scanner } from "@whit3rabbit/rsecrets-scanner";

const fastify = Fastify();
const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });

fastify.addHook("preHandler", async (request, reply) => {
  const payload = Buffer.from(JSON.stringify(request.body ?? {}), "utf8");
  const result = await scanner.scanProxyAsync(payload);

  if (result.hasFindings) {
    return reply.code(400).send({ error: "request contains a secret" });
  }
});
```

For raw-body Fastify setups, scan the raw `Buffer` directly. Keep framework body
limits at or below `maxFileSize` so the request is bounded before scanning.

## Next.js Route Handler

```ts
import { NextResponse, type NextRequest } from "next/server";
import { Scanner } from "@whit3rabbit/rsecrets-scanner";

export const runtime = "nodejs";

const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });

export async function POST(request: NextRequest) {
  const input = Buffer.from(await request.text(), "utf8");
  const result = await scanner.scanProxyAsync(input);

  if (result.hasFindings) {
    return NextResponse.json(
      { error: "request contains a secret" },
      { status: 400 }
    );
  }

  return NextResponse.json({ ok: true });
}
```

Native addons require the Node.js runtime. Do not run this package in the
Next.js Edge runtime.

## Node Script

```js
#!/usr/bin/env node
"use strict";

const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.fromDefaultRules({
  gitStaged: true,
  captureContext: false,
});

const result = scanner.scanPathStrict(".");

for (const finding of result.findings) {
  console.error(`${finding.file}:${finding.line}:${finding.col} ${finding.ruleId}`);
}

process.exitCode = result.hasFindings ? 1 : 0;
```

This is useful in npm scripts or custom CI steps:

```json
{
  "scripts": {
    "scan:secrets": "node scripts/scan-secrets.js"
  }
}
```

## Configuration

| Field | Notes |
|---|---|
| `redact` | Defaults to `true`. Set `false` only for trusted local debugging. |
| `redactionMode` | `"partial"` keeps first and last 4 chars. `"full"` returns `[REDACTED]`. |
| `minEntropy` | Raises rule entropy thresholds. It cannot weaken stricter rule thresholds. |
| `maxFileSize` | Bounds in-memory scans and file reads. Values must be positive safe integers. |
| `maxFindingsPerFile` | Cap for in-memory scans and per-file path findings. |
| `maxMatchedLen` | Maximum matched text length returned on findings. Proxy scans fully redact matches. |
| `binaryPolicy` | `"auto"`, `"skip"`, or `"scan"` for path scans. |
| `maxFiles` | Caps path traversal. |
| `maxFindings` | Total cap for path, git, staged, and history scans. |
| `gitTracked` | Scan git-tracked working-tree files. |
| `changedFiles` + `base` | Scan changed files, often relative to a base ref. |
| `gitStaged` | Scan staged index blob content. |
| `gitHistory` | Scan added lines from git history. |
| `historyAll` | Include all refs with `gitHistory`. |
| `historyLogOpts` | Extra trusted `git log` options. Each string is one argv entry. |
| `historyTimeoutSecs` | Stop history scans after a wall-clock budget. `0` means unlimited. |
| `includeUntracked` | Add untracked files to `gitTracked`, `changedFiles`, or `base` modes. |
| `gitFallbackWalk` | Fall back to directory walk if an explicit current-content git mode fails. |
| `captureContext` | Include context lines. Set `false` for server and CI output. |

Proxy config accepts only `minEntropy`, `maxFileSize`, `maxFindingsPerFile`, and
`maxMatchedLen`. Other fields are rejected because they could weaken or confuse
the hardened proxy posture.

## Errors

Errors expose a stable `error.code`:

- `ENGINE_BUILD`
- `INPUT_TOO_LARGE`
- `NOT_HARDENED`
- `POSITION_OVERFLOW`
- `INVALID_CONFIG`
- `INVALID_ARGUMENT`
- `INVALID_RULES`
- `INVALID_RULES_TOML`
- `IO`
- `INCOMPLETE_SCAN`
- `NATIVE_ERROR`
- `NATIVE_BINDING_NOT_FOUND`

Some errors include safe `error.details`, such as proxy input sizes or path scan
stats. Matched secret bytes are not included in those details.

## Rust API Mapping

The binding is a thin NAPI-RS layer over the Rust scanner implementation:

| Node API | Rust implementation |
|---|---|
| `Scanner.bundled()` | `secrets_scanner::Scanner::from_bundled()` |
| `Scanner.fromDefaultRules()` | `secrets_scanner::Scanner::new()` |
| `Scanner.fromRulesFile(path)` | `secrets_scanner::Scanner::from_file(path)` |
| `Scanner.fromToml(toml)` | `secrets_scanner::Scanner::from_toml(toml)` |
| `scanner.scanContent(path, text)` | `Scanner::scan_content(path, text)` |
| `scanner.scanBytes(path, bytes)` | `Scanner::scan_bytes(path, bytes)` |
| `scanner.scanAndRedactContent(path, text)` | `Scanner::scan_and_redact_content(path, text)` |
| `scanner.scanAndRedactBytes(path, bytes)` | `Scanner::scan_and_redact_bytes(path, bytes)` |
| `Scanner.proxy(config)` + `scanner.scanProxy(bytes)` | `ScanConfig::proxy()` + `Scanner::scan_proxy(bytes)` |
| `scanner.scanFile(path)` / `scanner.scanPath(path)` | `scan_file_with_stats(path)` / `scan_path_with_stats(path)` |

Keep `public.d.ts`, `index.js`, and `bindings/node/src/lib.rs` aligned when the
API changes.

## Local Development

```bash
cd bindings/node
npm install
npm run build
npm run typecheck
npm test
```

The root Rust crate is not a Cargo workspace member of this package. After
changing the Node binding, run checks inside `bindings/node`.
