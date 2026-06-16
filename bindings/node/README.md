# @whit3rabbit/rsecrets-scanner

Native Node.js bindings for the Rust `secrets_scanner` crate.

This is the Node library package. It is not the `secrets-scanner` CLI package
and it does not install a `secrets-scanner` binary. Use the root project
installers when you need the CLI.

For MCP clients, use the separate same-repo package:

```bash
npx -y @whit3rabbit/rsecrets-scanner-mcp --root /path/to/project
```

## Install

```bash
npm install @whit3rabbit/rsecrets-scanner
```

The package requires Node.js 18 or newer.

The current package shape ships a native `.node` artifact built for the publish
target. A full per-platform optional-package matrix is still separate release
work. If no published artifact matches your platform, build from a source
checkout:

```bash
git clone https://github.com/whit3rabbit/secrets-scanner.git
cd secrets-scanner/bindings/node
npm install
npm run build
npm test
```

`npm run build` emits `secrets_scanner_core.node`, which `index.js` loads at
runtime.

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

`Scanner.fromDefaultRules()` follows the Rust three-tier rule lookup:
`SECRETS_SCANNER_RULES`, then the OS data-dir cache, then bundled rules.
`Scanner.bundled()` uses only the compile-time bundled rules.

## Basic Use

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.bundled();
const result = scanner.scanAndRedactContent(
  "prompt.txt",
  "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567"
);

if (result.hasFindings) {
  // Decide whether to block, audit, or forward result.redacted.
}
```

Redaction is enabled by default for returned findings. The `scanAndRedact*`
methods always return forwardable redacted content. Redaction uses the full
pre-cap finding set, so `findingsTruncated: true` means only the returned
finding list was capped; the redacted payload still covers every detected
secret.

Use `scanContentDetailed()` / `scanBytesDetailed()` when callers need
`hasFindings` and `findingsTruncated`. The compatibility-first
`scanContent()` / `scanBytes()` methods return only `Finding[]`.

## Proxy Use

For attacker-controlled in-memory content, use the hardened proxy preset:

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });
const result = scanner.scanProxy(
  Buffer.from("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567")
);

if (result.hasFindings) {
  const safePayload = Buffer.from(result.redacted).toString("utf8");
  // Forward safePayload instead of the original input.
}
```

This mirrors Rust `ScanConfig::proxy()` and `Scanner::scan_proxy()`:

- `scanProxy()` fails closed with `INPUT_TOO_LARGE` when input exceeds
  `maxFileSize`.
- `scanProxy()` fails closed with `NOT_HARDENED` unless the scanner was built
  with `Scanner.proxy()` or `{ proxy: true }`.
- Inline allow markers are ignored, context capture is disabled, findings are
  capped, short `matched` values are fully redacted, and long `matched` values
  are replaced with a fixed omission marker.
- Proxy config accepts only `minEntropy`, `maxFileSize`,
  `maxFindingsPerFile`, and `maxMatchedLen`.

Custom-rule constructors can use the same hardened mode:

```js
const scanner = Scanner.fromToml(customRulesToml, { proxy: true });
```

## Path Scans

`scanFile()` and `scanPath()` return findings plus safe coverage stats:

```js
const result = Scanner.fromDefaultRules({ gitTracked: true }).scanPath(".");

if (result.incomplete) {
  // Unreadable files, oversized skips, git failure, git fallback, or a file cap
  // reduced coverage.
}
```

Use `scanFileStrict()` / `scanPathStrict()` or their async variants when partial
coverage should throw `INCOMPLETE_SCAN`.

`maxFindings` is a total-result cap for path, git, staged, and history scans.
For in-memory `scanContent*()` and `scanBytes*()` calls, use
`maxFindingsPerFile`.

Set `captureContext: false` for server-style path scans that should return
locations and findings without surrounding source lines. Set
`historyTimeoutSecs` with `gitHistory: true` to bound history scans.

## Async Methods

Every scan method has an `Async` form that returns a Promise, for example
`scanAndRedactContentAsync()` and `scanProxyAsync()`. Use these in Node servers
when scanning large payloads or paths so the event loop is not blocked.

## Errors

Errors expose a stable `error.code`:

- `INPUT_TOO_LARGE`
- `NOT_HARDENED`
- `INVALID_CONFIG`
- `INVALID_ARGUMENT`
- `INVALID_RULES`
- `INVALID_RULES_TOML`
- `INCOMPLETE_SCAN`
- `NATIVE_BINDING_NOT_FOUND`

Some errors include safe `error.details`, such as proxy input sizes or path scan
stats. Matched secret bytes are not included in those details.

## TypeScript

The package publishes `public.d.ts` as its public type surface. It is a
CommonJS package:

```ts
import { Scanner } from "@whit3rabbit/rsecrets-scanner";
```

Keep `public.d.ts`, `index.js`, and `bindings/node/src/lib.rs` aligned when the
API changes.
