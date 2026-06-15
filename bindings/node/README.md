# @whit3rabbit/rsecrets-scanner

Native Node.js bindings for the Rust `secrets-scanner` engine.

This package is the core binding only. MCP server packaging is intentionally a
follow-up layer over this API.

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

Redaction is enabled by default for findings. The `scanAndRedact*` methods
always return redacted content suitable for forwarding. Redaction uses the full
pre-cap finding set, so `findingsTruncated: true` means only the returned
finding list was capped; the redacted payload still covers every detected
secret.

For attacker-controlled in-memory content, use the hardened proxy preset and
`scanProxy()`. It fails closed when input exceeds `maxFileSize`, ignores inline
allow markers, skips context capture, and returns redacted bytes for forwarding.
Custom-rule constructors may also use `{ proxy: true }`; that direct proxy
config accepts only `minEntropy`, `maxFileSize`, `maxFindingsPerFile`, and
`maxMatchedLen`.

```js
const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });
const result = scanner.scanProxy(Buffer.from("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567"));

if (result.hasFindings) {
  const safePayload = Buffer.from(result.redacted).toString("utf8");
  // Forward safePayload instead of the original input.
}
```

Plain in-memory scans also enforce `maxFileSize` in this binding. Use
`scanContentDetailed()` / `scanBytesDetailed()` when callers need
`findingsTruncated`, and use the `*Async()` variants in Node servers to avoid
blocking the event loop on large payloads.

`scanFile()` and `scanPath()` return findings plus coverage stats. Treat
`result.incomplete` as a coverage warning: unreadable files, `maxFiles`, git
fallback, or git failure mean the scan did not fully cover the requested scope.
For CI-style consumers that should never ignore partial coverage, use
`scanFileStrict()` / `scanPathStrict()` or their async variants; they throw
`INCOMPLETE_SCAN` with safe `stats` details when coverage is incomplete.

The public wrapper is strict about argument types. Paths, TOML, and string
content must be strings; byte content must be a `Uint8Array`. Bad values throw
with `error.code` set to `INVALID_ARGUMENT` or `INVALID_CONFIG` instead of being
coerced with `String(...)`.

This package still ships the built host `.node` artifact only. Broad npm
distribution needs a separate per-platform prebuild or optional-package release
matrix.
