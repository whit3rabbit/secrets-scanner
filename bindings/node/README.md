# @secrets-scanner/core

Native Node.js bindings for the Rust `secrets-scanner` engine.

This package is the core binding only. MCP server packaging is intentionally a
follow-up layer over this API.

```js
const { Scanner } = require("@secrets-scanner/core");

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
always return redacted content suitable for forwarding.

For attacker-controlled in-memory content, use the hardened proxy preset and
`scanProxy()`. It fails closed when input exceeds `maxFileSize`, ignores inline
allow markers, skips context capture, and returns redacted bytes for forwarding.

```js
const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });
const result = scanner.scanProxy(Buffer.from("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567"));

if (result.hasFindings) {
  const safePayload = Buffer.from(result.redacted).toString("utf8");
  // Forward safePayload instead of the original input.
}
```
