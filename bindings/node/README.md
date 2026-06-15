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
