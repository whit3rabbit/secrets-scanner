# @whit3rabbit/rsecrets-scanner-wasm

Browser and edge WebAssembly bindings for `secrets-scanner`.

This package exposes only in-memory scanning and redaction APIs. It does not
read files, shell out to git, use the rules cache, run the updater, or provide a
CLI.

## Build

```sh
npm run build --prefix bindings/wasm
```

The build runs:

```sh
wasm-pack build --target web --scope whit3rabbit --out-dir pkg --out-name rsecrets_scanner_wasm
```

For Node-based API tests:

```sh
PATH="$PWD/target/wasm-tools/bin:$PATH" npm test --prefix bindings/wasm
```

## Usage

```js
import init, { Scanner } from "@whit3rabbit/rsecrets-scanner-wasm";

await init();

const scanner = Scanner.bundled();
const findings = scanner.scanContent(
  "input.env",
  "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde"
);
```

For untrusted payload redaction, use the hardened proxy preset:

```js
const proxy = Scanner.proxy();
const result = proxy.scanProxy(
  new TextEncoder().encode(
    "TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde"
  )
);
const safe = new TextDecoder().decode(result.redacted);
```

## API

- `Scanner.bundled(config?)`
- `Scanner.fromToml(toml, config?)`
- `Scanner.proxy(config?)`
- `scanContent(path, content)`
- `scanContentDetailed(path, content)`
- `scanAndRedactContent(path, content)`
- `scanBytes(path, bytes)`
- `scanProxy(bytes)`

Supported config fields are `redact`, `redactionMode`, `minEntropy`,
`maxFileSize`, `maxFindingsPerFile`, `maxMatchedLen`, and `captureContext`.
`Scanner.proxy()` accepts only `minEntropy`, `maxFileSize`,
`maxFindingsPerFile`, and `maxMatchedLen`.

Native-only fields such as git modes, path caps, binary policy, and history
options are rejected with `INVALID_CONFIG`.

## Browser footprint

`Scanner.bundled()` compiles the full embedded ruleset in the browser runtime.
Construct it once and reuse it. For memory-constrained browser or edge contexts,
prefer `Scanner.fromToml()` with a focused ruleset when full bundled coverage is
not required.

The byte APIs check `maxFileSize` before copying input into WASM memory. The
package also builds `secrets-scanner` with default features disabled, so native
filesystem, git, updater, CLI, and installer dependencies are not included in
the WASM dependency graph.

See [FUTURE.md](./FUTURE.md) for the remaining size, memory, speed, and security
work that was identified during the first WASM build pass.
