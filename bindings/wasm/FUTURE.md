# WASM Future Work

This package is intentionally browser/edge only. Future work should preserve the
v1 boundary: in-memory scan, redaction, and proxy APIs only. Do not add path
scanning, git modes, updater behavior, rules cache reads, or CLI behavior here.

## Current Measurements

Latest measured browser build:

- `rsecrets_scanner_wasm_bg.wasm`: 1,636,277 bytes raw
- Gzipped WASM: 532,753 bytes
- Gzipped JS wrapper: 3,569 bytes

Latest Node probe:

- `Scanner.bundled()` construction: about 2 seconds
- `Scanner.bundled()` RSS delta: about 630 MB
- `Scanner.fromToml()` with one focused rule: about 0.2 ms construction

The high memory cost is the compiled bundled rule engine. Native dependency
gating and wasm-opt tuning improved dependency surface and binary size, but did
not materially reduce bundled construction memory.

## Priority 1: Keep The WASM Dependency Graph Small

Keep `secrets_scanner = { default-features = false }` in this package. The WASM
test suite should continue to reject native-only crates such as `agent-config`,
`clap`, `env_logger`, `libc`, `rayon`, `serde_json`, `ureq`, and `walkdir`.

Add any new native dependency behind the root crate's `native` feature unless it
is required by in-memory scanning.

## Priority 2: Decide Whether To Add A Lite Ruleset

A smaller browser ruleset is the most likely way to reduce memory and startup
time without risky engine changes. Possible API:

```js
const scanner = Scanner.lite();
```

Tradeoff: this weakens coverage. Do not ship it as a silent replacement for
`Scanner.bundled()`. If added, document the rule-selection policy and keep the
full bundled scanner available.

Useful acceptance criteria:

- Size and memory budget documented before implementation.
- Rule count and excluded source families documented.
- Tests prove full and lite scanners produce different, expected coverage.

## Priority 3: Investigate Lazy Regex Compilation

The bundled scanner currently pays the compile cost up front. Lazy compilation
could reduce construction memory and time by compiling candidate rules on first
keyword hit.

Risks:

- First scan for a new candidate may become slower.
- Shared Rust engine behavior changes, not just WASM.
- Cache invalidation and thread-safety need careful review for native builds.

Only pursue this with a benchmark harness and parity tests against eager
compilation.

## Priority 4: Add Browser Benchmarks And Budgets

Add a repeatable benchmark script under this package for:

- Raw and gzipped WASM size.
- `Scanner.bundled()` construction time and memory.
- `Scanner.fromToml()` construction time.
- Clean scan throughput.
- Positive scan throughput with many findings.

Use the script before changing optimizer flags, rule loading, or the engine.
The quick experiments tried so far:

- `wasm-opt -Oz`: smaller than `-O4`, but slower in the positive-scan probe.
- Aho-Corasick NFA for WASM: no meaningful memory reduction, slower construction
  and positive scans.
- LTO plus `wasm-opt -O4`: best measured default so far.

## Priority 5: Worker-First Integration Example

Because `Scanner.bundled()` is heavy, browser integrations should construct it
once, preferably inside a Web Worker, and reuse it. Add an example only after the
core package API is stable enough that the example will not become a compatibility
burden.

## Priority 6: Security Hardening Follow-Ups

Keep proxy defaults fail-closed for untrusted payloads:

- Full redaction only.
- No allow markers.
- Bounded input size.
- Bounded finding count.
- No raw secret material in thrown errors or result fields.

Future tests worth adding:

- JS-side regression test that oversized `Uint8Array` input is rejected without
  allocating a copied Rust buffer.
- Fuzz or property tests for config decoding from `JsValue`.
- Browser test that proxy redaction does not leak raw bytes for invalid UTF-8.

## Explicitly Out Of Scope For v1

- WASI CLI.
- Browser filesystem traversal.
- Git scanning.
- Runtime updater or cache loading.
- Automatic fallback from the native Node package to WASM.
