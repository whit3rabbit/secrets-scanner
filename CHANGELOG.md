# Changelog

## v0.1.0 (2026-06-14)

Initial release.

### Core scanning
- Multi-layer scan pipeline: memchr SIMD pre-filter, Aho-Corasick keyword matching, Shannon entropy gating, regex capture
- Parallel file scanning with Rayon work-stealing
- Memory-mapped file support for large files
- Gitleaks-compatible TOML ruleset configuration
- Three-tier rule loading: env var, OS data dir cache, bundled defaults
- Runtime rule updater (HTTP download via `ureq`, feature-gated)
- Build-time TOML merge and validation

### CLI
- Subcommands: `scan`, `update-rules`, `validate-rules`, `list-rules`
- Output formats: text, JSON, JSONL, SARIF 2.1.0
- Configurable: custom rules path, rule exclusions, entropy threshold, file size cap, redaction toggle

### Rules engine
- Keyword-based Aho-Corasick automaton with case-insensitive matching
- Per-rule and global allowlists (paths, regexes, stopwords, conditions)
- `secretGroup` capture group extraction
- Regex validation with look-around detection and fallback
- Unkeyworded fallback rule evaluation with benchmark timing

### Quality
- `#[deny(clippy::unwrap_used)]` and `#[deny(missing_docs)]` enforced
- 40+ unit and integration tests
- CI matrix: Linux, macOS, Windows
