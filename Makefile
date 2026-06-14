# Makefile — secrets-scanner
# Common developer targets.  Run `make help` for a summary.

SHELL        := bash
BINARY       := secrets-scanner
CARGO        := cargo
FEATURES_UPD := --features updater
RULES_SCRIPT  := ./scripts/update_rules.sh
IMPORT_SCRIPT := ./scripts/import_secrets_patterns_db.py
KINGFISHER_DOWNLOAD := ./scripts/update_kingfisher_rules.py
KINGFISHER_CONVERT  := ./scripts/convert_kingfisher_rules.py

# ── colours ───────────────────────────────────────────────────────────────────
BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[0;32m
CYAN  := \033[0;36m

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT TARGET
# ─────────────────────────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@printf '$(BOLD)Usage:$(RESET)\n'
	@printf '  make $(CYAN)<target>$(RESET)\n\n'
	@printf '$(BOLD)Targets:$(RESET)\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-26s$(RESET) %s\n", $$1, $$2}'

# ─────────────────────────────────────────────────────────────────────────────
# BUILD
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: build
build: ## Build debug binary (no updater feature)
	$(CARGO) build

.PHONY: build-updater
build-updater: ## Build debug binary WITH runtime updater (ureq HTTP dep)
	$(CARGO) build $(FEATURES_UPD)

.PHONY: build-full
build-full: ## Build debug binary embedding the FULL ruleset (gitleaks+local+spdb)
	$(CARGO) build --features full-ruleset

.PHONY: release
release: ## Build optimised release binary (no updater feature)
	$(CARGO) build --release

.PHONY: release-updater
release-updater: ## Build optimised release binary WITH runtime updater
	$(CARGO) build --release $(FEATURES_UPD)

# ─────────────────────────────────────────────────────────────────────────────
# TEST & LINT
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: test
test: generate-fixtures ## Run all tests
	$(CARGO) test

.PHONY: test-updater
test-updater: generate-fixtures ## Run all tests including updater feature
	$(CARGO) test $(FEATURES_UPD)

.PHONY: clippy
clippy: ## Run clippy lints
	$(CARGO) clippy -- -D warnings

.PHONY: fmt
fmt: ## Auto-format source with rustfmt
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files (for CI)
	$(CARGO) fmt --check

.PHONY: check
check: ## Run cargo check (fast type-check, no binary output)
	$(CARGO) check

# ─────────────────────────────────────────────────────────────────────────────
# RULES — BUILD-TIME (shell script updates assets/gitleaks.toml)
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: update-rules
update-rules: ## Download latest gitleaks rules into assets/ (commits-ready)
	@chmod +x $(RULES_SCRIPT)
	$(RULES_SCRIPT)
	$(MAKE) validate-rules

.PHONY: check-rules
check-rules: ## Check if gitleaks rules are up to date (exit 1 = update available)
	@chmod +x $(RULES_SCRIPT)
	$(RULES_SCRIPT) --check

.PHONY: validate-rules
validate-rules: ## Validate rule TOML files in assets/
	$(CARGO) run $(FEATURES_UPD) --bin $(BINARY) -- validate-rules assets/gitleaks.toml assets/local.toml assets/secrets-scanner.toml

.PHONY: import-spdb
import-spdb: ## Download & deduplicate secrets-patterns-db rules → assets/secrets-patterns-db.toml
	python3 $(IMPORT_SCRIPT)
	$(MAKE) validate-rules

.PHONY: import-spdb-check
import-spdb-check: ## Dry-run import: report duplicate stats without writing files
	python3 $(IMPORT_SCRIPT) --check

.PHONY: import-spdb-merge
import-spdb-merge: ## Download, dedup, and append new rules into assets/local.toml
	python3 $(IMPORT_SCRIPT) --merge
	$(MAKE) validate-rules

.PHONY: convert-kingfisher
convert-kingfisher: ## Convert assets/kingfisher-rules.yml → assets/kingfisher-rules.toml (dedup + validate)
	python3 $(KINGFISHER_CONVERT)
	$(MAKE) validate-rules

.PHONY: convert-kingfisher-check
convert-kingfisher-check: ## Dry-run convert: report the count breakdown without writing files
	python3 $(KINGFISHER_CONVERT) --check

.PHONY: update-kingfisher
update-kingfisher: ## Download latest Kingfisher YAML, then re-convert to TOML
	python3 $(KINGFISHER_DOWNLOAD)
	$(MAKE) convert-kingfisher

.PHONY: merge-rules
merge-rules: ## Regenerate assets/secrets-scanner.toml (lean) from the manifest
	$(CARGO) run --bin $(BINARY) -- merge-rules \
		--manifest assets/sources.toml \
		--out assets/secrets-scanner.toml \
		--report target/merge-report.json

.PHONY: merge-rules-full
merge-rules-full: ## Merge including embed=false sources (spdb, …) to a scratch file
	$(CARGO) run --bin $(BINARY) -- merge-rules --all \
		--manifest assets/sources.toml \
		--out target/secrets-scanner.full.toml \
		--report target/merge-report.full.json

.PHONY: merge-rules-check
merge-rules-check: merge-rules ## CI drift: regenerate then fail if committed file is stale
	@git diff --exit-code -- assets/secrets-scanner.toml \
	  || { printf 'secrets-scanner.toml is stale — run "make merge-rules" and commit.\n'; exit 1; }

.PHONY: find-dups
find-dups: ## Advisory: surface duplicate rules across sources (needs: pip install rapidfuzz)
	python3 ./scripts/find_duplicate_rules.py \
		--manifest assets/sources.toml \
		--out target/dup-report.md --json target/dup-report.json

.PHONY: local-rules
local-rules: ## Convert custom CSV rules to assets/local.toml
	python3 ./scripts/convert_csv_to_toml.py

.PHONY: generate-fixtures
generate-fixtures: ## Generate positive test fixtures for custom rules
	python3 ./scripts/generate_fixtures.py

# ─────────────────────────────────────────────────────────────────────────────
# RULES — RUNTIME (binary downloads to OS data dir; no recompile needed)
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: update-rules-runtime
update-rules-runtime: build-updater ## Build updater binary, then run update-rules subcommand
	@printf '$(GREEN)Running runtime rule update via binary...$(RESET)\n'
	./target/debug/$(BINARY) update-rules

.PHONY: check-rules-runtime
check-rules-runtime: build-updater ## Check for rule updates via binary (exit 1 = update available)
	./target/debug/$(BINARY) update-rules --check

# ─────────────────────────────────────────────────────────────────────────────
# CLEAN
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean

.PHONY: clean-rules
clean-rules: ## Remove the cached runtime rules from the OS data dir
	@case "$$(uname -s)" in \
	  Darwin) dir="$$HOME/Library/Application Support/secrets-scanner" ;; \
	  Linux)  dir="$${XDG_DATA_HOME:-$$HOME/.local/share}/secrets-scanner" ;; \
	  *)      dir="$$APPDATA/secrets-scanner" ;; \
	esac; \
	if [ -d "$$dir" ]; then \
	  rm -rf "$$dir" && printf '$(GREEN)Removed $$dir$(RESET)\n'; \
	else \
	  printf 'No cached rules found at $$dir\n'; \
	fi

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: bench
bench: ## Run benchmarks with criterion
	$(CARGO) bench

# ─────────────────────────────────────────────────────────────────────────────
# FUZZ TESTING (requires cargo-fuzz: cargo install cargo-fuzz)
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: fuzz
fuzz: ## Run fuzz testing (byte-level, 30s per target)
	cargo fuzz run fuzz_scan_bytes -- -max_total_time=30 2>/dev/null || \
	  echo "Install cargo-fuzz: cargo install cargo-fuzz"

.PHONY: fuzz-prep
fuzz-prep: ## Create fuzz corpus from bundled rules
	mkdir -p fuzz/corpus/fuzz_scan_bytes fuzz/corpus/fuzz_scan_content

.PHONY: fuzz-content
fuzz-content: ## Run content-level fuzz testing (30s)
	cargo fuzz run fuzz_scan_content -- -max_total_time=30 2>/dev/null || \
	  echo "Install cargo-fuzz: cargo install cargo-fuzz"

# ─────────────────────────────────────────────────────────────────────────────
# CI — composite targets
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: ci
ci: fmt-check clippy test check-rules validate-rules merge-rules-check build-full ## Run all CI checks (format, lint, test, rule freshness/validation, merge drift, full build)
	@printf '$(GREEN)$(BOLD)All CI checks passed.$(RESET)\n'
