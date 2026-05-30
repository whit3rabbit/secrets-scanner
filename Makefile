# Makefile — secrets-scanner
# Common developer targets.  Run `make help` for a summary.

SHELL        := bash
BINARY       := secrets-scanner
CARGO        := cargo
FEATURES_UPD := --features updater
RULES_SCRIPT := ./scripts/update_rules.sh

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
test: ## Run all tests
	$(CARGO) test

.PHONY: test-updater
test-updater: ## Run all tests including updater feature
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

.PHONY: local-rules
local-rules: ## Convert custom CSV rules to assets/local.toml
	python3 ./scripts/convert_csv_to_toml.py

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
# CI — composite targets
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: ci
ci: fmt-check clippy test check-rules validate-rules ## Run all CI checks (format, lint, test, rule freshness, rule validation)
	@printf '$(GREEN)$(BOLD)All CI checks passed.$(RESET)\n'
