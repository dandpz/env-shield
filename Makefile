# Developer shortcuts. `make help` lists targets.

CARGO ?= cargo
MSRV  ?= 1.85

.DEFAULT_GOAL := help

.PHONY: help build release test lint fmt fmt-check check msrv install clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Debug build
	$(CARGO) build

release: ## Optimized release build
	$(CARGO) build --release --locked

test: ## Run unit + end-to-end tests
	$(CARGO) test

lint: ## Clippy with warnings denied (matches CI)
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## Format the tree
	$(CARGO) fmt

fmt-check: ## Fail if formatting is off (matches CI)
	$(CARGO) fmt --check

check: fmt-check lint test ## Everything CI runs — use before pushing

msrv: ## Verify the declared minimum Rust version compiles
	$(CARGO) +$(MSRV) check --all-targets

install: ## Install evs into ~/.cargo/bin
	$(CARGO) install --path . --locked

clean: ## Remove build artifacts
	$(CARGO) clean
