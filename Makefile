# Makefile for apigw.

-include .env
export

CARGO ?= cargo

.PHONY: all build check clean fmt fmt-check lint test test-coverage test-mutants deny hooks image run help

all: build

##@ Build

build: ## Build the workspace (release)
	$(CARGO) build --release

check: ## Type-check the workspace
	$(CARGO) check --workspace --all-targets --all-features

clean: ## Remove the cargo target/ build artifacts
	$(CARGO) clean

##@ Quality

fmt: ## Format all code
	$(CARGO) fmt --all

fmt-check: ## Verify formatting without writing
	$(CARGO) fmt --all --check

lint: ## Run clippy with warnings denied
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test: ## Run unit tests
	$(CARGO) test --workspace --all-features

test-coverage: ## Generate an HTML coverage report (requires cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

test-mutants: ## Run mutation testing (requires cargo-mutants)
	$(CARGO) mutants

deny: ## Check advisories, licenses, bans, and sources
	$(CARGO) deny check

hooks: ## Install prek git hooks (pre-commit + pre-push)
	prek install

##@ Container

image: ## Build the container image as apigw:local
	docker build -t apigw:local .

##@ Run

run: ## Run apigw: make run ARGS="--openapi-file api.json --tls-cert ... --tls-key ..."
	$(CARGO) run --bin apigw -- $(ARGS)

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
