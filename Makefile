# Makefile for apigw.

-include .env
export

CARGO ?= cargo

.PHONY: all build check clean fmt fmt-check lint test test-coverage test-mutants parity parity-record parity-live reference-images deny hooks image binary chart-lint run help

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

parity: ## Replay the recorded API Gateway fixtures against a local apigw build
	$(CARGO) build -p apigw -p apigw-parity
	./target/debug/apigw-parity replay

parity-record: ## Record every parity case against the deployed reference stack into parity/ (needs AWS_PROFILE)
	./scripts/parity-record.sh

parity-live: ## Compare AWS-service integrations between the reference APIs and apigw on ECS (needs AWS_PROFILE)
	./scripts/parity-live.sh

reference-images: ## Build, push, and pin the reference stack's gateway images at HEAD (needs AWS_PROFILE)
	./scripts/reference-images.sh

deny: ## Check advisories, licenses, bans, and sources
	$(CARGO) deny check

hooks: ## Install prek git hooks (pre-commit + pre-push)
	prek install

##@ Container

image: ## Build the container image as apigw:local
	docker build -t apigw:local .

binary: ## Build the release's static musl binary: make binary TARGET=aarch64-unknown-linux-musl
	docker buildx bake ci

##@ Packaging

chart-lint: ## Lint the Helm chart and validate what each ci/ value set renders (requires helm, kubeconform)
	@set -e; for values in charts/apigw/ci/*.yaml; do \
		echo "== $$values"; \
		helm lint --strict charts/apigw --values "$$values"; \
		helm template apigw charts/apigw --values "$$values" | kubeconform -strict -ignore-missing-schemas -summary; \
	done

##@ Run

run: ## Run apigw: make run ARGS="--openapi-file api.json --tls-cert ... --tls-key ..."
	$(CARGO) run --bin apigw -- $(ARGS)

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
