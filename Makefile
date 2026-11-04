.PHONY: help setup build develop fixtures lint format type test rust-test coverage all bench corpus validate compare hf-corpus hf-scan speed rules-doc diagram docker demo clean

LLVM ?= /opt/homebrew/opt/llvm/bin
DATA ?= ../.bench-data/model-supply-chain-scanner

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies (builds the Rust extension) and pre-commit hooks
	uv sync
	uv run pre-commit install || true

build: ## Build the release binary target/release/msscan
	cargo build --release -p msscan

develop: ## Rebuild the Python extension after editing crates/
	uv sync --reinstall-package model-supply-chain-scanner

fixtures: ## Regenerate tests/fixtures
	uv run python scripts/make_fixtures.py

format: ## Format Rust and Python
	cargo fmt --all
	uv run ruff format src tests scripts
	uv run ruff check --fix src tests scripts

lint: ## Format checks, clippy and ruff
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	uv run ruff format --check src tests scripts
	uv run ruff check src tests scripts

type: ## mypy
	uv run mypy src

rust-test: ## Rust unit, property and CLI tests
	cargo test --workspace --exclude msscan-py

test: rust-test ## All tests
	uv run pytest

coverage: ## Tests with the coverage gates used in CI (Rust 85% lines, Python 80%)
	LLVM_COV=$(LLVM)/llvm-cov LLVM_PROFDATA=$(LLVM)/llvm-profdata cargo llvm-cov --workspace --exclude msscan-py --fail-under-lines 85 --summary-only
	uv run pytest --cov=src --cov-report=term-missing --cov-fail-under=80

all: lint type coverage ## Full local gate (mirror of continuous integration)

rules-doc: build ## Regenerate docs/RULES.md
	./target/release/msscan rules --format markdown > docs/RULES.md

diagram: ## Render the architecture diagram
	npx -y @mermaid-js/mermaid-cli -i docs/architecture/architecture.mmd -o docs/architecture/architecture.svg \
	  -c docs/architecture/mermaid.config.json -b transparent

docker: ## Build the container image
	docker build -t msscan .

demo: build ## Record the demo GIFs with vhs
	for t in docs/demo/*.tape; do vhs $$t; done

clean: ## Remove build artifacts
	rm -rf target dist .pytest_cache .mypy_cache .ruff_cache coverage.xml
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
