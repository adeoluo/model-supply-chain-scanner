.PHONY: help setup build develop fixtures lint format type test rust-test coverage all corpus validate compare third-party hf-list hf-fetch hf-compare hf-heldout hf-status speed rules-doc diagram docker demo clean changelog cut-release

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
	uv run ruff format src tests scripts benchmarks
	uv run ruff check --fix src tests scripts benchmarks

lint: ## Format checks, clippy and ruff
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	uv run ruff format --check src tests scripts benchmarks
	uv run ruff check src tests scripts benchmarks

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

BENCH = uv run --project benchmarks python

corpus: ## Generate the inert synthetic corpus (malicious techniques and benign files)
	rm -rf $(DATA)/synthetic && $(BENCH) benchmarks/corpus/generate.py --out $(DATA)/synthetic

validate: ## Load every corpus file with its real loader in a subprocess (benchmarks/results/validation.json)
	$(BENCH) benchmarks/corpus/validate.py --corpus $(DATA)/synthetic --out benchmarks/results/validation.json

compare: ## msscan vs picklescan, modelscan and fickling on the synthetic corpus
	$(BENCH) benchmarks/compare.py --corpus $(DATA)/synthetic --out benchmarks/results/synthetic

third-party: ## Score every tool on test files written by other scanner projects (benchmarks/results/third_party.*)
	mkdir -p $(DATA)/third_party
	for r in mmaitre314/picklescan promptfoo/modelaudit protectai/modelscan trailofbits/fickling; do \
		d=$(DATA)/third_party/$$(basename $$r); [ -d $$d ] || git clone -q --depth 1 https://github.com/$$r $$d; done
	$(BENCH) benchmarks/third_party.py --src $(DATA)/third_party --out $(DATA)/third_party_corpus
	$(BENCH) benchmarks/compare.py --corpus $(DATA)/third_party_corpus --out benchmarks/results/third_party

hf-list: ## List Hugging Face Hub repositories and files (public endpoints, no token)
	$(BENCH) benchmarks/hf/collect.py list --data $(DATA)/hf

hf-fetch: ## Fetch headers and small files from the Hub (resumable, 2.5 GB budget)
	$(BENCH) benchmarks/hf/collect.py fetch --data $(DATA)/hf

hf-compare: ## Scan the Hub corpus with all five tools (benchmarks/results/hf_corpus.json)
	$(BENCH) benchmarks/hf/scan.py --data $(DATA)/hf --out benchmarks/results/hf_corpus

hf-review: ## Label flagged Hub files and tabulate flag rates (benchmarks/results/hf_review.*)
	$(BENCH) benchmarks/hf/review.py --data $(DATA)/hf --out benchmarks/results/hf_review

hf-heldout: ## Draw, fetch, scan and cross-check a second Hub sample of the newest repositories (never tuned on)
	$(BENCH) benchmarks/hf/collect.py list --data $(DATA)/hf_heldout --listing heldout --exclude $(DATA)/hf/private/repos.jsonl
	$(BENCH) benchmarks/hf/collect.py fetch --data $(DATA)/hf_heldout --per-kind 2
	$(BENCH) benchmarks/hf/scan.py --data $(DATA)/hf_heldout --out benchmarks/results/hf_heldout
	$(BENCH) benchmarks/hf/review.py --data $(DATA)/hf_heldout --corpus benchmarks/results/hf_heldout.json --out benchmarks/results/hf_heldout_review
	$(BENCH) benchmarks/hf/hub_status.py --data $(DATA)/hf_heldout --review benchmarks/results/hf_heldout_review.json --out benchmarks/results/hf_heldout_hub_status

hf-status: ## Ask the Hub what its own scanners say about the payload files (benchmarks/results/hf_hub_status.json)
	$(BENCH) benchmarks/hf/hub_status.py --data $(DATA)/hf --out benchmarks/results/hf_hub_status

speed: build ## Wall time and peak memory on large real checkpoints (benchmarks/results/speed.json)
	$(BENCH) benchmarks/speed.py --data $(DATA)/speed --msscan target/release/msscan

rules-doc: build ## Regenerate docs/RULES.md
	./target/release/msscan rules --format markdown > docs/RULES.md

diagram: ## Render every diagram in docs/architecture to SVG (house theme, white background)
	@for f in docs/architecture/*.mmd; do \
		npx -y @mermaid-js/mermaid-cli -q -i "$$f" -o "$${f%.mmd}.svg" -c mermaid.config.json -b white || exit 1; \
	done

docker: ## Build the container image
	docker build -t msscan .

demo: build ## Record the demo GIFs with vhs
	for t in docs/demo/*.tape; do vhs $$t; done

clean: ## Remove build artifacts
	rm -rf target dist .pytest_cache .mypy_cache .ruff_cache coverage.xml
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +

changelog: ## Regenerate CHANGELOG.md from Conventional Commits (git-cliff)
	git cliff --output CHANGELOG.md && perl -0pi -e 's/\n+\z/\n/' CHANGELOG.md

cut-release: ## Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional)
	scripts/release.sh $(RELEASE_VERSION)
