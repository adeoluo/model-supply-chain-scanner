# AGENTS.md

Working notes for coding agents and contributors in **Model Supply Chain Scanner**. The [README](README.md)
explains what the project does and why; this file explains how to change it safely.

## Project

A static scanner that finds code execution, file access and malformed structure in machine learning model files before they are loaded, without importing or running anything from them.

## Layout

- `action.yml`: action metadata: inputs, outputs, runtime
- `benchmarks/`: benchmark scripts and recorded results
- `docker-compose.yml`: local container setup
- `docs/`: documentation, architecture diagram source and render, design records
- `scripts/`: maintenance scripts (release, assets, data)
- `src/`: library and service source
- `tests/`: test suite

Key modules:

- `src/msscan/__init__.py`: Scan machine learning model files for code execution and unsafe content before loading them.
- `src/msscan/api.py`: Typed wrappers around the Rust core.
- `src/msscan/cli.py`: Command line: ``python -m msscan scan|rules|serve``.
- `src/msscan/reference.py`: A readable reference for the pickle import and call analysis, used only by parity tests.

## Commands

| Command | Purpose |
|---|---|
| `make help` | Show this help |
| `make setup` | Install dependencies (builds the Rust extension) and pre-commit hooks |
| `make build` | Build the release binary target/release/msscan |
| `make develop` | Rebuild the Python extension after editing crates/ |
| `make fixtures` | Regenerate tests/fixtures |
| `make format` | Format Rust and Python |
| `make lint` | Format checks, clippy and ruff |
| `make type` | mypy |
| `make rust-test` | Rust unit, property and CLI tests |
| `make test` | All tests |
| `make coverage` | Tests with the coverage gates used in CI (Rust 85% lines, Python 80%) |
| `make all` | Full local gate (mirror of continuous integration) |
| `make corpus` | Generate the inert synthetic corpus (malicious techniques and benign files) |
| `make validate` | Load every corpus file with its real loader in a subprocess (benchmarks/results/validation.json) |
| `make compare` | msscan vs picklescan, modelscan and fickling on the synthetic corpus |
| `make hf-list` | List Hugging Face Hub repositories and files (public endpoints, no token) |
| `make hf-fetch` | Fetch headers and small files from the Hub (resumable, 2.5 GB budget) |
| `make hf-compare` | Scan the Hub corpus with all four tools (benchmarks/results/hf_corpus.json) |
| `make hf-review` | Label flagged Hub files and tabulate flag rates (benchmarks/results/hf_review.*) |
| `make speed` | Wall time and peak memory on large real checkpoints (benchmarks/results/speed.json) |
| `make rules-doc` | Regenerate docs/RULES.md |
| `make diagram` | Render the architecture diagram |
| `make docker` | Build the container image |
| `make demo` | Record the demo GIFs with vhs |
| `make clean` | Remove build artifacts |
| `make changelog` | Regenerate CHANGELOG.md from Conventional Commits (git-cliff) |
| `make cut-release` | Cut a release locally: version bump, changelog, tag, GitHub release (RELEASE_VERSION=vX.Y.Z optional) |

Run the full local gate (`make all`) before committing; CI runs the same checks.

## Conventions

- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`).
  The changelog and the next version number are derived from them.
- Every number quoted in the README is produced by a command in this repository. When behavior
  changes, rerun that command and update the number in the same commit.
- When a component is added, removed or renamed, update `docs/architecture/architecture.mmd`
  and re-render `architecture.svg` so the diagram matches the code.
- README sections keep their fixed order. Prose avoids em and en dashes and promotional wording.
- Tests accompany behavior changes; a bug fix comes with a test that fails without it.
- Releases are cut with `make cut-release`.

## Python notes

- Python is managed with `uv`; run commands through `uv run` so the locked environment is used.
- Lint and format with `ruff`; type-check with `mypy`; tests use `pytest`.
- Public functions carry type hints and a docstring that states the contract, not the steps.

## Rust notes

- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.
- No `unwrap()` in library code paths that can fail at runtime; return a typed error.
- Unsafe code is limited to the places that need a syscall and carries a `SAFETY:` comment.
