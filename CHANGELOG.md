# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## [0.1.1] 2026-11-09

### Documentation

- Complete citation metadata and bump it on release (#8)
- Map the threat model to OWASP LLM 2026 and MITRE ATLAS v2026.10 (#10)
- Render every architecture diagram in the house style (#11)
- Diagrams on white in the shared theme, make diagram for every diagram, and a self-contained Definition of Done (#12)

### Tests

- Time the scanners on the Qwen3.5-0.8B safetensors file (was Qwen2.5-0.5B-Instruct) (#14)

### Maintenance

- Latest toolchain and CI versions (#7)
- Release script keeps hard-coded version strings in step (#9)
- Release script keeps nested crates and packages on the release version (#13)

## [0.1.0] 2026-11-04

### Features

- Pickle virtual machine and pickle-family formats in a Rust core (#1)
- Keras, SavedModel, ONNX, GGUF, safetensors and Hugging Face config analyzers (#2)
- Msscan CLI with SARIF output, HTTP service, Docker image and Python package (#3)
- Inert malicious corpus, loader validation and comparison with picklescan, modelscan and fickling (#4)
- Hugging Face Hub corpus scan, speed benchmark, GitHub Action and release workflow (#5)

### Maintenance

- Scaffold project
- Release tooling, changelog, AGENTS.md and llms.txt (#6)
