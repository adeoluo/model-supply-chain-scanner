# Changelog

All notable changes to this project are documented here. The file is generated
from Conventional Commits by [git-cliff](https://git-cliff.org) when a release is cut
with `make cut-release`.

## [0.2.0] 2026-11-24

### Features

- Refuse calls by shape, read hidden payloads and Lambda bytecode, open 7z and tar
- **bench:** Score every tool on other projects' test files and add ModelAudit
- **bench:** Held-out Hub sample of the newest repositories, ModelAudit in the Hub and speed runs
- **bench:** Hub verdict for every high alert, msscan-only rescans, stderr to a file in the speed harness
- Stored calls, links out of the tree, file paths in Keras configs and shard indexes
- **bench:** Frozen and final held-out results, fair ModelAudit scoring, corpus files for the new rules

### Bug fixes

- **pickle:** Block torch.utils.collect_env, functools.partial, pydoc, and command sinks
- **pickle:** Detect truncated protocol-0/1 pickles missing trailing STOP byte
- **pickle:** Stop trusted library namespaces sheltering code loaders
- Resolve lookups with a known result and stop grading named Lambdas as unreadable code
- Complete calls only for code strings, unused EXT lookups in broken streams, tuple-wrapped Lambda functions
- Report a stored function as called, and base findings on whether it runs on load

### Documentation

- State the evidence level
- Add a plain-English summary and check the payload files against the Hub's own scanners
- Name the formats and the quieter tools in the plain-English summary
- Record the Hub cross-check in the evaluation report
- Rename the opening section to Summary
- Rename the opening section to Highlights
- ADR 0007 on refusing calls by shape, architecture diagram for the new stages
- Results of 0.2.0 on four tests, the frozen held-out run, ADR 0008, limits and roadmap

### Maintenance

- Set the version to 0.2.0 and regenerate both corpus comparisons with it

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
