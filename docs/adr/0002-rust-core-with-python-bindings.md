# ADR-0002: One Rust core for the CLI, the service and the Python package

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
A model scanner runs in three places: in CI over checkpoints that can be gigabytes, inside
Python tooling (download hooks, training pipelines), and as a service that other systems call.
It parses hostile input, so memory safety matters as much as speed, and it must never import or
execute anything from the file it reads.

## Decision
Write every parser and the pickle virtual machine in Rust (`crates/msscan-core`), with three thin
front ends: the `msscan` binary (`crates/msscan-cli`), the HTTP service (in the core, used by both
the binary and Python), and PyO3 bindings compiled into the Python package as
`msscan.msscan_rs` with maturin. Reports cross the Python boundary as JSON and are turned into
frozen dataclasses. Files are memory-mapped, so a 10 GB safetensors file costs a header read.

A readable Python reimplementation of the pickle import and call analysis
(`src/msscan/reference.py`) exists only for parity tests.

## Alternatives considered
- **Python on top of `pickletools`.** Easy to write (picklescan, modelscan and fickling do this),
  but `pickletools.genops` stops at the first invalid opcode, which is exactly where joblib's raw
  array bytes and several evasion techniques sit, and Python is slower per opcode.
- **Go.** Fast and safe, but Python bindings are awkward; the Python ecosystem is where models
  are loaded.

## Consequences
- One implementation of the rules; the binary, the service and Python can never disagree.
- Contributors need a Rust toolchain; `uv sync` builds the extension, CI checks both languages.
- The Hypothesis parity suite keeps the Python reference and the Rust VM in agreement on
  generated pickles of every protocol.
