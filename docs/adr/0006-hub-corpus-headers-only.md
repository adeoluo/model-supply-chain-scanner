# ADR-0006: A Hub corpus from headers and stubs, published without names

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
False positive rates mean little on a corpus written by the author. The Hugging Face Hub holds
the files people actually load, but downloading thousands of checkpoints would take terabytes,
and some scan results concern specific, real repositories.

## Decision
- Fetch only what a scanner reads, with HTTP range requests: the pickle members of PyTorch zip
  checkpoints (the end-of-central-directory record, the central directory, then each `.pkl`
  member), rebuilt into a small stub zip that every tool can read; `config.json` of `.keras`
  archives; safetensors headers; GGUF headers (scanned in memory, not stored); whole files only
  up to 20 MB. No token is used, so gated repositories are skipped.
- Respect the published request budgets (API and resolver gates in `collect.py`), and never
  upload anything, open issues or contact repository owners.
- Keep repository names in a private directory outside the repository. Results carry salted
  pseudonyms and only aggregate rates are published.

## Consequences
- The stub of a PyTorch checkpoint holds exactly the bytes `torch.load` unpickles, so pickle
  findings are the same as on the full file; tensor storage bytes are never needed.
- Other tools see stubs, not the original files. For pickle-based formats this is the same
  input; formats they do not support are reported as not scanned.
- Readers can rebuild a comparable corpus with the scripts, but not the exact sample.
