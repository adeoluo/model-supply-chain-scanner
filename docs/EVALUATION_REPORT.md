# Evaluation Report: Model Supply Chain Scanner

Every number here comes from a script in `benchmarks/` whose raw output is committed in
`benchmarks/results/`. Hardware: Apple M1, 8 cores, 8 GB, shared with other work. Tool versions:
msscan 0.1.0, picklescan 1.0.5, modelscan 0.8.8, fickling 0.1.13.

## Setup

- **Question:** does a scanner flag files whose loading runs attacker code, reads outside the
  model or trips a parser, and how often does it flag files that do none of this?
- **Tools and thresholds:** each tool runs through its Python API in its own subprocess
  (`benchmarks/compare.py`). msscan flags at `high` (default) or `medium`; picklescan when it
  reports an infected file (and with `strict=True`); modelscan when it reports any issue;
  fickling when `scan_file` rates the file above `LIKELY_SAFE`, or only at
  `LIKELY_OVERTLY_MALICIOUS`.
- **Metrics:** detection rate on malicious files, flag rate on benign files, both with 95%
  Wilson intervals; files a tool skipped or failed on count as not flagged and are reported.
- **Corpora:** an inert synthetic corpus that covers every technique, and 7,607 real files from
  the Hugging Face Hub (see `docs/DATA_CARD.md`). Nothing is stochastic except the Hub listing
  order, which is fixed by `--seed 0`.

## 1. Synthetic corpus (116 malicious, 78 benign)

`make corpus validate compare`. Ground truth: `benchmarks/corpus/validate.py` loaded every file
that has a Python loader in a fresh subprocess; all 101 such malicious files ran their inert
payload or were rejected by the loader, and all 72 such benign files loaded. The other 15
malicious files are labeled by construction.

Versions: msscan 0.1.0 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: gguf | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: hf-json | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: joblib | 24 | 0/24 | 0/24 | 0/24 | 4/24 | 0/24 | 0/24 | 0/24 |
| benign: keras | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: numpy | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| benign: onnx | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: pickle | 10 | 0/10 | 0/10 | 0/10 | 9/10 | 0/10 | 10/10 | 1/10 |
| benign: pytorch | 21 | 0/21 | 0/21 | 0/21 | 9/21 | 0/21 | 21/21 | 4/21 |
| benign: safetensors | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: savedmodel | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| malicious: gguf / code-execution | 6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| malicious: gguf / structure | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| malicious: hf-json / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: joblib / code-execution | 8 | 8/8 | 8/8 | 1/8 | 3/8 | 1/8 | 1/8 | 1/8 |
| malicious: keras / code-execution | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 1/4 | 0/4 | 0/4 |
| malicious: keras / file-access | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| malicious: numpy / code-execution | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| malicious: onnx / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| malicious: pickle / code-execution | 63 | 63/63 | 63/63 | 59/63 | 62/63 | 35/63 | 62/63 | 61/63 |
| malicious: pickle / hard | 3 | 1/3 | 2/3 | 1/3 | 3/3 | 0/3 | 3/3 | 2/3 |
| malicious: pytorch / code-execution | 7 | 7/7 | 7/7 | 6/7 | 7/7 | 3/7 | 7/7 | 5/7 |
| malicious: safetensors / structure | 8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| malicious: savedmodel / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: savedmodel / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |

| Detection rate (malicious) | 116 | 114/116 = 0.983 (0.939 to 0.995) | 115/116 = 0.991 (0.953 to 0.998) | 69/116 = 0.595 (0.504 to 0.680) | 77/116 = 0.664 (0.574 to 0.743) | 40/116 = 0.345 (0.265 to 0.435) | 73/116 = 0.629 (0.539 to 0.712) | 69/116 = 0.595 (0.504 to 0.680) |
| False positive rate (benign) | 78 | 0/78 = 0.000 (0.000 to 0.047) | 0/78 = 0.000 (0.000 to 0.047) | 0/78 = 0.000 (0.000 to 0.047) | 22/78 = 0.282 (0.194 to 0.390) | 0/78 = 0.000 (0.000 to 0.047) | 31/78 = 0.397 (0.296 to 0.508) | 5/78 = 0.064 (0.028 to 0.141) |

| Files not scanned or with errors | | 0 | 0 | 10 | 10 | 90 | 93 | 93 |
| Wall time (s, one process, includes imports) | | 0.2 | 0.2 | 0.2 | 0.2 | 0.4 | 2.0 | 2.0 |

## 2. Hugging Face Hub corpus (7,607 files, 2,888 repositories)

`make hf-list hf-fetch hf-compare hf-review`. Collection used public listings and range
requests without a token, capped at 2.5 GB stored; files were scanned as headers and stubs
(ADR 0006). Labels come from file contents by the fixed rules in `benchmarks/hf/review.py`
(payload, security-test, code-by-design, nonstandard, benign), never from a tool's verdict.
Because the structural facts behind the labels are read by msscan's parsers, msscan's flags on
the benign label are zero by construction; the informative rows are the payload row, the
security-test group (reported per tool because labels cannot see what the parsers miss) and
the "no attack" row, which counts every alert on files without an attack payload.

Hub corpus: 7607 files from 2888 repositories.

All files (picklescan, modelscan and fickling receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 17 | 17/17 | 17/17 | 7/16 | 7/16 | 5/16 | 7/16 | 7/16 |
| security-test | 27 | 7/27 | 8/27 | 0/20 | 0/20 | 2/20 | 0/20 | 0/20 |
| code-by-design | 342 | 18/342 | 113/342 | 1/183 | 81/183 | 1/183 | 20/183 | 73/183 |
| nonstandard | 14 | 13/14 | 14/14 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| benign | 7207 | 0/7207 = 0.000 (0.000 to 0.001) | 15/7207 = 0.002 (0.001 to 0.003) | 0/2023 = 0.000 (0.000 to 0.002) | 492/2023 = 0.243 (0.225 to 0.262) | 0/2023 = 0.000 (0.000 to 0.002) | 125/2023 = 0.062 (0.052 to 0.073) | 1151/2023 = 0.569 (0.547 to 0.590) |
| no attack (code-by-design, nonstandard, benign) | 7563 | 31/7563 = 0.004 (0.003 to 0.006) | 142/7563 = 0.019 (0.016 to 0.022) | 1/2208 = 0.000 (0.000 to 0.003) | 573/2208 = 0.260 (0.242 to 0.278) | 1/2208 = 0.000 (0.000 to 0.003) | 145/2208 = 0.066 (0.056 to 0.077) | 1226/2208 = 0.555 (0.534 to 0.576) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 10 | 10/10 | 10/10 | 7/10 | 7/10 | 5/10 | 7/10 | 7/10 |
| security-test | 4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| code-by-design | 85 | 7/85 | 79/85 | 1/85 | 81/85 | 1/85 | 20/85 | 73/85 |
| nonstandard | 2 | 1/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| benign | 1433 | 0/1433 = 0.000 (0.000 to 0.003) | 3/1433 = 0.002 (0.001 to 0.006) | 0/1433 = 0.000 (0.000 to 0.003) | 492/1433 = 0.343 (0.319 to 0.368) | 0/1433 = 0.000 (0.000 to 0.003) | 125/1433 = 0.087 (0.074 to 0.103) | 1151/1433 = 0.803 (0.782 to 0.823) |
| no attack (code-by-design, nonstandard, benign) | 1520 | 8/1520 = 0.005 (0.003 to 0.010) | 84/1520 = 0.055 (0.045 to 0.068) | 1/1520 = 0.001 (0.000 to 0.004) | 573/1520 = 0.377 (0.353 to 0.402) | 1/1520 = 0.001 (0.000 to 0.004) | 145/1520 = 0.095 (0.082 to 0.111) | 1226/1520 = 0.807 (0.786 to 0.826) |

Wall time on the Hub corpus: msscan scanned 7,607 files in 9.8 s (one process, Python API); on the 2,244
files the other tools received, picklescan 75.3 s, modelscan 33.4 s, fickling 683.4 s.

## 3. Speed and memory

`make speed`. Median of three runs per tool and file, each in a fresh process under
`/usr/bin/time -l`, Python start-up and imports included. The safetensors file is the single
shard of `Qwen/Qwen3.5-0.8B` (1,746,942,600 bytes); the earlier table used the
Qwen2.5-0.5B-Instruct file (942 MB), and msscan's cost on it is the same because only the header
is read.

| Tool | opus-mt-en-de `.bin` (284 MB) | opus-mt-en-fr `.bin` (287 MB) | Qwen3.5-0.8B `.safetensors` (1,666 MB) | plain-data pickle (31 MB) |
|---|---:|---:|---:|---:|
| **msscan** (binary) | 0.01 s, 4 MB | < 0.01 s, 4 MB | < 0.01 s, 4 MB | 0.24 s, 241 MB |
| msscan (Python package) | 0.06 s, 21 MB | 0.06 s, 21 MB | 0.05 s, 21 MB | 0.42 s, 258 MB |
| picklescan | 0.19 s, 25 MB | 0.08 s, 26 MB | 0.08 s, 24 MB | 11 s, 896 MB |
| modelscan | 0.25 s, 40 MB | 0.17 s, 40 MB | 0.16 s, 40 MB | 12 s, 728 MB |
| fickling | 2.52 s, 318 MB | 2.32 s, 297 MB | 3.86 s, 504 MB | 103 s, 713 MB |

## Error analysis

- **Synthetic misses (msscan at high):** two of the three "hard" pickles, which reach behaviour
  through functions outside the denylist on purpose; one is reported at medium (unknown call).
- **Hub alerts without an attack (31 at high):** 11 Keras Lambda layers (code in the file by
  design), 9 GGUF files outside llama.cpp's limits (5-D tensors from video diffusion models,
  type ids from forks), 7 pickles calling `dill` internals or `getattr` or writing dunder
  attributes, 3 safetensors headers (two with uncovered data bytes, which the reference
  `safetensors` loader rejects, and one macOS metadata file), and a TensorFlow.js weight shard
  read as a safetensors header.
- **Changes made after the first Hub run:** the first run flagged 88 Keras files and 38 pickles
  at high. Keras configs that name functions by `{"module": "builtins", "class_name":
  "function"}` or `__main__` are resolved by name among Keras built-ins and caller-supplied
  custom objects, so they now report MS503 (low); third-party modules got their own medium rule
  (MS505); `torch.distributed` tensor and device-mesh classes moved from the denylist to library
  code. The synthetic results were rerun after the change and did not move (114/116, 0/78).
- **Security-test files msscan does not flag:** weight backdoors (out of scope), an ONNX
  docstring injection, safetensors files with unusual tensor names, a zip-slip `.keras` and a
  decompression-bomb `.keras` whose offending members were not fetched by headers-only
  collection, a NumPy shape needing 80 GB (medium), and benign baselines.

## Reproducibility

```bash
make build
make corpus validate compare        # synthetic corpus (about 1 MB)
make hf-list hf-fetch               # Hub corpus (2.5 GB stored, rate limited)
make hf-compare hf-review           # 13 minutes here, mostly fickling
make speed                          # 8 minutes here, mostly fickling on the plain-data pickle
```

The Hub listing changes over time, so a fresh collection gives a different sample; the committed
`hf_corpus.json` rows (pseudonymous ids) are the ones behind the tables.
