# Evaluation Report: Model Supply Chain Scanner

Every number here comes from a script in `benchmarks/` whose raw output is committed in
`benchmarks/results/`. Hardware: Apple M1, 8 cores, 8 GB. Tool versions: msscan 0.2.0,
picklescan 1.0.5, modelscan 0.8.8, fickling 0.1.13, ModelAudit 0.2.58.

## Setup

- **Question:** does a scanner flag files whose loading runs attacker code, reads outside the
  model or trips a parser, and how often does it flag files that do none of this?
- **Tools and thresholds:** each tool runs through its Python API in its own subprocess
  (`benchmarks/compare.py`). msscan flags at `high` (default) or `medium`; picklescan when it
  reports an infected file (and with `strict=True`); modelscan when it reports any issue;
  fickling when `scan_file` rates the file above `LIKELY_SAFE`, or only at
  `LIKELY_OVERTLY_MALICIOUS`; ModelAudit when it reports an issue at warning or critical (the
  condition for exit status 1 of its CLI), or at critical only.
- **Metrics:** detection rate on malicious files, flag rate on benign files, both with 95%
  Wilson intervals; files a tool skipped or failed on count as not flagged and are reported.
- **Corpora** (see `docs/DATA_CARD.md`): the test files of four other scanner projects, an
  inert authored corpus, and two samples of real files from the Hugging Face Hub. Nothing is
  stochastic except the Hub listing order, which is fixed by `--seed 0`.
- **Which numbers are fitted:** the rules of 0.2.0 were developed against corpora 1 to 3.
  Only the frozen run on the second Hub sample (section 4) is a measurement on files the
  rules had not seen.

## 1. Test files of other scanner projects (144 malicious, 37 benign)

`make third-party`. `benchmarks/third_party.py` clones four repositories and copies the files
their own tests use, labeled only by what those tests assert:

| Project | Commit | Malicious | Benign |
|---|---|---:|---:|
| picklescan (`tests/data`, `tests/data2`) | `5e7ab22` | 94 | 14 |
| ModelAudit (`tests/assets`) | `a5f388c` | 49 | 21 |
| modelscan (`tests/data`) | `61fcec9` | 1 | 1 |
| fickling (`test/fixtures`) | `a7c6514` | 0 | 1 |

ModelAudit's chat-template fixtures are stored as `tokenizer_config.json`, the name its own
tests copy them to before scanning.

Versions: msscan 0.2.0 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13 modelaudit 0.2.58

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) | ModelAudit | ModelAudit (critical) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: fickling suite | 1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| benign: modelaudit suite | 21 | 0/21 | 0/21 | 0/21 | 1/21 | 0/21 | 1/21 | 0/21 | 0/21 | 0/21 |
| benign: modelscan suite | 1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| benign: picklescan suite | 14 | 0/14 | 6/14 | 0/14 | 0/14 | 0/14 | 4/14 | 0/14 | 3/14 | 0/14 |
| malicious: modelaudit suite | 49 | 46/49 | 46/49 | 18/49 | 19/49 | 19/49 | 18/49 | 18/49 | 49/49 | 45/49 |
| malicious: modelscan suite | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| malicious: picklescan suite | 94 | 94/94 | 94/94 | 94/94 | 94/94 | 28/94 | 88/94 | 77/94 | 89/94 | 88/94 |

| Detection rate (malicious) | 144 | 141/144 = 0.979 (0.941 to 0.993) | 141/144 = 0.979 (0.941 to 0.993) | 113/144 = 0.785 (0.711 to 0.844) | 114/144 = 0.792 (0.718 to 0.850) | 48/144 = 0.333 (0.262 to 0.414) | 107/144 = 0.743 (0.666 to 0.807) | 96/144 = 0.667 (0.586 to 0.738) | 139/144 = 0.965 (0.921 to 0.985) | 134/144 = 0.931 (0.877 to 0.962) |
| False positive rate (benign) | 37 | 0/37 = 0.000 (0.000 to 0.094) | 7/37 = 0.189 (0.095 to 0.342) | 0/37 = 0.000 (0.000 to 0.094) | 2/37 = 0.054 (0.015 to 0.177) | 0/37 = 0.000 (0.000 to 0.094) | 6/37 = 0.162 (0.077 to 0.311) | 0/37 = 0.000 (0.000 to 0.094) | 4/37 = 0.108 (0.043 to 0.247) | 1/37 = 0.027 (0.005 to 0.138) |

| Files not scanned or with errors | | 0 | 0 | 6 | 6 | 57 | 51 | 51 | 7 | 7 |
| Wall time (s, one process, includes imports) | | 0.1 | 0.1 | 0.3 | 0.3 | 0.3 | 2.1 | 2.1 | 76.2 | 76.2 |

Misses at high: msscan 3 (ModelAudit's Keras HDF5 files that name a custom layer, loss or
metric and contain no code; reported at low by design). ModelAudit 5 (picklescan's zip
archives with altered header flags, central directory or checksum). No malicious file here
is flagged by msscan alone. msscan 0.1.1 detected 117 of the 144; of the 141 detected now, 21
are detected only through rules new in 0.2.0 and 20 of those through MS115.

## 2. Authored corpus (142 malicious, 101 benign)

`make corpus validate compare`. Ground truth: `benchmarks/corpus/validate.py` loaded every file
that has a Python loader in a fresh subprocess; all 106 such malicious files ran their inert
payload or were rejected by the loader, and all 72 such benign files loaded. The other 36
malicious files are labeled by construction.

Versions: msscan 0.2.0 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13 modelaudit 0.2.58

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) | ModelAudit | ModelAudit (critical) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: config | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: container | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: gguf | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: hf-json | 5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| benign: joblib | 25 | 0/25 | 1/25 | 1/25 | 5/25 | 0/25 | 1/25 | 1/25 | 25/25 | 6/25 |
| benign: keras | 5 | 0/5 | 1/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 2/5 | 0/5 |
| benign: look-alike | 5 | 0/5 | 0/5 | 0/5 | 1/5 | 0/5 | 1/5 | 0/5 | 2/5 | 2/5 |
| benign: numpy | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| benign: onnx | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: pickle | 13 | 0/13 | 2/13 | 1/13 | 10/13 | 0/13 | 12/13 | 3/13 | 8/13 | 3/13 |
| benign: pytorch | 22 | 0/22 | 1/22 | 1/22 | 10/22 | 0/22 | 22/22 | 5/22 | 14/22 | 1/22 |
| benign: safetensors | 8 | 0/8 | 1/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 3/8 | 1/8 |
| benign: savedmodel | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| malicious: call-shape / code-execution | 5 | 5/5 | 5/5 | 1/5 | 5/5 | 0/5 | 2/5 | 2/5 | 4/5 | 2/5 |
| malicious: config / code-execution | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 1/4 | 1/4 |
| malicious: container / code-execution | 3 | 3/3 | 3/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: gguf / code-execution | 6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 6/6 | 5/6 |
| malicious: gguf / structure | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 2/4 | 0/4 |
| malicious: hf-json / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: hf-json / file-access | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: joblib / code-execution | 8 | 8/8 | 8/8 | 1/8 | 3/8 | 1/8 | 1/8 | 1/8 | 8/8 | 8/8 |
| malicious: keras / code-execution | 5 | 5/5 | 5/5 | 0/5 | 0/5 | 1/5 | 0/5 | 0/5 | 5/5 | 2/5 |
| malicious: keras / file-access | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 4/4 | 0/4 |
| malicious: link / file-access | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 |
| malicious: numpy / code-execution | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: onnx / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: pickle / code-execution | 63 | 63/63 | 63/63 | 59/63 | 62/63 | 35/63 | 62/63 | 61/63 | 63/63 | 55/63 |
| malicious: pickle / hard | 3 | 3/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 | 2/3 | 3/3 | 3/3 |
| malicious: pytorch / code-execution | 7 | 7/7 | 7/7 | 6/7 | 7/7 | 3/7 | 7/7 | 5/7 | 5/7 | 5/7 |
| malicious: safetensors / structure | 8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 5/8 | 2/8 |
| malicious: savedmodel / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: savedmodel / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 |
| malicious: staged / code-execution | 7 | 7/7 | 7/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 7/7 | 6/7 |

| Detection rate (malicious) | 142 | 142/142 = 1.000 (0.974 to 1.000) | 142/142 = 1.000 (0.974 to 1.000) | 71/142 = 0.500 (0.419 to 0.581) | 83/142 = 0.585 (0.502 to 0.662) | 40/142 = 0.282 (0.214 to 0.361) | 75/142 = 0.528 (0.446 to 0.608) | 71/142 = 0.500 (0.419 to 0.581) | 128/142 = 0.901 (0.841 to 0.940) | 103/142 = 0.725 (0.647 to 0.792) |
| False positive rate (benign) | 101 | 0/101 = 0.000 (0.000 to 0.037) | 6/101 = 0.059 (0.028 to 0.124) | 3/101 = 0.030 (0.010 to 0.084) | 26/101 = 0.257 (0.182 to 0.350) | 0/101 = 0.000 (0.000 to 0.037) | 36/101 = 0.356 (0.270 to 0.454) | 9/101 = 0.089 (0.048 to 0.161) | 55/101 = 0.545 (0.448 to 0.638) | 14/101 = 0.139 (0.084 to 0.219) |

| Files not scanned or with errors | | 0 | 0 | 16 | 16 | 119 | 115 | 115 | 18 | 18 |
| Wall time (s, one process, includes imports) | | 0.3 | 0.3 | 0.4 | 0.4 | 0.3 | 1.6 | 1.6 | 233.4 | 233.4 |

## 3. Hugging Face Hub, first sample (8,541 files, 2,789 repositories)

`make hf-list hf-fetch hf-compare hf-review`. Collection used public listings and range
requests without a token; files were scanned as headers and stubs (ADR 0006). The listing is
the one drawn for version 0.1; the files were fetched again on 2026-11-23 and kept (3.7 GB),
because the first collection had not kept them. Labels come from file contents by the fixed
rules in `benchmarks/hf/review.py` (payload, security-test, code-by-design, nonstandard,
benign), never from a tool's verdict. The structural facts behind the labels are read by
msscan's parsers, so the payload row counts what the other tools miss, not what msscan
misses; the informative rows are the security-test group and the "no attack" row, which
counts every alert on files without an attack payload.

Hub corpus: 8541 files from 2789 repositories.

All files (picklescan, modelscan, fickling and ModelAudit receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 19 | 19/19 | 19/19 | 9/18 | 9/18 | 6/18 | 9/18 | 9/18 | 16/18 | 16/18 |
| security-test | 27 | 6/27 | 8/27 | 0/20 | 0/20 | 2/20 | 0/20 | 0/20 | 4/20 | 7/20 |
| code-by-design | 400 | 2/400 | 115/400 | 1/225 | 85/225 | 1/225 | 23/225 | 76/225 | 129/225 | 211/225 |
| nonstandard | 80 | 0/80 | 58/80 | 0/55 | 1/55 | 0/55 | 1/55 | 54/55 | 0/55 | 2/55 |
| benign | 8015 | 4/8015 = 0.000 (0.000 to 0.001) | 17/8015 = 0.002 (0.001 to 0.003) | 0/2377 = 0.000 (0.000 to 0.002) | 548/2377 = 0.231 (0.214 to 0.248) | 0/2377 = 0.000 (0.000 to 0.002) | 146/2377 = 0.061 (0.052 to 0.072) | 1228/2377 = 0.517 (0.497 to 0.537) | 228/2377 = 0.096 (0.085 to 0.108) | 1393/2377 = 0.586 (0.566 to 0.606) |
| no attack (code-by-design, nonstandard, benign) | 8495 | 6/8495 = 0.001 (0.000 to 0.002) | 190/8495 = 0.022 (0.019 to 0.026) | 1/2657 = 0.000 (0.000 to 0.002) | 634/2657 = 0.239 (0.223 to 0.255) | 1/2657 = 0.000 (0.000 to 0.002) | 170/2657 = 0.064 (0.055 to 0.074) | 1358/2657 = 0.511 (0.492 to 0.530) | 357/2657 = 0.134 (0.122 to 0.148) | 1606/2657 = 0.604 (0.586 to 0.623) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 12 | 12/12 | 12/12 | 9/12 | 9/12 | 6/12 | 9/12 | 9/12 | 12/12 | 12/12 |
| security-test | 4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| code-by-design | 90 | 2/90 | 79/90 | 1/90 | 85/90 | 1/90 | 23/90 | 76/90 | 60/90 | 90/90 |
| nonstandard | 54 | 0/54 | 54/54 | 0/54 | 0/54 | 0/54 | 1/54 | 54/54 | 0/54 | 1/54 |
| benign | 1550 | 1/1550 = 0.001 (0.000 to 0.004) | 5/1550 = 0.003 (0.001 to 0.008) | 0/1550 = 0.000 (0.000 to 0.002) | 548/1550 = 0.354 (0.330 to 0.378) | 0/1550 = 0.000 (0.000 to 0.002) | 146/1550 = 0.094 (0.081 to 0.110) | 1228/1550 = 0.792 (0.771 to 0.812) | 215/1550 = 0.139 (0.122 to 0.157) | 1303/1550 = 0.841 (0.822 to 0.858) |
| no attack (code-by-design, nonstandard, benign) | 1694 | 3/1694 = 0.002 (0.001 to 0.005) | 138/1694 = 0.081 (0.069 to 0.095) | 1/1694 = 0.001 (0.000 to 0.003) | 633/1694 = 0.374 (0.351 to 0.397) | 1/1694 = 0.001 (0.000 to 0.003) | 170/1694 = 0.100 (0.087 to 0.116) | 1358/1694 = 0.802 (0.782 to 0.820) | 275/1694 = 0.162 (0.146 to 0.181) | 1394/1694 = 0.823 (0.804 to 0.840) |

Wall time: msscan scanned 8,541 files in 18 s (one process, Python API); on the 2,695 files
the other tools received, picklescan 56 s, modelscan 29 s, fickling 312 s, ModelAudit 7,407 s
(with a second ModelAudit run on the machine).

## 4. Hugging Face Hub, second sample (4,032 files, 1,938 repositories)

`make hf-heldout`. The most recently created repositories (overall and with the pytorch,
sklearn, joblib, keras, onnx and gguf filters), minus every repository of the first sample;
at most two files of each kind per repository, including YAML configs, templates and
archives. 4,449 files were selected and 4,032 were stored and scanned (2.7 GB).

### 4a. Engine frozen at commit `4cb5212`, before the sample was scanned

This is the only unseen measurement in this report. The ModelAudit columns were rerun later
with the corrected harness (see Error analysis); the msscan columns are untouched.

Hub corpus: 4032 files from 1938 repositories.

All files (picklescan, modelscan, fickling and ModelAudit receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| security-test | 6 | 0/6 | 0/6 | 0/6 | 2/6 | 0/6 | 2/6 | 2/6 | 0/6 | 2/6 |
| code-by-design | 254 | 11/254 | 136/254 | 3/220 | 107/220 | 1/220 | 50/220 | 74/220 | 114/220 | 214/220 |
| nonstandard | 143 | 2/143 | 131/143 | 0/129 | 0/129 | 0/129 | 0/129 | 128/129 | 1/129 | 2/129 |
| benign | 3626 | 1/3626 = 0.000 (0.000 to 0.002) | 4/3626 = 0.001 (0.000 to 0.003) | 0/1964 = 0.000 (0.000 to 0.002) | 524/1964 = 0.267 (0.248 to 0.287) | 0/1964 = 0.000 (0.000 to 0.002) | 254/1964 = 0.129 (0.115 to 0.145) | 741/1964 = 0.377 (0.356 to 0.399) | 338/1964 = 0.172 (0.156 to 0.189) | 1018/1964 = 0.518 (0.496 to 0.540) |
| no attack (code-by-design, nonstandard, benign) | 4023 | 14/4023 = 0.003 (0.002 to 0.006) | 271/4023 = 0.067 (0.060 to 0.076) | 3/2313 = 0.001 (0.000 to 0.004) | 631/2313 = 0.273 (0.255 to 0.291) | 1/2313 = 0.000 (0.000 to 0.002) | 304/2313 = 0.131 (0.118 to 0.146) | 943/2313 = 0.408 (0.388 to 0.428) | 453/2313 = 0.196 (0.180 to 0.213) | 1234/2313 = 0.534 (0.513 to 0.554) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| security-test | 2 | 0/2 | 0/2 | 0/2 | 2/2 | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| code-by-design | 141 | 11/141 | 117/141 | 3/141 | 107/141 | 1/141 | 50/141 | 74/141 | 84/141 | 141/141 |
| nonstandard | 127 | 0/127 | 127/127 | 0/127 | 0/127 | 0/127 | 0/127 | 127/127 | 0/127 | 1/127 |
| benign | 1079 | 0/1079 = 0.000 (0.000 to 0.004) | 2/1079 = 0.002 (0.001 to 0.007) | 0/1079 = 0.000 (0.000 to 0.004) | 511/1079 = 0.474 (0.444 to 0.503) | 0/1079 = 0.000 (0.000 to 0.004) | 254/1079 = 0.235 (0.211 to 0.262) | 741/1079 = 0.687 (0.658 to 0.714) | 330/1079 = 0.306 (0.279 to 0.334) | 924/1079 = 0.856 (0.834 to 0.876) |
| no attack (code-by-design, nonstandard, benign) | 1347 | 11/1347 = 0.008 (0.005 to 0.015) | 246/1347 = 0.183 (0.163 to 0.204) | 3/1347 = 0.002 (0.001 to 0.007) | 618/1347 = 0.459 (0.432 to 0.485) | 1/1347 = 0.001 (0.000 to 0.004) | 304/1347 = 0.226 (0.204 to 0.249) | 942/1347 = 0.699 (0.674 to 0.723) | 414/1347 = 0.307 (0.283 to 0.333) | 1066/1347 = 0.791 (0.769 to 0.812) |

### 4b. After the fixes the frozen run led to (not an unseen measurement)

Two files moved to the payload label because the rules that read them (MS206, MS506) are
part of those fixes.

Hub corpus: 4032 files from 1938 repositories.

All files (picklescan, modelscan, fickling and ModelAudit receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 5 | 5/5 | 5/5 | 3/4 | 3/4 | 1/4 | 3/4 | 3/4 | 3/4 | 3/4 |
| security-test | 5 | 0/5 | 0/5 | 0/5 | 2/5 | 0/5 | 2/5 | 2/5 | 0/5 | 2/5 |
| code-by-design | 254 | 1/254 | 136/254 | 3/220 | 107/220 | 1/220 | 50/220 | 74/220 | 114/220 | 214/220 |
| nonstandard | 142 | 0/142 | 130/142 | 0/129 | 0/129 | 0/129 | 0/129 | 128/129 | 1/129 | 2/129 |
| benign | 3626 | 0/3626 = 0.000 (0.000 to 0.001) | 3/3626 = 0.001 (0.000 to 0.002) | 0/1964 = 0.000 (0.000 to 0.002) | 524/1964 = 0.267 (0.248 to 0.287) | 0/1964 = 0.000 (0.000 to 0.002) | 254/1964 = 0.129 (0.115 to 0.145) | 741/1964 = 0.377 (0.356 to 0.399) | 338/1964 = 0.172 (0.156 to 0.189) | 1018/1964 = 0.518 (0.496 to 0.540) |
| no attack (code-by-design, nonstandard, benign) | 4022 | 1/4022 = 0.000 (0.000 to 0.001) | 269/4022 = 0.067 (0.060 to 0.075) | 3/2313 = 0.001 (0.000 to 0.004) | 631/2313 = 0.273 (0.255 to 0.291) | 1/2313 = 0.000 (0.000 to 0.002) | 304/2313 = 0.131 (0.118 to 0.146) | 943/2313 = 0.408 (0.388 to 0.428) | 453/2313 = 0.196 (0.180 to 0.213) | 1234/2313 = 0.534 (0.513 to 0.554) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| security-test | 2 | 0/2 | 0/2 | 0/2 | 2/2 | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| code-by-design | 141 | 1/141 | 117/141 | 3/141 | 107/141 | 1/141 | 50/141 | 74/141 | 84/141 | 141/141 |
| nonstandard | 127 | 0/127 | 127/127 | 0/127 | 0/127 | 0/127 | 0/127 | 127/127 | 0/127 | 1/127 |
| benign | 1079 | 0/1079 = 0.000 (0.000 to 0.004) | 2/1079 = 0.002 (0.001 to 0.007) | 0/1079 = 0.000 (0.000 to 0.004) | 511/1079 = 0.474 (0.444 to 0.503) | 0/1079 = 0.000 (0.000 to 0.004) | 254/1079 = 0.235 (0.211 to 0.262) | 741/1079 = 0.687 (0.658 to 0.714) | 330/1079 = 0.306 (0.279 to 0.334) | 924/1079 = 0.856 (0.834 to 0.876) |
| no attack (code-by-design, nonstandard, benign) | 1347 | 1/1347 = 0.001 (0.000 to 0.004) | 246/1347 = 0.183 (0.163 to 0.204) | 3/1347 = 0.002 (0.001 to 0.007) | 618/1347 = 0.459 (0.432 to 0.485) | 1/1347 = 0.001 (0.000 to 0.004) | 304/1347 = 0.226 (0.204 to 0.249) | 942/1347 = 0.699 (0.674 to 0.723) | 414/1347 = 0.307 (0.283 to 0.333) | 1066/1347 = 0.791 (0.769 to 0.812) |

## 5. Were the dangerous files already known? (checked 2026-11-23)

`benchmarks/hf/hub_status.py` reads the Hub's published scan result for every file msscan
rates high and checks whether its repository presents itself as security test material (by
name, in its model card, or through another repository of the same owner).

| | First sample | Second sample, frozen | Second sample, after fixes |
|---|---:|---:|---:|
| Payload files | 19 | 3 | 5 |
| Flagged by the Hub | 16 | 2 | 2 |
| Not flagged by the Hub | 3 | 1 | 3 |
| In repositories presenting as security tests | 17 | 1 | 3 |
| Neither flagged nor in a test repository | 0 | 0 | 0 |
| Other files msscan rates high | 12 | 14 | 1 |
| of which flagged by the Hub | 5 | 0 | 0 |

No payload file is a discovery. Files were matched by path on `main`, not by hash; the
statuses are a snapshot and several moved between safe and queued during the day.

## 6. Speed and memory

`make speed`. Median of three runs per tool and file, each in a fresh process under
`/usr/bin/time -l`, Python start-up and imports included, on an otherwise idle machine. The
safetensors file is the single shard of `Qwen/Qwen3.5-0.8B` (1,746,942,600 bytes).

| Tool | opus-mt-en-de `.bin` (284 MB) | opus-mt-en-fr `.bin` (287 MB) | Qwen3.5-0.8B `.safetensors` (1,666 MB) | plain-data pickle (31 MB) |
|---|---:|---:|---:|---:|
| **msscan** (binary) | < 0.01 s, 4 MB | < 0.01 s, 4 MB | < 0.01 s, 4 MB | 0.16 s, 241 MB |
| msscan (Python package) | 0.04 s, 21 MB | 0.04 s, 21 MB | 0.03 s, 22 MB | 0.18 s, 258 MB |
| picklescan | 0.06 s, 26 MB | 0.06 s, 26 MB | 0.05 s, 24 MB | 6.1 s, 900 MB |
| modelscan | 0.10 s, 40 MB | 0.10 s, 40 MB | 0.10 s, 40 MB | 6.1 s, 915 MB |
| ModelAudit | 3.2 s, 178 MB | 3.3 s, 185 MB | 6.8 s, 107 MB | 16 s, 1,106 MB |
| fickling | 1.0 s, 494 MB | 0.95 s, 497 MB | 2.1 s, 1,046 MB | 37 s, 1,605 MB |

## Error analysis

- **Third-party misses (msscan at high):** three Keras HDF5 files that name a custom layer,
  loss or metric. msscan reports MS503 (low): the file holds no code and loading needs the
  caller to supply it. Raising MS503 to high would flag 123 files of the first Hub sample.
- **First Hub sample, alerts without an attack (6 at high):** two pickles carrying functions
  and classes serialized by dill (MS101, MS105, MS110; the Hub flags both), three pickles
  holding `lambda x: exec('import os; os.system(...)')` as a string (MS117; in a repository
  of generated test files that also holds payload files; ModelAudit flags them too), and one
  pickle calling `builtins.print` (MS115; fickling flags it too). Version 0.1.0 raised 31.
- **Fixes made after looking at the first sample with 0.2.0 rules:** a tokenizer vocabulary
  built from source code contained the word `os.system("shutdown`, so MS117 now needs a
  complete call; raw half-precision weights that begin with the `EXT4` byte were rated high
  as a pickle, so an `EXT` lookup whose result is never used in a broken stream is medium;
  `keras_metadata.pb` wraps a Lambda function in a `__tuple__` object, which was reported as
  unreadable bytecode.
- **Second Hub sample, frozen engine (14 alerts without an attack, by the frozen labels):**
  eight scikit-learn pipelines storing `functools.partial(check_array, ...)` in a
  `FunctionTransformer` (one of them through dill), one PyTorch Lightning checkpoint storing
  `partial(Adam, ...)`, one pipeline storing `operator.methodcaller("__floordiv__", 3600)`,
  one YAML config with `!!python/tuple`, one base64-encoded Git LFS pointer named
  `.safetensors`, one joblib file with an embedded pickle that rebuilds a function through
  numba's cloudpickle (still high after the fixes), and one 21-byte file whose content is
  `../../../etc/hostname` (a stored symbolic link, rated high as a broken header and counted
  by the frozen labels as a clean file). picklescan raised 3 alerts on the same files and
  modelscan 1.
- **Second Hub sample, frozen engine, missed:** a Keras archive whose tokenizer layer config
  names a file path on the loading machine (rated low; no other tool flagged it).
- **A defect found while examining that sample:** `scan_path` skipped every symbolic link, so
  a Hugging Face cache snapshot directory was reported as zero files scanned.
- **Harness faults found and fixed (the first two made ModelAudit look worse):** (1) the comparison worker
  silenced each tool by replacing `sys.stdout` with an in-memory buffer; under that
  condition ModelAudit rates benign PyTorch files critical. Output is now discarded at the
  file-descriptor level, and the verdicts of the other tools did not change. (2) ModelAudit's
  chat-template fixtures were scanned under their fixture names, which it does not route to
  its template scanner. With both faults ModelAudit scored 124 of 144 with 8 false alarms on
  the third-party files; without them, 139 with 4. (3) The speed harness left each tool's
  stderr in an unread pipe, which blocked ModelAudit for as long as the run was left.
- **Security-test files msscan does not flag:** weight backdoors (out of scope), an ONNX
  docstring injection, safetensors files with unusual tensor names, a zip-slip `.keras` and a
  decompression-bomb `.keras` whose offending members were not fetched by headers-only
  collection, a NumPy shape needing 80 GB (medium), and benign baselines.
- **History:** bypasses reported by outside reviewers of version 0.1 are listed in the
  README. The figures of version 0.1.0 (116 of 116 on a 194-file corpus; 17 of 17 payload
  files and 31 alerts on 7,607 Hub files) are in the git history of this file.

## Reproducibility

```bash
make build
make third-party                    # clones four repositories (about 70 MB)
make corpus validate compare        # authored corpus (about 1 MB)
make hf-list hf-fetch               # first Hub sample (3.7 GB stored, rate limited)
make hf-compare hf-review hf-status # about two hours here, almost all of it ModelAudit
make hf-heldout                     # second Hub sample: list, fetch, scan, review, status
make speed                          # 5 minutes here
```

The Hub listings change over time, so a fresh collection gives a different sample; the
committed `hf_corpus.json` and `hf_heldout*.json` rows (pseudonymous ids) are the ones behind
the tables. `make hf-heldout` scans whatever engine is checked out; the frozen figures need
commit `4cb5212`.
