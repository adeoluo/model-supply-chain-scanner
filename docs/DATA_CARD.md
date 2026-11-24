# Data Card

The project uses four sets of files. None is committed: all are rebuilt by scripts into
`../.bench-data/model-supply-chain-scanner/` (outside the repository).

## 1. Authored corpus (`benchmarks/corpus/generate.py`)

- **What:** 142 malicious files covering 100 techniques in 15 format families, and 101 benign
  files, most written by the real libraries (PyTorch 2.15, scikit-learn 1.9, joblib, NumPy 2.5,
  Keras 3.15, ONNX 1.23, safetensors). The benign files include the shapes that were false
  alarms in the Hub samples (a stored `functools.partial`, a vocabulary holding a code
  fragment, raw weights under a pickle name, a Git LFS pointer).
- **Payloads:** inert by construction. Code-execution payloads print the canary string
  `MSSCAN-CANARY`, return `os.getcwd()`, or set a harmless attribute in the loading process.
  External data paths point to files that do not exist. Nothing deletes, writes outside the
  corpus directory, opens network connections or persists.
- **Ground truth:** `benchmarks/corpus/validate.py` loads every file that has a Python loader in
  a fresh subprocess (`pickle`, `torch.load(weights_only=False)`, `np.load(allow_pickle=True)`,
  `joblib.load`, `keras.saving.load_model(safe_mode=False)`, unsandboxed Jinja rendering of chat
  templates, `safetensors.numpy.load_file`). All 106 validated malicious files ran their payload
  or were rejected by the reference loader (structural cases); all 72 benign files with a
  loader loaded. 36 malicious files (SavedModel ops, ONNX paths, GGUF structure, Keras configs,
  YAML and Hydra configs, checkpoint indexes, a stored link) are labeled by construction
  because their loaders are not installed, were patched, or would read a real file.
- **Bias:** written by the author of the scanner, who knew its rules. It is a regression gate
  and a map of which tool handles which technique, not an estimate of recall on unknown attacks.
  The hard tier (3 files) was written to use functions outside the denylist; those functions
  were denylisted in version 0.1.1, so the tier is now a regression check only.

## 2. Test files of other scanner projects (`benchmarks/third_party.py`)

- **What:** 181 files that picklescan, ModelAudit, modelscan and fickling keep in their own
  repositories to test themselves: 144 their tests say must be flagged, 37 their tests say
  must pass. The commits are listed in `docs/EVALUATION_REPORT.md`.
- **Labels:** only what the upstream test asserts. Files whose expected verdict the upstream
  tests do not state are left out.
- **Bias:** version 0.2.0 was developed against these files, so its score on them is fitted.
  Each project scores best on its own files.
- **Licenses:** the files are cloned at benchmark time and not redistributed.

## 3. Hugging Face Hub, first sample (`benchmarks/hf/collect.py`)

8,541 files from 2,789 public repositories (3.7 GB stored): 2,827 JSON configs, 2,587
safetensors headers, 1,710 pickle-family files, 525 Keras archives, 432 GGUF headers and 460
ONNX, HDF5 and SavedModel files. Labels (`benchmarks/hf/review.py`): 19 payload, 27
security-test, 400 code-by-design, 80 nonstandard, 8,015 benign. This is the repository
listing drawn for version 0.1 (then 7,607 files, which were not kept), fetched again on
2026-11-23. Repositories come from public listings
(most downloaded, most recently modified, most liked, and filters for gguf, keras, onnx,
sklearn, joblib and tf), skipping gated and private repositories. At most three files of each
kind are taken per repository, plus top-level `config.json` and `tokenizer_config.json`.

- PyTorch zip checkpoints: only the pickle members (and `version`, `byteorder`), fetched with
  range requests and rebuilt into a stub zip.
- `.keras`: only the JSON members. safetensors: only the header. GGUF: only the header, scanned
  in memory and not stored. Other formats: whole files up to 20 MB.
- **Privacy:** repository names stay in a private directory; published rows carry salted
  pseudonyms and sizes rounded up to a power of two, and only aggregate rates are reported (ADR 0006). No repository owner was contacted.
- **Licenses:** files are read for security analysis and not redistributed.

## 4. Hugging Face Hub, second sample (`make hf-heldout`)

4,032 files from 1,938 public repositories (2.7 GB stored), drawn to test the scanner on
files its rules had not seen: the most recently created repositories (overall and with the
pytorch, sklearn, joblib, keras, onnx and gguf filters), minus every repository of the first
sample, at most two files of each kind per repository. It adds YAML configs, chat template
files and 7z and tar archives to the kinds of the first sample. Labels after the fixes: 5
payload, 5 security-test, 254 code-by-design, 142 nonstandard, 3,626 benign.

- **Use:** scanned once with the engine frozen, then used to fix the scanner
  (ADR 0008). It is no longer an unseen sample.
- **Bias:** the listing asks for new scikit-learn and joblib repositories, so joblib files
  are 532 of 4,032 here against 254 of 8,541 in the first sample.
- **Privacy and licenses:** as for the first sample.
