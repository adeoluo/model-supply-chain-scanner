# Data Card

The project uses two corpora. Neither is committed: both are rebuilt by scripts into
`../.bench-data/model-supply-chain-scanner/` (outside the repository).

## 1. Synthetic corpus (`benchmarks/corpus/generate.py`)

- **What:** 116 malicious files covering 77 techniques in 11 format families, and 78 benign files
  written by the real libraries (PyTorch 2.15, scikit-learn 1.9, joblib, NumPy 2.5, Keras 3.15,
  ONNX 1.23, safetensors).
- **Payloads:** inert by construction. Code-execution payloads print the canary string
  `MSSCAN-CANARY`, return `os.getcwd()`, or set a harmless attribute in the loading process.
  External data paths point to files that do not exist. Nothing deletes, writes outside the
  corpus directory, opens network connections or persists.
- **Ground truth:** `benchmarks/corpus/validate.py` loads every file that has a Python loader in
  a fresh subprocess (`pickle`, `torch.load(weights_only=False)`, `np.load(allow_pickle=True)`,
  `joblib.load`, `keras.saving.load_model(safe_mode=False)`, unsandboxed Jinja rendering of chat
  templates, `safetensors.numpy.load_file`). All 101 validated malicious files ran their payload
  or were rejected by the reference loader (structural cases); all 72 benign files loaded.
  15 malicious files (SavedModel ops, ONNX paths, GGUF structure, two Keras configs) are labeled
  by construction because their loaders are not installed or were patched.
- **Bias:** written by the author of the scanner, who knew its rules. It is a regression gate
  and a map of which tool handles which technique, not an estimate of recall on unknown attacks.
  The hard tier (3 files) uses functions outside the denylist on purpose.

## 2. Hugging Face Hub corpus (`benchmarks/hf/collect.py`)

See `docs/EVALUATION_REPORT.md` for the final counts. Repositories come from public listings
(most downloaded, most recently modified, most liked, and filters for gguf, keras, onnx,
sklearn, joblib and tf), skipping gated and private repositories. At most three files of each
kind are taken per repository, plus top-level `config.json` and `tokenizer_config.json`.

- PyTorch zip checkpoints: only the pickle members (and `version`, `byteorder`), fetched with
  range requests and rebuilt into a stub zip.
- `.keras`: only the JSON members. safetensors: only the header. GGUF: only the header, scanned
  in memory and not stored. Other formats: whole files up to 20 MB.
- **Privacy:** repository names stay in a private directory; published rows carry salted
  pseudonyms and only aggregate rates are reported (ADR 0006). No repository owner was contacted.
- **Licenses:** files are read for security analysis and not redistributed.
