# Threat Model: Model Supply Chain Scanner

## What the scanner defends

A user who downloads a model file (a PyTorch checkpoint, a joblib model, a Keras model, a GGUF
file, an ONNX graph) and is about to load it. Loading a pickle-based file runs code chosen by
whoever wrote it; other formats can reach files, call Python from a graph, inject into a chat
template renderer, or crash a native parser. `msscan` reads the file without loading it and
reports what loading it would do.

## Assets

- The machine and credentials of whoever loads the model (developer laptops, CI runners,
  inference servers).
- The integrity of the model itself (a payload can patch library code or weights in memory).
- The scanner process, which parses hostile input.

## Trust boundaries

1. Model file to scanner: every byte is attacker-controlled. Parsers are written in Rust, read
   memory-mapped input with bounds checks, cap decompression, nesting, opcodes and node counts,
   and never import, unpickle or execute content.
2. HTTP client to service: request bodies are hostile and size-limited (`--max-body`). The
   service scans only the bytes it receives; it never opens paths or URLs from a request.
3. Scanner to user: a clean report is evidence about known techniques, not proof of safety.

## Threats and mitigations

| Threat | Vector | Impact | Mitigation in msscan |
|---|---|---|---|
| Code execution on load | `REDUCE`, `INST`, `OBJ`, `NEWOBJ` of dangerous globals | Full compromise | Symbolic VM, denylist of 90 modules and 69 names (MS101) |
| Evasion by computed imports | `STACK_GLOBAL` fed by `_codecs.encode(..., "rot13")` or memo tricks | Bypasses import lists | Operands tracked through memo and calls (MS103) |
| Evasion by attribute writes | `BUILD` sets `__setstate__`, or patches an imported class | Code execution or tampering | Dunder and global-target `BUILD` detection (MS105) |
| Evasion by indirection | `functools.partial(os.getcwd)()`, `getattr(__import__("os"), ...)()` | Bypasses callee checks | Globals in call arguments count as called; calls of call results (MS110) |
| Nested payloads | `pickle.loads(b"...")`, `torch.storage._load_from_bytes` | Hidden second stage | Embedded bytes scanned recursively (MS106) |
| Parser differentials | Zip local header name or encryption flag differs from the central directory | Scanner and loader see different files | Both headers read and compared; plaintext "encrypted" members still scanned (MS202, MS205) |
| Hiding behind data | joblib raw array bytes before the payload; legacy PyTorch storages | Linear opcode walkers stop early | Exact array skipping; legacy streams read as five pickles |
| Wrapper formats | gzip, zlib, bz2, xz, lzma, lz4 around pickles; `.npz`; misleading extensions | Formats not unpacked | Content sniffing, bounded decompression (MS203), extension mismatch (MS1001) |
| Decompression bombs | Huge inflated sizes | Scanner memory exhaustion | Per-member and per-stream limits (default 1 GiB) |
| Keras code | Lambda layers, system and third-party modules in configs, `TFOpLambda` file ops | Code execution, file writes | Config walk (MS501, MS502, MS505) |
| Graph side effects | `ReadFile`, `WriteFile`, `PyFunc` in SavedModel graphs | File access, Python calls | Protobuf op scan (MS601, MS602) |
| Path traversal | ONNX external data `../..` or absolute paths; zip entry names | Reading or writing outside the model directory | MS701, MS201 |
| Template injection | GGUF or tokenizer chat templates reaching `__globals__` | Code execution in unsandboxed renderers | Tag-level checks (MS801, MS802) |
| Native parser bugs | GGUF counts, string lengths, tensor bounds; safetensors offsets | Memory corruption or exhaustion in loaders | Structural validation (MS803, MS901, MS902) |
| Scanner denial of service | Deep nesting, huge opcode counts | Slow or crashed scans | Limits on opcodes, nodes, container items, nesting depth (MS114) |

## Residual risk

- Functions outside the denylist that run code are reported only as unknown or library calls
  (medium or low), below the default failure threshold. The benchmark's hard tier shows two such
  techniques (`logging.config.dictConfig`, `typing._eval_type`) that pass at the default
  threshold.
- TorchScript code, TFLite, Core ML, MLflow, TensorRT and other formats are not analyzed.
- A model can be harmful without code: poisoned or backdoored weights are out of scope.
- `weights_only=True` loading in PyTorch 2.6 and later already blocks most pickle payloads;
  msscan matters for every other loader and for older code paths.
