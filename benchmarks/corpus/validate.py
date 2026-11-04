"""Confirm that each malicious corpus file really runs its inert payload under its loader.

Each file is loaded in a fresh subprocess whose working directory is a scratch directory, so
an ``os.getcwd`` payload is visible in the output. A payload counts as executed when the
canary string or the scratch path appears in the subprocess output. Benign files with a loader
are loaded too, to confirm they load cleanly. Structural cases (safetensors) count as confirmed
when the reference loader rejects them.

Usage: uv run --project benchmarks python benchmarks/corpus/validate.py --corpus DIR --out FILE
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

CANARY = "MSSCAN-CANARY"

LOADER = r"""
import os, sys, json
kind, path = sys.argv[1], sys.argv[2]
os.environ.setdefault("KERAS_BACKEND", "torch")
def show(obj):
    print("LOADED", repr(obj)[:2000])
if kind == "pickle":
    import pickle
    with open(path, "rb") as f:
        show(pickle.load(f))
    import argparse
    print(getattr(argparse.Namespace, "msscan_canary", ""))
elif kind == "pickle-gzip":
    import gzip, pickle
    with gzip.open(path, "rb") as f:
        show(pickle.load(f))
elif kind == "torch":
    import torch
    show(torch.load(path, map_location="cpu", weights_only=False))
elif kind == "numpy":
    import numpy as np
    show(np.load(path, allow_pickle=True))
elif kind == "numpy-npz":
    import numpy as np
    z = np.load(path, allow_pickle=True)
    show({k: z[k] for k in z.files})
elif kind == "joblib":
    import joblib
    show(joblib.load(path))
elif kind == "keras":
    import keras, numpy as np
    m = keras.saving.load_model(path, safe_mode=False)
    show(m(np.zeros((1, 4), "float32")))
elif kind in ("jinja", "jinja-json"):
    import jinja2
    from jinja2.sandbox import ImmutableSandboxedEnvironment
    if kind == "jinja":
        from gguf import GGUFReader
        r = GGUFReader(path)
        templates = []
        for name, field in r.fields.items():
            if name.startswith("tokenizer.chat_template"):
                templates.append(bytes(field.parts[field.data[0]]).decode())
    else:
        templates = [json.load(open(path))["chat_template"]]
    ctx = dict(messages=[{"role": "user", "content": "hi"}], add_generation_prompt=True,
               bos_token="<s>", eos_token="</s>", raise_exception=lambda m: None, tools=None)
    for t in templates:
        try:
            ImmutableSandboxedEnvironment().from_string(t).render(**ctx)
            print("SANDBOX rendered")
        except Exception as e:
            print("SANDBOX blocked", type(e).__name__)
        # unsandboxed rendering, as vulnerable chat template code paths did
        print("RENDER", jinja2.Environment().from_string(t).render(**ctx)[:2000])
elif kind == "safetensors":
    from safetensors.numpy import load_file
    show(load_file(path))
"""


def run_one(corpus: Path, scratch: Path, item: dict[str, Any]) -> dict[str, Any]:
    path = corpus / item["path"]
    t0 = time.perf_counter()
    try:
        p = subprocess.run(
            [sys.executable, "-c", LOADER, item["loader"], str(path)],
            cwd=scratch,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        out, err, code = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", "timeout", -1
    executed = CANARY in out or str(scratch) in out
    sandbox = (
        "blocked" if "SANDBOX blocked" in out else ("rendered" if "SANDBOX rendered" in out else "")
    )
    last_err = err.strip().splitlines()[-1][:300] if err.strip() else ""
    return {
        "path": item["path"],
        "label": item["label"],
        "family": item["family"],
        "technique": item["technique"],
        "category": item["category"],
        "loader": item["loader"],
        "executed": executed,
        "loaded": code == 0,
        "sandbox": sandbox,
        "error": last_err if code != 0 else "",
        "seconds": round(time.perf_counter() - t0, 3),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args()
    items = [json.loads(line) for line in (args.corpus / "manifest.jsonl").open()]
    todo = [i for i in items if i["loader"]]
    scratch = (args.corpus.parent / "validate-scratch").resolve()
    scratch.mkdir(exist_ok=True)
    with ThreadPoolExecutor(args.workers) as ex:
        rows = list(ex.map(lambda i: run_one(args.corpus, scratch, i), todo))
    mal = [r for r in rows if r["label"] == "malicious"]
    confirmed = sum(
        r["executed"] if r["category"] != "structure" else (not r["loaded"]) for r in mal
    )
    benign = [r for r in rows if r["label"] == "benign"]
    summary = {
        "malicious_validated": len(mal),
        "malicious_confirmed": confirmed,
        "benign_loaded": sum(r["loaded"] and not r["executed"] for r in benign),
        "benign_total": len(benign),
        "not_validated": [
            i["path"] for i in items if i["label"] == "malicious" and not i["loader"]
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    for r in mal:
        ok = r["executed"] if r["category"] != "structure" else not r["loaded"]
        if not ok:
            print("NOT CONFIRMED", r["path"], r["error"])


if __name__ == "__main__":
    main()
