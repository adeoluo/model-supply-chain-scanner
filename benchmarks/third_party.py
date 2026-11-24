"""Build a corpus from test files that other scanner projects wrote and committed.

msscan's own corpus was written by its author, so it cannot show what msscan misses. The
files here come from the test suites of picklescan, ModelAudit, ModelScan and fickling. Each
project wrote them to pin down attacks its own scanner must catch (many are the proof-of-concept
files of published advisories) and benign files it must leave alone.

Labels follow the upstream tests and nothing else:

- picklescan: ``tests/data`` and ``tests/data2``. Files whose upstream test expects no dangerous
  global are benign (listed in ``PICKLESCAN_BENIGN``); the rest are malicious.
- ModelAudit: ``tests/assets``. The malicious and safe lists of its regression test, the
  ``exploits`` and ``pickles`` attack directories, and the ``malicious``, ``obfuscated`` and
  ``benign`` chat-template directories.
- ModelScan and fickling: the few model files they commit.

Nothing is loaded or executed. The files are copied and a manifest is written.

Usage:
    uv run --project benchmarks python benchmarks/third_party.py --src DIR --out DIR
where ``--src`` holds clones of the four repositories (``make third-party`` clones them).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

REPOS = {
    "picklescan": "https://github.com/mmaitre314/picklescan",
    "modelaudit": "https://github.com/promptfoo/modelaudit",
    "modelscan": "https://github.com/protectai/modelscan",
    "fickling": "https://github.com/trailofbits/fickling",
}

# Upstream tests expect no dangerous global in these (tests/test_scanner.py).
PICKLESCAN_BENIGN = {
    "benign0_v0.pkl",
    "benign0_v3.pkl",
    "benign0_v4.pkl",
    "bad_pytorch.pt",
    "not_a_pickle.bin",
    "new_pytorch_model.bin",
    "pytorch_model.bin",
    "benign_password_protected.zip",
    "int_array.npy",
    "int_arrays.npz",
    "int_arrays_compressed.npz",
    "object_array.npy",
    "object_arrays.npz",
    "object_arrays_compressed.npz",
}
# Upstream only says this one fails to parse; it has no expected verdict.
PICKLESCAN_UNLABELED = {"broken_model.pkl"}

MODELAUDIT_MALICIOUS = {
    "samples/pickles/malicious_system_call.pkl",
    "samples/pickles/malicious_model_realistic.pkl",
    "samples/pickles/decode_exec_chain.pkl",
    "samples/pickles/evil.pickle",
    "samples/pickles/nested_pickle_raw.pkl",
    "samples/pickles/nested_pickle_hex.pkl",
    "samples/pickles/nested_pickle_base64.pkl",
    "samples/pickles/nested_pickle_multistage.pkl",
    "samples/safetensors/malicious_import.safetensors",
    "samples/pytorch/malicious_eval.pt",
    "samples/archives/path_traversal.zip",
    "samples/keras/malicious_lambda.h5",
    "samples/keras/loss_injection.h5",
    "samples/keras/metric_injection.h5",
    "samples/keras/custom_layer_attack.h5",
    "samples/tensorflow/malicious_pyfunc/saved_model.pb",
    "samples/jinja2/standalone/malicious_standalone.jinja",
    "samples/jinja2/standalone/malicious_subprocess.template",
    "samples/jinja2/yaml/malicious_config.yaml",
}
MODELAUDIT_BENIGN = {
    "samples/pickles/safe_data.pkl",
    "samples/pickles/safe_large_model.pkl",
    "samples/pickles/safe_model_with_binary.pkl",
    "samples/pickles/safe_model_with_encoding.pkl",
    "samples/pickles/safe_model_with_tokens.pkl",
    "samples/pickles/safe_nested_structure.pkl",
    "samples/safetensors/safe_model.safetensors",
    "samples/pytorch/safe_model.pt",
    "samples/archives/safe_model.zip",
    "samples/keras/safe_model.h5",
    "samples/tensorflow/safe_savedmodel/saved_model.pb",
    "samples/jinja2/standalone/benign_chat.j2",
    "samples/jinja2/standalone/flint_chat_template.jinja",
    "samples/jinja2/yaml/model_config.yaml",
    "samples/manifests/safe_config.json",
}


def commit(repo: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def picklescan_items(root: Path) -> list[tuple[Path, str, str]]:
    items = []
    for sub in ("data", "data2"):
        for p in sorted((root / "tests" / sub).iterdir()):
            if not p.is_file() or p.name in PICKLESCAN_UNLABELED:
                continue
            label = "benign" if p.name in PICKLESCAN_BENIGN else "malicious"
            items.append((p, label, f"{sub}/{p.name}"))
    return items


def modelaudit_items(root: Path) -> list[tuple[Path, str, str]]:
    assets = root / "tests" / "assets"
    items = []
    for p in sorted(assets.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(assets).as_posix()
        top = rel.split("/")[0]
        if rel in MODELAUDIT_MALICIOUS or top in ("exploits", "pickles"):
            label = "malicious"
        elif rel in MODELAUDIT_BENIGN:
            label = "benign"
        elif rel.startswith(("samples/jinja2/malicious/", "samples/jinja2/obfuscated/")):
            label = "malicious"
        elif rel.startswith("samples/jinja2/benign/"):
            label = "benign"
        else:
            continue
        if rel.startswith("samples/jinja2/") and rel.endswith(".json"):
            # ModelAudit reads a chat template only from a file named like a tokenizer config,
            # and its own tests copy these fixtures under that name before scanning them
            # (tests/scanners/test_jinja2_template_scanner.py). Do the same, so it is scored on
            # its fixtures the way its authors score it.
            rel = f"huggingface/{p.parent.name}/{p.stem}/tokenizer_config.json"
        items.append((p, label, rel))
    return items


def modelscan_items(root: Path) -> list[tuple[Path, str, str]]:
    data = root / "tests" / "data"
    return [
        (data / "unsafe_zip_pytorch.pt", "malicious", "unsafe_zip_pytorch.pt"),
        (data / "password_protected.zip", "benign", "password_protected.zip"),
    ]


def fickling_items(root: Path) -> list[tuple[Path, str, str]]:
    p = root / "test" / "fixtures" / "squeezenet1_0_torchscript_v1_4.pt"
    return [(p, "benign", p.name)]


SUITES = {
    "picklescan": picklescan_items,
    "modelaudit": modelaudit_items,
    "modelscan": modelscan_items,
    "fickling": fickling_items,
}


def family(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower()
    return {
        "pkl": "pickle",
        "pickle": "pickle",
        "bin": "pickle",
        "pt": "pytorch",
        "npy": "numpy",
        "npz": "numpy",
        "zip": "archive",
        "7z": "archive",
        "h5": "keras",
        "pb": "savedmodel",
        "safetensors": "safetensors",
        "json": "chat-template",
        "jinja": "chat-template",
        "template": "chat-template",
        "j2": "chat-template",
        "yaml": "chat-template",
    }.get(ext, ext)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)
    rows = []
    commits = {}
    for suite, collect in SUITES.items():
        root = args.src / suite
        commits[suite] = commit(root)
        for src, label, rel in collect(root):
            dst = args.out / suite / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            rows.append(
                {
                    "path": f"{suite}/{rel}",
                    "label": label,
                    "suite": suite,
                    "family": family(src.name),
                    "sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                }
            )
    with (args.out / "manifest.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    (args.out / "sources.json").write_text(
        json.dumps({s: {"repository": REPOS[s], "commit": c} for s, c in commits.items()}, indent=1)
        + "\n"
    )
    for suite in SUITES:
        mal = sum(r["suite"] == suite and r["label"] == "malicious" for r in rows)
        ben = sum(r["suite"] == suite and r["label"] == "benign" for r in rows)
        print(f"{suite}: {mal} malicious, {ben} benign ({commits[suite][:7]})")


if __name__ == "__main__":
    main()
