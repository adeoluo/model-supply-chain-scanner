"""Label the Hub corpus by what each file contains and tabulate every tool's flags per label.

There is no ground truth for files found in the wild, so labels come from evidence in the file
and its repository, by fixed rules applied in this order:

1. ``payload``: the file reaches a system or evaluation primitive when loaded: a pickle call
   into os, posix, nt, subprocess, sys, socket, requests or ``builtins.eval``/``exec``, a Keras
   config that names such a module, a GGUF chat template that reaches Python internals, or an
   ONNX external data path that leaves the model directory.
2. ``security-test``: the repository describes itself as security test material (its name has
   a word such as poc, malicious, exploit, payload, bypass, huntr or test-models). These files
   are reported as a group; they include crafted payloads and benign baselines.
3. ``code-by-design``: loading runs code that is not plain data reconstruction: a Keras Lambda
   layer or a class from outside Keras, a pickle call into ``__main__``, dill or another module
   outside the known libraries, a TorchScript archive, or a Hugging Face config that asks for
   remote code. Flagging these is policy, not detection of an attack.
4. ``nonstandard``: a file that breaks its format's current specification (for example a GGUF
   tensor with five dimensions or a type id that llama.cpp does not define, or a safetensors file
   whose tensors do not cover its data section), written by legitimate tools.
5. ``benign``: everything else: plain tensors, library objects and configs.

The structural facts (imports, Lambda layers, header fields) are read by msscan's parsers, so a
construct that those parsers miss is invisible here too; the security-test group is reported per
tool for that reason. Labels never use any tool's verdict.

Usage: uv run --project benchmarks python benchmarks/hf/review.py --data DIR --out PREFIX
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.compare import wilson

SECURITY_TEST = re.compile(
    r"(^|[^a-z])(poc|malicious|exploit|payloads?|bypass|huntr|scanme|test-models)([^a-z]|$)", re.I
)
EXEC_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "requests",
    "urllib",
    "webbrowser",
    "runpy",
    "pty",
}
EXEC_BUILTINS = {"eval", "exec", "compile", "__import__"}
PAYLOAD_RULES = {"MS502", "MS701", "MS801"}
CODE_RULES = {"MS501", "MS503", "MS505", "MS402", "MS1003"}
NONSTANDARD_RULES = {
    "MS803",
    "MS901",
    "MS902",
    "MS302",
    "MS109",
    "MS204",
    "MS504",
    "MS703",
    "MS603",
}
LABELS = ["payload", "security-test", "code-by-design", "nonstandard", "benign"]
COLUMNS = [
    ("msscan", "default", "msscan (high)"),
    ("msscan", "medium", "msscan (medium)"),
    ("picklescan", "default", "picklescan"),
    ("picklescan", "strict", "picklescan --strict"),
    ("modelscan", "default", "modelscan"),
    ("fickling", "overtly", "fickling (overtly malicious)"),
    ("fickling", "default", "fickling"),
]


def label(row: dict[str, Any], priv: dict[str, Any]) -> tuple[str, str]:
    rules = {f["rule"] for f in priv["findings"]}
    calls = [(i["module"].split(".")[0], i["name"]) for i in priv["imports"]]
    hits = sorted(
        {
            f"{m}.{n}"
            for m, n in calls
            if m in EXEC_MODULES or (m in ("builtins", "__builtin__") and n in EXEC_BUILTINS)
        }
    )
    if hits or rules & PAYLOAD_RULES:
        return "payload", ", ".join(hits + sorted(rules & PAYLOAD_RULES))
    if SECURITY_TEST.search(priv["repo"]):
        return "security-test", "repository describes itself as security test material"
    unknown = sorted({i["module"].split(".")[0] for i in priv["imports"] if i["tier"] != "library"})
    if rules & CODE_RULES or unknown:
        why = sorted(rules & CODE_RULES) + (
            [f"calls into {len(unknown)} module(s) outside the known libraries"] if unknown else []
        )
        return "code-by-design", ", ".join(why)
    if rules & NONSTANDARD_RULES:
        return "nonstandard", ", ".join(sorted(rules & NONSTANDARD_RULES))
    return "benign", ""


def flagged(row: dict[str, Any], tool: str, variant: str) -> bool | None:
    """True or False when the tool scanned the file, None when it did not receive it."""
    t = row.get(tool)
    if t is None:
        return None
    return bool(t["flags"].get(variant))


GROUPS: list[tuple[str, set[str]]] = [(lab, {lab}) for lab in LABELS] + [
    ("no attack (code-by-design, nonstandard, benign)", {"code-by-design", "nonstandard", "benign"})
]


def table(rows: list[dict[str, Any]], labels: dict[str, str], kinds: set[str] | None) -> str:
    head = "| Label | Files | " + " | ".join(c[2] for c in COLUMNS) + " |"
    out = [head, "|---|---:|" + "---:|" * len(COLUMNS)]
    for name, members in GROUPS:
        sel = [
            r for r in rows if labels[r["id"]] in members and (kinds is None or r["kind"] in kinds)
        ]
        if not sel:
            continue
        cells = []
        for tool, variant, _ in COLUMNS:
            got = [flagged(r, tool, variant) for r in sel]
            seen = [g for g in got if g is not None]
            k = sum(seen)
            if not seen:
                cells.append("not run")
            elif len(members) > 1 or name == "benign":
                lo, hi = wilson(k, len(seen))
                cells.append(f"{k}/{len(seen)} = {k / len(seen):.3f} ({lo:.3f} to {hi:.3f})")
            else:
                cells.append(f"{k}/{len(seen)}")
        out.append(f"| {name} | {len(sel)} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, default=Path("benchmarks/results/hf_corpus.json"))
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    corpus = json.loads(args.corpus.read_text())
    rows = corpus["rows"]
    priv = {}
    for line in (args.data / "private" / "hf_private_rows.jsonl").open():
        d = json.loads(line)
        priv[d["id"]] = d
    labels: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for r in rows:
        labels[r["id"]], reasons[r["id"]] = label(r, priv[r["id"]])
    by_label = Counter(labels.values())
    by_kind_label: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        by_kind_label[r["kind"]][labels[r["id"]]] += 1
    payload = {
        "labels": by_label,
        "by_kind": {k: dict(v) for k, v in sorted(by_kind_label.items())},
        "rows": [
            {"id": r["id"], "label": labels[r["id"]], "basis": reasons[r["id"]]} for r in rows
        ],
    }
    Path(f"{args.out}.json").write_text(json.dumps(payload, indent=1) + "\n")
    md = [
        f"Hub corpus: {len(rows)} files from {corpus['summary']['repositories']} repositories.",
        "",
        "All files (picklescan, modelscan and fickling receive the pickle-family, Keras, ONNX "
        "and SavedModel files stored in full; header stubs and JSON configs are msscan only):",
        "",
        table(rows, labels, None),
        "",
        "Pickle-family files only (every tool scanned the same files):",
        "",
        table(rows, labels, {"pickle"}),
        "",
    ]
    Path(f"{args.out}.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
