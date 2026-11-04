"""Run msscan, picklescan, modelscan and fickling over a corpus and score them.

Each tool runs in its own subprocess (so one tool's import cost or crash cannot affect
another) over the same file list, through its Python API with default settings:

- msscan: flagged when a finding reaches ``high`` (the CLI's default ``--fail-on``).
- picklescan: flagged when ``infected_files > 0``; not scanned when it skips the file.
- modelscan: flagged when it reports any issue; not scanned when it skips the file.
- fickling: flagged when ``scan_file`` returns a severity above LIKELY_SAFE (``is_safe`` false).

Usage: uv run --project benchmarks python benchmarks/compare.py --corpus DIR --out PREFIX
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any

TOOLS = ("msscan", "picklescan", "modelscan", "fickling")

WORKER = r"""
import json, sys, time, os, io, contextlib, logging
from pathlib import Path, PurePosixPath
logging.disable(logging.CRITICAL)
tool, listing = sys.argv[1], sys.argv[2]
paths = [l.rstrip("\n") for l in open(listing)]
if tool == "msscan":
    import msscan
    ORDER = ["info", "low", "medium", "high", "critical"]
    def scan(p):
        r = msscan.scan_file(p)
        rank = ORDER.index(r.max_severity) if r.max_severity else -1
        return {"flags": {"default": rank >= 3, "medium": rank >= 2}, "scanned": r.format != "unknown",
                "error": r.error or "", "detail": sorted(r.rules())[:8]}
elif tool == "picklescan":
    from picklescan.scanner import scan_file_path
    def scan(p):
        r = scan_file_path(p)
        s = scan_file_path(p, strict=True)
        bad = sorted({f"{g.module}.{g.name}" for g in r.globals if "Innocuous" not in str(g.safety)})
        return {"flags": {"default": r.infected_files > 0, "strict": s.infected_files > 0},
                "scanned": r.scanned_files > 0, "error": "scan error" if r.scan_err else "",
                "detail": bad[:8]}
elif tool == "modelscan":
    from modelscan.modelscan import ModelScan
    def scan(p):
        r = ModelScan().scan(p)
        issues = r.get("issues", [])
        scanned = r.get("summary", {}).get("scanned", {}).get("scanned_files", [])
        errs = r.get("errors", [])
        return {"flags": {"default": len(issues) > 0}, "scanned": bool(scanned),
                "error": "; ".join(str(e.get("description", e))[:120] for e in errs)[:300],
                "detail": sorted({str(i.get("operator", "")) for i in issues})[:8]}
elif tool == "fickling":
    # The same triage fickling's own Hugging Face scanner applies (fickling/cli.py).
    from fickling.analysis import Severity, check_safety
    from fickling.loader import scan_file, scan_zip_archive
    from fickling.polyglot import find_file_properties
    from fickling.pytorch import PyTorchModelWrapper
    RAW = {".bin", ".pkl", ".pickle"}
    ZIPX = {".pt", ".pth"}
    def scan(p):
        ext = PurePosixPath(p).suffix.lower()
        props = find_file_properties(p)
        results, errors = [], []
        if props["is_torch_zip"] or props["is_standard_zip"] or ext in ZIPX:
            for r in scan_zip_archive(p, graceful=True).values():
                results.append(r.severity); errors += r.errors
            if props["is_torch_zip"] and ext in ZIPX:
                try:
                    results.append(check_safety(PyTorchModelWrapper(Path(p)).pickled).severity)
                except Exception as e:
                    results.append(Severity.SUSPICIOUS); errors.append(type(e).__name__)
        elif props["is_valid_pickle"] or ext in RAW:
            r = scan_file(p, graceful=True)
            results.append(r.severity); errors += r.errors
        else:
            return {"flags": {"default": False, "overtly": False}, "scanned": False, "error": "",
                    "detail": ["skipped"]}
        worst = max(results, default=Severity.LIKELY_SAFE)
        return {"flags": {"default": worst > Severity.LIKELY_SAFE,
                          "overtly": worst >= Severity.LIKELY_OVERTLY_MALICIOUS},
                "scanned": True, "error": "; ".join(errors)[:300], "detail": [worst.name]}
for p in paths:
    t0 = time.perf_counter()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            row = scan(p)
    except BaseException as e:
        row = {"flags": {}, "scanned": False, "error": f"{type(e).__name__}: {e}"[:300], "detail": []}
    row["path"] = p
    row["seconds"] = time.perf_counter() - t0
    print(json.dumps(row), flush=True)
"""


def version(tool: str) -> str:
    dist = {"msscan": "model-supply-chain-scanner"}.get(tool, tool)
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return "?"


def run_tool(tool: str, files: list[Path], listing: Path) -> dict[str, dict[str, Any]]:
    listing.write_text("".join(f"{p}\n" for p in files))
    t0 = time.perf_counter()
    p = subprocess.run(
        [sys.executable, "-c", WORKER, tool, str(listing)],
        capture_output=True,
        text=True,
        check=False,
    )
    wall = time.perf_counter() - t0
    rows = {}
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            r = json.loads(line)
            rows[r["path"]] = r
    if len(rows) != len(files):
        print(
            f"{tool}: {len(rows)} of {len(files)} rows; stderr tail: {p.stderr[-500:]}",
            file=sys.stderr,
        )
    rows["__wall__"] = {"seconds": wall}
    return rows


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument(
        "--out", type=Path, required=True, help="output prefix, e.g. benchmarks/results/synthetic"
    )
    ap.add_argument("--tools", default=",".join(TOOLS))
    args = ap.parse_args()
    items = [json.loads(line) for line in (args.corpus / "manifest.jsonl").open()]
    files = [(args.corpus / i["path"]).resolve() for i in items]
    work = args.corpus.parent / "compare-work"
    work.mkdir(exist_ok=True)
    results: dict[str, Any] = {"tools": {}, "items": items}
    for tool in args.tools.split(","):
        rows = run_tool(tool, files, work / f"{tool}.txt")
        wall = rows.pop("__wall__")["seconds"]
        for r in rows.values():
            r.pop("path", None)
        results["tools"][tool] = {
            "version": version(tool),
            "wall_seconds": round(wall, 3),
            "rows": [
                rows.get(
                    str(f),
                    {"flags": {}, "scanned": False, "error": "missing", "detail": [], "seconds": 0},
                )
                for f in files
            ],
        }
        print(f"{tool} {results['tools'][tool]['version']}: {wall:.1f} s", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    Path(f"{args.out}.json").write_text(json.dumps(results, indent=1) + "\n")
    Path(f"{args.out}.md").write_text(summarize(results))
    print(summarize(results))


def columns(results: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(tool, variant, header) for every scored configuration."""
    names = {
        ("msscan", "default"): "msscan (high)",
        ("msscan", "medium"): "msscan (medium)",
        ("picklescan", "default"): "picklescan",
        ("picklescan", "strict"): "picklescan --strict",
        ("modelscan", "default"): "modelscan",
        ("fickling", "default"): "fickling",
        ("fickling", "overtly"): "fickling (overtly malicious)",
    }
    return [(t, v, h) for (t, v), h in names.items() if t in results["tools"]]


def flagged(results: dict[str, Any], tool: str, variant: str, i: int) -> bool:
    return bool(results["tools"][tool]["rows"][i]["flags"].get(variant, False))


def summarize(results: dict[str, Any]) -> str:
    items = results["items"]
    cols = columns(results)
    vers = " ".join(f"{t} {results['tools'][t]['version']}" for t in results["tools"])
    lines = [
        f"Versions: {vers}",
        "",
        "| Group | Files | " + " | ".join(h for _, _, h in cols) + " |",
        "|---|---:|" + "---:|" * len(cols),
    ]
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, it in enumerate(items):
        if it["label"] == "malicious":
            tier = "hard" if it["technique"].startswith("hard-") else it["category"]
            groups[("malicious", f"{it['family']} / {tier}")].append(idx)
        else:
            groups[("benign", it["family"])].append(idx)
    for (label, name), idxs in sorted(groups.items()):
        cells = [f"{sum(flagged(results, t, v, i) for i in idxs)}/{len(idxs)}" for t, v, _ in cols]
        lines.append(f"| {label}: {name} | {len(idxs)} | " + " | ".join(cells) + " |")
    lines.append("")
    for label in ("malicious", "benign"):
        idxs = [i for i, it in enumerate(items) if it["label"] == label]
        cells = []
        for t, v, _ in cols:
            k = sum(flagged(results, t, v, i) for i in idxs)
            lo, hi = wilson(k, len(idxs))
            cells.append(f"{k}/{len(idxs)} = {k / len(idxs):.3f} ({lo:.3f} to {hi:.3f})")
        name = (
            "Detection rate (malicious)" if label == "malicious" else "False positive rate (benign)"
        )
        lines.append(f"| {name} | {len(idxs)} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append(
        "| Files not scanned or with errors | | "
        + " | ".join(
            str(sum(bool(r["error"]) or not r["scanned"] for r in results["tools"][t]["rows"]))
            for t, _, _ in cols
        )
        + " |"
    )
    lines.append(
        "| Wall time (s, one process, includes imports) | | "
        + " | ".join(f"{results['tools'][t]['wall_seconds']:.1f}" for t, _, _ in cols)
        + " |"
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
