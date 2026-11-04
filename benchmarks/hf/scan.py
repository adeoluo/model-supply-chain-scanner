"""Scan the Hub corpus with all four tools and write pseudonymous results.

msscan scans every stored file in process (header stubs with their real size, so offsets are
checked against the full file) and contributes the GGUF headers scanned during collection. The
other tools run through the same workers as ``benchmarks/compare.py`` on the stored files.

Published rows carry a pseudonym, the file kind, the size rounded up to a power of two and per-tool verdicts with rule ids or
severity names only; module names, file names and repository names stay in the private
directory (``--private-out``) for labeling.

Usage: uv run --project benchmarks python benchmarks/hf/scan.py --data DIR --out PREFIX
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import msscan

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.compare import run_tool

ORDER = ["info", "low", "medium", "high", "critical"]


def rank(sev: str | None) -> int:
    return ORDER.index(sev) if sev in ORDER else -1


def size_log2(size: int) -> int:
    """Size rounded up to a power of two (exact sizes could identify files)."""
    return max(0, math.ceil(math.log2(max(size, 1))))


def file_id(salt: str, repo: str, path: str) -> str:
    return "f" + hashlib.sha256(f"{salt}|{repo}|{path}".encode()).hexdigest()[:12]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tools", default="picklescan,modelscan,fickling")
    args = ap.parse_args()
    priv = args.data / "private"
    salt = (priv / "salt").read_text().strip()
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for line in (priv / "fetched.jsonl").open():
        d = json.loads(line)
        latest[(d["repo"], d["path"])] = d  # a retried file replaces its earlier record
    fetched = list(latest.values())
    from benchmarks.hf.collect import pseudonym

    rows: list[dict[str, Any]] = []
    private_rows: list[dict[str, Any]] = []
    stored: list[tuple[int, Path]] = []
    t0 = time.perf_counter()
    for rec in fetched:
        if rec.get("status") != "ok":
            continue
        fid = file_id(salt, rec["repo"], rec["path"])
        row: dict[str, Any] = {
            "id": fid,
            "repo": pseudonym(salt, rec["repo"]),
            "kind": rec["kind"],
            "mode": rec["mode"],
            "size_log2": size_log2(rec["size"]),
        }
        if rec["mode"] == "header-streamed":
            rep = rec["report"]
            row["prefix_incomplete"] = rec.get("prefix_incomplete", False)
        else:
            p = args.data / "files" / pseudonym(salt, rec["repo"]) / rec["stored"]
            declared = rec["size"] if rec["mode"] == "header" else None
            rep = msscan.scan_bytes(p.read_bytes(), rec["stored"], declared_size=declared).raw
            stored.append((len(rows), p))
        row["format"] = rep["format"]
        row["msscan"] = {
            "severity": rep["max_severity"],
            "flags": {
                "default": rank(rep["max_severity"]) >= 3,
                "medium": rank(rep["max_severity"]) >= 2,
            },
            "rules": sorted({f["rule"] for f in rep["findings"]}),
            "rules_high": sorted({f["rule"] for f in rep["findings"] if rank(f["severity"]) >= 3}),
        }
        private_rows.append(
            {
                "id": fid,
                "repo": rec["repo"],
                "path": rec["path"],
                "findings": rep["findings"],
                "imports": [i for i in rep["imports"] if i["tier"] != "safe"],
            }
        )
        rows.append(row)
    msscan_seconds = time.perf_counter() - t0
    print(f"msscan: {len(rows)} files in {msscan_seconds:.1f} s", file=sys.stderr)

    # Other tools on stored pickle-family, Keras, ONNX and SavedModel files (header stubs and
    # JSON files are formats they do not read, so they are not passed to them).
    others = [
        (i, p)
        for i, p in stored
        if rows[i]["mode"] not in ("header",) and rows[i]["kind"] != "json"
    ]
    work = args.data / "compare-work"
    work.mkdir(exist_ok=True)
    tool_meta = {}
    for tool in args.tools.split(","):
        res = run_tool(tool, [p for _, p in others], work / f"hf-{tool}.txt")
        wall = res.pop("__wall__")["seconds"]
        tool_meta[tool] = {"wall_seconds": round(wall, 1), "files": len(others)}
        for i, p in others:
            r = res.get(str(p), {"flags": {}, "scanned": False, "error": "missing", "detail": []})
            rows[i][tool] = {
                "flags": r["flags"],
                "scanned": r["scanned"],
                "error": bool(r["error"]),
            }
            private_rows[i][tool] = {"detail": r["detail"], "error": r["error"]}
        print(f"{tool}: {wall:.1f} s", file=sys.stderr)

    out = {
        "summary": summarize(rows),
        "tools": tool_meta,
        "msscan_seconds": round(msscan_seconds, 1),
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    Path(f"{args.out}.json").write_text(json.dumps(out, indent=1) + "\n")
    (priv / "hf_private_rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in private_rows))
    print(json.dumps(out["summary"], indent=1))


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind = Counter(r["kind"] for r in rows)
    by_format = Counter(r["format"] for r in rows)
    flagged = Counter()
    rules = Counter()
    for r in rows:
        for t in ("msscan", "picklescan", "modelscan", "fickling"):
            for v, f in r.get(t, {}).get("flags", {}).items():
                if f:
                    flagged[f"{t}:{v}:{r['kind']}"] += 1
        for rule in r["msscan"]["rules"]:
            rules[rule] += 1
    return {
        "files": len(rows),
        "repositories": len({r["repo"] for r in rows}),
        "by_kind": dict(by_kind),
        "by_format": dict(by_format.most_common()),
        "flagged": dict(sorted(flagged.items())),
        "msscan_rule_counts": dict(rules.most_common()),
    }


if __name__ == "__main__":
    main()
