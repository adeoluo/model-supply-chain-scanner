"""Wall time and peak memory of each scanner on large files, one fresh process per run.

Files: real checkpoints from the Hub (read from the shared Hugging Face cache when present,
otherwise downloaded into ``--data``) plus a large generated plain-data pickle. Each tool scans
each file ``--repeat`` times in a new process under ``/usr/bin/time -l`` (macOS); the median wall
time and peak resident memory are reported. A run is stopped when the process tree exceeds
``--max-rss-gb`` or ``--max-seconds`` and recorded as stopped.

Usage: uv run --project benchmarks python benchmarks/speed.py --data DIR --msscan target/release/msscan
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests

REAL = [
    ("opus-mt-en-de-pytorch_model.bin", "Helsinki-NLP/opus-mt-en-de", "pytorch_model.bin"),
    ("opus-mt-en-fr-pytorch_model.bin", "Helsinki-NLP/opus-mt-en-fr", "pytorch_model.bin"),
    (
        "qwen3.5-0.8b-model.safetensors",
        "Qwen/Qwen3.5-0.8B",
        "model.safetensors-00001-of-00001.safetensors",
    ),
]
HF_CACHE = Path(os.environ.get("HF_HUB_CACHE", Path.home() / ".cache/huggingface/hub"))


def cached(repo: str, path: str) -> Path | None:
    snaps = HF_CACHE / f"models--{repo.replace('/', '--')}" / "snapshots"
    hits = sorted(snaps.glob(f"*/{path}")) if snaps.exists() else []
    return hits[0].resolve() if hits else None


RUNNERS = {
    "picklescan": "from picklescan.scanner import scan_file_path; r = scan_file_path(P)",
    "modelscan": "from modelscan.modelscan import ModelScan; r = ModelScan().scan(P)",
    "fickling": (
        "import fickling; from fickling.polyglot import find_file_properties\n"
        "props = find_file_properties(P)\n"
        "r = fickling.scan_zip_archive(P, graceful=True) if props['is_torch_zip'] or props['is_standard_zip'] "
        "else fickling.scan_file(P, graceful=True)"
    ),
    "msscan-python": "import msscan; r = msscan.scan_file(P)",
}


def fetch(data: Path) -> list[tuple[str, Path]]:
    out = []
    for name, repo, path in REAL:
        p = data / name
        hit = cached(repo, path)
        if hit is not None:
            out.append((name, hit))
            continue
        if not p.exists():
            url = f"https://huggingface.co/{repo}/resolve/main/{path}"
            with requests.get(url, stream=True, timeout=120) as r:
                r.raise_for_status()
                with p.open("wb") as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
        out.append((name, p))
    big = data / "plain-data.pkl"
    if not big.exists():
        rng = random.Random(0)
        obj = {
            "ints": list(range(1_500_000)),
            "floats": [rng.random() for _ in range(1_000_000)],
            "strs": [f"token-{i}" for i in range(700_000)],
            "nested": [{"id": i, "tags": ("a", "b"), "w": [i, i + 1]} for i in range(150_000)],
        }
        big.write_bytes(pickle.dumps(obj, protocol=4))
    out.append((big.name, big))
    return out


def tree_rss(pid: int) -> int:
    """Resident bytes of ``pid`` and its descendants."""
    ps = subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid=,rss="], capture_output=True, text=True
    ).stdout
    kids: dict[int, list[int]] = {}
    rss: dict[int, int] = {}
    for line in ps.splitlines():
        a, b, c = (int(x) for x in line.split())
        kids.setdefault(b, []).append(a)
        rss[a] = c * 1024
    total, todo = 0, [pid]
    while todo:
        q = todo.pop()
        total += rss.get(q, 0)
        todo.extend(kids.get(q, []))
    return total


def timed(cmd: list[str], max_rss: int, max_seconds: float) -> tuple[float, int, str]:
    """(wall seconds, peak RSS bytes, status) of one run; status is ok, memory or time."""
    with subprocess.Popen(
        ["/usr/bin/time", "-l", *cmd], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
    ) as p:
        t0, status = time.monotonic(), "ok"
        while p.poll() is None:
            time.sleep(0.1)
            if tree_rss(p.pid) > max_rss:
                status = "memory"
            elif time.monotonic() - t0 > max_seconds:
                status = "time"
            if status != "ok":
                for line in subprocess.run(
                    ["pgrep", "-P", str(p.pid)], capture_output=True, text=True
                ).stdout.split():
                    os.kill(int(line), 9)
                p.wait()
                return time.monotonic() - t0, max_rss, status
        err = p.stderr.read() if p.stderr else ""
    rss = int(re.search(r"(\d+)\s+maximum resident set size", err).group(1))  # type: ignore[union-attr]
    real = float(re.search(r"([\d.]+) real", err).group(1))  # type: ignore[union-attr]
    return real, rss, "ok"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--msscan", type=Path, required=True)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--max-rss-gb", type=float, default=2.5)
    ap.add_argument("--max-seconds", type=float, default=600)
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/speed.json"))
    args = ap.parse_args()
    args.data.mkdir(parents=True, exist_ok=True)
    files = fetch(args.data)
    rows: list[dict[str, Any]] = []
    for name, f in files:
        for tool in ["msscan", *RUNNERS]:
            if tool == "msscan":
                cmd = [
                    str(args.msscan.resolve()),
                    "scan",
                    "--fail-on",
                    "none",
                    "-f",
                    "json",
                    str(f),
                ]
            else:
                code = f"P = {str(f)!r}\n{RUNNERS[tool]}\nprint('done')"
                cmd = [sys.executable, "-c", code]
            runs = []
            for _ in range(args.repeat):
                runs.append(timed(cmd, int(args.max_rss_gb * 2**30), args.max_seconds))
                if runs[-1][2] != "ok":
                    break
            row = {
                "file": name,
                "size_mb": round(f.stat().st_size / 2**20, 1),
                "tool": tool,
                "wall_s": round(statistics.median(r[0] for r in runs), 3),
                "peak_rss_mb": round(statistics.median(r[1] for r in runs) / 2**20, 1),
                "runs": [round(r[0], 3) for r in runs],
                "status": next((r[2] for r in runs if r[2] != "ok"), "ok"),
            }
            rows.append(row)
            print(json.dumps(row), file=sys.stderr)
    args.out.write_text(json.dumps(rows, indent=1) + "\n")


if __name__ == "__main__":
    main()
