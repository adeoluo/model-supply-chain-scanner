"""Ask the Hugging Face Hub what its own scanners say about the files labeled ``payload``.

The Hub scans every file with several tools (Protect AI Guardian, JFrog, picklescan, ClamAV and
VirusTotal) and publishes the result. This script reads that result for each payload file of the
corpus, so the question "did msscan find something nobody knew about?" has a checkable answer.

It also records whether the repository presents itself as security test material, using the same
name rule as ``review.py`` and a look at its model card.

Repository names stay in the private data directory. The committed output holds pseudonymous
file ids, the basis of the payload label, the Hub statuses and counts.

Usage:
    uv run --project benchmarks python benchmarks/hf/hub_status.py \
        --data ../.bench-data/model-supply-chain-scanner/hf --out benchmarks/results/hf_hub_status
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.hf.review import SECURITY_TEST

CARD_WORDS = re.compile(
    r"proof[- ]of[- ]concept|\bpoc\b|malicious|exploit|payload|huntr|bypass|"
    r"do not (use|load)|security (test|research)",
    re.I,
)
SCANNERS = ("protectAiScan", "jFrogScan", "pickleImportScan", "avScan", "virusTotalScan")
FLAGGED = {"unsafe", "suspicious"}


def fetch(url: str, body: str | None = None) -> tuple[int, str]:
    """GET (or POST a JSON body) with curl and return the status code and the text."""
    cmd = ["curl", "-sS", "-L", "-m", "30", "-w", "\n%{http_code}", "-A", "msscan-research", url]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", body]
    done = subprocess.run(cmd, capture_output=True, text=True, check=False)
    text, _, code = done.stdout.rpartition("\n")
    return (int(code) if code.isdigit() else 0), text


def file_status(repo: str, path: str) -> dict[str, Any]:
    """The Hub's published scan result for one file on the main branch."""
    quoted = urllib.parse.quote(repo, safe="/")
    code, text = fetch(
        f"https://huggingface.co/api/models/{quoted}/paths-info/main",
        json.dumps({"paths": [path], "expand": True}),
    )
    if code != 200:
        return {"http": code, "status": "unavailable", "scanners": {}}
    entries = json.loads(text)
    security = (entries[0].get("securityFileStatus") or {}) if entries else {}
    scanners = {
        name: (security.get(name) or {}).get("status", "unscanned")
        for name in SCANNERS
        if name in security
    }
    return {"http": code, "status": security.get("status", "unscanned"), "scanners": scanners}


def presents_as_test(repo: str, path: str) -> dict[str, bool]:
    """Whether the repository says it is security test material, by name or in its card."""
    code, card = fetch(
        f"https://huggingface.co/{urllib.parse.quote(repo, safe='/')}/raw/main/README.md"
    )
    return {
        "by_name": bool(SECURITY_TEST.search(repo) or SECURITY_TEST.search(path)),
        "by_model_card": code == 200 and bool(CARD_WORDS.search(card)),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--review", type=Path, default=Path("benchmarks/results/hf_review.json"))
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/hf_hub_status"))
    args = ap.parse_args()

    review = json.loads(args.review.read_text())
    payload = {r["id"]: r["basis"] for r in review["rows"] if r["label"] == "payload"}
    private = {}
    with (args.data / "private" / "hf_private_rows.jsonl").open() as fh:
        for line in fh:
            row = json.loads(line)
            if row["id"] in payload:
                private[row["id"]] = row

    rows = []
    repo_ids: dict[str, int] = {}
    for fid in sorted(private, key=lambda i: (private[i]["repo"], private[i]["path"])):
        repo, path = private[fid]["repo"], private[fid]["path"]
        hub = file_status(repo, path)
        test = presents_as_test(repo, path)
        rows.append(
            {
                "id": fid,
                "repository": repo_ids.setdefault(repo, len(repo_ids) + 1),
                "basis": payload[fid],
                "msscan": "high",
                "hub_status": hub["status"],
                "hub_scanners": hub["scanners"],
                "hub_flags_it": hub["status"] in FLAGGED,
                "presents_as_security_test": test["by_name"] or test["by_model_card"],
                "presents_as_security_test_by": [k for k, v in test.items() if v],
            }
        )

    not_flagged = [r for r in rows if not r["hub_flags_it"]]
    summary = {
        "checked_on": datetime.date.today().isoformat(),
        "payload_files": len(rows),
        "repositories": len(repo_ids),
        "hub_status": dict(Counter(r["hub_status"] for r in rows)),
        "flagged_by_the_hub": sum(r["hub_flags_it"] for r in rows),
        "not_flagged_by_the_hub": len(not_flagged),
        "in_repositories_presenting_as_security_tests": sum(
            r["presents_as_security_test"] for r in rows
        ),
        "neither_flagged_nor_a_declared_test": sum(
            not r["presents_as_security_test"] for r in not_flagged
        ),
        "note": (
            "A discovery would be a payload file that the Hub does not flag and that is not in "
            "a repository presenting itself as a security test. Statuses are a snapshot of the "
            "main branch on the day of the check; files were matched by path, not by hash, and "
            "queued scans may finish later."
        ),
    }
    args.out.with_suffix(".json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=1) + "\n"
    )
    print(json.dumps(summary, indent=1))
    for r in not_flagged:
        print(
            r["id"], r["basis"], r["hub_status"], r["hub_scanners"], r["presents_as_security_test"]
        )


if __name__ == "__main__":
    main()
