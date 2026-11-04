"""Unit tests for the benchmark scoring code (the heavy runs happen outside CI)."""

from __future__ import annotations

from benchmarks.compare import columns, summarize, wilson


def test_wilson_interval() -> None:
    assert wilson(0, 0) == (0.0, 0.0)
    lo, hi = wilson(0, 78)
    assert lo == 0.0 and 0.04 < hi < 0.05
    lo, hi = wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and lo > 0.7


def test_summary_tables() -> None:
    items = [
        {"label": "malicious", "family": "pickle", "technique": "t", "category": "code-execution"},
        {
            "label": "malicious",
            "family": "pickle",
            "technique": "hard-x",
            "category": "code-execution",
        },
        {"label": "benign", "family": "pickle", "technique": "b", "category": "benign"},
    ]

    def rows(*flags: bool) -> list[dict[str, object]]:
        return [{"flags": {"default": f}, "scanned": True, "error": ""} for f in flags]

    results = {
        "items": items,
        "tools": {
            "msscan": {"version": "0.1.0", "wall_seconds": 0.1, "rows": rows(True, False, False)},
            "picklescan": {"version": "1", "wall_seconds": 0.2, "rows": rows(True, True, True)},
        },
    }
    assert [h for _, _, h in columns(results)][:2] == ["msscan (high)", "msscan (medium)"]
    text = summarize(results)
    assert "| malicious: pickle / hard | 1 | 0/1 | 0/1 | 1/1 | 0/1 |" in text
    assert "False positive rate (benign) | 1 | 0/1 = 0.000" in text
