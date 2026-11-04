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


def test_hub_review_labels() -> None:
    from benchmarks.hf.review import label, table

    def priv(repo: str, rules: list[str], imports: list[tuple[str, str, str]]) -> dict[str, object]:
        return {
            "repo": repo,
            "findings": [{"rule": r} for r in rules],
            "imports": [{"module": m, "name": n, "tier": t} for m, n, t in imports],
        }

    cases = {
        "payload": priv("org/weights", ["MS101"], [("posix", "system", "dangerous")]),
        "security-test": priv(
            "someone/scanner-bypass-poc", ["MS111"], [("builtins", "print", "library")]
        ),
        "code-by-design": priv("org/keras-model", ["MS505"], []),
        "nonstandard": priv("org/wan-gguf", ["MS803"], []),
        "benign": priv("org/bert", ["MS111"], [("sklearn.svm", "SVC", "library")]),
    }
    for expected, p in cases.items():
        assert label({}, p)[0] == expected, expected
    # "Vulnerability" and "pocket" are not security-test words
    assert label({}, priv("org/Drought_Vulnerability", [], []))[0] == "benign"
    assert label({}, priv("org/POCKET-26B", [], []))[0] == "benign"
    assert label({}, priv("someone/MaliciousModel", [], []))[0] == "security-test"
    assert (
        label({}, priv("org/dtensor", [], [("torch.distributed.tensor", "DTensor", "library")]))[0]
        == "benign"
    )

    rows = [
        {
            "id": "a",
            "kind": "pickle",
            "msscan": {"flags": {"default": True}},
            "picklescan": {"flags": {}},
        },
        {"id": "b", "kind": "gguf", "msscan": {"flags": {"default": False}}},
    ]
    text = table(rows, {"a": "payload", "b": "benign"}, None)
    assert "| payload | 1 | 1/1 | 0/1 | 0/1 |" in text
    assert "| benign | 1 | 0/1 = 0.000" in text
    assert "not run" in text
