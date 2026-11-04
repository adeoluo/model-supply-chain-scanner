from __future__ import annotations

from pathlib import Path

import pytest

import msscan

FIXTURES = sorted((Path(__file__).parent / "fixtures").iterdir())


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_fixture_verdicts(path: Path) -> None:
    r = msscan.scan_file(path)
    expected = {"malicious": "malicious", "clean": "clean", "invalid": "unsafe"}[
        path.name.split("_")[0].split(".")[0]
    ]
    assert r.verdict == expected, r.summary()
